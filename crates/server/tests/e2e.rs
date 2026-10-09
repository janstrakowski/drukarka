//! End-to-end tests — **no physical printer**.
//!
//! Two layers:
//! 1. In-process: axum router + mock CUPS + IPP proxy (fast).
//! 2. Process: real `drukarka-server` binary over HTTPS + mock CUPS (closer to prod).
//!
//! Run: `cargo test-e2e`

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use http_body_util::BodyExt;
use server::ipp::{self, test_ipp_with_uri};
use server::{auth, pages, state};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

#[derive(Default)]
struct MockCups {
    hits: AtomicUsize,
    last_path: Mutex<String>,
    last_body: Mutex<Vec<u8>>,
    last_method: Mutex<String>,
}

async fn spawn_mock_cups(state: Arc<MockCups>) -> SocketAddr {
    let state_get = state.clone();
    let app = axum::Router::new()
        .route(
            "/",
            get(|| async {
                axum::response::Html(
                    r#"<!doctype html><a href="/printers/FakePrinter">Fake</a>"#,
                )
            }),
        )
        .route(
            "/printers/{name}",
            get(
                |axum::extract::Path(name): axum::extract::Path<String>| async move {
                    // Simulate CUPS redirect that would escape /cups/ without Location rewrite.
                    if name == "RedirectMe" {
                        return axum::response::Redirect::temporary("/printers/FakePrinter")
                            .into_response();
                    }
                    axum::response::Html(format!(
                        r#"<!doctype html><h1>{name}</h1><a href="/admin">admin</a><form action=/admin method=post></form>"#
                    ))
                    .into_response()
                },
            )
            .post({
                let st = state.clone();
                move |axum::extract::Path(name): axum::extract::Path<String>,
                      req: Request<Body>| {
                    let st = st.clone();
                    async move {
                        st.hits.fetch_add(1, Ordering::SeqCst);
                        *st.last_method.lock().unwrap() = "POST".into();
                        *st.last_path.lock().unwrap() = format!("/printers/{name}");
                        let bytes = req.into_body().collect().await.unwrap().to_bytes();
                        *st.last_body.lock().unwrap() = bytes.to_vec();
                        StatusCode::OK
                    }
                }
            }),
        )
        .fallback(move |req: Request<Body>| {
            let st = state_get.clone();
            async move {
                st.hits.fetch_add(1, Ordering::SeqCst);
                *st.last_method.lock().unwrap() = req.method().to_string();
                *st.last_path.lock().unwrap() = req.uri().path().to_string();
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                *st.last_body.lock().unwrap() = bytes.to_vec();
                (StatusCode::OK, axum::response::Html("<html>ok</html>"))
            }
        });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    addr
}

fn test_app(db_path: &Path, cups: SocketAddr) -> axum::Router {
    let st = Arc::new(
        state::AppState::with_cups(
            db_path.to_path_buf(),
            cups.ip().to_string(),
            cups.port(),
        )
        .unwrap(),
    );
    pages::router(st)
}

async fn body_text(res: axum::response::Response) -> String {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn session_cookie(db_path: &Path) -> String {
    let conn = server::db::open(db_path).unwrap();
    let sid = auth::create_session(&conn).unwrap();
    format!("drukarka_session={sid}")
}

// --- in-process e2e ---

#[tokio::test]
async fn e2e_public_surfaces() {
    let dir = tempfile::tempdir().unwrap();
    // Dummy CUPS addr — unused by these routes.
    let app = test_app(&dir.path().join("state.db"), "127.0.0.1:9".parse().unwrap());

    let res = app
        .clone()
        .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "ok");

    let res = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("passkey"));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/enroll?token=e2e-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("e2e-token"));
    assert!(html.contains("Create passkey"));
}

#[tokio::test]
async fn e2e_cups_auth_gate_proxy_and_escape_redirect() {
    let mock = Arc::new(MockCups::default());
    let cups_addr = spawn_mock_cups(mock.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.db");
    let app = test_app(&db_path, cups_addr);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/cups/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(res.status().is_redirection());

    let cookie = session_cookie(&db_path);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/cups/")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("/cups/printers/FakePrinter"), "{html}");

    // Follow the product path users hit when CUPS escapes the wrap.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/printers/FakePrinter")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(res.status().is_redirection());
    assert_eq!(
        res.headers().get("location").unwrap().to_str().unwrap(),
        "/cups/printers/FakePrinter"
    );

    let res = app
        .oneshot(
            Request::builder()
                .uri("/cups/printers/FakePrinter")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let page = body_text(res).await;
    assert!(page.contains("FakePrinter"));
    assert!(page.contains("action=/cups/admin") || page.contains("href=\"/cups/admin\""));
}

#[tokio::test]
async fn e2e_cups_location_header_stays_under_wrap() {
    let mock = Arc::new(MockCups::default());
    let cups_addr = spawn_mock_cups(mock).await;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.db");
    let app = test_app(&db_path, cups_addr);
    let cookie = session_cookie(&db_path);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/cups/printers/RedirectMe")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(res.status().is_redirection());
    let loc = res.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        loc, "/cups/printers/FakePrinter",
        "CUPS Location:/printers/… must be rewritten under /cups/"
    );
}

#[tokio::test]
async fn e2e_print_job_never_touches_hardware() {
    let mock = Arc::new(MockCups::default());
    let cups_addr = spawn_mock_cups(mock.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.db");
    let app = test_app(&db_path, cups_addr);
    let cookie = session_cookie(&db_path);

    let payload = b"%!PS-Adobe e2e fake job - not a real printer";
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cups/printers/FakePrinter")
                .header("cookie", cookie)
                .header("content-type", "application/postscript")
                .body(Body::from(payload.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(mock.hits.load(Ordering::SeqCst), 1);
    assert_eq!(mock.last_method.lock().unwrap().as_str(), "POST");
    assert_eq!(
        mock.last_path.lock().unwrap().as_str(),
        "/printers/FakePrinter"
    );
    assert_eq!(mock.last_body.lock().unwrap().as_slice(), payload);
}

#[tokio::test]
async fn e2e_win7_ipp_path_rewrite_to_queue() {
    let mock = Arc::new(MockCups::default());
    let cups_addr = spawn_mock_cups(mock.clone()).await;

    let ipp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ipp_addr = ipp_listener.local_addr().unwrap();
    let cups_port = cups_addr.port();
    tokio::spawn(async move {
        ipp::run_listener(ipp_listener, "127.0.0.1", cups_port)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let ipp_body = test_ipp_with_uri("ipp://drukarka.local:631/ipp/print");
    let mut stream = tokio::net::TcpStream::connect(ipp_addr).await.unwrap();
    let req = format!(
        "POST /ipp/print HTTP/1.1\r\nHost: drukarka.local:631\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        ipp_body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(&ipp_body).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();

    assert!(mock.hits.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        mock.last_path.lock().unwrap().as_str(),
        "/printers/HP_LaserJet_P1005"
    );
    let body_bytes = mock.last_body.lock().unwrap().clone();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("/printers/HP_LaserJet_P1005"));
    assert!(!body.contains("/ipp/print"));
}

#[tokio::test]
async fn e2e_logout_revokes_cups_access() {
    let mock = Arc::new(MockCups::default());
    let cups_addr = spawn_mock_cups(mock).await;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.db");
    let app = test_app(&db_path, cups_addr);
    let cookie = session_cookie(&db_path);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header("cookie", &cookie)
                .header("origin", "https://drukarka.local")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/cups/")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status().is_redirection(),
        "logged-out session must not reach CUPS"
    );
}

// --- process-level e2e (real binary + HTTPS) ---

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_test_tls(dir: &Path) -> (PathBuf, PathBuf) {
    let mut params = rcgen::CertificateParams::new(vec![
        "drukarka.local".into(),
        "127.0.0.1".into(),
        "localhost".into(),
    ])
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "drukarka.local");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_path = dir.join("test.crt");
    let key_path = dir.join("test.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path)
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn server_exe() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_drukarka_server") {
        return PathBuf::from(p);
    }
    // Cargo sometimes omits CARGO_BIN_EXE_* depending on invocation; fall back.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // repo root
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push("drukarka-server");
    p
}

#[tokio::test]
async fn e2e_process_https_server_against_mock_cups() {
    let mock = Arc::new(MockCups::default());
    let cups_addr = spawn_mock_cups(mock.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.db");
    let (cert, key) = write_test_tls(dir.path());
    let https_port = free_port();
    let http_port = free_port();

    // Ensure DB exists with a session before the server starts.
    {
        let conn = server::db::open(&db_path).unwrap();
        server::migrate::apply(&conn).unwrap();
        let _ = auth::create_session(&conn).unwrap();
    }
    // Re-open to mint cookie after migrate schema is ready
    let cookie = session_cookie(&db_path);

    let bin = server_exe();
    assert!(
        bin.exists(),
        "missing {}, run: cargo build -p server",
        bin.display()
    );
    let child = Command::new(&bin)
        .args([
            "serve",
            "--db",
            db_path.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--https-port",
            &https_port.to_string(),
            "--http-port",
            &http_port.to_string(),
        ])
        .env("DRUKARKA_CUPS_HOST", "127.0.0.1")
        .env("DRUKARKA_CUPS_PORT", cups_addr.port().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn drukarka-server");
    let _guard = ChildGuard(child);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let base = format!("https://127.0.0.1:{https_port}");
    // Wait until listening
    for _ in 0..50 {
        if client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let health = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);

    let denied = client
        .get(format!("{base}/cups/"))
        .send()
        .await
        .unwrap();
    assert!(
        denied.status().is_redirection(),
        "process e2e: unauthenticated /cups/ must redirect"
    );

    let ok = client
        .get(format!("{base}/cups/"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let html = ok.text().await.unwrap();
    assert!(
        html.contains("/cups/printers/FakePrinter"),
        "process e2e HTML rewrite failed: {html}"
    );

    let print = client
        .post(format!("{base}/cups/printers/FakePrinter"))
        .header("cookie", &cookie)
        .header("content-type", "application/postscript")
        .body("%!PS process-e2e")
        .send()
        .await
        .unwrap();
    assert_eq!(print.status(), reqwest::StatusCode::OK);
    assert_eq!(
        mock.last_path.lock().unwrap().as_str(),
        "/printers/FakePrinter"
    );
    assert_eq!(
        mock.last_body.lock().unwrap().as_slice(),
        b"%!PS process-e2e"
    );
}
