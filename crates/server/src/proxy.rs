use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::OnceLock;

fn client() -> &'static Client<HttpConnector, Full<Bytes>> {
    static C: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();
    C.get_or_init(|| Client::builder(TokioExecutor::new()).build(HttpConnector::new()))
}

/// Forward authenticated requests under /cups/ to local CUPS, rewriting paths
/// so CUPS's absolute links stay under /cups/.
pub async fn forward_cups(
    req: Request<Body>,
    cups_host: &str,
    cups_port: u16,
) -> Result<Response<Body>> {
    let path = req.uri().path();
    let rest = path.strip_prefix("/cups").unwrap_or(path);
    let rest = if rest.is_empty() { "/" } else { rest };
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target: Uri = format!("http://{cups_host}:{cups_port}{rest}{query}")
        .parse()
        .context("target uri")?;

    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .context("read body")?
        .to_bytes();

    let mut outbound = Request::builder().method(method).uri(target);
    {
        let h = outbound.headers_mut().unwrap();
        for (k, v) in headers.iter() {
            if k == axum::http::header::HOST
                || k == axum::http::header::CONNECTION
                || k == axum::http::header::CONTENT_LENGTH
            {
                continue;
            }
            h.insert(k.clone(), v.clone());
        }
        // CUPS DNS-rebinding protection: only trust the upstream Host we chose.
        h.insert(
            axum::http::header::HOST,
            format!("{cups_host}:{cups_port}").parse().unwrap(),
        );
    }
    let outbound = outbound
        .body(Full::new(body_bytes))
        .context("build outbound")?;

    let resp = client().request(outbound).await.context("cups request")?;
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_body = resp.into_body().collect().await?.to_bytes();

    let content_type = resp_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let body_out = if content_type.contains("text/html")
        || content_type.contains("text/css")
        || content_type.contains("javascript")
    {
        Body::from(rewrite_cups_html(&String::from_utf8_lossy(&resp_body)))
    } else {
        Body::from(resp_body)
    };

    let mut out = Response::builder().status(status);
    {
        let h = out.headers_mut().unwrap();
        for (k, v) in resp_headers.iter() {
            if k == axum::http::header::TRANSFER_ENCODING
                || k == axum::http::header::CONTENT_LENGTH
                || k == axum::http::header::CONTENT_SECURITY_POLICY
            {
                continue;
            }
            if k == axum::http::header::LOCATION {
                if let Ok(loc) = v.to_str() {
                    h.insert(
                        axum::http::header::LOCATION,
                        rewrite_cups_location(loc).parse().unwrap_or(v.clone()),
                    );
                    continue;
                }
            }
            h.insert(k.clone(), v.clone());
        }
    }
    out.body(body_out).context("response")
}

pub fn rewrite_cups_html(s: &str) -> String {
    s.replace("href=\"/", "href=\"/cups/")
        .replace("href='/", "href='/cups/")
        .replace("href=/", "href=/cups/")
        .replace("src=\"/", "src=\"/cups/")
        .replace("src='/", "src='/cups/")
        .replace("action=\"/", "action=\"/cups/")
        .replace("action='/", "action='/cups/")
        .replace("action=/", "action=/cups/")
        .replace("url(/", "url(/cups/")
        // Avoid double-prefix if CUPS or a prior rewrite already used /cups/
        .replace("/cups/cups/", "/cups/")
}

pub fn rewrite_cups_location(loc: &str) -> String {
    if loc.starts_with("/cups/") || loc.starts_with("http") {
        return loc.to_string();
    }
    if let Some(rest) = loc.strip_prefix('/') {
        format!("/cups/{rest}")
    } else {
        loc.to_string()
    }
}

pub fn bad_gateway(msg: impl Into<String>) -> Response<Body> {
    (StatusCode::BAD_GATEWAY, msg.into()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_rewrites_absolute_links() {
        let html = r#"<a href="/printers/X">p</a><img src='/cups.css'><form action=/admin>"#;
        let out = rewrite_cups_html(html);
        assert!(out.contains("href=\"/cups/printers/X\""));
        assert!(out.contains("src='/cups/cups.css'") || out.contains("src=\"/cups/"));
        assert!(out.contains("action=/cups/admin"));
        assert!(!out.contains("/cups/cups/cups"));
    }

    #[test]
    fn html_dedupes_double_cups_prefix() {
        let html = r#"<a href="/cups/printers/X">"#;
        // first replace makes /cups/cups/… then dedupe
        let out = rewrite_cups_html(html);
        assert!(out.contains("/cups/printers/X"));
        assert!(!out.contains("/cups/cups/printers"));
    }

    #[test]
    fn location_rewrites_root_paths() {
        assert_eq!(
            rewrite_cups_location("/printers/HP_LaserJet_P1005"),
            "/cups/printers/HP_LaserJet_P1005"
        );
        assert_eq!(
            rewrite_cups_location("/cups/printers/X"),
            "/cups/printers/X"
        );
        assert_eq!(
            rewrite_cups_location("https://example/x"),
            "https://example/x"
        );
    }
}

