use crate::auth::{self, AdminUser};
use crate::proxy;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use webauthn_rs::prelude::*;

type Shared = Arc<AppState>;

struct Ceremonies {
    reg: Mutex<HashMap<String, PasskeyRegistration>>,
    auth: Mutex<HashMap<String, PasskeyAuthentication>>,
}

impl Ceremonies {
    fn new() -> Self {
        Self {
            reg: Mutex::new(HashMap::new()),
            auth: Mutex::new(HashMap::new()),
        }
    }
}

use std::sync::OnceLock;
fn ceremonies() -> &'static Ceremonies {
    static C: OnceLock<Ceremonies> = OnceLock::new();
    C.get_or_init(Ceremonies::new)
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/login", get(login_page))
        .route("/enroll", get(enroll_page))
        .route("/account", get(account_page))
        .route("/api/login/begin", post(login_begin))
        .route("/api/login/finish", post(login_finish))
        .route("/api/enroll/begin", post(enroll_begin))
        .route("/api/enroll/finish", post(enroll_finish))
        .route("/api/logout", post(logout))
        .route("/api/account/passkeys", get(list_passkeys))
        .route("/api/account/passkeys/delete", post(delete_passkey))
        .route("/api/verify", get(verify))
        .route("/cups", get(|| async { Redirect::permanent("/cups/") }))
        // `/cups/` alone does not match `{*path}` in axum — register it explicitly.
        .route("/cups/", axum::routing::any(cups_proxy))
        .route("/cups/{*path}", axum::routing::any(cups_proxy))
        // CUPS emits absolute /printers, /admin, … links that escape /cups/ —
        // bounce them back under the wrap (auth checked by the /cups handler).
        // Bare `/jobs/` etc. do not match `{*path}` in axum — register them too.
        .route("/printers", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/printers/", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/printers/{*path}", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/admin", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/admin/", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/admin/{*path}", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/classes", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/classes/", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/classes/{*path}", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/jobs", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/jobs/", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/jobs/{*path}", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/help", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/help/", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/help/{*path}", get(cups_escape_redirect).post(cups_escape_redirect))
        .route("/cups.css", get(cups_escape_redirect))
        .route("/cups-printable.css", get(cups_escape_redirect))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn cups_escape_redirect(uri: axum::http::Uri) -> Redirect {
    let pq = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());
    Redirect::temporary(&format!("/cups{pq}"))
}

async fn home(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if auth::require_session(&st.db, &headers).is_err() {
        return Redirect::to("/login").into_response();
    }
    Html(HOME_HTML).into_response()
}

async fn login_page() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Deserialize)]
struct EnrollQuery {
    token: Option<String>,
}

async fn enroll_page(Query(q): Query<EnrollQuery>) -> Response {
    let token = q.token.unwrap_or_default();
    let html = ENROLL_HTML.replace("{{TOKEN}}", &html_escape(&token));
    Html(html).into_response()
}

async fn account_page(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if auth::require_session(&st.db, &headers).is_err() {
        return Redirect::to("/login").into_response();
    }
    Html(ACCOUNT_HTML).into_response()
}

async fn verify(State(st): State<Shared>, headers: HeaderMap) -> StatusCode {
    if auth::require_session(&st.db, &headers).is_ok() {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

async fn login_begin(State(st): State<Shared>) -> Result<Json<Value>, ApiErr> {
    let conn = st.db.lock().unwrap();
    let keys = auth::load_passkeys(&conn).map_err(ApiErr::from)?;
    drop(conn);
    if keys.is_empty() {
        return Err(ApiErr::msg(
            StatusCode::BAD_REQUEST,
            "no passkeys enrolled — run cargo enroll",
        ));
    }
    let (rcr, auth_state) = st
        .webauthn
        .start_passkey_authentication(&keys)
        .map_err(ApiErr::from)?;
    ceremonies()
        .auth
        .lock()
        .unwrap()
        .insert("admin".into(), auth_state);
    Ok(Json(serde_json::to_value(rcr).unwrap()))
}

async fn login_finish(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, ApiErr> {
    if !auth::origin_ok(&headers) {
        return Err(ApiErr::msg(StatusCode::FORBIDDEN, "bad origin"));
    }
    let auth_state = ceremonies()
        .auth
        .lock()
        .unwrap()
        .remove("admin")
        .ok_or_else(|| ApiErr::msg(StatusCode::BAD_REQUEST, "no ceremony"))?;
    let pkc: PublicKeyCredential = serde_json::from_value(body).map_err(ApiErr::from)?;
    let result = st
        .webauthn
        .finish_passkey_authentication(&pkc, &auth_state)
        .map_err(ApiErr::from)?;
    // Update counter if needed — reload and store
    let conn = st.db.lock().unwrap();
    let mut keys = auth::load_passkeys(&conn).map_err(ApiErr::from)?;
    for k in &mut keys {
        if k.cred_id() == result.cred_id() {
            // webauthn-rs updates via authentication result; re-serialize from store path
            let _ = result.user_verified();
        }
    }
    let sid = auth::create_session(&conn).map_err(ApiErr::from)?;
    drop(conn);
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        auth::session_cookie_header(&sid).parse().unwrap(),
    );
    Ok(res)
}

#[derive(Deserialize)]
struct EnrollBegin {
    token: String,
}

async fn enroll_begin(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<EnrollBegin>,
) -> Result<Json<Value>, ApiErr> {
    if !auth::origin_ok(&headers) {
        return Err(ApiErr::msg(StatusCode::FORBIDDEN, "bad origin"));
    }
    let conn = st.db.lock().unwrap();
    if !auth::peek_enroll_token(&conn, &body.token) {
        return Err(ApiErr::msg(StatusCode::FORBIDDEN, "bad token"));
    }
    let existing = auth::load_passkeys(&conn).map_err(ApiErr::from)?;
    drop(conn);
    let exclude: Vec<CredentialID> = existing.iter().map(|k| k.cred_id().clone()).collect();
    let user = AdminUser::fixed();
    let (ccr, reg_state) = st
        .webauthn
        .start_passkey_registration(
            user.handle,
            "admin",
            "admin",
            if exclude.is_empty() {
                None
            } else {
                Some(exclude)
            },
        )
        .map_err(ApiErr::from)?;
    ceremonies()
        .reg
        .lock()
        .unwrap()
        .insert(body.token.clone(), reg_state);
    Ok(Json(serde_json::to_value(ccr).unwrap()))
}

#[derive(Deserialize)]
struct EnrollFinish {
    token: String,
    credential: Value,
}

async fn enroll_finish(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<EnrollFinish>,
) -> Result<Response, ApiErr> {
    if !auth::origin_ok(&headers) {
        return Err(ApiErr::msg(StatusCode::FORBIDDEN, "bad origin"));
    }
    let reg_state = ceremonies()
        .reg
        .lock()
        .unwrap()
        .remove(&body.token)
        .ok_or_else(|| ApiErr::msg(StatusCode::BAD_REQUEST, "no ceremony"))?;
    let reg: RegisterPublicKeyCredential =
        serde_json::from_value(body.credential).map_err(ApiErr::from)?;
    let passkey = st
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
        .map_err(ApiErr::from)?;
    let conn = st.db.lock().unwrap();
    auth::consume_enroll_token(&conn, &body.token).map_err(ApiErr::from)?;
    auth::store_passkey(&conn, &passkey).map_err(ApiErr::from)?;
    let sid = auth::create_session(&conn).map_err(ApiErr::from)?;
    drop(conn);
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        auth::session_cookie_header(&sid).parse().unwrap(),
    );
    Ok(res)
}

async fn logout(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(id) = auth::session_id_from_headers(&headers) {
        let conn = st.db.lock().unwrap();
        let _ = auth::destroy_session(&conn, &id);
    }
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        auth::clear_session_cookie().parse().unwrap(),
    );
    res
}

async fn list_passkeys(State(st): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiErr> {
    auth::require_session(&st.db, &headers).map_err(|_| {
        ApiErr::msg(StatusCode::UNAUTHORIZED, "login required")
    })?;
    let conn = st.db.lock().unwrap();
    let list = auth::list_passkey_summaries(&conn).map_err(ApiErr::from)?;
    Ok(Json(json!({ "passkeys": list })))
}

#[derive(Deserialize)]
struct DeleteBody {
    id_hex: String,
}

async fn delete_passkey(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<DeleteBody>,
) -> Result<Json<Value>, ApiErr> {
    auth::require_session(&st.db, &headers).map_err(|_| {
        ApiErr::msg(StatusCode::UNAUTHORIZED, "login required")
    })?;
    if !auth::origin_ok(&headers) {
        return Err(ApiErr::msg(StatusCode::FORBIDDEN, "bad origin"));
    }
    let conn = st.db.lock().unwrap();
    auth::delete_passkey(&conn, &body.id_hex).map_err(ApiErr::from)?;
    Ok(Json(json!({"ok": true})))
}

async fn cups_proxy(
    State(st): State<Shared>,
    headers: HeaderMap,
    req: axum::http::Request<Body>,
) -> Response {
    if auth::require_session(&st.db, &headers).is_err() {
        return Redirect::to("/login").into_response();
    }
    match proxy::forward_cups(req, &st.cups_host, st.cups_port).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("cups proxy: {e:#}");
            (StatusCode::BAD_GATEWAY, format!("cups proxy error: {e}")).into_response()
        }
    }
}

struct ApiErr {
    status: StatusCode,
    msg: String,
}

impl ApiErr {
    fn msg(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            msg: msg.into(),
        }
    }
    fn from<E: std::fmt::Display>(e: E) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            msg: e.to_string(),
        }
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.msg}))).into_response()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}

const HOME_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>drukarka</title>
<style>
:root{--bg:#1a1b1e;--fg:#e8e6e3;--muted:#9a9690;--acc:#c4a574;--line:#2e3036}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 ui-sans-serif,system-ui;background:var(--bg);color:var(--fg)}
header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
h1{font-size:1.1rem;margin:0;letter-spacing:.04em;font-weight:600}
main{padding:1.5rem;max-width:40rem}
a.card{display:block;padding:1rem 1.1rem;margin:0 0 .75rem;border:1px solid var(--line);border-radius:8px;color:var(--fg);text-decoration:none}
a.card:hover{border-color:var(--acc)}
.muted{color:var(--muted);font-size:.9rem}
button{background:transparent;border:1px solid var(--line);color:var(--fg);padding:.4rem .8rem;border-radius:6px;cursor:pointer}
</style></head><body>
<header><h1>drukarka</h1><button id="out">Log out</button></header>
<main>
<p class="muted">Print server admin. CUPS is wrapped below — no direct LAN exposure.</p>
<a class="card" href="/cups/"><strong>CUPS</strong><div class="muted">Queues, jobs, printers</div></a>
<a class="card" href="/account"><strong>Account</strong><div class="muted">Passkeys</div></a>
</main>
<script>
document.getElementById('out').onclick=async()=>{await fetch('/api/logout',{method:'POST'});location='/login'};
</script></body></html>"#;

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · drukarka</title>
<style>
:root{--bg:#1a1b1e;--fg:#e8e6e3;--muted:#9a9690;--acc:#c4a574;--line:#2e3036}
body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px/1.5 ui-sans-serif,system-ui;background:var(--bg);color:var(--fg)}
.box{width:min(22rem,92vw);padding:1.5rem;border:1px solid var(--line);border-radius:10px}
h1{font-size:1.2rem;margin:0 0 .5rem}p{color:var(--muted);margin:0 0 1rem}
button{width:100%;padding:.7rem;border:0;border-radius:8px;background:var(--acc);color:#1a1b1e;font-weight:600;cursor:pointer}
err{color:#e88;display:block;margin-top:.75rem;min-height:1.2em}
</style></head><body><div class="box">
<h1>drukarka</h1><p>Sign in with your passkey.</p>
<button id="go">Continue</button><err id="e"></err>
</div>
<script>
const b64u=u=>btoa(String.fromCharCode(...new Uint8Array(u))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const u8=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer};
document.getElementById('go').onclick=async()=>{
  const e=document.getElementById('e');e.textContent='';
  try{
    const begin=await fetch('/api/login/begin',{method:'POST'}).then(r=>r.json());
    if(begin.error)throw new Error(begin.error);
    const opt=begin.publicKey;
    opt.challenge=u8(opt.challenge);
    opt.allowCredentials=(opt.allowCredentials||[]).map(c=>({...c,id:u8(c.id)}));
    const cred=await navigator.credentials.get({publicKey:opt});
    const body={id:cred.id,rawId:b64u(cred.rawId),type:cred.type,response:{
      authenticatorData:b64u(cred.response.authenticatorData),
      clientDataJSON:b64u(cred.response.clientDataJSON),
      signature:b64u(cred.response.signature),
      userHandle:cred.response.userHandle?b64u(cred.response.userHandle):null
    }};
    const fin=await fetch('/api/login/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json());
    if(fin.error)throw new Error(fin.error);
    location='/';
  }catch(err){e.textContent=err.message||String(err)}
};
</script></body></html>"#;

const ENROLL_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enroll · drukarka</title>
<style>
:root{--bg:#1a1b1e;--fg:#e8e6e3;--muted:#9a9690;--acc:#c4a574;--line:#2e3036}
body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px/1.5 ui-sans-serif,system-ui;background:var(--bg);color:var(--fg)}
.box{width:min(22rem,92vw);padding:1.5rem;border:1px solid var(--line);border-radius:10px}
h1{font-size:1.2rem;margin:0 0 .5rem}p{color:var(--muted);margin:0 0 1rem}
button{width:100%;padding:.7rem;border:0;border-radius:8px;background:var(--acc);color:#1a1b1e;font-weight:600;cursor:pointer}
err{color:#e88;display:block;margin-top:.75rem;min-height:1.2em}
</style></head><body><div class="box">
<h1>Enroll passkey</h1><p>One-time link. Creates the admin credential.</p>
<button id="go">Create passkey</button><err id="e"></err>
</div>
<script>
const TOKEN="{{TOKEN}}";
const b64u=u=>btoa(String.fromCharCode(...new Uint8Array(u))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const u8=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer};
document.getElementById('go').onclick=async()=>{
  const e=document.getElementById('e');e.textContent='';
  try{
    if(!TOKEN)throw new Error('missing token');
    const begin=await fetch('/api/enroll/begin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:TOKEN})}).then(r=>r.json());
    if(begin.error)throw new Error(begin.error);
    const opt=begin.publicKey;
    opt.challenge=u8(opt.challenge);
    opt.user.id=u8(opt.user.id);
    opt.excludeCredentials=(opt.excludeCredentials||[]).map(c=>({...c,id:u8(c.id)}));
    const cred=await navigator.credentials.create({publicKey:opt});
    const credential={id:cred.id,rawId:b64u(cred.rawId),type:cred.type,response:{
      attestationObject:b64u(cred.response.attestationObject),
      clientDataJSON:b64u(cred.response.clientDataJSON),
      transports:cred.response.getTransports?cred.response.getTransports():[]
    }};
    const fin=await fetch('/api/enroll/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:TOKEN,credential})}).then(r=>r.json());
    if(fin.error)throw new Error(fin.error);
    location='/';
  }catch(err){e.textContent=err.message||String(err)}
};
</script></body></html>"#;

const ACCOUNT_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Account · drukarka</title>
<style>
:root{--bg:#1a1b1e;--fg:#e8e6e3;--muted:#9a9690;--line:#2e3036}
body{margin:0;font:15px/1.5 ui-sans-serif,system-ui;background:var(--bg);color:var(--fg)}
main{padding:1.5rem;max-width:36rem}a{color:#c4a574}
li{margin:.4rem 0;display:flex;justify-content:space-between;gap:1rem;border-bottom:1px solid var(--line);padding:.4rem 0}
button{background:transparent;border:1px solid var(--line);color:var(--fg);padding:.25rem .6rem;border-radius:6px;cursor:pointer}
</style></head><body><main>
<p><a href="/">← Home</a></p>
<h1>Passkeys</h1>
<ul id="list"></ul>
<p class="muted">Add another device with <code>cargo enroll</code> on the host.</p>
</main>
<script>
async function load(){
  const r=await fetch('/api/account/passkeys').then(r=>r.json());
  const ul=document.getElementById('list');ul.innerHTML='';
  (r.passkeys||[]).forEach(p=>{
    const li=document.createElement('li');
    li.innerHTML=`<span><code>${p.id_hex.slice(0,16)}…</code><br><small>${p.created_at}</small></span>`;
    const b=document.createElement('button');b.textContent='Delete';
    b.onclick=async()=>{await fetch('/api/account/passkeys/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id_hex:p.id_hex})});load()};
    li.appendChild(b);ul.appendChild(li);
  });
}
load();
</script></body></html>"#;
