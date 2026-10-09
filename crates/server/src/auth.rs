use anyhow::{bail, Context, Result};
use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const SESSION_COOKIE: &str = "drukarka_session";
const SESSION_HOURS: i64 = 12;
const ENROLL_MINUTES: i64 = 30;

#[derive(Clone)]
pub struct AdminUser {
    pub handle: Uuid,
}

impl AdminUser {
    pub fn fixed() -> Self {
        // Stable handle so credentials stay tied to one admin identity.
        Self {
            handle: Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
        }
    }
}

pub fn session_cookie_header(id: &str) -> String {
    format!(
        "{SESSION_COOKIE}={id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        SESSION_HOURS * 3600
    )
}

pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
}

pub fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(v.to_string());
        }
    }
    None
}

pub fn valid_session(conn: &Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sessions WHERE id = ?1 AND expires_at > datetime('now')",
        [id],
        |_| Ok(()),
    )
    .is_ok()
}

pub fn create_session(conn: &Connection) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let exp = (Utc::now() + Duration::hours(SESSION_HOURS))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    conn.execute(
        "INSERT INTO sessions (id, expires_at) VALUES (?1, ?2)",
        params![id, exp],
    )?;
    Ok(id)
}

pub fn destroy_session(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE id = ?1", [id])?;
    Ok(())
}

pub fn create_enroll_link(conn: &Connection) -> Result<String> {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let exp = (Utc::now() + Duration::minutes(ENROLL_MINUTES))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    conn.execute(
        "INSERT INTO enroll_tokens (token, expires_at, used) VALUES (?1, ?2, 0)",
        params![token, exp],
    )?;
    Ok(format!(
        "https://{}/enroll?token={token}",
        shared::DOMAIN
    ))
}

pub fn consume_enroll_token(conn: &Connection, token: &str) -> Result<()> {
    let changed = conn.execute(
        "UPDATE enroll_tokens SET used = 1
         WHERE token = ?1 AND used = 0 AND expires_at > datetime('now')",
        [token],
    )?;
    if changed != 1 {
        bail!("invalid or expired enroll token");
    }
    Ok(())
}

pub fn peek_enroll_token(conn: &Connection, token: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM enroll_tokens WHERE token = ?1 AND used = 0 AND expires_at > datetime('now')",
        [token],
        |_| Ok(()),
    )
    .is_ok()
}

pub fn load_passkeys(conn: &Connection) -> Result<Vec<Passkey>> {
    let mut stmt = conn.prepare("SELECT public_key FROM credentials")?;
    let rows = stmt.query_map([], |r| {
        let blob: Vec<u8> = r.get(0)?;
        Ok(blob)
    })?;
    let mut out = Vec::new();
    for row in rows {
        let blob = row?;
        let pk: Passkey = serde_json::from_slice(&blob).context("decode passkey")?;
        out.push(pk);
    }
    Ok(out)
}

pub fn store_passkey(conn: &Connection, passkey: &Passkey) -> Result<()> {
    let id = passkey.cred_id().to_vec();
    let blob = serde_json::to_vec(passkey)?;
    let handle = AdminUser::fixed().handle.as_bytes().to_vec();
    conn.execute(
        "INSERT INTO credentials (id, user_handle, public_key, sign_count, created_at)
         VALUES (?1, ?2, ?3, 0, datetime('now'))
         ON CONFLICT(id) DO UPDATE SET public_key = excluded.public_key",
        params![id, handle, blob],
    )?;
    Ok(())
}

pub fn update_passkey(conn: &Connection, passkey: &Passkey) -> Result<()> {
    let id = passkey.cred_id().to_vec();
    let blob = serde_json::to_vec(passkey)?;
    conn.execute(
        "UPDATE credentials SET public_key = ?1 WHERE id = ?2",
        params![blob, id],
    )?;
    Ok(())
}

pub fn list_passkey_summaries(conn: &Connection) -> Result<Vec<PasskeySummary>> {
    let mut stmt = conn.prepare("SELECT id, created_at FROM credentials ORDER BY created_at")?;
    let rows = stmt.query_map([], |r| {
        let id: Vec<u8> = r.get(0)?;
        let created: String = r.get(1)?;
        Ok(PasskeySummary {
            id_hex: hex::encode(&id),
            created_at: created,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn delete_passkey(conn: &Connection, id_hex: &str) -> Result<()> {
    let id = hex::decode(id_hex).context("hex id")?;
    let n = conn.execute("DELETE FROM credentials WHERE id = ?1", [id])?;
    if n == 0 {
        bail!("passkey not found");
    }
    Ok(())
}

#[derive(Serialize)]
pub struct PasskeySummary {
    pub id_hex: String,
    pub created_at: String,
}

pub fn origin_ok(headers: &HeaderMap) -> bool {
    let expected = format!("https://{}", shared::DOMAIN);
    if let Some(o) = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return o == expected;
    }
    if let Some(r) = headers.get(axum::http::header::REFERER).and_then(|v| v.to_str().ok()) {
        return r.starts_with(&format!("{expected}/"));
    }
    false
}

pub fn require_session(db: &Mutex<Connection>, headers: &HeaderMap) -> Result<String> {
    let id = session_id_from_headers(headers).context("no session")?;
    let conn = db.lock().unwrap();
    if !valid_session(&conn, &id) {
        bail!("invalid session");
    }
    Ok(id)
}

pub fn token_fingerprint(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate;
    use axum::http::HeaderMap;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        migrate::apply(&conn).unwrap();
        conn
    }

    #[test]
    fn enroll_token_single_use() {
        let conn = fresh_db();
        let url = create_enroll_link(&conn).unwrap();
        let token = url.split("token=").nth(1).unwrap();
        assert!(peek_enroll_token(&conn, token));
        consume_enroll_token(&conn, token).unwrap();
        assert!(!peek_enroll_token(&conn, token));
        assert!(consume_enroll_token(&conn, token).is_err());
    }

    #[test]
    fn session_roundtrip() {
        let conn = fresh_db();
        let id = create_session(&conn).unwrap();
        assert!(valid_session(&conn, &id));
        destroy_session(&conn, &id).unwrap();
        assert!(!valid_session(&conn, &id));
    }

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "foo=1; drukarka_session=abc; bar=2".parse().unwrap(),
        );
        assert_eq!(session_id_from_headers(&h).as_deref(), Some("abc"));
    }

    #[test]
    fn origin_check() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::ORIGIN,
            "https://drukarka.local".parse().unwrap(),
        );
        assert!(origin_ok(&h));
        h.insert(
            axum::http::header::ORIGIN,
            "https://evil.example".parse().unwrap(),
        );
        assert!(!origin_ok(&h));
    }
}
