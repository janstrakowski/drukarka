use anyhow::Result;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;
use webauthn_rs::prelude::*;

use crate::db;
use crate::migrate;

pub struct AppState {
    pub db_path: PathBuf,
    pub db: Mutex<Connection>,
    pub webauthn: Webauthn,
    pub cups_host: String,
    pub cups_port: u16,
}

impl AppState {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let (host, port) = crate::cups_upstream();
        Self::with_cups(db_path, host, port)
    }

    pub fn with_cups(db_path: PathBuf, cups_host: String, cups_port: u16) -> Result<Self> {
        let conn = db::open(&db_path)?;
        migrate::apply(&conn)?;
        let rp_id = shared::DOMAIN.to_string();
        let rp_origin = Url::parse(&format!("https://{}", shared::DOMAIN))?;
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?.rp_name("drukarka");
        let webauthn = builder.build()?;
        Ok(Self {
            db_path,
            db: Mutex::new(conn),
            webauthn,
            cups_host,
            cups_port,
        })
    }
}
