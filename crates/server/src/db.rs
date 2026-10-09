use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let conn = Connection::open(path).with_context(|| format!("open db {}", path.display()))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;",
    )?;
    Ok(conn)
}

pub fn open_mutex(path: &Path) -> Result<std::sync::Mutex<Connection>> {
    Ok(std::sync::Mutex::new(open(path)?))
}
