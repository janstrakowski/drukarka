use anyhow::{Context, Result};
use rusqlite::Connection;

/// Ordered migrations. Append new ones; never renumber.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_init",
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            id BLOB PRIMARY KEY,
            user_handle BLOB NOT NULL,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            transports TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS enroll_tokens (
            token TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL
        );
        "#,
    ),
];

pub fn apply(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );",
    )?;
    for (id, sql) in MIGRATIONS {
        let already: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE id = ?1)",
                [id],
                |r| r.get(0),
            )
            .unwrap_or(false);
        if already {
            continue;
        }
        conn.execute_batch(sql)
            .with_context(|| format!("migration {id}"))?;
        conn.execute(
            "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, datetime('now'))",
            [id],
        )?;
        tracing::info!("applied migration {id}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn).unwrap();
        apply(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert!(n >= 1);
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))
            .unwrap();
    }
}
