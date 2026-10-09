pub mod auth;
pub mod db;
pub mod ipp;
pub mod migrate;
pub mod pages;
pub mod proxy;
pub mod state;

/// CUPS upstream used by the reverse proxy. Override in tests with
/// `DRUKARKA_CUPS_HOST` / `DRUKARKA_CUPS_PORT`.
pub fn cups_upstream() -> (String, u16) {
    let host = std::env::var("DRUKARKA_CUPS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("DRUKARKA_CUPS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(shared::CUPS_LOCAL_PORT);
    (host, port)
}
