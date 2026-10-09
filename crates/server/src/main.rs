use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, Subcommand};
use server::{auth, db, ipp, migrate, pages, state};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "drukarka-server")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Serve {
        #[arg(long, default_value = shared::STATE_DB)]
        db: PathBuf,
        #[arg(long, default_value = "/etc/drukarka-ca/drukarka.crt")]
        cert: PathBuf,
        #[arg(long, default_value = "/etc/drukarka-ca/drukarka.key")]
        key: PathBuf,
        #[arg(long, default_value_t = shared::HTTPS_PORT)]
        https_port: u16,
        #[arg(long, default_value_t = shared::HTTP_PORT)]
        http_port: u16,
    },
    IppProxy {
        #[arg(long, default_value_t = shared::IPP_LISTEN_PORT)]
        listen: u16,
        #[arg(long, default_value = "127.0.0.1")]
        cups_host: String,
        #[arg(long, default_value_t = shared::CUPS_LOCAL_PORT)]
        cups_port: u16,
    },
    Migrate {
        #[arg(long, default_value = shared::STATE_DB)]
        db: PathBuf,
    },
    GenerateEnrollLink {
        #[arg(long, default_value = shared::STATE_DB)]
        db: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Command::Serve {
        db: PathBuf::from(shared::STATE_DB),
        cert: PathBuf::from("/etc/drukarka-ca/drukarka.crt"),
        key: PathBuf::from("/etc/drukarka-ca/drukarka.key"),
        https_port: shared::HTTPS_PORT,
        http_port: shared::HTTP_PORT,
    }) {
        Command::Serve {
            db,
            cert,
            key,
            https_port,
            http_port,
        } => serve(db, cert, key, https_port, http_port).await,
        Command::IppProxy {
            listen,
            cups_host,
            cups_port,
        } => ipp::run(listen, &cups_host, cups_port).await,
        Command::Migrate { db } => {
            let conn = db::open(&db)?;
            migrate::apply(&conn)?;
            println!("migrations ok");
            Ok(())
        }
        Command::GenerateEnrollLink { db } => {
            let conn = db::open(&db)?;
            migrate::apply(&conn)?;
            let url = auth::create_enroll_link(&conn)?;
            println!("{url}");
            Ok(())
        }
    }
}

async fn serve(
    db: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    https_port: u16,
    http_port: u16,
) -> Result<()> {
    let app_state = Arc::new(state::AppState::new(db)?);
    let app = pages::router(app_state);

    let redirect = axum::Router::new().fallback(axum::routing::any(
        |uri: axum::http::Uri| async move {
            let loc = format!("https://{}{}", shared::DOMAIN, uri);
            axum::response::Redirect::permanent(&loc)
        },
    ));
    let http_addr = SocketAddr::from(([0, 0, 0, 0], http_port));
    tokio::spawn(async move {
        if let Ok(listener) = tokio::net::TcpListener::bind(http_addr).await {
            tracing::info!("HTTP redirect on {http_addr}");
            let _ = axum::serve(listener, redirect).await;
        }
    });

    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("load tls {} / {}", cert.display(), key.display()))?;
    let https_addr = SocketAddr::from(([0, 0, 0, 0], https_port));
    tracing::info!("HTTPS listening on {https_addr}");
    axum_server::bind_rustls(https_addr, tls)
        .serve(app.into_make_service())
        .await
        .context("https serve")?;
    Ok(())
}
