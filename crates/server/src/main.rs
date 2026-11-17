use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use banshee_server::acme::AcmeConfig;
use banshee_server::{Config, Server};
use tracing::info;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// A setting that's set and not blank.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    // plain text when the output goes to `docker logs` rather than a terminal
    tracing_subscriber::fmt().with_ansi(std::io::stdout().is_terminal()).init();
    let config = Config {
        bind: env("BANSHEE_BIND", "0.0.0.0:7700").parse().context("BANSHEE_BIND")?,
        data_dir: PathBuf::from(env("BANSHEE_DATA", "data")),
        channels: env("BANSHEE_CHANNELS", "Lobby,Gaming,AFK")
            .split(',')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect(),
        max_file: env("BANSHEE_MAX_FILE_MB", "500").parse::<u64>().context("BANSHEE_MAX_FILE_MB")? * 1_000_000,
        tls_files: match (var("BANSHEE_TLS_CERT"), var("BANSHEE_TLS_KEY")) {
            (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
            (None, None) => None,
            _ => anyhow::bail!("BANSHEE_TLS_CERT and BANSHEE_TLS_KEY go together"),
        },
        acme: match var("BANSHEE_DOMAIN") {
            Some(domain) => Some(AcmeConfig {
                domain,
                email: std::env::var("BANSHEE_ACME_EMAIL").ok().filter(|e| !e.trim().is_empty()),
                http: env("BANSHEE_ACME_HTTP", "0.0.0.0:8080").parse().context("BANSHEE_ACME_HTTP")?,
                staging: env("BANSHEE_ACME_STAGING", "") == "1",
                directory: std::env::var("BANSHEE_ACME_DIRECTORY").ok(),
                directory_root: std::env::var("BANSHEE_ACME_DIRECTORY_ROOT").ok().map(PathBuf::from),
            }),
            None => None,
        },
    };
    let domain = config.acme.as_ref().map(|a| a.domain.clone());
    let server = Server::bind(config)?;
    match &domain {
        Some(domain) => info!(addr = %server.local_addr()?, "listening; connect with banshee://{domain}"),
        None => info!(
            addr = %server.local_addr()?,
            "listening; connect with banshee://<address>#{}",
            server.fingerprint()
        ),
    }
    if let Some(token) = server.admin_token() {
        info!("redeem this token to become admin: {token}");
    }
    tokio::select! {
        () = server.run() => {}
        () = shutdown() => info!("shutting down"),
    }
    Ok(())
}

/// Ctrl+C, or SIGTERM from `docker stop`.
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
