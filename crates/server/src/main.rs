use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use banshee_server::{Config, Server};
use tracing::info;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
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
    };
    let server = Server::bind(config)?;
    info!(addr = %server.local_addr()?, fingerprint = server.fingerprint(), "listening");
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
