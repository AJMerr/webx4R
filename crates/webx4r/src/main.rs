//! `webx4r`: command-line interface for the webx4R app platform.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use webxcore::config::{Config, ConfigError};
use webxcore::server::Server;

/// Log filter variable, e.g. `WEBX4R_LOG=debug`.
const LOG_ENV: &str = "WEBX4R_LOG";

#[derive(Parser)]
#[command(version, about = "The webx4R app platform")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the sites in a config file.
    Serve {
        /// Path to the config file.
        #[arg(short, long, default_value = "webx4r.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    match cli.command {
        Command::Serve { config } => serve(&config).await,
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
}

async fn serve(path: &Path) -> ExitCode {
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(e @ ConfigError::Read { .. }) => return fail(e),
        Err(e) => return fail(format!("{}: {e}", path.display())),
    };
    let server = match Server::bind(&config).await {
        Ok(server) => server,
        Err(e) => return fail(e),
    };
    match server.local_addr() {
        Ok(addr) => tracing::info!("listening on http://{addr}"),
        Err(e) => return fail(e),
    }

    server.run(shutdown_signal()).await;
    tracing::info!("stopped");
    ExitCode::SUCCESS
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    tracing::error!("{error}");
    ExitCode::FAILURE
}

/// Resolves on Ctrl-C, or on SIGTERM (sent by `systemctl stop`, `kill` and Docker) on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "can't listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "can't listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
