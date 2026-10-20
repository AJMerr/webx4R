//! `webx4r`: command-line interface for the webx4R app platform.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use webxcore::config::{Config, ConfigError};
#[cfg(unix)]
use webxcore::server::Reloader;
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
        Err(e) => return fail(describe(path, e)),
    };
    let server = match Server::bind(&config).await {
        Ok(server) => server,
        Err(e) => return fail(e),
    };
    if let Some(addr) = server.http_addr() {
        tracing::info!("listening on http://{addr}");
    }
    if let Some(addr) = server.https_addr() {
        tracing::info!("listening on https://{addr}");
    }

    // Registered before serving: until a handler exists, SIGHUP would kill the process.
    #[cfg(unix)]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hangups) => {
            tokio::spawn(reload_on_hangup(hangups, path.to_owned(), server.reloader()));
        }
        Err(e) => tracing::warn!(error = %e, "can't listen for SIGHUP"),
    }

    server.run(shutdown_signal()).await;
    tracing::info!("stopped");
    ExitCode::SUCCESS
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    tracing::error!("{error}");
    ExitCode::FAILURE
}

/// A config error, naming the file unless the message already does.
fn describe(path: &Path, error: ConfigError) -> String {
    match error {
        e @ ConfigError::Read { .. } => e.to_string(),
        e => format!("{}: {e}", path.display()),
    }
}

/// Re-reads and applies the config file on each SIGHUP, as sent by `systemctl reload` or
/// `kill -HUP`. A failed reload is logged and the old config stays.
#[cfg(unix)]
async fn reload_on_hangup(
    mut hangups: tokio::signal::unix::Signal,
    path: PathBuf,
    reloader: Reloader,
) {
    while hangups.recv().await.is_some() {
        let result = Config::load(&path)
            .map_err(|e| describe(&path, e))
            .and_then(|config| reloader.reload(&config).map_err(|e| e.to_string()));
        match result {
            Ok(()) => tracing::info!("reloaded {}", path.display()),
            Err(e) => tracing::error!("reload failed: {e}"),
        }
    }
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
