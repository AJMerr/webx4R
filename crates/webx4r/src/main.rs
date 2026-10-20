//! `webx4r`: command-line interface for the webx4R app platform.

mod logging;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use webxcore::config::{Config, ConfigError};
use webxcore::control::{self, ControlListener};
use webxcore::server::{Reloader, Server};

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
    /// Make a running server reload its config file.
    Reload {
        /// Path to the config file the server was started with.
        #[arg(short, long, default_value = "webx4r.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => serve(&config).await,
        Command::Reload { config } => {
            let _ = logging::init(None);
            request_reload(&config).await
        }
    }
}

async fn serve(path: &Path) -> ExitCode {
    // Loaded first, since `[log]` decides where errors go; a bad config is reported on stderr.
    let config = Config::load(path);
    let logging = logging::init(config.as_ref().ok().and_then(|config| config.log.as_ref()));
    let config = match config {
        Ok(config) => config,
        Err(e) => return fail(describe(path, e)),
    };
    // Held until exit; dropping it flushes the log files.
    let mut logging = match logging {
        Ok(logging) => logging,
        Err(e) => return fail(e),
    };
    let mut server = match Server::bind(&config).await {
        Ok(server) => server,
        Err(e) => return fail(e),
    };
    if let Some(access) = logging.access.take() {
        server.set_access_log(access);
    }
    let control = match ControlListener::bind(&config.control_endpoint()) {
        Ok(control) => control,
        Err(e) => return fail(e),
    };
    if let Some(addr) = server.http_addr() {
        tracing::info!("listening on http://{addr}");
    }
    if let Some(addr) = server.https_addr() {
        tracing::info!("listening on https://{addr}");
    }
    tracing::info!("`webx4r reload` reaches this server at {}", control.endpoint().display());

    // Registered before serving: until a handler exists, SIGHUP would kill the process.
    #[cfg(unix)]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hangups) => {
            tokio::spawn(reload_on_hangup(hangups, path.to_owned(), server.reloader()));
        }
        Err(e) => tracing::warn!(error = %e, "can't listen for SIGHUP"),
    }

    let on_reload = {
        let (path, reloader) = (path.to_owned(), server.reloader());
        move || reload(&path, &reloader)
    };
    // The control loop never ends; it's dropped, removing its socket, once the server stops.
    tokio::select! {
        () = server.run(shutdown_signal()) => {}
        () = control.run(on_reload) => {}
    }
    tracing::info!("stopped");
    ExitCode::SUCCESS
}

/// `webx4r reload`: asks the server over its control socket and reports the outcome.
async fn request_reload(path: &Path) -> ExitCode {
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(e) => return fail(format!("reload failed: {}", describe(path, e))),
    };
    let endpoint = config.control_endpoint();
    match control::request_reload(&endpoint).await {
        Ok(Ok(())) => {
            tracing::info!("reloaded {}", path.display());
            ExitCode::SUCCESS
        }
        Ok(Err(e)) => fail(format!("reload failed: {e}")),
        Err(e) => {
            fail(format!("can't reach webx4r at {}: {e}; is it running?", endpoint.display()))
        }
    }
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

/// Re-reads and applies the config file, logging the outcome; on failure, the old config stays.
fn reload(path: &Path, reloader: &Reloader) -> Result<(), String> {
    let result = Config::load(path)
        .map_err(|e| describe(path, e))
        .and_then(|config| reloader.reload(&config).map_err(|e| e.to_string()));
    match &result {
        Ok(()) => tracing::info!("reloaded {}", path.display()),
        Err(e) => tracing::error!("reload failed: {e}"),
    }
    result
}

/// Reloads on each SIGHUP, as sent by `systemctl reload` or `kill -HUP`.
#[cfg(unix)]
async fn reload_on_hangup(
    mut hangups: tokio::signal::unix::Signal,
    path: PathBuf,
    reloader: Reloader,
) {
    while hangups.recv().await.is_some() {
        // `reload` logs the outcome, and there's no one else to tell.
        let _ = reload(&path, &reloader);
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
