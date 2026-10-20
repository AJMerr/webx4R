//! Where logs go: the server log to stderr, or with `[log] dir`, the server log and the
//! access log to files there, one per day.

use std::io::{self, IsTerminal, Write};

use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use webxcore::access_log::AccessLog;
use webxcore::config::Log;

/// Log filter variable, e.g. `WEBX4R_LOG=debug`.
const LOG_ENV: &str = "WEBX4R_LOG";

/// Keeps the log files' writer threads running; dropping it flushes them.
#[derive(Default)]
pub struct Logging {
    _guards: Vec<WorkerGuard>,
    /// Present with `[log]`.
    pub access: Option<AccessLog>,
}

/// Sets up logging for `log`, or stderr without it. If the files can't be opened, logs to
/// stderr instead and returns the error.
pub fn init(log: Option<&Log>) -> io::Result<Logging> {
    let Some(log) = log else {
        stderr();
        return Ok(Logging::default());
    };
    let [(server, server_guard), (access, access_guard)] = match writers(log) {
        Ok(writers) => writers,
        Err(e) => {
            stderr();
            return Err(e);
        }
    };
    tracing_subscriber::fmt().json().with_env_filter(filter()).with_writer(server).init();
    // The only line on stderr, so a terminal shows where everything went.
    eprintln!("webx4r: logging to {}", log.dir.display());
    let access = AccessLog::new(log.access_format, move |line| {
        // One call per line, and so one message to the writer thread: lines never interleave.
        let _ = access.clone().write_all(line);
    });
    Ok(Logging { _guards: vec![server_guard, access_guard], access: Some(access) })
}

fn stderr() {
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .init();
}

fn filter() -> EnvFilter {
    EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"))
}

/// The server log's and the access log's writers.
fn writers(log: &Log) -> io::Result<[(NonBlocking, WorkerGuard); 2]> {
    // Made here: the appender reports a missing folder on stderr before creating it.
    std::fs::create_dir_all(&log.dir).map_err(|e| unwritable(log, e))?;
    Ok([writer(log, "server")?, writer(log, "access")?])
}

/// `<name>.<date>.log` files in `log.dir`, a new one each midnight UTC, keeping `keep_days`.
/// Writes happen on their own thread, off the request path.
fn writer(log: &Log, name: &str) -> io::Result<(NonBlocking, WorkerGuard)> {
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(name)
        .filename_suffix("log")
        .max_log_files(log.keep_days as usize)
        .build(&log.dir)
        .map_err(|e| unwritable(log, e))?;
    // Waits, rather than dropping lines, if the disk falls behind.
    let writer = NonBlockingBuilder::default().lossy(false).thread_name(&format!("{name}-log"));
    Ok(writer.finish(appender))
}

fn unwritable(log: &Log, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("can't write logs in {}: {error}", log.dir.display()))
}
