//! Local control channel: `webx4r reload` asks a running server to reload its config over a
//! Unix socket, or a named pipe on Windows. The client sends one command line; the server
//! replies `ok` or `error: <message>` and closes the connection.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// How long a client gets to send its command.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest command line accepted, in bytes.
const MAX_COMMAND: u64 = 64;

/// Pause after a failed accept, as in the HTTP listeners.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

type OnReload = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// The server end of the control channel.
pub struct ControlListener {
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    /// The pipe instance the next client connects to.
    #[cfg(windows)]
    next: tokio::net::windows::named_pipe::NamedPipeServer,
    endpoint: PathBuf,
}

impl ControlListener {
    /// Fails if another server is already listening at `endpoint`.
    pub fn bind(endpoint: &Path) -> io::Result<Self> {
        Self::bind_inner(endpoint).map_err(|e| {
            io::Error::new(e.kind(), format!("can't listen on {}: {e}", endpoint.display()))
        })
    }

    #[cfg(unix)]
    fn bind_inner(endpoint: &Path) -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        match std::fs::symlink_metadata(endpoint) {
            Ok(meta) if !meta.file_type().is_socket() => {
                let msg = "a file that isn't a socket is in the way";
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, msg));
            }
            Ok(_) if std::os::unix::net::UnixStream::connect(endpoint).is_ok() => {
                let msg = "another webx4r is already listening there";
                return Err(io::Error::new(io::ErrorKind::AddrInUse, msg));
            }
            // A socket nobody answers on, left by a server that didn't shut down cleanly.
            Ok(_) => std::fs::remove_file(endpoint)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = tokio::net::UnixListener::bind(endpoint).map_err(|e| match e.kind() {
            // Most likely the path is too long for a socket.
            io::ErrorKind::InvalidInput => {
                io::Error::new(e.kind(), format!("{e}; set `[server] control` to a shorter path"))
            }
            _ => e,
        })?;
        std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, endpoint: endpoint.to_owned() })
    }

    #[cfg(windows)]
    fn bind_inner(endpoint: &Path) -> io::Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;

        // The first instance fails if another process already owns the pipe name.
        let next = ServerOptions::new().first_pipe_instance(true).create(endpoint)?;
        Ok(Self { next, endpoint: endpoint.to_owned() })
    }

    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Answers clients until dropped, calling `on_reload` for each `reload` command.
    pub async fn run(mut self, on_reload: impl Fn() -> Result<(), String> + Send + Sync + 'static) {
        let on_reload: OnReload = Arc::new(on_reload);
        loop {
            let stream = match self.accept().await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::warn!(error = %e, "control accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            let on_reload = Arc::clone(&on_reload);
            tokio::spawn(async move {
                if let Err(e) = answer(stream, on_reload).await {
                    tracing::debug!(error = %e, "control request failed");
                }
            });
        }
    }

    #[cfg(unix)]
    async fn accept(&mut self) -> io::Result<tokio::net::UnixStream> {
        Ok(self.listener.accept().await?.0)
    }

    #[cfg(windows)]
    async fn accept(&mut self) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        use tokio::net::windows::named_pipe::ServerOptions;

        self.next.connect().await?;
        // A fresh instance takes the next client while this one is answered.
        let next = ServerOptions::new().create(&self.endpoint)?;
        Ok(std::mem::replace(&mut self.next, next))
    }
}

#[cfg(unix)]
impl Drop for ControlListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.endpoint);
    }
}

/// Reads one command and replies to it.
async fn answer<S>(stream: S, on_reload: OnReload) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let mut command = String::new();
    let mut limited = (&mut stream).take(MAX_COMMAND);
    let read = limited.read_line(&mut command);
    tokio::time::timeout(READ_TIMEOUT, read).await.map_err(|_| io::ErrorKind::TimedOut)??;

    let reply = match command.trim_end() {
        // Reloading reads files and may generate keys, so it runs off the async threads.
        "reload" => match tokio::task::spawn_blocking(move || on_reload()).await {
            Ok(Ok(())) => "ok".to_owned(),
            Ok(Err(e)) => format!("error: {e}"),
            Err(e) => format!("error: reload panicked: {e}"),
        },
        other => format!("error: unknown command {other:?}"),
    };
    let stream = stream.get_mut();
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await
}

/// Asks the server at `endpoint` to reload. `Ok(Err(message))` means it tried and failed.
pub async fn request_reload(endpoint: &Path) -> io::Result<Result<(), String>> {
    let reply = request(endpoint, "reload").await?;
    Ok(match reply.strip_prefix("error: ") {
        Some(message) => Err(message.to_owned()),
        None if reply == "ok" => Ok(()),
        None => Err(format!("unexpected reply {reply:?}")),
    })
}

async fn request(endpoint: &Path, command: &str) -> io::Result<String> {
    let mut stream = connect(endpoint).await?;
    stream.write_all(format!("{command}\n").as_bytes()).await?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await?;
    Ok(reply)
}

#[cfg(unix)]
async fn connect(endpoint: &Path) -> io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(endpoint).await
}

#[cfg(windows)]
async fn connect(endpoint: &Path) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;

    /// Every pipe instance is taken; another frees up as soon as the server creates it.
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..20 {
        match ClientOptions::new().open(endpoint) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            result => return result,
        }
    }
    ClientOptions::new().open(endpoint)
}

#[cfg(test)]
mod tests;
