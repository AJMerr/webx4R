use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A fresh endpoint: a socket in `dir` on Unix, a uniquely named pipe on Windows.
fn endpoint(dir: &Path) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    if cfg!(windows) {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(format!(r"\\.\pipe\webx4r-test-{}-{n}", std::process::id()))
    } else {
        dir.join("control.sock")
    }
}

/// Binds at `endpoint` and answers reloads with `outcome`, counting them.
fn serve(endpoint: &Path, outcome: Result<(), String>) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let listener = ControlListener::bind(endpoint).unwrap();
    tokio::spawn(listener.run(move || {
        counted.fetch_add(1, Ordering::Relaxed);
        outcome.clone()
    }));
    calls
}

#[tokio::test]
async fn reload_runs_the_handler() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    let calls = serve(&endpoint, Ok(()));
    assert_eq!(request_reload(&endpoint).await.unwrap(), Ok(()));
    assert_eq!(request_reload(&endpoint).await.unwrap(), Ok(()));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn failed_reload_is_reported_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    serve(&endpoint, Err("webx4r.toml: bad\nsecond line".to_owned()));
    let reply = request_reload(&endpoint).await.unwrap();
    assert_eq!(reply, Err("webx4r.toml: bad\nsecond line".to_owned()));
}

#[tokio::test]
async fn unknown_commands_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    let calls = serve(&endpoint, Ok(()));
    let reply = request(&endpoint, "restart").await.unwrap();
    assert_eq!(reply, "error: unknown command \"restart\"");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn second_listener_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    serve(&endpoint, Ok(()));
    let err = ControlListener::bind(&endpoint).err().unwrap();
    assert!(err.to_string().starts_with("can't listen on"), "{err}");
    #[cfg(unix)]
    assert!(err.to_string().ends_with("another webx4r is already listening there"), "{err}");
}

#[tokio::test]
async fn nobody_listening_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(request_reload(&endpoint(dir.path())).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn stale_socket_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    // Binding and dropping a std listener leaves the socket file behind, as a crash would.
    drop(std::os::unix::net::UnixListener::bind(&endpoint).unwrap());
    serve(&endpoint, Ok(()));
    assert_eq!(request_reload(&endpoint).await.unwrap(), Ok(()));
}

#[cfg(unix)]
#[tokio::test]
async fn other_files_are_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    std::fs::write(&endpoint, "important").unwrap();
    let err = ControlListener::bind(&endpoint).err().unwrap();
    assert!(err.to_string().ends_with("a file that isn't a socket is in the way"), "{err}");
    assert_eq!(std::fs::read_to_string(&endpoint).unwrap(), "important");
}

#[cfg(unix)]
#[tokio::test]
async fn socket_is_private_and_removed_on_drop() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let endpoint = endpoint(dir.path());
    let listener = ControlListener::bind(&endpoint).unwrap();
    let mode = std::fs::metadata(&endpoint).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    drop(listener);
    assert!(!endpoint.exists());
}
