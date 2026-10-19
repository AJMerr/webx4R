//! End-to-end tests that run the real `webx4r` binary.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};

use tempfile::TempDir;

/// A temp folder with `www/index.html` and a `webx4r.toml` serving it on a random port.
fn site() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("www")).unwrap();
    fs::write(dir.path().join("www/index.html"), "hello from webx4r").unwrap();
    let config = dir.path().join("webx4r.toml");
    let text = "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nroot = \"www\"\ndefault = true\n";
    fs::write(&config, text).unwrap();
    (dir, config)
}

fn serve(config: &Path) -> (Child, BufReader<ChildStderr>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_webx4r"))
        .arg("serve")
        .arg("--config")
        .arg(config)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = BufReader::new(child.stderr.take().unwrap());
    (child, stderr)
}

/// Reads log lines until the server reports its address.
fn listening_addr(stderr: &mut BufReader<ChildStderr>) -> String {
    for line in stderr.lines() {
        let line = line.unwrap();
        if let Some(addr) = line.split("listening on http://").nth(1) {
            return addr.trim().to_owned();
        }
    }
    panic!("webx4r exited without reporting its address");
}

fn get(addr: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn serves_the_configured_site() {
    let (_dir, config) = site();
    let (mut child, mut stderr) = serve(&config);
    let response = get(&listening_addr(&mut stderr));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("hello from webx4r"), "{response}");
}

#[cfg(unix)]
#[test]
fn sigterm_shuts_down_cleanly() {
    let (_dir, config) = site();
    let (mut child, mut stderr) = serve(&config);
    listening_addr(&mut stderr);

    let killed = Command::new("kill").arg("-TERM").arg(child.id().to_string()).status().unwrap();
    assert!(killed.success());
    let status = child.wait().unwrap();
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "{status}: {rest}");
    assert!(rest.contains("shutting down") && rest.contains("stopped"), "{rest}");
}

#[test]
fn invalid_config_exits_with_an_error() {
    let (dir, config) = site();
    fs::write(&config, "[server]\nhttp = \"127.0.0.1:0\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_webx4r"))
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("config needs at least one [[site]]"), "{stderr}");
    drop(dir);
}

#[test]
fn missing_config_exits_with_an_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_webx4r"))
        .args(["serve", "--config", "/nonexistent/webx4r.toml"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("can't read /nonexistent/webx4r.toml"), "{stderr}");
}
