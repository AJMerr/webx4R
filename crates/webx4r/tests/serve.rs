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

/// Reads log lines until the server reports its `scheme` address; returns it and the log before it.
fn listening_addr(stderr: &mut BufReader<ChildStderr>, scheme: &str) -> (String, String) {
    let marker = format!("listening on {scheme}://");
    let mut log = String::new();
    for line in stderr.lines() {
        let line = line.unwrap();
        if let Some(addr) = line.split(&marker).nth(1) {
            return (addr.trim().to_owned(), log);
        }
        log.push_str(&line);
        log.push('\n');
    }
    panic!("webx4r exited without reporting its {scheme} address:\n{log}");
}

fn get(addr: &str) -> String {
    get_path(addr, "/")
}

fn get_path(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn serves_the_configured_site() {
    let (_dir, config) = site();
    let (mut child, mut stderr) = serve(&config);
    let response = get(&listening_addr(&mut stderr, "http").0);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("hello from webx4r"), "{response}");
}

/// Starts an upstream that answers one request with the request line it received.
fn upstream() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut lines = BufReader::new(&stream).lines().map(Result::unwrap);
        let request_line = lines.next().unwrap();
        lines.take_while(|line| !line.is_empty()).for_each(drop);
        let body = format!("upstream saw {request_line}");
        let len = body.len();
        write!(
            &stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}"
        )
        .unwrap();
    });
    addr
}

#[test]
fn proxies_a_path_and_serves_the_rest() {
    let (_dir, config) = site();
    let text = format!(
        "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nroot = \"www\"\ndefault = true\n\
         [[site.proxy]]\npath = \"/app\"\nupstreams = [\"{}\"]\nstrip_prefix = true\n",
        upstream()
    );
    fs::write(&config, text).unwrap();
    let (mut child, mut stderr) = serve(&config);
    let addr = listening_addr(&mut stderr, "http").0;
    let proxied = get_path(&addr, "/app/hello?x=1");
    let static_page = get(&addr);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(proxied.ends_with("upstream saw GET /hello?x=1 HTTP/1.1"), "{proxied}");
    assert!(static_page.ends_with("hello from webx4r"), "{static_page}");
}

#[test]
fn serves_https_only_with_a_self_signed_localhost_cert() {
    let (_dir, config) = site();
    let text = "[server]\nhttps = \"127.0.0.1:0\"\n\
                [[site]]\nhosts = [\"localhost\"]\nroot = \"www\"\ndefault = true\n";
    fs::write(&config, text).unwrap();
    let (mut child, mut stderr) = serve(&config);
    let (addr, log) = listening_addr(&mut stderr, "https");
    let connected = TcpStream::connect(&addr);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(log.contains("using a self-signed certificate"), "{log}");
    assert!(!log.contains("listening on http://"), "{log}");
    connected.unwrap();
}

/// Reads log lines until one contains `needle`, and returns it.
fn wait_for_log(stderr: &mut BufReader<ChildStderr>, needle: &str) -> String {
    for line in stderr.lines() {
        let line = line.unwrap();
        if line.contains(needle) {
            return line;
        }
    }
    panic!("webx4r exited before logging {needle:?}");
}

#[cfg(unix)]
fn send_signal(child: &Child, name: &str) {
    let sent = Command::new("kill").arg(format!("-{name}")).arg(child.id().to_string()).status();
    assert!(sent.unwrap().success(), "kill -{name} failed");
}

#[cfg(unix)]
#[test]
fn sighup_reloads_the_config_file() {
    let (dir, config) = site();
    fs::create_dir(dir.path().join("www2")).unwrap();
    fs::write(dir.path().join("www2/index.html"), "reloaded site").unwrap();
    let (mut child, mut stderr) = serve(&config);
    let addr = listening_addr(&mut stderr, "http").0;

    let text = fs::read_to_string(&config).unwrap();
    fs::write(&config, text.replace("\"www\"", "\"www2\"")).unwrap();
    send_signal(&child, "HUP");
    wait_for_log(&mut stderr, "reloaded");
    let reloaded = get(&addr);

    fs::write(&config, "not a config").unwrap();
    send_signal(&child, "HUP");
    let failure = wait_for_log(&mut stderr, "reload failed");
    let kept = get(&addr);
    child.kill().unwrap();
    child.wait().unwrap();

    assert!(reloaded.ends_with("reloaded site"), "{reloaded}");
    assert!(failure.contains("webx4r.toml"), "names the file: {failure}");
    assert!(kept.ends_with("reloaded site"), "a failed reload keeps the old config: {kept}");
}

#[cfg(unix)]
#[test]
fn sigterm_shuts_down_cleanly() {
    let (dir, config) = site();
    let (mut child, mut stderr) = serve(&config);
    listening_addr(&mut stderr, "http");
    assert!(dir.path().join("webx4r.sock").exists(), "control socket next to the config");

    send_signal(&child, "TERM");
    let status = child.wait().unwrap();
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "{status}: {rest}");
    assert!(rest.contains("shutting down") && rest.contains("stopped"), "{rest}");
    assert!(!dir.path().join("webx4r.sock").exists(), "control socket removed on exit");
}

/// Runs `webx4r reload --config <config>`.
fn reload(config: &Path) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_webx4r"))
        .args(["reload", "--config"])
        .arg(config)
        .output()
        .unwrap();
    (output.status.code(), String::from_utf8_lossy(&output.stderr).into_owned())
}

#[test]
fn reload_command_applies_the_config_file() {
    let (dir, config) = site();
    fs::create_dir(dir.path().join("www2")).unwrap();
    fs::write(dir.path().join("www2/index.html"), "reloaded site").unwrap();
    let (mut child, mut stderr) = serve(&config);
    let addr = listening_addr(&mut stderr, "http").0;

    let text = fs::read_to_string(&config).unwrap();
    fs::write(&config, text.replace("\"www\"", "\"www2\"")).unwrap();
    let (applied, applied_log) = reload(&config);
    let reloaded = get(&addr);

    // Valid to parse, so only the server can tell it's wrong.
    fs::write(&config, text.replace("\"www\"", "\"missing\"")).unwrap();
    let (refused, refused_log) = reload(&config);
    let kept = get(&addr);
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(applied, Some(0), "{applied_log}");
    assert!(applied_log.contains("reloaded"), "{applied_log}");
    assert!(reloaded.ends_with("reloaded site"), "{reloaded}");
    assert_eq!(refused, Some(1), "{refused_log}");
    assert!(refused_log.contains("reload failed: site 1: can't open root"), "{refused_log}");
    assert!(kept.ends_with("reloaded site"), "a failed reload keeps the old config: {kept}");
}

#[test]
fn reload_without_a_server_says_so() {
    let (_dir, config) = site();
    let (code, log) = reload(&config);
    assert_eq!(code, Some(1));
    assert!(log.contains("is it running?"), "{log}");
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
