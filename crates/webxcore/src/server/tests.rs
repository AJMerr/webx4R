use std::fs;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioExecutor;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use super::*;

/// A running server on a random port with sites `a.test`, `b.test` and optionally a default.
struct Running {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

impl Running {
    async fn start(with_default: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [("a", "site a"), ("b", "site b"), ("fallback", "fallback")] {
            fs::create_dir(dir.path().join(name)).unwrap();
            fs::write(dir.path().join(name).join("index.html"), body).unwrap();
        }
        let mut text = String::from(
            "[server]\nhttp = \"127.0.0.1:0\"\n\
             [[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
             [[site]]\nhosts = [\"b.test\"]\nroot = \"b\"\n",
        );
        if with_default {
            text.push_str("[[site]]\nroot = \"fallback\"\ndefault = true\n");
        }
        let config = Config::parse(&text, dir.path()).unwrap();

        let server = Server::bind(&config).await.unwrap();
        let addr = server.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let done = tokio::spawn(server.run(async {
            let _ = stopped.await;
        }));
        Self { addr, stop: Some(stop), done, _dir: dir }
    }

    /// Sends a raw HTTP/1.1 request and returns the whole response as text.
    async fn raw(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    async fn get(&self, host: &str) -> String {
        self.raw(&format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")).await
    }

    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.done.await.unwrap();
    }
}

#[tokio::test]
async fn routes_by_host() {
    let server = Running::start(false).await;
    assert!(server.get("a.test").await.ends_with("site a"));
    assert!(server.get("b.test").await.ends_with("site b"));
    server.stop().await;
}

#[tokio::test]
async fn host_matching_ignores_case_port_and_trailing_dot() {
    let server = Running::start(false).await;
    assert!(server.get("A.Test:8080").await.ends_with("site a"));
    assert!(server.get("b.test.").await.ends_with("site b"));
    server.stop().await;
}

#[tokio::test]
async fn unknown_host_without_default_is_misdirected() {
    let server = Running::start(false).await;
    let response = server.get("other.test").await;
    assert!(response.starts_with("HTTP/1.1 421 Misdirected Request"), "{response}");
    assert!(response.contains("this server has no site for the requested hostname"));
    server.stop().await;
}

#[tokio::test]
async fn unknown_host_uses_the_default_site() {
    let server = Running::start(true).await;
    assert!(server.get("other.test").await.ends_with("fallback"));
    assert!(server.get("127.0.0.1").await.ends_with("fallback"));
    server.stop().await;
}

#[tokio::test]
async fn http11_without_host_is_a_bad_request() {
    let server = Running::start(true).await;
    let response = server.raw("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{response}");
    server.stop().await;
}

#[tokio::test]
async fn http10_without_host_uses_the_default_site() {
    let server = Running::start(true).await;
    assert!(server.raw("GET / HTTP/1.0\r\n\r\n").await.ends_with("fallback"));
    server.stop().await;
}

#[tokio::test]
async fn serves_http2_by_authority() {
    let server = Running::start(false).await;
    let stream = TcpStream::connect(server.addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);

    let req = Request::get("http://b.test/").body(Empty::<Bytes>::new()).unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.version(), Version::HTTP_2);
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), "site b");
    drop(sender);
    server.stop().await;
}

#[tokio::test]
async fn missing_root_fails_at_bind() {
    let dir = tempfile::tempdir().unwrap();
    let text =
        "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\nroot = \"nope\"\n";
    let config = Config::parse(text, dir.path()).unwrap();
    let err = Server::bind(&config).await.err().unwrap();
    assert!(err.to_string().starts_with("site 1: can't open root"), "{err}");
}

#[tokio::test]
async fn shutdown_stops_accepting() {
    let server = Running::start(false).await;
    let addr = server.addr;
    server.stop().await;
    assert!(TcpStream::connect(addr).await.is_err());
}
