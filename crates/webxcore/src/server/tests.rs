use std::fs;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::*;
use crate::tls::tests::write_pair;

/// A running server on random ports with sites `a.test`, `b.test` and optionally a default.
struct Running {
    http: Option<SocketAddr>,
    https: Option<SocketAddr>,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<()>,
    dir: TempDir,
}

impl Running {
    /// Plain HTTP only.
    async fn start(with_default: bool) -> Self {
        let mut text = String::from(
            "[server]\nhttp = \"127.0.0.1:0\"\n\
             [[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
             [[site]]\nhosts = [\"b.test\"]\nroot = \"b\"\n",
        );
        if with_default {
            text.push_str("[[site]]\nroot = \"fallback\"\ndefault = true\n");
        }
        Self::start_with(tempfile::tempdir().unwrap(), &text).await
    }

    /// HTTPS with a self-signed cert per site, plus HTTP if `with_http`.
    async fn start_tls(with_http: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "a.test");
        write_pair(dir.path(), "b.test");
        let http = if with_http { "http = \"127.0.0.1:0\"\n" } else { "" };
        let text = format!(
            "[server]\n{http}https = \"127.0.0.1:0\"\n\
             [[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\ncert = \"a.test.crt\"\nkey = \"a.test.key\"\n\
             [[site]]\nhosts = [\"b.test\"]\nroot = \"b\"\ncert = \"b.test.crt\"\nkey = \"b.test.key\"\n"
        );
        Self::start_with(dir, &text).await
    }

    async fn start_with(dir: TempDir, config: &str) -> Self {
        for (name, body) in [("a", "site a"), ("b", "site b"), ("fallback", "fallback")] {
            fs::create_dir(dir.path().join(name)).unwrap();
            fs::write(dir.path().join(name).join("index.html"), body).unwrap();
        }
        let config = Config::parse(config, dir.path()).unwrap();

        let server = Server::bind(&config).await.unwrap();
        let (http, https) = (server.http_addr(), server.https_addr());
        let (stop, stopped) = oneshot::channel();
        let done = tokio::spawn(server.run(async {
            let _ = stopped.await;
        }));
        Self { http, https, stop: Some(stop), done, dir }
    }

    /// Opens a TLS connection with SNI `host`, offering `alpn` and trusting only that site's cert.
    async fn tls(&self, host: &str, alpn: &[u8]) -> TlsStream<TcpStream> {
        let cert = self.dir.path().join(format!("{host}.crt"));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_file(cert).unwrap()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];

        let tcp = TcpStream::connect(self.https.unwrap()).await.unwrap();
        let name = ServerName::try_from(host.to_owned()).unwrap();
        TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap()
    }

    /// Sends a raw HTTP/1.1 request and returns the whole response as text.
    async fn raw(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(self.http.unwrap()).await.unwrap();
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

/// Sends `GET https://{host}/` with the protocol ALPN chose; returns the version and body.
async fn get_tls(stream: TlsStream<TcpStream>, host: &str) -> (Version, Bytes) {
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(stream);
    let req = Request::get(format!("https://{host}/")).body(Empty::<Bytes>::new()).unwrap();
    let res = if h2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await.unwrap();
        tokio::spawn(conn);
        sender.send_request(req).await.unwrap()
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        sender.send_request(req).await.unwrap()
    };
    (res.version(), res.into_body().collect().await.unwrap().to_bytes())
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
    let stream = TcpStream::connect(server.http.unwrap()).await.unwrap();
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
async fn missing_cert_fails_at_bind() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("a")).unwrap();
    let text = "[server]\nhttps = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
                cert = \"nope.crt\"\nkey = \"nope.key\"\n";
    let config = Config::parse(text, dir.path()).unwrap();
    let err = Server::bind(&config).await.err().unwrap();
    assert!(err.to_string().starts_with("site 1: can't load"), "{err}");
}

#[tokio::test]
async fn serves_https_by_sni_and_alpn() {
    let server = Running::start_tls(false).await;
    assert_eq!(server.http, None);
    for (alpn, version) in [(&b"h2"[..], Version::HTTP_2), (b"http/1.1", Version::HTTP_11)] {
        for (host, body) in [("a.test", "site a"), ("b.test", "site b")] {
            let stream = server.tls(host, alpn).await;
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(alpn));
            assert_eq!(get_tls(stream, host).await, (version, Bytes::from(body)));
        }
    }
    server.stop().await;
}

#[tokio::test]
async fn serves_http_and_https_together() {
    let server = Running::start_tls(true).await;
    assert!(server.get("a.test").await.ends_with("site a"));
    let (_, body) = get_tls(server.tls("b.test", b"h2").await, "b.test").await;
    assert_eq!(body, "site b");
    server.stop().await;
}

#[tokio::test]
async fn failed_handshake_leaves_the_listener_running() {
    let server = Running::start_tls(false).await;
    let mut plain = TcpStream::connect(server.https.unwrap()).await.unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
    // The server drops the connection; a reset instead of a clean close is fine.
    let _ = plain.read_to_end(&mut Vec::new()).await;

    let (_, body) = get_tls(server.tls("a.test", b"h2").await, "a.test").await;
    assert_eq!(body, "site a");
    server.stop().await;
}

#[tokio::test]
async fn shutdown_stops_accepting() {
    let server = Running::start_tls(true).await;
    let addrs = [server.http.unwrap(), server.https.unwrap()];
    server.stop().await;
    for addr in addrs {
        assert!(TcpStream::connect(addr).await.is_err(), "{addr}");
    }
}
