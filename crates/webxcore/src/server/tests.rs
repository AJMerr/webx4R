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
use crate::proxy::tests::{echo_upstream, upgrade_upstream};
use crate::tls::tests::write_pair;

/// A running server on random ports with sites `a.test`, `b.test` and optionally a default.
struct Running {
    http: Option<SocketAddr>,
    https: Option<SocketAddr>,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<()>,
    reloader: Reloader,
    /// The config text the server started with.
    config: String,
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

    async fn start_with(dir: TempDir, text: &str) -> Self {
        for (name, body) in [("a", "site a"), ("b", "site b"), ("fallback", "fallback")] {
            fs::create_dir(dir.path().join(name)).unwrap();
            fs::write(dir.path().join(name).join("index.html"), body).unwrap();
        }
        let config = Config::parse(text, dir.path()).unwrap();

        let server = Server::bind(&config).await.unwrap();
        let (http, https) = (server.http_addr(), server.https_addr());
        let reloader = server.reloader();
        let (stop, stopped) = oneshot::channel();
        let done = tokio::spawn(server.run(async {
            let _ = stopped.await;
        }));
        Self { http, https, stop: Some(stop), done, reloader, config: text.to_owned(), dir }
    }

    /// Reloads with `config`, resolved against the same folder as the first one.
    fn reload(&self, config: &str) -> io::Result<()> {
        self.reloader.reload(&Config::parse(config, self.dir.path()).unwrap())
    }

    /// Opens a TLS connection with SNI `host`, offering `alpn` and trusting only that site's cert.
    async fn tls(&self, host: &str, alpn: &[u8]) -> TlsStream<TcpStream> {
        self.try_tls(host, alpn).await.unwrap()
    }

    async fn try_tls(&self, host: &str, alpn: &[u8]) -> io::Result<TlsStream<TcpStream>> {
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
        TlsConnector::from(Arc::new(config)).connect(name, tcp).await
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
        self.get_path(host, "/").await
    }

    async fn get_path(&self, host: &str, path: &str) -> String {
        self.raw(&format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")).await
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
async fn site_without_root_has_no_static_files() {
    let text = "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"c.test\"]\n\
                [[site.proxy]]\npath = \"/api\"\nupstreams = [\"127.0.0.1:9\"]\n";
    let server = Running::start_with(tempfile::tempdir().unwrap(), text).await;
    let response = server.get("c.test").await;
    assert!(response.starts_with("HTTP/1.1 404 Not Found"), "{response}");
    server.stop().await;
}

/// An address with nothing listening on it.
async fn closed_port() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

#[tokio::test]
async fn routes_paths_to_proxies_and_static_files() {
    let upstream = echo_upstream().await;
    let text = format!(
        "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
         [[site.proxy]]\npath = \"/api\"\nupstreams = [\"{upstream}\"]\n\
         [[site.proxy]]\npath = \"/api/v2/\"\nupstreams = [\"{upstream}\"]\nstrip_prefix = true\n"
    );
    let server = Running::start_with(tempfile::tempdir().unwrap(), &text).await;
    let body = |res: String| res.split_once("\r\n\r\n").unwrap().1.to_owned();

    assert_eq!(body(server.get("a.test").await), "site a");
    let api = body(server.get_path("a.test", "/api/users?page=2").await);
    assert!(api.starts_with("GET /api/users?page=2\n"), "{api}");
    assert!(api.contains("\nx-forwarded-for: 127.0.0.1\n"), "{api}");
    assert!(api.contains("\nx-forwarded-proto: http\n"), "{api}");
    let v2 = body(server.get_path("a.test", "/api/v2/users").await);
    assert!(v2.starts_with("GET /users\n"), "longest prefix wins, and is stripped: {v2}");
    assert!(body(server.get_path("a.test", "/api/v2").await).starts_with("GET /\n"));
    let other = server.get_path("a.test", "/apix").await;
    assert!(other.starts_with("HTTP/1.1 404"), "not a proxy path: {other}");
    server.stop().await;
}

#[tokio::test]
async fn proxies_https_requests_to_http_upstreams() {
    let upstream = echo_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    write_pair(dir.path(), "a.test");
    let text = format!(
        "[server]\nhttps = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\n\
         cert = \"a.test.crt\"\nkey = \"a.test.key\"\n\
         [[site.proxy]]\npath = \"/\"\nupstreams = [\"{upstream}\"]\n"
    );
    let server = Running::start_with(dir, &text).await;
    let (version, body) = get_tls(server.tls("a.test", b"h2").await, "a.test").await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(version, Version::HTTP_2);
    assert!(body.contains("\nhost: a.test\n"), "{body}");
    assert!(body.contains("\nx-forwarded-proto: https\n"), "{body}");
    server.stop().await;
}

#[tokio::test]
async fn upgrades_are_relayed_both_ways() {
    let upstream = upgrade_upstream().await;
    let text = format!(
        "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\n\
         [[site.proxy]]\npath = \"/ws\"\nupstreams = [\"{upstream}\"]\n"
    );
    let server = Running::start_with(tempfile::tempdir().unwrap(), &text).await;
    let mut stream = TcpStream::connect(server.http.unwrap()).await.unwrap();
    let request =
        "GET /ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 101 switching protocols"), "{head}");
    assert!(head.contains("\r\nconnection: upgrade\r\n"), "{head}");
    assert!(head.contains("\r\nupgrade: echo\r\n"), "{head}");

    for message in ["ping", "pong"] {
        stream.write_all(message.as_bytes()).await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, message.as_bytes());
    }
    drop(stream);
    server.stop().await;
}

#[tokio::test]
async fn unreachable_upstream_gets_a_502_page() {
    let upstream = closed_port().await;
    let text = format!(
        "[server]\nhttp = \"127.0.0.1:0\"\n\
         [[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
         [[site.proxy]]\npath = \"/api\"\nupstreams = [\"{upstream}\"]\n\
         [[site]]\nhosts = [\"c.test\"]\n\
         [[site.proxy]]\npath = \"/\"\nupstreams = [\"{upstream}\"]\n"
    );
    let server = Running::start_with(tempfile::tempdir().unwrap(), &text).await;
    fs::write(server.dir.path().join("a/502.html"), "custom 502").unwrap();

    let custom = server.get_path("a.test", "/api").await;
    assert!(custom.starts_with("HTTP/1.1 502 Bad Gateway"), "{custom}");
    assert!(custom.ends_with("custom 502"), "the site's own page: {custom}");
    let built_in = server.get("c.test").await;
    assert!(built_in.starts_with("HTTP/1.1 502 Bad Gateway"), "{built_in}");
    assert!(built_in.contains("upstream server"), "{built_in}");
    server.stop().await;
}

const SITE_A_IN: &str = "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\nroot = ";

#[tokio::test]
async fn reload_swaps_sites() {
    let server = Running::start(false).await;
    server.reload(&format!("{SITE_A_IN}\"b\"\n")).unwrap();
    assert!(server.get("a.test").await.ends_with("site b"), "a.test now serves b's root");
    let removed = server.get("b.test").await;
    assert!(removed.starts_with("HTTP/1.1 421"), "b.test is gone: {removed}");
    server.stop().await;
}

#[tokio::test]
async fn reload_applies_to_open_keep_alive_connections() {
    let server = Running::start(false).await;
    let stream = TcpStream::connect(server.http.unwrap()).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let get = || Request::get("/").header(HOST, "a.test").body(Empty::<Bytes>::new()).unwrap();

    let before = sender.send_request(get()).await.unwrap();
    assert_eq!(before.into_body().collect().await.unwrap().to_bytes(), "site a");
    server.reload(&format!("{SITE_A_IN}\"b\"\n")).unwrap();
    let after = sender.send_request(get()).await.unwrap();
    assert_eq!(after.into_body().collect().await.unwrap().to_bytes(), "site b");
    drop(sender);
    server.stop().await;
}

#[tokio::test]
async fn failed_reload_keeps_the_old_config() {
    let server = Running::start(false).await;
    let err = server.reload(&format!("{SITE_A_IN}\"missing\"\n")).unwrap_err();
    assert!(err.to_string().starts_with("site 1: can't open root"), "{err}");
    assert!(server.get("b.test").await.ends_with("site b"));

    let moved = format!("{SITE_A_IN}\"b\"\n").replace("127.0.0.1:0", "127.0.0.1:1");
    let err = server.reload(&moved).unwrap_err();
    assert_eq!(err.to_string(), "[server] settings changed; restart to apply them");
    assert!(server.get("b.test").await.ends_with("site b"));
    server.stop().await;
}

#[tokio::test]
async fn reload_serves_renewed_certificates() {
    let server = Running::start_tls(false).await;
    // Replaces a.test's files; until a reload, the server still has the old cert.
    write_pair(server.dir.path(), "a.test");
    assert!(server.try_tls("a.test", b"h2").await.is_err(), "old cert isn't trusted");

    server.reload(&server.config).unwrap();
    let (_, body) = get_tls(server.tls("a.test", b"h2").await, "a.test").await;
    assert_eq!(body, "site a");
    server.stop().await;
}

#[tokio::test]
async fn bad_certificate_fails_the_whole_reload() {
    let server = Running::start_tls(true).await;
    fs::write(server.dir.path().join("b.test.crt"), "").unwrap();
    let swapped_roots = server.config.replace("root = \"a\"", "root = \"b\"");
    let err = server.reload(&swapped_roots).unwrap_err();
    assert!(err.to_string().ends_with("no certificates found"), "{err}");
    assert!(server.get("a.test").await.ends_with("site a"), "sites weren't swapped either");
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
