use std::fs;
use std::net::SocketAddr;
use std::sync::Mutex;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::*;
use crate::acme::Storage;
use crate::acme::pebble::{Pebble, free_port};
use crate::proxy::tests::{echo_upstream, upgrade_upstream};
use crate::tls::tests::write_pair;

/// A running server on random ports with sites `a.test`, `b.test` and optionally a default.
struct Running {
    http: Option<SocketAddr>,
    https: Option<SocketAddr>,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<()>,
    reloader: Reloader,
    challenges: Option<Arc<Challenges>>,
    metrics: Option<Arc<Metrics>>,
    /// Every access log entry so far, in JSON.
    access: Arc<Mutex<Vec<serde_json::Value>>>,
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
        Self::start_tls_with(with_http, "").await
    }

    /// Like [`Running::start_tls`], with `extra` added to the config.
    async fn start_tls_with(with_http: bool, extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "a.test");
        write_pair(dir.path(), "b.test");
        let http = if with_http { "http = \"127.0.0.1:0\"\n" } else { "" };
        let text = format!(
            "[server]\n{http}https = \"127.0.0.1:0\"\n\
             [[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\ncert = \"a.test.crt\"\nkey = \"a.test.key\"\n\
             [[site]]\nhosts = [\"b.test\"]\nroot = \"b\"\ncert = \"b.test.crt\"\nkey = \"b.test.key\"\n\
             {extra}"
        );
        Self::start_with(dir, &text).await
    }

    async fn start_with(dir: TempDir, text: &str) -> Self {
        for (name, body) in [("a", "site a"), ("b", "site b"), ("fallback", "fallback")] {
            fs::create_dir(dir.path().join(name)).unwrap();
            fs::write(dir.path().join(name).join("index.html"), body).unwrap();
        }
        let config = Config::parse(text, dir.path()).unwrap();

        let mut server = Server::bind(&config).await.unwrap();
        let access = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&access);
        server.set_access_log(AccessLog::new(config::AccessFormat::Json, move |line| {
            sink.lock().unwrap().push(serde_json::from_slice(line).unwrap());
        }));
        let (http, https) = (server.http_addr(), server.https_addr());
        let reloader = server.reloader();
        let (challenges, metrics) = (server.challenges.clone(), server.metrics());
        let (stop, stopped) = oneshot::channel();
        let done = tokio::spawn(server.run(async {
            let _ = stopped.await;
        }));
        let config = text.to_owned();
        let stop = Some(stop);
        Self { http, https, stop, done, reloader, challenges, metrics, access, config, dir }
    }

    /// Waits briefly for the metrics to contain every line in `lines`: like an access log
    /// entry, a response is counted when its body is dropped.
    async fn wait_for_metrics(&self, lines: &[&str]) {
        let metrics = self.metrics.as_ref().expect("the config has [metrics]");
        for _ in 0..100 {
            let text = metrics.encode();
            if lines.iter().all(|line| text.contains(&format!("{line}\n"))) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("expected {lines:#?} in:\n{}", metrics.encode());
    }

    /// The first `n` access log entries, waiting briefly: an entry is written when its body
    /// is dropped, which can come just after the client has the whole response.
    async fn access_entries(&self, n: usize) -> Vec<serde_json::Value> {
        for _ in 0..100 {
            {
                let entries = self.access.lock().unwrap();
                if entries.len() >= n {
                    return entries[..n].to_vec();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("fewer than {n} entries: {:?}", self.access.lock().unwrap());
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
async fn access_log_records_files_proxied_and_redirected_responses() {
    let upstream = echo_upstream().await;
    // Joins the last site, b.test.
    let sites = format!("[[site.proxy]]\npath = \"/\"\nupstreams = [\"{upstream}\"]\n");
    let server = Running::start_tls_with(true, &sites).await;
    let (_, body) = get_tls(server.tls("a.test", b"h2").await, "a.test").await;
    assert_eq!(body, "site a");
    let echoed = get_tls(server.tls("b.test", b"http/1.1").await, "b.test").await.1;
    let redirect = server.get_path("a.test", "/old?x=1").await;
    assert!(redirect.starts_with("HTTP/1.1 308"), "{redirect}");

    let entries = server.access_entries(3).await;
    let find = |uri: &str| entries.iter().find(|entry| entry["uri"] == uri).unwrap();
    let file = find("/");
    assert_eq!((&file["host"], &file["protocol"]), (&json!("a.test"), &json!("HTTP/2.0")));
    assert_eq!((&file["status"], &file["bytes"]), (&json!(200), &json!(6)));
    assert_eq!(file["client"], "127.0.0.1");
    let proxied = &entries.iter().find(|entry| entry["host"] == "b.test").unwrap();
    assert_eq!(proxied["upstream"], upstream.as_str(), "{proxied}");
    assert_eq!(proxied["bytes"], echoed.len());
    let redirected = find("/old?x=1");
    assert_eq!((&redirected["status"], &redirected["bytes"]), (&json!(308), &json!(0)));
    server.stop().await;
}

#[tokio::test]
async fn metrics_count_responses_per_site_across_reloads() {
    let text = "[server]\nhttp = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
                [[site]]\nroot = \"fallback\"\ndefault = true\n\
                [metrics]\nlisten = \"127.0.0.1:0\"\n";
    let server = Running::start_with(tempfile::tempdir().unwrap(), text).await;
    server.get("a.test").await;
    server.get_path("a.test", "/missing").await;
    server.get("unknown.test").await;
    server.raw("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").await;
    server
        .wait_for_metrics(&[
            "webx4r_http_responses_total{site=\"a.test\",code=\"2xx\"} 1",
            "webx4r_http_responses_total{site=\"a.test\",code=\"4xx\"} 1",
            "webx4r_http_responses_total{site=\"default\",code=\"2xx\"} 1",
            "webx4r_http_responses_total{site=\"none\",code=\"4xx\"} 1",
            "webx4r_http_response_body_bytes_total{site=\"default\"} 8",
        ])
        .await;

    server.reload(text).unwrap();
    server.get("a.test").await;
    let line = "webx4r_http_responses_total{site=\"a.test\",code=\"2xx\"} 2";
    server.wait_for_metrics(&[line]).await;
    server.stop().await;
}

#[tokio::test]
async fn metrics_count_connections_failures_and_reloads() {
    let unreachable = closed_port().await;
    // The proxy joins the last site, b.test.
    let extra = format!(
        "[[site.proxy]]\npath = \"/\"\nupstreams = [\"{unreachable}\"]\n\
         [metrics]\nlisten = \"127.0.0.1:0\"\n"
    );
    let server = Running::start_tls_with(true, &extra).await;
    let mut plain = TcpStream::connect(server.https.unwrap()).await.unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.unwrap();
    // The server drops the connection; a reset instead of a clean close is fine.
    let _ = plain.read_to_end(&mut Vec::new()).await;
    let (_, body) = get_tls(server.tls("b.test", b"h2").await, "b.test").await;
    assert!(String::from_utf8_lossy(&body).contains("502"), "{body:?}");
    assert!(server.get("a.test").await.starts_with("HTTP/1.1 308"));
    server.reload(&server.config).unwrap();
    server.reload(&server.config.replace("root = \"a\"", "root = \"missing\"")).unwrap_err();

    let upstream = format!(
        "webx4r_proxy_upstream_failures_total{{upstream=\"{unreachable}\",kind=\"connect\"}} 1"
    );
    server
        .wait_for_metrics(&[
            "webx4r_connections_total{listener=\"http\"} 1",
            "webx4r_connections_total{listener=\"https\"} 2",
            "webx4r_connections_open{listener=\"http\"} 0",
            "webx4r_tls_handshake_failures_total{reason=\"error\"} 1",
            &upstream,
            "webx4r_config_reloads_total{result=\"ok\"} 1",
            "webx4r_config_reloads_total{result=\"error\"} 1",
        ])
        .await;
    server.stop().await;
}

#[tokio::test]
async fn no_metrics_without_the_table() {
    let server = Running::start(false).await;
    assert!(server.metrics.is_none());
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
    let (_, body) = get_tls(server.tls("a.test", b"h2").await, "a.test").await;
    assert_eq!(body, "site a", "sites weren't swapped either");
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
async fn redirects_http_to_https_for_hosts_with_a_cert() {
    let server = Running::start_tls(true).await;
    let port = server.https.unwrap().port();
    let res = server.get_path("a.test", "/x/y?q=1").await;
    assert!(res.starts_with("HTTP/1.1 308"), "{res}");
    assert!(res.contains(&format!("\r\nlocation: https://a.test:{port}/x/y?q=1\r\n")), "{res}");
    let challenge = server.get_path("a.test", "/.well-known/acme-challenge/tok").await;
    assert!(challenge.starts_with("HTTP/1.1 404"), "ACME challenges stay on HTTP: {challenge}");

    let (_, body) = get_tls(server.tls("b.test", b"h2").await, "b.test").await;
    assert_eq!(body, "site b");
    server.stop().await;
}

#[tokio::test]
async fn no_redirect_when_opted_out_or_without_a_cert() {
    let sites = "[[site]]\nhosts = [\"c.test\"]\nroot = \"b\"\n\
                 cert = \"a.test.crt\"\nkey = \"a.test.key\"\nredirect_https = false\n\
                 [[site]]\nroot = \"fallback\"\ndefault = true\n";
    let server = Running::start_tls_with(true, sites).await;
    assert!(server.get("c.test").await.ends_with("site b"), "opted out");
    assert!(server.get("unknown.test").await.ends_with("fallback"), "no cert for this name");
    server.stop().await;
}

#[test]
fn redirect_location_omits_the_default_port() {
    let location = |port, uri: &str| {
        let res = redirect_to_https("a.test", port, &uri.parse().unwrap());
        res.headers()[LOCATION].to_str().unwrap().to_owned()
    };
    assert_eq!(location(443, "/a?b=c"), "https://a.test/a?b=c");
    assert_eq!(location(8443, "/a?b=c"), "https://a.test:8443/a?b=c");
    assert_eq!(location(443, "http://a.test"), "https://a.test/", "absolute form, no path");
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
async fn answers_http01_challenges_before_sites() {
    let path = "/.well-known/acme-challenge/tok";
    let plain = Running::start(false).await;
    assert!(plain.get_path("a.test", path).await.starts_with("HTTP/1.1 404"), "no [acme]");
    plain.stop().await;

    let server = Running::start_tls_with(true, "[acme]\n").await;
    server.challenges.as_ref().unwrap().add_http("tok", "tok.thumbprint");
    let res = server.get_path("a.test", path).await;
    assert!(res.starts_with("HTTP/1.1 200") && res.ends_with("\r\n\r\ntok.thumbprint"), "{res}");
    let other = server.get_path("a.test", "/.well-known/acme-challenge/other").await;
    assert!(other.starts_with("HTTP/1.1 404"), "unknown tokens go to the site: {other}");
    server.stop().await;
}

/// Accepts any server cert, for reading what a TLS-ALPN-01 handshake presents. It skips
/// signature checks too: rustls's parser rejects the critical acmeIdentifier extension.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crate::tls::provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Connects like a CA checking TLS-ALPN-01: SNI `host`, offering only `acme-tls/1`.
async fn acme_handshake(addr: SocketAddr, host: &str) -> io::Result<TlsStream<TcpStream>> {
    connect_any(addr, host, ACME_TLS_ALPN).await
}

/// Connects with SNI `host`, offering `alpn` and accepting whatever cert the server sends.
async fn connect_any(
    addr: SocketAddr,
    host: &str,
    alpn: &[u8],
) -> io::Result<TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(host.to_owned()).unwrap();
    TlsConnector::from(Arc::new(config)).connect(name, tcp).await
}

/// The leaf cert the server presents for `host`, and the body of `GET /` over that connection.
async fn served(addr: SocketAddr, host: &str) -> (CertificateDer<'static>, Bytes) {
    let stream = connect_any(addr, host, b"h2").await.unwrap();
    let leaf = stream.get_ref().1.peer_certificates().unwrap()[0].clone();
    (leaf, get_tls(stream, host).await.1)
}

#[tokio::test]
async fn serves_saved_acme_certs_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    // Nothing listens here, so the cert below can only come from storage.
    let directory = "https://127.0.0.1:1/dir";
    let names = vec!["a.test".to_owned()];
    let saved = rcgen::generate_simple_self_signed(names.clone()).unwrap();
    let storage = Storage::new(&dir.path().join("state"), directory);
    storage.save_cert(&names, &saved.signing_key.serialize_pem(), &saved.cert.pem()).unwrap();

    let text = format!(
        "[server]\nhttps = \"127.0.0.1:0\"\n[[site]]\nhosts = [\"a.test\"]\nroot = \"a\"\n\
         [acme]\ndirectory = \"{directory}\"\nstorage = \"state\"\n\
         [metrics]\nlisten = \"127.0.0.1:0\"\n"
    );
    let server = Running::start_with(dir, &text).await;
    let (leaf, body) = served(server.https.unwrap(), "a.test").await;
    assert_eq!(&leaf, saved.cert.der());
    assert_eq!(body, "site a");
    // rcgen's default expiry.
    let expires = rcgen::date_time_ymd(4096, 1, 1).unix_timestamp();
    let expiry =
        format!("webx4r_acme_certificate_expiry_timestamp_seconds{{name=\"a.test\"}} {expires}");
    server.wait_for_metrics(&[&expiry]).await;
    server.stop().await;
}

#[tokio::test]
async fn reload_rejects_acme_changes() {
    let server = Running::start_tls_with(true, "[acme]\n").await;
    let changed = format!("{}email = \"me@example.com\"\n", server.config);
    let removed = server.config.replace("[acme]\n", "");
    for config in [changed, removed] {
        let err = server.reload(&config).unwrap_err().to_string();
        assert_eq!(err, "[acme] settings changed; restart to apply them");
    }
    server.stop().await;
}

#[tokio::test]
async fn reload_rejects_log_and_metrics_changes() {
    let server = Running::start(false).await;
    for (table, added) in [
        ("[log]", "[log]\ndir = \"logs\"\n"),
        ("[metrics]", "[metrics]\nlisten = \"127.0.0.1:9100\"\n"),
    ] {
        let err = server.reload(&format!("{}{added}", server.config)).unwrap_err();
        assert_eq!(err.to_string(), format!("{table} settings changed; restart to apply them"));
    }
    assert!(server.get("a.test").await.ends_with("site a"), "the old config stays");
    server.stop().await;
}

/// Waits until the manager has saved a cert covering `names`.
async fn wait_for_cert(storage: &Storage, names: &[&str], pebble: &Pebble) -> acme::Issued {
    let names: Vec<_> = names.iter().map(|name| name.to_string()).collect();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(issued) = storage.load_cert(&names).unwrap() {
            return issued;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("no certificate for {names:?}:\n{}", pebble.logs());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A server whose `a.test` site gets its cert from Pebble, which really connects back:
/// over HTTP-01 if `with_http`, otherwise TLS-ALPN-01.
async fn start_with_pebble(with_http: bool) -> (Running, Pebble, Storage) {
    let (http, https) = (free_port(), free_port());
    let pebble = Pebble::start_validating(http, https);
    let http = if with_http { format!("http = \"127.0.0.1:{http}\"\n") } else { String::new() };
    // Literal strings, so Windows paths' backslashes aren't escapes.
    let text = format!(
        "[server]\n{http}https = \"127.0.0.1:{https}\"\n\
         [[site]]\nhosts = [\"a.test\", \"www.a.test\"]\nroot = \"a\"\ndefault = true\n\
         [acme]\ndirectory = '{}'\nca_root = '{}'\nstorage = \"state\"\n",
        pebble.url(),
        pebble.root().display()
    );
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(&dir.path().join("state"), pebble.url());
    let server = Running::start_with(dir, &text).await;
    (server, pebble, storage)
}

#[tokio::test]
#[ignore = "needs pebble on PATH"]
async fn issues_certs_over_http01_and_reissues_for_new_names() {
    let (server, pebble, storage) = start_with_pebble(true).await;
    let issued = wait_for_cert(&storage, &["a.test", "www.a.test"], &pebble).await;
    let addr = server.https.unwrap();
    for host in ["a.test", "www.a.test", "unknown.test"] {
        assert_eq!(served(addr, host).await, (issued.certified.cert[0].clone(), "site a".into()));
    }

    let more_names = server.config.replace("\"www.a.test\"", "\"www.a.test\", \"new.a.test\"");
    server.reload(&more_names).unwrap();
    let reissued = wait_for_cert(&storage, &["a.test", "www.a.test", "new.a.test"], &pebble).await;
    let (leaf, _) = served(addr, "new.a.test").await;
    assert_eq!(leaf, reissued.certified.cert[0]);
    server.stop().await;
}

#[tokio::test]
#[ignore = "needs pebble on PATH"]
async fn issues_certs_over_tls_alpn01_without_http() {
    let (server, pebble, storage) = start_with_pebble(false).await;
    let issued = wait_for_cert(&storage, &["a.test", "www.a.test"], &pebble).await;
    let (leaf, body) = served(server.https.unwrap(), "www.a.test").await;
    assert_eq!((leaf, body), (issued.certified.cert[0].clone(), "site a".into()));
    server.stop().await;
}

#[tokio::test]
async fn answers_tls_alpn01_challenges_then_closes() {
    let server = Running::start_tls_with(false, "[acme]\n").await;
    let challenges = server.challenges.as_ref().unwrap();
    challenges.add_tls_alpn("a.test", &[7; 32]).unwrap();

    let mut stream = acme_handshake(server.https.unwrap(), "a.test").await.unwrap();
    let (_, tls) = stream.get_ref();
    assert_eq!(tls.alpn_protocol(), Some(ACME_TLS_ALPN));
    let expected = &challenges.tls_alpn_cert("a.test").unwrap().cert[0];
    assert_eq!(&tls.peer_certificates().unwrap()[0], expected);
    // The server closes the connection; a reset instead of a clean close is fine.
    let read = stream.read(&mut [0; 1]).await;
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

    assert!(acme_handshake(server.https.unwrap(), "b.test").await.is_err(), "no challenge");
    let (_, body) = get_tls(server.tls("a.test", b"h2").await, "a.test").await;
    assert_eq!(body, "site a", "other clients still get the site's cert");
    server.stop().await;
}

#[tokio::test]
async fn acme_tls_alpn_is_refused_without_acme() {
    let server = Running::start_tls(false).await;
    assert!(acme_handshake(server.https.unwrap(), "a.test").await.is_err());
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
