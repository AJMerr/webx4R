use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;

/// A Pebble test CA, run from `pebble` on `PATH` and stopped on drop.
pub(crate) struct Pebble {
    /// Pebble, after `pebble-challtestsrv` when validating.
    children: Vec<(&'static str, Child)>,
    dir: TempDir,
    url: String,
}

impl Pebble {
    /// A CA for account tests; it can't validate challenges.
    pub(crate) fn start() -> Self {
        Self::launch(5002, 5001, false)
    }

    /// A CA that validates challenges at 127.0.0.1, whatever the name: HTTP-01 on
    /// `http_port` and TLS-ALPN-01 on `tls_port`. `pebble-challtestsrv` answers its DNS.
    pub(crate) fn start_validating(http_port: u16, tls_port: u16) -> Self {
        Self::launch(http_port, tls_port, true)
    }

    fn launch(http_port: u16, tls_port: u16, validate: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        fs::write(&cert, pair.cert.pem()).unwrap();
        fs::write(&key, pair.signing_key.serialize_pem()).unwrap();

        let port = free_port();
        let config = serde_json::json!({ "pebble": {
            "listenAddress": format!("127.0.0.1:{port}"),
            "managementListenAddress": format!("127.0.0.1:{}", free_port()),
            "certificate": cert,
            "privateKey": key,
            "httpPort": http_port,
            "tlsPort": tls_port,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
        }});
        let config_path = dir.path().join("pebble.json");
        fs::write(&config_path, config.to_string()).unwrap();

        let url = format!("https://localhost:{port}/dir");
        let mut pebble = Self { children: Vec::new(), dir, url };
        let mut args = vec!["-config".to_owned(), config_path.to_str().unwrap().to_owned()];
        if validate {
            let (dns, management) = (free_port(), free_port());
            let (dns, management) = (format!("127.0.0.1:{dns}"), format!("127.0.0.1:{management}"));
            // Only the DNS server; empty addresses turn off its other servers.
            let off = ["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""];
            // `-dnsserver` was `-dns01` before Pebble 2.7.
            let mut challtestsrv = vec!["-dnsserver", &dns, "-management", &management];
            challtestsrv.extend(off);
            // No AAAA answers, so Pebble connects over IPv4, where the tests listen.
            challtestsrv.extend(["-defaultIPv6", ""]);
            pebble.spawn("pebble-challtestsrv", &challtestsrv);
            pebble.wait_for(&management);
            args.extend(["-dnsserver".to_owned(), dns]);
        }
        pebble.spawn("pebble", &args);
        pebble.wait_for(&format!("127.0.0.1:{port}"));
        pebble
    }

    fn spawn(&mut self, program: &'static str, args: &[impl AsRef<std::ffi::OsStr>]) {
        let log = File::create(self.dir.path().join(format!("{program}.log"))).unwrap();
        let child = Command::new(program)
            .args(args)
            .env("PEBBLE_VA_NOSLEEP", "1")
            // Pebble rejects some nonces on purpose by default; tests must be repeatable.
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap_or_else(|e| panic!("tests that need pebble need `{program}` on PATH: {e}"));
        self.children.push((program, child));
    }

    /// Waits for a TCP listener at `addr`, failing with the logs if a child exits first.
    fn wait_for(&mut self, addr: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(addr).is_err() {
            let exited = self.children.iter_mut().any(|(_, c)| c.try_wait().unwrap().is_some());
            if exited || Instant::now() > deadline {
                panic!("pebble didn't start:\n{}", self.logs());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Every child's output, for failure messages.
    pub(crate) fn logs(&self) -> String {
        let log = |(program, _): &(&str, Child)| {
            let text = fs::read_to_string(self.dir.path().join(format!("{program}.log")));
            format!("--- {program}\n{}", text.unwrap_or_default())
        };
        self.children.iter().map(log).collect::<Vec<_>>().join("\n")
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// `[acme]` settings for this CA.
    pub(crate) fn acme(&self) -> Acme {
        Acme { email: None, directory: Some(self.url.clone()), storage: None }
    }

    /// Makes ACME clients that trust Pebble's HTTPS cert.
    pub(crate) fn connector(&self) -> Connector {
        let root = self.dir.path().join("cert.pem");
        Arc::new(move || Account::builder_with_root(&root))
    }

    fn builder(&self) -> AccountBuilder {
        (self.connector())().unwrap()
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A port that was free a moment ago.
pub(crate) fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn http_challenges_answer_pending_tokens() {
    use http_body_util::BodyExt;

    let challenges = Challenges::default();
    challenges.add_http("tok", "tok.thumbprint");
    let req =
        |method: Method, path: &str| Request::builder().method(method).uri(path).body(()).unwrap();
    let path = "/.well-known/acme-challenge/tok";

    let res = challenges.http_response(&req(Method::GET, path)).unwrap();
    assert_eq!(res.headers()[CONTENT_TYPE], "application/octet-stream");
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), "tok.thumbprint");
    assert!(challenges.http_response(&req(Method::POST, path)).is_none());
    assert!(
        challenges.http_response(&req(Method::GET, "/.well-known/acme-challenge/other")).is_none()
    );
    assert!(challenges.http_response(&req(Method::GET, "/tok")).is_none());

    challenges.remove_http("tok");
    assert!(challenges.http_response(&req(Method::GET, path)).is_none());
}

#[test]
fn tls_alpn_certs_carry_the_digest() {
    let challenges = Challenges::default();
    let digest = [7; 32];
    challenges.add_tls_alpn("a.test", &digest).unwrap();
    let certified = challenges.tls_alpn_cert("a.test.").unwrap();

    // acmeIdentifier's OID (1.3.6.1.5.5.7.1.31), critical, then the digest as a nested
    // OCTET STRING (RFC 8737 §3).
    let mut extension = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
    extension.extend([0x01, 0x01, 0xff, 0x04, 0x22, 0x04, 0x20]);
    extension.extend(digest);
    let der = certified.cert[0].as_ref();
    assert!(der.windows(extension.len()).any(|window| window == extension));

    assert!(challenges.tls_alpn_cert("b.test").is_none());
    challenges.remove_tls_alpn("a.test");
    assert!(challenges.tls_alpn_cert("a.test").is_none());
}

/// A key and cert for `names` as PEM, valid for 90 days from 2026-01-01.
fn issued_pem(names: &[String]) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(names).unwrap();
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 4, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (key.serialize_pem(), cert.pem())
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

#[test]
fn saved_certs_load_back() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(dir.path(), "https://ca.test/dir");
    let site = names(&["a.test", "www.a.test"]);
    assert!(storage.load_cert(&site).unwrap().is_none());

    let (key, chain) = issued_pem(&site);
    let saved = storage.save_cert(&site, &key, &chain).unwrap();
    assert_eq!(saved.names, site);
    let march_2 = rcgen::date_time_ymd(2026, 3, 2).unix_timestamp() as u64;
    assert_eq!(saved.renew_at, UNIX_EPOCH + Duration::from_secs(march_2), "30 of 90 days left");

    let loaded = storage.load_cert(&site).unwrap().unwrap();
    assert_eq!(loaded.certified.cert, saved.certified.cert);
    assert_eq!(loaded.renew_at, saved.renew_at);
    assert!(
        storage.load_cert(&names(&["a.test"])).unwrap().is_some(),
        "fewer names: still covered"
    );
    let more = names(&["a.test", "new.a.test"]);
    assert!(storage.load_cert(&more).unwrap().is_none(), "new names need a new cert");
}

#[test]
fn unusable_certs_are_not_saved() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(dir.path(), "https://ca.test/dir");
    let site = names(&["a.test"]);
    let ((key, _), (_, other_chain)) = (issued_pem(&site), issued_pem(&site));
    let err = storage.save_cert(&site, &key, &other_chain).unwrap_err().to_string();
    assert!(err.starts_with("the CA's certificate for [\"a.test\"] is unusable"), "{err}");
    assert!(storage.load_cert(&site).unwrap().is_none());
}

#[test]
fn corrupt_cert_files_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::new(dir.path(), "https://ca.test/dir");
    let site = names(&["a.test"]);
    write_private(&storage.cert_path(&site), b"garbage").unwrap();
    let err = storage.load_cert(&site).unwrap_err().to_string();
    assert!(err.starts_with("can't load ") && err.ends_with("no certificates found"), "{err}");
}

#[test]
fn storage_is_named_after_the_directory() {
    let root = Path::new("/state");
    let lets_encrypt = Storage::new(root, "https://acme-v02.api.letsencrypt.org/directory");
    assert_eq!(lets_encrypt.dir, root.join("acme-v02.api.letsencrypt.org-directory"));
    let pebble = Storage::new(root, "https://localhost:14000/dir");
    assert_eq!(pebble.dir, root.join("localhost-14000-dir"));
}

#[test]
fn private_files_are_replaced_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a/b/secret.json");
    write_private(&path, b"one").unwrap();
    write_private(&path, b"two").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"two");
    assert!(!path.with_extension("tmp").exists());
    assert_eq!(read_if_exists(&dir.path().join("missing")).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn private_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a/b/secret.json");
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    write_private(&path, b"one").unwrap();
    assert_eq!((mode(&path), mode(path.parent().unwrap())), (0o600, 0o700));

    let temp = path.with_extension("tmp");
    fs::write(&temp, "leftover").unwrap();
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o644)).unwrap();
    write_private(&path, b"two").unwrap();
    assert_eq!(mode(&path), 0o600, "a leftover temp file's mode isn't kept");
}

#[tokio::test]
async fn unreadable_account_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let acme = Acme { email: None, directory: None, storage: None };
    let storage = Storage::new(dir.path(), acme.directory_url());
    write_private(&storage.account_path(), b"not json").unwrap();
    let err = account(Account::builder().unwrap(), &acme, &storage).await.err().unwrap();
    assert!(err.to_string().starts_with("can't read "), "{err}");
}

#[tokio::test]
#[ignore = "needs pebble on PATH"]
async fn registers_once_then_reuses_the_account() {
    let pebble = Pebble::start();
    let dir = tempfile::tempdir().unwrap();
    let acme = Acme { email: Some("me@example.com".into()), ..pebble.acme() };
    let storage = Storage::new(dir.path(), acme.directory_url());

    let first = account(pebble.builder(), &acme, &storage).await.unwrap();
    assert!(storage.account_path().exists());
    let again = account(pebble.builder(), &acme, &storage).await.unwrap();
    assert_eq!(again.id(), first.id(), "the saved account is reused");
}
