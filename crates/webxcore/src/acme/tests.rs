use super::pebble::Pebble;
use super::*;

/// `[acme]` with every key unset.
fn acme() -> Acme {
    Acme { email: None, directory: None, storage: None, ca_root: None }
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
    let acme = acme();
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
    let directory = Some(pebble.url().to_owned());
    let acme = Acme { email: Some("me@example.com".into()), directory, ..acme() };
    let storage = Storage::new(dir.path(), acme.directory_url());
    let builder = || Account::builder_with_root(pebble.root()).unwrap();

    let first = account(builder(), &acme, &storage).await.unwrap();
    assert!(storage.account_path().exists());
    let again = account(builder(), &acme, &storage).await.unwrap();
    assert_eq!(again.id(), first.id(), "the saved account is reused");
}
