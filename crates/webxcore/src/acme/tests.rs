use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;

/// A Pebble test CA, run from `pebble` on `PATH` and stopped on drop.
pub(crate) struct Pebble {
    child: Child,
    dir: TempDir,
    url: String,
}

impl Pebble {
    pub(crate) fn start() -> Self {
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
            "httpPort": 5002,
            "tlsPort": 5001,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
        }});
        let config_path = dir.path().join("pebble.json");
        fs::write(&config_path, config.to_string()).unwrap();

        let log = File::create(dir.path().join("pebble.log")).unwrap();
        let child = Command::new("pebble")
            .arg("-config")
            .arg(&config_path)
            .env("PEBBLE_VA_NOSLEEP", "1")
            // Pebble rejects some nonces on purpose by default; tests must be repeatable.
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("tests that need pebble need `pebble` on PATH");
        let mut pebble = Self { child, dir, url: format!("https://localhost:{port}/dir") };
        pebble.wait_for_port(port);
        pebble
    }

    /// `[acme]` settings for this CA.
    pub(crate) fn acme(&self) -> Acme {
        Acme { email: None, directory: Some(self.url.clone()), storage: None }
    }

    /// An ACME client that trusts Pebble's HTTPS cert.
    pub(crate) fn builder(&self) -> AccountBuilder {
        Account::builder_with_root(self.dir.path().join("cert.pem")).unwrap()
    }

    fn wait_for_port(&mut self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            let exited = self.child.try_wait().unwrap();
            if exited.is_some() || Instant::now() > deadline {
                let log = fs::read_to_string(self.dir.path().join("pebble.log")).unwrap();
                panic!("pebble didn't start ({exited:?}):\n{log}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port that was free a moment ago.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
