//! Automatic certificates over ACME (RFC 8555): the account, the files it keeps, the
//! answers to the CA's challenges, and the [`Manager`] that orders and renews certs.

mod manager;
#[cfg(test)]
pub(crate) mod tests;

pub use manager::{Connector, Handle, Manager};

use std::collections::HashMap;
use std::fmt::Display;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::CONTENT_TYPE;
use http::{Method, Request, Response};
use instant_acme::{Account, AccountBuilder, AccountCredentials, NewAccount};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use webxlib::body::Body;
use x509_parser::extensions::GeneralName;

use crate::config::Acme;
use crate::tls;

/// The ALPN protocol of TLS-ALPN-01 challenges (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

const HTTP_CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

/// Answers to pending challenges, which prove to the CA that we control a hostname.
#[derive(Debug, Default)]
pub struct Challenges {
    /// HTTP-01: key authorizations by token.
    http: Mutex<HashMap<String, String>>,
    /// TLS-ALPN-01: challenge certs by hostname.
    tls_alpn: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl Challenges {
    pub fn add_http(&self, token: &str, key_authorization: &str) {
        self.http.lock().unwrap().insert(token.to_owned(), key_authorization.to_owned());
    }

    pub fn remove_http(&self, token: &str) {
        self.http.lock().unwrap().remove(token);
    }

    /// `digest` is the SHA-256 of the key authorization.
    pub fn add_tls_alpn(&self, host: &str, digest: &[u8]) -> io::Result<()> {
        let certified = Arc::new(tls_alpn_cert(host, digest)?);
        self.tls_alpn.lock().unwrap().insert(host.to_owned(), certified);
        Ok(())
    }

    pub fn remove_tls_alpn(&self, host: &str) {
        self.tls_alpn.lock().unwrap().remove(host);
    }

    /// The HTTP-01 answer, if `req` asks for a pending token. Other requests under the
    /// challenge path go to the site, so other ACME clients can still use it.
    pub fn http_response<B>(&self, req: &Request<B>) -> Option<Response<Body>> {
        let token = req.uri().path().strip_prefix(HTTP_CHALLENGE_PATH)?;
        if req.method() != Method::GET {
            return None;
        }
        let key_authorization = self.http.lock().unwrap().get(token)?.clone();
        let res = Response::builder()
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::bytes(key_authorization))
            .expect("static header is valid");
        Some(res)
    }

    /// The TLS-ALPN-01 cert for `host`; `None` aborts the handshake.
    pub fn tls_alpn_cert(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.strip_suffix('.').unwrap_or(host);
        self.tls_alpn.lock().unwrap().get(host).cloned()
    }
}

/// A self-signed cert for `host` with the critical acmeIdentifier extension (RFC 8737 §3).
fn tls_alpn_cert(host: &str, digest: &[u8]) -> io::Result<CertifiedKey> {
    let error = |e: &dyn Display| {
        let msg = format!("can't make a TLS-ALPN-01 cert for {host}: {e}");
        io::Error::new(io::ErrorKind::InvalidData, msg)
    };
    if digest.len() != 32 {
        return Err(error(&"the digest must be a SHA-256"));
    }
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).map_err(|e| error(&e))?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let key = rcgen::KeyPair::generate().map_err(|e| error(&e))?;
    let cert = params.self_signed(&key).map_err(|e| error(&e))?;
    let key = PrivatePkcs8KeyDer::from(key.serialize_der());
    // Not `CertifiedKey::from_der`: its parser rejects the critical acmeIdentifier extension.
    let signer =
        tls::provider().key_provider.load_private_key(key.into()).map_err(|e| error(&e))?;
    Ok(CertifiedKey::new(vec![cert.der().clone()], signer))
}

/// The files kept for one CA: its account and the certificates it issued.
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    /// A folder in `root` named after `directory_url`, since an account belongs to one CA.
    pub fn new(root: &Path, directory_url: &str) -> Self {
        let url = directory_url.trim_start_matches("https://");
        let name: String = url
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' })
            .collect();
        Self { dir: root.join(name) }
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    /// One PEM file with the private key and the chain, so a single rename replaces both.
    /// Named after the first name, so certs for a site's old and new names share a file.
    fn cert_path(&self, names: &[String]) -> PathBuf {
        self.dir.join("certs").join(format!("{}.pem", names[0]))
    }

    /// The saved cert for `names`, if there is one that covers them all.
    pub fn load_cert(&self, names: &[String]) -> io::Result<Option<Issued>> {
        let path = self.cert_path(names);
        let Some(pem) = read_if_exists(&path)? else { return Ok(None) };
        let issued = Issued::parse(&pem)
            .map_err(|e| io::Error::new(e.kind(), format!("can't load {}: {e}", path.display())))?;
        Ok(issued.covers(names).then_some(issued))
    }

    /// Checks the CA's `chain_pem` against `key_pem`, then saves both for `names`.
    pub fn save_cert(
        &self,
        names: &[String],
        key_pem: &str,
        chain_pem: &str,
    ) -> io::Result<Issued> {
        let pem = format!("{}\n{chain_pem}", key_pem.trim_end());
        let issued = Issued::parse(pem.as_bytes()).map_err(|e| {
            io::Error::new(e.kind(), format!("the CA's certificate for {names:?} is unusable: {e}"))
        })?;
        write_private(&self.cert_path(names), pem.as_bytes())?;
        Ok(issued)
    }
}

/// A certificate from the CA, ready to serve.
#[derive(Debug, Clone)]
pub struct Issued {
    pub certified: Arc<CertifiedKey>,
    /// The DNS names it covers.
    pub names: Vec<String>,
    /// When a third of its lifetime is left, as Let's Encrypt recommends.
    pub renew_at: SystemTime,
}

impl Issued {
    /// Reads a private key and certificate chain from `pem`, and checks that they match.
    fn parse(pem: &[u8]) -> io::Result<Self> {
        let invalid = |e: &dyn Display| io::Error::new(io::ErrorKind::InvalidData, e.to_string());
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid(&e))?;
        let leaf = chain.first().ok_or_else(|| invalid(&"no certificates found"))?;
        let (_, x509) = x509_parser::parse_x509_certificate(leaf).map_err(|e| invalid(&e))?;
        let names = match x509.subject_alternative_name().map_err(|e| invalid(&e))? {
            Some(san) => san
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some(name.to_ascii_lowercase()),
                    _ => None,
                })
                .collect(),
            None => Vec::new(),
        };
        let validity = x509.validity();
        let (start, end) = (validity.not_before.timestamp(), validity.not_after.timestamp());
        let renew_at = end - (end - start) / 3;
        let renew_at = UNIX_EPOCH + Duration::from_secs(u64::try_from(renew_at).unwrap_or(0));

        let key = PrivateKeyDer::from_pem_slice(pem).map_err(|e| invalid(&e))?;
        let certified =
            CertifiedKey::from_der(chain, key, &tls::provider()).map_err(|e| invalid(&e))?;
        Ok(Self { certified: Arc::new(certified), names, renew_at })
    }

    fn covers(&self, names: &[String]) -> bool {
        names.iter().all(|name| self.names.contains(name))
    }
}

/// Loads the saved account for `acme`'s CA, or registers a new one and saves it.
/// Registering agrees to the CA's terms of service.
pub async fn account(
    builder: AccountBuilder,
    acme: &Acme,
    storage: &Storage,
) -> io::Result<Account> {
    let url = acme.directory_url();
    let path = storage.account_path();
    if let Some(json) = read_if_exists(&path)? {
        let credentials: AccountCredentials = serde_json::from_slice(&json).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("can't read {}: {e}", path.display()),
            )
        })?;
        return builder
            .from_credentials(credentials)
            .await
            .map_err(|e| io::Error::other(format!("can't reach the ACME server at {url}: {e}")));
    }

    let contact = acme.email.as_ref().map(|email| format!("mailto:{email}"));
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let new = NewAccount {
        contact: &contact,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, credentials) = builder
        .create(&new, url.to_owned(), None)
        .await
        .map_err(|e| io::Error::other(format!("can't register an ACME account at {url}: {e}")))?;
    let json = serde_json::to_vec_pretty(&credentials).map_err(io::Error::other)?;
    write_private(&path, &json)?;
    tracing::info!(directory = url, "registered an ACME account");
    Ok(account)
}

/// `None` if `path` doesn't exist.
fn read_if_exists(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io::Error::new(e.kind(), format!("can't read {}: {e}", path.display()))),
    }
}

/// Replaces `path` atomically. On Unix, only this user can read the file or its folders.
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let error =
        |e: io::Error| io::Error::new(e.kind(), format!("can't write {}: {e}", path.display()));
    let dir = path.parent().expect("storage paths have a folder");
    let mut folders = fs::DirBuilder::new();
    folders.recursive(true);
    let mut options = fs::OpenOptions::new();
    // `create_new` so the mode applies; a leftover temp file could have looser permissions.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        folders.mode(0o700);
        options.mode(0o600);
    }
    folders.create(dir).map_err(error)?;

    let temp = path.with_extension("tmp");
    if let Err(e) = fs::remove_file(&temp)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(error(e));
    }
    let mut file = options.open(&temp).map_err(error)?;
    file.write_all(contents).and_then(|()| file.sync_all()).map_err(error)?;
    fs::rename(&temp, path).map_err(error)
}
