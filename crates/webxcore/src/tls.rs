//! HTTPS certificates: loads each site's PEM files or self-signs localhost names,
//! and picks one per handshake by SNI.

use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config::{Config, is_localhost};

/// rustls settings for the HTTPS listener: TLS 1.2 and 1.3, certs by SNI, h2 or HTTP/1.1 by ALPN.
pub fn server_config(config: &Config) -> io::Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certs = Certs::new(config, &provider)?;
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(certs));
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

/// Each site's certificate, keyed by hostname.
#[derive(Debug)]
pub struct Certs {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    /// The default site's certificate, for unknown names and clients that send no SNI.
    default: Option<Arc<CertifiedKey>>,
}

impl Certs {
    /// Loads each site's cert files; a site without them gets a self-signed cert
    /// for its localhost names, if it has any.
    pub fn new(config: &Config, provider: &CryptoProvider) -> io::Result<Self> {
        let mut by_host = HashMap::new();
        let mut default = None;
        for (i, site) in config.sites.iter().enumerate() {
            let (certified, hosts) = match (&site.cert, &site.key) {
                (Some(cert), Some(key)) => (load(cert, key, provider), site.hosts.iter().collect()),
                _ => {
                    let local: Vec<_> = site.hosts.iter().filter(|h| is_localhost(h)).collect();
                    if local.is_empty() {
                        continue;
                    }
                    (self_signed(&local, provider), local)
                }
            };
            let certified =
                certified.map_err(|e| io::Error::new(e.kind(), format!("site {}: {e}", i + 1)))?;
            let certified = Arc::new(certified);
            for host in hosts {
                by_host.insert(host.clone(), Arc::clone(&certified));
            }
            if site.default {
                default = Some(certified);
            }
        }
        Ok(Self { by_host, default })
    }

    /// `None` aborts the handshake.
    fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        // rustls has already lowercased the name.
        let host = sni.map(|name| name.strip_suffix('.').unwrap_or(name));
        host.and_then(|host| self.by_host.get(host)).or(self.default.as_ref()).cloned()
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(hello.server_name())
    }
}

/// Reads a PEM certificate chain and private key, and checks that they match.
fn load(cert: &Path, key: &Path, provider: &CryptoProvider) -> io::Result<CertifiedKey> {
    let error = |path: &Path, e: &dyn Display| {
        io::Error::new(io::ErrorKind::InvalidData, format!("can't load {}: {e}", path.display()))
    };
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| error(cert, &e))?;
    if chain.is_empty() {
        return Err(error(cert, &"no certificates found"));
    }
    let key_der = PrivateKeyDer::from_pem_file(key).map_err(|e| error(key, &e))?;
    CertifiedKey::from_der(chain, key_der, provider).map_err(|e| {
        let (key, cert) = (key.display(), cert.display());
        io::Error::new(io::ErrorKind::InvalidData, format!("can't use {key} with {cert}: {e}"))
    })
}

/// Generates an in-memory cert for `hosts` and the loopback addresses.
fn self_signed(hosts: &[&String], provider: &CryptoProvider) -> io::Result<CertifiedKey> {
    let error = |e: &dyn Display| {
        io::Error::new(io::ErrorKind::InvalidData, format!("can't self-sign {hosts:?}: {e}"))
    };
    let mut names: Vec<String> = hosts.iter().map(|host| host.to_string()).collect();
    names.extend(["127.0.0.1".to_owned(), "::1".to_owned()]);
    let pair = rcgen::generate_simple_self_signed(names).map_err(|e| error(&e))?;
    let key = PrivatePkcs8KeyDer::from(pair.signing_key.serialize_der());
    let certified = CertifiedKey::from_der(vec![pair.cert.der().clone()], key.into(), provider)
        .map_err(|e| error(&e))?;
    tracing::info!(?hosts, "using a self-signed certificate; browsers will warn about it");
    Ok(certified)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    /// Writes a self-signed cert and key for `host` into `dir`.
    pub(crate) fn write_pair(dir: &Path, host: &str) -> (PathBuf, PathBuf) {
        let pair = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
        let (cert, key) = (dir.join(format!("{host}.crt")), dir.join(format!("{host}.key")));
        fs::write(&cert, pair.cert.pem()).unwrap();
        fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
        (cert, key)
    }

    /// Loads `sites` with cert paths relative to `dir`.
    fn certs(dir: &Path, sites: &str) -> io::Result<Certs> {
        let text = format!("[server]\nhttp = \"127.0.0.1:0\"\nhttps = \"127.0.0.1:0\"\n{sites}");
        let config = Config::parse(&text, dir).unwrap();
        Certs::new(&config, &rustls::crypto::aws_lc_rs::default_provider())
    }

    fn site(host: &str, files: &str, default: bool) -> String {
        format!(
            "[[site]]\nhosts = [\"{host}\"]\nroot = \"www\"\ndefault = {default}\n\
             cert = \"{files}.crt\"\nkey = \"{files}.key\"\n"
        )
    }

    #[test]
    fn picks_cert_by_sni() {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "a.test");
        write_pair(dir.path(), "b.test");
        let sites = site("a.test", "a.test", false) + &site("b.test", "b.test", true);
        let certs = certs(dir.path(), &sites).unwrap();

        let is = |sni, host: &str| Arc::ptr_eq(&certs.lookup(sni).unwrap(), &certs.by_host[host]);
        assert!(is(Some("a.test"), "a.test"));
        assert!(is(Some("a.test."), "a.test"));
        assert!(is(Some("b.test"), "b.test"));
        assert!(is(Some("unknown.test"), "b.test"), "unknown names get the default site's cert");
        assert!(is(None, "b.test"), "no SNI gets the default site's cert");
    }

    #[test]
    fn no_default_cert_aborts_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "a.test");
        let sites = site("a.test", "a.test", false) + "[[site]]\nroot = \"www\"\ndefault = true\n";
        let certs = certs(dir.path(), &sites).unwrap();
        assert!(certs.lookup(Some("a.test")).is_some());
        assert!(certs.lookup(Some("unknown.test")).is_none());
        assert!(certs.lookup(None).is_none());
    }

    #[test]
    fn mismatched_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "a.test");
        let (_, other_key) = write_pair(dir.path(), "b.test");
        fs::rename(other_key, dir.path().join("a.test.key")).unwrap();
        let err = certs(dir.path(), &site("a.test", "a.test", false)).unwrap_err().to_string();
        assert!(err.starts_with("site 1: can't use "), "{err}");
    }

    #[test]
    fn unreadable_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = certs(dir.path(), &site("a.test", "a.test", false)).unwrap_err().to_string();
        let cert = dir.path().join("a.test.crt");
        assert!(
            missing.starts_with(&format!("site 1: can't load {}", cert.display())),
            "{missing}"
        );

        write_pair(dir.path(), "a.test");
        fs::write(&cert, "").unwrap();
        let empty = certs(dir.path(), &site("a.test", "a.test", false)).unwrap_err().to_string();
        assert!(empty.ends_with("no certificates found"), "{empty}");
    }

    /// Whether `cert`, trusted as its own root, is valid for `name`.
    fn valid_for(cert: &CertificateDer<'static>, name: &str) -> bool {
        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let name = ServerName::try_from(name.to_owned()).unwrap();
        verifier.verify_server_cert(cert, &[], &name, &[], UnixTime::now()).is_ok()
    }

    #[test]
    fn localhost_names_are_self_signed() {
        let dir = tempfile::tempdir().unwrap();
        let sites = "[[site]]\nhosts = [\"localhost\", \"app.localhost\", \"example.com\"]\n\
                     root = \"www\"\n";
        let certs = certs(dir.path(), sites).unwrap();

        let certified = certs.lookup(Some("app.localhost")).unwrap();
        for name in ["localhost", "app.localhost", "127.0.0.1", "::1"] {
            assert!(valid_for(&certified.cert[0], name), "{name}");
        }
        assert!(!valid_for(&certified.cert[0], "example.com"));
        assert!(
            certs.lookup(Some("example.com")).is_none(),
            "only localhost names are self-signed"
        );
    }

    #[test]
    fn default_localhost_site_covers_clients_without_sni() {
        let dir = tempfile::tempdir().unwrap();
        let sites = "[[site]]\nhosts = [\"localhost\"]\nroot = \"www\"\ndefault = true\n";
        let certified = certs(dir.path(), sites).unwrap().lookup(None).unwrap();
        assert!(valid_for(&certified.cert[0], "127.0.0.1"));
    }

    #[test]
    fn cert_files_override_self_signing() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = write_pair(dir.path(), "localhost");
        let certs = certs(dir.path(), &site("localhost", "localhost", false)).unwrap();
        let file_cert = CertificateDer::from_pem_file(cert).unwrap();
        assert_eq!(certs.lookup(Some("localhost")).unwrap().cert[0], file_cert);
    }
}
