//! HTTPS certificates: loads each site's PEM files and picks one per handshake by SNI.

use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config::Config;

/// Each site's certificate, keyed by hostname.
#[derive(Debug)]
pub struct Certs {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    /// The default site's certificate, for unknown names and clients that send no SNI.
    default: Option<Arc<CertifiedKey>>,
}

impl Certs {
    /// Loads the cert files of every site that has them.
    pub fn new(config: &Config, provider: &CryptoProvider) -> io::Result<Self> {
        let mut by_host = HashMap::new();
        let mut default = None;
        for (i, site) in config.sites.iter().enumerate() {
            let (Some(cert), Some(key)) = (&site.cert, &site.key) else { continue };
            let certified = load(cert, key, provider)
                .map_err(|e| io::Error::new(e.kind(), format!("site {}: {e}", i + 1)))?;
            let certified = Arc::new(certified);
            for host in &site.hosts {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    /// Writes a self-signed cert and key for `host` into `dir`.
    fn write_pair(dir: &Path, host: &str) -> (PathBuf, PathBuf) {
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
}
