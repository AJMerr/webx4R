//! HTTPS certificates: loads each site's PEM files or self-signs localhost names,
//! picks one per handshake by SNI, and swaps them on reload.

use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::acme::{ACME_TLS_ALPN, Challenges};
use crate::config::{Config, is_localhost};

/// The crypto backend for every certificate and handshake.
pub(crate) fn provider() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// The live certificates, which rustls asks for on every handshake.
#[derive(Debug)]
pub struct CertStore {
    provider: Arc<CryptoProvider>,
    current: ArcSwap<Certs>,
    /// Present with `[acme]`, to answer TLS-ALPN-01 challenges.
    challenges: Option<Arc<Challenges>>,
}

impl CertStore {
    pub fn new(config: &Config, challenges: Option<Arc<Challenges>>) -> io::Result<Self> {
        let provider = Arc::new(provider());
        let certs = Certs::new(config, &provider, None)?;
        Ok(Self { provider, current: ArcSwap::from_pointee(certs), challenges })
    }

    /// Loads `config`'s certificates without applying them; see [`CertStore::store`].
    pub fn load(&self, config: &Config) -> io::Result<Certs> {
        Certs::new(config, &self.provider, Some(&self.current.load()))
    }

    pub fn store(&self, certs: Certs) {
        self.current.store(Arc::new(certs));
    }

    /// rustls settings for the HTTPS listener: TLS 1.2 and 1.3, certs from this store by SNI,
    /// h2 or HTTP/1.1 by ALPN, and `acme-tls/1` with challenges.
    pub fn server_config(self: &Arc<Self>) -> ServerConfig {
        let mut tls = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs supports TLS 1.2 and 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        if self.challenges.is_some() {
            tls.alpn_protocols.push(ACME_TLS_ALPN.to_vec());
        }
        tls
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello.alpn().is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        match &self.challenges {
            Some(challenges) if acme => challenges.tls_alpn_cert(hello.server_name()?),
            _ => self.current.load().lookup(hello.server_name()),
        }
    }
}

/// Each site's certificate, keyed by hostname.
#[derive(Debug)]
pub struct Certs {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    /// The default site's certificate, for unknown names and clients that send no SNI.
    default: Option<Arc<CertifiedKey>>,
    /// Self-signed certs by the names they cover, for reuse on reload.
    self_signed: HashMap<Vec<String>, Arc<CertifiedKey>>,
}

impl Certs {
    /// Loads each site's cert files; a site without them gets a self-signed cert for its
    /// localhost names, if it has any. `previous` supplies self-signed certs to keep, so
    /// browsers don't warn again after a reload.
    fn new(
        config: &Config,
        provider: &CryptoProvider,
        previous: Option<&Certs>,
    ) -> io::Result<Self> {
        let mut by_host = HashMap::new();
        let mut default = None;
        let mut self_signed_certs = HashMap::new();
        for (i, site) in config.sites.iter().enumerate() {
            let in_site = |e: io::Error| io::Error::new(e.kind(), format!("site {}: {e}", i + 1));
            let (certified, hosts): (_, Vec<_>) = match (&site.cert, &site.key) {
                (Some(cert), Some(key)) => (
                    Arc::new(load(cert, key, provider).map_err(in_site)?),
                    site.hosts.iter().collect(),
                ),
                _ => {
                    let local: Vec<_> = site.hosts.iter().filter(|h| is_localhost(h)).collect();
                    if local.is_empty() {
                        continue;
                    }
                    let names: Vec<String> = local.iter().map(|host| host.to_string()).collect();
                    let kept = previous.and_then(|certs| certs.self_signed.get(&names)).cloned();
                    let certified = match kept {
                        Some(certified) => certified,
                        None => Arc::new(self_signed(&local, provider).map_err(in_site)?),
                    };
                    self_signed_certs.insert(names, Arc::clone(&certified));
                    (certified, local)
                }
            };
            for host in hosts {
                by_host.insert(host.clone(), Arc::clone(&certified));
            }
            if site.default {
                default = Some(certified);
            }
        }
        Ok(Self { by_host, default, self_signed: self_signed_certs })
    }

    /// `None` aborts the handshake.
    fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        // rustls has already lowercased the name.
        let host = sni.map(|name| name.strip_suffix('.').unwrap_or(name));
        host.and_then(|host| self.by_host.get(host)).or(self.default.as_ref()).cloned()
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

    /// `sites` as a config, with cert paths relative to `dir`.
    fn config(dir: &Path, sites: &str) -> Config {
        let text = format!("[server]\nhttp = \"127.0.0.1:0\"\nhttps = \"127.0.0.1:0\"\n{sites}");
        Config::parse(&text, dir).unwrap()
    }

    fn certs(dir: &Path, sites: &str) -> io::Result<Certs> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        Certs::new(&config(dir, sites), &provider, None)
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

    #[test]
    fn reload_keeps_self_signed_certs_for_the_same_names() {
        let dir = tempfile::tempdir().unwrap();
        let local = |hosts: &str| {
            config(dir.path(), &format!("[[site]]\nhosts = [{hosts}]\nroot = \"www\"\n"))
        };
        let store = CertStore::new(&local("\"localhost\""), None).unwrap();
        let first = store.current.load().lookup(Some("localhost")).unwrap();

        store.store(store.load(&local("\"localhost\"")).unwrap());
        let same = store.current.load().lookup(Some("localhost")).unwrap();
        assert!(Arc::ptr_eq(&first, &same), "unchanged names keep their cert");

        store.store(store.load(&local("\"localhost\", \"app.localhost\"")).unwrap());
        let changed = store.current.load().lookup(Some("localhost")).unwrap();
        assert!(!Arc::ptr_eq(&first, &changed), "new names need a new cert");
        assert!(valid_for(&changed.cert[0], "app.localhost"));
    }

    #[test]
    fn reload_rereads_cert_files() {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "a.test");
        let sites = config(dir.path(), &site("a.test", "a.test", false));
        let store = CertStore::new(&sites, None).unwrap();

        let (renewed, _) = write_pair(dir.path(), "a.test");
        store.store(store.load(&sites).unwrap());
        let served = store.current.load().lookup(Some("a.test")).unwrap();
        assert_eq!(served.cert[0], CertificateDer::from_pem_file(renewed).unwrap());
    }
}
