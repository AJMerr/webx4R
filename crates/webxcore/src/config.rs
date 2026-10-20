//! The `webx4r.toml` config file: parsing and validation.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use webxlib::static_files::{PathPolicy, Symlinks};

/// A validated config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    #[serde(rename = "site", default)]
    pub sites: Vec<Site>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Address for plain HTTP, e.g. `0.0.0.0:8080`.
    pub http: Option<SocketAddr>,
    /// Address for HTTPS, e.g. `0.0.0.0:8443`.
    pub https: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    /// Lowercase hostnames, without ports.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Static files. Absolute after loading; relative paths resolve against the config file's folder.
    pub root: Option<PathBuf>,
    /// Paths forwarded to upstream apps.
    #[serde(rename = "proxy", default)]
    pub proxies: Vec<Proxy>,
    /// Serves requests whose `Host` matches no other site.
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub directory_listing: bool,
    #[serde(default)]
    pub allow_dotfiles: bool,
    #[serde(default)]
    pub symlinks: SymlinkSetting,
    /// PEM certificate chain for HTTPS; resolved like `root`.
    pub cert: Option<PathBuf>,
    /// PEM private key for `cert`.
    pub key: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    /// Path prefix matched by whole segments, without a trailing `/` (except `/` itself).
    pub path: String,
    /// `host:port` of each upstream app.
    pub upstreams: Vec<String>,
    /// Remove `path` from the request path before forwarding.
    #[serde(default)]
    pub strip_prefix: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymlinkSetting {
    Follow,
    #[default]
    InsideRoot,
    Deny,
}

impl Site {
    /// Whether HTTPS can serve this site: it has cert files, or a localhost name to self-sign.
    pub fn has_tls(&self) -> bool {
        self.cert.is_some() || self.hosts.iter().any(|host| is_localhost(host))
    }

    pub fn policy(&self) -> PathPolicy {
        PathPolicy {
            allow_dotfiles: self.allow_dotfiles,
            directory_listing: self.directory_listing,
            symlinks: match self.symlinks {
                SymlinkSetting::Follow => Symlinks::Follow,
                SymlinkSetting::InsideRoot => Symlinks::InsideRoot,
                SymlinkSetting::Deny => Symlinks::Deny,
            },
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read { path: PathBuf, source: io::Error },
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "can't read {}: {source}", path.display()),
            Self::Parse(e) => write!(f, "{e}"),
            Self::Invalid(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_owned(), source })?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse(&text, base)
    }

    /// Parses and validates `text`; relative site roots resolve against `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(text).map_err(ConfigError::Parse)?;
        for site in &mut config.sites {
            for path in [&mut site.root, &mut site.cert, &mut site.key].into_iter().flatten() {
                *path = base.join(&*path);
            }
            for host in &mut site.hosts {
                host.make_ascii_lowercase();
            }
            for proxy in &mut site.proxies {
                let trimmed = proxy.path.trim_end_matches('/').len();
                proxy.path.truncate(trimmed.max(1));
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        if self.server.http.is_none() && self.server.https.is_none() {
            return invalid("[server] needs `http`, `https` or both".into());
        }
        if self.sites.is_empty() {
            return invalid("config needs at least one [[site]]".into());
        }

        let mut owners: HashMap<&str, usize> = HashMap::new();
        let mut default = None;
        for (i, site) in self.sites.iter().enumerate() {
            let n = i + 1;
            if site.default {
                if let Some(first) = default {
                    return invalid(format!("sites {first} and {n} are both `default`"));
                }
                default = Some(n);
            }
            if site.hosts.is_empty() && !site.default {
                return invalid(format!("site {n} needs `hosts`, or `default = true`"));
            }
            if site.root.is_none() && site.proxies.is_empty() {
                return invalid(format!("site {n} needs a `root`, a [[site.proxy]] or both"));
            }
            validate_proxies(n, &site.proxies)?;
            match (&site.cert, &site.key) {
                (Some(_), None) => return invalid(format!("site {n} has `cert` but no `key`")),
                (None, Some(_)) => return invalid(format!("site {n} has `key` but no `cert`")),
                _ => {}
            }
            if site.cert.is_some() && self.server.https.is_none() {
                return invalid(format!("site {n} has a `cert`, but [server] has no `https`"));
            }
            for host in &site.hosts {
                if !is_hostname(host) {
                    return invalid(format!(
                        "site {n}: \"{host}\" isn't a hostname (no port or path; \
                         write internationalized names in their xn-- form)"
                    ));
                }
                if let Some(first) = owners.insert(host, n) {
                    return invalid(format!("\"{host}\" is listed in both site {first} and {n}"));
                }
            }
        }
        if self.server.https.is_some() && !self.sites.iter().any(Site::has_tls) {
            return invalid(
                "[server] has `https`, but no site has a `cert` or a localhost host".into(),
            );
        }
        Ok(())
    }
}

fn validate_proxies(n: usize, proxies: &[Proxy]) -> Result<(), ConfigError> {
    let invalid = |msg: String| Err(ConfigError::Invalid(msg));
    let mut paths = HashSet::new();
    for Proxy { path, upstreams, .. } in proxies {
        if !path.starts_with('/') || path.contains(['?', '#']) {
            return invalid(format!(
                "site {n}: proxy path \"{path}\" must start with `/` and have no `?` or `#`"
            ));
        }
        if !paths.insert(path) {
            return invalid(format!("site {n} has two proxies for \"{path}\""));
        }
        if upstreams.is_empty() {
            return invalid(format!("site {n}: proxy \"{path}\" needs `upstreams`"));
        }
        if let Some(bad) = upstreams.iter().find(|upstream| !is_upstream(upstream)) {
            return invalid(format!(
                "site {n}: upstream \"{bad}\" must be host:port, such as 127.0.0.1:3000"
            ));
        }
    }
    Ok(())
}

/// `host:port` with an IP address or hostname and a non-zero port; no scheme or path.
fn is_upstream(addr: &str) -> bool {
    match addr.parse::<SocketAddr>() {
        Ok(addr) => addr.port() != 0,
        Err(_) => addr.rsplit_once(':').is_some_and(|(host, port)| {
            port.parse::<u16>().is_ok_and(|port| port != 0) && is_hostname(host)
        }),
    }
}

/// `localhost` and its subdomains, which RFC 6761 reserves for loopback.
pub fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// ASCII letters, digits, `-` and `.`, in non-empty dot-separated labels.
fn is_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("/etc/webx4r"))
    }

    fn invalid(text: &str) -> String {
        match parse(text) {
            Err(ConfigError::Invalid(msg)) => msg,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    const MINIMAL: &str = r#"
        [server]
        http = "0.0.0.0:8080"

        [[site]]
        hosts = ["example.com"]
        root = "www"
    "#;

    #[test]
    fn minimal_config_with_defaults() {
        let config = parse(MINIMAL).unwrap();
        assert_eq!(config.server.http, Some("0.0.0.0:8080".parse().unwrap()));
        assert_eq!(config.server.https, None);
        let site = &config.sites[0];
        assert_eq!(site.root.as_deref(), Some(Path::new("/etc/webx4r/www")));
        assert!(site.proxies.is_empty());
        assert!(!site.default && !site.directory_listing && !site.allow_dotfiles);
        assert_eq!(site.policy().symlinks, Symlinks::InsideRoot);
    }

    #[test]
    fn full_site_settings() {
        let config = parse(
            r#"
            [server]
            http = "127.0.0.1:80"

            [[site]]
            hosts = ["Example.COM", "www.example.com"]
            root = "/srv/www"
            default = true
            directory_listing = true
            allow_dotfiles = true
            symlinks = "deny"
            "#,
        )
        .unwrap();
        let site = &config.sites[0];
        assert_eq!(site.hosts, ["example.com", "www.example.com"]);
        assert_eq!(site.root.as_deref(), Some(Path::new("/srv/www")));
        let policy = site.policy();
        assert!(site.default && policy.directory_listing && policy.allow_dotfiles);
        assert_eq!(policy.symlinks, Symlinks::Deny);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = MINIMAL.replace("root = \"www\"", "root = \"www\"\ndirectory_listings = true");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("directory_listings"), "{err}");
    }

    #[test]
    fn bad_values_are_parse_errors() {
        let bad_addr = MINIMAL.replace("0.0.0.0:8080", "localhost");
        let bad_symlinks = MINIMAL.replace("root = \"www\"", "root = \"www\"\nsymlinks = \"some\"");
        assert!(matches!(parse(&bad_addr), Err(ConfigError::Parse(_))));
        assert!(matches!(parse(&bad_symlinks), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn needs_an_address() {
        let msg = invalid(&MINIMAL.replace("http = \"0.0.0.0:8080\"", ""));
        assert_eq!(msg, "[server] needs `http`, `https` or both");
        let https_only = MINIMAL.replace("http =", "https =") + "cert = \"a.crt\"\nkey = \"a.key\"";
        assert_eq!(parse(&https_only).unwrap().server.http, None);
    }

    #[test]
    fn needs_a_site() {
        let msg = invalid("[server]\nhttp = \"0.0.0.0:8080\"");
        assert_eq!(msg, "config needs at least one [[site]]");
    }

    #[test]
    fn only_one_default() {
        let msg = invalid(
            r#"
            [server]
            http = "0.0.0.0:8080"
            [[site]]
            root = "a"
            default = true
            [[site]]
            root = "b"
            default = true
            "#,
        );
        assert_eq!(msg, "sites 1 and 2 are both `default`");
    }

    #[test]
    fn hostless_site_must_be_default() {
        let msg = invalid(&MINIMAL.replace("hosts = [\"example.com\"]", ""));
        assert_eq!(msg, "site 1 needs `hosts`, or `default = true`");
    }

    #[test]
    fn hostnames_are_validated() {
        for host in ["example.com:8080", "example.com/x", "", "-bad.com", "a..b", "café.com"] {
            let text = MINIMAL.replace("example.com", host);
            let msg = invalid(&text);
            assert!(msg.contains("isn't a hostname"), "{host}: {msg}");
        }
    }

    #[test]
    fn hosts_are_unique_across_sites() {
        let text = format!("{MINIMAL}\n[[site]]\nhosts = [\"EXAMPLE.com\"]\nroot = \"other\"");
        assert_eq!(invalid(&text), "\"example.com\" is listed in both site 1 and 2");
    }

    const HTTPS: &str = "https = \"0.0.0.0:8443\"";
    const CERT: &str = "cert = \"certs/a.crt\"\nkey = \"/keys/a.key\"";

    fn with_tls(server: &str, site: &str) -> String {
        MINIMAL.replace("0.0.0.0:8080\"", &format!("0.0.0.0:8080\"\n{server}")) + site
    }

    #[test]
    fn tls_settings() {
        let config = parse(&with_tls(HTTPS, CERT)).unwrap();
        assert_eq!(config.server.https, Some("0.0.0.0:8443".parse().unwrap()));
        let site = &config.sites[0];
        assert_eq!(site.cert.as_deref(), Some(Path::new("/etc/webx4r/certs/a.crt")));
        assert_eq!(site.key.as_deref(), Some(Path::new("/keys/a.key")));
        assert!(site.has_tls());
    }

    #[test]
    fn cert_and_key_go_together() {
        let no_key = invalid(&with_tls(HTTPS, "cert = \"a.crt\""));
        let no_cert = invalid(&with_tls(HTTPS, "key = \"a.key\""));
        assert_eq!(no_key, "site 1 has `cert` but no `key`");
        assert_eq!(no_cert, "site 1 has `key` but no `cert`");
    }

    #[test]
    fn cert_needs_https() {
        let msg = invalid(&with_tls("", CERT));
        assert_eq!(msg, "site 1 has a `cert`, but [server] has no `https`");
    }

    #[test]
    fn https_needs_a_site_with_tls() {
        let msg = invalid(&with_tls(HTTPS, ""));
        assert_eq!(msg, "[server] has `https`, but no site has a `cert` or a localhost host");
        for host in ["localhost", "app.localhost"] {
            let config = parse(&with_tls(HTTPS, "").replace("example.com", host)).unwrap();
            assert!(config.sites[0].has_tls(), "{host}");
        }
    }

    #[test]
    fn localhost_names() {
        assert!(is_localhost("localhost") && is_localhost("a.b.localhost"));
        assert!(!is_localhost("mylocalhost") && !is_localhost("localhost.com"));
    }

    /// MINIMAL with `root` replaced by `site`, e.g. proxy blocks.
    fn with_site(site: &str) -> String {
        MINIMAL.replace("root = \"www\"", site)
    }

    fn proxy(path: &str, upstreams: &str) -> String {
        format!("[[site.proxy]]\npath = \"{path}\"\nupstreams = [{upstreams}]\n")
    }

    #[test]
    fn proxy_settings() {
        let site = proxy("/api/", "\"127.0.0.1:8081\", \"localhost:8082\"")
            + &proxy("/", "\"[::1]:3000\"")
            + "strip_prefix = true";
        let config = parse(&with_site(&site)).unwrap();
        let site = &config.sites[0];
        assert_eq!(site.root, None);
        let [api, all] = &site.proxies[..] else { panic!("{:?}", site.proxies) };
        assert_eq!(api.path, "/api", "trailing slashes are trimmed");
        assert_eq!(api.upstreams, ["127.0.0.1:8081", "localhost:8082"]);
        assert!(!api.strip_prefix);
        assert_eq!((all.path.as_str(), all.strip_prefix), ("/", true));
    }

    #[test]
    fn site_needs_root_or_proxy() {
        let msg = invalid(&with_site(""));
        assert_eq!(msg, "site 1 needs a `root`, a [[site.proxy]] or both");
    }

    #[test]
    fn proxy_paths_are_validated() {
        for path in ["api", "", "/api?x", "/a#b"] {
            let msg = invalid(&with_site(&proxy(path, "\"127.0.0.1:1\"")));
            assert!(msg.contains("must start with `/`"), "{path}: {msg}");
        }
        let twice = proxy("/api", "\"127.0.0.1:1\"") + &proxy("/api/", "\"127.0.0.1:2\"");
        assert_eq!(invalid(&with_site(&twice)), "site 1 has two proxies for \"/api\"");
    }

    #[test]
    fn upstreams_are_validated() {
        let msg = invalid(&with_site(&proxy("/", "")));
        assert_eq!(msg, "site 1: proxy \"/\" needs `upstreams`");
        for bad in ["127.0.0.1", "localhost", "http://127.0.0.1:3000", "a:0", "a:99999", "a/b:80"] {
            let msg = invalid(&with_site(&proxy("/", &format!("\"{bad}\""))));
            assert!(msg.contains("must be host:port"), "{bad}: {msg}");
        }
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let err = Config::load(Path::new("/nonexistent/webx4r.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
        assert!(err.to_string().starts_with("can't read /nonexistent/webx4r.toml"));
    }
}
