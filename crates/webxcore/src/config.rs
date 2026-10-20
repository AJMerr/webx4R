//! The `webx4r.toml` config file: parsing and validation.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use webxlib::static_files::{PathPolicy, Symlinks};

const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// A validated config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    /// Automatic certificates; see [`Site::acme_hosts`] for which names get one.
    pub acme: Option<Acme>,
    /// Log files. Without it, the server log goes to stderr and access logs are off.
    pub log: Option<Log>,
    /// The Prometheus endpoint, off without it.
    pub metrics: Option<Metrics>,
    #[serde(rename = "site", default)]
    pub sites: Vec<Site>,
    /// The folder relative paths resolve against: the config file's folder.
    #[serde(skip)]
    pub dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Address for plain HTTP, e.g. `0.0.0.0:8080`.
    pub http: Option<SocketAddr>,
    /// Address for HTTPS, e.g. `0.0.0.0:8443`.
    pub https: Option<SocketAddr>,
    /// Control socket path on Unix, pipe name (`\\.\pipe\…`) on Windows; resolved like `root`.
    /// See [`Config::control_endpoint`] for the default.
    pub control: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    /// Folder for `server.log` and `access.log`, rotated daily; resolved like `root`.
    pub dir: PathBuf,
    /// How many days of each log to keep, today's included.
    #[serde(default = "default_keep_days")]
    pub keep_days: u32,
    #[serde(default)]
    pub access_format: AccessFormat,
}

fn default_keep_days() -> u32 {
    14
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessFormat {
    /// One JSON object per line.
    #[default]
    Json,
    /// nginx's `combined` format.
    Combined,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Address for `/metrics`, apart from the sites, e.g. `127.0.0.1:9100`.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    /// Contact address the CA may use for notices about the account.
    pub email: Option<String>,
    /// `production` (the default) or `staging` for Let's Encrypt, or another CA's
    /// directory URL; see [`Acme::directory_url`].
    pub directory: Option<String>,
    /// Folder for the account key and certificates; resolved like `root`.
    /// See [`Config::acme_storage`] for the default.
    pub storage: Option<PathBuf>,
    /// PEM root certificate to trust, instead of the system's, for the directory's HTTPS:
    /// for private CAs such as step-ca or Pebble. Resolved like `root`.
    pub ca_root: Option<PathBuf>,
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
    /// Redirect plain HTTP requests to HTTPS for the hosts that have a cert; see
    /// [`Site::tls_hosts`]. ACME challenges are never redirected.
    #[serde(default = "yes")]
    pub redirect_https: bool,
}

fn yes() -> bool {
    true
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

impl Acme {
    pub fn directory_url(&self) -> &str {
        match self.directory.as_deref() {
            None | Some("production") => LETS_ENCRYPT,
            Some("staging") => LETS_ENCRYPT_STAGING,
            Some(url) => url,
        }
    }
}

impl Site {
    /// Whether HTTPS can serve this site: it has cert files, a localhost name to self-sign,
    /// or, when `acme` is on, a name to request a cert for.
    pub fn has_tls(&self, acme: bool) -> bool {
        self.cert.is_some()
            || self.hosts.iter().any(|host| is_localhost(host))
            || (acme && self.acme_hosts().next().is_some())
    }

    /// The names ACME requests a cert for: none if the site has cert files, otherwise its
    /// hosts that aren't localhost or IP addresses.
    pub fn acme_hosts(&self) -> impl Iterator<Item = &String> {
        let hosts: &[String] = if self.cert.is_some() { &[] } else { &self.hosts };
        hosts.iter().filter(|host| !is_localhost(host) && host.parse::<IpAddr>().is_err())
    }

    /// The hosts HTTPS has a cert for: all of them with cert files; otherwise localhost
    /// names, and when `acme` is on, the names in [`Site::acme_hosts`].
    pub fn tls_hosts(&self, acme: bool) -> impl Iterator<Item = &String> {
        self.hosts.iter().filter(move |host| {
            self.cert.is_some() || is_localhost(host) || (acme && host.parse::<IpAddr>().is_err())
        })
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

    /// Parses and validates `text`; relative paths resolve against `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(text).map_err(ConfigError::Parse)?;
        config.dir = base.to_owned();
        if let Some(control) = &mut config.server.control {
            // Pipe names are absolute paths on Windows, so `join` leaves them as they are.
            *control = base.join(&*control);
        }
        if let Some(acme) = &mut config.acme {
            for path in [&mut acme.storage, &mut acme.ca_root].into_iter().flatten() {
                *path = base.join(&*path);
            }
        }
        if let Some(log) = &mut config.log {
            log.dir = base.join(&log.dir);
        }
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

    /// Where `webx4r reload` reaches the server: `[server] control`, or the default from
    /// [`default_control_endpoint`].
    pub fn control_endpoint(&self) -> PathBuf {
        match &self.server.control {
            Some(control) => control.clone(),
            None => default_control_endpoint(&self.dir, std::env::var_os("XDG_RUNTIME_DIR")),
        }
    }

    /// Where ACME keeps its account key and certificates: `[acme] storage`, or the default
    /// from [`default_acme_storage`].
    pub fn acme_storage(&self) -> PathBuf {
        match self.acme.as_ref().and_then(|acme| acme.storage.clone()) {
            Some(storage) => storage,
            None => default_acme_storage(&self.dir, std::env::var_os),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        if self.server.http.is_none() && self.server.https.is_none() {
            return invalid("[server] needs `http`, `https` or both".into());
        }
        if let Some(acme) = &self.acme {
            if self.server.https.is_none() {
                return invalid("[acme] needs `https` in [server]".into());
            }
            validate_acme(acme)?;
        }
        if self.log.as_ref().is_some_and(|log| log.keep_days == 0) {
            return invalid("[log] keep_days must be at least 1".into());
        }
        // Port 0 picks a free port, so it can't clash.
        if let Some(Metrics { listen }) = &self.metrics
            && listen.port() != 0
            && [self.server.http, self.server.https].contains(&Some(*listen))
        {
            return invalid(format!("[metrics] listen {listen} is already used in [server]"));
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
        let acme = self.acme.is_some();
        if self.server.https.is_some() && !self.sites.iter().any(|site| site.has_tls(acme)) {
            return invalid(
                "[server] has `https`, but no site has a `cert`, a localhost host, \
                 or a public host with [acme]"
                    .into(),
            );
        }
        Ok(())
    }
}

fn validate_acme(acme: &Acme) -> Result<(), ConfigError> {
    let invalid = |msg: String| Err(ConfigError::Invalid(msg));
    if let Some(email) = &acme.email {
        let address = email.split_once('@').filter(|(user, domain)| {
            !user.is_empty() && is_hostname(domain) && !user.contains(char::is_whitespace)
        });
        if address.is_none() {
            return invalid(format!("[acme] email \"{email}\" isn't an email address"));
        }
    }
    if !acme.directory_url().starts_with("https://") {
        return invalid(
            "[acme] directory must be `production`, `staging` or an https:// URL".into(),
        );
    }
    Ok(())
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

/// Named after the config folder `dir`, so each config gets its own:
/// - Windows: `\\.\pipe\webx4r-<hash>`
/// - Unix: `$XDG_RUNTIME_DIR/webx4r-<hash>.sock`, a short per-user path; socket paths are
///   limited to about 100 bytes. Without that variable, `webx4r.sock` in `dir`.
fn default_control_endpoint(dir: &Path, runtime_dir: Option<OsString>) -> PathBuf {
    let (dir, hash) = config_folder(dir);
    if cfg!(windows) {
        return PathBuf::from(format!(r"\\.\pipe\webx4r-{hash:016x}"));
    }
    match runtime_dir.map(PathBuf::from) {
        // The XDG spec says to ignore a relative value.
        Some(runtime_dir) if runtime_dir.is_absolute() => {
            runtime_dir.join(format!("webx4r-{hash:016x}.sock"))
        }
        _ => dir.join("webx4r.sock"),
    }
}

/// `webx4r/<hash>/acme` in the per-user state folder, named after the config folder `dir`:
/// `%LOCALAPPDATA%` on Windows, else `$XDG_STATE_HOME` or `~/.local/state`.
/// Without those, `webx4r-acme` in `dir`. `var` reads an environment variable.
fn default_acme_storage(dir: &Path, var: impl Fn(&'static str) -> Option<OsString>) -> PathBuf {
    let (dir, hash) = config_folder(dir);
    // The XDG spec says to ignore relative values.
    let absolute = |name| var(name).map(PathBuf::from).filter(|path| path.is_absolute());
    let state = if cfg!(windows) {
        absolute("LOCALAPPDATA")
    } else {
        absolute("XDG_STATE_HOME").or_else(|| Some(absolute("HOME")?.join(".local/state")))
    };
    match state {
        Some(state) => state.join("webx4r").join(format!("{hash:016x}")).join("acme"),
        None => dir.join("webx4r-acme"),
    }
}

/// `dir` made absolute, and its hash for naming per-config files and folders.
fn config_folder(dir: &Path) -> (PathBuf, u64) {
    let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_owned());
    let key = dir.to_string_lossy();
    // Windows paths ignore case, so differently-cased spellings must hash alike.
    let key = if cfg!(windows) { key.to_lowercase() } else { key.into_owned() };
    let hash = fnv1a(key.as_bytes());
    (dir, hash)
}

/// 64-bit FNV-1a: a hash that stays the same across Rust versions, unlike `DefaultHasher`,
/// so a newer `webx4r reload` still finds an older server's pipe.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |hash, &b| (hash ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
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
        assert!(site.has_tls(false));
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
        assert_eq!(
            msg,
            "[server] has `https`, but no site has a `cert`, a localhost host, \
             or a public host with [acme]"
        );
        for host in ["localhost", "app.localhost"] {
            let config = parse(&with_tls(HTTPS, "").replace("example.com", host)).unwrap();
            assert!(config.sites[0].has_tls(false), "{host}");
        }
        let config = parse(&(with_tls(HTTPS, "") + ACME)).unwrap();
        assert!(config.sites[0].has_tls(true), "ACME covers example.com");
    }

    #[test]
    fn tls_hosts_and_redirects() {
        let hosts = "\"example.com\", \"localhost\", \"127.0.0.1\"";
        let text = with_tls(HTTPS, "").replace("\"example.com\"", hosts);
        let config = parse(&text).unwrap();
        let site = &config.sites[0];
        assert!(site.redirect_https, "on by default");
        assert_eq!(site.tls_hosts(false).collect::<Vec<_>>(), ["localhost"]);
        assert_eq!(site.tls_hosts(true).collect::<Vec<_>>(), ["example.com", "localhost"]);

        let config = parse(&(text.clone() + CERT + "\nredirect_https = false")).unwrap();
        let site = &config.sites[0];
        assert!(!site.redirect_https);
        assert_eq!(site.tls_hosts(false).count(), 3, "cert files cover every host");
    }

    const ACME: &str = "\n[acme]\n";

    #[test]
    fn acme_settings() {
        let acme = "email = \"me@example.com\"\ndirectory = \"staging\"\nstorage = \"state\"\n\
                    ca_root = \"ca/root.pem\"";
        let config = parse(&(with_tls(HTTPS, "") + ACME + acme)).unwrap();
        let acme = config.acme.as_ref().unwrap();
        assert_eq!(acme.email.as_deref(), Some("me@example.com"));
        assert_eq!(acme.directory_url(), LETS_ENCRYPT_STAGING);
        assert_eq!(acme.ca_root.as_deref(), Some(Path::new("/etc/webx4r/ca/root.pem")));
        assert_eq!(config.acme_storage(), Path::new("/etc/webx4r/state"));
    }

    #[test]
    fn acme_defaults() {
        let config = parse(&(with_tls(HTTPS, "") + ACME)).unwrap();
        let acme = config.acme.as_ref().unwrap();
        assert_eq!((acme.email.as_deref(), acme.storage.as_deref()), (None, None));
        assert_eq!(acme.ca_root, None);
        assert_eq!(acme.directory_url(), LETS_ENCRYPT);
        assert_eq!(parse(MINIMAL).unwrap().acme, None, "off without [acme]");
    }

    #[test]
    fn acme_needs_https() {
        let msg = invalid(&(MINIMAL.to_owned() + ACME));
        assert_eq!(msg, "[acme] needs `https` in [server]");
    }

    #[test]
    fn acme_directory_is_validated() {
        let url = "https://localhost:14000/dir";
        let custom = parse(&(with_tls(HTTPS, "") + ACME + &format!("directory = \"{url}\"")));
        assert_eq!(custom.unwrap().acme.unwrap().directory_url(), url);
        for bad in ["http://localhost:14000/dir", "prod", ""] {
            let msg = invalid(&(with_tls(HTTPS, "") + ACME + &format!("directory = \"{bad}\"")));
            assert!(msg.contains("must be `production`, `staging`"), "{bad}: {msg}");
        }
    }

    #[test]
    fn acme_email_is_validated() {
        for bad in ["me", "@example.com", "me@", "me @example.com", "me@exa mple.com"] {
            let msg = invalid(&(with_tls(HTTPS, "") + ACME + &format!("email = \"{bad}\"")));
            assert!(msg.ends_with("isn't an email address"), "{bad}: {msg}");
        }
    }

    #[test]
    fn acme_hosts_skip_localhost_ips_and_cert_files() {
        let hosts = "\"example.com\", \"localhost\", \"127.0.0.1\", \"www.example.com\"";
        let text = with_tls(HTTPS, "").replace("\"example.com\"", hosts) + ACME;
        let config = parse(&text).unwrap();
        let names: Vec<_> = config.sites[0].acme_hosts().collect();
        assert_eq!(names, ["example.com", "www.example.com"]);

        let config = parse(&(with_tls(HTTPS, CERT) + ACME)).unwrap();
        assert_eq!(config.sites[0].acme_hosts().count(), 0, "cert files take priority");
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
    fn log_settings_and_defaults() {
        assert_eq!(parse(MINIMAL).unwrap().log, None, "stderr only without [log]");
        let config = parse(&format!("{MINIMAL}\n[log]\ndir = \"logs\"")).unwrap();
        let log = config.log.unwrap();
        assert_eq!(log.dir, Path::new("/etc/webx4r/logs"));
        assert_eq!((log.keep_days, log.access_format), (14, AccessFormat::Json));

        let text = format!("{MINIMAL}\n[log]\ndir = \"/var/log/webx4r\"\nkeep_days = 30\n");
        let config = parse(&(text + "access_format = \"combined\"")).unwrap();
        let log = config.log.unwrap();
        assert_eq!(log.dir, Path::new("/var/log/webx4r"));
        assert_eq!((log.keep_days, log.access_format), (30, AccessFormat::Combined));
    }

    #[test]
    fn log_settings_are_validated() {
        let no_dir = parse(&format!("{MINIMAL}\n[log]\nkeep_days = 7"));
        assert!(matches!(no_dir, Err(ConfigError::Parse(_))), "`dir` is required");
        let msg = invalid(&format!("{MINIMAL}\n[log]\ndir = \"logs\"\nkeep_days = 0"));
        assert_eq!(msg, "[log] keep_days must be at least 1");
        let format = parse(&format!("{MINIMAL}\n[log]\ndir = \"logs\"\naccess_format = \"xml\""));
        assert!(matches!(format, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn metrics_listen_is_its_own_address() {
        assert_eq!(parse(MINIMAL).unwrap().metrics, None, "off without [metrics]");
        let config = parse(&format!("{MINIMAL}\n[metrics]\nlisten = \"127.0.0.1:9100\"")).unwrap();
        assert_eq!(config.metrics.unwrap().listen, "127.0.0.1:9100".parse().unwrap());
        let msg = invalid(&format!("{MINIMAL}\n[metrics]\nlisten = \"0.0.0.0:8080\""));
        assert_eq!(msg, "[metrics] listen 0.0.0.0:8080 is already used in [server]");
        let any_port = MINIMAL.replace("0.0.0.0:8080", "127.0.0.1:0");
        parse(&format!("{any_port}\n[metrics]\nlisten = \"127.0.0.1:0\"")).unwrap();
    }

    #[test]
    fn explicit_control_endpoint_resolves_like_root() {
        let text = MINIMAL.replace("0.0.0.0:8080\"", "0.0.0.0:8080\"\ncontrol = \"run/ctl.sock\"");
        let explicit = parse(&text).unwrap().control_endpoint();
        assert_eq!(explicit, Path::new("/etc/webx4r/run/ctl.sock"));
    }

    #[cfg(windows)]
    #[test]
    fn default_control_endpoint_is_a_pipe_per_folder() {
        let pipe = |dir: &str| default_control_endpoint(Path::new(dir), None);
        assert!(pipe(r"C:\sites\a").to_string_lossy().starts_with(r"\\.\pipe\webx4r-"));
        assert_eq!(pipe(r"C:\Sites\A"), pipe(r"c:\sites\a"), "case doesn't matter");
        assert_ne!(pipe(r"C:\sites\a"), pipe(r"C:\sites\b"));
    }

    #[cfg(unix)]
    #[test]
    fn default_control_endpoint_is_a_short_per_user_socket() {
        let runtime = Some(OsString::from("/run/user/1000"));
        let a = default_control_endpoint(Path::new("/srv/a/deeply/nested/folder"), runtime.clone());
        let b = default_control_endpoint(Path::new("/srv/b"), runtime);
        assert_eq!(a.parent(), Some(Path::new("/run/user/1000")));
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("webx4r-") && name.ends_with(".sock") && name.len() == 28,
            "{name}"
        );
        assert_ne!(a, b, "one socket per config folder");
    }

    #[cfg(unix)]
    #[test]
    fn default_control_endpoint_without_a_runtime_dir() {
        let dir = Path::new("/etc/webx4r");
        let next_to_config = Path::new("/etc/webx4r/webx4r.sock");
        assert_eq!(default_control_endpoint(dir, None), next_to_config);
        let relative = Some(OsString::from("run"));
        assert_eq!(default_control_endpoint(dir, relative), next_to_config, "relative is ignored");
    }

    /// [`default_acme_storage`] with only the environment variables in `vars` set.
    fn acme_storage(dir: &str, vars: &[(&str, &str)]) -> PathBuf {
        default_acme_storage(Path::new(dir), |name| {
            vars.iter().find(|(var, _)| *var == name).map(|(_, value)| OsString::from(value))
        })
    }

    #[cfg(windows)]
    #[test]
    fn default_acme_storage_is_in_local_app_data() {
        let local = [("LOCALAPPDATA", r"C:\Users\me\AppData\Local")];
        let a = acme_storage(r"C:\sites\a", &local);
        assert!(a.starts_with(r"C:\Users\me\AppData\Local\webx4r") && a.ends_with("acme"), "{a:?}");
        assert_eq!(acme_storage(r"C:\Sites\A", &local), a, "case doesn't matter");
        assert_ne!(acme_storage(r"C:\sites\b", &local), a);
        assert_eq!(acme_storage(r"C:\sites\a", &[]), Path::new(r"C:\sites\a\webx4r-acme"));
    }

    #[cfg(unix)]
    #[test]
    fn default_acme_storage_is_per_user_state() {
        let state = [("XDG_STATE_HOME", "/state"), ("HOME", "/home/me")];
        let a = acme_storage("/srv/a", &state);
        let name = a.parent().unwrap().file_name().unwrap().to_str().unwrap();
        assert_eq!(a, Path::new("/state/webx4r").join(name).join("acme"));
        assert_eq!(name.len(), 16, "{name}");
        assert_ne!(acme_storage("/srv/b", &state), a, "one folder per config folder");

        let home = acme_storage("/srv/a", &[("XDG_STATE_HOME", "state"), ("HOME", "/home/me")]);
        assert!(home.starts_with("/home/me/.local/state/webx4r"), "relative is ignored: {home:?}");
        assert_eq!(acme_storage("/srv/a", &[]), Path::new("/srv/a/webx4r-acme"));
    }

    #[test]
    fn fnv1a_matches_the_reference() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let err = Config::load(Path::new("/nonexistent/webx4r.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
        assert!(err.to_string().starts_with("can't read /nonexistent/webx4r.toml"));
    }
}
