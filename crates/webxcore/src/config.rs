//! The `webx4r.toml` config file: parsing and validation.

use std::collections::HashMap;
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
    pub http: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    /// Lowercase hostnames, without ports.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Absolute after loading; relative paths resolve against the config file's folder.
    pub root: PathBuf,
    /// Serves requests whose `Host` matches no other site.
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub directory_listing: bool,
    #[serde(default)]
    pub allow_dotfiles: bool,
    #[serde(default)]
    pub symlinks: SymlinkSetting,
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
            site.root = base.join(&site.root);
            for host in &mut site.hosts {
                host.make_ascii_lowercase();
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
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
        Ok(())
    }
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
        assert_eq!(config.server.http, "0.0.0.0:8080".parse().unwrap());
        let site = &config.sites[0];
        assert_eq!(site.root, Path::new("/etc/webx4r/www"));
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
        assert_eq!(site.root, Path::new("/srv/www"));
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

    #[test]
    fn missing_file_is_a_read_error() {
        let err = Config::load(Path::new("/nonexistent/webx4r.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
        assert!(err.to_string().starts_with("can't read /nonexistent/webx4r.toml"));
    }
}
