//! Automatic certificates over ACME (RFC 8555): the account, and the files it keeps.

#[cfg(test)]
pub(crate) mod tests;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use instant_acme::{Account, AccountBuilder, AccountCredentials, NewAccount};

use crate::config::Acme;

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
