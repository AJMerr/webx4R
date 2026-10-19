//! Turns a request path into a relative file path that can't escape the site root.

use std::path::PathBuf;

use percent_encoding::percent_decode_str;

/// Controls which request paths are served.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathPolicy {
    /// Allow segments starting with `.`; a leading `/.well-known/` is always allowed.
    pub allow_dotfiles: bool,
    pub symlinks: Symlinks,
    /// List the contents of directories that have no `index.html`.
    pub directory_listing: bool,
}

/// How symlinks inside a site root are treated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Symlinks {
    /// Follow every link, wherever it points.
    Follow,
    /// Follow relative links that stay inside the site root; absolute targets are refused.
    #[default]
    InsideRoot,
    /// Refuse any path that goes through a link.
    Deny,
}

/// A request path that is safe to join onto a site root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePath {
    /// Path relative to the site root; empty for `/`.
    pub relative: PathBuf,
    /// Whether the request path ended in `/`.
    pub trailing_slash: bool,
}

/// Why a request path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Not absolute, not UTF-8 after decoding, or contains NUL, `/` (encoded), `\` or `:`.
    Invalid,
    /// A `..` segment climbs above the site root.
    EscapesRoot,
    /// Hidden by policy, or a name Windows would alias to another file or a device.
    Forbidden,
}

/// Decodes and normalizes `path` (the URI path, without the query string).
pub fn sanitize(path: &str, policy: PathPolicy) -> Result<SafePath, PathError> {
    let rest = path.strip_prefix('/').ok_or(PathError::Invalid)?;
    let mut relative = PathBuf::new();

    for raw in rest.split('/') {
        let segment = percent_decode_str(raw).decode_utf8().map_err(|_| PathError::Invalid)?;
        match segment.as_ref() {
            "" | "." => {}
            ".." => {
                if !relative.pop() {
                    return Err(PathError::EscapesRoot);
                }
            }
            name => {
                check_segment(name, policy, relative.as_os_str().is_empty())?;
                relative.push(name);
            }
        }
    }

    Ok(SafePath { relative, trailing_slash: path.ends_with('/') })
}

pub(super) fn check_segment(
    name: &str,
    policy: PathPolicy,
    is_first: bool,
) -> Result<(), PathError> {
    if name.contains(['\0', '/', '\\', ':']) {
        return Err(PathError::Invalid);
    }
    let well_known = is_first && name == ".well-known";
    if name.starts_with('.') && !policy.allow_dotfiles && !well_known {
        return Err(PathError::Forbidden);
    }
    // Windows strips trailing dots and spaces, so `secret.txt.` would open `secret.txt`.
    if name.ends_with(['.', ' ']) || is_windows_device(name) {
        return Err(PathError::Forbidden);
    }
    Ok(())
}

/// Windows reserves these names in every directory, with or without an extension.
fn is_windows_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    matches!(
        stem.as_bytes(),
        b"CON"
            | b"PRN"
            | b"AUX"
            | b"NUL"
            | [b'C', b'O', b'M', b'1'..=b'9']
            | [b'L', b'P', b'T', b'1'..=b'9']
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY: PathPolicy = PathPolicy {
        allow_dotfiles: false,
        symlinks: Symlinks::InsideRoot,
        directory_listing: false,
    };
    const ALLOW: PathPolicy = PathPolicy { allow_dotfiles: true, ..DENY };

    fn ok(path: &str) -> SafePath {
        sanitize(path, DENY).unwrap()
    }

    fn err(path: &str) -> PathError {
        sanitize(path, DENY).unwrap_err()
    }

    #[test]
    fn root_and_plain_paths() {
        assert_eq!(ok("/").relative, PathBuf::new());
        assert!(ok("/").trailing_slash);
        assert_eq!(ok("/index.html").relative, PathBuf::from("index.html"));
        assert_eq!(ok("/a/b/c.css").relative, PathBuf::from("a/b/c.css"));
        assert!(!ok("/docs").trailing_slash);
        assert!(ok("/docs/").trailing_slash);
    }

    #[test]
    fn dot_segments_resolve_within_root() {
        assert_eq!(ok("/a/./b").relative, PathBuf::from("a/b"));
        assert_eq!(ok("/a/../b").relative, PathBuf::from("b"));
        assert_eq!(ok("//a//b").relative, PathBuf::from("a/b"));
        assert_eq!(ok("/a/..").relative, PathBuf::new());
    }

    #[test]
    fn climbing_above_root_is_rejected() {
        assert_eq!(err("/.."), PathError::EscapesRoot);
        assert_eq!(err("/a/../../etc/passwd"), PathError::EscapesRoot);
        assert_eq!(err("/%2e%2e/etc/passwd"), PathError::EscapesRoot);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(ok("/my%20file.txt").relative, PathBuf::from("my file.txt"));
        assert_eq!(ok("/caf%C3%A9").relative, PathBuf::from("café"));
    }

    #[test]
    fn malformed_paths_are_invalid() {
        assert_eq!(err("index.html"), PathError::Invalid);
        assert_eq!(err("/a%2Fb"), PathError::Invalid);
        assert_eq!(err("/a%5Cb"), PathError::Invalid);
        assert_eq!(err("/a\\b"), PathError::Invalid);
        assert_eq!(err("/c:/windows"), PathError::Invalid);
        assert_eq!(err("/file%00.txt"), PathError::Invalid);
        assert_eq!(err("/%FF"), PathError::Invalid);
    }

    #[test]
    fn dotfiles_follow_policy() {
        assert_eq!(err("/.env"), PathError::Forbidden);
        assert_eq!(err("/.git/config"), PathError::Forbidden);
        assert_eq!(err("/app/.env"), PathError::Forbidden);
        assert_eq!(err("/a/../.env"), PathError::Forbidden);
        let allowed = sanitize("/.env", ALLOW).unwrap();
        assert_eq!(allowed.relative, PathBuf::from(".env"));
    }

    #[test]
    fn well_known_is_always_allowed_at_the_top() {
        assert_eq!(
            ok("/.well-known/security.txt").relative,
            PathBuf::from(".well-known/security.txt")
        );
        assert_eq!(err("/a/.well-known/x"), PathError::Forbidden);
        assert_eq!(err("/.well-known/.hidden"), PathError::Forbidden);
    }

    #[test]
    fn windows_aliases_are_forbidden() {
        assert_eq!(err("/secret.txt."), PathError::Forbidden);
        assert_eq!(err("/secret.txt%20"), PathError::Forbidden);
        assert_eq!(err("/CON"), PathError::Forbidden);
        assert_eq!(err("/nul.txt"), PathError::Forbidden);
        assert_eq!(err("/files/com1.log"), PathError::Forbidden);
        assert_eq!(err("/LPT9"), PathError::Forbidden);
        assert_eq!(ok("/console.html").relative, PathBuf::from("console.html"));
        assert_eq!(ok("/com10").relative, PathBuf::from("com10"));
    }

    #[test]
    fn multibyte_names_near_device_length() {
        assert_eq!(ok("/ab%C3%A9").relative, PathBuf::from("abé"));
        assert_eq!(ok("/%C3%A9").relative, PathBuf::from("é"));
    }
}
