//! Serves files from a site root, following the original webxlib's behavior.

mod path;
#[cfg(test)]
mod tests;

use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};

use http::header::{ALLOW, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use tokio::fs::{self, File};

use crate::body::Body;
use crate::mime;

pub use path::{PathError, PathPolicy, SafePath, Symlinks, sanitize};

/// Served when a directory is requested with a trailing slash.
const INDEX: &str = "index.html";

/// Characters escaped when rebuilding a path segment for a `Location` header.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Serves GET and HEAD requests from one site root.
#[derive(Debug, Clone)]
pub struct StaticFiles {
    /// Canonical, so symlink targets can be checked against it.
    root: PathBuf,
    policy: PathPolicy,
}

impl StaticFiles {
    /// Fails if `root` doesn't exist.
    pub fn new(root: impl AsRef<Path>, policy: PathPolicy) -> io::Result<Self> {
        Ok(Self {
            root: std::fs::canonicalize(root)?,
            policy,
        })
    }

    pub async fn serve<B>(&self, req: &Request<B>) -> Response<Body> {
        let head = match *req.method() {
            Method::GET => false,
            Method::HEAD => true,
            _ => return method_not_allowed(),
        };
        let safe = match sanitize(req.uri().path(), self.policy) {
            Ok(safe) => safe,
            Err(PathError::Forbidden) => return status(StatusCode::NOT_FOUND),
            Err(PathError::Invalid | PathError::EscapesRoot) => {
                return status(StatusCode::BAD_REQUEST);
            }
        };

        let (path, meta) = match self.locate(&safe.relative).await {
            Ok(found) => found,
            Err(e) => return io_error(&e),
        };
        if meta.is_file() {
            return file_response(&safe.relative, &path, &meta, head).await;
        }
        if !meta.is_dir() {
            return status(StatusCode::NOT_FOUND);
        }
        if !safe.trailing_slash {
            return redirect_to_dir(&safe.relative, req.uri().query());
        }

        let index = safe.relative.join(INDEX);
        match self.locate(&index).await {
            Ok((path, meta)) if meta.is_file() => file_response(&index, &path, &meta, head).await,
            // Directory listings arrive in a later step.
            Ok(_) => status(StatusCode::NOT_FOUND),
            Err(e) => io_error(&e),
        }
    }

    /// Resolves `relative` under the root, applying the symlink policy.
    async fn locate(&self, relative: &Path) -> io::Result<(PathBuf, Metadata)> {
        let path = self.root.join(relative);
        let resolved = match self.policy.symlinks {
            Symlinks::Follow => path,
            Symlinks::InsideRoot => {
                let real = fs::canonicalize(&path).await?;
                if !real.starts_with(&self.root) {
                    return Err(io::ErrorKind::NotFound.into());
                }
                real
            }
            Symlinks::Deny => {
                let real = fs::canonicalize(&path).await?;
                // Any difference means a link was followed; on case-insensitive
                // filesystems a case mismatch is refused too.
                if real != path {
                    return Err(io::ErrorKind::NotFound.into());
                }
                real
            }
        };
        let meta = fs::metadata(&resolved).await?;
        Ok((resolved, meta))
    }
}

/// `name` picks the content type, so a link is typed by its own name rather than its target's.
async fn file_response(name: &Path, path: &Path, meta: &Metadata, head: bool) -> Response<Body> {
    let len = meta.len();
    let body = if head {
        Body::empty()
    } else {
        match File::open(path).await {
            Ok(file) => Body::file(file, len),
            Err(e) => return io_error(&e),
        }
    };
    let content_type = HeaderValue::from_str(&mime::content_type(name))
        .unwrap_or(HeaderValue::from_static(mime::OCTET_STREAM));

    let mut res = Response::new(body);
    let headers = res.headers_mut();
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    res
}

/// Rebuilt from the sanitized path so `//evil.com` can't become an off-site redirect.
fn redirect_to_dir(relative: &Path, query: Option<&str>) -> Response<Body> {
    let mut location = String::from("/");
    for segment in relative.iter() {
        location.extend(utf8_percent_encode(&segment.to_string_lossy(), SEGMENT));
        location.push('/');
    }
    if let Some(query) = query {
        location.push('?');
        location.push_str(query);
    }

    let Ok(location) = HeaderValue::try_from(location) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut res = status(StatusCode::MOVED_PERMANENTLY);
    res.headers_mut().insert(LOCATION, location);
    res
}

fn method_not_allowed() -> Response<Body> {
    let mut res = status(StatusCode::METHOD_NOT_ALLOWED);
    res.headers_mut()
        .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
    res
}

fn io_error(e: &io::Error) -> Response<Body> {
    match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => status(StatusCode::NOT_FOUND),
        io::ErrorKind::PermissionDenied => status(StatusCode::FORBIDDEN),
        _ => status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn status(code: StatusCode) -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = code;
    res
}
