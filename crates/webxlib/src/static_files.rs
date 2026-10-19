//! Serves files from a site root, following the original webxlib's behavior.

mod path;
#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use http::header::{ALLOW, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use tokio::fs::File;

use crate::body::Body;
use crate::{mime, pages};

pub use path::{PathError, PathPolicy, SafePath, Symlinks, sanitize};

/// Served when a directory is requested with a trailing slash.
const INDEX: &str = "index.html";

const HTML: &str = "text/html; charset=utf-8";

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
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Handle that sandboxes lookups: the OS refuses to resolve outside it.
    dir: Dir,
    /// Canonical root path, used only by [`Symlinks::Follow`].
    root: PathBuf,
    policy: PathPolicy,
}

/// What a sanitized path refers to.
enum Target {
    File { file: File, len: u64 },
    Dir,
}

impl StaticFiles {
    /// Fails if `root` doesn't exist.
    pub fn new(root: impl AsRef<Path>, policy: PathPolicy) -> io::Result<Self> {
        let root = std::fs::canonicalize(root)?;
        let dir = Dir::open_ambient_dir(&root, ambient_authority())?;
        Ok(Self {
            inner: Arc::new(Inner { dir, root, policy }),
        })
    }

    pub async fn serve<B>(&self, req: &Request<B>) -> Response<Body> {
        let head = req.method() == Method::HEAD;
        match self.respond(req, head).await {
            Ok(res) => res,
            Err(code) => self.error_response(code, head).await,
        }
    }

    async fn respond<B>(&self, req: &Request<B>, head: bool) -> Result<Response<Body>, StatusCode> {
        if !matches!(*req.method(), Method::GET | Method::HEAD) {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        let safe = sanitize(req.uri().path(), self.inner.policy).map_err(|e| match e {
            PathError::Forbidden => StatusCode::NOT_FOUND,
            PathError::Invalid | PathError::EscapesRoot => StatusCode::BAD_REQUEST,
        })?;

        let target = self.locate(safe.relative.clone()).await;
        match target.map_err(|e| io_status(&e))? {
            Target::File { file, len } => Ok(file_response(&safe.relative, file, len, head)),
            Target::Dir if !safe.trailing_slash => {
                redirect_to_dir(&safe.relative, req.uri().query())
            }
            Target::Dir => {
                let index = safe.relative.join(INDEX);
                match self.locate(index.clone()).await {
                    Ok(Target::File { file, len }) => Ok(file_response(&index, file, len, head)),
                    Err(e) if io_status(&e) != StatusCode::NOT_FOUND => Err(io_status(&e)),
                    _ if safe.relative.as_os_str().is_empty() => {
                        Ok(html_response(pages::welcome(), head))
                    }
                    // Directory listings arrive in a later step.
                    _ => Err(StatusCode::NOT_FOUND),
                }
            }
        }
    }

    /// Serves the site's own `<code>.html` if it has one, else the built-in page.
    async fn error_response(&self, code: StatusCode, head: bool) -> Response<Body> {
        let custom = PathBuf::from(format!("{}.html", code.as_u16()));
        let mut res = match self.locate(custom.clone()).await {
            Ok(Target::File { file, len }) => file_response(&custom, file, len, head),
            _ => html_response(pages::error(code), head),
        };
        *res.status_mut() = code;
        if code == StatusCode::METHOD_NOT_ALLOWED {
            res.headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        }
        res
    }

    /// Runs all filesystem work for one lookup in a single blocking task.
    async fn locate(&self, relative: PathBuf) -> io::Result<Target> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.locate(&relative))
            .await
            .map_err(io::Error::other)?
    }
}

impl Inner {
    fn locate(&self, relative: &Path) -> io::Result<Target> {
        match self.policy.symlinks {
            Symlinks::Follow => self.locate_follow(relative),
            Symlinks::InsideRoot => self.locate_inside_root(relative).map_err(hide_escape),
            Symlinks::Deny => self.locate_no_links(relative).map_err(hide_escape),
        }
    }

    fn locate_follow(&self, relative: &Path) -> io::Result<Target> {
        let path = self.root.join(relative);
        if std::fs::metadata(&path)?.is_dir() {
            return Ok(Target::Dir);
        }
        open_regular(std::fs::File::open(path)?)
    }

    /// The open is sandboxed, so a link swapped after the metadata check still can't escape.
    fn locate_inside_root(&self, relative: &Path) -> io::Result<Target> {
        let path = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        let meta = self.dir.metadata(path)?;
        if meta.is_dir() {
            return Ok(Target::Dir);
        }
        // Checked before opening: opening a FIFO would block the thread.
        if !meta.is_file() {
            return Err(io::ErrorKind::NotFound.into());
        }
        open_regular(self.dir.open(path)?.into_std())
    }

    /// Walks one component at a time without following links, so no link is ever traversed.
    fn locate_no_links(&self, relative: &Path) -> io::Result<Target> {
        let mut parts = relative.iter();
        let Some(last) = parts.next_back() else {
            return Ok(Target::Dir);
        };
        let mut dir = self.dir.try_clone()?;
        for part in parts {
            // Checked explicitly: the error a no-follow open gives for a link differs by OS.
            if dir.symlink_metadata(part)?.file_type().is_symlink() {
                return Err(io::ErrorKind::NotFound.into());
            }
            dir = dir.open_dir_nofollow(part)?;
        }

        let file_type = dir.symlink_metadata(last)?.file_type();
        if file_type.is_symlink() || !(file_type.is_dir() || file_type.is_file()) {
            return Err(io::ErrorKind::NotFound.into());
        }
        if file_type.is_dir() {
            return Ok(Target::Dir);
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        open_regular(dir.open_with(last, &options)?.into_std())
    }
}

/// Re-checks the opened handle, which is authoritative even if the path changed.
fn open_regular(file: std::fs::File) -> io::Result<Target> {
    let meta = file.metadata()?;
    if meta.is_dir() {
        Ok(Target::Dir)
    } else if meta.is_file() {
        Ok(Target::File {
            file: File::from_std(file),
            len: meta.len(),
        })
    } else {
        Err(io::ErrorKind::NotFound.into())
    }
}

/// cap-std reports escape attempts as `PermissionDenied` with no OS error code;
/// answer those with 404 so they look like any missing file.
fn hide_escape(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::PermissionDenied && e.raw_os_error().is_none() {
        io::ErrorKind::NotFound.into()
    } else {
        e
    }
}

/// `name` picks the content type, so a link is typed by its own name rather than its target's.
fn file_response(name: &Path, file: File, len: u64, head: bool) -> Response<Body> {
    let body = if head {
        Body::empty()
    } else {
        Body::file(file, len)
    };
    let content_type = HeaderValue::from_str(&mime::content_type(name))
        .unwrap_or(HeaderValue::from_static(mime::OCTET_STREAM));

    let mut res = Response::new(body);
    let headers = res.headers_mut();
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    res
}

fn html_response(page: Bytes, head: bool) -> Response<Body> {
    let len = page.len();
    let body = if head {
        Body::empty()
    } else {
        Body::bytes(page)
    };

    let mut res = Response::new(body);
    let headers = res.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(HTML));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    res
}

/// Rebuilt from the sanitized path so `//evil.com` can't become an off-site redirect.
fn redirect_to_dir(relative: &Path, query: Option<&str>) -> Result<Response<Body>, StatusCode> {
    let mut location = String::from("/");
    for segment in relative.iter() {
        location.extend(utf8_percent_encode(&segment.to_string_lossy(), SEGMENT));
        location.push('/');
    }
    if let Some(query) = query {
        location.push('?');
        location.push_str(query);
    }

    let location =
        HeaderValue::try_from(location).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::MOVED_PERMANENTLY;
    res.headers_mut().insert(LOCATION, location);
    Ok(res)
}

fn io_status(e: &io::Error) -> StatusCode {
    match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
