//! Serves files from a site root, following the original webxlib's behavior.

mod conditional;
mod listing;
mod path;
mod range;
#[cfg(test)]
mod tests;

use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use http::header::{
    ACCEPT_RANGES, ALLOW, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use tokio::fs::File;
use tokio::io::AsyncSeekExt;

use crate::body::Body;
use crate::{mime, pages};

use conditional::{Precondition, Validators};
use listing::Entry;
use path::check_segment;
pub use path::{PathError, PathPolicy, SafePath, Symlinks, sanitize};
use range::{ByteRange, RangePlan};

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
    File(OpenFile),
    /// An open handle, so later reads use the directory that passed the policy checks.
    Dir(Dir),
}

/// A regular file, with metadata read from its open handle.
struct OpenFile {
    file: File,
    len: u64,
    modified: Option<SystemTime>,
}

impl StaticFiles {
    /// Fails if `root` doesn't exist.
    pub fn new(root: impl AsRef<Path>, policy: PathPolicy) -> io::Result<Self> {
        let root = std::fs::canonicalize(root)?;
        let dir = Dir::open_ambient_dir(&root, ambient_authority())?;
        Ok(Self { inner: Arc::new(Inner { dir, root, policy }) })
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
            Target::File(open) => serve_file(req, &safe.relative, open, head).await,
            Target::Dir(_) if !safe.trailing_slash => {
                redirect_to_dir(&safe.relative, req.uri().query())
            }
            Target::Dir(dir) => {
                let index = safe.relative.join(INDEX);
                match self.locate(index.clone()).await {
                    Ok(Target::File(open)) => return serve_file(req, &index, open, head).await,
                    Err(e) if io_status(&e) != StatusCode::NOT_FOUND => return Err(io_status(&e)),
                    _ => {}
                }
                if self.inner.policy.directory_listing {
                    let page = self.listing(dir, safe.relative).await;
                    Ok(html_response(page.map_err(|e| io_status(&e))?, head))
                } else if safe.relative.as_os_str().is_empty() {
                    Ok(html_response(pages::welcome(), head))
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
    }

    /// Serves the site's own `<code>.html` if it has one, else the built-in page.
    async fn error_response(&self, code: StatusCode, head: bool) -> Response<Body> {
        let custom = PathBuf::from(format!("{}.html", code.as_u16()));
        let mut res = match self.locate(custom.clone()).await {
            Ok(Target::File(open)) => file_response(&custom, open, head),
            _ => html_response(pages::error(code), head),
        };
        *res.status_mut() = code;
        if code == StatusCode::METHOD_NOT_ALLOWED {
            res.headers_mut().insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
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

    async fn listing(&self, dir: Dir, relative: PathBuf) -> io::Result<Bytes> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let entries = inner.list(&dir, &relative)?;
            Ok(listing::render(&relative, entries))
        })
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
            let dir = Dir::open_ambient_dir(&path, ambient_authority())?;
            return Ok(Target::Dir(dir));
        }
        open_regular(std::fs::File::open(path)?)
    }

    /// The open is sandboxed, so a link swapped after the metadata check still can't escape.
    fn locate_inside_root(&self, relative: &Path) -> io::Result<Target> {
        let path = if relative.as_os_str().is_empty() { Path::new(".") } else { relative };
        let meta = self.dir.metadata(path)?;
        if meta.is_dir() {
            return Ok(Target::Dir(self.dir.open_dir(path)?));
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
            return Ok(Target::Dir(self.dir.try_clone()?));
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
            return Ok(Target::Dir(dir.open_dir_nofollow(last)?));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        open_regular(dir.open_with(last, &options)?.into_std())
    }

    /// Lists only entries a request could actually reach under the current policy.
    fn list(&self, dir: &Dir, relative: &Path) -> io::Result<Vec<Entry>> {
        let at_root = relative.as_os_str().is_empty();
        let mut entries = Vec::new();
        for entry in dir.entries()? {
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if check_segment(&name, self.policy, at_root).is_err() {
                continue;
            }
            let file_type = entry.file_type()?;
            let is_dir = if file_type.is_symlink() {
                match self.link_is_dir(relative, &name) {
                    Some(is_dir) => is_dir,
                    None => continue,
                }
            } else if file_type.is_dir() || file_type.is_file() {
                file_type.is_dir()
            } else {
                continue;
            };
            entries.push(Entry { name, is_dir });
        }
        Ok(entries)
    }

    /// Whether a link leads to a directory, or `None` if the symlink policy would refuse it.
    fn link_is_dir(&self, relative: &Path, name: &str) -> Option<bool> {
        let (is_dir, is_file) = match self.policy.symlinks {
            Symlinks::Deny => return None,
            Symlinks::InsideRoot => {
                let meta = self.dir.metadata(relative.join(name)).ok()?;
                (meta.is_dir(), meta.is_file())
            }
            Symlinks::Follow => {
                let meta = std::fs::metadata(self.root.join(relative).join(name)).ok()?;
                (meta.is_dir(), meta.is_file())
            }
        };
        (is_dir || is_file).then_some(is_dir)
    }
}

/// Re-checks the opened handle, which is authoritative even if the path changed.
fn open_regular(file: std::fs::File) -> io::Result<Target> {
    let meta = file.metadata()?;
    if meta.is_dir() {
        Ok(Target::Dir(Dir::from_std_file(file)))
    } else if meta.is_file() {
        Ok(Target::File(OpenFile {
            file: File::from_std(file),
            len: meta.len(),
            modified: meta.modified().ok(),
        }))
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
/// A full or partial file response with validators, or 304/412/416 when the request calls for it.
async fn serve_file<B>(
    req: &Request<B>,
    name: &Path,
    open: OpenFile,
    head: bool,
) -> Result<Response<Body>, StatusCode> {
    let validators = Validators::new(open.len, open.modified);
    let mut res = match conditional::evaluate(req.headers(), &validators) {
        Precondition::Failed => return Err(StatusCode::PRECONDITION_FAILED),
        Precondition::NotModified => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::NOT_MODIFIED;
            res
        }
        Precondition::Proceed => match requested_ranges(req, &validators, open.len) {
            RangePlan::Full => file_response(name, open, head),
            RangePlan::Partial(ranges) => {
                partial_response(name, open, &ranges).await.map_err(|e| io_status(&e))?
            }
            RangePlan::Unsatisfiable => range_not_satisfiable(open.len),
        },
    };
    validators.insert_into(res.headers_mut());
    res.headers_mut().insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(res)
}

/// Range is defined only for GET, and only while `If-Range` still names this version.
fn requested_ranges<B>(req: &Request<B>, validators: &Validators, len: u64) -> RangePlan {
    let header = req.headers().get(RANGE).and_then(|v| v.to_str().ok());
    match header {
        Some(header)
            if req.method() == Method::GET
                && conditional::if_range_matches(req.headers(), validators) =>
        {
            range::plan(header, len)
        }
        _ => RangePlan::Full,
    }
}

async fn partial_response(
    name: &Path,
    open: OpenFile,
    ranges: &[ByteRange],
) -> io::Result<Response<Body>> {
    let OpenFile { mut file, len: total, .. } = open;
    let mut res = if let [range] = ranges {
        let content_range = HeaderValue::try_from(range.content_range(total));
        let content_range = content_range.map_err(io::Error::other)?;
        file.seek(SeekFrom::Start(range.start)).await?;
        let mut res = Response::new(Body::file(file, range.len()));
        let headers = res.headers_mut();
        headers.insert(CONTENT_TYPE, content_type(name));
        headers.insert(CONTENT_LENGTH, HeaderValue::from(range.len()));
        headers.insert(CONTENT_RANGE, content_range);
        res
    } else {
        let part_type = mime::content_type(name);
        let (multipart_type, len, stream) = range::multipart(file, &part_type, ranges, total);
        let multipart_type = HeaderValue::try_from(multipart_type).map_err(io::Error::other)?;
        let mut res = Response::new(Body::stream(stream, len));
        let headers = res.headers_mut();
        headers.insert(CONTENT_TYPE, multipart_type);
        headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
        res
    };
    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
    Ok(res)
}

fn range_not_satisfiable(len: u64) -> Response<Body> {
    let code = StatusCode::RANGE_NOT_SATISFIABLE;
    let mut res = html_response(pages::error(code), false);
    *res.status_mut() = code;
    if let Ok(value) = HeaderValue::try_from(format!("bytes */{len}")) {
        res.headers_mut().insert(CONTENT_RANGE, value);
    }
    res
}

fn file_response(name: &Path, open: OpenFile, head: bool) -> Response<Body> {
    let OpenFile { file, len, .. } = open;
    let body = if head { Body::empty() } else { Body::file(file, len) };
    let mut res = Response::new(body);
    let headers = res.headers_mut();
    headers.insert(CONTENT_TYPE, content_type(name));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    res
}

fn content_type(name: &Path) -> HeaderValue {
    HeaderValue::from_str(&mime::content_type(name))
        .unwrap_or(HeaderValue::from_static(mime::OCTET_STREAM))
}

fn html_response(page: Bytes, head: bool) -> Response<Body> {
    let len = page.len();
    let body = if head { Body::empty() } else { Body::bytes(page) };

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
