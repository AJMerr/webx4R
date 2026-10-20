//! The access log: one line per response, written once its body is sent, so the entry has
//! the bytes actually sent and the full duration, like nginx's.

#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{HOST, REFERER, USER_AGENT};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use serde::Serialize;
use webxlib::body::Body;

use crate::config::AccessFormat;
use crate::proxy::Answered;

/// Takes each finished line.
type Write = Box<dyn Fn(&[u8]) + Send + Sync>;

/// Turns finished requests into lines in the configured format.
pub struct AccessLog {
    format: AccessFormat,
    write: Write,
}

impl AccessLog {
    /// `write` gets each entry as one line, newline included.
    pub fn new(format: AccessFormat, write: impl Fn(&[u8]) + Send + Sync + 'static) -> Self {
        Self { format, write: Box::new(write) }
    }
}

/// What's known about a request when it arrives.
pub(crate) struct Started {
    at: Instant,
    client: IpAddr,
    method: Method,
    /// Path and query, as requested.
    uri: String,
    version: Version,
    /// As sent, port included; from the URI for HTTP/2.
    host: Option<String>,
    referer: Option<HeaderValue>,
    user_agent: Option<HeaderValue>,
}

impl Started {
    pub(crate) fn new<B>(req: &Request<B>, client: IpAddr) -> Self {
        let uri = req.uri();
        let headers = req.headers();
        let host = match uri.authority() {
            Some(authority) => Some(authority.as_str().to_owned()),
            None => headers.get(HOST).map(|host| String::from_utf8_lossy(host.as_bytes()).into()),
        };
        Self {
            at: Instant::now(),
            client: client.to_canonical(),
            method: req.method().clone(),
            uri: uri.path_and_query().map_or_else(|| uri.to_string(), |pq| pq.as_str().to_owned()),
            version: req.version(),
            host,
            referer: headers.get(REFERER).cloned(),
            user_agent: headers.get(USER_AGENT).cloned(),
        }
    }
}

/// A response body that writes its access log entry when dropped: after the last byte, or
/// when the client goes away first.
pub struct Logged {
    body: Body,
    entry: Option<Entry>,
}

impl Logged {
    /// A body with no entry to write, for servers without an access log.
    pub(crate) fn unlogged(body: Body) -> Self {
        Self { body, entry: None }
    }

    /// Wraps `res`'s body so `log` gets its entry.
    pub(crate) fn wrap(
        log: Arc<AccessLog>,
        started: Started,
        res: Response<Body>,
    ) -> Response<Self> {
        let upstream = res.extensions().get::<Answered>().map(|answered| Arc::clone(&answered.0));
        let status = res.status();
        res.map(|body| {
            let entry = Entry { log, started, status, upstream, bytes: 0 };
            Self { body, entry: Some(entry) }
        })
    }
}

impl HttpBody for Logged {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.body).poll_frame(cx));
        if let (Some(Ok(frame)), Some(entry)) = (&frame, &mut this.entry)
            && let Some(data) = frame.data_ref()
        {
            entry.bytes += data.len() as u64;
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for Logged {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            let line = entry.line(SystemTime::now(), entry.started.at.elapsed());
            (entry.log.write)(&line);
        }
    }
}

struct Entry {
    log: Arc<AccessLog>,
    started: Started,
    status: StatusCode,
    /// The proxy upstream that answered, if any.
    upstream: Option<Arc<str>>,
    /// Body bytes sent so far.
    bytes: u64,
}

#[derive(Serialize)]
struct JsonEntry<'a> {
    time: String,
    client: IpAddr,
    host: Option<&'a str>,
    method: &'a str,
    uri: &'a str,
    protocol: &'a str,
    status: u16,
    bytes: u64,
    /// Seconds.
    duration: f64,
    referer: Option<Cow<'a, str>>,
    user_agent: Option<Cow<'a, str>>,
    upstream: Option<&'a str>,
}

impl Entry {
    fn line(&self, now: SystemTime, elapsed: Duration) -> Vec<u8> {
        let started = &self.started;
        let (referer, user_agent) = (text(&started.referer), text(&started.user_agent));
        let time = Utc::from(now);
        match self.log.format {
            AccessFormat::Json => {
                let entry = JsonEntry {
                    time: time.rfc3339(),
                    client: started.client,
                    host: started.host.as_deref(),
                    method: started.method.as_str(),
                    uri: &started.uri,
                    protocol: protocol(started.version),
                    status: self.status.as_u16(),
                    bytes: self.bytes,
                    duration: elapsed.as_secs_f64(),
                    referer,
                    user_agent,
                    upstream: self.upstream.as_deref(),
                };
                let mut line = serde_json::to_vec(&entry).expect("plain fields serialize");
                line.push(b'\n');
                line
            }
            AccessFormat::Combined => {
                let request =
                    format!("{} {} {}", started.method, started.uri, protocol(started.version));
                let line = format!(
                    "{} - - [{}] \"{}\" {} {} \"{}\" \"{}\"\n",
                    started.client,
                    time.clf(),
                    escape(&request),
                    self.status.as_u16(),
                    self.bytes,
                    escape(referer.as_deref().unwrap_or("-")),
                    escape(user_agent.as_deref().unwrap_or("-")),
                );
                line.into_bytes()
            }
        }
    }
}

/// A header's value as text; invalid UTF-8 becomes U+FFFD.
fn text(value: &Option<HeaderValue>) -> Option<Cow<'_, str>> {
    value.as_ref().map(|value| String::from_utf8_lossy(value.as_bytes()))
}

fn protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "-",
    }
}

/// nginx's escaping for quoted fields: `"` and `\` get a backslash, and bytes outside
/// printable ASCII become `\xHH`.
fn escape(value: &str) -> Cow<'_, str> {
    let plain = |b: u8| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\';
    if value.bytes().all(plain) {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len() + 8);
    for b in value.bytes() {
        match b {
            b'"' | b'\\' => {
                escaped.push('\\');
                escaped.push(b as char);
            }
            b if plain(b) => escaped.push(b as char),
            b => {
                let _ = write!(escaped, "\\x{b:02X}");
            }
        }
    }
    Cow::Owned(escaped)
}

/// A time's UTC calendar fields.
#[derive(Debug, PartialEq, Eq)]
struct Utc {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
}

const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

impl From<SystemTime> for Utc {
    /// Uses Howard Hinnant's `civil_from_days`.
    fn from(time: SystemTime) -> Self {
        let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = since.as_secs();
        let (days, rest) = ((secs / 86_400) as i64, (secs % 86_400) as u32);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month,
            day,
            hour: rest / 3_600,
            minute: rest % 3_600 / 60,
            second: rest % 60,
            millis: since.subsec_millis(),
        }
    }
}

impl Utc {
    /// `2026-10-20T05:25:12.474Z`
    fn rfc3339(&self) -> String {
        let Self { year, month, day, hour, minute, second, millis } = self;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    }

    /// The Common Log Format's `20/Oct/2026:05:25:12 +0000`.
    fn clf(&self) -> String {
        let Self { year, month, day, hour, minute, second, .. } = self;
        let month = MONTHS[*month as usize - 1];
        format!("{day:02}/{month}/{year:04}:{hour:02}:{minute:02}:{second:02} +0000")
    }
}
