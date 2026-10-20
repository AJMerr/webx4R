//! Reverse proxy: forwards requests to upstream apps over pooled HTTP/1.1 connections.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONNECTION, HOST, TE, TRANSFER_ENCODING, UPGRADE};
use http::request::Parts;
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use webxlib::body::Body;

use crate::config;

/// How long an upstream gets to accept a TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an upstream gets to send its response headers; bodies may stream for longer.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long an upstream is skipped after it fails to connect or respond in time.
const FAIL_TIMEOUT: Duration = Duration::from_secs(10);

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The client end of a proxied request.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub addr: SocketAddr,
    /// Whether the client connected over TLS.
    pub https: bool,
}

#[derive(Debug)]
pub enum ProxyError {
    /// The upstream refused the connection or didn't accept in time; nothing was sent.
    Connect(legacy::Error),
    /// The upstream didn't send response headers in time.
    Timeout,
    /// The exchange failed after the request was sent.
    Upstream(legacy::Error),
    /// The request can't be addressed to an upstream, e.g. `OPTIONS *`.
    BadRequest,
    /// The upstream switched protocols on a request that didn't ask to.
    UnexpectedUpgrade,
}

impl ProxyError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Connect(_) | Self::Upstream(_) | Self::UnexpectedUpgrade => {
                StatusCode::BAD_GATEWAY
            }
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::BadRequest => StatusCode::BAD_REQUEST,
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // legacy::Error's own message is vague; its chain of sources says what went wrong.
        let detail = |e: &legacy::Error| {
            let mut messages = Vec::new();
            let mut next = std::error::Error::source(e);
            while let Some(source) = next {
                messages.push(source.to_string());
                next = source.source();
            }
            if messages.is_empty() { e.to_string() } else { messages.join(": ") }
        };
        match self {
            Self::Connect(e) => write!(f, "can't connect: {}", detail(e)),
            Self::Timeout => write!(f, "no response within {RESPONSE_TIMEOUT:?}"),
            Self::Upstream(e) => write!(f, "upstream failed: {}", detail(e)),
            Self::BadRequest => f.write_str("request has no path to forward"),
            Self::UnexpectedUpgrade => f.write_str("upstream switched protocols unasked"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// An HTTP/1.1 client with one connection pool for every upstream.
#[derive(Clone)]
pub struct Client {
    inner: legacy::Client<HttpConnector, UnsyncBoxBody<Bytes, BoxError>>,
    response_timeout: Duration,
}

impl Default for Client {
    fn default() -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
        connector.set_nodelay(true);
        let inner = legacy::Client::builder(TokioExecutor::new())
            // Lets the pool close idle connections; without a timer they're kept forever.
            .pool_timer(TokioTimer::new())
            .build(connector);
        Self { inner, response_timeout: RESPONSE_TIMEOUT }
    }
}

impl Client {
    /// Sends `req` to `upstream` (`host:port`) with its path and query unchanged.
    pub async fn forward<B>(
        &self,
        req: Request<B>,
        upstream: &str,
        peer: Peer,
    ) -> Result<Response<Body>, ProxyError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (head, body) = prepare(req, peer)?;
        self.send(&head, body, upstream).await
    }

    /// Sends a request made by [`prepare`] to `upstream`.
    async fn send<B>(
        &self,
        head: &Parts,
        body: B,
        upstream: &str,
    ) -> Result<Response<Body>, ProxyError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let path = head.uri.path_and_query().map_or("/", PathAndQuery::as_str);
        let mut req = Request::new(body.map_err(Into::into).boxed_unsync());
        *req.method_mut() = head.method.clone();
        *req.uri_mut() = Uri::try_from(format!("http://{upstream}{path}"))
            .map_err(|_| ProxyError::BadRequest)?;
        *req.version_mut() = Version::HTTP_11;
        *req.headers_mut() = head.headers.clone();

        let res = match tokio::time::timeout(self.response_timeout, self.inner.request(req)).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) if e.is_connect() => return Err(ProxyError::Connect(e)),
            Ok(Err(e)) => return Err(ProxyError::Upstream(e)),
            Err(_) => return Err(ProxyError::Timeout),
        };
        if res.status() == StatusCode::SWITCHING_PROTOCOLS {
            return switch_protocols(res, head.extensions.get::<OnUpgrade>().cloned(), upstream);
        }

        let (mut parts, body) = res.into_parts();
        remove_hop_by_hop(&mut parts.headers);
        // The upstream's HTTP version describes its connection, not the client's.
        parts.version = Version::default();
        Ok(Response::from_parts(parts, Body::boxed(body)))
    }
}

/// Checks that `req` has a path to forward and rewrites its headers for an upstream.
/// The URI is addressed to each upstream in [`Client::send`].
fn prepare<B>(req: Request<B>, peer: Peer) -> Result<(Parts, B), ProxyError> {
    let (mut parts, body) = req.into_parts();
    if !parts.uri.path_and_query().is_some_and(|p| p.as_str().starts_with('/')) {
        return Err(ProxyError::BadRequest);
    }
    // HTTP/2 clients send the host in the URI, HTTP/1.1 clients in `Host`.
    let host = match parts.uri.authority() {
        Some(authority) => HeaderValue::from_str(authority.as_str()).ok(),
        None => parts.headers.get(HOST).cloned(),
    };
    let upgrade = upgrade_protocol(&parts);

    let headers = &mut parts.headers;
    remove_hop_by_hop(headers);
    if let Some(protocol) = upgrade {
        set_upgrade(headers, protocol);
    }
    if let Some(host) = host {
        headers.insert(HOST, host.clone());
        headers.insert(X_FORWARDED_HOST, host);
    }
    append_forwarded_for(headers, peer.addr.ip().to_canonical());
    let proto = HeaderValue::from_static(if peer.https { "https" } else { "http" });
    headers.insert(X_FORWARDED_PROTO, proto);
    Ok((parts, body))
}

/// The `Upgrade` value of an HTTP/1.1 request that asks to switch protocols, e.g. `websocket`.
fn upgrade_protocol(parts: &Parts) -> Option<HeaderValue> {
    let asks = parts.version == Version::HTTP_11
        && connection_tokens(&parts.headers).any(|token| token.eq_ignore_ascii_case("upgrade"));
    asks.then(|| parts.headers.get(UPGRADE).cloned()).flatten()
}

fn set_upgrade(headers: &mut HeaderMap, protocol: HeaderValue) {
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, protocol);
}

/// Passes the upstream's `101` on to the client, then relays bytes between the two upgraded
/// connections until either side closes.
fn switch_protocols(
    mut res: Response<Incoming>,
    client: Option<OnUpgrade>,
    upstream: &str,
) -> Result<Response<Body>, ProxyError> {
    let Some(client) = client else { return Err(ProxyError::UnexpectedUpgrade) };
    let upstream_side = hyper::upgrade::on(&mut res);
    let upstream = upstream.to_owned();
    tokio::spawn(async move {
        let relay = async {
            let (client, upstream) = tokio::try_join!(client, upstream_side)?;
            let (mut client, mut upstream) = (TokioIo::new(client), TokioIo::new(upstream));
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok::<_, BoxError>(())
        };
        if let Err(e) = relay.await {
            tracing::debug!(%upstream, error = %e, "upgraded connection ended with an error");
        }
    });

    let (mut parts, _) = res.into_parts();
    let protocol = parts.headers.get(UPGRADE).cloned();
    remove_hop_by_hop(&mut parts.headers);
    if let Some(protocol) = protocol {
        set_upgrade(&mut parts.headers, protocol);
    }
    parts.version = Version::default();
    Ok(Response::from_parts(parts, Body::empty()))
}

/// A site's `[[site.proxy]]`: requests at or below `prefix` go to its upstreams in turn.
pub struct Route {
    prefix: String,
    upstreams: Vec<Upstream>,
    strip_prefix: bool,
    /// Round-robin counter.
    next: AtomicUsize,
    /// Zero point for [`Upstream::down_until`].
    epoch: Instant,
}

struct Upstream {
    addr: String,
    /// Milliseconds after the route's epoch until which this upstream is skipped; 0 when up.
    down_until: AtomicU64,
}

impl Upstream {
    fn is_up(&self, now: u64) -> bool {
        self.down_until.load(Ordering::Relaxed) <= now
    }

    fn mark_down(&self, now: u64) {
        self.down_until.store(now + FAIL_TIMEOUT.as_millis() as u64, Ordering::Relaxed);
    }

    fn mark_up(&self) {
        // Load first, so healthy upstreams don't take a write on every request.
        if self.down_until.load(Ordering::Relaxed) != 0 {
            self.down_until.store(0, Ordering::Relaxed);
        }
    }
}

impl Route {
    pub fn new(config: &config::Proxy) -> Self {
        let upstreams = config
            .upstreams
            .iter()
            .map(|addr| Upstream { addr: addr.clone(), down_until: AtomicU64::new(0) });
        Self {
            prefix: config.path.clone(),
            upstreams: upstreams.collect(),
            strip_prefix: config.strip_prefix,
            next: AtomicUsize::new(0),
            epoch: Instant::now(),
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Matches whole segments: `/api` matches `/api` and `/api/x`, not `/apix`.
    pub fn matches(&self, path: &str) -> bool {
        path.strip_prefix(self.prefix.as_str())
            .is_some_and(|rest| self.prefix == "/" || rest.is_empty() || rest.starts_with('/'))
    }

    /// Forwards `req` to the next healthy upstream, without the prefix if `strip_prefix` is set.
    /// If connecting fails, the request was never sent, so the next upstream gets it.
    pub async fn forward<B>(
        &self,
        client: &Client,
        mut req: Request<B>,
        peer: Peer,
    ) -> Result<Response<Body>, ProxyError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        if self.strip_prefix && self.prefix != "/" {
            *req.uri_mut() = strip_prefix(req.uri(), &self.prefix)?;
        }
        let (head, body) = prepare(req, peer)?;
        let slot = Arc::new(Mutex::new(Some(body)));

        let mut last_error = None;
        for upstream in self.candidates() {
            let body = Reclaimable { slot: Arc::clone(&slot), body: None };
            let error = match client.send(&head, body, &upstream.addr).await {
                Ok(res) => {
                    upstream.mark_up();
                    return Ok(res);
                }
                Err(e) => e,
            };
            tracing::warn!(upstream = %upstream.addr, client = %peer.addr, %error, "proxy request failed");
            if matches!(error, ProxyError::Connect(_) | ProxyError::Timeout) {
                upstream.mark_down(self.now());
            }
            let retry = matches!(error, ProxyError::Connect(_)) && lock(&slot).is_some();
            if !retry {
                return Err(error);
            }
            last_error = Some(error);
        }
        Err(last_error.expect("config validation requires at least one upstream"))
    }

    /// Every upstream, starting at the next in rotation: those that are up, then those marked
    /// down as a last resort.
    fn candidates(&self) -> Vec<&Upstream> {
        let n = self.upstreams.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut order: Vec<_> = (0..n).map(|i| &self.upstreams[(start + i) % n]).collect();
        let now = self.now();
        // A stable sort keeps the rotation order within each group.
        order.sort_by_key(|upstream| !upstream.is_up(now));
        order
    }

    fn now(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
}

/// A request body that stays in `slot` until an upstream first reads it, so a request whose
/// connection failed can be sent again.
struct Reclaimable<B> {
    slot: Arc<Mutex<Option<B>>>,
    /// Moved out of `slot` on the first read.
    body: Option<B>,
}

impl<B: hyper::body::Body + Unpin> hyper::body::Body for Reclaimable<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let this = self.get_mut();
        if this.body.is_none() {
            this.body = lock(&this.slot).take();
        }
        match &mut this.body {
            Some(body) => Pin::new(body).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.body {
            Some(body) => body.is_end_stream(),
            None => lock(&self.slot).as_ref().is_none_or(|body| body.is_end_stream()),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.body {
            Some(body) => body.size_hint(),
            None => lock(&self.slot).as_ref().map_or(SizeHint::with_exact(0), |b| b.size_hint()),
        }
    }
}

/// Locks `mutex`, ignoring poisoning: the data is an `Option` that a panic can't leave half-set.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `/api/x?q` without `/api` is `/x?q`; the prefix alone becomes `/`.
fn strip_prefix(uri: &Uri, prefix: &str) -> Result<Uri, ProxyError> {
    let rest = uri.path().strip_prefix(prefix).unwrap_or(uri.path());
    let rest = if rest.is_empty() { "/" } else { rest };
    let path = match uri.query() {
        Some(query) => format!("{rest}?{query}"),
        None => rest.to_owned(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::try_from(path).map_err(|_| ProxyError::BadRequest)?);
    Uri::from_parts(parts).map_err(|_| ProxyError::BadRequest)
}

/// Removes headers that apply to a single connection (RFC 9110 §7.6.1),
/// including any that `Connection` names.
fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = connection_tokens(headers)
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    let fixed = [CONNECTION, TE, TRANSFER_ENCODING, UPGRADE];
    let legacy = ["keep-alive", "proxy-connection"].map(HeaderName::from_static);
    for name in fixed.into_iter().chain(legacy) {
        headers.remove(name);
    }
}

/// The comma-separated names in every `Connection` header.
fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
}

/// Adds the client's address to the end of `X-Forwarded-For`.
fn append_forwarded_for(headers: &mut HeaderMap, ip: IpAddr) {
    let mut value = String::new();
    for prior in headers.get_all(&X_FORWARDED_FOR).iter().filter_map(|v| v.to_str().ok()) {
        value.push_str(prior);
        value.push_str(", ");
    }
    value.push_str(&ip.to_string());
    if let Ok(value) = HeaderValue::try_from(value) {
        headers.insert(X_FORWARDED_FOR, value);
    }
}

#[cfg(test)]
pub(crate) mod tests;
