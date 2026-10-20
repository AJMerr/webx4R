//! Reverse proxy: forwards requests to upstream apps over pooled HTTP/1.1 connections.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HOST, TE, TRANSFER_ENCODING, UPGRADE};
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use webxlib::body::Body;

use crate::config;

/// How long an upstream gets to accept a TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an upstream gets to send its response headers; bodies may stream for longer.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

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
}

impl ProxyError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Connect(_) | Self::Upstream(_) => StatusCode::BAD_GATEWAY,
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
        let (mut parts, body) = req.into_parts();
        let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or_default();
        if !path.starts_with('/') {
            return Err(ProxyError::BadRequest);
        }
        // HTTP/2 clients send the host in the URI, HTTP/1.1 clients in `Host`.
        let host = match parts.uri.authority() {
            Some(authority) => HeaderValue::from_str(authority.as_str()).ok(),
            None => parts.headers.get(HOST).cloned(),
        };
        parts.uri = Uri::try_from(format!("http://{upstream}{path}"))
            .map_err(|_| ProxyError::BadRequest)?;
        parts.version = Version::HTTP_11;

        let headers = &mut parts.headers;
        remove_hop_by_hop(headers);
        if let Some(host) = host {
            headers.insert(HOST, host.clone());
            headers.insert(X_FORWARDED_HOST, host);
        }
        append_forwarded_for(headers, peer.addr.ip().to_canonical());
        let proto = HeaderValue::from_static(if peer.https { "https" } else { "http" });
        headers.insert(X_FORWARDED_PROTO, proto);

        let req = Request::from_parts(parts, body.map_err(Into::into).boxed_unsync());
        let res = match tokio::time::timeout(self.response_timeout, self.inner.request(req)).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) if e.is_connect() => return Err(ProxyError::Connect(e)),
            Ok(Err(e)) => return Err(ProxyError::Upstream(e)),
            Err(_) => return Err(ProxyError::Timeout),
        };

        let (mut parts, body) = res.into_parts();
        remove_hop_by_hop(&mut parts.headers);
        // The upstream's HTTP version describes its connection, not the client's.
        parts.version = Version::default();
        Ok(Response::from_parts(parts, Body::boxed(body)))
    }
}

/// A site's `[[site.proxy]]`: requests at or below `prefix` go to its upstreams.
pub struct Route {
    prefix: String,
    upstreams: Vec<String>,
    strip_prefix: bool,
}

impl Route {
    pub fn new(config: &config::Proxy) -> Self {
        Self {
            prefix: config.path.clone(),
            upstreams: config.upstreams.clone(),
            strip_prefix: config.strip_prefix,
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

    /// Forwards `req` to an upstream, without the prefix if `strip_prefix` is set.
    pub async fn forward<B>(
        &self,
        client: &Client,
        mut req: Request<B>,
        peer: Peer,
    ) -> Result<Response<Body>, ProxyError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        if self.strip_prefix && self.prefix != "/" {
            *req.uri_mut() = strip_prefix(req.uri(), &self.prefix)?;
        }
        let upstream = &self.upstreams[0];
        let result = client.forward(req, upstream, peer).await;
        if let Err(e) = &result {
            tracing::warn!(%upstream, client = %peer.addr, error = %e, "proxy request failed");
        }
        result
    }
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
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
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
