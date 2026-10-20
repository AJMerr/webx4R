//! Prometheus metrics. Handles used on every request or connection are resolved ahead of
//! time (each site's when the router is built, each listener's when it starts accepting), so
//! recording takes no locks or lookups.

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::StatusCode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};

use crate::proxy::ProxyError;

/// Response durations, from 1 ms to 10 s.
const DURATION_BUCKETS: [f64; 13] =
    [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

const STATUS_CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

/// The `site` label for responses that reach no site: unknown hosts, bad requests and ACME
/// challenges.
pub(crate) const NO_SITE: &str = "none";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SiteLabels {
    site: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResponseLabels {
    site: String,
    code: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ListenerLabels {
    listener: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReasonLabels {
    reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct UpstreamLabels {
    upstream: String,
    kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct NameLabels {
    name: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabels {
    result: String,
}

type HistogramFamily<L> = Family<L, Histogram, fn() -> Histogram>;

/// Every metric, named `webx4r_*`.
pub struct Metrics {
    registry: Registry,
    responses: Family<ResponseLabels, Counter>,
    duration: HistogramFamily<SiteLabels>,
    body_bytes: Family<SiteLabels, Counter>,
    connections: Family<ListenerLabels, Counter>,
    connections_open: Family<ListenerLabels, Gauge>,
    tls_failures: Family<ReasonLabels, Counter>,
    upstream_failures: Family<UpstreamLabels, Counter>,
    certificate_expiry: Family<NameLabels, Gauge>,
    order_failures: Family<NameLabels, Counter>,
    reloads: Family<ResultLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut metrics = Self {
            registry: Registry::with_prefix("webx4r"),
            responses: Family::default(),
            duration: Family::new_with_constructor(|| Histogram::new(DURATION_BUCKETS)),
            body_bytes: Family::default(),
            connections: Family::default(),
            connections_open: Family::default(),
            tls_failures: Family::default(),
            upstream_failures: Family::default(),
            certificate_expiry: Family::default(),
            order_failures: Family::default(),
            reloads: Family::default(),
        };
        let registry = &mut metrics.registry;
        registry.register(
            "http_responses",
            "Responses sent, by site and status class",
            metrics.responses.clone(),
        );
        registry.register_with_unit(
            "http_response_duration",
            "Time from a request's arrival to its response's last byte",
            Unit::Seconds,
            metrics.duration.clone(),
        );
        registry.register_with_unit(
            "http_response_body",
            "Response body bytes sent",
            Unit::Bytes,
            metrics.body_bytes.clone(),
        );
        registry.register(
            "connections",
            "Client connections accepted",
            metrics.connections.clone(),
        );
        registry.register(
            "connections_open",
            "Client connections open now, TLS handshakes included",
            metrics.connections_open.clone(),
        );
        registry.register(
            "tls_handshake_failures",
            "TLS handshakes that failed (`error`) or took too long (`timeout`)",
            metrics.tls_failures.clone(),
        );
        registry.register(
            "proxy_upstream_failures",
            "Failed exchanges with upstreams: `connect`, `timeout` waiting for response \
             headers, or `error` after the request was sent",
            metrics.upstream_failures.clone(),
        );
        registry.register_with_unit(
            "acme_certificate_expiry_timestamp",
            "When each ACME certificate expires, as a Unix time; `name` is its first name",
            Unit::Seconds,
            metrics.certificate_expiry.clone(),
        );
        registry.register(
            "acme_order_failures",
            "Failed ACME orders; `name` is the certificate's first name",
            metrics.order_failures.clone(),
        );
        registry.register(
            "config_reloads",
            "Config reloads, by result: `ok` or `error`",
            metrics.reloads.clone(),
        );
        metrics
    }
}

impl Metrics {
    /// Handles for `site`'s metrics. A site keeps its counts across reloads while its name
    /// stays the same.
    pub(crate) fn site(&self, site: &str) -> Arc<SiteMetrics> {
        let labels = SiteLabels { site: site.to_owned() };
        let responses = STATUS_CLASSES.map(|code| {
            let labels = ResponseLabels { site: site.to_owned(), code: code.to_owned() };
            self.responses.get_or_create(&labels).clone()
        });
        Arc::new(SiteMetrics {
            responses,
            duration: self.duration.get_or_create(&labels).clone(),
            body_bytes: self.body_bytes.get_or_create(&labels).clone(),
        })
    }

    /// Handles for the `http` or `https` listener's connections.
    pub(crate) fn listener(&self, listener: &str) -> ListenerMetrics {
        let labels = ListenerLabels { listener: listener.to_owned() };
        let reason = |reason: &str| {
            self.tls_failures.get_or_create(&ReasonLabels { reason: reason.to_owned() }).clone()
        };
        ListenerMetrics {
            accepted: self.connections.get_or_create(&labels).clone(),
            open: self.connections_open.get_or_create(&labels).clone(),
            tls_error: reason("error"),
            tls_timeout: reason("timeout"),
        }
    }

    /// Handles for an upstream's failures, by `host:port`.
    pub(crate) fn upstream(&self, upstream: &str) -> UpstreamMetrics {
        let kind = |kind: &str| {
            let labels = UpstreamLabels { upstream: upstream.to_owned(), kind: kind.to_owned() };
            self.upstream_failures.get_or_create(&labels).clone()
        };
        UpstreamMetrics { connect: kind("connect"), timeout: kind("timeout"), error: kind("error") }
    }

    pub(crate) fn certificate_expires(&self, name: &str, expires_at: SystemTime) {
        let secs = expires_at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let labels = NameLabels { name: name.to_owned() };
        self.certificate_expiry.get_or_create(&labels).set(secs.try_into().unwrap_or(i64::MAX));
    }

    /// Drops the expiry series of a certificate no longer in use.
    pub(crate) fn certificate_removed(&self, name: &str) {
        self.certificate_expiry.remove(&NameLabels { name: name.to_owned() });
    }

    pub(crate) fn order_failed(&self, name: &str) {
        self.order_failures.get_or_create(&NameLabels { name: name.to_owned() }).inc();
    }

    pub(crate) fn reloaded(&self, ok: bool) {
        let result = if ok { "ok" } else { "error" }.to_owned();
        self.reloads.get_or_create(&ResultLabels { result }).inc();
    }

    /// The OpenMetrics text exposition of every metric.
    pub fn encode(&self) -> String {
        let mut text = String::new();
        encode(&mut text, &self.registry).expect("writing to a String can't fail");
        text
    }
}

/// One site's response metrics.
pub(crate) struct SiteMetrics {
    /// By status class, 1xx to 5xx.
    responses: [Counter; 5],
    duration: Histogram,
    body_bytes: Counter,
}

impl SiteMetrics {
    pub(crate) fn record(&self, status: StatusCode, body_bytes: u64, elapsed: Duration) {
        let class = usize::from(status.as_u16() / 100).clamp(1, 5) - 1;
        self.responses[class].inc();
        self.duration.observe(elapsed.as_secs_f64());
        self.body_bytes.inc_by(body_bytes);
    }
}

/// One listener's connection metrics.
pub(crate) struct ListenerMetrics {
    accepted: Counter,
    open: Gauge,
    tls_error: Counter,
    tls_timeout: Counter,
}

impl ListenerMetrics {
    /// Counts a new connection, which stays open until the guard is dropped.
    pub(crate) fn accepted(&self) -> OpenConnection {
        self.accepted.inc();
        self.open.inc();
        OpenConnection(self.open.clone())
    }

    pub(crate) fn handshake_failed(&self, timed_out: bool) {
        if timed_out { &self.tls_timeout } else { &self.tls_error }.inc();
    }
}

/// An open connection, counted in `webx4r_connections_open` until dropped.
pub(crate) struct OpenConnection(Gauge);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// One upstream's failure counters.
pub(crate) struct UpstreamMetrics {
    connect: Counter,
    timeout: Counter,
    error: Counter,
}

impl UpstreamMetrics {
    pub(crate) fn failed(&self, error: &ProxyError) {
        match error {
            ProxyError::Connect(_) => self.connect.inc(),
            ProxyError::Timeout => self.timeout.inc(),
            ProxyError::Upstream(_) | ProxyError::UnexpectedUpgrade => self.error.inc(),
            // The request was never sent: not the upstream's failure.
            ProxyError::BadRequest => return,
        };
    }
}
