//! Prometheus metrics. Each site's handles are resolved once, when the router is built, so
//! recording a response takes no locks or lookups.

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};

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

type HistogramFamily<L> = Family<L, Histogram, fn() -> Histogram>;

/// Every metric, named `webx4r_*`.
pub struct Metrics {
    registry: Registry,
    responses: Family<ResponseLabels, Counter>,
    duration: HistogramFamily<SiteLabels>,
    body_bytes: Family<SiteLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("webx4r");
        let responses = Family::default();
        let help = "Responses sent, by site and status class";
        registry.register("http_responses", help, responses.clone());
        let duration: HistogramFamily<_> =
            Family::new_with_constructor(|| Histogram::new(DURATION_BUCKETS));
        let help = "Time from a request's arrival to its response's last byte";
        registry.register_with_unit(
            "http_response_duration",
            help,
            Unit::Seconds,
            duration.clone(),
        );
        let body_bytes = Family::default();
        let help = "Response body bytes sent";
        registry.register_with_unit("http_response_body", help, Unit::Bytes, body_bytes.clone());
        Self { registry, responses, duration, body_bytes }
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
