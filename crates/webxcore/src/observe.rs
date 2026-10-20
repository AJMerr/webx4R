//! Records each response once its body is sent: the access log entry and the site's
//! metrics, with the bytes actually sent and the full duration.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use bytes::Bytes;
use http::{Response, StatusCode};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use webxlib::body::Body;

use crate::access_log::Entry;
use crate::metrics::SiteMetrics;

/// A response body that records its response when dropped: after the last byte, or when
/// the client goes away first.
pub struct Observed {
    body: Body,
    /// Body bytes sent so far.
    bytes: u64,
    record: Option<Record>,
}

struct Record {
    arrived: Instant,
    status: StatusCode,
    entry: Option<Entry>,
    metrics: Option<Arc<SiteMetrics>>,
}

impl Observed {
    /// Wraps `res`'s body to write `entry` and update `metrics`. With neither, it's a plain
    /// pass-through.
    pub(crate) fn wrap(
        res: Response<Body>,
        arrived: Instant,
        entry: Option<Entry>,
        metrics: Option<Arc<SiteMetrics>>,
    ) -> Response<Self> {
        let record = (entry.is_some() || metrics.is_some()).then(|| Record {
            arrived,
            status: res.status(),
            entry,
            metrics,
        });
        res.map(|body| Self { body, bytes: 0, record })
    }
}

impl HttpBody for Observed {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.body).poll_frame(cx));
        if let Some(Ok(frame)) = &frame
            && let Some(data) = frame.data_ref()
        {
            this.bytes += data.len() as u64;
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

impl Drop for Observed {
    fn drop(&mut self) {
        let Some(record) = self.record.take() else { return };
        let elapsed = record.arrived.elapsed();
        if let Some(entry) = &record.entry {
            entry.write(record.status, self.bytes, elapsed);
        }
        if let Some(metrics) = &record.metrics {
            metrics.record(record.status, self.bytes, elapsed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use http::Request;
    use http_body_util::BodyExt;
    use serde_json::{Value, json};

    use super::*;
    use crate::access_log::{AccessLog, Started};
    use crate::config::AccessFormat;
    use crate::metrics::Metrics;
    use crate::proxy::Answered;

    #[tokio::test]
    async fn bodies_record_once_when_dropped() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let log = Arc::new(AccessLog::new(AccessFormat::Json, move |line| {
            sink.lock().unwrap().push(serde_json::from_slice::<Value>(line).unwrap());
        }));
        let metrics = Metrics::default();
        let site = metrics.site("a.test");
        let observe = |res: Response<Body>| {
            let req = Request::get("/").body(()).unwrap();
            let entry =
                Entry::new(Arc::clone(&log), Started::new(&req, [127, 0, 0, 1].into()), &res);
            Observed::wrap(res, Instant::now(), Some(entry), Some(Arc::clone(&site)))
        };

        let mut res = Response::builder().status(404).body(Body::bytes("not found")).unwrap();
        res.extensions_mut().insert(Answered("127.0.0.1:3000".into()));
        let body = observe(res).into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "not found");
        drop(observe(Response::new(Body::bytes("never sent"))));

        let lines = lines.lock().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!((&lines[0]["status"], &lines[0]["bytes"]), (&json!(404), &json!(9)));
        assert_eq!(lines[0]["upstream"], "127.0.0.1:3000");
        assert_eq!((&lines[1]["status"], &lines[1]["bytes"]), (&json!(200), &json!(0)));
        let text = metrics.encode();
        for line in [
            "webx4r_http_responses_total{site=\"a.test\",code=\"4xx\"} 1\n",
            "webx4r_http_responses_total{site=\"a.test\",code=\"2xx\"} 1\n",
            "webx4r_http_response_body_bytes_total{site=\"a.test\"} 9\n",
            "webx4r_http_response_duration_seconds_count{site=\"a.test\"} 2\n",
        ] {
            assert!(text.contains(line), "{line}in:\n{text}");
        }
    }
}
