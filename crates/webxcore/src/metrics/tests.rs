use super::*;

fn assert_has(text: &str, lines: &[&str]) {
    for line in lines {
        assert!(text.contains(&format!("{line}\n")), "no `{line}` in:\n{text}");
    }
}

#[test]
fn sites_keep_their_counts_when_resolved_again() {
    let metrics = Metrics::default();
    metrics.site("a.test").record(StatusCode::OK, 10, Duration::from_millis(3));
    // As after a reload, which builds a new router.
    metrics.site("a.test").record(StatusCode::OK, 5, Duration::from_millis(30));
    let text = metrics.encode();
    assert_has(
        &text,
        &[
            "webx4r_http_responses_total{site=\"a.test\",code=\"2xx\"} 2",
            "webx4r_http_response_body_bytes_total{site=\"a.test\"} 15",
            "webx4r_http_response_duration_seconds_bucket{le=\"0.005\",site=\"a.test\"} 1",
            "webx4r_http_response_duration_seconds_bucket{le=\"0.05\",site=\"a.test\"} 2",
            "webx4r_http_response_duration_seconds_count{site=\"a.test\"} 2",
        ],
    );
    assert!(text.ends_with("# EOF\n"), "{text}");
}

#[test]
fn connections_upstreams_certificates_and_reloads() {
    let metrics = Metrics::default();
    let https = metrics.listener("https");
    let open = https.accepted();
    drop(https.accepted());
    https.handshake_failed(true);
    let upstream = metrics.upstream("127.0.0.1:3000");
    upstream.failed(&ProxyError::Timeout);
    upstream.failed(&ProxyError::BadRequest);
    metrics.certificate_expires("a.test", UNIX_EPOCH + Duration::from_secs(1_800_000_000));
    metrics.certificate_expires("b.test", UNIX_EPOCH);
    metrics.certificate_removed("b.test");
    metrics.order_failed("a.test");
    for ok in [true, false, false] {
        metrics.reloaded(ok);
    }

    let text = metrics.encode();
    assert_has(
        &text,
        &[
            "webx4r_connections_total{listener=\"https\"} 2",
            "webx4r_connections_open{listener=\"https\"} 1",
            "webx4r_tls_handshake_failures_total{reason=\"timeout\"} 1",
            "webx4r_tls_handshake_failures_total{reason=\"error\"} 0",
            "webx4r_proxy_upstream_failures_total{upstream=\"127.0.0.1:3000\",kind=\"timeout\"} 1",
            "webx4r_proxy_upstream_failures_total{upstream=\"127.0.0.1:3000\",kind=\"connect\"} 0",
            "webx4r_acme_certificate_expiry_timestamp_seconds{name=\"a.test\"} 1800000000",
            "webx4r_acme_order_failures_total{name=\"a.test\"} 1",
            "webx4r_config_reloads_total{result=\"ok\"} 1",
            "webx4r_config_reloads_total{result=\"error\"} 2",
        ],
    );
    assert!(!text.contains("name=\"b.test\""), "removed certificates lose their series");
    drop(open);
    assert_has(&metrics.encode(), &["webx4r_connections_open{listener=\"https\"} 0"]);
}

#[test]
fn every_status_class_has_a_series() {
    let metrics = Metrics::default();
    let site = metrics.site("a.test");
    for status in [101, 302, 404, 404, 503] {
        site.record(StatusCode::from_u16(status).unwrap(), 0, Duration::ZERO);
    }
    let count = |code: &str, n: u32| {
        format!("webx4r_http_responses_total{{site=\"a.test\",code=\"{code}\"}} {n}")
    };
    let lines =
        [count("1xx", 1), count("2xx", 0), count("3xx", 1), count("4xx", 2), count("5xx", 1)];
    assert_has(&metrics.encode(), &lines.each_ref().map(String::as_str));
}
