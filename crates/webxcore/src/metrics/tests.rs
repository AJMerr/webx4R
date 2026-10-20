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
