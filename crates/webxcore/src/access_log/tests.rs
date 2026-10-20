use std::sync::Mutex;

use http_body_util::BodyExt;
use serde_json::{Value, json};

use super::*;

fn at(secs: u64, millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(secs * 1_000 + millis)
}

#[test]
fn utc_dates_and_times() {
    assert_eq!(Utc::from(UNIX_EPOCH).rfc3339(), "1970-01-01T00:00:00.000Z");
    assert_eq!(Utc::from(at(951_782_400, 0)).rfc3339(), "2000-02-29T00:00:00.000Z");
    assert_eq!(Utc::from(at(1_735_689_599, 999)).rfc3339(), "2024-12-31T23:59:59.999Z");
    assert_eq!(Utc::from(at(1_700_000_000, 474)).rfc3339(), "2023-11-14T22:13:20.474Z");
    assert_eq!(Utc::from(at(1_700_000_000, 474)).clf(), "14/Nov/2023:22:13:20 +0000");
}

/// An entry for `GET /x?y=1` from an IPv4-mapped address, answered by an upstream.
fn entry(format: AccessFormat) -> Entry {
    let req = Request::get("/x?y=1")
        .header(HOST, "a.test:8080")
        .header(REFERER, "https://ref.test/")
        .header(USER_AGENT, "curl/8 \"quoted\"")
        .body(())
        .unwrap();
    Entry {
        log: Arc::new(AccessLog::new(format, |_| {})),
        started: Started::new(&req, "::ffff:192.0.2.1".parse().unwrap()),
        status: StatusCode::OK,
        upstream: Some("127.0.0.1:3000".into()),
        bytes: 1234,
    }
}

fn line(entry: &Entry) -> String {
    String::from_utf8(entry.line(at(1_700_000_000, 474), Duration::from_micros(1_500))).unwrap()
}

#[test]
fn json_entries() {
    let line = line(&entry(AccessFormat::Json));
    assert!(line.ends_with('\n') && line.lines().count() == 1, "{line}");
    let value: Value = serde_json::from_str(&line).unwrap();
    let expected = json!({
        "time": "2023-11-14T22:13:20.474Z",
        "client": "192.0.2.1",
        "host": "a.test:8080",
        "method": "GET",
        "uri": "/x?y=1",
        "protocol": "HTTP/1.1",
        "status": 200,
        "bytes": 1234,
        "duration": 0.0015,
        "referer": "https://ref.test/",
        "user_agent": "curl/8 \"quoted\"",
        "upstream": "127.0.0.1:3000",
    });
    assert_eq!(value, expected);
}

#[test]
fn combined_entries() {
    let expected = "192.0.2.1 - - [14/Nov/2023:22:13:20 +0000] \"GET /x?y=1 HTTP/1.1\" 200 1234 \
                    \"https://ref.test/\" \"curl/8 \\\"quoted\\\"\"\n";
    assert_eq!(line(&entry(AccessFormat::Combined)), expected);

    let mut bare = entry(AccessFormat::Combined);
    (bare.started.referer, bare.started.user_agent) = (None, None);
    assert!(line(&bare).ends_with(" 200 1234 \"-\" \"-\"\n"), "missing headers are `-`");
}

#[test]
fn escapes_like_nginx() {
    assert!(matches!(escape("plain text"), Cow::Borrowed("plain text")));
    assert_eq!(escape("a\"b\\c\x01é"), "a\\\"b\\\\c\\x01\\xC3\\xA9");
}

#[tokio::test]
async fn bodies_write_one_entry_when_dropped() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let log = Arc::new(AccessLog::new(AccessFormat::Json, move |line| {
        sink.lock().unwrap().push(serde_json::from_slice::<Value>(line).unwrap());
    }));
    let started = || Started::new(&Request::get("/").body(()).unwrap(), [127, 0, 0, 1].into());

    let mut res = Response::builder().status(404).body(Body::bytes("not found")).unwrap();
    res.extensions_mut().insert(Answered("127.0.0.1:3000".into()));
    let res = Logged::wrap(Arc::clone(&log), started(), res);
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), "not found");
    let unread = Logged::wrap(log, started(), Response::new(Body::bytes("never sent")));
    drop(unread);

    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!((&lines[0]["status"], &lines[0]["bytes"]), (&json!(404), &json!(9)));
    assert_eq!(lines[0]["upstream"], "127.0.0.1:3000");
    assert_eq!((&lines[1]["status"], &lines[1]["bytes"]), (&json!(200), &json!(0)));
    assert_eq!(lines[1]["upstream"], Value::Null);
}
