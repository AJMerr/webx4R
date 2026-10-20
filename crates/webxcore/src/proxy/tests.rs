use std::convert::Infallible;
use std::net::Ipv4Addr;

use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::*;

/// The client's address in every test request.
const PEER: Peer =
    Peer { addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 5555), https: true };

/// Starts an upstream that answers each request with its method, URI, headers and body,
/// and names itself in `x-upstream`.
pub(crate) async fn echo_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let name = addr.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let name = name.clone();
            let service = service_fn(move |req| echo(req, name.clone()));
            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service);
            tokio::spawn(conn);
        }
    });
    addr
}

async fn echo(req: Request<Incoming>, name: String) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut text = format!("{} {}\n", req.method(), req.uri());
    for (name, value) in req.headers() {
        text.push_str(&format!("{name}: {}\n", value.to_str().unwrap()));
    }
    text.push_str(&String::from_utf8_lossy(&req.into_body().collect().await?.to_bytes()));
    let res = Response::builder()
        .header("keep-alive", "timeout=5")
        .header("x-app", "echo")
        .header("x-upstream", name);
    Ok(res.body(Full::new(Bytes::from(text))).unwrap())
}

/// Starts an upstream that accepts any `Upgrade` with a 101, then echoes bytes back.
pub(crate) async fn upgrade_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(switch))
                .with_upgrades();
            tokio::spawn(conn);
        }
    });
    addr
}

async fn switch(mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let protocol = req.headers()[UPGRADE].clone();
    let upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(TokioIo::new(upgrade.await.unwrap()));
        tokio::io::copy(&mut reader, &mut writer).await
    });
    let res = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "upgrade")
        .header(UPGRADE, protocol);
    Ok(res.body(Full::default()).unwrap())
}

/// An address with nothing listening on it.
async fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

/// An upstream that accepts connections and never answers.
async fn silent_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap());
        }
    });
    addr
}

/// Forwards `req` through a fresh client and returns the response with its body as text.
async fn forward(req: Request<Full<Bytes>>, upstream: &str) -> Response<String> {
    let res = Client::default().forward(req, upstream, PEER).await.unwrap();
    let (parts, body) = res.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    Response::from_parts(parts, String::from_utf8(body.to_vec()).unwrap())
}

fn get(uri: &str) -> http::request::Builder {
    Request::get(uri).header(HOST, "example.com:8080")
}

#[tokio::test]
async fn forwards_method_path_query_and_body() {
    let upstream = echo_upstream().await;
    let req = Request::post("/api/items?page=2").header(HOST, "example.com");
    let res = forward(req.body(Full::from("payload")).unwrap(), &upstream).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.body().starts_with("POST /api/items?page=2\n"), "{}", res.body());
    assert!(res.body().ends_with("\npayload"), "{}", res.body());
}

#[tokio::test]
async fn sets_forwarding_headers() {
    let upstream = echo_upstream().await;
    let req = get("/").header("x-forwarded-for", "10.0.0.1").header("x-forwarded-proto", "http");
    let res = forward(req.body(Full::default()).unwrap(), &upstream).await;
    let body = res.body();
    assert!(body.contains("\nhost: example.com:8080\n"), "keeps the client's Host: {body}");
    assert!(body.contains("\nx-forwarded-host: example.com:8080\n"), "{body}");
    assert!(body.contains("\nx-forwarded-for: 10.0.0.1, 192.0.2.7\n"), "{body}");
    assert!(body.contains("\nx-forwarded-proto: https\n"), "{body}");
}

#[tokio::test]
async fn http2_authority_becomes_host() {
    let upstream = echo_upstream().await;
    let req = Request::get("https://example.com/x").version(Version::HTTP_2);
    let res = forward(req.body(Full::default()).unwrap(), &upstream).await;
    assert!(res.body().starts_with("GET /x\n"), "{}", res.body());
    assert!(res.body().contains("\nhost: example.com\n"), "{}", res.body());
}

#[tokio::test]
async fn removes_hop_by_hop_headers() {
    let upstream = echo_upstream().await;
    let req = get("/")
        .header("connection", "x-session")
        .header("x-session", "secret")
        .header("keep-alive", "timeout=1")
        .header("te", "trailers")
        .header("x-kept", "yes");
    let res = forward(req.body(Full::default()).unwrap(), &upstream).await;
    let body = res.body();
    for name in ["x-session", "keep-alive", "te"] {
        assert!(!body.contains(&format!("\n{name}:")), "{name} reached the upstream: {body}");
    }
    assert!(body.contains("\nx-kept: yes\n"), "{body}");

    assert!(!res.headers().contains_key("keep-alive"), "response hop-by-hop header kept");
    assert_eq!(res.headers()["x-app"], "echo");
}

#[tokio::test]
async fn keeps_upgrade_headers_only_when_asked() {
    let upstream = echo_upstream().await;
    let asked = get("/").header("connection", "keep-alive, Upgrade").header("upgrade", "websocket");
    let body = forward(asked.body(Full::default()).unwrap(), &upstream).await.into_body();
    assert!(body.contains("\nconnection: upgrade\n"), "{body}");
    assert!(body.contains("\nupgrade: websocket\n"), "{body}");

    let unasked = get("/").header("upgrade", "websocket");
    let body = forward(unasked.body(Full::default()).unwrap(), &upstream).await.into_body();
    assert!(!body.contains("\nupgrade:"), "{body}");
}

#[tokio::test]
async fn upgrade_without_a_client_connection_is_a_bad_gateway() {
    let upstream = upgrade_upstream().await;
    let req = get("/").header("connection", "upgrade").header("upgrade", "websocket");
    let req = req.body(Full::default()).unwrap();
    let err = Client::default().forward(req, &upstream, PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::UnexpectedUpgrade), "{err:?}");
    assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn refused_connection_is_a_bad_gateway() {
    let upstream = closed_port().await;
    let req = get("/").body(Full::default()).unwrap();
    let err = Client::default().forward(req, &upstream, PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::Connect(_)), "{err:?}");
    assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    assert!(err.to_string().contains("refused"), "{err}");
}

#[tokio::test]
async fn closed_connection_is_a_bad_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    let req = get("/").body(Full::default()).unwrap();
    let err = Client::default().forward(req, &upstream, PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::Upstream(_)), "{err:?}");
    assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn slow_upstream_is_a_gateway_timeout() {
    let upstream = silent_upstream().await;
    let client = Client { response_timeout: Duration::from_millis(100), ..Client::default() };
    let req = get("/").body(Full::default()).unwrap();
    let err = client.forward(req, &upstream, PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::Timeout), "{err:?}");
    assert_eq!(err.status(), StatusCode::GATEWAY_TIMEOUT);
}

fn route(prefix: &str) -> Route {
    Route::new(&config::Proxy {
        path: prefix.to_owned(),
        upstreams: vec!["127.0.0.1:9".to_owned()],
        strip_prefix: true,
    })
}

#[test]
fn routes_match_whole_segments() {
    let api = route("/api");
    assert!(api.matches("/api") && api.matches("/api/") && api.matches("/api/x/y"));
    assert!(!api.matches("/apix") && !api.matches("/") && !api.matches("/API"));
    assert!(route("/").matches("/") && route("/").matches("/anything"));
}

#[test]
fn strip_prefix_keeps_the_rest() {
    let strip = |uri: &str, prefix| strip_prefix(&uri.parse().unwrap(), prefix).unwrap();
    assert_eq!(strip("/api/users?page=2", "/api"), "/users?page=2");
    assert_eq!(strip("/api", "/api"), "/");
    assert_eq!(strip("/api?x", "/api"), "/?x");
    assert_eq!(strip("https://example.com/api/x", "/api"), "https://example.com/x");
}

#[tokio::test]
async fn path_less_requests_are_rejected() {
    let req = Request::options("*").body(Full::default()).unwrap();
    let err = Client::default().forward(req, "127.0.0.1:9", PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::BadRequest), "{err:?}");
}

/// A route for `/` over `upstreams`.
fn balanced(upstreams: &[&String]) -> Route {
    Route::new(&config::Proxy {
        path: "/".to_owned(),
        upstreams: upstreams.iter().map(|u| u.to_string()).collect(),
        strip_prefix: false,
    })
}

/// Sends `req` through `route` and returns the `x-upstream` that answered.
async fn answered_by(route: &Route, client: &Client, req: Request<Full<Bytes>>) -> String {
    let res = route.forward(client, req, PEER).await.map_err(|e| e.to_string()).unwrap();
    res.headers()["x-upstream"].to_str().unwrap().to_owned()
}

#[tokio::test]
async fn round_robin_across_upstreams() {
    let (a, b) = (echo_upstream().await, echo_upstream().await);
    let route = balanced(&[&a, &b]);
    let client = Client::default();
    let mut seen = Vec::new();
    for _ in 0..4 {
        seen.push(answered_by(&route, &client, get("/").body(Full::default()).unwrap()).await);
    }
    assert_eq!(seen, [a.as_str(), &b, &a, &b]);
}

#[tokio::test]
async fn refused_upstream_is_retried_elsewhere_and_marked_down() {
    let (down, up) = (closed_port().await, echo_upstream().await);
    let route = balanced(&[&down, &up]);
    let client = Client::default();

    // The first request starts at `down`; its body must survive the failed attempt.
    let req = Request::post("/").header(HOST, "a.test").body(Full::from("payload")).unwrap();
    let res = route.forward(&client, req, PEER).await.map_err(|e| e.to_string()).unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body.ends_with(b"\npayload"), "{body:?}");
    assert!(!route.upstreams[0].is_up(route.now()), "a refused upstream is marked down");

    // While it's down, rotation skips it.
    for _ in 0..3 {
        let req = get("/").body(Full::default()).unwrap();
        assert_eq!(answered_by(&route, &client, req).await, up);
    }
}

#[tokio::test]
async fn upstreams_marked_down_are_still_tried_last() {
    let up = echo_upstream().await;
    let route = balanced(&[&up]);
    route.upstreams[0].mark_down(route.now());
    let req = get("/").body(Full::default()).unwrap();
    assert_eq!(answered_by(&route, &Client::default(), req).await, up);
    assert!(route.upstreams[0].is_up(route.now()), "a success marks it up again");
}

#[tokio::test]
async fn timeouts_mark_down_without_retrying() {
    let (silent, up) = (silent_upstream().await, echo_upstream().await);
    let route = balanced(&[&silent, &up]);
    let client = Client { response_timeout: Duration::from_millis(100), ..Client::default() };
    let req = get("/").body(Full::default()).unwrap();
    // The silent upstream may have acted on the request, so it isn't sent again.
    let err = route.forward(&client, req, PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::Timeout), "{err:?}");
    assert!(!route.upstreams[0].is_up(route.now()));
}
