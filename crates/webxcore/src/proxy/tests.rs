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

/// Starts an upstream that answers each request with its method, URI, headers and body.
async fn echo_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(echo));
            tokio::spawn(conn);
        }
    });
    addr
}

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut text = format!("{} {}\n", req.method(), req.uri());
    for (name, value) in req.headers() {
        text.push_str(&format!("{name}: {}\n", value.to_str().unwrap()));
    }
    text.push_str(&String::from_utf8_lossy(&req.into_body().collect().await?.to_bytes()));
    let res = Response::builder().header("keep-alive", "timeout=5").header("x-app", "echo");
    Ok(res.body(Full::new(Bytes::from(text))).unwrap())
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
async fn refused_connection_is_a_bad_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().to_string();
    drop(listener);
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().to_string();
    // Accepts, then never answers.
    tokio::spawn(async move {
        let _held = listener.accept().await.unwrap();
        std::future::pending::<Infallible>().await
    });
    let client = Client { response_timeout: Duration::from_millis(100), ..Client::default() };
    let req = get("/").body(Full::default()).unwrap();
    let err = client.forward(req, &upstream, PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::Timeout), "{err:?}");
    assert_eq!(err.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn path_less_requests_are_rejected() {
    let req = Request::options("*").body(Full::default()).unwrap();
    let err = Client::default().forward(req, "127.0.0.1:9", PEER).await.err().unwrap();
    assert!(matches!(err, ProxyError::BadRequest), "{err:?}");
}
