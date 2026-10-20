//! HTTP and HTTPS listeners: accept connections and route each request to a site by its host.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::header::HOST;
use http::uri::Authority;
use http::{Request, Response, StatusCode, Version};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use webxlib::body::Body;
use webxlib::pages;
use webxlib::static_files::StaticFiles;

use crate::config::Config;
use crate::tls;

/// How long shutdown waits for in-flight requests before dropping them.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Pause after a failed accept; errors like running out of file descriptors repeat instantly.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// How long a client gets to finish the TLS handshake; hyper's header timeout starts after it.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type ConnBuilder = auto::Builder<TokioExecutor>;

pub struct Server {
    http: Option<Listener>,
    https: Option<Listener>,
    router: Arc<Router>,
}

/// A bound socket; the HTTPS one carries its TLS acceptor.
struct Listener {
    tcp: TcpListener,
    addr: SocketAddr,
    tls: Option<TlsAcceptor>,
}

impl Listener {
    async fn bind(addr: SocketAddr, tls: Option<TlsAcceptor>) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("can't listen on {addr}: {e}")))?;
        Ok(Self { addr: tcp.local_addr()?, tcp, tls })
    }
}

impl Server {
    /// Opens every site root and loads every cert, then binds the listeners.
    pub async fn bind(config: &Config) -> io::Result<Self> {
        let router = Arc::new(Router::new(config)?);
        let https = match config.server.https {
            Some(addr) => Some((addr, TlsAcceptor::from(Arc::new(tls::server_config(config)?)))),
            None => None,
        };
        let http = match config.server.http {
            Some(addr) => Some(Listener::bind(addr, None).await?),
            None => None,
        };
        let https = match https {
            Some((addr, acceptor)) => Some(Listener::bind(addr, Some(acceptor)).await?),
            None => None,
        };
        Ok(Self { http, https, router })
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|listener| listener.addr)
    }

    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https.as_ref().map(|listener| listener.addr)
    }

    /// Serves until `shutdown` resolves, then lets in-flight requests finish.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        // Enables hyper's header-read timeout, which guards against slow-header attacks.
        builder.http1().timer(TokioTimer::new());
        let builder = Arc::new(builder);
        let graceful = GracefulShutdown::new();

        let http = self.accept(self.http.as_ref(), &builder, &graceful);
        let https = self.accept(self.https.as_ref(), &builder, &graceful);
        tokio::select! {
            _ = async { tokio::join!(http, https) } => {}
            () = shutdown => {}
        }

        // Closes the listeners, so new connections are refused while in-flight ones finish.
        drop(self);
        if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
            tracing::warn!(
                "in-flight requests still running after {DRAIN_TIMEOUT:?}; dropping them"
            );
        }
    }

    /// Accepts connections until dropped; with no listener, waits forever.
    async fn accept(
        &self,
        listener: Option<&Listener>,
        builder: &Arc<ConnBuilder>,
        graceful: &GracefulShutdown,
    ) {
        let Some(listener) = listener else { return std::future::pending().await };
        loop {
            let (stream, peer) = match listener.tcp.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            if let Err(e) = stream.set_nodelay(true) {
                tracing::debug!(%peer, error = %e, "couldn't set TCP_NODELAY");
            }

            let conn = Connection {
                peer,
                router: Arc::clone(&self.router),
                builder: Arc::clone(builder),
                watcher: graceful.watcher(),
            };
            // The handshake runs in the connection's task so a slow client can't stall accepts.
            match listener.tls.clone() {
                None => tokio::spawn(conn.serve(stream)),
                Some(acceptor) => tokio::spawn(async move {
                    let handshake = acceptor.accept(stream);
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, handshake).await {
                        Ok(Ok(stream)) => conn.serve(stream).await,
                        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                }),
            };
        }
    }
}

/// An accepted connection, served once any TLS handshake is done.
struct Connection {
    peer: SocketAddr,
    router: Arc<Router>,
    builder: Arc<ConnBuilder>,
    /// Held from accept, so shutdown also waits for handshakes in progress.
    watcher: Watcher,
}

impl Connection {
    async fn serve<I>(self, io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Self { peer, router, builder, watcher } = self;
        let service = service_fn(move |req| {
            let router = Arc::clone(&router);
            async move { Ok::<_, Infallible>(router.handle(req).await) }
        });
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
        if let Err(e) = watcher.watch(conn.into_owned()).await {
            tracing::debug!(%peer, error = %e, "connection ended with an error");
        }
    }
}

/// Picks the site for each request.
struct Router {
    sites: HashMap<String, StaticFiles>,
    default: Option<StaticFiles>,
}

impl Router {
    fn new(config: &Config) -> io::Result<Self> {
        let mut sites = HashMap::new();
        let mut default = None;
        for (i, site) in config.sites.iter().enumerate() {
            let files = StaticFiles::new(&site.root, site.policy()).map_err(|e| {
                let root = site.root.display();
                io::Error::new(e.kind(), format!("site {}: can't open root {root}: {e}", i + 1))
            })?;
            for host in &site.hosts {
                sites.insert(host.clone(), files.clone());
            }
            if site.default {
                default = Some(files);
            }
        }
        Ok(Self { sites, default })
    }

    async fn handle<B>(&self, req: Request<B>) -> Response<Body> {
        let host = match request_host(&req) {
            Ok(host) => host,
            Err(code) => return pages::error_response(code),
        };
        let site = host.and_then(|host| self.sites.get(&host)).or(self.default.as_ref());
        match site {
            Some(site) => site.serve(&req).await,
            None => pages::error_response(StatusCode::MISDIRECTED_REQUEST),
        }
    }
}

/// The request's hostname, lowercased, without port or trailing dot.
/// HTTP/2 sends it in the URI authority; HTTP/1.1 must send a `Host` header.
fn request_host<B>(req: &Request<B>) -> Result<Option<String>, StatusCode> {
    let host = match (req.uri().host(), req.headers().get(HOST)) {
        (Some(host), _) => host.to_owned(),
        (None, Some(value)) => {
            let authority = Authority::try_from(value.as_bytes());
            authority.map_err(|_| StatusCode::BAD_REQUEST)?.host().to_owned()
        }
        (None, None) if req.version() == Version::HTTP_11 => return Err(StatusCode::BAD_REQUEST),
        (None, None) => return Ok(None),
    };
    Ok(Some(host.trim_end_matches('.').to_ascii_lowercase()))
}
