//! HTTP listener: accepts connections and routes each request to a site by its host.

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
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use webxlib::body::Body;
use webxlib::pages;
use webxlib::static_files::StaticFiles;

use crate::config::Config;

/// How long shutdown waits for in-flight requests before dropping them.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Pause after a failed accept; errors like running out of file descriptors repeat instantly.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

pub struct Server {
    listener: TcpListener,
    router: Arc<Router>,
}

impl Server {
    /// Opens every site root, then binds the HTTP listener.
    pub async fn bind(config: &Config) -> io::Result<Self> {
        let router = Arc::new(Router::new(config)?);
        let listener = TcpListener::bind(config.server.http).await?;
        Ok(Self { listener, router })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves until `shutdown` resolves, then lets in-flight requests finish.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        // Enables hyper's header-read timeout, which guards against slow-header attacks.
        builder.http1().timer(TokioTimer::new());
        let graceful = GracefulShutdown::new();
        tokio::pin!(shutdown);

        loop {
            let (stream, peer) = tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                },
                () = &mut shutdown => break,
            };
            if let Err(e) = stream.set_nodelay(true) {
                tracing::debug!(%peer, error = %e, "couldn't set TCP_NODELAY");
            }

            let router = Arc::clone(&self.router);
            let service = service_fn(move |req| {
                let router = Arc::clone(&router);
                async move { Ok::<_, Infallible>(router.handle(req).await) }
            });
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
            let conn = graceful.watch(conn.into_owned());
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(%peer, error = %e, "connection ended with an error");
                }
            });
        }

        drop(self.listener);
        if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
            tracing::warn!(
                "in-flight requests still running after {DRAIN_TIMEOUT:?}; dropping them"
            );
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
