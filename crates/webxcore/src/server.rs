//! HTTP and HTTPS listeners: accept connections and route each request to a site by its host.

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use http::header::{HOST, LOCATION};
use http::uri::{Authority, PathAndQuery};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use hyper::body::Incoming;
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

use crate::access_log::{AccessLog, Entry, Started};
use crate::acme::{self, ACME_TLS_ALPN, Challenges};
use crate::config::{self, Config};
use crate::metrics::{self, Metrics, SiteMetrics};
use crate::observe::Observed;
use crate::proxy::{self, Peer, Route};
use crate::tls::CertStore;

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
    reloader: Reloader,
    /// Present with `[acme]`, like `manager`.
    challenges: Option<Arc<Challenges>>,
    manager: Option<acme::Manager>,
    access_log: Option<Arc<AccessLog>>,
}

/// Applies a new config to a running [`Server`].
#[derive(Clone)]
pub struct Reloader {
    /// Loaded once per request, so in-flight requests keep the config they started with.
    router: Arc<ArcSwap<Router>>,
    /// Outlives reloads, so connections to unchanged upstreams stay pooled.
    client: proxy::Client,
    /// Present when serving HTTPS.
    certs: Option<Arc<CertStore>>,
    /// The tables only a restart can change.
    server: config::Server,
    acme: Option<config::Acme>,
    log: Option<config::Log>,
    metrics: Option<config::Metrics>,
    /// Tells the ACME manager which names the new config needs certs for.
    manager: Option<acme::Handle>,
    /// The bound HTTPS port, for redirects.
    https_port: Option<u16>,
    /// Present with `[metrics]`; outlives reloads, so counts carry on.
    registry: Option<Arc<Metrics>>,
}

impl Reloader {
    /// Builds the new config's sites and certificates, then swaps them in;
    /// on error, the old config stays.
    pub fn reload(&self, config: &Config) -> io::Result<()> {
        let result = self.apply(config);
        if let Some(registry) = &self.registry {
            registry.reloaded(result.is_ok());
        }
        result
    }

    fn apply(&self, config: &Config) -> io::Result<()> {
        let restart = |table| {
            let msg = format!("{table} settings changed; restart to apply them");
            Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
        };
        if config.server != self.server {
            return restart("[server]");
        }
        if config.acme != self.acme {
            return restart("[acme]");
        }
        if config.log != self.log {
            return restart("[log]");
        }
        if config.metrics != self.metrics {
            return restart("[metrics]");
        }
        let client = self.client.clone();
        let router = Router::new(config, client, self.https_port, self.registry.as_deref())?;
        let certs = match &self.certs {
            Some(store) => Some((store, store.load(config)?)),
            None => None,
        };
        self.router.store(Arc::new(router));
        if let Some((store, certs)) = certs {
            store.store(certs);
        }
        if let Some(manager) = &self.manager {
            manager.update(config);
        }
        Ok(())
    }
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
    /// Loads every cert, binds the listeners, then opens every site root.
    pub async fn bind(config: &Config) -> io::Result<Self> {
        let challenges = config.acme.as_ref().map(|_| Arc::new(Challenges::default()));
        let certs = match config.server.https {
            Some(_) => Some(Arc::new(CertStore::new(config, challenges.clone())?)),
            None => None,
        };
        let http = match config.server.http {
            Some(addr) => Some(Listener::bind(addr, None).await?),
            None => None,
        };
        let https = match (config.server.https, &certs) {
            (Some(addr), Some(certs)) => {
                let acceptor = TlsAcceptor::from(Arc::new(certs.server_config()));
                Some(Listener::bind(addr, Some(acceptor)).await?)
            }
            _ => None,
        };
        // After binding, so redirects name the port actually bound.
        let https_port = https.as_ref().map(|listener| listener.addr.port());
        let client = proxy::Client::default();
        let registry = config.metrics.as_ref().map(|_| Arc::new(Metrics::default()));
        let router = Router::new(config, client.clone(), https_port, registry.as_deref())?;
        let router = Arc::new(ArcSwap::from_pointee(router));
        let manager = match (&challenges, &certs) {
            (Some(challenges), Some(certs)) => {
                let (challenges, certs) = (Arc::clone(challenges), Arc::clone(certs));
                acme::Manager::new(config, challenges, certs, registry.clone())?
            }
            _ => None,
        };
        let (manager, handle) = manager.unzip();
        let reloader = Reloader {
            router,
            client,
            certs,
            server: config.server.clone(),
            acme: config.acme.clone(),
            log: config.log.clone(),
            metrics: config.metrics.clone(),
            manager: handle,
            https_port,
            registry,
        };
        Ok(Self { http, https, reloader, challenges, manager, access_log: None })
    }

    /// Records every response in `log` from now on.
    pub fn set_access_log(&mut self, log: AccessLog) {
        self.access_log = Some(Arc::new(log));
    }

    /// Present with `[metrics]`.
    pub fn metrics(&self) -> Option<Arc<Metrics>> {
        self.reloader.registry.clone()
    }

    /// A handle for reloading the config while [`Server::run`] serves.
    pub fn reloader(&self) -> Reloader {
        self.reloader.clone()
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|listener| listener.addr)
    }

    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https.as_ref().map(|listener| listener.addr)
    }

    /// Serves, and keeps ACME certs issued, until `shutdown` resolves; then lets in-flight
    /// requests finish.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        // Enables hyper's header-read timeout, which guards against slow-header attacks.
        builder.http1().timer(TokioTimer::new());
        let builder = Arc::new(builder);
        let graceful = GracefulShutdown::new();

        let manager = self.manager.take();
        let acme = async {
            match manager {
                Some(manager) => manager.run().await,
                None => std::future::pending().await,
            }
        };
        let http = self.accept(self.http.as_ref(), &builder, &graceful);
        let https = self.accept(self.https.as_ref(), &builder, &graceful);
        tokio::select! {
            _ = async { tokio::join!(http, https, acme) } => {}
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
        let name = if listener.tls.is_some() { "https" } else { "http" };
        let metrics =
            self.reloader.registry.as_ref().map(|registry| Arc::new(registry.listener(name)));
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
                peer: Peer { addr: peer, https: listener.tls.is_some() },
                router: Arc::clone(&self.reloader.router),
                challenges: self.challenges.clone(),
                access_log: self.access_log.clone(),
                builder: Arc::clone(builder),
                watcher: graceful.watcher(),
            };
            // Counted as open until the task below ends.
            let open = metrics.as_ref().map(|metrics| metrics.accepted());
            let metrics = metrics.clone();
            // The handshake runs in the connection's task so a slow client can't stall accepts.
            match listener.tls.clone() {
                None => tokio::spawn(async move {
                    conn.serve(stream).await;
                    drop(open);
                }),
                Some(acceptor) => tokio::spawn(async move {
                    let _open = open;
                    let failed = |timed_out| {
                        if let Some(metrics) = &metrics {
                            metrics.handshake_failed(timed_out);
                        }
                    };
                    let handshake = acceptor.accept(stream);
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, handshake).await {
                        // The handshake is the whole TLS-ALPN-01 answer (RFC 8737 §3).
                        Ok(Ok(stream))
                            if stream.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN) =>
                        {
                            tracing::debug!(%peer, "answered a TLS-ALPN-01 challenge");
                        }
                        Ok(Ok(stream)) => conn.serve(stream).await,
                        Ok(Err(e)) => {
                            failed(false);
                            tracing::debug!(%peer, error = %e, "TLS handshake failed");
                        }
                        Err(_) => {
                            failed(true);
                            tracing::debug!(%peer, "TLS handshake timed out");
                        }
                    }
                }),
            };
        }
    }
}

/// An accepted connection, served once any TLS handshake is done.
struct Connection {
    peer: Peer,
    router: Arc<ArcSwap<Router>>,
    challenges: Option<Arc<Challenges>>,
    access_log: Option<Arc<AccessLog>>,
    builder: Arc<ConnBuilder>,
    /// Held from accept, so shutdown also waits for handshakes in progress.
    watcher: Watcher,
}

impl Connection {
    async fn serve<I>(self, io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Self { peer, router, challenges, access_log, builder, watcher } = self;
        let service = service_fn(move |req| {
            let arrived = Instant::now();
            let logging = access_log
                .as_ref()
                .map(|log| (Arc::clone(log), Started::new(&req, peer.addr.ip())));
            let answer = challenges.as_ref().and_then(|challenges| challenges.http_response(&req));
            let router = router.load_full();
            async move {
                let (res, metrics) = match answer {
                    Some(res) => (res, router.unrouted.clone()),
                    None => router.handle(req, peer).await,
                };
                let entry = logging.map(|(log, started)| Entry::new(log, started, &res));
                Ok::<_, Infallible>(Observed::wrap(res, arrived, entry, metrics))
            }
        });
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
        if let Err(e) = watcher.watch(conn.into_owned()).await {
            tracing::debug!(peer = %peer.addr, error = %e, "connection ended with an error");
        }
    }
}

/// Picks the site for each request.
struct Router {
    sites: HashMap<String, Arc<SiteHandler>>,
    default: Option<Arc<SiteHandler>>,
    /// Shared by every site, so they all draw on one pool of upstream connections.
    client: proxy::Client,
    /// The HTTPS port that plain HTTP requests are redirected to, when there is one.
    https_port: Option<u16>,
    /// Metrics for responses that reach no site; present with `[metrics]`.
    unrouted: Option<Arc<SiteMetrics>>,
}

/// Serves one site's requests.
struct SiteHandler {
    files: Option<StaticFiles>,
    /// Longest prefix first, so the most specific route wins.
    routes: Vec<Route>,
    /// Hosts whose plain HTTP requests are redirected to HTTPS.
    redirect_hosts: HashSet<String>,
    /// Present with `[metrics]`, labeled with the site's first host, or `default`.
    metrics: Option<Arc<SiteMetrics>>,
}

impl Router {
    fn new(
        config: &Config,
        client: proxy::Client,
        https_port: Option<u16>,
        registry: Option<&Metrics>,
    ) -> io::Result<Self> {
        let mut sites = HashMap::new();
        let mut default = None;
        let acme = config.acme.is_some();
        for (i, site) in config.sites.iter().enumerate() {
            let files = match &site.root {
                Some(root) => Some(StaticFiles::new(root, site.policy()).map_err(|e| {
                    let root = root.display();
                    io::Error::new(e.kind(), format!("site {}: can't open root {root}: {e}", i + 1))
                })?),
                None => None,
            };
            let route = |proxy| Route::new(proxy, registry);
            let mut routes: Vec<_> = site.proxies.iter().map(route).collect();
            routes.sort_by_key(|route| std::cmp::Reverse(route.prefix().len()));
            let redirect_hosts = match https_port {
                Some(_) if site.redirect_https => site.tls_hosts(acme).cloned().collect(),
                _ => HashSet::new(),
            };
            let name = site.hosts.first().map_or("default", String::as_str);
            let metrics = registry.map(|registry| registry.site(name));
            let handler = Arc::new(SiteHandler { files, routes, redirect_hosts, metrics });
            for host in &site.hosts {
                sites.insert(host.clone(), Arc::clone(&handler));
            }
            if site.default {
                default = Some(handler);
            }
        }
        let unrouted = registry.map(|registry| registry.site(metrics::NO_SITE));
        Ok(Self { sites, default, client, https_port, unrouted })
    }

    /// The response, and the metrics of the site that answered.
    async fn handle(
        &self,
        req: Request<Incoming>,
        peer: Peer,
    ) -> (Response<Body>, Option<Arc<SiteMetrics>>) {
        let host = match request_host(&req) {
            Ok(host) => host,
            Err(code) => return (pages::error_response(code), self.unrouted.clone()),
        };
        let site = host.as_ref().and_then(|host| self.sites.get(host)).or(self.default.as_ref());
        let Some(site) = site else {
            let res = pages::error_response(StatusCode::MISDIRECTED_REQUEST);
            return (res, self.unrouted.clone());
        };
        let metrics = site.metrics.clone();
        // Unknown hosts reach the default site but aren't in its `redirect_hosts`, since no
        // cert covers them.
        if let (false, Some(port), Some(host)) = (peer.https, self.https_port, &host)
            && site.redirect_hosts.contains(host)
            && !req.uri().path().starts_with(acme::HTTP_CHALLENGE_PATH)
        {
            return (redirect_to_https(host, port, req.uri()), metrics);
        }
        (site.handle(req, peer, &self.client).await, metrics)
    }
}

impl SiteHandler {
    /// Proxies the request if a route matches its path, else serves static files.
    async fn handle(
        &self,
        req: Request<Incoming>,
        peer: Peer,
        client: &proxy::Client,
    ) -> Response<Body> {
        let Some(route) = self.routes.iter().find(|route| route.matches(req.uri().path())) else {
            return match &self.files {
                Some(files) => files.serve(&req).await,
                None => pages::error_response(StatusCode::NOT_FOUND),
            };
        };
        let head = req.method() == Method::HEAD;
        match route.forward(client, req, peer).await {
            Ok(res) => res,
            Err(e) => match &self.files {
                Some(files) => files.error_response(e.status(), head).await,
                None => pages::error_response(e.status()),
            },
        }
    }
}

/// A permanent redirect to the same URL over HTTPS on `port`; 308 keeps the method and body.
fn redirect_to_https(host: &str, port: u16, uri: &Uri) -> Response<Body> {
    let port = if port == 443 { String::new() } else { format!(":{port}") };
    let path = uri.path_and_query().map_or("/", PathAndQuery::as_str);
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(LOCATION, format!("https://{host}{port}{path}"))
        .body(Body::empty())
        .expect("hostnames and URI paths are valid header values")
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
