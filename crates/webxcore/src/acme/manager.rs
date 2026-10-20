//! Orders each `[acme]` site's certificate, then renews it before it expires.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountBuilder, AuthorizationStatus, ChallengeType, Identifier, NewOrder, Order,
    OrderStatus, RetryPolicy,
};
use tokio::sync::watch;

use super::{Challenges, Issued, Storage, account};
use crate::config::{Acme, Config};
use crate::tls::CertStore;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Makes the client that talks to the CA; tests swap in one that trusts Pebble.
pub type Connector = Arc<dyn Fn() -> Result<AccountBuilder, instant_acme::Error> + Send + Sync>;

/// The wait after a first failed order; each further failure waits 3 times longer.
/// Let's Encrypt allows 5 failed validations per name per hour.
const RETRY_FIRST: Duration = Duration::from_secs(2 * 60);
const RETRY_MAX: Duration = Duration::from_secs(12 * 60 * 60);

/// The longest wait between checks, so a suspended machine or a clock change can't put
/// renewal off for long.
const MAX_SLEEP: Duration = Duration::from_secs(60 * 60);

/// How long the CA gets to validate an order's challenges, and then to issue its cert.
const ORDER_POLL: RetryPolicy = RetryPolicy::new().timeout(Duration::from_secs(120));

/// Keeps a cert issued for each site's ACME names, serving them from a [`CertStore`].
pub struct Manager {
    acme: Acme,
    storage: Storage,
    connector: Connector,
    challenges: Arc<Challenges>,
    certs: Arc<CertStore>,
    /// Whether HTTP-01 is possible: it needs the plain HTTP listener.
    http: bool,
    /// One name set per site; [`Handle::update`] sends new ones on reload.
    wanted: watch::Receiver<Vec<Vec<String>>>,
    /// Registered or loaded on first use.
    account: Option<Account>,
    issued: HashMap<Vec<String>, Issued>,
    failures: HashMap<Vec<String>, Failure>,
}

struct Failure {
    count: u32,
    retry_at: SystemTime,
}

/// Tells a running [`Manager`] about a reloaded config.
#[derive(Clone)]
pub struct Handle(Arc<watch::Sender<Vec<Vec<String>>>>);

impl Handle {
    pub fn update(&self, config: &Config) {
        self.0.send_replace(wanted(config));
    }
}

impl Manager {
    /// `None` without `[acme]`. Serves the certs saved earlier right away.
    pub fn new(
        config: &Config,
        connector: Connector,
        challenges: Arc<Challenges>,
        certs: Arc<CertStore>,
    ) -> Option<(Self, Handle)> {
        let acme = config.acme.clone()?;
        let root = config.acme_storage();
        tracing::info!(storage = %root.display(), "ACME certificates are kept here");
        let storage = Storage::new(&root, acme.directory_url());
        let (sender, wanted) = watch::channel(self::wanted(config));
        let mut manager = Self {
            acme,
            storage,
            connector,
            challenges,
            certs,
            http: config.server.http.is_some(),
            wanted,
            account: None,
            issued: HashMap::new(),
            failures: HashMap::new(),
        };
        let wanted = manager.wanted.borrow().clone();
        manager.load_saved(&wanted);
        Some((manager, Handle(Arc::new(sender))))
    }

    /// Orders and renews certs until dropped.
    pub async fn run(mut self) {
        loop {
            let wanted = self.wanted.borrow_and_update().clone();
            self.load_saved(&wanted);
            for names in &wanted {
                if self.next_order(names) <= SystemTime::now() {
                    self.order(names).await;
                }
            }
            let next = wanted.iter().map(|names| self.next_order(names)).min();
            let wait = next.map_or(MAX_SLEEP, |next| {
                next.duration_since(SystemTime::now()).unwrap_or_default().min(MAX_SLEEP)
            });
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                Ok(()) = self.wanted.changed() => {}
            }
        }
    }

    /// Loads saved certs for names that have none yet, forgets names no longer wanted, and
    /// serves the result.
    fn load_saved(&mut self, wanted: &[Vec<String>]) {
        self.issued.retain(|names, _| wanted.contains(names));
        self.failures.retain(|names, _| wanted.contains(names));
        for names in wanted {
            if self.issued.contains_key(names) {
                continue;
            }
            match self.storage.load_cert(names) {
                Ok(Some(issued)) => {
                    self.issued.insert(names.clone(), issued);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "ignoring a saved certificate"),
            }
        }
        self.publish();
    }

    fn publish(&self) {
        let mut by_host = HashMap::new();
        for (names, issued) in &self.issued {
            for name in names {
                by_host.insert(name.clone(), Arc::clone(&issued.certified));
            }
        }
        self.certs.store_acme(by_host);
    }

    /// Now for names without a cert; otherwise at renewal time, or after a failure, at
    /// the retry time if that's later.
    fn next_order(&self, names: &[String]) -> SystemTime {
        let due = self.issued.get(names).map_or(UNIX_EPOCH, |issued| issued.renew_at);
        match self.failures.get(names) {
            Some(failure) => due.max(failure.retry_at),
            None => due,
        }
    }

    async fn order(&mut self, names: &[String]) {
        let failures = self.failures.get(names).map_or(0, |failure| failure.count);
        let kind = challenge_type(self.http, failures);
        tracing::info!(?names, challenge = ?kind, "requesting a certificate");
        match self.issue(names, kind.clone()).await {
            Ok(issued) => {
                let renew_at = httpdate::fmt_http_date(issued.renew_at);
                tracing::info!(?names, renew_at, "got a certificate");
                self.failures.remove(names);
                self.issued.insert(names.to_vec(), issued);
                self.publish();
            }
            Err(e) => {
                let delay = retry_delay(failures + 1);
                tracing::warn!(
                    ?names, challenge = ?kind, error = %e,
                    "couldn't get a certificate; retrying in {delay:?}"
                );
                let retry_at = SystemTime::now() + delay;
                self.failures.insert(names.to_vec(), Failure { count: failures + 1, retry_at });
            }
        }
    }

    async fn issue(&mut self, names: &[String], kind: ChallengeType) -> Result<Issued, Error> {
        let account = match &self.account {
            Some(account) => account.clone(),
            None => {
                let account = account((self.connector)()?, &self.acme, &self.storage).await?;
                self.account.insert(account).clone()
            }
        };
        let (key_pem, chain_pem) = order(&account, names, kind, &self.challenges).await?;
        Ok(self.storage.save_cert(names, &key_pem, &chain_pem)?)
    }
}

/// The names each site needs an ACME cert for, skipping sites with none.
fn wanted(config: &Config) -> Vec<Vec<String>> {
    if config.acme.is_none() {
        return Vec::new();
    }
    let names = config.sites.iter().map(|site| site.acme_hosts().cloned().collect::<Vec<_>>());
    names.filter(|names| !names.is_empty()).collect()
}

/// HTTP-01 when there's a plain HTTP listener, else TLS-ALPN-01; after each failure, the
/// other one, in case a firewall or proxy blocks one port.
fn challenge_type(http: bool, failures: u32) -> ChallengeType {
    if http && failures.is_multiple_of(2) {
        ChallengeType::Http01
    } else {
        ChallengeType::TlsAlpn01
    }
}

fn retry_delay(failures: u32) -> Duration {
    let factor = 3u32.saturating_pow(failures.saturating_sub(1));
    RETRY_FIRST.saturating_mul(factor).min(RETRY_MAX)
}

/// Runs one order to the end: answers each challenge, waits for the CA to validate them,
/// then sends a CSR. Returns the new private key and the cert chain, as PEM.
async fn order(
    account: &Account,
    names: &[String],
    kind: ChallengeType,
    challenges: &Challenges,
) -> Result<(String, String), Error> {
    let identifiers: Vec<_> = names.iter().map(|name| Identifier::Dns(name.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut answers = Answers { challenges, tokens: Vec::new(), hosts: Vec::new() };
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        let host = authorization.identifier().to_string();
        match authorization.status {
            AuthorizationStatus::Pending => {}
            // The CA remembers names this account proved recently.
            AuthorizationStatus::Valid => continue,
            status => return Err(format!("the CA's authorization for {host} is {status:?}").into()),
        }
        let mut challenge = authorization
            .challenge(kind.clone())
            .ok_or_else(|| format!("the CA offers no {kind:?} challenge for {host}"))?;
        let key_authorization = challenge.key_authorization();
        if kind == ChallengeType::Http01 {
            challenges.add_http(&challenge.token, key_authorization.as_str());
            answers.tokens.push(challenge.token.clone());
        } else {
            challenges.add_tls_alpn(&host, key_authorization.digest().as_ref())?;
            answers.hosts.push(host);
        }
        challenge.set_ready().await?;
    }

    let status = order.poll_ready(&ORDER_POLL).await?;
    drop(answers);
    if status != OrderStatus::Ready {
        return Err(
            format!("the CA refused the order: {}", failure_reasons(&mut order).await).into()
        );
    }
    let key_pem = order.finalize().await?;
    let chain_pem = order.poll_certificate(&ORDER_POLL).await?;
    Ok((key_pem, chain_pem))
}

/// The CA's reasons for failing `order`, from its challenges' errors.
async fn failure_reasons(order: &mut Order) -> String {
    let mut reasons = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authorization)) = authorizations.next().await {
        let host = authorization.identifier().to_string();
        let errors = authorization.challenges.iter().filter_map(|c| c.error.as_ref());
        reasons.extend(errors.map(|error| format!("{host}: {error}")));
    }
    if reasons.is_empty() { "no reason given".to_owned() } else { reasons.join("; ") }
}

/// One order's challenge answers, withdrawn when the order ends however it ends.
struct Answers<'a> {
    challenges: &'a Challenges,
    tokens: Vec<String>,
    hosts: Vec<String>,
}

impl Drop for Answers<'_> {
    fn drop(&mut self) {
        for token in &self.tokens {
            self.challenges.remove_http(token);
        }
        for host in &self.hosts {
            self.challenges.remove_tls_alpn(host);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn retries_wait_longer_up_to_a_cap() {
        let minutes: Vec<_> = (1..=6).map(|n| retry_delay(n).as_secs() / 60).collect();
        assert_eq!(minutes, [2, 6, 18, 54, 162, 486]);
        assert_eq!(retry_delay(7), RETRY_MAX);
        assert_eq!(retry_delay(u32::MAX), RETRY_MAX);
    }

    #[test]
    fn challenge_types_alternate_after_failures() {
        let types: Vec<_> = (0..3).map(|failures| challenge_type(true, failures)).collect();
        assert_eq!(types, [ChallengeType::Http01, ChallengeType::TlsAlpn01, ChallengeType::Http01]);
        assert_eq!(challenge_type(false, 0), ChallengeType::TlsAlpn01, "no HTTP listener");
        assert_eq!(challenge_type(false, 1), ChallengeType::TlsAlpn01);
    }

    #[test]
    fn wanted_names_are_per_site() {
        let text = "[server]\nhttp = \"127.0.0.1:0\"\nhttps = \"127.0.0.1:0\"\n\
                    [[site]]\nhosts = [\"a.test\", \"www.a.test\", \"localhost\"]\nroot = \"a\"\n\
                    [[site]]\nhosts = [\"localhost.b\", \"b.localhost\"]\nroot = \"b\"\n\
                    [[site]]\nhosts = [\"127.0.0.1\"]\nroot = \"c\"\n";
        let without = Config::parse(text, Path::new("/srv")).unwrap();
        assert!(wanted(&without).is_empty(), "no [acme]");
        let with = Config::parse(&format!("{text}[acme]\n"), Path::new("/srv")).unwrap();
        let expected = [vec!["a.test", "www.a.test"], vec!["localhost.b"]];
        assert_eq!(wanted(&with), expected);
    }
}
