//! Test support: runs Pebble, Let's Encrypt's test CA. The `webx4r` crate's end-to-end
//! tests compile this file too, so it uses only std and dev-dependencies.

use std::fs::{self, File};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Pebble, run from `PATH` and stopped on drop. Needs Pebble 2.7 or later.
pub struct Pebble {
    /// Pebble, after `pebble-challtestsrv` when validating.
    children: Vec<(&'static str, Child)>,
    dir: TempDir,
    url: String,
}

impl Pebble {
    /// A CA for account tests; it can't validate challenges.
    pub fn start() -> Self {
        Self::launch(5002, 5001, false)
    }

    /// A CA that validates challenges at 127.0.0.1, whatever the name: HTTP-01 on
    /// `http_port` and TLS-ALPN-01 on `tls_port`. `pebble-challtestsrv` answers its DNS.
    pub fn start_validating(http_port: u16, tls_port: u16) -> Self {
        Self::launch(http_port, tls_port, true)
    }

    fn launch(http_port: u16, tls_port: u16, validate: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        fs::write(&cert, pair.cert.pem()).unwrap();
        fs::write(&key, pair.signing_key.serialize_pem()).unwrap();

        let port = free_port();
        let config = serde_json::json!({ "pebble": {
            "listenAddress": format!("127.0.0.1:{port}"),
            "managementListenAddress": format!("127.0.0.1:{}", free_port()),
            "certificate": cert,
            "privateKey": key,
            "httpPort": http_port,
            "tlsPort": tls_port,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
        }});
        let config_path = dir.path().join("pebble.json");
        fs::write(&config_path, config.to_string()).unwrap();

        let url = format!("https://localhost:{port}/dir");
        let mut pebble = Self { children: Vec::new(), dir, url };
        let mut args = vec!["-config".to_owned(), config_path.to_str().unwrap().to_owned()];
        if validate {
            let (dns, management) = (free_port(), free_port());
            let (dns, management) = (format!("127.0.0.1:{dns}"), format!("127.0.0.1:{management}"));
            // `-dnsserver` was `-dns01` before Pebble 2.7.
            let mut challtestsrv = vec!["-dnsserver", &dns, "-management", &management];
            // Only the DNS server; empty addresses turn off its other servers.
            challtestsrv.extend(["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""]);
            // No AAAA answers, so Pebble connects over IPv4, where the tests listen.
            challtestsrv.extend(["-defaultIPv6", ""]);
            pebble.spawn("pebble-challtestsrv", &challtestsrv);
            pebble.wait_for(&management);
            args.extend(["-dnsserver".to_owned(), dns]);
        }
        pebble.spawn("pebble", &args);
        pebble.wait_for(&format!("127.0.0.1:{port}"));
        pebble
    }

    fn spawn(&mut self, program: &'static str, args: &[impl AsRef<std::ffi::OsStr>]) {
        let log = File::create(self.dir.path().join(format!("{program}.log"))).unwrap();
        let child = Command::new(program)
            .args(args)
            .env("PEBBLE_VA_NOSLEEP", "1")
            // Pebble rejects some nonces on purpose by default; tests must be repeatable.
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap_or_else(|e| panic!("tests that need pebble need `{program}` on PATH: {e}"));
        self.children.push((program, child));
    }

    /// Waits for a TCP listener at `addr`, failing with the logs if a child exits first.
    fn wait_for(&mut self, addr: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(addr).is_err() {
            let exited = self.children.iter_mut().any(|(_, c)| c.try_wait().unwrap().is_some());
            if exited || Instant::now() > deadline {
                panic!("pebble didn't start:\n{}", self.logs());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Every child's output, for failure messages.
    pub fn logs(&self) -> String {
        let log = |(program, _): &(&str, Child)| {
            let text = fs::read_to_string(self.dir.path().join(format!("{program}.log")));
            format!("--- {program}\n{}", text.unwrap_or_default())
        };
        self.children.iter().map(log).collect::<Vec<_>>().join("\n")
    }

    /// The ACME directory URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Pebble's self-signed HTTPS cert: the root to trust for [`Pebble::url`].
    pub fn root(&self) -> PathBuf {
        self.dir.path().join("cert.pem")
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
