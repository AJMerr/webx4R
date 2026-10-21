# webx4R

A web server and app platform written in Rust. Today it serves static sites and proxies requests to apps written in any language. The plan is to run those apps itself next, then spread them across several machines.

## Status

Version 1.0. Binaries for Linux and Windows are on the [releases page](https://github.com/AJMerr/webx4R/releases). What works now:

- Static files over HTTP/1.1 and HTTP/2
- HTTPS with a certificate per site, picked by hostname (SNI); `localhost` sites get a self-signed certificate automatically
- Automatic certificates from Let's Encrypt or another ACME CA, renewed before they expire, and HTTP → HTTPS redirects
- Several sites on one listener, picked by hostname
- Reverse proxy to apps by path prefix, with several upstreams per route, passive health checks, retries and WebSocket pass-through
- ETag and Last-Modified, with 304 Not Modified responses
- Range requests, including multiple ranges in one request
- Optional directory listings
- Built-in error pages that a site can replace with its own
- Config reload without downtime, with `webx4r reload` or SIGHUP on Unix
- Graceful shutdown on Ctrl-C, or SIGTERM on Unix
- Access logs in JSON or nginx's combined format, and server logs, written to daily files
- Prometheus metrics for responses, connections, TLS, upstreams, certificates and reloads

Benchmarks against nginx are the rest of the first milestone.

Linux is the main target. Windows is supported and tested in CI.

## Quick start

You need a recent stable Rust toolchain (edition 2024).

```sh
git clone https://github.com/AJMerr/webx4R
cd webx4R
cargo build --release
```

Make a folder with a site in it and a config file next to it:

```text
mysite/
├── webx4r.toml
└── www/
    └── index.html
```

`mysite/webx4r.toml`:

```toml
[server]
http = "127.0.0.1:8080"

[[site]]
hosts = ["localhost"]
root = "www"
default = true
```

Start the server and open http://localhost:8080:

```sh
./target/release/webx4r serve --config mysite/webx4r.toml
```

Logs go to stderr at the `info` level. Set `WEBX4R_LOG=debug` for more detail, or see [Logs](#logs) to write them to files.

## Configuration

### `[server]`

| Key | Meaning |
|---|---|
| `http` | Address to listen on for plain HTTP, such as `0.0.0.0:8080`. |
| `https` | Address to listen on for HTTPS, such as `0.0.0.0:8443`. |
| `control` | Where `webx4r reload` reaches the server: a socket path on Unix, or a pipe name (`\\.\pipe\…`) on Windows. Optional; see [Reloading](#reloading) for the default. |

At least one of `http` and `https` is required.

### `[[site]]`

Add one block per site.

| Key | Default | Meaning |
|---|---|---|
| `hosts` | `[]` | Hostnames the site answers to: lowercase ASCII, no port. |
| `root` | none | Folder of static files to serve. A relative path is resolved from the config file's folder. A site needs a `root`, at least one `[[site.proxy]]`, or both. |
| `default` | `false` | Serve requests whose hostname matches no other site. Only one site can be the default, and a site with no `hosts` must be. |
| `directory_listing` | `false` | List the contents of folders that have no `index.html`. |
| `allow_dotfiles` | `false` | Serve names that start with `.`. `/.well-known/` is always served. |
| `symlinks` | `"inside-root"` | `"inside-root"` follows relative links that stay inside `root`. `"follow"` follows any link. `"deny"` refuses all links. |
| `cert` | none | PEM certificate chain for HTTPS, resolved like `root`. Needs `key` and `[server] https`. |
| `key` | none | PEM private key for `cert`. |
| `redirect_https` | `true` | Redirect plain HTTP to HTTPS for the site's hostnames that have a certificate. See [HTTPS](#https). |

A request for an unknown hostname gets `421 Misdirected Request` when no site is the default. Unknown keys are rejected at startup, so typos don't go unnoticed.

To replace a built-in error page, put a file named after the status code (`404.html`, `502.html`) in the site's root.

### `[[site.proxy]]`

Add one block under a site for each path that should go to an app.

| Key | Default | Meaning |
|---|---|---|
| `path` | required | Path prefix to forward, such as `/api`. It matches whole segments: `/api` matches `/api` and `/api/users`, not `/apix`. `/` forwards everything. |
| `upstreams` | required | Apps to forward to, as `host:port`, such as `["127.0.0.1:3000", "127.0.0.1:3001"]`. Plain HTTP/1.1 only. |
| `strip_prefix` | `false` | Remove `path` before forwarding, so `/api/users` reaches the app as `/users`. |

```toml
[[site]]
hosts = ["example.com"]
root = "www"

[[site.proxy]]
path = "/api"
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
```

When several prefixes match, the longest wins. Paths that match none are served from `root`, or get a 404 if the site has none.

The app sees the client's `Host` header, plus `X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto`. Requests take turns across `upstreams`. An upstream that refuses a connection or doesn't respond is skipped for 10 seconds. If a connection fails, the request is retried on the next upstream, since it was never sent. An upstream gets 5 seconds to accept a connection (otherwise `502 Bad Gateway`) and 60 seconds to start its response (otherwise `504 Gateway Timeout`). WebSockets and other `Upgrade` requests pass through.

### HTTPS

Set `[server] https` and give each site a `cert` and `key`. The server offers HTTP/2 and HTTP/1.1 over TLS, and picks each connection's certificate from the hostname the client sends (SNI). A client that sends an unknown name, or none, gets the default site's certificate.

A site without cert files gets a self-signed certificate for its `localhost` and `*.localhost` names, plus `127.0.0.1` and `::1`. It's made fresh at every start and never saved, so browsers warn about it after each restart. A reload keeps it as long as the site's names stay the same. The warning is expected for local development. For public names, use [`[acme]`](#automatic-certificates-acme).

With both `http` and `https` set, a plain HTTP request for a hostname that has a certificate gets a `308 Permanent Redirect` to the same URL over HTTPS. ACME challenges under `/.well-known/acme-challenge/` are never redirected, and neither are hostnames without a certificate. Set `redirect_https = false` to serve a site over both.

### Automatic certificates (ACME)

Add an `[acme]` table, and every site without `cert` and `key` gets a certificate for its hostnames from Let's Encrypt, or another CA that speaks ACME. `localhost` names keep their self-signed certificate, and IP addresses are skipped. Each site gets one certificate that covers all its names.

```toml
[server]
http = "0.0.0.0:80"
https = "0.0.0.0:443"

[acme]
email = "you@example.com"

[[site]]
hosts = ["example.com", "www.example.com"]
root = "www"
```

| Key | Default | Meaning |
|---|---|---|
| `email` | none | Address where the CA can reach you about your account. |
| `directory` | `"production"` | `"production"` or `"staging"` for Let's Encrypt, or another CA's directory URL. Staging certificates aren't trusted by browsers, but its rate limits are far higher, so use it while testing. |
| `storage` | see below | Folder for the account key and certificates, resolved like `root`. |
| `ca_root` | none | PEM root certificate to trust for the CA's own HTTPS instead of the system's, for a private CA such as step-ca. |

`[acme]` needs `[server] https`. The CA has to reach this server at each hostname: on port 80 for the HTTP-01 challenge, used when `[server] http` is set, or on port 443 for TLS-ALPN-01. If an attempt fails, the next one uses the other challenge. Retries wait 2 minutes, then 6, 18 and so on, up to 12 hours, and each failure is logged with the CA's reason. On Linux, listening on ports below 1024 needs root or the `CAP_NET_BIND_SERVICE` capability, for example `sudo setcap cap_net_bind_service=+ep target/release/webx4r`, or `AmbientCapabilities=CAP_NET_BIND_SERVICE` in a systemd unit.

Certificates are renewed when a third of their lifetime is left, which is 30 days before expiry for Let's Encrypt's 90-day certificates. They're saved under `$XDG_STATE_HOME/webx4r/<id>/acme` on Unix (`~/.local/state/…` when that variable isn't set) and `%LOCALAPPDATA%\webx4r\<id>\acme` on Windows, named after the config's folder. The server logs the location at startup. Keys are readable only by their owner, and saved certificates are served right away after a restart.

Registering an account accepts the CA's terms of service, which for Let's Encrypt is its [Subscriber Agreement](https://letsencrypt.org/repository/).

### Reloading

Edit the config, then apply it without a restart:

```sh
./target/release/webx4r reload --config mysite/webx4r.toml
```

On Unix, `kill -HUP <pid>` (or systemd's `ExecReload`) does the same. The new config is checked first. If anything is wrong, the error is printed and the server keeps its current config. Requests already in progress finish on the old config; every new request uses the new one, including on keep-alive connections that are already open.

Sites, proxy routes and certificates all reload, so renewed certificate files take effect too, and new hostnames get ACME certificates. Changes to `[server]`, `[acme]`, `[log]` and `[metrics]` need a restart.

`webx4r reload` reaches the server through a control socket that only its owner can use. On Unix it's `$XDG_RUNTIME_DIR/webx4r-<id>.sock`, named after the config's folder, or `webx4r.sock` next to the config when that variable isn't set. On Windows it's a named pipe. The server logs the location at startup. Set `[server] control` to choose it yourself.

### Logs

Without a `[log]` table, the server log goes to stderr and there's no access log. Add one to write both to files:

```toml
[log]
dir = "logs"
```

| Key | Default | Meaning |
|---|---|---|
| `dir` | required | Folder for the log files, resolved like `root`. It's created if missing. |
| `keep_days` | `14` | Days of each log to keep, today's included. Older files are deleted. |
| `access_format` | `"json"` | `"json"`, or `"combined"` for nginx's combined format. |

Each log starts a new file at midnight UTC: `server.<date>.log` and `access.<date>.log`. The server log is JSON, one object per line; set `WEBX4R_LOG` to change its level. At startup, stderr gets one line saying where the logs went. If the folder can't be written, the server doesn't start.

An access log entry is written when its response has been sent, so it records the bytes actually sent and the full time taken. JSON entries look like this, on one line:

```json
{"time":"2026-10-20T14:03:07.218Z","client":"203.0.113.7","host":"example.com","method":"GET","uri":"/api/users?page=2","protocol":"HTTP/2.0","status":200,"bytes":1234,"duration":0.0042,"referer":null,"user_agent":"curl/8.10.1","upstream":"127.0.0.1:3000"}
```

`duration` is in seconds, from the request's arrival to the response's last byte. `upstream` names the app that answered, or is `null` for static files.

### Metrics

Add a `[metrics]` table to serve Prometheus metrics at `/metrics` on an address of their own:

```toml
[metrics]
listen = "127.0.0.1:9100"
```

The endpoint has no authentication or TLS, so keep it on loopback or a private network. It's separate from the sites, so they never expose it, and scrapes aren't counted or logged. Metrics are in the OpenMetrics format and count from when the server starts; reloads don't reset them.

| Metric | Labels | Meaning |
|---|---|---|
| `webx4r_http_responses_total` | `site`, `code` | Responses by status class: `2xx`, `4xx` and so on. |
| `webx4r_http_response_duration_seconds` | `site` | Histogram of the time from a request's arrival to its response's last byte. |
| `webx4r_http_response_body_bytes_total` | `site` | Response body bytes sent. |
| `webx4r_connections_total` | `listener` | Client connections accepted on `http` or `https`. |
| `webx4r_connections_open` | `listener` | Client connections open now. |
| `webx4r_tls_handshake_failures_total` | `reason` | Failed TLS handshakes: `error`, or `timeout` after 10 seconds. |
| `webx4r_proxy_upstream_failures_total` | `upstream`, `kind` | Failed exchanges with an app: `connect`, `timeout` waiting for its response, or `error` after the request was sent. |
| `webx4r_acme_certificate_expiry_timestamp_seconds` | `name` | When each ACME certificate expires, as a Unix time. |
| `webx4r_acme_order_failures_total` | `name` | Failed attempts to get an ACME certificate. |
| `webx4r_config_reloads_total` | `result` | Reloads, `ok` or `error`. |

`site` is the site's first hostname, `default` for a default site with no `hosts`, or `none` for responses that reached no site, such as `421 Misdirected Request`. `name` is a certificate's first hostname.

## Development

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs all three on Linux and Windows.

The ACME tests need [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's test CA, so they're skipped by default. To run them, put `pebble` and `pebble-challtestsrv` 2.7 or later on your `PATH`, then run `cargo test --workspace -- --include-ignored`. CI runs them on Linux.

| Crate | Contents |
|---|---|
| `crates/webxlib` | HTTP building blocks: static files, MIME types, pages, response bodies |
| `crates/webxcore` | The server: config, listeners, TLS, ACME, routing, reverse proxy, access logs, metrics |
| `crates/webx4r` | The `webx4r` command |

## History

webx was first written in C++ by Skyler Nelson ([ThaPrintz](https://github.com/ThaPrintz)). His versions, ending with [webX3.0](https://github.com/ThaPrintz/webX3.0) and the [webxlib](https://github.com/ThaPrintz/webxlib) framework in 2020 and 2021, hosted his programming portfolio. webx4R is the fourth version, rewritten in Rust (the "R"). It keeps his crate names and several of his behaviors: the index fallback, the built-in pages, the MIME table and the look of the directory listings.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option. Unless you say otherwise, any contribution you submit is licensed the same way.
