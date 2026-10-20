# webx4R

A web server and app platform written in Rust. Today it serves static sites and proxies requests to apps written in any language. The plan is to run those apps itself next, then spread them across several machines.

## Status

Early development; there are no releases yet. What works now:

- Static files over HTTP/1.1 and HTTP/2
- HTTPS with a certificate per site, picked by hostname (SNI); `localhost` sites get a self-signed certificate automatically
- Several sites on one listener, picked by hostname
- Reverse proxy to apps by path prefix, with several upstreams per route, passive health checks, retries and WebSocket pass-through
- ETag and Last-Modified, with 304 Not Modified responses
- Range requests, including multiple ranges in one request
- Optional directory listings
- Built-in error pages that a site can replace with its own
- Config reload without downtime, with `webx4r reload` or SIGHUP on Unix
- Graceful shutdown on Ctrl-C, or SIGTERM on Unix

Automatic certificates (ACME) and metrics are not built yet. They make up the rest of the first milestone.

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

Logs go to stderr at the `info` level. Set `WEBX4R_LOG=debug` for more detail.

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

A site without cert files gets a self-signed certificate for its `localhost` and `*.localhost` names, plus `127.0.0.1` and `::1`. It's made fresh at every start and never saved, so browsers warn about it after each restart. A reload keeps it as long as the site's names stay the same. The warning is expected for local development.

### Reloading

Edit the config, then apply it without a restart:

```sh
./target/release/webx4r reload --config mysite/webx4r.toml
```

On Unix, `kill -HUP <pid>` (or systemd's `ExecReload`) does the same. The new config is checked first. If anything is wrong, the error is printed and the server keeps its current config. Requests already in progress finish on the old config; every new request uses the new one, including on keep-alive connections that are already open.

Sites, proxy routes and certificates all reload, so renewed certificate files take effect too. Changes to `[server]` need a restart.

`webx4r reload` reaches the server through a control socket that only its owner can use. On Unix it's `$XDG_RUNTIME_DIR/webx4r-<id>.sock`, named after the config's folder, or `webx4r.sock` next to the config when that variable isn't set. On Windows it's a named pipe. The server logs the location at startup. Set `[server] control` to choose it yourself.

## Development

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs all three on Linux and Windows.

| Crate | Contents |
|---|---|
| `crates/webxlib` | HTTP building blocks: static files, MIME types, pages, response bodies |
| `crates/webxcore` | The server: config, listeners, TLS, routing, reverse proxy |
| `crates/webx4r` | The `webx4r` command |

## History

webx was first written in C++ by Skyler Nelson ([ThaPrintz](https://github.com/ThaPrintz)). His versions, ending with [webX3.0](https://github.com/ThaPrintz/webX3.0) and the [webxlib](https://github.com/ThaPrintz/webxlib) framework in 2020 and 2021, hosted his programming portfolio. webx4R is the fourth version, rewritten in Rust (the "R"). It keeps his crate names and several of his behaviors: the index fallback, the built-in pages, the MIME table and the look of the directory listings.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option. Unless you say otherwise, any contribution you submit is licensed the same way.
