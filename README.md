# webx4R

A web server and app platform written in Rust. Today it serves static sites. The plan is to add a reverse proxy for apps written in any language, then run those apps itself, then spread them across several machines.

## Status

Early development; there are no releases yet. What works now:

- Static files over HTTP/1.1 and HTTP/2
- HTTPS with a certificate per site, picked by hostname (SNI); `localhost` sites get a self-signed certificate automatically
- Several sites on one listener, picked by hostname
- ETag and Last-Modified, with 304 Not Modified responses
- Range requests, including multiple ranges in one request
- Optional directory listings
- Built-in error pages that a site can replace with its own
- Graceful shutdown on Ctrl-C, or SIGTERM on Unix

The reverse proxy, config reload, automatic certificates (ACME) and metrics are not built yet. They make up the rest of the first milestone.

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

At least one of the two is required.

### `[[site]]`

Add one block per site.

| Key | Default | Meaning |
|---|---|---|
| `hosts` | `[]` | Hostnames the site answers to: lowercase ASCII, no port. |
| `root` | required | Folder to serve. A relative path is resolved from the config file's folder. |
| `default` | `false` | Serve requests whose hostname matches no other site. Only one site can be the default, and a site with no `hosts` must be. |
| `directory_listing` | `false` | List the contents of folders that have no `index.html`. |
| `allow_dotfiles` | `false` | Serve names that start with `.`. `/.well-known/` is always served. |
| `symlinks` | `"inside-root"` | `"inside-root"` follows relative links that stay inside `root`. `"follow"` follows any link. `"deny"` refuses all links. |
| `cert` | none | PEM certificate chain for HTTPS, resolved like `root`. Needs `key` and `[server] https`. |
| `key` | none | PEM private key for `cert`. |

A request for an unknown hostname gets `421 Misdirected Request` when no site is the default. Unknown keys are rejected at startup, so typos don't go unnoticed.

To replace a built-in error page, put a file named after the status code (`404.html`, `500.html`) in the site's root.

### HTTPS

Set `[server] https` and give each site a `cert` and `key`. The server offers HTTP/2 and HTTP/1.1 over TLS, and picks each connection's certificate from the hostname the client sends (SNI). A client that sends an unknown name, or none, gets the default site's certificate.

A site without cert files gets a self-signed certificate for its `localhost` and `*.localhost` names, plus `127.0.0.1` and `::1`. It's made fresh at every start and never saved, so browsers warn about it each time. That's expected for local development.

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
| `crates/webxcore` | The server: config, listeners, TLS, routing |
| `crates/webx4r` | The `webx4r` command |

## History

webx was first written in C++ by Skyler Nelson ([ThaPrintz](https://github.com/ThaPrintz)). His versions, ending with [webX3.0](https://github.com/ThaPrintz/webX3.0) and the [webxlib](https://github.com/ThaPrintz/webxlib) framework in 2020 and 2021, hosted his programming portfolio. webx4R is the fourth version, rewritten in Rust (the "R"). It keeps his crate names and several of his behaviors: the index fallback, the built-in pages, the MIME table and the look of the directory listings.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option. Unless you say otherwise, any contribution you submit is licensed the same way.
