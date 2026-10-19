use std::fs;

use bytes::Bytes;
use http::header::{ALLOW, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, LOCATION};
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;

use super::*;

/// A site root plus a sibling `outside/` directory for symlink tests.
struct Site {
    dir: TempDir,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("www");
        for d in ["docs", "empty", "evil.com", "my dir", ".well-known"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::create_dir(dir.path().join("outside")).unwrap();
        fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
        fs::write(root.join("style.css"), "body{}").unwrap();
        fs::write(root.join("docs/index.html"), "docs").unwrap();
        fs::write(root.join(".env"), "SECRET").unwrap();
        fs::write(root.join(".well-known/security.txt"), "contact").unwrap();
        fs::write(dir.path().join("outside/secret.txt"), "outside").unwrap();
        Self { dir }
    }

    async fn request(&self, method: Method, uri: &str, policy: PathPolicy) -> Response<Body> {
        let server = StaticFiles::new(self.dir.path().join("www"), policy).unwrap();
        let req = Request::builder().method(method).uri(uri).body(()).unwrap();
        server.serve(&req).await
    }

    async fn get(&self, uri: &str) -> Response<Body> {
        self.request(Method::GET, uri, PathPolicy::default()).await
    }

    async fn status(&self, uri: &str) -> StatusCode {
        self.get(uri).await.status()
    }
}

async fn body(res: Response<Body>) -> Bytes {
    res.into_body().collect().await.unwrap().to_bytes()
}

fn header(res: &Response<Body>, name: HeaderName) -> &str {
    res.headers()[name].to_str().unwrap()
}

#[tokio::test]
async fn root_serves_index_html() {
    let res = Site::new().get("/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(header(&res, CONTENT_TYPE), "text/html; charset=utf-8");
    assert_eq!(header(&res, CONTENT_LENGTH), "13");
    assert_eq!(body(res).await, "<h1>home</h1>");
}

#[tokio::test]
async fn file_with_content_type() {
    let res = Site::new().get("/style.css").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(header(&res, CONTENT_TYPE), "text/css; charset=utf-8");
    assert_eq!(body(res).await, "body{}");
}

#[tokio::test]
async fn head_has_headers_but_no_body() {
    let site = Site::new();
    let res = site
        .request(Method::HEAD, "/style.css", PathPolicy::default())
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(header(&res, CONTENT_LENGTH), "6");
    assert!(body(res).await.is_empty());
}

#[tokio::test]
async fn directory_without_slash_redirects() {
    let site = Site::new();
    let res = site.get("/docs").await;
    assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(header(&res, LOCATION), "/docs/");
    let res = site.get("/docs?page=2").await;
    assert_eq!(header(&res, LOCATION), "/docs/?page=2");
    let res = site.get("/my%20dir").await;
    assert_eq!(header(&res, LOCATION), "/my%20dir/");
}

#[tokio::test]
async fn redirect_cannot_leave_the_site() {
    let res = Site::new().get("//evil.com").await;
    assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(header(&res, LOCATION), "/evil.com/");
}

#[tokio::test]
async fn directory_with_slash_serves_its_index() {
    let res = Site::new().get("/docs/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body(res).await, "docs");
}

#[tokio::test]
async fn directory_without_index_is_not_found() {
    assert_eq!(Site::new().status("/empty/").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_paths_are_not_found() {
    let site = Site::new();
    assert_eq!(site.status("/missing.html").await, StatusCode::NOT_FOUND);
    assert_eq!(site.status("/style.css/extra").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dotfiles_hidden_except_well_known() {
    let site = Site::new();
    assert_eq!(site.status("/.env").await, StatusCode::NOT_FOUND);
    let res = site.get("/.well-known/security.txt").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body(res).await, "contact");
}

#[tokio::test]
async fn escaping_the_root_is_a_bad_request() {
    let status = Site::new().status("/%2e%2e/outside/secret.txt").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn other_methods_are_not_allowed() {
    let site = Site::new();
    let res = site.request(Method::POST, "/", PathPolicy::default()).await;
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header(&res, ALLOW), "GET, HEAD");
}

#[cfg(unix)]
mod symlinks {
    use std::os::unix::fs::symlink;

    use super::*;

    fn site_with_links() -> Site {
        let site = Site::new();
        let root = site.dir.path().join("www");
        let outside = site.dir.path().join("outside/secret.txt");
        symlink(root.join("style.css"), root.join("link-in.css")).unwrap();
        symlink(outside, root.join("link-out.txt")).unwrap();
        site
    }

    async fn get_with(site: &Site, uri: &str, symlinks: Symlinks) -> Response<Body> {
        let policy = PathPolicy {
            symlinks,
            ..PathPolicy::default()
        };
        site.request(Method::GET, uri, policy).await
    }

    #[tokio::test]
    async fn inside_root_is_the_default() {
        let site = site_with_links();
        assert_eq!(site.status("/link-in.css").await, StatusCode::OK);
        assert_eq!(site.status("/link-out.txt").await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn follow_serves_any_target() {
        let site = site_with_links();
        let res = get_with(&site, "/link-out.txt", Symlinks::Follow).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body(res).await, "outside");
    }

    #[tokio::test]
    async fn deny_refuses_every_link() {
        let site = site_with_links();
        let link = get_with(&site, "/link-in.css", Symlinks::Deny).await;
        let plain = get_with(&site, "/style.css", Symlinks::Deny).await;
        assert_eq!(link.status(), StatusCode::NOT_FOUND);
        assert_eq!(plain.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn link_is_typed_by_its_own_name() {
        let res = site_with_links().get("/link-in.css").await;
        assert_eq!(header(&res, CONTENT_TYPE), "text/css; charset=utf-8");
    }
}
