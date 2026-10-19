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
        fs::create_dir_all(root.join("files/sub")).unwrap();
        fs::write(root.join("files/a.txt"), "a").unwrap();
        fs::write(root.join("files/.hidden"), "hidden").unwrap();
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

mod pages {
    use super::*;

    fn text(bytes: Bytes) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn root_without_index_shows_welcome_page() {
        let site = Site::new();
        fs::remove_file(site.dir.path().join("www/index.html")).unwrap();
        let res = site.get("/").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(header(&res, CONTENT_TYPE), "text/html; charset=utf-8");
        assert!(text(body(res).await).contains("webx4R is online"));
    }

    #[tokio::test]
    async fn subdirectory_without_index_is_not_welcomed() {
        let res = Site::new().get("/empty/").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(text(body(res).await).contains("404 Not Found"));
    }

    #[tokio::test]
    async fn errors_get_built_in_pages() {
        let site = Site::new();
        let res = site.get("/missing.html").await;
        assert_eq!(header(&res, CONTENT_TYPE), "text/html; charset=utf-8");
        assert!(text(body(res).await).contains("<h1>404 Not Found</h1>"));

        let res = site.get("/%2e%2e/x").await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(text(body(res).await).contains("<h1>400 Bad Request</h1>"));
    }

    #[tokio::test]
    async fn site_page_overrides_built_in() {
        let site = Site::new();
        fs::write(site.dir.path().join("www/404.html"), "custom 404").unwrap();
        let res = site.get("/missing.html").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(header(&res, CONTENT_LENGTH), "10");
        assert_eq!(body(res).await, "custom 404");
    }

    #[tokio::test]
    async fn head_error_has_length_but_no_body() {
        let site = Site::new();
        let res = site
            .request(Method::HEAD, "/missing.html", PathPolicy::default())
            .await;
        let expected = crate::pages::error(StatusCode::NOT_FOUND).len().to_string();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(header(&res, CONTENT_LENGTH), expected);
        assert!(body(res).await.is_empty());
    }

    #[tokio::test]
    async fn method_not_allowed_keeps_allow_header() {
        let site = Site::new();
        let policy = PathPolicy::default();
        let res = site.request(Method::DELETE, "/", policy).await;
        assert_eq!(header(&res, ALLOW), "GET, HEAD");
        assert!(text(body(res).await).contains("405 Method Not Allowed"));
    }
}

mod listings {
    use super::*;

    const LISTING: PathPolicy = PathPolicy {
        allow_dotfiles: false,
        symlinks: Symlinks::InsideRoot,
        directory_listing: true,
    };

    async fn listing_of(site: &Site, uri: &str) -> String {
        let res = site.request(Method::GET, uri, LISTING).await;
        assert_eq!(res.status(), StatusCode::OK);
        String::from_utf8(body(res).await.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn off_by_default() {
        assert_eq!(Site::new().status("/files/").await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn lists_files_and_folders_but_not_dotfiles() {
        let html = listing_of(&Site::new(), "/files/").await;
        assert!(html.contains(r#"href="/files/a.txt""#));
        assert!(html.contains(r#"href="/files/sub/""#));
        assert!(!html.contains(".hidden"));
    }

    #[tokio::test]
    async fn index_html_still_wins() {
        let res = Site::new().request(Method::GET, "/docs/", LISTING).await;
        assert_eq!(body(res).await, "docs");
    }

    #[tokio::test]
    async fn root_lists_instead_of_welcome() {
        let site = Site::new();
        fs::remove_file(site.dir.path().join("www/index.html")).unwrap();
        let html = listing_of(&site, "/").await;
        assert!(html.contains("<title>Index of /</title>"));
        assert!(!html.contains("webx4R is online"));
        assert!(!html.contains(".env"));
    }
}

mod symlinks {
    use std::path::Path;

    use super::*;

    fn link_file(target: impl AsRef<Path>, link: impl AsRef<Path>) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    fn link_dir(target: impl AsRef<Path>, link: impl AsRef<Path>) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target, link).unwrap();
    }

    fn site_with_links() -> Site {
        let site = Site::new();
        let root = site.dir.path().join("www");
        let secret = site.dir.path().join("outside/secret.txt");
        let relative_secret = Path::new("..").join("outside/secret.txt");
        link_file("style.css", root.join("link-in.css"));
        link_file(root.join("style.css"), root.join("abs-in.css"));
        link_file(secret, root.join("link-out.txt"));
        link_file(relative_secret, root.join("rel-out.txt"));
        link_dir("docs", root.join("docs-link"));
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
        assert_eq!(site.status("/docs-link/").await, StatusCode::OK);
        assert_eq!(site.status("/link-out.txt").await, StatusCode::NOT_FOUND);
        assert_eq!(site.status("/rel-out.txt").await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn inside_root_refuses_absolute_targets() {
        let site = site_with_links();
        assert_eq!(site.status("/abs-in.css").await, StatusCode::NOT_FOUND);
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
        let dir_link = get_with(&site, "/docs-link/index.html", Symlinks::Deny).await;
        let plain = get_with(&site, "/docs/index.html", Symlinks::Deny).await;
        let root = get_with(&site, "/", Symlinks::Deny).await;
        assert_eq!(link.status(), StatusCode::NOT_FOUND);
        assert_eq!(dir_link.status(), StatusCode::NOT_FOUND);
        assert_eq!(plain.status(), StatusCode::OK);
        assert_eq!(root.status(), StatusCode::OK);
    }

    async fn root_listing(site: &Site, symlinks: Symlinks) -> String {
        fs::remove_file(site.dir.path().join("www/index.html")).unwrap();
        let policy = PathPolicy {
            symlinks,
            directory_listing: true,
            ..PathPolicy::default()
        };
        let res = site.request(Method::GET, "/", policy).await;
        String::from_utf8(body(res).await.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn listing_shows_only_reachable_links() {
        let html = root_listing(&site_with_links(), Symlinks::InsideRoot).await;
        assert!(html.contains(r#"href="/link-in.css""#));
        assert!(html.contains(r#"href="/docs-link/""#));
        assert!(!html.contains("link-out.txt"));
        assert!(!html.contains("rel-out.txt"));
        assert!(!html.contains("abs-in.css"));
    }

    #[tokio::test]
    async fn listing_hides_all_links_under_deny() {
        let html = root_listing(&site_with_links(), Symlinks::Deny).await;
        assert!(html.contains(r#"href="/style.css""#));
        assert!(!html.contains("link-in.css"));
        assert!(!html.contains("docs-link"));
    }

    #[tokio::test]
    async fn link_is_typed_by_its_own_name() {
        let res = site_with_links().get("/link-in.css").await;
        assert_eq!(header(&res, CONTENT_TYPE), "text/css; charset=utf-8");
    }
}
