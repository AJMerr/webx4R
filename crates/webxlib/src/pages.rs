//! Built-in HTML pages, ported from the original webxlib's `defaults.h`.
//!
//! Pages are built only from fixed strings; nothing from the request is echoed back.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};

use crate::body::Body;

/// Shown at a site's root when it has no `index.html`.
pub fn welcome() -> Bytes {
    render("webx4R is online", "add an index.html to this site's root to replace this page")
}

/// A complete response carrying the default page for `code`.
pub fn error_response(code: StatusCode) -> Response<Body> {
    let page = error(code);
    let len = page.len();
    let mut res = Response::new(Body::bytes(page));
    *res.status_mut() = code;
    let headers = res.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    res
}

/// The default page for an error status.
pub fn error(code: StatusCode) -> Bytes {
    let title = format!("{} {}", code.as_u16(), code.canonical_reason().unwrap_or("Error"));
    render(&title, message(code))
}

fn message(code: StatusCode) -> &'static str {
    match code {
        StatusCode::BAD_REQUEST => "the server cannot respond due to a client error",
        StatusCode::UNAUTHORIZED => "the target resource lacks valid authentication credentials",
        StatusCode::FORBIDDEN => "you don't have permission to access this resource",
        StatusCode::NOT_FOUND => "the server can't find the requested resource",
        StatusCode::METHOD_NOT_ALLOWED => {
            "the request method is recognized by the server, but not supported by the target resource"
        }
        StatusCode::PRECONDITION_FAILED => "a condition in the request was not met",
        StatusCode::RANGE_NOT_SATISFIABLE => "the requested range is outside the file",
        StatusCode::MISDIRECTED_REQUEST => "this server has no site for the requested hostname",
        StatusCode::INTERNAL_SERVER_ERROR => "the server encountered an unexpected error",
        StatusCode::BAD_GATEWAY => "the server got an invalid response from an upstream server",
        StatusCode::SERVICE_UNAVAILABLE => "the server is temporarily unable to handle the request",
        StatusCode::GATEWAY_TIMEOUT => "an upstream server didn't respond in time",
        _ if code.is_client_error() => "the request could not be completed",
        _ => "the server could not complete the request",
    }
}

fn render(title: &str, message: &str) -> Bytes {
    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head><meta charset=\"utf-8\"><title>{title}</title></head>\n\
         <body style=\"text-align:center;font-family:sans-serif\">\n\
         <h1>{title}</h1>\n\
         <p>{message}</p>\n\
         <p><small>powered by webx4R</small></p>\n\
         </body>\n\
         </html>\n"
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(page: Bytes) -> String {
        String::from_utf8(page.to_vec()).unwrap()
    }

    #[test]
    fn error_page_has_status_message_and_footer() {
        let page = text(error(StatusCode::NOT_FOUND));
        assert!(page.contains("<title>404 Not Found</title>"));
        assert!(page.contains("<h1>404 Not Found</h1>"));
        assert!(page.contains("the server can't find the requested resource"));
        assert!(page.contains("powered by webx4R"));
    }

    #[test]
    fn statuses_without_a_message_use_a_generic_one() {
        let page = text(error(StatusCode::IM_A_TEAPOT));
        assert!(page.contains("<h1>418 I'm a teapot</h1>"));
        assert!(page.contains("the request could not be completed"));
    }

    #[test]
    fn welcome_page() {
        let page = text(welcome());
        assert!(page.contains("<h1>webx4R is online</h1>"));
        assert!(page.starts_with("<!DOCTYPE html>"));
    }
}
