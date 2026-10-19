//! File extension → `Content-Type` lookup.
//!
//! Lookup order: web overrides, then mime_guess, then legacy types from the original webxlib.
//! Unknown or missing extensions fall back to `application/octet-stream`, as in the original.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::path::Path;

mod legacy;

/// Returned for unknown or missing extensions.
pub const OCTET_STREAM: &str = "application/octet-stream";

/// Types where mime_guess 2.0.5 is outdated or wrong for browsers.
const OVERRIDES: &[(&str, &str)] = &[
    ("m4a", "audio/mp4"),
    ("map", "application/json"),
    ("mjs", "text/javascript"),
    ("otf", "font/otf"),
    ("woff", "font/woff"),
];

/// Returns the MIME type for `path`, without parameters.
pub fn mime_type(path: &Path) -> &'static str {
    path.extension().and_then(|ext| ext.to_str()).and_then(lookup).unwrap_or(OCTET_STREAM)
}

/// Returns the `Content-Type` header value for `path`; `text/*` types get `charset=utf-8`.
pub fn content_type(path: &Path) -> Cow<'static, str> {
    let mime = mime_type(path);
    if mime.starts_with("text/") {
        Cow::Owned(format!("{mime}; charset=utf-8"))
    } else {
        Cow::Borrowed(mime)
    }
}

fn lookup(ext: &str) -> Option<&'static str> {
    if let Some(&(_, mime)) = OVERRIDES.iter().find(|(e, _)| e.eq_ignore_ascii_case(ext)) {
        return Some(mime);
    }
    if let Some(mime) = mime_guess::from_ext(ext).first_raw() {
        return Some(mime);
    }
    legacy::TYPES
        .binary_search_by(|(e, _)| cmp_ignore_ascii_case(e, ext))
        .ok()
        .map(|i| legacy::TYPES[i].1)
}

fn cmp_ignore_ascii_case(a: &str, b: &str) -> Ordering {
    a.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mime(name: &str) -> &'static str {
        mime_type(Path::new(name))
    }

    #[test]
    fn overrides_win_over_mime_guess() {
        assert_eq!(mime("app.mjs"), "text/javascript");
        assert_eq!(mime("font.woff"), "font/woff");
        assert_eq!(mime("font.otf"), "font/otf");
        assert_eq!(mime("app.js.map"), "application/json");
        assert_eq!(mime("song.m4a"), "audio/mp4");
    }

    #[test]
    fn common_web_types() {
        assert_eq!(mime("index.html"), "text/html");
        assert_eq!(mime("style.css"), "text/css");
        assert_eq!(mime("app.js"), "text/javascript");
        assert_eq!(mime("data.json"), "application/json");
        assert_eq!(mime("logo.svg"), "image/svg+xml");
        assert_eq!(mime("module.wasm"), "application/wasm");
        assert_eq!(mime("photo.jpg"), "image/jpeg");
        assert_eq!(mime("song.mp3"), "audio/mpeg");
        assert_eq!(mime("font.woff2"), "font/woff2");
    }

    #[test]
    fn legacy_types_fill_gaps() {
        assert_eq!(mime("events.event-stream"), "text/event-stream");
        assert_eq!(mime("doc.wp5"), "application/wordperfect6.0");
        assert_eq!(mime("archive.gzip"), "application/gzip");
        assert_eq!(mime("module.pyc"), "application/x-python-code");
    }

    #[test]
    fn lookup_ignores_case() {
        assert_eq!(mime("INDEX.HTML"), "text/html");
        assert_eq!(mime("Song.M4A"), "audio/mp4");
        assert_eq!(mime("DOC.WP5"), "application/wordperfect6.0");
    }

    #[test]
    fn unknown_or_missing_extension_falls_back() {
        assert_eq!(mime("file.nosuchext"), OCTET_STREAM);
        assert_eq!(mime("README"), OCTET_STREAM);
        assert_eq!(mime("program.o"), OCTET_STREAM);
    }

    #[test]
    fn text_types_get_utf8_charset() {
        assert_eq!(content_type(Path::new("a.html")), "text/html; charset=utf-8");
        assert_eq!(content_type(Path::new("a.png")), "image/png");
    }

    #[test]
    fn legacy_table_is_sorted_and_unique() {
        for pair in legacy::TYPES.windows(2) {
            assert_eq!(
                cmp_ignore_ascii_case(pair[0].0, pair[1].0),
                Ordering::Less,
                "{} must sort before {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn legacy_table_only_covers_gaps() {
        for (ext, _) in legacy::TYPES {
            assert!(
                mime_guess::from_ext(ext).first_raw().is_none(),
                "{ext} is already known to mime_guess"
            );
        }
    }
}
