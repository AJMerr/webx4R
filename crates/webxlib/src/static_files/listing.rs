//! Directory listing page, styled after the original webxlib's Bootstrap listing.

use std::path::Path;

use bytes::Bytes;
use percent_encoding::utf8_percent_encode;

use super::SEGMENT;

const BOOTSTRAP: &str = "https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css";
/// Subresource Integrity hash of the stylesheet; browsers refuse a modified copy.
const BOOTSTRAP_SRI: &str =
    "sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N";

pub(super) struct Entry {
    pub(super) name: String,
    pub(super) is_dir: bool,
}

/// Renders the listing for `relative` (the directory's path below the site root).
pub(super) fn render(relative: &Path, mut entries: Vec<Entry>) -> Bytes {
    entries.sort_by_cached_key(|e| (!e.is_dir, e.name.to_lowercase()));

    let mut href_base = String::from("/");
    let mut display = String::from("/");
    for segment in relative.iter() {
        let segment = segment.to_string_lossy();
        href_base.extend(utf8_percent_encode(&segment, SEGMENT));
        href_base.push('/');
        display.push_str(&segment);
        display.push('/');
    }
    let title = escape(&display);

    let mut page = format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Index of {title}</title>\n\
         <link rel=\"stylesheet\" href=\"{BOOTSTRAP}\" integrity=\"{BOOTSTRAP_SRI}\" crossorigin=\"anonymous\">\n\
         </head>\n\
         <body class=\"bg-dark\">\n\
         <div class=\"container py-5\">\n\
         <div class=\"row justify-content-center\">\n\
         <div class=\"col-lg-8 text-center\">\n\
         <h1 class=\"text-white font-weight-bold\">{title}</h1>\n\
         <hr class=\"my-4\">\n\
         </div>\n\
         <div class=\"col-lg-8 align-self-baseline\">\n"
    );
    if !relative.as_os_str().is_empty() {
        push_entry(&mut page, "../", "../");
    }
    for entry in &entries {
        let slash = if entry.is_dir { "/" } else { "" };
        let encoded: String = utf8_percent_encode(&entry.name, SEGMENT).collect();
        let href = format!("{href_base}{encoded}{slash}");
        let text = format!("{display}{}{slash}", entry.name);
        push_entry(&mut page, &escape(&href), &escape(&text));
    }
    page.push_str(
        "<p class=\"text-center text-white-50\"><small>powered by webx4R</small></p>\n\
         </div>\n\
         </div>\n\
         </div>\n\
         </body>\n\
         </html>\n",
    );
    page.into()
}

/// `href` and `text` must already be HTML-escaped.
fn push_entry(page: &mut String, href: &str, text: &str) {
    page.push_str("<div class=\"alert alert-info\" role=\"alert\"><a href=\"");
    page.push_str(href);
    page.push_str("\" class=\"alert-link\">");
    page.push_str(text);
    page.push_str("</a></div>\n");
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, is_dir: bool) -> Entry {
        Entry {
            name: name.to_owned(),
            is_dir,
        }
    }

    fn page(relative: &str, entries: Vec<Entry>) -> String {
        String::from_utf8(render(Path::new(relative), entries).to_vec()).unwrap()
    }

    #[test]
    fn entries_link_to_their_full_paths() {
        let entries = vec![entry("guide.pdf", false), entry("images", true)];
        let html = page("docs", entries);
        assert!(html.contains("<title>Index of /docs/</title>"));
        assert!(html.contains(r#"href="/docs/guide.pdf" class="alert-link">/docs/guide.pdf</a>"#));
        assert!(html.contains(r#"href="/docs/images/" class="alert-link">/docs/images/</a>"#));
    }

    #[test]
    fn folders_come_first_then_names_ignore_case() {
        let mut entries = vec![entry("b.txt", false), entry("Zed", true)];
        entries.push(entry("A.txt", false));
        let html = page("", entries);
        let zed = html.find("/Zed/").unwrap();
        let a = html.find("/A.txt").unwrap();
        let b = html.find("/b.txt").unwrap();
        assert!(zed < a && a < b);
    }

    #[test]
    fn parent_link_everywhere_but_the_root() {
        assert!(page("docs", vec![]).contains(r#"<a href="../""#));
        assert!(!page("", vec![]).contains(r#"<a href="../""#));
    }

    #[test]
    fn names_are_escaped_in_text_and_links() {
        let xss = "<img src=x onerror=alert(1)>.html";
        let html = page("", vec![entry(xss, false), entry("a&b \"c\".txt", false)]);
        assert!(!html.contains("<img"));
        assert!(html.contains(r#"href="/%3Cimg%20src=x%20onerror=alert(1)%3E.html""#));
        assert!(html.contains("/&lt;img src=x onerror=alert(1)&gt;.html</a>"));
        assert!(html.contains(r#"href="/a&amp;b%20%22c%22.txt""#));
        assert!(html.contains("/a&amp;b &quot;c&quot;.txt</a>"));
    }

    #[test]
    fn stylesheet_is_pinned_with_integrity() {
        let html = page("", vec![]);
        assert!(html.contains(BOOTSTRAP));
        assert!(html.contains(&format!("integrity=\"{BOOTSTRAP_SRI}\"")));
    }
}
