//! ETag / Last-Modified validators and conditional request evaluation (RFC 9110 §13).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::{
    ETAG, HeaderName, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE,
    LAST_MODIFIED,
};
use http::{HeaderMap, HeaderValue};

/// Fingerprints of one version of a file; absent when the filesystem has no modification time.
pub(super) struct Validators {
    /// Strong ETag, quotes included: `"<mtime ns hex>-<size hex>"`.
    etag: Option<String>,
    /// Truncated to whole seconds, the precision of HTTP dates.
    last_modified: Option<SystemTime>,
}

/// Outcome of evaluating a request's preconditions.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Precondition {
    Proceed,
    NotModified,
    Failed,
}

impl Validators {
    pub(super) fn new(len: u64, modified: Option<SystemTime>) -> Self {
        let since_epoch = modified.and_then(|m| m.duration_since(UNIX_EPOCH).ok());
        Self {
            etag: since_epoch.map(|d| format!("\"{:x}-{len:x}\"", d.as_nanos())),
            last_modified: since_epoch.map(|d| UNIX_EPOCH + Duration::from_secs(d.as_secs())),
        }
    }

    pub(super) fn insert_into(&self, headers: &mut HeaderMap) {
        if let Some(etag) = &self.etag
            && let Ok(value) = HeaderValue::from_str(etag)
        {
            headers.insert(ETAG, value);
        }
        if let Some(time) = self.last_modified
            && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(time))
        {
            headers.insert(LAST_MODIFIED, value);
        }
    }
}

/// Evaluates preconditions for a GET or HEAD in the order RFC 9110 §13.2.2 requires.
pub(super) fn evaluate(headers: &HeaderMap, validators: &Validators) -> Precondition {
    let etag = validators.etag.as_deref();
    if headers.contains_key(IF_MATCH) {
        if !matches_any(headers, IF_MATCH, etag, true) {
            return Precondition::Failed;
        }
    } else if let (Some(since), Some(modified)) =
        (date(headers, IF_UNMODIFIED_SINCE), validators.last_modified)
        && modified > since
    {
        return Precondition::Failed;
    }

    if headers.contains_key(IF_NONE_MATCH) {
        if matches_any(headers, IF_NONE_MATCH, etag, false) {
            return Precondition::NotModified;
        }
    } else if let (Some(since), Some(modified)) =
        (date(headers, IF_MODIFIED_SINCE), validators.last_modified)
        && modified <= since
    {
        return Precondition::NotModified;
    }
    Precondition::Proceed
}

/// Whether a `Range` may be honored: true without `If-Range`, otherwise only if it names
/// this exact version. Weak tags never match, since parts must splice byte-for-byte.
pub(super) fn if_range_matches(headers: &HeaderMap, validators: &Validators) -> bool {
    let Some(value) = headers.get(IF_RANGE) else {
        return true;
    };
    let Ok(value) = value.to_str().map(str::trim) else {
        return false;
    };
    if value.starts_with('"') {
        validators.etag.as_deref() == Some(value)
    } else if value.starts_with("W/") {
        false
    } else {
        httpdate::parse_http_date(value).is_ok_and(|date| validators.last_modified == Some(date))
    }
}

/// `*` matches any existing file; `strong` rejects weak tags, as `If-Match` requires.
fn matches_any(headers: &HeaderMap, name: HeaderName, ours: Option<&str>, strong: bool) -> bool {
    for value in headers.get_all(name) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if value.trim() == "*" {
            return true;
        }
        let Some(ours) = ours else {
            continue;
        };
        if entity_tags(value).any(|tag| !(strong && tag.weak) && tag.opaque == ours) {
            return true;
        }
    }
    false
}

/// An entity tag from a request header; `opaque` keeps its quotes.
struct EntityTag<'a> {
    weak: bool,
    opaque: &'a str,
}

/// Parses a comma-separated entity-tag list, stopping at the first malformed item.
fn entity_tags(list: &str) -> impl Iterator<Item = EntityTag<'_>> {
    let mut rest = list;
    std::iter::from_fn(move || {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        let weak = rest.starts_with("W/");
        if weak {
            rest = &rest[2..];
        }
        if !rest.starts_with('"') {
            return None;
        }
        let end = rest[1..].find('"')? + 2;
        let (opaque, tail) = rest.split_at(end);
        rest = tail;
        Some(EntityTag { weak, opaque })
    })
}

fn date(headers: &HeaderMap, name: HeaderName) -> Option<SystemTime> {
    let value = headers.get(name)?.to_str().ok()?;
    httpdate::parse_http_date(value).ok()
}

#[cfg(test)]
mod tests {
    use super::Precondition::{Failed, NotModified, Proceed};
    use super::*;

    const MODIFIED_SECS: u64 = 1_700_000_000;

    fn validators() -> Validators {
        let modified = UNIX_EPOCH + Duration::new(MODIFIED_SECS, 500);
        Validators::new(42, Some(modified))
    }

    fn etag() -> String {
        validators().etag.unwrap()
    }

    fn http_date(secs: u64) -> String {
        httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(secs))
    }

    fn eval(pairs: &[(HeaderName, &str)]) -> Precondition {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(name, HeaderValue::from_str(value).unwrap());
        }
        evaluate(&headers, &validators())
    }

    #[test]
    fn etag_is_strong_and_built_from_mtime_and_size() {
        let nanos = u128::from(MODIFIED_SECS) * 1_000_000_000 + 500;
        assert_eq!(etag(), format!("\"{nanos:x}-2a\""));
    }

    #[test]
    fn last_modified_drops_subsecond_precision() {
        let expected = UNIX_EPOCH + Duration::from_secs(MODIFIED_SECS);
        assert_eq!(validators().last_modified, Some(expected));
    }

    #[test]
    fn no_validators_without_a_modification_time() {
        let v = Validators::new(42, None);
        assert!(v.etag.is_none() && v.last_modified.is_none());
    }

    #[test]
    fn parses_entity_tag_lists() {
        let tags: Vec<_> =
            entity_tags(r#" "a", W/"b",,"c,d" "#).map(|t| (t.weak, t.opaque)).collect();
        let expected = [(false, "\"a\""), (true, "\"b\""), (false, "\"c,d\"")];
        assert_eq!(tags, expected);
        assert_eq!(entity_tags(r#""a", bad, "c""#).count(), 1);
        assert_eq!(entity_tags(r#""unterminated"#).count(), 0);
    }

    #[test]
    fn no_conditions_proceeds() {
        assert_eq!(eval(&[]), Proceed);
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        let weak = format!("W/{}", etag());
        assert_eq!(eval(&[(IF_NONE_MATCH, &etag())]), NotModified);
        assert_eq!(eval(&[(IF_NONE_MATCH, &weak)]), NotModified);
        assert_eq!(eval(&[(IF_NONE_MATCH, "*")]), NotModified);
        assert_eq!(eval(&[(IF_NONE_MATCH, "\"other\"")]), Proceed);
    }

    #[test]
    fn if_match_uses_strong_comparison() {
        let weak = format!("W/{}", etag());
        assert_eq!(eval(&[(IF_MATCH, &etag())]), Proceed);
        assert_eq!(eval(&[(IF_MATCH, "*")]), Proceed);
        assert_eq!(eval(&[(IF_MATCH, &weak)]), Failed);
        assert_eq!(eval(&[(IF_MATCH, "\"other\"")]), Failed);
    }

    #[test]
    fn if_modified_since_compares_whole_seconds() {
        let same = http_date(MODIFIED_SECS);
        let earlier = http_date(MODIFIED_SECS - 1);
        assert_eq!(eval(&[(IF_MODIFIED_SINCE, &same)]), NotModified);
        assert_eq!(eval(&[(IF_MODIFIED_SINCE, &earlier)]), Proceed);
        assert_eq!(eval(&[(IF_MODIFIED_SINCE, "garbage")]), Proceed);
    }

    #[test]
    fn if_unmodified_since_fails_for_newer_files() {
        let earlier = http_date(MODIFIED_SECS - 1);
        let same = http_date(MODIFIED_SECS);
        assert_eq!(eval(&[(IF_UNMODIFIED_SINCE, &earlier)]), Failed);
        assert_eq!(eval(&[(IF_UNMODIFIED_SINCE, &same)]), Proceed);
    }

    #[test]
    fn if_range_needs_this_exact_version() {
        let range_if = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(IF_RANGE, HeaderValue::from_str(value).unwrap());
            if_range_matches(&headers, &validators())
        };
        assert!(if_range_matches(&HeaderMap::new(), &validators()));
        assert!(range_if(&etag()));
        assert!(range_if(&http_date(MODIFIED_SECS)));
        assert!(!range_if(&format!("W/{}", etag())));
        assert!(!range_if("\"other\""));
        assert!(!range_if(&http_date(MODIFIED_SECS + 1)));
        assert!(!range_if("garbage"));
    }

    #[test]
    fn etag_conditions_take_precedence_over_dates() {
        let later = http_date(MODIFIED_SECS + 60);
        let earlier = http_date(MODIFIED_SECS - 60);
        let not_modified_by_date = (IF_MODIFIED_SINCE, later.as_str());
        let unmodified_failure = (IF_UNMODIFIED_SINCE, earlier.as_str());
        let stale = eval(&[(IF_NONE_MATCH, "\"other\""), not_modified_by_date]);
        let matched = eval(&[(IF_MATCH, &etag()), unmodified_failure]);
        assert_eq!(stale, Proceed);
        assert_eq!(matched, Proceed);
    }
}
