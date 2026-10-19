//! `Range` requests (RFC 9110 §14): parsing, merging, and `multipart/byteranges` bodies.

use std::collections::VecDeque;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, SeekFrom};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// A header with more ranges than this is ignored and the full file is sent.
pub(super) const MAX_RANGES: usize = 16;

const CHUNK: u64 = 64 * 1024;

/// An inclusive byte range within a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ByteRange {
    pub(super) start: u64,
    pub(super) end: u64,
}

impl ByteRange {
    pub(super) fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    pub(super) fn content_range(&self, total: u64) -> String {
        format!("bytes {}-{}/{total}", self.start, self.end)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RangePlan {
    /// Ignore the header and send the whole file.
    Full,
    /// Sorted, non-overlapping ranges.
    Partial(Vec<ByteRange>),
    Unsatisfiable,
}

/// Plans the response to a `Range` header for a file of `len` bytes.
/// Malformed or unsupported headers are ignored, as RFC 9110 allows.
pub(super) fn plan(header: &str, len: u64) -> RangePlan {
    let Some((unit, set)) = header.split_once('=') else {
        return RangePlan::Full;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return RangePlan::Full;
    }
    let specs: Vec<&str> = set.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if specs.is_empty() || specs.len() > MAX_RANGES {
        return RangePlan::Full;
    }

    let mut ranges = Vec::with_capacity(specs.len());
    for spec in specs {
        let Some((first, last)) = spec.split_once('-') else {
            return RangePlan::Full;
        };
        let (first, last) = (first.trim(), last.trim());
        let range = match (digits(first), digits(last)) {
            // `-N` is the last N bytes.
            (None, Some(suffix)) if first.is_empty() => {
                if suffix == 0 || len == 0 {
                    continue;
                }
                ByteRange { start: len.saturating_sub(suffix), end: len - 1 }
            }
            (Some(start), None) if last.is_empty() => ByteRange { start, end: u64::MAX },
            (Some(start), Some(end)) if start <= end => ByteRange { start, end },
            _ => return RangePlan::Full,
        };
        if range.start >= len {
            continue;
        }
        ranges.push(ByteRange { end: range.end.min(len - 1), ..range });
    }
    if ranges.is_empty() { RangePlan::Unsatisfiable } else { RangePlan::Partial(merge(ranges)) }
}

/// Digits only: `str::parse` would also accept a leading `+`.
fn digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Sorts and coalesces overlapping or adjacent ranges.
fn merge(mut ranges: Vec<ByteRange>) -> Vec<ByteRange> {
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<ByteRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(prev) if range.start <= prev.end.saturating_add(1) => {
                prev.end = prev.end.max(range.end);
            }
            _ => merged.push(range),
        }
    }
    merged
}

/// A `multipart/byteranges` body for `ranges` of `file`: its `Content-Type`, exact length,
/// and a stream that reads each range from disk as it goes.
pub(super) fn multipart(
    file: File,
    part_type: &str,
    ranges: &[ByteRange],
    total: u64,
) -> (String, u64, impl Stream<Item = io::Result<Bytes>> + Send + use<>) {
    let boundary = boundary();
    let mut pieces = VecDeque::with_capacity(ranges.len() * 2 + 1);
    let mut len = 0;
    for range in ranges {
        let content_range = range.content_range(total);
        let head = format!(
            "\r\n--{boundary}\r\nContent-Type: {part_type}\r\nContent-Range: {content_range}\r\n\r\n"
        );
        len += head.len() as u64 + range.len();
        pieces.push_back(Piece::Bytes(head.into()));
        pieces.push_back(Piece::File { start: range.start, len: range.len() });
    }
    let tail = format!("\r\n--{boundary}--\r\n");
    len += tail.len() as u64;
    pieces.push_back(Piece::Bytes(tail.into()));

    let reader = Reader { file, pieces, left: 0 };
    let stream = futures_util::stream::unfold(Some(reader), |state| async move {
        let mut reader = state?;
        match reader.next().await {
            Ok(Some(chunk)) => Some((Ok(chunk), Some(reader))),
            Ok(None) => None,
            Err(e) => Some((Err(e), None)),
        }
    });
    (format!("multipart/byteranges; boundary={boundary}"), len, stream)
}

/// Random so it can't match file content by accident; std seeds `RandomState` per process.
fn boundary() -> String {
    let random = || RandomState::new().hash_one(0u8);
    format!("{:016x}{:016x}", random(), random())
}

enum Piece {
    Bytes(Bytes),
    File { start: u64, len: u64 },
}

struct Reader {
    file: File,
    pieces: VecDeque<Piece>,
    /// Bytes still to read from the current file range.
    left: u64,
}

impl Reader {
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            if self.left > 0 {
                let mut buf = BytesMut::zeroed(self.left.min(CHUNK) as usize);
                let read = self.file.read(&mut buf).await?;
                if read == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                buf.truncate(read);
                self.left -= read as u64;
                return Ok(Some(buf.freeze()));
            }
            match self.pieces.pop_front() {
                None => return Ok(None),
                Some(Piece::Bytes(bytes)) => return Ok(Some(bytes)),
                Some(Piece::File { start, len }) => {
                    self.file.seek(SeekFrom::Start(start)).await?;
                    self.left = len;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RangePlan::{Full, Partial, Unsatisfiable};
    use super::*;

    fn r(start: u64, end: u64) -> ByteRange {
        ByteRange { start, end }
    }

    #[test]
    fn single_ranges() {
        assert_eq!(plan("bytes=0-99", 1000), Partial(vec![r(0, 99)]));
        assert_eq!(plan("bytes=500-", 1000), Partial(vec![r(500, 999)]));
        assert_eq!(plan("bytes=-100", 1000), Partial(vec![r(900, 999)]));
        assert_eq!(plan("BYTES = 0-0", 1000), Partial(vec![r(0, 0)]));
    }

    #[test]
    fn ranges_are_clamped_to_the_file() {
        assert_eq!(plan("bytes=900-5000", 1000), Partial(vec![r(900, 999)]));
        assert_eq!(plan("bytes=-5000", 1000), Partial(vec![r(0, 999)]));
    }

    #[test]
    fn ranges_past_the_end_are_unsatisfiable() {
        assert_eq!(plan("bytes=1000-", 1000), Unsatisfiable);
        assert_eq!(plan("bytes=-0", 1000), Unsatisfiable);
        assert_eq!(plan("bytes=0-", 0), Unsatisfiable);
        assert_eq!(plan("bytes=2000-3000, 0-9", 1000), Partial(vec![r(0, 9)]));
    }

    #[test]
    fn malformed_headers_are_ignored() {
        for header in ["bytes=abc", "bytes=5-2", "items=0-1", "bytes=+5-9", "bytes=", "0-1"] {
            assert_eq!(plan(header, 1000), Full, "{header}");
        }
        assert_eq!(plan("bytes=0-99999999999999999999999", 1000), Full);
    }

    #[test]
    fn too_many_ranges_are_ignored() {
        let many: Vec<String> = (0..=MAX_RANGES).map(|i| format!("{i}-{i}")).collect();
        assert_eq!(plan(&format!("bytes={}", many.join(",")), 1000), Full);
    }

    #[test]
    fn overlapping_and_adjacent_ranges_merge() {
        assert_eq!(plan("bytes=50-149,0-99", 1000), Partial(vec![r(0, 149)]));
        assert_eq!(plan("bytes=0-9,10-19", 1000), Partial(vec![r(0, 19)]));
        assert_eq!(plan("bytes=0-9,20-29", 1000), Partial(vec![r(0, 9), r(20, 29)]));
    }

    #[test]
    fn boundaries_differ() {
        assert_ne!(boundary(), boundary());
    }
}
