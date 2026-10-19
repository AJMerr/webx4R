//! Response body: empty, in-memory bytes, a file streamed from disk, or any stream of known length.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use http_body::{Frame, SizeHint};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, Take};
use tokio_util::io::ReaderStream;

/// Read size for file bodies; larger chunks mean fewer syscalls per response.
const FILE_CHUNK: usize = 64 * 1024;

/// An [`http_body::Body`] with an exact size known up front.
pub struct Body(Kind);

type BoxStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

enum Kind {
    Empty,
    Bytes(Option<Bytes>),
    File { stream: ReaderStream<Take<File>>, remaining: u64 },
    Stream { stream: BoxStream, remaining: u64 },
}

impl Body {
    pub fn empty() -> Self {
        Self(Kind::Empty)
    }

    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() { Self::empty() } else { Self(Kind::Bytes(Some(bytes))) }
    }

    /// Streams `len` bytes from the file's current position.
    pub fn file(file: File, len: u64) -> Self {
        if len == 0 {
            return Self::empty();
        }
        Self(Kind::File {
            stream: ReaderStream::with_capacity(file.take(len), FILE_CHUNK),
            remaining: len,
        })
    }

    /// Streams exactly `len` bytes from `stream`; yielding fewer or more is an error.
    pub fn stream(
        stream: impl Stream<Item = io::Result<Bytes>> + Send + 'static,
        len: u64,
    ) -> Self {
        Self(Kind::Stream { stream: Box::pin(stream), remaining: len })
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match &mut self.get_mut().0 {
            Kind::Empty => Poll::Ready(None),
            Kind::Bytes(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Kind::File { stream, remaining } => poll_sized(Pin::new(stream), remaining, cx),
            Kind::Stream { stream, remaining } => poll_sized(stream.as_mut(), remaining, cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Kind::Empty => true,
            Kind::Bytes(bytes) => bytes.is_none(),
            Kind::File { remaining, .. } | Kind::Stream { remaining, .. } => *remaining == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            Kind::Empty => SizeHint::with_exact(0),
            Kind::Bytes(bytes) => {
                SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64))
            }
            Kind::File { remaining, .. } | Kind::Stream { remaining, .. } => {
                SizeHint::with_exact(*remaining)
            }
        }
    }
}

/// Polls `stream` while holding it to exactly `remaining` bytes.
fn poll_sized<S: Stream<Item = io::Result<Bytes>> + ?Sized>(
    stream: Pin<&mut S>,
    remaining: &mut u64,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
    match stream.poll_next(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Some(Ok(chunk))) => match remaining.checked_sub(chunk.len() as u64) {
            Some(left) => {
                *remaining = left;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            None => {
                *remaining = 0;
                let e = io::Error::new(io::ErrorKind::InvalidData, "body longer than declared");
                Poll::Ready(Some(Err(e)))
            }
        },
        Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
        // The source shrank mid-response; fail rather than send fewer bytes than promised.
        Poll::Ready(None) if *remaining > 0 => {
            *remaining = 0;
            Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())))
        }
        Poll::Ready(None) => Poll::Ready(None),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use http_body::Body as _;
    use http_body_util::BodyExt;

    use super::*;

    async fn file_with(contents: &[u8]) -> (tempfile::NamedTempFile, File) {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(contents).unwrap();
        let file = File::open(tmp.path()).await.unwrap();
        (tmp, file)
    }

    #[tokio::test]
    async fn empty_body() {
        let body = Body::empty();
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.collect().await.unwrap().to_bytes().is_empty());
    }

    #[tokio::test]
    async fn bytes_body() {
        let body = Body::bytes("hello");
        assert_eq!(body.size_hint().exact(), Some(5));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "hello");
        assert!(Body::bytes("").is_end_stream());
    }

    #[tokio::test]
    async fn file_body_streams_whole_file() {
        let contents: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let (_tmp, file) = file_with(&contents).await;
        let body = Body::file(file, contents.len() as u64);
        assert_eq!(body.size_hint().exact(), Some(contents.len() as u64));
        assert_eq!(body.collect().await.unwrap().to_bytes(), contents);
    }

    #[tokio::test]
    async fn file_body_stops_at_len() {
        let (_tmp, file) = file_with(b"0123456789").await;
        let body = Body::file(file, 4);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "0123");
    }

    #[tokio::test]
    async fn file_shorter_than_len_is_an_error() {
        let (_tmp, file) = file_with(b"short").await;
        let err = Body::file(file, 100).collect().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    fn chunks(parts: &[&'static str]) -> impl Stream<Item = io::Result<Bytes>> + Send + use<> {
        let parts: Vec<_> = parts.iter().map(|p| Ok(Bytes::from_static(p.as_bytes()))).collect();
        futures_util::stream::iter(parts)
    }

    #[tokio::test]
    async fn stream_body_with_exact_length() {
        let body = Body::stream(chunks(&["ab", "cd"]), 4);
        assert_eq!(body.size_hint().exact(), Some(4));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "abcd");
    }

    #[tokio::test]
    async fn stream_shorter_than_len_is_an_error() {
        let err = Body::stream(chunks(&["ab"]), 4).collect().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn stream_longer_than_len_is_an_error() {
        let err = Body::stream(chunks(&["ab", "cd"]), 3).collect().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
