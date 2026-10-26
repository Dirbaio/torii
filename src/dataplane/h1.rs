//! HTTP/1.x: request and response heads (parsed with httparse), message framing,
//! and the chunked coding.
//!
//! A parsed head is one exact-size copy of its bytes plus the offsets of its parts,
//! about 16 bytes per field, rather than a map of owned strings. torii forwards
//! heads with a few edits, so it mostly reads them and writes them back out.

use bytes::{Buf, Bytes, BytesMut};

use super::io::Outgoing;
use crate::route_table::HeaderLookup;

/// Most fields a request head may have (what torii always allowed; nginx has
/// none, but its head size limit bounds them).
pub const MAX_REQUEST_FIELDS: usize = 256;
/// Most fields of a backend's response head (T046: a backend's huge heads were
/// held for the stream's lifetime).
pub const MAX_RESPONSE_FIELDS: usize = 128;
/// Most bytes of a request head; larger ones get a 431.
pub const MAX_REQUEST_HEAD: usize = 64 * 1024;
/// Most bytes of a backend's response head; larger ones are a 502.
pub const MAX_RESPONSE_HEAD: usize = 64 * 1024;
/// Most bytes of a chunk-size line (with its extensions), and of all the trailer
/// fields of a chunked body.
const MAX_CHUNK_LINE: u32 = 4096;
const MAX_TRAILERS: u32 = 16 * 1024;

/// A byte range in a head's buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    start: u32,
    end: u32,
}

impl Span {
    fn of(base: &[u8], part: &[u8]) -> Span {
        let start = part.as_ptr() as usize - base.as_ptr() as usize;
        Span {
            start: start as u32,
            end: (start + part.len()) as u32,
        }
    }

    fn get(self, raw: &[u8]) -> &[u8] {
        &raw[self.start as usize..self.end as usize]
    }
}

/// One header field of a head.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    name: Span,
    value: Span,
}

/// The protocol a request came in on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
    /// HTTP/2: the head was built from the h2 crate's request, not parsed.
    Http2,
}

/// The fields of a head, over its raw bytes.
#[derive(Debug)]
pub struct Fields {
    raw: Box<[u8]>,
    fields: Vec<Field>,
}

impl Fields {
    /// Every field, in order, as (name, value).
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.fields
            .iter()
            .map(|f| (f.name.get(&self.raw), f.value.get(&self.raw)))
    }

    /// The values of the field `name`, compared without case.
    pub fn get_all<'a, 'n>(&'a self, name: &'n str) -> impl Iterator<Item = &'a [u8]> + use<'a, 'n> {
        self.iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v)
    }

    /// The first value of the field `name`.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.get_all(name).next()
    }

    /// The first value of the field `name`, if it is a string.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Whether the comma-separated values of the field `name` hold `token`,
    /// compared without case (`Connection: keep-alive, Upgrade`).
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .flat_map(|v| v.split(|&b| b == b','))
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
    }
}

impl HeaderLookup for Fields {
    fn any_value(&self, name: &str, f: &mut dyn FnMut(&str) -> bool) -> bool {
        self.get_all(name)
            .filter(|v| v.iter().all(|&b| b == b'\t' || (b' '..=b'~').contains(&b)))
            .filter_map(|v| std::str::from_utf8(v).ok())
            .any(f)
    }
}

/// A request head.
#[derive(Debug)]
pub struct RequestHead {
    pub fields: Fields,
    method: Span,
    target: Span,
    pub version: Version,
}

impl RequestHead {
    /// The method: a token, so ASCII.
    pub fn method(&self) -> &str {
        std::str::from_utf8(self.method.get(&self.fields.raw)).unwrap_or("")
    }

    /// The request target as received: origin-form or absolute-form for HTTP/1,
    /// the `:path` for HTTP/2.
    pub fn target(&self) -> &[u8] {
        self.target.get(&self.fields.raw)
    }

    /// Build the head of an HTTP/2 request: the method, the `:path`, and the fields
    /// (the authority goes in as a `host` field, which h2 never passes on itself).
    pub fn from_parts(method: &str, target: &[u8], fields: &[(&[u8], &[u8])]) -> RequestHead {
        let size = method.len() + target.len() + fields.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>();
        let mut raw = Vec::with_capacity(size);
        let mut spans = Vec::with_capacity(fields.len());
        let push = |raw: &mut Vec<u8>, part: &[u8]| {
            let start = raw.len() as u32;
            raw.extend_from_slice(part);
            Span {
                start,
                end: raw.len() as u32,
            }
        };
        let method = push(&mut raw, method.as_bytes());
        let target = push(&mut raw, target);
        for (name, value) in fields {
            let name = push(&mut raw, name);
            let value = push(&mut raw, value);
            spans.push(Field { name, value });
        }
        RequestHead {
            fields: Fields {
                raw: raw.into_boxed_slice(),
                fields: spans,
            },
            method,
            target,
            version: Version::Http2,
        }
    }
}

/// A response head from a backend.
#[derive(Debug)]
pub struct ResponseHead {
    pub fields: Fields,
    pub status: u16,
    reason: Span,
    pub version: Version,
}

impl ResponseHead {
    pub fn reason(&self) -> &[u8] {
        self.reason.get(&self.fields.raw)
    }
}

/// Why a head was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadError {
    /// Too many fields (431 for a request).
    TooManyFields,
    /// Not valid HTTP/1.x.
    Invalid,
}

/// Parse a complete request head (as found by [`HeadScan`]).
pub fn parse_request(head: &[u8]) -> Result<RequestHead, HeadError> {
    let raw: Box<[u8]> = head.into();
    let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_FIELDS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&raw) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(HeadError::Invalid),
        Err(httparse::Error::TooManyHeaders) => return Err(HeadError::TooManyFields),
        Err(_) => return Err(HeadError::Invalid),
    }
    let version = match req.version {
        Some(0) => Version::Http10,
        Some(1) => Version::Http11,
        _ => return Err(HeadError::Invalid),
    };
    let (Some(method), Some(target)) = (req.method, req.path) else {
        return Err(HeadError::Invalid);
    };
    let fields: Vec<Field> = req
        .headers
        .iter()
        .map(|h| Field {
            name: Span::of(&raw, h.name.as_bytes()),
            value: Span::of(&raw, h.value),
        })
        .collect();
    let method = Span::of(&raw, method.as_bytes());
    let target = Span::of(&raw, target.as_bytes());
    Ok(RequestHead {
        fields: Fields { raw, fields },
        method,
        target,
        version,
    })
}

/// Parse a complete response head (as found by [`HeadScan`]).
pub fn parse_response(head: &[u8]) -> Result<ResponseHead, HeadError> {
    let raw: Box<[u8]> = head.into();
    let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_FIELDS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&raw) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(HeadError::Invalid),
        Err(httparse::Error::TooManyHeaders) => return Err(HeadError::TooManyFields),
        Err(_) => return Err(HeadError::Invalid),
    }
    let version = match resp.version {
        Some(0) => Version::Http10,
        Some(1) => Version::Http11,
        _ => return Err(HeadError::Invalid),
    };
    let Some(status) = resp.code else {
        return Err(HeadError::Invalid);
    };
    let fields: Vec<Field> = resp
        .headers
        .iter()
        .map(|h| Field {
            name: Span::of(&raw, h.name.as_bytes()),
            value: Span::of(&raw, h.value),
        })
        .collect();
    let reason = resp.reason.map(|r| Span::of(&raw, r.as_bytes())).unwrap_or_default();
    Ok(ResponseHead {
        fields: Fields { raw, fields },
        status,
        reason,
        version,
    })
}

/// The scan for the end of an HTTP/1.x head, fed its bytes as they arrive: the
/// first empty line after the start line, as httparse finds it. Lines end in LF or
/// CRLF, and empty lines before the start line are skipped. Bytes httparse would
/// reject (a CR not followed by LF) never end the head here, so a scan never ends
/// early, and the parser rejects such a head when it gets it.
#[derive(Clone, Copy, Debug, Default)]
pub enum HeadScan {
    /// No start line yet.
    #[default]
    Start,
    /// Inside a line.
    Line,
    /// At the start of a line after the start line.
    LineStart,
    /// After a CR at the start of a line.
    LineStartCr,
}

impl HeadScan {
    /// Feed the next bytes of the head. Returns how many of them complete it, or
    /// None if the head goes on.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<usize> {
        for (i, &b) in bytes.iter().enumerate() {
            *self = match (*self, b) {
                (Self::Start, b'\r' | b'\n') => Self::Start,
                (Self::Line, b'\n') => Self::LineStart,
                (Self::LineStart, b'\r') => Self::LineStartCr,
                (Self::LineStart | Self::LineStartCr, b'\n') => return Some(i + 1),
                _ => Self::Line,
            };
        }
        None
    }
}

/// Reads a head into a connection's buffer: reads that grow the buffer by doubling
/// it at most (so a head trickled in many pieces still costs linear work), scanned
/// as they arrive, and parsed once when complete.
#[derive(Debug)]
pub struct HeadReader {
    scan: HeadScan,
    /// Bytes of the buffer already scanned.
    scanned: usize,
    /// The first read's size.
    first: usize,
    /// Most bytes the head may take.
    limit: usize,
}

/// What [`HeadReader::poll`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadEvent {
    /// The head is the first `n` bytes of the buffer.
    Complete(usize),
    /// EOF; `partial` if part of a head had arrived.
    Eof { partial: bool },
    /// No end within the limit.
    TooLarge,
}

impl HeadReader {
    pub fn new(first: usize, limit: usize) -> HeadReader {
        HeadReader {
            scan: HeadScan::default(),
            scanned: 0,
            first,
            limit,
        }
    }

    pub fn poll<S: tokio::io::AsyncRead + Unpin + ?Sized>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        io: &mut S,
        buf: &mut BytesMut,
    ) -> std::task::Poll<std::io::Result<HeadEvent>> {
        loop {
            let end = buf.len().min(self.limit);
            if end > self.scanned {
                if let Some(n) = self.scan.feed(&buf[self.scanned..end]) {
                    return std::task::Poll::Ready(Ok(HeadEvent::Complete(self.scanned + n)));
                }
                self.scanned = end;
            }
            if self.scanned >= self.limit {
                return std::task::Poll::Ready(Ok(HeadEvent::TooLarge));
            }
            let want = self.first.max(buf.len()).min(self.limit - buf.len()).max(1);
            let n = std::task::ready!(super::io::poll_read_lazy(io, cx, buf, want))?;
            if n == 0 {
                return std::task::Poll::Ready(Ok(HeadEvent::Eof {
                    partial: !buf.is_empty(),
                }));
            }
        }
    }
}

/// How a request body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestFraming {
    None,
    Length(u64),
    Chunked,
}

/// How a response body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseFraming {
    None,
    Length(u64),
    Chunked,
    /// Until the backend closes the connection.
    Eof,
}

/// Parse a Content-Length value: digits only, no sign or list.
fn parse_length(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 18 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// The framing of a downstream HTTP/1 request body, or the status to refuse it
/// with. Strict, so that no message can mean two things to torii and a backend
/// (request smuggling): Transfer-Encoding must be exactly `chunked`, never with a
/// Content-Length or on HTTP/1.0, and there is at most one Content-Length.
pub fn request_framing(head: &RequestHead) -> Result<RequestFraming, u16> {
    let f = &head.fields;
    let mut te = f.get_all("transfer-encoding").peekable();
    let mut cl = f.get_all("content-length");
    if te.peek().is_some() {
        if head.version == Version::Http10 || f.get("content-length").is_some() {
            return Err(400);
        }
        let mut codings = te.flat_map(|v| v.split(|&b| b == b',')).map(<[u8]>::trim_ascii);
        return match (codings.next(), codings.next()) {
            (Some(c), None) if c.eq_ignore_ascii_case(b"chunked") => Ok(RequestFraming::Chunked),
            _ => Err(501),
        };
    }
    match (cl.next(), cl.next()) {
        (None, _) => Ok(RequestFraming::None),
        (Some(v), None) => match parse_length(v) {
            Some(0) => Ok(RequestFraming::None),
            Some(n) => Ok(RequestFraming::Length(n)),
            None => Err(400),
        },
        (Some(_), Some(_)) => Err(400),
    }
}

/// The framing of a backend's response body (RFC 9112 §6.3), or None if it is
/// ambiguous (differing Content-Lengths).
pub fn response_framing(head: &ResponseHead, request_method: &str) -> Option<ResponseFraming> {
    if request_method.eq_ignore_ascii_case("HEAD") || head.status < 200 || head.status == 204 || head.status == 304 {
        return Some(ResponseFraming::None);
    }
    let f = &head.fields;
    if f.get("transfer-encoding").is_some() {
        let last = f
            .get_all("transfer-encoding")
            .flat_map(|v| v.split(|&b| b == b','))
            .map(<[u8]>::trim_ascii)
            .filter(|c| !c.is_empty())
            .last();
        return Some(match last {
            Some(c) if c.eq_ignore_ascii_case(b"chunked") => ResponseFraming::Chunked,
            _ => ResponseFraming::Eof,
        });
    }
    let mut length = None;
    for v in f.get_all("content-length").flat_map(|v| v.split(|&b| b == b',')) {
        let n = parse_length(v.trim_ascii())?;
        if length.is_some_and(|l| l != n) {
            return None;
        }
        length = Some(n);
    }
    Some(match length {
        Some(n) => ResponseFraming::Length(n),
        None => ResponseFraming::Eof,
    })
}

/// A malformed body.
#[derive(Debug)]
pub struct BodyError(pub &'static str);

/// Takes the data of a body out of a read buffer, as it arrives.
#[derive(Debug)]
pub enum Decoder {
    Length(u64),
    Chunked(Chunked),
    /// Until EOF.
    Eof,
    Done,
}

impl Decoder {
    pub fn for_request(framing: RequestFraming) -> Decoder {
        match framing {
            RequestFraming::None => Decoder::Done,
            RequestFraming::Length(n) => Decoder::Length(n),
            RequestFraming::Chunked => Decoder::Chunked(Chunked::default()),
        }
    }

    pub fn for_response(framing: ResponseFraming) -> Decoder {
        match framing {
            ResponseFraming::None | ResponseFraming::Length(0) => Decoder::Done,
            ResponseFraming::Length(n) => Decoder::Length(n),
            ResponseFraming::Chunked => Decoder::Chunked(Chunked::default()),
            ResponseFraming::Eof => Decoder::Eof,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Decoder::Done)
    }

    /// Take the next piece of body data (at most `max` bytes) out of `buf`,
    /// consuming any framing before it. `Ok(None)`: `buf` holds no more data (then
    /// read more, unless [`Decoder::is_done`]).
    pub fn decode(&mut self, buf: &mut BytesMut, max: usize) -> Result<Option<Bytes>, BodyError> {
        match self {
            Decoder::Done => Ok(None),
            Decoder::Length(n) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                let take = (*n).min(buf.len() as u64).min(max as u64) as usize;
                *n -= take as u64;
                if *n == 0 {
                    *self = Decoder::Done;
                }
                Ok(Some(buf.split_to(take).freeze()))
            }
            Decoder::Eof => {
                if buf.is_empty() {
                    return Ok(None);
                }
                let take = buf.len().min(max);
                Ok(Some(buf.split_to(take).freeze()))
            }
            Decoder::Chunked(c) => {
                let data = c.decode(buf, max)?;
                if c.is_done() {
                    *self = Decoder::Done;
                }
                Ok(data)
            }
        }
    }

    /// [`Decoder::decode`], gathering a small piece with the data right behind it
    /// in `buf` (up to `max` bytes) into one exact-size copy. A body of many small
    /// chunks then moves on in few writes and frames, and no small piece keeps the
    /// read buffer it came from alive.
    pub fn decode_gathered(&mut self, buf: &mut BytesMut, max: usize) -> Result<Option<Bytes>, BodyError> {
        let Some(first) = self.decode(buf, max)? else {
            return Ok(None);
        };
        if first.len() >= max / 4 {
            return Ok(Some(first));
        }
        let mut gathered = Vec::with_capacity((first.len() + buf.len()).min(max));
        gathered.extend_from_slice(&first);
        while gathered.len() < max {
            match self.decode(buf, max - gathered.len())? {
                Some(more) => gathered.extend_from_slice(&more),
                None => break,
            }
        }
        Ok(Some(Bytes::from(gathered)))
    }

    /// The connection reached EOF. Fine only for an EOF-delimited body.
    pub fn on_eof(&mut self) -> Result<(), BodyError> {
        match self {
            Decoder::Eof | Decoder::Done => {
                *self = Decoder::Done;
                Ok(())
            }
            _ => Err(BodyError("connection closed before the end of the body")),
        }
    }
}

/// The state of a chunked body (RFC 9112 §7.1), parsed strictly: lines end in
/// CRLF, sizes are hex digits, extensions and trailers are bounded and dropped.
#[derive(Debug, Default)]
pub struct Chunked {
    state: ChunkState,
    /// The size being read, or the data left in the current chunk.
    size: u64,
    /// Bytes of the current size line, and of all the trailers.
    line: u32,
    trailers: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ChunkState {
    /// Before the first hex digit of a size.
    #[default]
    SizeStart,
    Size,
    /// Whitespace after the size, before `;` or CR.
    SizeWs,
    /// A chunk extension, until CR.
    Ext,
    SizeLf,
    Data,
    DataCr,
    DataLf,
    /// At the start of a trailer line (or the final empty line).
    TrailerStart,
    TrailerLine,
    TrailerLf,
    EndLf,
    Done,
}

impl Chunked {
    fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    fn decode(&mut self, buf: &mut BytesMut, max: usize) -> Result<Option<Bytes>, BodyError> {
        use ChunkState::*;
        while !buf.is_empty() {
            if self.state == Data {
                let take = self.size.min(buf.len() as u64).min(max as u64) as usize;
                self.size -= take as u64;
                if self.size == 0 {
                    self.state = DataCr;
                }
                return Ok(Some(buf.split_to(take).freeze()));
            }
            let b = buf[0];
            buf.advance(1);
            self.state = match (self.state, b) {
                (SizeStart | Size, _) if b.is_ascii_hexdigit() => {
                    if self.size >> 60 != 0 {
                        return Err(BodyError("chunk size too large"));
                    }
                    self.size = (self.size << 4) | u64::from(char::from(b).to_digit(16).unwrap_or(0));
                    self.count_line()?;
                    Size
                }
                (Size | SizeWs, b' ' | b'\t') => SizeWs,
                (Size | SizeWs, b';') => Ext,
                (Size | SizeWs | Ext, b'\r') => SizeLf,
                (Ext, _) if b == b'\t' || (b >= b' ' && b != 0x7f) => {
                    self.count_line()?;
                    Ext
                }
                (SizeLf, b'\n') => {
                    self.line = 0;
                    if self.size == 0 { TrailerStart } else { Data }
                }
                (DataCr, b'\r') => DataLf,
                (DataLf, b'\n') => SizeStart,
                (TrailerStart, b'\r') => EndLf,
                (TrailerStart | TrailerLine, _) if b == b'\t' || (b >= b' ' && b != 0x7f) || b >= 0x80 => {
                    self.trailers += 1;
                    if self.trailers > MAX_TRAILERS {
                        return Err(BodyError("chunked trailers too large"));
                    }
                    TrailerLine
                }
                (TrailerLine, b'\r') => TrailerLf,
                (TrailerLf, b'\n') => TrailerStart,
                (EndLf, b'\n') => {
                    self.state = Done;
                    return Ok(None);
                }
                _ => return Err(BodyError("malformed chunked body")),
            };
        }
        Ok(None)
    }

    fn count_line(&mut self) -> Result<(), BodyError> {
        self.line += 1;
        if self.line > MAX_CHUNK_LINE {
            return Err(BodyError("chunk size line too long"));
        }
        Ok(())
    }
}

/// How torii frames a body it sends on HTTP/1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoder {
    /// As is: the head carries a Content-Length, or the body ends at close.
    Raw,
    Chunked,
}

impl Encoder {
    /// The write for one chunk of body data.
    pub fn frame(self, data: Bytes) -> Outgoing {
        match self {
            Encoder::Raw => Outgoing::new(&[], data, b""),
            Encoder::Chunked => {
                let mut line = [0u8; 20];
                let len = hex_line(data.len(), &mut line);
                Outgoing::new(&line[..len], data, b"\r\n")
            }
        }
    }

    /// The write that ends the body, if the framing has one.
    pub fn finish(self) -> Option<Outgoing> {
        match self {
            Encoder::Raw => None,
            Encoder::Chunked => Some(Outgoing::new(self.end(), Bytes::new(), b"")),
        }
    }

    /// Append one chunk of body data, framed, to `out` (a copy, for a write that
    /// carries a head too).
    pub fn append(self, out: &mut Vec<u8>, data: &[u8]) {
        if self == Encoder::Chunked {
            let mut line = [0u8; 20];
            let len = hex_line(data.len(), &mut line);
            out.extend_from_slice(&line[..len]);
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(data);
        }
    }

    /// The bytes that end the body: none, or the last chunk.
    pub fn end(self) -> &'static [u8] {
        match self {
            Encoder::Raw => b"",
            Encoder::Chunked => b"0\r\n\r\n",
        }
    }
}

/// Write `n` in hex followed by CRLF into `out`; returns the length.
fn hex_line(n: usize, out: &mut [u8; 20]) -> usize {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut out[..]);
    let _ = write!(cursor, "{n:x}\r\n");
    cursor.position() as usize
}

/// The reason phrase for a status torii answers itself.
pub fn reason(status: u16) -> &'static str {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_scan_finds_the_end_of_the_head() {
        let mut s = HeadScan::default();
        assert_eq!(s.feed(b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\nbody"), Some(29));
        let mut s = HeadScan::default();
        assert_eq!(s.feed(b"GET / HTTP/1.1\nHost: a\n"), None);
        assert_eq!(s.feed(b"\n"), Some(1));
        let mut s = HeadScan::default();
        assert_eq!(s.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r"), None);
        assert_eq!(s.feed(b"\n"), Some(1));
    }

    #[test]
    fn parses_a_request_head() {
        let h = parse_request(b"GET /a?b HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nx-a: 2\r\n\r\n").unwrap();
        assert_eq!(h.method(), "GET");
        assert_eq!(h.target(), b"/a?b");
        assert_eq!(h.version, Version::Http11);
        assert_eq!(h.fields.get_all("X-A").collect::<Vec<_>>(), vec![b"1", b"2"]);
        assert!(h.fields.any_value("x-a", &mut |v| v == "2"));
    }

    #[test]
    fn request_framing_is_strict() {
        let framing = |head: &str| request_framing(&parse_request(head.as_bytes()).unwrap());
        assert_eq!(
            framing("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
            Ok(RequestFraming::Length(5))
        );
        assert_eq!(
            framing("POST / HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n"),
            Ok(RequestFraming::Chunked)
        );
        assert_eq!(
            framing("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"),
            Err(400)
        );
        assert_eq!(framing("POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n"), Err(400));
        assert_eq!(framing("POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n"), Err(400));
        assert_eq!(
            framing("POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(400)
        );
        assert_eq!(
            framing("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
            Err(501)
        );
        assert_eq!(
            framing("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(400)
        );
    }

    fn decode_all(d: &mut Decoder, input: &[u8]) -> Result<Vec<u8>, BodyError> {
        let mut buf = BytesMut::from(input);
        let mut out = Vec::new();
        while let Some(data) = d.decode(&mut buf, 3)? {
            out.extend_from_slice(&data);
        }
        Ok(out)
    }

    #[test]
    fn decodes_chunked() {
        let mut d = Decoder::for_request(RequestFraming::Chunked);
        let out = decode_all(&mut d, b"5;ext=1\r\nhello\r\n0\r\nTrailer: x\r\n\r\nNEXT").unwrap();
        assert_eq!(out, b"hello");
        assert!(d.is_done());
        // Byte by byte.
        let mut d = Decoder::for_request(RequestFraming::Chunked);
        let mut out = Vec::new();
        for b in b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n" {
            out.extend(decode_all(&mut d, &[*b]).unwrap());
        }
        assert_eq!(out, b"abcde");
        assert!(d.is_done());
    }

    #[test]
    fn gathers_small_chunks() {
        let body: String = (0..100).map(|_| "1\r\nx\r\n").collect::<String>() + "0\r\n\r\n";
        let mut buf = BytesMut::from(body.as_bytes());
        let mut d = Decoder::for_request(RequestFraming::Chunked);
        let data = d.decode_gathered(&mut buf, 16 * 1024).unwrap().unwrap();
        assert_eq!(data.len(), 100, "100 one-byte chunks in one piece");
        assert!(d.decode_gathered(&mut buf, 16 * 1024).unwrap().is_none());
        assert!(d.is_done());
    }

    #[test]
    fn rejects_malformed_chunked() {
        for bad in [
            &b"5\nhello\r\n"[..],
            b"x\r\n",
            b"5\r\nhelloXX",
            b"-1\r\n",
            b"11111111111111111\r\n",
        ] {
            let mut d = Decoder::for_request(RequestFraming::Chunked);
            assert!(decode_all(&mut d, bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn frames_chunks() {
        let mut out = Encoder::Chunked.frame(Bytes::from_static(b"hello"));
        let mut sink = Vec::new();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        while !out.is_done() {
            let _ = out.poll_write(&mut sink, &mut cx);
        }
        assert_eq!(sink, b"5\r\nhello\r\n");
    }
}
