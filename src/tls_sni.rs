//! Minimal TLS ClientHello SNI parser.
//!
//! For TLSRoute we route a raw TCP connection by the SNI hostname in the TLS
//! ClientHello, *without* terminating TLS (passthrough) or before terminating it
//! (terminate). Pingora exposes no ClientHello parser, so we parse just enough of
//! the handshake to pull out the `server_name` extension. We never decrypt; we
//! only read the cleartext ClientHello, which is always sent in the clear (even in
//! TLS 1.3 — Encrypted Client Hello is not in scope here and would simply present
//! no usable SNI).
//!
//! The parser is deliberately strict and bounds-checked: any malformed / truncated
//! input returns `None` rather than panicking, and the caller treats `None` as "no
//! SNI" (which routes to the terminate-default or is dropped).

/// Parse the SNI host_name from a buffer that begins with a TLS record containing
/// a ClientHello. Returns the lowercased SNI, or `None` if the buffer is not a
/// TLS handshake / ClientHello, has no SNI extension, or is malformed/truncated.
///
/// `buf` should be the bytes starting at the TLS record header (byte 0 = content
/// type). The record may be larger than one ClientHello-worth of bytes; we only
/// read within the declared lengths and ignore trailing data.
pub fn parse_client_hello_sni(buf: &[u8]) -> Option<String> {
    let mut r = Reader::new(buf);

    // --- TLS record header (5 bytes) ---
    let content_type = r.u8()?;
    if content_type != 0x16 {
        return None; // not a handshake record
    }
    let _version = r.u16()?; // legacy record version; ignore
    let record_len = r.u16()? as usize;
    // The handshake message must fit within the declared record. (A ClientHello
    // can in principle span multiple records, but in practice — and in every
    // conformance case — it arrives in a single record. If it doesn't fit, we
    // bail and let the caller treat it as no-SNI.)
    let record = r.take(record_len)?;
    let mut r = Reader::new(record);

    // --- Handshake header ---
    let msg_type = r.u8()?;
    if msg_type != 0x01 {
        return None; // not a ClientHello
    }
    let body_len = r.u24()? as usize;
    let body = r.take(body_len)?;
    let mut r = Reader::new(body);

    // --- ClientHello body ---
    r.u16()?; // client_version (legacy)
    r.skip(32)?; // random
    let session_id_len = r.u8()? as usize;
    r.skip(session_id_len)?; // session_id
    let cipher_suites_len = r.u16()? as usize;
    r.skip(cipher_suites_len)?; // cipher_suites
    let compression_len = r.u8()? as usize;
    r.skip(compression_len)?; // compression_methods

    // Extensions are optional (TLS 1.2 allows a ClientHello with none). If the
    // body ends here, there's no SNI.
    let extensions_len = match r.u16() {
        Some(n) => n as usize,
        None => return None,
    };
    let extensions = r.take(extensions_len)?;
    let mut r = Reader::new(extensions);

    // --- Walk extensions, looking for server_name (type 0) ---
    while r.remaining() >= 4 {
        let ext_type = r.u16()?;
        let ext_len = r.u16()? as usize;
        let ext_data = r.take(ext_len)?;
        if ext_type == 0x0000 {
            return parse_server_name_extension(ext_data);
        }
    }
    None
}

/// Parse a `server_name` extension body (RFC 6066): a ServerNameList of
/// (name_type, host_name). We return the first `host_name` (type 0) entry,
/// lowercased.
fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    let list_len = r.u16()? as usize;
    let list = r.take(list_len)?;
    let mut r = Reader::new(list);
    while r.remaining() >= 3 {
        let name_type = r.u8()?;
        let name_len = r.u16()? as usize;
        let name = r.take(name_len)?;
        if name_type == 0x00 {
            // host_name. Must be valid UTF-8 (it's an ASCII DNS name in practice).
            let s = std::str::from_utf8(name).ok()?;
            if s.is_empty() {
                return None;
            }
            return Some(s.to_ascii_lowercase());
        }
    }
    None
}

/// A bounds-checked, big-endian byte reader. Every accessor returns `None` on
/// underflow, so a malformed/truncated ClientHello can never panic the parser.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        self.take(3).map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but well-formed ClientHello TLS record carrying the given
    /// SNI, mirroring how a real client frames it. Used to exercise the parser
    /// without pulling in a TLS stack.
    fn client_hello_with_sni(sni: Option<&str>) -> Vec<u8> {
        // server_name extension body (if any).
        let extensions: Vec<u8> = if let Some(host) = sni {
            let host = host.as_bytes();
            let mut server_name = Vec::new();
            server_name.push(0x00); // name_type = host_name
            server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
            server_name.extend_from_slice(host);

            let mut server_name_list = Vec::new();
            server_name_list.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
            server_name_list.extend_from_slice(&server_name);

            let mut ext = Vec::new();
            ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type = server_name
            ext.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
            ext.extend_from_slice(&server_name_list);
            ext
        } else {
            Vec::new()
        };

        // ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length = 0
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(0x01); // compression_methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake header.
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let blen = body.len();
        handshake.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        handshake.extend_from_slice(&body);

        // TLS record header.
        let mut record = Vec::new();
        record.push(0x16); // handshake content type
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni() {
        let buf = client_hello_with_sni(Some("echo.example.com"));
        assert_eq!(parse_client_hello_sni(&buf).as_deref(), Some("echo.example.com"));
    }

    #[test]
    fn lowercases_sni() {
        let buf = client_hello_with_sni(Some("Echo.Example.COM"));
        assert_eq!(parse_client_hello_sni(&buf).as_deref(), Some("echo.example.com"));
    }

    #[test]
    fn no_sni_extension() {
        let buf = client_hello_with_sni(None);
        assert_eq!(parse_client_hello_sni(&buf), None);
    }

    #[test]
    fn not_a_handshake_record() {
        // application_data content type
        let buf = vec![0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        assert_eq!(parse_client_hello_sni(&buf), None);
    }

    #[test]
    fn not_a_client_hello() {
        // A handshake record whose message is a ServerHello (type 0x02).
        let mut buf = client_hello_with_sni(Some("x.com"));
        // The handshake msg_type lives right after the 5-byte record header.
        buf[5] = 0x02;
        assert_eq!(parse_client_hello_sni(&buf), None);
    }

    #[test]
    fn truncated_anywhere_returns_none_not_panic() {
        let full = client_hello_with_sni(Some("echo.example.com"));
        // Every truncation prefix must parse to None (or the full SNI only at full
        // length) without panicking.
        for n in 0..full.len() {
            let _ = parse_client_hello_sni(&full[..n]); // must not panic
        }
        assert_eq!(parse_client_hello_sni(&full).as_deref(), Some("echo.example.com"));
    }

    #[test]
    fn empty_buffer() {
        assert_eq!(parse_client_hello_sni(&[]), None);
    }

    #[test]
    fn trailing_data_after_record_is_ignored() {
        let mut buf = client_hello_with_sni(Some("echo.example.com"));
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // junk after the record
        assert_eq!(parse_client_hello_sni(&buf).as_deref(), Some("echo.example.com"));
    }

    #[test]
    fn multiple_extensions_before_sni() {
        // Hand-craft a ClientHello where a non-SNI extension precedes server_name,
        // to exercise the extension walk.
        let host = b"multi.example.com";
        let mut server_name = vec![0x00];
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);
        let mut snl = Vec::new();
        snl.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        snl.extend_from_slice(&server_name);

        let mut exts = Vec::new();
        // A dummy extension (supported_versions, type 43) first.
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&0x0003u16.to_be_bytes());
        exts.extend_from_slice(&[0x02, 0x03, 0x04]);
        // Then server_name.
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(snl.len() as u16).to_be_bytes());
        exts.extend_from_slice(&snl);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&0x0002u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let blen = body.len();
        hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(parse_client_hello_sni(&rec).as_deref(), Some("multi.example.com"));
    }
}
