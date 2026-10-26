//! TLS with OpenSSL, used directly: the server context, the choice of certificate
//! for a connection, and the client contexts for backends a BackendTLSPolicy
//! re-encrypts to.
//!
//! One server context serves every connection. The certificate is chosen before
//! the handshake from the ClientHello torii already peeked (SNI, and whether it is
//! an ACME TLS-ALPN-01 validation), and attached to the connection's `SSL` by
//! reference: the snapshot keeps every certificate parsed, so a handshake neither
//! re-parses PEM nor copies a key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openssl::ssl::{
    AlpnError, Ssl, SslAcceptor, SslConnector, SslContext, SslMethod, SslMode, SslOptions, SslSessionCacheMode,
    SslVerifyMode,
};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;

use crate::cert_store::{CertKey, ParsedCertKey};
use crate::route_table::UpstreamTls;
use crate::snapshot::DataPlane;
use crate::tls_sni::ClientHello;

/// TLS 1.2 suites: ECDHE key exchange only. Mozilla intermediate also has the
/// DHE-RSA suites, which let a client make each handshake against an RSA
/// certificate ~20-70% more expensive, and every client it targets has ECDHE.
const TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
                             ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

/// The server side: one context for every TLS port, and the certificates.
pub struct Server {
    /// For HTTPS: ALPN `h2` or `http/1.1`.
    http: SslContext,
    /// For an ACME TLS-ALPN-01 validation: ALPN `acme-tls/1` only.
    acme: SslContext,
    /// For a TLSRoute Terminate pipe: no ALPN, since the stream is whatever the
    /// client speaks (T173).
    raw: SslContext,
    data_plane: DataPlane,
    /// Self-signed last-resort certificate, generated once at startup. Served when
    /// no real one matches so the handshake completes (with a browser warning)
    /// instead of failing, letting a user click through to the upstream.
    fallback: CertKey,
}

/// What a TLS connection is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    Http,
    Pipe,
}

/// A server context with our settings, selecting the first protocol of `alpn` the
/// client offers (none: no ALPN; a client that offers none of them gets none, and
/// HTTP/1.1).
fn server_context(alpn: &'static [&'static [u8]]) -> SslContext {
    let mut builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("failed to create TLS acceptor builder");
    // Let OpenSSL free a connection's record buffers whenever they're empty,
    // instead of holding ~34 KB for the connection's lifetime (nginx sets the
    // same mode).
    builder.set_mode(SslMode::RELEASE_BUFFERS);
    builder
        .set_cipher_list(TLS12_CIPHERS)
        .expect("failed to set TLS 1.2 cipher list");
    // Keep no sessions in memory (nginx's default, `ssl_session_cache none`):
    // OpenSSL's built-in cache holds up to 20,480 TLS 1.2 sessions past their
    // connections. Session tickets still let clients resume.
    builder.set_session_cache_mode(
        SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_AUTO_CLEAR | SslSessionCacheMode::NO_INTERNAL_STORE,
    );
    if !alpn.is_empty() {
        builder.set_alpn_select_callback(move |_ssl, client| {
            alpn.iter()
                .find_map(|proto| select_alpn(client, proto))
                .ok_or(AlpnError::NOACK)
        });
    }
    builder.build().into_context()
}

impl Server {
    pub fn new(data_plane: DataPlane) -> Server {
        let fallback = CertKey::generate_self_signed().expect("failed to generate fallback TLS cert");
        Server {
            http: server_context(&[b"h2", b"http/1.1"]),
            acme: server_context(&[b"acme-tls/1"]),
            raw: server_context(&[]),
            data_plane,
            fallback,
        }
    }

    /// The `SSL` for a new connection whose ClientHello is `hello`, with its
    /// certificate attached; None if the connection must be refused.
    pub fn ssl_for(&self, hello: Option<&ClientHello>, use_: Use) -> Option<Ssl> {
        let sni = hello.and_then(|h| h.sni.as_deref());
        // ACME TLS-ALPN-01: a client that offers `acme-tls/1` for an SNI with a
        // pending challenge gets that protocol and the challenge certificate —
        // never a real one. Otherwise `acme-tls/1` is never selected (T168).
        if use_ == Use::Http && hello.is_some_and(|h| h.offers_acme) {
            let challenges = self.data_plane.load_challenges();
            if let Some(ck) = sni.and_then(|h| challenges.get(h)) {
                let mut ssl = Ssl::new(&self.acme).ok()?;
                attach(&mut ssl, ck.parsed()?)?;
                return Some(ssl);
            }
        }
        let mut ssl = Ssl::new(match use_ {
            Use::Http => &self.http,
            Use::Pipe => &self.raw,
        })
        .ok()?;
        let snapshot = self.data_plane.load();
        let ck = snapshot.certs.select(sni).unwrap_or_else(|| {
            // No real cert (no SNI match, Secret missing, ACME not done yet).
            tracing::debug!(?sni, "no matching cert; serving self-signed fallback");
            &self.fallback
        });
        attach(&mut ssl, ck.parsed().or(self.fallback.parsed())?)?;
        Some(ssl)
    }
}

/// Attach a parsed certificate chain (leaf first) and key to a connection.
/// Serving the intermediates is what lets clients build a path to a root they
/// trust — without them, an ACME/CA-issued leaf fails to verify.
fn attach(ssl: &mut Ssl, ck: &ParsedCertKey) -> Option<()> {
    let (leaf, intermediates) = ck.chain.split_first()?;
    ssl.set_certificate(leaf).ok()?;
    ssl.set_private_key(&ck.key).ok()?;
    for inter in intermediates {
        ssl.add_chain_cert(inter.clone()).ok()?;
    }
    Some(())
}

/// Find `proto` in the client's wire-format ALPN list, returning a sub-slice of
/// `client` (required: the ALPN-select callback's return must borrow from `client`).
fn select_alpn<'a>(client: &'a [u8], proto: &[u8]) -> Option<&'a [u8]> {
    let mut bytes = client;
    while !bytes.is_empty() {
        let len = bytes[0] as usize;
        bytes = &bytes[1..];
        if len > bytes.len() {
            return None;
        }
        if &bytes[..len] == proto {
            return Some(&bytes[..len]);
        }
        bytes = &bytes[len..];
    }
    None
}

/// Client contexts for backends, one per CA bundle, built once and shared. A
/// BackendTLSPolicy's bundle used to be parsed on every proxied request (T047).
#[derive(Default)]
pub struct Clients {
    by_ca: Mutex<HashMap<Vec<u8>, CachedConnector>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// A client context and its id (see [`ClientIdentity`]).
type CachedConnector = (Arc<SslConnector>, u64);

/// Most distinct CA bundles kept; past it the cache starts over.
const MAX_CLIENT_CONTEXTS: usize = 64;

/// What a pooled backend connection was verified against: two connections are
/// interchangeable only if this matches.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientIdentity {
    pub hostname: String,
    /// Which connector (so which CA bundle) verified it. Never reused for
    /// another bundle, so a connection verified against one tenant's CA never
    /// serves another's.
    connector: u64,
    /// Offers ALPN `http/1.1` (an HTTPRoute backend) or none (a TLSRoute one).
    http: bool,
}

impl Clients {
    /// The client context for `tls`'s CA bundle: the system roots if it is empty.
    /// A bundle that does not parse trusts nothing, so the handshake fails rather
    /// than falling back to the system roots.
    fn connector(&self, ca_pem: &[u8]) -> CachedConnector {
        let mut cache = self.by_ca.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cache.get(ca_pem) {
            return c.clone();
        }
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let entry = (Arc::new(build_connector(ca_pem)), id);
        if cache.len() >= MAX_CLIENT_CONTEXTS {
            cache.clear();
        }
        cache.insert(ca_pem.to_vec(), entry.clone());
        entry
    }

    /// The client side of a connection to a backend: what a pooled connection
    /// must match, and how to make a new one. `http`: offer ALPN `http/1.1`; a
    /// TLSRoute pipe offers none, since its stream is whatever the client speaks,
    /// and a backend that enforces ALPN would refuse the handshake.
    pub fn client(&self, tls: &UpstreamTls, http: bool) -> Client {
        let (connector, id) = self.connector(&tls.ca_pem);
        Client {
            connector,
            identity: ClientIdentity {
                hostname: tls.hostname.clone(),
                connector: id,
                http,
            },
        }
    }
}

/// See [`Clients::client`].
pub struct Client {
    connector: Arc<SslConnector>,
    pub identity: ClientIdentity,
}

impl Client {
    /// The `SSL` for a new connection: SNI and verified name the policy's hostname.
    pub fn ssl(&self) -> Option<Ssl> {
        let mut config = self.connector.configure().ok()?;
        if self.identity.http {
            config.set_alpn_protos(b"\x08http/1.1").ok()?;
        }
        config.into_ssl(&self.identity.hostname).ok()
    }
}

fn build_connector(ca_pem: &[u8]) -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("failed to create TLS connector");
    builder.set_mode(SslMode::RELEASE_BUFFERS);
    // No renegotiation a backend could start mid-response (T176), and forward
    // secrecy: no static-RSA key exchange (T208).
    builder.set_options(SslOptions::NO_RENEGOTIATION);
    builder
        .set_cipher_list("HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4:!3DES")
        .expect("failed to set the backend cipher list");
    builder.set_verify(SslVerifyMode::PEER);
    if !ca_pem.is_empty() {
        let mut store = X509StoreBuilder::new().expect("failed to create X509 store");
        match X509::stack_from_pem(ca_pem) {
            Ok(certs) => {
                for cert in certs {
                    let _ = store.add_cert(cert);
                }
            }
            Err(e) => tracing::warn!(error = %e, "BackendTLSPolicy CA bundle does not parse; trusting nothing"),
        }
        builder
            .set_verify_cert_store(store.build())
            .expect("failed to set the CA store");
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_alpn_finds_offered_protocols() {
        let offer = b"\x08http/1.1\x02h2";
        let pick = [&b"h2"[..], b"http/1.1"].iter().find_map(|p| select_alpn(offer, p));
        assert_eq!(pick, Some(&b"h2"[..]));
        assert_eq!(select_alpn(b"\x05bogus", b"h2"), None);
        assert_eq!(select_alpn(b"\x09h2", b"h2"), None, "truncated list");
    }
}
