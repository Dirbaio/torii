//! TLS with rustls: reading a client's ClientHello before deciding what to do
//! with its connection, the server side of the handshake and the choice of
//! certificate, and the client side for backends a BackendTLSPolicy re-encrypts to.
//!
//! A TLS-port connection starts with [`read_client_hello`]: rustls reassembles and
//! parses the ClientHello (its SNI validated) without answering it, and torii
//! routes on that one parse. A TLSRoute passthrough then replays the bytes read to
//! its backend; anything else finishes the handshake with [`Server::accept`].
//!
//! The certificate is resolved per handshake from the current snapshot, by SNI:
//! the snapshot keeps every certificate parsed, so a handshake neither re-parses
//! PEM nor copies a key.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::{fmt, io};

use bytes::BytesMut;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::{Accepted, AcceptedAlert, Acceptor, NoServerSessionStorage, ProducesTickets, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{StartHandshake, TlsConnector, TlsStream};

use crate::cert_store::{CertKey, ca_roots};
use crate::route_table::UpstreamTls;
use crate::snapshot::DataPlane;

/// Most encrypted data rustls holds unsent for a connection's peer: one full
/// record. Its default, 64 KiB, would let a peer that stops reading hold that
/// much on top of the relay's chunk.
const SEND_BUFFER_LIMIT: usize = 16 * 1024;

/// rustls on ring. Its default suites are what torii wants: TLS 1.3, and TLS 1.2
/// with ECDHE key exchange and AEAD ciphers only. No DHE-RSA, which lets a client
/// make each handshake against an RSA certificate ~20-70% more expensive; no
/// static RSA, which has no forward secrecy (T208); and no renegotiation (T176).
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client's ClientHello, parsed by rustls, and what torii needs from it.
pub struct Hello {
    accepted: Accepted,
    /// The SNI, lowercased. None without one, or with an IP address (RFC 6066
    /// forbids those, and rustls takes them as none).
    pub sni: Option<String>,
    /// The ALPN offer includes `acme-tls/1` (an ACME TLS-ALPN-01 validation).
    pub offers_acme: bool,
    /// The client offers no ALPN, or `h2` or `http/1.1`.
    offers_http: bool,
    /// Every byte read from the client: a passthrough replays them to its backend.
    pub bytes: BytesMut,
}

impl Hello {
    fn new(accepted: Accepted, bytes: BytesMut) -> Hello {
        let (sni, offers_acme, offers_http) = {
            let hello = accepted.client_hello();
            let offers = |proto: &[u8]| hello.alpn().is_some_and(|mut a| a.any(|p| p == proto));
            (
                hello.server_name().map(str::to_owned),
                offers(b"acme-tls/1"),
                hello.alpn().is_none() || offers(b"h2") || offers(b"http/1.1"),
            )
        };
        Hello {
            accepted,
            sni,
            offers_acme,
            offers_http,
            bytes,
        }
    }
}

/// Read a client's ClientHello, and keep the bytes read. rustls puts one split
/// over several records back together, takes one of up to 64 KiB, and refuses
/// a malformed one (an invalid or second SNI, a repeated extension). It answers
/// nothing: the client hears from torii, or from a passthrough backend, only
/// once torii has decided.
///
/// Err: the connection is to be closed, after sending the alert if there is one
/// (rustls refused the ClientHello).
pub async fn read_client_hello(tcp: &mut TcpStream) -> Result<Hello, Option<AcceptedAlert>> {
    let mut acceptor = Acceptor::default();
    let mut bytes = BytesMut::new();
    let accepted = std::future::poll_fn(|cx| {
        loop {
            let mut rd = Recorder {
                tcp: &mut *tcp,
                cx: &mut *cx,
                bytes: &mut bytes,
            };
            match acceptor.read_tls(&mut rd) {
                Ok(0) => return Poll::Ready(Err(None)),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                // An I/O error, or a ClientHello over 64 KiB.
                Err(_) => return Poll::Ready(Err(None)),
            }
            match acceptor.accept() {
                Ok(Some(accepted)) => return Poll::Ready(Ok(accepted)),
                Ok(None) => {}
                Err((e, alert)) => {
                    tracing::debug!(error = %e, "invalid ClientHello");
                    return Poll::Ready(Err(Some(alert)));
                }
            }
        }
    })
    .await?;
    Ok(Hello::new(accepted, bytes))
}

/// Send the alert for a refused ClientHello, if the socket takes it now.
pub fn send_alert(tcp: &TcpStream, mut alert: AcceptedAlert) {
    struct TryWrite<'a>(&'a TcpStream);
    impl io::Write for TryWrite<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.try_write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let _ = alert.write_all(&mut TryWrite(tcp));
}

/// A blocking-style reader over a socket for rustls, that keeps a copy of what it
/// reads. "Would block" when the socket has nothing (the waker is registered).
struct Recorder<'a, 'b> {
    tcp: &'a mut TcpStream,
    cx: &'a mut Context<'b>,
    bytes: &'a mut BytesMut,
}

impl io::Read for Recorder<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = ReadBuf::new(buf);
        match Pin::new(&mut *self.tcp).poll_read(self.cx, &mut read) {
            Poll::Ready(Ok(())) => {
                self.bytes.extend_from_slice(read.filled());
                Ok(read.filled().len())
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// The server side: one config per kind of connection, shared by every TLS port.
pub struct Server {
    /// For HTTPS: ALPN `h2` or `http/1.1`.
    http: Arc<ServerConfig>,
    /// No ALPN: for a TLSRoute Terminate pipe, whose stream is whatever the client
    /// speaks (T173), and for an HTTPS client whose ALPN offer has neither `h2`
    /// nor `http/1.1` (it gets HTTP/1.1, as before rustls, which would refuse the
    /// handshake rather than select nothing).
    raw: Arc<ServerConfig>,
    /// For an ACME TLS-ALPN-01 validation: ALPN `acme-tls/1` only, and the
    /// challenge certificate.
    acme: Arc<ServerConfig>,
    data_plane: DataPlane,
}

/// What a TLS connection is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    Http,
    Pipe,
}

/// A server config with our settings, selecting the first protocol of `alpn` the
/// client offers (none: no ALPN).
fn server_config(
    certs: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
    ticketer: &Arc<dyn ProducesTickets>,
) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_no_client_auth()
        .with_cert_resolver(certs);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // Keep no sessions in memory (nginx's default, `ssl_session_cache none`):
    // clients resume with tickets. rustls resumes a session only under the SNI it
    // was made for (RFC 6066), and rotates the ticket key every 6 hours.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = ticketer.clone();
    Arc::new(config)
}

impl Server {
    pub fn new(data_plane: DataPlane) -> Server {
        let fallback = CertKey::generate_self_signed().expect("failed to generate fallback TLS cert");
        let certs: Arc<dyn ResolvesServerCert> = Arc::new(Certs {
            data_plane: data_plane.clone(),
            fallback: fallback.parsed().expect("the fallback TLS cert parses").clone(),
        });
        let challenges = Arc::new(Challenges(data_plane.clone()));
        let ticketer = rustls::crypto::ring::Ticketer::new().expect("failed to create the TLS ticketer");
        Server {
            http: server_config(certs.clone(), &[b"h2", b"http/1.1"], &ticketer),
            raw: server_config(certs, &[], &ticketer),
            acme: server_config(challenges, &[b"acme-tls/1"], &ticketer),
            data_plane,
        }
    }

    /// Finish the handshake of a client whose ClientHello is `hello`, as `use_`
    /// needs it.
    pub async fn accept(&self, tcp: TcpStream, hello: Hello, use_: Use) -> io::Result<TlsStream<TcpStream>> {
        let config = self.config_for(&hello, use_);
        let stream = StartHandshake::from_parts(hello.accepted, tcp)
            .into_stream_with(config, |conn| conn.set_buffer_limit(Some(SEND_BUFFER_LIMIT)))
            .await?;
        Ok(stream.into())
    }

    fn config_for(&self, hello: &Hello, use_: Use) -> Arc<ServerConfig> {
        // ACME TLS-ALPN-01: a client that offers `acme-tls/1` for an SNI with a
        // pending challenge gets that protocol and the challenge certificate —
        // never a real one. Otherwise `acme-tls/1` is never selected (T168).
        if use_ == Use::Http
            && hello.offers_acme
            && let Some(sni) = &hello.sni
            && self.data_plane.load_challenges().contains_key(sni)
        {
            return self.acme.clone();
        }
        match use_ {
            Use::Http if hello.offers_http => self.http.clone(),
            _ => self.raw.clone(),
        }
    }
}

/// The certificate for a handshake: the snapshot's for its SNI, else the
/// self-signed fallback.
struct Certs {
    data_plane: DataPlane,
    /// Served when no real certificate matches, so the handshake completes (with
    /// a browser warning) instead of failing, letting a user click through to the
    /// upstream. Generated once at startup.
    fallback: Arc<CertifiedKey>,
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name();
        let snapshot = self.data_plane.load();
        let cert = snapshot.certs.select(sni).and_then(CertKey::parsed);
        Some(cert.cloned().unwrap_or_else(|| {
            // No real cert (no SNI match, Secret missing, ACME not done yet).
            tracing::debug!(?sni, "no matching cert; serving self-signed fallback");
            self.fallback.clone()
        }))
    }
}

/// The certificate for an ACME TLS-ALPN-01 validation: the pending challenge's
/// for its SNI.
struct Challenges(DataPlane);

impl ResolvesServerCert for Challenges {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load_challenges().get(hello.server_name()?)?.parsed().cloned()
    }
}

impl fmt::Debug for Certs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certs")
    }
}

impl fmt::Debug for Challenges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenges")
    }
}

/// Client configs for backends, one pair per CA bundle, built once and shared. A
/// BackendTLSPolicy's bundle used to be parsed on every proxied request (T047).
#[derive(Default)]
pub struct Clients {
    by_ca: Mutex<HashMap<Vec<u8>, CachedConnector>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// The client configs for one CA bundle (None: it trusts nothing), and their id
/// (see [`ClientIdentity`]).
type CachedConnector = (Option<Arc<Connector>>, u64);

/// The client configs for one CA bundle.
struct Connector {
    /// Offering ALPN `http/1.1`.
    http: Arc<ClientConfig>,
    /// Offering no ALPN.
    raw: Arc<ClientConfig>,
}

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
    /// The client configs for `tls`'s CA bundle: the system roots if it is empty.
    /// A bundle with no certificate that parses trusts nothing, so the handshake
    /// fails rather than falling back to the system roots.
    fn connector(&self, ca_pem: &[u8]) -> CachedConnector {
        let mut cache = self.by_ca.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cache.get(ca_pem) {
            return c.clone();
        }
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let entry = (build_connector(ca_pem).map(Arc::new), id);
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
    connector: Option<Arc<Connector>>,
    pub identity: ClientIdentity,
}

impl Client {
    /// Run the client side of a handshake on `tcp`: SNI and verified name the
    /// policy's hostname.
    pub async fn connect(&self, tcp: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        let connector = self
            .connector
            .as_ref()
            .ok_or_else(|| io::Error::other("the BackendTLSPolicy trusts no CA"))?;
        let config = match self.identity.http {
            true => &connector.http,
            false => &connector.raw,
        };
        let name = ServerName::try_from(self.identity.hostname.clone()).map_err(io::Error::other)?;
        let stream = TlsConnector::from(config.clone())
            .connect_with(name, tcp, |conn| conn.set_buffer_limit(Some(SEND_BUFFER_LIMIT)))
            .await?;
        Ok(stream.into())
    }
}

fn build_connector(ca_pem: &[u8]) -> Option<Connector> {
    let roots = match ca_pem.is_empty() {
        true => system_roots().clone(),
        false => Arc::new(ca_roots(ca_pem)),
    };
    if roots.is_empty() {
        tracing::warn!("BackendTLSPolicy CA bundle holds no certificate that parses; trusting nothing");
        return None;
    }
    let raw = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = raw.clone();
    http.alpn_protocols = vec![b"http/1.1".to_vec()];
    Some(Connector {
        http: Arc::new(http),
        raw: Arc::new(raw),
    })
}

/// The system's CA certificates, loaded once.
fn system_roots() -> &'static Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let found = rustls_native_certs::load_native_certs();
        for e in &found.errors {
            tracing::warn!(error = %e, "loading the system CA certificates");
        }
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(found.certs);
        Arc::new(roots)
    })
}
