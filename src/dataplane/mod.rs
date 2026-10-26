//! The data plane: torii's proxy.
//!
//! Built directly on tokio sockets, OpenSSL, our own HTTP/1 (on httparse) and our
//! fork of h2. Per request it reads the current [`RouteTable`] snapshot, matches
//! the request, and forwards it to a backend pod over HTTP/1.1, or answers it
//! itself (404 when nothing matches, redirects, CORS preflights, errors).
//!
//! Memory works as in nginx: a connection waiting on its client holds no I/O
//! buffer (see [`io`]), a request in flight holds one chunk per direction (see
//! [`relay`]), and everything a request needs lives in a future that exists only
//! while it does.
//!
//! [`RouteTable`]: crate::route_table::RouteTable

mod h1;
mod io;
mod proxy;
mod relay;
mod serve_h1;
mod serve_h2;
#[cfg(test)]
mod tests;
mod tls;
mod upstream;

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use io::Stream;
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio_openssl::SslStream;

use crate::conn_limit::{ConnLimiter, ConnLimits};
use crate::route_table::BackendTls;
use crate::snapshot::DataPlane;
use crate::tls_sni::ClientHello;
use crate::tls_table::TlsDecision;

/// Most response data the kernel may hold unsent on a client connection
/// (`TCP_NOTSENT_LOWAT`, see [`io::setup_downstream`]).
#[cfg(target_os = "linux")]
const CLIENT_NOTSENT_LOWAT: u32 = 128 * 1024;

/// How long a client may stall an exchange before torii gives up on it: leave a
/// response write without progress (it stopped reading, or keeps an h2 stream's
/// flow-control window closed), or keep torii waiting on a request body (see
/// [`MIN_BODY_PROGRESS`]). nginx's `send_timeout` / `client_body_timeout`.
const CLIENT_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// The least a request body must bring for each [`CLIENT_STALL_TIMEOUT`] that
/// torii waits for it, unless it ends: one HTTP/2 DATA frame of the default
/// maximum size, ~270 B/s. If any data reset the clock, a client could send a
/// byte every minute and hold its backend connection for as long as it liked
/// (T041). Apache asks 500 B/s of a request body.
const MIN_BODY_PROGRESS: u64 = 16 * 1024;

/// How long an HTTP/1.x connection may wait for the first byte of its next
/// request head.
const H1_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a request head may take from its first byte to its end (nginx's
/// `client_header_timeout`, Go's `ReadHeaderTimeout`).
const H1_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle timeout for an HTTP/2 connection: if no stream starts or ends within this
/// window and none is in flight, the connection is closed. Also bounds the wait
/// for the connection preface. Without it, browsers' idle h2 connections
/// accumulated until the process OOMed (seen in prod). Matches nginx's ~75 s
/// keepalive_timeout.
const H2_IDLE_TIMEOUT: Duration = Duration::from_secs(75);

/// Cap on concurrent HTTP/2 streams per connection (SETTINGS_MAX_CONCURRENT_STREAMS,
/// RFC 9113 §6.5.2). 100 is the RFC's recommended minimum. A stream holds at most
/// one chunk per direction ([`relay::CHUNK`]) plus h2's send buffer, so one
/// connection holds a few MB at most; the request caps bound how many such
/// streams a client has on all its connections (see `conn_limit`).
const H2_MAX_CONCURRENT_STREAMS: u32 = 100;

/// Cap on the stream tasks of one HTTP/2 connection, open streams or not (see
/// [`serve_h2::serve`]). Twice the stream limit, because a client at that limit
/// may cancel a stream and open another at once (RFC 9113 §5.1.2), as proxies do
/// when their user goes away: both frames usually come in one read, before the
/// cancelled stream's task has even run to see the reset.
const H2_MAX_STREAM_TASKS: usize = 2 * H2_MAX_CONCURRENT_STREAMS as usize;

/// Cap on the decoded header list of an HTTP/2 request (SETTINGS_MAX_HEADER_LIST_SIZE),
/// counted as name + value + 32 bytes per field. Larger requests get a 431 (far
/// larger ones a GOAWAY). Without an explicit cap h2 accepts 16 MiB, and HPACK
/// lets a client repeat a ~4 KB dynamic-table entry for one byte each (T001). h2
/// keeps request trailers decoded until the stream ends, so this also bounds those.
const H2_MAX_HEADER_LIST_SIZE: u32 = 32 * 1024;

/// Cap on the fields of an HTTP/2 request head: 256, as for HTTP/1. torii copies
/// the head while it forwards it, and an empty field repeated costs one byte on
/// the wire, so a longer head gets a 431 before the stream gets a task.
const H2_MAX_HEADER_FIELDS: usize = h1::MAX_REQUEST_FIELDS;

/// Cap on the response data h2 holds per stream that it has not written to the
/// connection yet (h2's default is 400 KiB): one chunk of the relay.
const H2_MAX_SEND_BUFFER_SIZE: usize = relay::CHUNK;

/// How long to try to flush the GOAWAY to a client that keeps opening streams over
/// the task cap. Such a client may not be reading.
const H2_GOAWAY_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// Deadline for completing a client's TLS handshake. A client that sends a
/// ClientHello then stalls would otherwise pin a task forever.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to wait for the ClientHello's bytes, to read its SNI.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Most of a ClientHello peeked for its SNI. A real ClientHello is well under it.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Idle timeout for a TLSRoute connection (passthrough, or terminate to TCP): if
/// no byte moves in EITHER direction for this long, it is closed. An idle bound
/// doesn't cut long transfers or long polls the way a total cap would.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// After SIGTERM, how long torii keeps accepting connections: Kubernetes removes
/// the pod from Service endpoints and load balancers at the same time as it sends
/// SIGTERM, and those updates take a moment to reach every node (T035).
const DRAIN_DELAY: Duration = Duration::from_secs(5);

/// Then how long the connections in flight get to finish. DRAIN_DELAY plus this
/// stays under the default 30 s `terminationGracePeriodSeconds`.
const DRAIN_GRACE: Duration = Duration::from_secs(20);

/// Deadlines for torii's connections and requests to backends (the `--upstream-*`
/// flags; `None` disables one).
#[derive(Clone, Copy, Debug)]
pub struct UpstreamTimeouts {
    /// For connecting to a backend, TLS handshake included.
    pub connect: Option<Duration>,
    /// How long a backend may go without sending or accepting data during a request,
    /// the wait for its response included, for HTTPRoute rules without `timeouts`.
    pub response: Option<Duration>,
}

/// What every connection shares.
pub struct Ctx {
    data_plane: DataPlane,
    timeouts: UpstreamTimeouts,
    /// Forward request paths with an encoded `/` or `\` (see `normalize_path`).
    allow_encoded_slashes: bool,
    /// How long a client may stall an exchange: [`CLIENT_STALL_TIMEOUT`] (tests
    /// shorten it).
    client_stall: Duration,
    limiter: Arc<ConnLimiter>,
    pool: Arc<upstream::Pool>,
    clients: tls::Clients,
    /// Present when there are TLS ports.
    tls: Option<tls::Server>,
    /// True once torii drains for shutdown: connections finish what they are
    /// doing and close.
    shutdown: watch::Sender<bool>,
    live: Live,
}

impl Ctx {
    fn draining(&self) -> bool {
        *self.shutdown.borrow()
    }
}

/// What a request knows about its connection.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    /// The local port the connection came in on: the Gateway listener's port.
    pub port: u16,
    pub peer: Option<IpAddr>,
    /// Came in on a TLS port.
    pub tls: bool,
}

/// The number of client connections open, for the shutdown drain.
#[derive(Default)]
struct Live {
    count: AtomicUsize,
    zero: Notify,
}

struct LiveGuard<'a>(&'a Live);

impl Live {
    fn track(&self) -> LiveGuard<'_> {
        self.count.fetch_add(1, Ordering::Relaxed);
        LiveGuard(self)
    }

    async fn wait_zero(&self) {
        loop {
            let notified = self.zero.notified();
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.zero.notify_waiters();
        }
    }
}

/// Run the data plane: listen on `http_ports` (plain HTTP) and `tls_ports`
/// (TLSRoute passthrough / terminate per SNI, else TLS-terminated HTTP) on
/// `threads` worker threads, until SIGTERM (drain, then exit) or SIGINT (exit).
///
/// This blocks forever (it ends the process), so call it from a dedicated thread.
#[allow(clippy::too_many_arguments)]
pub fn run(
    data_plane: DataPlane,
    bind_ip: &str,
    http_ports: &[u16],
    tls_ports: &[u16],
    timeouts: UpstreamTimeouts,
    allow_encoded_slashes: bool,
    limits: ConnLimits,
    threads: usize,
) -> ! {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads.max(1))
        .thread_name("dataplane")
        .enable_all()
        .build()
        .expect("failed to build the data-plane runtime");
    let code = runtime.block_on(async {
        let ctx = Arc::new(Ctx {
            tls: (!tls_ports.is_empty()).then(|| tls::Server::new(data_plane.clone())),
            data_plane,
            timeouts,
            allow_encoded_slashes,
            client_stall: CLIENT_STALL_TIMEOUT,
            limiter: ConnLimiter::new(limits),
            pool: Arc::default(),
            clients: tls::Clients::default(),
            shutdown: watch::Sender::new(false),
            live: Live::default(),
        });
        let (stop_accepting, stop) = watch::channel(false);
        let ports = http_ports
            .iter()
            .map(|&p| (p, false))
            .chain(tls_ports.iter().map(|&p| (p, true)));
        for (port, tls) in ports {
            let ip = bind_ip.trim_start_matches('[').trim_end_matches(']');
            let Ok(ip) = ip.parse::<IpAddr>() else {
                tracing::error!(bind_ip, "invalid --bind-ip");
                return 1;
            };
            let addr = SocketAddr::new(ip, port);
            let listener = match listen(addr) {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(%addr, error = %e, "failed to listen");
                    return 1;
                }
            };
            tokio::spawn(accept_loop(ctx.clone(), listener, tls, stop.clone()));
        }
        tracing::info!(
            bind_ip,
            ?http_ports,
            ?tls_ports,
            ?limits,
            threads,
            "data plane listening"
        );

        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to install the SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install the SIGINT handler");
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("SIGINT received; exiting");
                return 0;
            }
            _ = sigterm.recv() => {}
        }
        tracing::info!(?DRAIN_DELAY, ?DRAIN_GRACE, "SIGTERM received; draining");
        // Connections finish what they are doing and close (h2 gets a GOAWAY now),
        // while new ones are still accepted for DRAIN_DELAY.
        ctx.shutdown.send_replace(true);
        tokio::time::sleep(DRAIN_DELAY).await;
        let _ = stop_accepting.send(true);
        match tokio::time::timeout(DRAIN_GRACE, ctx.live.wait_zero()).await {
            Ok(()) => tracing::info!("drained; exiting"),
            Err(_) => tracing::info!(
                open = ctx.live.count.load(Ordering::Relaxed),
                "drain grace period over; exiting"
            ),
        }
        0
    });
    std::process::exit(code)
}

/// A listening socket: SO_REUSEADDR, and a long accept backlog.
fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(65535)?;
    TcpListener::from_std(socket.into())
}

/// Accept connections until told to stop, and serve each on its own task.
///
/// Admission control happens here, before any work for the connection (the SNI
/// peek, the TLS handshake, the HTTP session): the permit is held until the
/// connection ends.
async fn accept_loop(ctx: Arc<Ctx>, listener: TcpListener, tls: bool, mut stop: watch::Receiver<bool>) {
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = stop.wait_for(|&s| s) => return,
        };
        let (tcp, peer) = match accepted {
            Ok(a) => a,
            Err(e) => {
                // Out of file descriptors and the like: back off instead of spinning.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        // On a `::` listener, IPv4 clients come as IPv4-mapped addresses.
        let peer_ip = peer.ip().to_canonical();
        let Some(permit) = ctx.limiter.admit(Some(peer_ip)) else {
            continue;
        };
        io::setup_downstream(&tcp);
        let info = ConnInfo {
            port: tcp.local_addr().map(|a| a.port()).unwrap_or(0),
            peer: Some(peer_ip),
            tls,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _live = ctx.live.track();
            if tls {
                serve_tls(&ctx, tcp, &info).await;
            } else {
                serve_h1::serve(&ctx, Stream::Plain(tcp), &info).await;
            }
        });
    }
}

/// A connection to a TLS port: peek its SNI and dispatch.
///
/// - TLSRoute **passthrough**: pipe the still-encrypted bytes to the backend.
/// - TLSRoute **terminate**: terminate TLS here, pipe the cleartext to the backend
///   (re-encrypted if a BackendTLSPolicy targets it).
/// - **otherwise** (no TLSRoute for the SNI): terminate TLS here and serve HTTP —
///   this is how HTTPS HTTPRoutes keep working on the same port.
///
/// The peek leaves the bytes in the socket, so whichever branch runs sees the
/// whole byte stream, ClientHello included.
async fn serve_tls(ctx: &Arc<Ctx>, tcp: TcpStream, info: &ConnInfo) {
    // The setup (peek, dispatch, handshake) runs in its own allocation, let go
    // once it is done: an idle connection then holds only the serving state.
    let Some(conn) = Box::pin(tls_setup(ctx, tcp, info)).await else {
        return;
    };
    match conn {
        TlsConn::Pipe(mut down, mut up) => {
            let (mut down_buf, mut up_buf) = (BytesMut::new(), BytesMut::new());
            let _ = relay::pipe(&mut down, &mut down_buf, &mut up, &mut up_buf, Some(PIPE_IDLE_TIMEOUT)).await;
        }
        TlsConn::Http(stream) => match stream.alpn() {
            // An ACME TLS-ALPN-01 validation ends with the handshake.
            Some(b"acme-tls/1") => {}
            Some(b"h2") => Box::pin(serve_h2::serve(ctx, stream, info)).await,
            _ => serve_h1::serve(ctx, stream, info).await,
        },
    }
}

/// What a TLS-port connection becomes once it is set up.
enum TlsConn {
    /// A TLSRoute: a byte pipe between the client and a backend.
    Pipe(Stream, Stream),
    /// TLS terminated for HTTP.
    Http(Stream),
}

/// Peek a TLS-port connection's SNI, dispatch it, and run the handshake if torii
/// terminates it. None: the connection is to be closed.
async fn tls_setup(ctx: &Ctx, tcp: TcpStream, info: &ConnInfo) -> Option<TlsConn> {
    let hello = peek_client_hello(&tcp).await;
    let sni = hello.as_ref().and_then(|h| h.sni.as_deref());
    let decision = ctx.data_plane.load().tls.lookup(info.port, sni, proxy::next_rng());
    match decision {
        TlsDecision::Passthrough(ep) => {
            tracing::debug!(port = info.port, ?sni, ip = %ep.ip, ep_port = ep.port, "TLS passthrough");
            let up = upstream::connect_raw(&ctx.clients, &ep, None, ctx.timeouts.connect)
                .await
                .ok()?;
            Some(TlsConn::Pipe(Stream::Plain(tcp), up))
        }
        TlsDecision::Terminate(ep) => {
            tracing::debug!(port = info.port, ?sni, ip = %ep.ip, ep_port = ep.port, "TLS terminate -> TCP");
            // An invalid BackendTLSPolicy targets the backend: refuse the connection
            // (the HTTP path answers 500), never fall back to plaintext.
            let upstream_tls = match &ep.tls {
                BackendTls::Invalid => return None,
                BackendTls::ReEncrypt(tls) => Some(tls),
                BackendTls::Plaintext => None,
            };
            let tls = tls_accept(ctx, tcp, hello.as_ref(), tls::Use::Pipe).await?;
            let up = upstream::connect_raw(&ctx.clients, &ep, upstream_tls, ctx.timeouts.connect)
                .await
                .ok()?;
            Some(TlsConn::Pipe(Stream::Tls(tls), up))
        }
        TlsDecision::NoBackend => {
            tracing::debug!(port = info.port, ?sni, "TLSRoute matched but no backend -> close");
            None
        }
        // No TLSRoute for the SNI on a port with TLSRoutes, and no HTTPS listener
        // there serves the SNI either: close, so the client sees EOF rather than a
        // handshake with some certificate (T170). An ACME validation is answered.
        TlsDecision::NoRoute
            if !https_serves(ctx, info.port, sni) && !hello.as_ref().is_some_and(|h| h.offers_acme) =>
        {
            tracing::debug!(
                port = info.port,
                ?sni,
                "no TLSRoute or HTTPS listener for the SNI -> close"
            );
            None
        }
        TlsDecision::NoRoute => Some(TlsConn::Http(Stream::Tls(
            tls_accept(ctx, tcp, hello.as_ref(), tls::Use::Http).await?,
        ))),
    }
}

/// Whether a connection with SNI `sni` on `port` is for HTTPS: the port carries
/// no TLSRoute (it is an HTTPS port), or an HTTPS listener on it serves the SNI.
fn https_serves(ctx: &Ctx, port: u16, sni: Option<&str>) -> bool {
    let snapshot = ctx.data_plane.load();
    !snapshot.tls.has_port(port) || snapshot.routes.serves_host(port, sni)
}

/// Run the server side of a client's TLS handshake, with the certificate for its
/// ClientHello, giving up after [`TLS_HANDSHAKE_TIMEOUT`].
async fn tls_accept(
    ctx: &Ctx,
    tcp: TcpStream,
    hello: Option<&ClientHello>,
    use_: tls::Use,
) -> Option<SslStream<TcpStream>> {
    let ssl = ctx.tls.as_ref()?.ssl_for(hello, use_)?;
    let mut stream = SslStream::new(ssl, tcp).ok()?;
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, Pin::new(&mut stream).accept()).await {
        Ok(Ok(())) => Some(stream),
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "TLS handshake failed");
            None
        }
        Err(_) => {
            tracing::debug!("TLS handshake timed out; closing");
            None
        }
    }
}

/// Peek a connection's ClientHello, leaving its bytes in the socket: the record
/// header first (to learn the record's length), then the whole record, within
/// [`PEEK_TIMEOUT`]. None if it is not TLS, is truncated or times out.
async fn peek_client_hello(tcp: &TcpStream) -> Option<ClientHello> {
    tokio::time::timeout(PEEK_TIMEOUT, async {
        let mut header = [0u8; 5];
        peek_exact(tcp, &mut header).await?;
        if header[0] != 0x16 {
            return None; // not a TLS handshake record
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0u8; (5 + record_len).min(MAX_CLIENT_HELLO)];
        peek_exact(tcp, &mut record).await?;
        crate::tls_sni::parse_client_hello(&record)
    })
    .await
    .ok()
    .flatten()
}

/// Peek until `buf` can be filled. A peek that finds too few bytes reports
/// "would block", which clears the socket's readiness, so the next wait is for
/// new bytes rather than a spin on the ones already there.
async fn peek_exact(tcp: &TcpStream, buf: &mut [u8]) -> Option<()> {
    let sock = socket2::SockRef::from(tcp);
    loop {
        tcp.readable().await.ok()?;
        let r = tcp.try_io(Interest::READABLE, || {
            // SAFETY: `peek` only writes initialized bytes into the buffer.
            let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
            match sock.peek(uninit)? {
                0 => Err(std::io::ErrorKind::UnexpectedEof.into()),
                n if n < buf.len() => Err(std::io::ErrorKind::WouldBlock.into()),
                _ => Ok(()),
            }
        });
        match r {
            Ok(()) => return Some(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return None,
        }
    }
}
