//! I/O primitives of the data plane: the stream type every connection runs on,
//! reads into buffers that exist only while they hold bytes, and the timers that
//! bound a stalled peer.
//!
//! The rule that keeps an idle connection small (as in nginx): no buffer is held
//! while waiting on a peer. [`poll_read_lazy`] reserves its buffer right before a
//! read and lets go of it when the read would block with nothing buffered, so a
//! connection waiting for its next request holds a socket and a few words of state.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsStream;

/// A connection: plain TCP, or TLS over TCP. One enum rather than a trait object,
/// so that a plain connection needs no box for its stream.
#[derive(Debug)]
pub enum Stream {
    Plain(TcpStream),
    /// Boxed: rustls's state for a connection is ~1 KB, and a connection's
    /// future holds its stream.
    Tls(Box<TlsStream<TcpStream>>),
    /// An in-memory connection, for tests on a paused clock.
    #[cfg(test)]
    Duplex(tokio::io::DuplexStream),
}

impl Stream {
    /// The ALPN protocol the TLS handshake selected, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        match self {
            Stream::Plain(_) => None,
            Stream::Tls(s) => s.get_ref().1.alpn_protocol(),
            #[cfg(test)]
            Stream::Duplex(_) => None,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
            #[cfg(test)]
            Stream::Duplex(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
            #[cfg(test)]
            Stream::Duplex(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Tls(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
            #[cfg(test)]
            Stream::Duplex(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Plain(s) => s.is_write_vectored(),
            Stream::Tls(s) => s.is_write_vectored(),
            #[cfg(test)]
            Stream::Duplex(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
            #[cfg(test)]
            Stream::Duplex(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
            #[cfg(test)]
            Stream::Duplex(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Read at most `max` more bytes into `buf`, reserving the room first. Returns the
/// number of bytes read, 0 at EOF.
///
/// When the read would block and `buf` holds nothing, `buf` is replaced by an
/// unallocated one: the memory comes back only when the peer sends again. A
/// spurious wake-up costs one allocation and one free, which jemalloc serves from
/// its thread cache.
pub fn poll_read_lazy<S: AsyncRead + Unpin + ?Sized>(
    io: &mut S,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
    max: usize,
) -> Poll<io::Result<usize>> {
    debug_assert!(max > 0);
    if buf.capacity() - buf.len() < max {
        buf.reserve(max);
    }
    let spare = &mut buf.spare_capacity_mut()[..max];
    let mut read = ReadBuf::uninit(spare);
    match Pin::new(io).poll_read(cx, &mut read) {
        Poll::Ready(Ok(())) => {
            let n = read.filled().len();
            // SAFETY: `poll_read` initialized the first `n` bytes of the spare capacity.
            unsafe { buf.set_len(buf.len() + n) };
            Poll::Ready(Ok(n))
        }
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Pending => {
            if buf.is_empty() {
                *buf = BytesMut::new();
            }
            Poll::Pending
        }
    }
}

/// [`poll_read_lazy`] as a future.
pub async fn read_lazy<S: AsyncRead + Unpin + ?Sized>(io: &mut S, buf: &mut BytesMut, max: usize) -> io::Result<usize> {
    std::future::poll_fn(|cx| poll_read_lazy(io, cx, buf, max)).await
}

/// Write all of `data` to `io` and flush, failing with `TimedOut` if no write makes
/// progress for `stall`.
pub async fn write_all<S: AsyncWrite + Unpin + ?Sized>(io: &mut S, data: &[u8], stall: Duration) -> io::Result<()> {
    let mut timer = Timer::new();
    let mut pos = 0;
    std::future::poll_fn(|cx| {
        while pos < data.len() {
            match Pin::new(&mut *io).poll_write(cx, &data[pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    pos += n;
                    timer.disarm();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return timer.poll_stall(cx, stall),
            }
        }
        match Pin::new(&mut *io).poll_flush(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => timer.poll_stall(cx, stall),
        }
    })
    .await
}

/// One write in progress: a small framing prefix (an HTTP/1 chunk size line), a
/// body chunk, and a framing suffix, written in that order. Written as one vectored
/// write where the stream supports it, else gathered into one buffer first, so that
/// a TLS stream sends them in one record.
#[derive(Debug, Default)]
pub struct Outgoing {
    prefix: [u8; 20],
    prefix_len: u8,
    data: Bytes,
    suffix: &'static [u8],
    /// Bytes of prefix + data + suffix written so far.
    written: usize,
}

impl Outgoing {
    pub fn new(prefix: &[u8], data: Bytes, suffix: &'static [u8]) -> Outgoing {
        let mut out = Outgoing {
            prefix_len: prefix.len() as u8,
            data,
            suffix,
            ..Default::default()
        };
        out.prefix[..prefix.len()].copy_from_slice(prefix);
        out
    }

    fn len(&self) -> usize {
        self.prefix_len as usize + self.data.len() + self.suffix.len()
    }

    pub fn is_done(&self) -> bool {
        self.written >= self.len()
    }

    /// Write what is left. Ready(Ok(n)) after each write that made progress (n > 0),
    /// so that the caller can count it; done once [`Outgoing::is_done`].
    pub fn poll_write<S: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let prefix = &self.prefix[..self.prefix_len as usize];
        let skip = self.written;
        let (p, rest) = (prefix.get(skip..).unwrap_or(&[]), skip.saturating_sub(prefix.len()));
        let d = self.data.get(rest..).unwrap_or(&[]);
        let s = self.suffix.get(rest.saturating_sub(self.data.len())..).unwrap_or(&[]);
        let n = if p.is_empty() && s.is_empty() {
            ready!(Pin::new(&mut *io).poll_write(cx, d))?
        } else if io.is_write_vectored() {
            let bufs = [io::IoSlice::new(p), io::IoSlice::new(d), io::IoSlice::new(s)];
            ready!(Pin::new(&mut *io).poll_write_vectored(cx, &bufs))?
        } else {
            // Gather into one TLS record. The copy is the price of not sending a
            // record of a few bytes for each chunk-size line.
            let mut all = Vec::with_capacity(p.len() + d.len() + s.len());
            all.extend_from_slice(p);
            all.extend_from_slice(d);
            all.extend_from_slice(s);
            ready!(Pin::new(&mut *io).poll_write(cx, &all))?
        };
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        self.written += n;
        if self.is_done() {
            // Let go of the chunk as soon as it is written.
            self.data = Bytes::new();
        }
        Poll::Ready(Ok(n))
    }
}

/// A resettable deadline for "no progress for this long". Allocated once per
/// request (it boxes a tokio `Sleep`), never per connection.
pub struct Timer {
    sleep: Option<Pin<Box<Sleep>>>,
    armed: bool,
}

impl Timer {
    pub fn new() -> Timer {
        Timer {
            sleep: None,
            armed: false,
        }
    }

    /// Start the clock unless it is already running.
    pub fn arm(&mut self, after: Duration) {
        if !self.armed {
            self.rearm(after);
        }
    }

    /// Restart the clock from now.
    pub fn rearm(&mut self, after: Duration) {
        let deadline = Instant::now() + after;
        match &mut self.sleep {
            Some(s) => s.as_mut().reset(deadline),
            None => self.sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
        self.armed = true;
    }

    /// Stop the clock.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Whether the armed clock has run out. Registers the waker if not.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> bool {
        match (&mut self.sleep, self.armed) {
            (Some(s), true) => s.as_mut().poll(cx).is_ready(),
            _ => false,
        }
    }

    /// For an operation that just returned `Pending`: arm the clock (if it is not
    /// running) and fail with `TimedOut` once it runs out.
    pub fn poll_stall<T>(&mut self, cx: &mut Context<'_>, after: Duration) -> Poll<io::Result<T>> {
        self.arm(after);
        if self.poll_expired(cx) {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "peer stalled")))
        } else {
            Poll::Pending
        }
    }
}

/// Set up an accepted downstream socket: no Nagle delay, and a bound on the unsent
/// data the kernel keeps for it.
///
/// `TCP_NOTSENT_LOWAT`: a write waits while the socket has this much it could not
/// send yet. Without it, the send buffer takes as much as autotuning grows it to (up
/// to 4 MB by default), and a client that stops reading leaves it full: 2.5 MB per
/// connection on loopback, more than torii itself held for the stalled request.
/// Data in flight is not limited, so neither is throughput.
pub fn setup_downstream(tcp: &TcpStream) {
    let _ = tcp.set_nodelay(true);
    #[cfg(target_os = "linux")]
    if let Err(e) = socket2::SockRef::from(tcp).set_tcp_notsent_lowat(super::CLIENT_NOTSENT_LOWAT) {
        tracing::debug!(error = %e, "setting TCP_NOTSENT_LOWAT failed");
    }
}

/// Set up a socket to a backend: no Nagle delay, and TCP keepalive, so that a
/// backend that vanished without a FIN or RST (node power loss, a dropped conntrack
/// entry) is noticed by a connection waiting with no timeout: a pooled one, one
/// whose route disables its timeouts, or a TLSRoute pipe until its idle timeout.
pub fn setup_upstream(tcp: &TcpStream) {
    let _ = tcp.set_nodelay(true);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let keepalive = keepalive.with_retries(3);
    if let Err(e) = socket2::SockRef::from(tcp).set_tcp_keepalive(&keepalive) {
        tracing::debug!(error = %e, "setting TCP keepalive failed");
    }
}
