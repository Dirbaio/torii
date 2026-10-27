//! Connections to backends: connecting (TCP, and TLS for a BackendTLSPolicy), and
//! the pool of idle HTTP/1.1 connections kept for reuse.
//!
//! A pooled connection holds its socket (and TLS state) and no buffer, and nothing
//! runs for it: whether the backend closed it, or sent something unasked, is checked
//! when it is taken, and [`Pool::sweep`] closes the ones that idled out or that the
//! backend closed meanwhile.

use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Waker};
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::io::{Stream, setup_upstream};
use super::tls::{Client, ClientIdentity, Clients};
use crate::route_table::{BackendTls, Endpoint, UpstreamTls};

/// How long a pooled connection may stay idle (nginx's upstream `keepalive_timeout`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How often [`Pool::sweep`] looks for connections to close.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);
/// Most requests one backend connection serves (nginx's `keepalive_requests`).
const MAX_REQUESTS: u32 = 1000;
/// Most idle connections kept per backend endpoint, and in all. Each costs a socket
/// and ~1-2 KB. Room for a backend's usual concurrency matters more than the bytes:
/// a connection the pool has no room for is closed, and its port then sits in
/// TIME_WAIT for a minute, so a pool smaller than the requests in flight churns
/// through the ephemeral ports (32 per endpoint ran them out within seconds at 64
/// concurrent requests, and requests got 502s).
const MAX_IDLE_PER_KEY: usize = 256;
const MAX_IDLE: usize = 1024;

/// Which pooled connections are interchangeable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    addr: SocketAddr,
    tls: Option<ClientIdentity>,
}

/// A connection to a backend, with its read buffer.
pub struct Upstream {
    pub stream: Stream,
    pub buf: BytesMut,
    key: PoolKey,
    requests: u32,
    /// It came from the pool (so the backend may have closed it meanwhile).
    pub reused: bool,
}

/// Connect to `ep` for an HTTP request, reusing a pooled connection if there is
/// one. `timeout` bounds the whole connect, TLS handshake included.
pub async fn connect_http(
    pool: &Arc<Pool>,
    clients: &Clients,
    ep: &Endpoint,
    timeout: Option<Duration>,
    fresh: bool,
) -> io::Result<Upstream> {
    let addr = SocketAddr::new(ep.ip, ep.port);
    let tls = match &ep.tls {
        BackendTls::Plaintext => None,
        BackendTls::ReEncrypt(tls) => Some(tls),
        BackendTls::Invalid => return Err(io::Error::other("backend has an invalid BackendTLSPolicy")),
    };
    // The identity of a TLS connection depends on its CA bundle: resolve it first
    // (from the client-context cache), so pooled connections can be matched.
    let client = tls.map(|tls| clients.client(tls, true));
    let key = PoolKey {
        addr,
        tls: client.as_ref().map(|c| c.identity.clone()),
    };
    if !fresh && let Some(up) = pool.take(&key) {
        return Ok(up);
    }
    let stream = connect(addr, client.as_ref(), timeout).await?;
    Ok(Upstream {
        stream,
        buf: BytesMut::new(),
        key,
        requests: 0,
        reused: false,
    })
}

/// Connect to a TLSRoute backend: plain TCP, or TLS (offering no ALPN) when a
/// BackendTLSPolicy re-encrypts to it. Never pooled.
pub async fn connect_raw(
    clients: &Clients,
    ep: &Endpoint,
    tls: Option<&UpstreamTls>,
    timeout: Option<Duration>,
) -> io::Result<Stream> {
    let addr = SocketAddr::new(ep.ip, ep.port);
    let client = tls.map(|tls| clients.client(tls, false));
    connect(addr, client.as_ref(), timeout).await
}

/// Connect to `addr`, and run the TLS handshake if there is a `client`.
async fn connect(addr: SocketAddr, client: Option<&Client>, timeout: Option<Duration>) -> io::Result<Stream> {
    with_timeout(timeout, async {
        let tcp = TcpStream::connect(addr).await?;
        setup_upstream(&tcp);
        Ok(match client {
            None => Stream::Plain(tcp),
            Some(client) => Stream::Tls(Box::new(client.connect(tcp).await?)),
        })
    })
    .await
}

async fn with_timeout<T>(timeout: Option<Duration>, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    match timeout {
        Some(t) => tokio::time::timeout(t, f)
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "backend connect timed out"))),
        None => f.await,
    }
}

/// Idle connections to backends.
#[derive(Default)]
pub struct Pool {
    inner: Mutex<PoolInner>,
}

#[derive(Default)]
struct PoolInner {
    /// Per key, oldest first.
    idle: HashMap<PoolKey, Vec<Idle>>,
    count: usize,
}

/// A pooled connection, and since when it has been idle.
struct Idle {
    up: Upstream,
    since: Instant,
}

impl Idle {
    /// Whether it may serve another request.
    fn usable(&mut self) -> bool {
        self.since.elapsed() < IDLE_TIMEOUT && is_idle(&mut self.up.stream)
    }
}

impl Pool {
    fn lock(&self) -> MutexGuard<'_, PoolInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Keep `up` for reuse, if it may be and there is room.
    pub fn put(&self, mut up: Upstream) {
        up.requests += 1;
        if up.requests >= MAX_REQUESTS || !up.buf.is_empty() {
            return;
        }
        up.buf = BytesMut::new();
        up.reused = true;
        let mut inner = self.lock();
        if inner.count >= MAX_IDLE {
            return;
        }
        let list = inner.idle.entry(up.key.clone()).or_default();
        if list.len() >= MAX_IDLE_PER_KEY {
            return;
        }
        list.push(Idle {
            up,
            since: Instant::now(),
        });
        inner.count += 1;
    }

    /// The most recently pooled connection for `key` that is still usable, if any.
    fn take(&self, key: &PoolKey) -> Option<Upstream> {
        loop {
            let mut idle = {
                let mut inner = self.lock();
                let list = inner.idle.get_mut(key)?;
                let idle = list.pop();
                if list.is_empty() {
                    inner.idle.remove(key);
                }
                let idle = idle?;
                inner.count -= 1;
                idle
            };
            if idle.usable() {
                return Some(idle.up);
            }
        }
    }

    /// Close, every [`SWEEP_INTERVAL`], the pooled connections that idled out or
    /// that the backend closed. Runs for as long as the data plane does.
    pub async fn sweep(self: Arc<Self>) {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            let mut closed = Vec::new();
            let mut inner = self.lock();
            inner.idle.retain(|_, list| {
                closed.extend(list.extract_if(.., |idle| !idle.usable()));
                !list.is_empty()
            });
            inner.count -= closed.len();
            // The sockets close (and TLS state is freed) once the lock is let go.
            drop(inner);
        }
    }
}

/// Whether a pooled connection is as it was left: nothing to read, not even an
/// EOF. A byte the backend sent unasked, or its close, makes it unusable.
///
/// A connection the event loop has seen no event for answers without a syscall.
fn is_idle(stream: &mut Stream) -> bool {
    let mut byte = [MaybeUninit::uninit()];
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(stream)
        .poll_read(&mut cx, &mut ReadBuf::uninit(&mut byte))
        .is_pending()
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// A backend, a pool, and one connection to the backend in the pool.
    async fn pooled() -> (TcpListener, TcpStream, Arc<Pool>, PoolKey) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ep = Endpoint {
            ip: addr.ip(),
            port: addr.port(),
            tls: BackendTls::Plaintext,
        };
        let pool = Arc::new(Pool::default());
        let up = connect_http(&pool, &Clients::default(), &ep, None, false)
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let key = up.key.clone();
        pool.put(up);
        (listener, server, pool, key)
    }

    #[tokio::test]
    async fn a_connection_the_backend_closed_is_not_reused() {
        let (_listener, server, pool, key) = pooled().await;
        let up = pool.take(&key).expect("an open connection is reused");
        pool.put(up);
        drop(server);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pool.take(&key).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_idled_out_is_not_reused() {
        let (_listener, _server, pool, key) = pooled().await;
        tokio::time::advance(IDLE_TIMEOUT).await;
        assert!(pool.take(&key).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_sweep_closes_connections_that_idled_out() {
        let (_listener, mut server, pool, _key) = pooled().await;
        tokio::spawn(pool.clone().sweep());
        tokio::time::sleep(IDLE_TIMEOUT + SWEEP_INTERVAL).await;
        assert_eq!(pool.lock().count, 0);
        let mut buf = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(&mut server, &mut buf).await.unwrap();
        assert_eq!(n, 0, "the backend sees the close");
    }
}
