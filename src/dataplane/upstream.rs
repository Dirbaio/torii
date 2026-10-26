//! Connections to backends: connecting (TCP, and TLS for a BackendTLSPolicy), and
//! the pool of idle HTTP/1.1 connections kept for reuse.
//!
//! A pooled connection holds its socket (and TLS state), and a small task that
//! watches it: the connection is dropped as soon as the backend closes it or sends
//! something unasked, or after [`IDLE_TIMEOUT`]. It holds no buffer.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_openssl::SslStream;

use super::io::{Stream, read_lazy, setup_upstream};
use super::tls::{ClientIdentity, Clients};
use crate::route_table::{BackendTls, Endpoint, UpstreamTls};

/// How long a pooled connection may stay idle (nginx's upstream `keepalive_timeout`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Most requests one backend connection serves (nginx's `keepalive_requests`).
const MAX_REQUESTS: u32 = 1000;
/// Most idle connections kept per backend endpoint, and in all.
const MAX_IDLE_PER_KEY: usize = 32;
const MAX_IDLE: usize = 512;

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
    if !fresh && let Some(up) = pool.take(&key).await {
        return Ok(up);
    }
    let ssl = match &client {
        Some(c) => Some(c.ssl().ok_or_else(|| io::Error::other("TLS setup failed"))?),
        None => None,
    };
    let stream = with_timeout(timeout, async {
        let tcp = TcpStream::connect(addr).await?;
        setup_upstream(&tcp);
        Ok(match ssl {
            None => Stream::Plain(tcp),
            Some(ssl) => Stream::Tls(tls_connect(ssl, tcp).await?),
        })
    })
    .await?;
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
    let ssl = match tls {
        Some(tls) => Some(
            clients
                .client(tls, false)
                .ssl()
                .ok_or_else(|| io::Error::other("TLS setup failed"))?,
        ),
        None => None,
    };
    with_timeout(timeout, async {
        let tcp = TcpStream::connect(addr).await?;
        setup_upstream(&tcp);
        Ok(match ssl {
            None => Stream::Plain(tcp),
            Some(ssl) => Stream::Tls(tls_connect(ssl, tcp).await?),
        })
    })
    .await
}

async fn tls_connect(ssl: openssl::ssl::Ssl, tcp: TcpStream) -> io::Result<SslStream<TcpStream>> {
    let mut stream = SslStream::new(ssl, tcp).map_err(io::Error::other)?;
    Pin::new(&mut stream).connect().await.map_err(io::Error::other)?;
    Ok(stream)
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
    idle: HashMap<PoolKey, Vec<Idle>>,
    count: usize,
    next_id: u64,
}

/// A pooled connection, as the pool sees it: a way to ask its watcher for it.
struct Idle {
    id: u64,
    take: oneshot::Sender<oneshot::Sender<Upstream>>,
}

impl Pool {
    /// Keep `up` for reuse, if it may be and there is room.
    pub fn put(self: &Arc<Self>, mut up: Upstream) {
        up.requests += 1;
        if up.requests >= MAX_REQUESTS || !up.buf.is_empty() {
            return;
        }
        up.buf = BytesMut::new();
        up.reused = true;
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.count >= MAX_IDLE {
                return;
            }
            let id = inner.next_id;
            inner.next_id += 1;
            let list = inner.idle.entry(up.key.clone()).or_default();
            if list.len() >= MAX_IDLE_PER_KEY {
                return;
            }
            list.push(Idle { id, take: tx });
            inner.count += 1;
            id
        };
        tokio::spawn(watch(self.clone(), id, up, rx));
    }

    /// The most recently pooled connection for `key`, if any is still open.
    async fn take(&self, key: &PoolKey) -> Option<Upstream> {
        loop {
            let idle = {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let list = inner.idle.get_mut(key)?;
                let idle = list.pop();
                if list.is_empty() {
                    inner.idle.remove(key);
                }
                let idle = idle?;
                inner.count -= 1;
                idle
            };
            let (tx, rx) = oneshot::channel();
            if idle.take.send(tx).is_err() {
                continue;
            }
            if let Ok(up) = rx.await {
                return Some(up);
            }
        }
    }

    /// Forget a pooled connection whose watcher dropped it.
    fn remove(&self, key: &PoolKey, id: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = inner.idle.get_mut(key) else {
            return;
        };
        let Some(i) = list.iter().position(|idle| idle.id == id) else {
            return;
        };
        list.swap_remove(i);
        if list.is_empty() {
            inner.idle.remove(key);
        }
        inner.count -= 1;
    }
}

/// Hold a pooled connection until it is taken, the backend closes it, or it has
/// idled for [`IDLE_TIMEOUT`].
async fn watch(pool: Arc<Pool>, id: u64, mut up: Upstream, take: oneshot::Receiver<oneshot::Sender<Upstream>>) {
    let taken = {
        let closed = async {
            // Any byte or EOF makes the connection unusable: nothing was asked.
            let mut buf = BytesMut::new();
            let _ = read_lazy(&mut up.stream, &mut buf, 1).await;
        };
        tokio::select! {
            r = take => r.ok(),
            () = closed => None,
            () = tokio::time::sleep(IDLE_TIMEOUT) => None,
        }
    };
    match taken {
        Some(tx) => {
            let _ = tx.send(up);
        }
        None => pool.remove(&up.key, id),
    }
}
