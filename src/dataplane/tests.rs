//! End-to-end tests of the data plane: a gateway on a loopback port with a
//! hand-built snapshot, backends as in-process HTTP/1.1 servers, and raw clients.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

use super::h1::{self, Decoder, HeadEvent, HeadReader};
use super::*;
use crate::conn_limit::Caps;
use crate::route_table::{Backend, Endpoint, Filters, RouteEntry, RouteMatch, RouteTable};

const NO_LIMITS: ConnLimits = ConnLimits {
    connections: Caps {
        per_source: None,
        total: None,
    },
    requests: Caps {
        per_source: None,
        total: None,
    },
};

const TIMEOUTS: UpstreamTimeouts = UpstreamTimeouts {
    connect: Some(Duration::from_secs(5)),
    response: Some(Duration::from_secs(5)),
};

fn ctx_with(routes: RouteTable, timeouts: UpstreamTimeouts, limits: ConnLimits) -> Arc<Ctx> {
    let snapshot = crate::snapshot::Snapshot {
        routes,
        ..Default::default()
    };
    ctx_from(snapshot, timeouts, limits, CLIENT_STALL_TIMEOUT)
}

fn ctx_from(
    snapshot: crate::snapshot::Snapshot,
    timeouts: UpstreamTimeouts,
    limits: ConnLimits,
    client_stall: Duration,
) -> Arc<Ctx> {
    let data_plane = DataPlane::new();
    data_plane.store(snapshot);
    Arc::new(Ctx {
        tls: Some(tls::Server::new(data_plane.clone())),
        data_plane,
        timeouts,
        allow_encoded_slashes: false,
        client_stall,
        limiter: ConnLimiter::new(limits),
        pool: Arc::default(),
        clients: tls::Clients::default(),
        shutdown: watch::Sender::new(false),
        live: Live::default(),
    })
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        ip: addr.ip(),
        port: addr.port(),
        tls: Default::default(),
    }
}

/// A route table whose one route on `port` sends everything to `backend`.
fn one_route(port: u16, backend: SocketAddr, filters: Filters, timeout: Option<Duration>) -> RouteTable {
    let mut routes = RouteTable::default();
    routes.entries.push(RouteEntry {
        listener_port: port,
        listener_hostname: None,
        hostnames: vec![],
        r#match: RouteMatch::default(),
        backends: vec![Backend {
            weight: 1,
            endpoints: vec![endpoint(backend)],
            filters: Filters::default(),
        }],
        filters,
        request_timeout: timeout,
        route_creation: 0,
        route_key: "ns/route".into(),
        rule_order: 0,
        match_order: 0,
    });
    routes.sort();
    routes
}

struct Gateway {
    addr: SocketAddr,
    _stop: watch::Sender<bool>,
}

/// A gateway on a loopback port, with the routes `routes` builds for that port.
async fn gateway(routes: impl FnOnce(u16) -> RouteTable) -> Gateway {
    gateway_with(routes, TIMEOUTS, NO_LIMITS).await
}

async fn gateway_with(
    routes: impl FnOnce(u16) -> RouteTable,
    timeouts: UpstreamTimeouts,
    limits: ConnLimits,
) -> Gateway {
    let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = ctx_with(routes(addr.port()), timeouts, limits);
    let (stop, stop_rx) = watch::channel(false);
    tokio::spawn(accept_loop(ctx, listener, false, stop_rx));
    Gateway { addr, _stop: stop }
}

/// A backend that answers each request with what it got:
/// `<method> <target>\n<name>: <value>\n...\n\n<body>`, and counts connections.
async fn echo_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    backend(|_head, _body| None).await
}

/// A backend whose response is `respond(head, body)`'s raw bytes, or the echo.
async fn backend(
    respond: impl Fn(&h1::RequestHead, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let respond = Arc::new(respond);
    let counter = conns.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let respond = respond.clone();
            tokio::spawn(async move {
                let mut buf = BytesMut::new();
                loop {
                    let mut reader = HeadReader::new(1024, 1 << 20);
                    let Ok(HeadEvent::Complete(n)) = std::future::poll_fn(|cx| reader.poll(cx, &mut s, &mut buf)).await
                    else {
                        return;
                    };
                    let head = h1::parse_request(&buf.split_to(n)).unwrap();
                    let mut decoder = Decoder::for_request(h1::request_framing(&head).unwrap());
                    let mut body = Vec::new();
                    while !decoder.is_done() {
                        match decoder.decode(&mut buf, 1 << 20).unwrap() {
                            Some(d) => body.extend_from_slice(&d),
                            None if decoder.is_done() => break,
                            None => {
                                if s.read_buf(&mut buf).await.unwrap() == 0 {
                                    return;
                                }
                            }
                        }
                    }
                    let out = respond(&head, &body).unwrap_or_else(|| {
                        let mut text = format!("{} {}\n", head.method(), String::from_utf8_lossy(head.target()));
                        for (n, v) in head.fields.iter() {
                            text += &format!("{}: {}\n", String::from_utf8_lossy(n), String::from_utf8_lossy(v));
                        }
                        text += "\n";
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{text}",
                            text.len() + body.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&body);
                        out
                    });
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, conns)
}

/// A response as a client saw it.
#[derive(Debug)]
struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Resp {
    fn field(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

/// Read one response; None at EOF.
async fn read_response(s: &mut (impl tokio::io::AsyncRead + Unpin), buf: &mut BytesMut, method: &str) -> Option<Resp> {
    let mut reader = HeadReader::new(1024, 1 << 20);
    let HeadEvent::Complete(n) = std::future::poll_fn(|cx| reader.poll(cx, s, buf)).await.ok()? else {
        return None;
    };
    let raw = buf.split_to(n);
    let head = h1::parse_response(&raw).unwrap();
    let mut decoder = Decoder::for_response(h1::response_framing(&head, method).unwrap());
    let mut body = Vec::new();
    loop {
        match decoder.decode(buf, 1 << 20).unwrap() {
            Some(d) => body.extend_from_slice(&d),
            None if decoder.is_done() => break,
            None => {
                if s.read_buf(buf).await.unwrap() == 0 {
                    decoder.on_eof().unwrap();
                }
            }
        }
    }
    Some(Resp {
        status: head.status,
        head: String::from_utf8_lossy(&raw).into_owned(),
        body,
    })
}

/// Send `req` on a new connection and read the response.
async fn request(addr: SocketAddr, req: &str) -> Option<Resp> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let method = req.split(' ').next().unwrap();
    read_response(&mut s, &mut BytesMut::new(), method).await
}

#[tokio::test]
async fn proxies_a_request_with_forwarded_headers() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let resp = request(
        gw.addr,
        "GET /a/./b/../c?x=1 HTTP/1.1\r\nHost: web.example:8080\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: keep-alive, X-Drop\r\nX-Drop: 1\r\nKeep-Alive: 5\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(resp.status, 200);
    let echo = String::from_utf8(resp.body).unwrap();
    assert!(echo.starts_with("GET /a/c?x=1\n"), "{echo}");
    assert!(echo.contains("Host: web.example:8080\n"), "{echo}");
    assert!(echo.contains("X-Forwarded-For: 127.0.0.1\n"), "{echo}");
    assert!(!echo.contains("6.6.6.6"), "{echo}");
    assert!(echo.contains("X-Forwarded-Host: web.example\n"), "{echo}");
    assert!(
        echo.contains(&format!("X-Forwarded-Port: {}\n", gw.addr.port())),
        "{echo}"
    );
    assert!(echo.contains("X-Forwarded-Proto: http\n"), "{echo}");
    assert!(!echo.to_ascii_lowercase().contains("x-drop"), "{echo}");
    assert!(!echo.to_ascii_lowercase().contains("keep-alive"), "{echo}");
}

#[tokio::test]
async fn local_answers() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port + 1, backend, Filters::default(), None)).await;
    let resp = request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    assert_eq!(resp.status, 404);
    let resp = request(gw.addr, "GET /a%00 HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    assert_eq!(resp.status, 400);
    let resp = request(gw.addr, "GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert_eq!(resp.status, 400, "HTTP/1.1 without Host");
    let resp = request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status, 400, "two Hosts");
}

#[tokio::test]
async fn keep_alive_reuses_the_backend_connection() {
    let (backend, conns) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let mut s = TcpStream::connect(gw.addr).await.unwrap();
    let mut buf = BytesMut::new();
    for i in 0..3 {
        s.write_all(format!("GET /{i} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let resp = read_response(&mut s, &mut buf, "GET").await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(String::from_utf8_lossy(&resp.body).starts_with(&format!("GET /{i}\n")));
    }
    assert_eq!(conns.load(Ordering::SeqCst), 1, "one backend connection, pooled");
    // Pipelined requests are answered in order.
    s.write_all(b"GET /p1 HTTP/1.1\r\nHost: a\r\n\r\nGET /p2 HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    for p in ["/p1", "/p2"] {
        let resp = read_response(&mut s, &mut buf, "GET").await.unwrap();
        assert!(String::from_utf8_lossy(&resp.body).starts_with(&format!("GET {p}\n")));
    }
}

#[tokio::test]
async fn forwards_request_bodies() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let resp = request(gw.addr, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello")
        .await
        .unwrap();
    let echo = String::from_utf8(resp.body).unwrap();
    assert!(
        echo.contains("Content-Length: 5\n") && echo.ends_with("\n\nhello"),
        "{echo}"
    );

    let resp = request(
        gw.addr,
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nT: 1\r\n\r\n",
    )
    .await
    .unwrap();
    let echo = String::from_utf8(resp.body).unwrap();
    assert!(
        echo.contains("Transfer-Encoding: chunked\n") && echo.ends_with("\n\nabcde"),
        "{echo}"
    );

    // A large body, in many chunks.
    let body = "x".repeat(300_000);
    let resp = request(
        gw.addr,
        &format!(
            "PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
    .unwrap();
    assert!(resp.body.ends_with(body.as_bytes()));

    // Expect: 100-continue is answered by torii.
    let mut s = TcpStream::connect(gw.addr).await.unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n")
        .await
        .unwrap();
    let mut buf = BytesMut::new();
    let cont = read_response(&mut s, &mut buf, "GET").await.unwrap();
    assert_eq!(cont.status, 100);
    s.write_all(b"ok").await.unwrap();
    let resp = read_response(&mut s, &mut buf, "POST").await.unwrap();
    let echo = String::from_utf8(resp.body).unwrap();
    assert!(
        echo.ends_with("\n\nok") && !echo.to_ascii_lowercase().contains("expect"),
        "{echo}"
    );
}

#[tokio::test]
async fn refuses_ambiguous_framing() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    for (req, status) in [
        (
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            400,
        ),
        ("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", 501),
        (
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
            400,
        ),
        (
            "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            400,
        ),
        ("GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n", 400),
    ] {
        let resp = request(gw.addr, req).await.unwrap();
        assert_eq!(resp.status, status, "{req:?}");
        assert_eq!(resp.field("connection").as_deref(), Some("close"), "{req:?}");
    }
}

#[tokio::test]
async fn refuses_large_heads() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let big = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n", "y".repeat(70_000));
    assert_eq!(request(gw.addr, &big).await.unwrap().status, 431);
    let many: String = (0..300).map(|i| format!("X-{i}: 1\r\n")).collect();
    let req = format!("GET / HTTP/1.1\r\nHost: a\r\n{many}\r\n");
    assert_eq!(request(gw.addr, &req).await.unwrap().status, 431);
}

#[tokio::test]
async fn relays_response_framings() {
    let (backend, _) = backend(|head, _| {
        Some(match head.target() {
            b"/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec(),
            b"/head" => b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".to_vec(),
            b"/interim" => b"HTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            _ => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nProxy-Connection: x\r\n\r\nhi".to_vec(),
        })
    })
    .await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let resp = request(gw.addr, "GET /chunked HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        (resp.body.as_slice(), resp.field("transfer-encoding").as_deref()),
        (&b"abc"[..], Some("chunked"))
    );
    // An HTTP/1.0 client gets a body that ends at close.
    let resp = request(gw.addr, "GET /chunked HTTP/1.0\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.body, b"abc");
    assert_eq!(resp.field("transfer-encoding"), None);
    let resp = request(gw.addr, "HEAD /head HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.field("content-length").as_deref(), Some("10"));
    // An interim response is passed on, then the final one.
    let mut s = TcpStream::connect(gw.addr).await.unwrap();
    s.write_all(b"GET /interim HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    let mut buf = BytesMut::new();
    let hints = read_response(&mut s, &mut buf, "GET").await.unwrap();
    assert_eq!((hints.status, hints.field("link").as_deref()), (103, Some("x")));
    assert_eq!(read_response(&mut s, &mut buf, "GET").await.unwrap().status, 204);
    // Not to an HTTP/1.0 client.
    let resp = request(gw.addr, "GET /interim HTTP/1.0\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status, 204);
    let resp = request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    assert_eq!(resp.body, b"hi");
    assert_eq!(resp.field("proxy-connection"), None);
    assert_eq!(resp.field("connection"), None, "the backend's Connection is its own");
}

#[tokio::test]
async fn backend_failures() {
    // Refused connection: 502.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let gw = gateway(|port| one_route(port, closed, Filters::default(), None)).await;
    assert_eq!(
        request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap()
            .status,
        502
    );

    // Silent backend: 504 after the rule's timeout.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(silent.accept().await.unwrap());
        }
    });
    let gw = gateway(|port| one_route(port, addr, Filters::default(), Some(Duration::from_millis(200)))).await;
    let start = std::time::Instant::now();
    assert_eq!(
        request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap()
            .status,
        504
    );
    assert!(start.elapsed() < Duration::from_secs(2));

    // Malformed response: 502.
    let (bad, _) =
        backend(|_, _| Some(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx".to_vec())).await;
    let gw = gateway(|port| one_route(port, bad, Filters::default(), None)).await;
    assert_eq!(
        request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap()
            .status,
        502
    );
}

#[tokio::test]
async fn a_stale_pooled_connection_is_retried() {
    // A backend that answers one request per connection, then closes it without
    // saying so.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            });
        }
    });
    let gw = gateway(|port| one_route(port, addr, Filters::default(), None)).await;
    for _ in 0..3 {
        let resp = request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
        assert_eq!(resp.status, 200);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn upgrades_to_a_websocket_pipe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = BytesMut::new();
        let mut reader = HeadReader::new(1024, 1 << 20);
        let HeadEvent::Complete(n) = std::future::poll_fn(|cx| reader.poll(cx, &mut s, &mut buf))
            .await
            .unwrap()
        else {
            return;
        };
        let head = h1::parse_request(&buf.split_to(n)).unwrap();
        assert!(head.fields.has_token("connection", "upgrade"));
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\nhello")
            .await
            .unwrap();
        // Echo what follows.
        let mut b = [0u8; 64];
        let n = s.read(&mut b).await.unwrap();
        s.write_all(&b[..n]).await.unwrap();
    });
    let gw = gateway(|port| one_route(port, addr, Filters::default(), None)).await;
    let mut s = TcpStream::connect(gw.addr).await.unwrap();
    s.write_all(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        .await
        .unwrap();
    let mut buf = BytesMut::new();
    let mut reader = HeadReader::new(1024, 1 << 20);
    let HeadEvent::Complete(n) = std::future::poll_fn(|cx| reader.poll(cx, &mut s, &mut buf))
        .await
        .unwrap()
    else {
        panic!()
    };
    let head = h1::parse_response(&buf.split_to(n)).unwrap();
    assert_eq!(head.status, 101);
    while buf.len() < 5 {
        s.read_buf(&mut buf).await.unwrap();
    }
    assert_eq!(&buf[..5], b"hello");
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
}

#[tokio::test]
async fn request_caps_answer_503() {
    let (backend, _) = backend(|_, _| None).await;
    let limits = ConnLimits {
        requests: Caps {
            per_source: Some(1),
            total: None,
        },
        ..NO_LIMITS
    };
    // A backend that never answers holds the one slot.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(silent.accept().await.unwrap());
        }
    });
    let _ = backend;
    let gw = gateway_with(
        |port| one_route(port, silent_addr, Filters::default(), None),
        TIMEOUTS,
        limits,
    )
    .await;
    let mut first = TcpStream::connect(gw.addr).await.unwrap();
    first.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        request(gw.addr, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap()
            .status,
        503
    );
}

#[tokio::test]
async fn connection_caps_close_connections() {
    let (backend, _) = echo_backend().await;
    let limits = ConnLimits {
        connections: Caps {
            per_source: Some(2),
            total: None,
        },
        ..NO_LIMITS
    };
    let gw = gateway_with(
        |port| one_route(port, backend, Filters::default(), None),
        TIMEOUTS,
        limits,
    )
    .await;
    let _a = TcpStream::connect(gw.addr).await.unwrap();
    let _b = TcpStream::connect(gw.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut c = TcpStream::connect(gw.addr).await.unwrap();
    let mut b = [0u8; 1];
    assert_eq!(c.read(&mut b).await.unwrap_or(0), 0, "the third connection is closed");
}

/// Serve one client connection over an in-memory stream (for the paused clock).
fn serve_duplex(ctx: &Arc<Ctx>) -> tokio::io::DuplexStream {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let info = ConnInfo {
            port: 0,
            peer: None,
            tls: false,
        };
        serve_h1::serve(&ctx, io::Stream::Duplex(server), &info).await;
    });
    client
}

#[tokio::test(start_paused = true)]
async fn a_trickled_head_gets_408() {
    let ctx = ctx_with(RouteTable::default(), TIMEOUTS, NO_LIMITS);
    let mut client = serve_duplex(&ctx);
    let start = tokio::time::Instant::now();
    // One byte every 10 s: each read is quick, the head as a whole is not.
    for b in b"GET / HTTP/1.1\r\nHost: a\r\nX: ".iter() {
        if client.write_all(&[*b]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
        if start.elapsed() > H1_HEAD_TIMEOUT + Duration::from_secs(20) {
            break;
        }
    }
    let resp = read_response(&mut client, &mut BytesMut::new(), "GET").await.unwrap();
    assert_eq!(resp.status, 408);
    assert!(start.elapsed() <= H1_HEAD_TIMEOUT + Duration::from_secs(11));
}

#[tokio::test(start_paused = true)]
async fn an_idle_connection_is_closed() {
    let ctx = ctx_with(RouteTable::default(), TIMEOUTS, NO_LIMITS);
    let mut client = serve_duplex(&ctx);
    let start = tokio::time::Instant::now();
    let mut b = [0u8; 1];
    assert_eq!(client.read(&mut b).await.unwrap(), 0);
    assert!(start.elapsed() >= H1_IDLE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn the_idle_clock_restarts_with_each_request() {
    let ctx = ctx_with(RouteTable::default(), TIMEOUTS, NO_LIMITS);
    let mut client = serve_duplex(&ctx);
    let start = tokio::time::Instant::now();
    // Each request comes within the idle timeout of the one before, not of the
    // first: all are served (a 404, keeping the connection).
    let gap = H1_IDLE_TIMEOUT - Duration::from_secs(10);
    for _ in 0..3 {
        client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
        let resp = read_response(&mut client, &mut BytesMut::new(), "GET").await.unwrap();
        assert_eq!(resp.status, 404);
        tokio::time::sleep(gap).await;
    }
    let mut b = [0u8; 1];
    assert_eq!(client.read(&mut b).await.unwrap(), 0);
    assert!(start.elapsed() >= 2 * gap + H1_IDLE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn an_idle_h2_connection_is_closed_after_its_last_stream() {
    let ctx = ctx_with(RouteTable::default(), TIMEOUTS, NO_LIMITS);
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let info = ConnInfo {
            port: 0,
            peer: None,
            tls: true,
        };
        serve_h2::serve(&ctx, io::Stream::Duplex(server), &info).await;
    });
    let (mut client, conn) = h2::client::handshake(client).await.unwrap();
    let conn = tokio::spawn(conn);
    let start = tokio::time::Instant::now();
    let gap = H2_IDLE_TIMEOUT - Duration::from_secs(10);
    tokio::time::sleep(gap).await;
    let req = http::Request::builder().uri("https://a/").body(()).unwrap();
    let resp = client.send_request(req, true).unwrap().0.await.unwrap();
    assert_eq!(resp.status(), 404);
    let _ = conn.await;
    assert!(start.elapsed() >= gap + H2_IDLE_TIMEOUT);
}

#[tokio::test]
async fn a_client_that_stops_reading_is_cut_off() {
    tokio::time::pause();
    let (backend, _) = backend(|_, _| {
        let body = vec![b'x'; 8 << 20];
        let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend(body);
        Some(out)
    })
    .await;
    let ctx = ctx_with(
        one_route(0, backend, Filters::default(), None),
        UpstreamTimeouts {
            connect: None,
            response: None,
        },
        NO_LIMITS,
    );
    let mut client = serve_duplex(&ctx);
    client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    // Read the start of the response (so the exchange runs), then stop reading:
    // after the stall timeout torii gives up and closes.
    let mut b = vec![0u8; 1 << 16];
    let mut total = client.read(&mut b).await.unwrap();
    tokio::time::sleep(CLIENT_STALL_TIMEOUT + Duration::from_secs(5)).await;
    loop {
        match client.read(&mut b).await {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    assert!(total < 8 << 20, "the response was cut short ({total} bytes)");
}

#[tokio::test]
async fn h2_proxies_requests() {
    let (backend, conns) = echo_backend().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = ctx_with(
        one_route(addr.port(), backend, Filters::default(), None),
        TIMEOUTS,
        NO_LIMITS,
    );
    tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let info = ConnInfo {
            port: addr.port(),
            peer: Some(peer.ip()),
            tls: true,
        };
        serve_h2::serve(&ctx, io::Stream::Plain(tcp), &info).await;
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut client, conn) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(conn);

    let req = http::Request::builder()
        .method("POST")
        .uri("https://web.example/x/../y?q")
        .header("cookie", "a=1")
        .header("cookie", "b=2")
        .body(())
        .unwrap();
    let (resp, mut send) = client.send_request(req, false).unwrap();
    send.send_data(Bytes::from_static(b"body!"), true).unwrap();
    let resp = resp.await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let mut echo = Vec::new();
    while let Some(d) = body.data().await {
        let d = d.unwrap();
        let _ = body.flow_control().release_capacity(d.len());
        echo.extend_from_slice(&d);
    }
    let echo = String::from_utf8(echo).unwrap();
    assert!(echo.starts_with("POST /y?q\n"), "{echo}");
    assert!(echo.contains("Host: web.example\n"), "{echo}");
    assert!(echo.contains("cookie: a=1; b=2\n"), "{echo}");
    assert!(
        echo.contains("Transfer-Encoding: chunked\n") && echo.ends_with("\n\nbody!"),
        "{echo}"
    );
    assert!(echo.contains("X-Forwarded-Proto: https\n"), "{echo}");

    // Several streams at once share the pooled backend connections.
    let mut pending = Vec::new();
    for i in 0..10 {
        let req = http::Request::builder()
            .uri(format!("https://web.example/{i}"))
            .body(())
            .unwrap();
        pending.push(client.send_request(req, true).unwrap().0);
    }
    for p in pending {
        assert_eq!(p.await.unwrap().status(), 200);
    }
    assert!(conns.load(Ordering::SeqCst) <= 11);

    // Too many fields: 431.
    let mut req = http::Request::builder().uri("https://web.example/");
    for i in 0..300 {
        req = req.header(format!("x-{i}"), "1");
    }
    let resp = client
        .send_request(req.body(()).unwrap(), true)
        .unwrap()
        .0
        .await
        .unwrap();
    assert_eq!(resp.status(), 431);

    // Conflicting Content-Lengths: reset.
    let req = http::Request::builder()
        .method("POST")
        .uri("https://web.example/")
        .header("content-length", "1")
        .header("content-length", "2")
        .body(())
        .unwrap();
    let (resp, _send) = client.send_request(req, false).unwrap();
    assert!(resp.await.is_err());
}

#[test]
fn idle_reads_hold_no_buffer() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (mut a, _b) = tokio::io::duplex(1024);
        let mut buf = BytesMut::new();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(io::poll_read_lazy(&mut a, &mut cx, &mut buf, 4096).is_pending());
        assert_eq!(buf.capacity(), 0, "a read that would block lets go of the buffer");
    });
}

/// The per-connection futures stay small: what an idle connection holds is its
/// task, so their size is most of an idle connection's footprint. (The h2 and TLS
/// futures are boxed inside the accept task, so they cost only while in use.)
#[tokio::test]
async fn connection_futures_are_small() {
    let ctx = ctx_with(RouteTable::default(), TIMEOUTS, NO_LIMITS);
    let (_client, server) = tokio::io::duplex(1);
    let info = ConnInfo {
        port: 0,
        peer: None,
        tls: false,
    };
    let h1 = serve_h1::serve(&ctx, io::Stream::Duplex(server), &info);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let tls = serve_tls(&ctx, tcp, &info);
    let (_client, server) = tokio::io::duplex(1);
    let h2 = serve_h2::serve(&ctx, io::Stream::Duplex(server), &info);
    let sizes = [
        std::mem::size_of_val(&h1),
        std::mem::size_of_val(&tls),
        std::mem::size_of_val(&h2),
    ];
    eprintln!(
        "future sizes: serve_h1 {} B, serve_tls {} B, serve_h2 {} B",
        sizes[0], sizes[1], sizes[2]
    );
    assert!(sizes[0] <= 1024, "serve_h1: {} bytes", sizes[0]);
    assert!(sizes[1] <= 2048, "serve_tls: {} bytes", sizes[1]);
}

/// A self-signed certificate for `host`.
fn cert_for(host: &str) -> crate::cert_store::CertKey {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    crate::cert_store::CertKey::new(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
}

/// A gateway TLS port serving `snapshot` (built for its port).
async fn tls_gateway(
    snapshot: impl FnOnce(u16) -> crate::snapshot::Snapshot,
) -> (SocketAddr, Arc<Ctx>, watch::Sender<bool>) {
    let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = ctx_from(snapshot(addr.port()), TIMEOUTS, NO_LIMITS, CLIENT_STALL_TIMEOUT);
    let (stop, stop_rx) = watch::channel(false);
    tokio::spawn(accept_loop(ctx.clone(), listener, true, stop_rx));
    (addr, ctx, stop)
}

/// A TLS client connection with SNI `sni` offering the ALPN list `alpn`
/// (wire format), not verifying the certificate.
async fn tls_client(addr: SocketAddr, sni: &str, alpn: &[u8]) -> Result<SslStream<TcpStream>, openssl::ssl::Error> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_alpn_protos(alpn).unwrap();
    let ssl = builder
        .build()
        .configure()
        .unwrap()
        .verify_hostname(false)
        .into_ssl(sni)
        .unwrap();
    let mut s = SslStream::new(ssl, TcpStream::connect(addr).await.unwrap()).unwrap();
    Pin::new(&mut s).connect().await?;
    Ok(s)
}

/// The DNS names of the certificate the server presented.
fn peer_names(s: &SslStream<TcpStream>) -> Vec<String> {
    let cert = s.ssl().peer_certificate().unwrap();
    cert.subject_alt_names()
        .into_iter()
        .flatten()
        .filter_map(|n| n.dnsname().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn tls_serves_by_sni_and_alpn() {
    let (backend, _) = echo_backend().await;
    let (addr, ctx, _stop) = tls_gateway(|port| {
        let mut certs = crate::cert_store::CertStore::default();
        certs.insert("a.example", cert_for("a.example"));
        crate::snapshot::Snapshot {
            routes: one_route(port, backend, Filters::default(), None),
            certs,
            ..Default::default()
        }
    })
    .await;

    // HTTP/1.1, with the SNI's certificate.
    let mut s = tls_client(addr, "a.example", b"\x08http/1.1").await.unwrap();
    assert_eq!(peer_names(&s), vec!["a.example"]);
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
    s.write_all(b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n")
        .await
        .unwrap();
    let resp = read_response(&mut s, &mut BytesMut::new(), "GET").await.unwrap();
    let echo = String::from_utf8(resp.body).unwrap();
    assert!(echo.contains("X-Forwarded-Proto: https\n"), "{echo}");

    // An unknown SNI gets the fallback certificate.
    let s = tls_client(addr, "other.example", b"\x08http/1.1").await.unwrap();
    assert_eq!(peer_names(&s), vec!["torii-fallback.invalid"]);

    // HTTP/2 by ALPN.
    let s = tls_client(addr, "a.example", b"\x02h2\x08http/1.1").await.unwrap();
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
    let (mut client, conn) = h2::client::handshake(s).await.unwrap();
    tokio::spawn(conn);
    let req = http::Request::builder().uri("https://a.example/h2").body(()).unwrap();
    let resp = client.send_request(req, true).unwrap().0.await.unwrap();
    assert_eq!(resp.status(), 200);

    // ACME TLS-ALPN-01: the challenge certificate, only for `acme-tls/1`.
    ctx.data_plane
        .store_challenges([("a.example".to_string(), cert_for("challenge.invalid"))].into());
    let s = tls_client(addr, "a.example", b"\x0aacme-tls/1").await.unwrap();
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"acme-tls/1"[..]));
    assert_eq!(peer_names(&s), vec!["challenge.invalid"]);
    // No challenge pending for the SNI: no acme-tls/1, the normal certificate.
    let s = tls_client(addr, "b.example", b"\x0aacme-tls/1\x08http/1.1")
        .await
        .unwrap();
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(peer_names(&s), vec!["torii-fallback.invalid"]);
    let s = tls_client(addr, "a.example", b"\x08http/1.1").await.unwrap();
    assert_eq!(peer_names(&s), vec!["a.example"]);
}

/// A TCP backend that echoes what it gets.
async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn tlsroute_passthrough_and_terminate() {
    use crate::tls_table::{TlsAction, TlsBackend, TlsBackends, TlsTable};
    // The passthrough backend terminates TLS itself, and echoes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let passthrough = listener.local_addr().unwrap();
    let backend_cert = cert_for("p.example");
    tokio::spawn(async move {
        let parsed = backend_cert.parsed().unwrap();
        let mut acceptor = openssl::ssl::SslAcceptor::mozilla_intermediate_v5(openssl::ssl::SslMethod::tls()).unwrap();
        acceptor.set_certificate(&parsed.chain[0]).unwrap();
        acceptor.set_private_key(&parsed.key).unwrap();
        let acceptor = acceptor.build();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = SslStream::new(openssl::ssl::Ssl::new(acceptor.context()).unwrap(), tcp).unwrap();
            tokio::spawn(async move {
                Pin::new(&mut s).accept().await.unwrap();
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await.unwrap();
                s.write_all(&b).await.unwrap();
            });
        }
    });
    let terminate = tcp_echo().await;
    let backends = |addr: SocketAddr| TlsBackends {
        backends: vec![TlsBackend {
            weight: 1,
            endpoints: vec![endpoint(addr)],
        }],
    };
    let (addr, _ctx, _stop) = tls_gateway(|port| {
        let mut tls = TlsTable::default();
        tls.insert(port, "p.example", TlsAction::Passthrough(backends(passthrough)));
        tls.insert(port, "t.example", TlsAction::Terminate(backends(terminate)));
        let mut certs = crate::cert_store::CertStore::default();
        certs.insert("t.example", cert_for("t.example"));
        crate::snapshot::Snapshot {
            tls,
            certs,
            ..Default::default()
        }
    })
    .await;

    let mut s = tls_client(addr, "p.example", b"").await.unwrap();
    assert_eq!(peer_names(&s), vec!["p.example"], "the backend's own certificate");
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");

    let mut s = tls_client(addr, "t.example", b"\x02h2\x08http/1.1").await.unwrap();
    assert_eq!(peer_names(&s), vec!["t.example"], "torii's certificate");
    assert_eq!(s.ssl().selected_alpn_protocol(), None, "a pipe negotiates no protocol");
    s.write_all(b"pong").await.unwrap();
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"pong");
}

fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend([ty, flags]);
    f.extend(stream.to_be_bytes());
    f.extend(payload);
    f
}

async fn read_frame(io: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    io.read_exact(&mut head).await.ok()?;
    let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
    io.read_exact(&mut payload).await.ok()?;
    let stream = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff;
    Some((head[3], head[4], stream, payload))
}

/// An h2 server (prior knowledge, plain TCP) over `ctx` on a loopback port.
async fn h2_server(ctx: Arc<Ctx>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = listener.accept().await.unwrap();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let info = ConnInfo {
                    port: 0,
                    peer: Some(peer.ip()),
                    tls: true,
                };
                serve_h2::serve(&ctx, io::Stream::Plain(tcp), &info).await;
            });
        }
    });
    addr
}

/// A backend that records the targets it is asked for.
async fn recording_backend() -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let (addr, _) = backend(move |head, _| {
        log.lock()
            .unwrap()
            .push(String::from_utf8_lossy(head.target()).into_owned());
        Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
    })
    .await;
    (addr, seen)
}

/// GET https://a<path>, as an HPACK block: static indices 2 (GET) and 7 (https),
/// then :path and :authority literals without indexing.
fn h2_get_block(path: &str) -> Vec<u8> {
    let mut block = vec![0x82, 0x87, 0x04, path.len() as u8];
    block.extend(path.as_bytes());
    block.extend([0x01, 0x01, b'a']);
    block
}

// HPACK bomb: a field inserted into the dynamic table once, then repeated with
// 1-byte references, decodes to far more than its wire size. The bomb must not
// reach a backend, while the connection keeps serving.
#[tokio::test]
async fn h2_header_list_bomb_is_refused() {
    let (backend, seen) = recording_backend().await;
    let addr = h2_server(ctx_with(
        one_route(0, backend, Filters::default(), None),
        TIMEOUTS,
        NO_LIMITS,
    ))
    .await;
    // `x: <1000 bytes>` counts 1033 bytes toward the list; 39 more references
    // (0xbe = index 62) make ~41 KB decoded from ~1 KB on the wire.
    let mut bomb = h2_get_block("/bomb");
    bomb.extend([0x40, 0x01, b'x', 0x7f, 0xe9, 0x06]);
    bomb.extend([b'A'; 1000]);
    bomb.extend([0xbe; 39]);
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend(h2_frame(0x4, 0, 0, &[]));
    req.extend(h2_frame(0x1, 0x5, 1, &bomb));
    req.extend(h2_frame(0x1, 0x5, 3, &h2_get_block("/ok")));
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&req).await.unwrap();

    // The server's SETTINGS advertise the caps.
    let (ty, _, _, payload) = read_frame(&mut client).await.unwrap();
    assert_eq!(ty, 0x4, "server must open with SETTINGS");
    let setting = |id: u16| {
        let s = payload.chunks(6).find(|s| s[..2] == id.to_be_bytes())?;
        Some(u32::from_be_bytes(s[2..6].try_into().unwrap()))
    };
    assert_eq!(setting(0x6), Some(H2_MAX_HEADER_LIST_SIZE));
    assert_eq!(setting(0x3), Some(H2_MAX_CONCURRENT_STREAMS));
    let served = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some((ty, _, stream, _)) = read_frame(&mut client).await {
            if ty == 0x1 && stream == 3 {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(served, Ok(true));
    assert_eq!(*seen.lock().unwrap(), vec!["/ok"]);
}

#[tokio::test]
async fn h2_empty_data_frame_flood_gets_goaway() {
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(silent.accept().await.unwrap());
        }
    });
    let addr = h2_server(ctx_with(
        one_route(0, silent_addr, Filters::default(), None),
        TIMEOUTS,
        NO_LIMITS,
    ))
    .await;
    // POST https://a/ (static indices 3, 7, 4 and an :authority literal), then
    // 1000 empty DATA frames.
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend(h2_frame(0x4, 0, 0, &[]));
    req.extend(h2_frame(0x1, 0x4, 1, &[0x83, 0x87, 0x84, 0x41, 0x01, b'a']));
    for _ in 0..1000 {
        req.extend(h2_frame(0x0, 0, 1, &[]));
    }
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&req).await.unwrap();
    let goaway = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some((ty, _, _, payload)) = read_frame(&mut client).await {
            if ty == 0x7 {
                return Some(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
            }
        }
        None
    })
    .await;
    assert_eq!(goaway, Ok(Some(0xb)), "expected GOAWAY(ENHANCE_YOUR_CALM)");
}

// A client's SETTINGS_HEADER_TABLE_SIZE is a ceiling, not a demand: torii's encoder
// keeps no dynamic table, so a response field costs no memory past its frame, and
// the second response carries it as a literal again.
#[tokio::test]
async fn h2_encoder_keeps_no_table() {
    let (backend, _) = backend(|_, _| {
        Some(
            format!(
                "HTTP/1.1 200 OK\r\nx-big: {}\r\nContent-Length: 0\r\n\r\n",
                "x".repeat(300)
            )
            .into_bytes(),
        )
    })
    .await;
    let addr = h2_server(ctx_with(
        one_route(0, backend, Filters::default(), None),
        TIMEOUTS,
        NO_LIMITS,
    ))
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend(h2_frame(0x4, 0, 0, &[0x00, 0x01, 0xff, 0xff, 0xff, 0xff]));
    client.write_all(&req).await.unwrap();
    let blocks = tokio::time::timeout(Duration::from_secs(5), async {
        while !matches!(read_frame(&mut client).await, Some((0x4, 0x1, ..))) {}
        let mut req = h2_frame(0x1, 0x5, 1, &h2_get_block("/1"));
        req.extend(h2_frame(0x1, 0x5, 3, &h2_get_block("/2")));
        client.write_all(&req).await.unwrap();
        let mut blocks = [0, 0];
        while blocks.contains(&0) {
            let (ty, _, stream, payload) = read_frame(&mut client).await.unwrap();
            if ty == 0x1 {
                blocks[stream as usize / 2] = payload.len();
            }
        }
        blocks
    })
    .await
    .unwrap();
    assert!(blocks[0] > 200 && blocks[1] >= blocks[0], "{blocks:?}");
}

#[tokio::test]
async fn h2_stalls_are_cut_off() {
    let (backend, _) = backend(|head, _| {
        Some(match head.target() {
            b"/big" => {
                let mut out = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n".to_vec();
                out.extend(vec![b'x'; 1_000_000]);
                out
            }
            _ => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        })
    })
    .await;
    let snapshot = crate::snapshot::Snapshot {
        routes: one_route(0, backend, Filters::default(), None),
        ..Default::default()
    };
    let addr = h2_server(ctx_from(snapshot, TIMEOUTS, NO_LIMITS, Duration::from_millis(300))).await;

    // A client that keeps the stream's window closed gets the stream reset.
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend(h2_frame(0x4, 0, 0, &[0x00, 0x04, 0, 0, 0, 0])); // INITIAL_WINDOW_SIZE = 0
    req.extend(h2_frame(0x1, 0x5, 1, &h2_get_block("/big")));
    client.write_all(&req).await.unwrap();
    let reset = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some((ty, _, stream, _)) = read_frame(&mut client).await {
            if ty == 0x3 && stream == 1 {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(reset, Ok(true), "expected RST_STREAM on the stalled stream");

    // A request body that stalls gets a 408 (here, a HEADERS frame).
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend(h2_frame(0x4, 0, 0, &[]));
    // POST https://a/ with content-length: 100000 (index 28, literal), no END_STREAM.
    let mut block = vec![0x83, 0x87, 0x84, 0x41, 0x01, b'a', 0x0f, 0x0d, 0x06];
    block.extend(b"100000");
    req.extend(h2_frame(0x1, 0x4, 1, &block));
    req.extend(h2_frame(0x0, 0, 1, b"0123456789"));
    client.write_all(&req).await.unwrap();
    let answered = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some((ty, _, stream, _)) = read_frame(&mut client).await {
            if (ty == 0x1 || ty == 0x3) && stream == 1 {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(answered, Ok(true), "expected the stalled body to be answered");
}

#[tokio::test]
async fn h1_stalled_body_gets_408() {
    let (backend, _) = echo_backend().await;
    let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let snapshot = crate::snapshot::Snapshot {
        routes: one_route(addr.port(), backend, Filters::default(), None),
        ..Default::default()
    };
    let ctx = ctx_from(snapshot, TIMEOUTS, NO_LIMITS, Duration::from_millis(300));
    let (_stop, stop_rx) = watch::channel(false);
    tokio::spawn(accept_loop(ctx, listener, false, stop_rx));
    let start = std::time::Instant::now();
    let resp = request(addr, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\nsome")
        .await
        .unwrap();
    assert_eq!(resp.status, 408);
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn half_closed_clients_get_their_response() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let mut s = TcpStream::connect(gw.addr).await.unwrap();
    s.write_all(b"GET /hc HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    s.shutdown().await.unwrap();
    let resp = read_response(&mut s, &mut BytesMut::new(), "GET").await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.field("connection").as_deref(), Some("close"));
}

#[tokio::test]
async fn spoofable_fields_are_dropped() {
    let (backend, _) = echo_backend().await;
    let gw = gateway(|port| one_route(port, backend, Filters::default(), None)).await;
    let resp = request(
        gw.addr,
        "GET / HTTP/1.1\r\nHost: a\r\nX_Forwarded_For: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nX-Ok: 1\r\n\r\n",
    )
    .await
    .unwrap();
    let echo = String::from_utf8(resp.body).unwrap();
    assert!(!echo.contains("6.6.6.6") && echo.contains("X-Ok: 1\n"), "{echo}");
    // A Host that is not a name or an address.
    let resp = request(gw.addr, "GET / HTTP/1.1\r\nHost: evil.example/x?\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status, 400);
}
