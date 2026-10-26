//! HTTP/1.x from clients: the keep-alive loop of a connection, and the exchange
//! of one request with a backend.
//!
//! Between requests a connection holds its socket and an unallocated buffer: the
//! wait for the next request is a [`read_lazy`], and the per-request state (the
//! head, the plan, the exchange's buffers and clocks) lives in a boxed future that
//! exists only while a request is in flight.

use std::sync::Arc;
use std::task::Poll;

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use super::h1::{
    self, Decoder, Encoder, HeadError, HeadEvent, HeadReader, MAX_REQUEST_HEAD, MAX_RESPONSE_HEAD, RequestFraming,
    RequestHead, ResponseFraming, Version,
};
use super::io::{Stream, read_lazy, write_all};
use super::proxy::{self, Decision, Local, Plan, UpstreamBody};
use super::relay::{self, Down, H1Sink, RelayError, ReqPump, ReqSource, RespPump, RespSink, Timers, Up};
use super::upstream::{self, Upstream};
use super::{ConnInfo, Ctx, H1_HEAD_TIMEOUT, H1_IDLE_TIMEOUT};

/// The first read of a request head; later reads double it (nginx's
/// `client_header_buffer_size`).
const FIRST_READ: usize = 1024;
/// Most 1xx responses skipped before a final one.
const MAX_INTERIM: usize = 8;
/// Most requests one connection serves (nginx's `keepalive_requests`, T193).
const MAX_REQUESTS: u32 = 1000;

/// Serve HTTP/1.x requests on a client connection until it closes, idles out, or
/// a request ends it.
pub async fn serve(ctx: &Arc<Ctx>, mut stream: Stream, info: &ConnInfo) {
    let mut buf = BytesMut::new();
    let mut first = true;
    let mut served = 0;
    loop {
        let head = match read_request(ctx, &mut stream, &mut buf, first).await {
            Ok(Some(head)) => head,
            Ok(None) => break,
            Err(status) => {
                let _ = write_local(&mut stream, &Local::status(status), true, ctx.client_stall).await;
                break;
            }
        };
        served += 1;
        let last = served >= MAX_REQUESTS;
        let keep_alive = Box::pin(handle(ctx, &mut stream, &mut buf, head, info, last)).await;
        if !keep_alive {
            break;
        }
        first = false;
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), stream.shutdown()).await;
}

/// Read the next request head: `Ok(None)` if the connection closes or idles out
/// first, `Err(status)` for a head to refuse.
///
/// The client gets [`H1_IDLE_TIMEOUT`] to start a head, then [`H1_HEAD_TIMEOUT`] in
/// all to finish it, however it paces its bytes (T041: a client that sent one byte
/// a minute held the connection forever).
///
/// While torii drains for shutdown, a keep-alive connection waiting for its next
/// request is closed; a new connection still gets its first request served.
async fn read_request(
    ctx: &Ctx,
    stream: &mut Stream,
    buf: &mut BytesMut,
    first: bool,
) -> Result<Option<RequestHead>, u16> {
    if buf.is_empty() {
        let mut draining = ctx.shutdown.subscribe();
        tokio::select! {
            r = tokio::time::timeout(H1_IDLE_TIMEOUT, read_lazy(stream, buf, FIRST_READ)) => match r {
                Ok(Ok(n)) if n > 0 => {}
                _ => return Ok(None),
            },
            _ = draining.wait_for(|&d| d), if !first => return Ok(None),
        }
    }
    let mut reader = HeadReader::new(FIRST_READ, MAX_REQUEST_HEAD);
    let event = tokio::time::timeout(H1_HEAD_TIMEOUT, std::future::poll_fn(|cx| reader.poll(cx, stream, buf))).await;
    match event {
        Err(_) => {
            tracing::debug!("request head timed out -> 408");
            Err(408)
        }
        Ok(Err(_)) | Ok(Ok(HeadEvent::Eof { .. })) => Ok(None),
        Ok(Ok(HeadEvent::TooLarge)) => Err(431),
        Ok(Ok(HeadEvent::Complete(n))) => {
            let head = buf.split_to(n);
            match h1::parse_request(&head) {
                Ok(head) => Ok(Some(head)),
                Err(HeadError::TooManyFields) => Err(431),
                Err(HeadError::Invalid) => Err(400),
            }
        }
    }
}

/// Write a response torii answers itself (empty body).
async fn write_local(
    stream: &mut Stream,
    local: &Local,
    close: bool,
    stall: std::time::Duration,
) -> std::io::Result<()> {
    let fields = local.headers.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes()));
    // No Content-Length on a status that never has a body (T191).
    let mut framing: Vec<(&[u8], &[u8])> = Vec::new();
    if local.status >= 200 && local.status != 204 && local.status != 304 {
        framing.push((b"Content-Length", b"0"));
    }
    if close {
        framing.push((b"Connection", b"close"));
    }
    let head = proxy::h1_response_head(local.status, h1::reason(local.status).as_bytes(), fields, &framing);
    write_all(stream, &head, stall).await
}

/// Handle one request. Returns whether the connection may serve another.
async fn handle(
    ctx: &Arc<Ctx>,
    stream: &mut Stream,
    buf: &mut BytesMut,
    head: RequestHead,
    info: &ConnInfo,
    last: bool,
) -> bool {
    let close =
        last || head.version == Version::Http10 || head.fields.has_token("connection", "close") || ctx.draining();
    // `Connection` may nominate hop-by-hop fields, but not the ones a request needs
    // to be understood at all (T109).
    if ["host", "content-length", "transfer-encoding"]
        .iter()
        .any(|f| head.fields.has_token("connection", f))
    {
        let _ = write_local(stream, &Local::status(400), true, ctx.client_stall).await;
        return false;
    }
    let framing = match h1::request_framing(&head) {
        Ok(f) => f,
        Err(status) => {
            let _ = write_local(stream, &Local::status(status), true, ctx.client_stall).await;
            return false;
        }
    };
    match proxy::decide(ctx, &head, info) {
        Decision::Local(local) => {
            // A body torii does not read leaves the connection unusable.
            let close = close || framing != RequestFraming::None;
            write_local(stream, &local, close, ctx.client_stall).await.is_ok() && !close
        }
        Decision::Proxy(plan) => exchange(ctx, stream, buf, &head, *plan, framing, close).await,
    }
}

/// Forward one request to its backend and the response back. Returns whether the
/// connection may serve another request.
async fn exchange(
    ctx: &Arc<Ctx>,
    stream: &mut Stream,
    buf: &mut BytesMut,
    head: &RequestHead,
    plan: Plan,
    framing: RequestFraming,
    close: bool,
) -> bool {
    // An upgrade (WebSocket, SPDY for kubectl, Docker's tcp) is passed on, but not
    // to h2c: that would let the client speak HTTP/2 to the backend past routing
    // and filters (h2c smuggling, T118).
    let upgrade = (head.version == Version::Http11 && head.fields.has_token("connection", "upgrade"))
        .then(|| head.fields.get("upgrade"))
        .flatten()
        .filter(|p| {
            !p.split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"h2c"))
        })
        .map(<[u8]>::to_vec);
    let expect_continue = head.version == Version::Http11
        && framing != RequestFraming::None
        && head
            .fields
            .get("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"));
    let (up_body, encoder) = match framing {
        RequestFraming::None => (UpstreamBody::None, Encoder::Raw),
        RequestFraming::Length(n) => (UpstreamBody::Length(n), Encoder::Raw),
        RequestFraming::Chunked => (UpstreamBody::Chunked, Encoder::Chunked),
    };
    let up_head = Bytes::from(proxy::upstream_head(head, &plan, up_body, upgrade.as_deref()));
    let mut timers = Timers::new(plan.timeout, ctx.client_stall);
    let mut pump = ReqPump::new(ReqSource::H1(Decoder::for_request(framing)), encoder);
    // torii answers `Expect: 100-continue` itself, as it starts reading the body
    // (the Expect field is not forwarded).
    if expect_continue
        && write_all(stream, b"HTTP/1.1 100 Continue\r\n\r\n", ctx.client_stall)
            .await
            .is_err()
    {
        return false;
    }

    // Phase A: send the head, then the body while waiting for the response head.
    // A pooled connection the backend has closed meanwhile fails before any
    // response byte: a request without a body is then retried once on a new one.
    //
    // A rule's `timeouts` is also a deadline for the response head, however the
    // backend paces it (T051).
    let mut client = ClientSide {
        forward_interim: head.version == Version::Http11,
        stall: ctx.client_stall,
        closed: false,
    };
    let head_phase = async {
        let mut fresh = false;
        loop {
            let mut up = upstream::connect_http(&ctx.pool, &ctx.clients, &plan.endpoint, plan.connect_timeout, fresh)
                .await
                .map_err(RelayError::BackendIo)?;
            match response_head(stream, buf, &mut up, &up_head, &mut pump, &mut timers, &mut client).await {
                Ok(resp) => return Ok((up, resp)),
                Err(e) if up.reused && !fresh && framing == RequestFraming::None && e.is_stale() => {
                    tracing::debug!(error = %e, "pooled backend connection failed; retrying on a new one");
                    fresh = true;
                }
                Err(e) => return Err(e),
            }
        }
    };
    let result = match plan.deadline {
        Some(deadline) => tokio::time::timeout(deadline, head_phase)
            .await
            .unwrap_or(Err(RelayError::BackendTimeout)),
        None => head_phase.await,
    };
    let (mut up, resp) = match result {
        Ok(r) => r,
        Err(e) => return fail(ctx, stream, e, &pump, close).await,
    };
    // A client that half-closed its side still gets the response, then the close.
    let close = close || client.closed;

    // A switched protocol (WebSocket): hand both connections to a byte pipe.
    if resp.status == 101 {
        if upgrade.is_none() {
            return fail(ctx, stream, RelayError::BadResponse("unrequested 101"), &pump, close).await;
        }
        // A backend that answers 101 but goes on parsing HTTP would get the client's
        // next requests through the tunnel, past routing and filters (T127). So a
        // WebSocket 101 must complete the handshake, and no client bytes may be
        // waiting: a client starts the new protocol only once it has the 101.
        let websocket = upgrade
            .as_deref()
            .is_some_and(|p| p.trim_ascii().eq_ignore_ascii_case(b"websocket"));
        if (websocket && !websocket_accepted(head, &resp)) || !buf.is_empty() {
            return fail(
                ctx,
                stream,
                RelayError::BadResponse("101 without a completed handshake"),
                &pump,
                close,
            )
            .await;
        }
        let mut fields = proxy::response_fields(&resp, &plan);
        fields.push((
            std::borrow::Cow::Borrowed(b"Connection"),
            std::borrow::Cow::Borrowed(b"upgrade"),
        ));
        let out = proxy::h1_response_head(101, resp.reason(), fields.iter().map(|(n, v)| (&n[..], &v[..])), &[]);
        if write_all(stream, &out, ctx.client_stall).await.is_err() {
            return false;
        }
        drop(fields);
        let _ = relay::pipe(stream, buf, &mut up.stream, &mut up.buf, plan.timeout).await;
        return false;
    }

    let Some(resp_framing) = h1::response_framing(&resp, head.method()) else {
        return fail(
            ctx,
            stream,
            RelayError::BadResponse("conflicting Content-Length"),
            &pump,
            close,
        )
        .await;
    };
    // To an HTTP/1.0 client, a body of unknown length ends at close.
    let chunked_ok = head.version == Version::Http11;
    let close_after = close || (matches!(resp_framing, ResponseFraming::Chunked | ResponseFraming::Eof) && !chunked_ok);
    let length;
    let mut framing_fields: Vec<(&[u8], &[u8])> = Vec::new();
    let down_encoder = match resp_framing {
        ResponseFraming::Length(n) => {
            length = n.to_string();
            framing_fields.push((b"Content-Length", length.as_bytes()));
            Encoder::Raw
        }
        ResponseFraming::None => {
            // A HEAD or 304 response carries the length of the body it stands for.
            if resp.status != 204 && resp.status >= 200 {
                for v in resp.fields.get_all("content-length") {
                    framing_fields.push((b"Content-Length", v));
                }
            }
            Encoder::Raw
        }
        ResponseFraming::Chunked | ResponseFraming::Eof if chunked_ok => {
            framing_fields.push((b"Transfer-Encoding", b"chunked"));
            Encoder::Chunked
        }
        ResponseFraming::Chunked | ResponseFraming::Eof => Encoder::Raw,
    };
    if close_after {
        framing_fields.push((b"Connection", b"close"));
    }
    let fields = proxy::response_fields(&resp, &plan);
    let out = proxy::h1_response_head(
        resp.status,
        resp.reason(),
        fields.iter().map(|(n, v)| (&n[..], &v[..])),
        &framing_fields,
    );
    drop(fields);
    let backend_keeps_alive = resp.version == Version::Http11
        && !resp.fields.has_token("connection", "close")
        && resp_framing != ResponseFraming::Eof;
    drop(resp);

    // Phase B: the response body, while any rest of the request body goes on.
    let mut sink = H1Sink::new(down_encoder);
    sink.start_raw(Bytes::from(out));
    let mut resp_pump = RespPump::new(Decoder::for_response(resp_framing), RespSink::H1(sink));
    let done = std::future::poll_fn(|cx| {
        let mut down = Down::H1 {
            io: &mut *stream,
            buf: &mut *buf,
        };
        if !pump.is_done() {
            match pump.poll(cx, &mut down, &mut up.stream, &mut timers) {
                // The backend may stop reading a body it has answered.
                Poll::Ready(Err(RelayError::BackendIo(_))) => pump.abandon(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) | Poll::Pending => {}
            }
        }
        let mut up = Up {
            io: &mut up.stream,
            buf: &mut up.buf,
        };
        resp_pump.poll(cx, &mut down, &mut up, &mut timers)
    })
    .await;
    if let Err(e) = done {
        tracing::debug!(error = %e, "exchange failed after the response head");
        return false;
    }
    let request_complete = pump.is_done() && !pump.is_abandoned();
    if backend_keeps_alive && request_complete {
        ctx.pool.put(up);
    }
    request_complete && !close_after
}

/// Send the request head (and body) to the backend and read its response head,
/// skipping interim (1xx) responses other than 101.
async fn response_head(
    stream: &mut Stream,
    buf: &mut BytesMut,
    up: &mut Upstream,
    up_head: &Bytes,
    pump: &mut ReqPump,
    timers: &mut Timers,
    client: &mut ClientSide,
) -> Result<h1::ResponseHead, RelayError> {
    let mut head_out = Some(super::io::Outgoing::new(&[], up_head.clone(), b""));
    let mut interim = 0;
    loop {
        let mut reader = HeadReader::new(4096, MAX_RESPONSE_HEAD);
        let n = std::future::poll_fn(|cx| {
            // The head first, then the body.
            while let Some(out) = &mut head_out {
                if out.is_done() {
                    head_out = None;
                    break;
                }
                match out.poll_write(&mut up.stream, cx) {
                    Poll::Ready(Ok(_)) => timers.backend_progress(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(RelayError::BackendIo(e))),
                    Poll::Pending => {
                        timers.backend_waiting(cx)?;
                        return Poll::Pending;
                    }
                }
            }
            let mut down = Down::H1 {
                io: &mut *stream,
                buf: &mut *buf,
            };
            if !pump.is_done()
                && let Poll::Ready(Err(e)) = pump.poll(cx, &mut down, &mut up.stream, timers)
            {
                return Poll::Ready(Err(e));
            }
            let before = up.buf.len();
            let event = reader.poll(cx, &mut up.stream, &mut up.buf);
            if up.buf.len() > before {
                timers.backend_progress();
            }
            match event {
                Poll::Ready(Ok(HeadEvent::Complete(n))) => return Poll::Ready(Ok(n)),
                Poll::Ready(Ok(HeadEvent::Eof { .. })) => {
                    return Poll::Ready(Err(RelayError::BackendIo(std::io::ErrorKind::UnexpectedEof.into())));
                }
                Poll::Ready(Ok(HeadEvent::TooLarge)) => {
                    return Poll::Ready(Err(RelayError::BadResponse("response head too large")));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(RelayError::BackendIo(e))),
                Poll::Pending => {}
            }
            if pump.is_done() {
                timers.backend_waiting(cx)?;
                // While the backend works, read what the client sends: bytes it
                // pipelines stay in the buffer (up to a bound), an error means it is
                // gone. An EOF may be a half-close after a complete request (T106):
                // the response still goes out, and then the connection closes.
                if !client.closed
                    && buf.len() < MAX_REQUEST_HEAD
                    && let Poll::Ready(r) = super::io::poll_read_lazy(&mut *stream, cx, buf, FIRST_READ)
                {
                    match r {
                        Ok(0) => client.closed = true,
                        Ok(_) => cx.waker().wake_by_ref(),
                        Err(e) => return Poll::Ready(Err(RelayError::ClientIo(e))),
                    }
                }
            }
            Poll::Pending
        })
        .await?;
        let raw = up.buf.split_to(n);
        let resp = match h1::parse_response(&raw) {
            Ok(resp) => resp,
            Err(HeadError::TooManyFields) => return Err(RelayError::BadResponse("too many response fields")),
            Err(HeadError::Invalid) => return Err(RelayError::BadResponse("malformed response head")),
        };
        if resp.status >= 200 || resp.status == 101 {
            return Ok(resp);
        }
        interim += 1;
        if interim > MAX_INTERIM {
            return Err(RelayError::BadResponse("too many interim responses"));
        }
        // Pass on interim responses (103 Early Hints, 102) to an HTTP/1.1 client
        // (an HTTP/1.0 one must not get them). A 100 answers an Expect torii does
        // not forward: it answers that itself.
        if client.forward_interim && resp.status != 100 {
            let fields = proxy::interim_fields(&resp);
            let out = proxy::h1_response_head(
                resp.status,
                resp.reason(),
                fields.iter().map(|(n, v)| (&n[..], &v[..])),
                &[],
            );
            super::io::write_all(stream, &out, client.stall)
                .await
                .map_err(RelayError::ClientIo)?;
        }
    }
}

/// What [`response_head`] knows of the client side.
struct ClientSide {
    /// Pass interim (1xx) responses on: the client speaks HTTP/1.1.
    forward_interim: bool,
    stall: std::time::Duration,
    /// The client half-closed its side while waiting (see [`response_head`]).
    closed: bool,
}

/// Whether a 101 answers the request's WebSocket handshake (RFC 6455 §4.2.2): its
/// Sec-WebSocket-Accept is the hash of the request's Sec-WebSocket-Key.
fn websocket_accepted(req: &RequestHead, resp: &h1::ResponseHead) -> bool {
    const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let (Some(key), Some(accept)) = (
        req.fields.get("sec-websocket-key"),
        resp.fields.get("sec-websocket-accept"),
    ) else {
        return false;
    };
    let mut input = key.trim_ascii().to_vec();
    input.extend_from_slice(GUID);
    let expected = openssl::base64::encode_block(&openssl::sha::sha1(&input));
    accept.trim_ascii() == expected.as_bytes()
}

/// Answer a request whose exchange failed before its response head, if the client
/// can still be answered. Returns whether the connection may serve another request.
async fn fail(ctx: &Ctx, stream: &mut Stream, e: RelayError, pump: &ReqPump, close: bool) -> bool {
    tracing::debug!(error = %e, "exchange failed");
    let status = e.status();
    if status == 0 {
        return false;
    }
    // A request body not read to its end leaves the connection unusable.
    let close = close || !pump.is_done() || pump.is_abandoned();
    write_local(stream, &Local::status(status), close, ctx.client_stall)
        .await
        .is_ok()
        && !close
}
