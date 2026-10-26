//! HTTP/2 from clients (TLS with ALPN `h2`): the connection's accept loop, and the
//! exchange of each stream with a backend over HTTP/1.1.
//!
//! The connection runs on our fork of h2 (github.com/Dirbaio/h2, branch `torii`),
//! which holds no I/O buffer while the connection is idle.

use std::sync::Arc;
use std::task::Poll;

use bytes::{Bytes, BytesMut};
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use http::{HeaderName, HeaderValue, Request, Response};

use super::h1::{self, Decoder, Encoder, HeadEvent, HeadReader, MAX_RESPONSE_HEAD, RequestHead, ResponseFraming};
use super::io::{Outgoing, Stream};
use super::proxy::{self, Decision, Local, Plan, UpstreamBody};
use super::relay::{Down, H2Send, RelayError, ReqPump, ReqSource, RespPump, RespSink, Timers, Up};
use super::upstream::{self, Upstream};
use super::{
    ConnInfo, Ctx, H2_GOAWAY_FLUSH_TIMEOUT, H2_IDLE_TIMEOUT, H2_MAX_CONCURRENT_STREAMS, H2_MAX_HEADER_FIELDS,
    H2_MAX_HEADER_LIST_SIZE, H2_MAX_SEND_BUFFER_SIZE, H2_MAX_STREAM_TASKS,
};

/// Serve an HTTP/2 connection: accept its streams and run each one as a task,
/// until the client closes it, it idles for [`H2_IDLE_TIMEOUT`] with no stream in
/// flight, or torii shuts down (GOAWAY, then the streams in flight finish).
///
/// A stream the client resets frees its MAX_CONCURRENT_STREAMS slot at once, but
/// its task runs on until it notices, i.e. until its backend connect ends.
/// Resetting accepted streams would let one connection pile up any number of
/// tasks behind a slow backend (the CVE-2023-39325 pattern), so a stream that
/// arrives while [`H2_MAX_STREAM_TASKS`] tasks run is refused (REFUSED_STREAM,
/// which the client may retry). A client that has had [`H2_MAX_CONCURRENT_STREAMS`]
/// refused while no task ended keeps opening streams into a full cap, and gets
/// GOAWAY(ENHANCE_YOUR_CALM). Leaving the loop drops the tasks still running: their
/// client is gone.
pub async fn serve(ctx: &Arc<Ctx>, stream: Stream, info: &ConnInfo) {
    let mut builder = h2::server::Builder::new();
    builder
        .max_header_list_size(H2_MAX_HEADER_LIST_SIZE)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .max_send_buffer_size(H2_MAX_SEND_BUFFER_SIZE);
    // A client can negotiate `h2` and then never send the connection preface.
    let mut conn = match tokio::time::timeout(H2_IDLE_TIMEOUT, builder.handshake::<_, Bytes>(stream)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "h2 handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!("h2 handshake timed out (no preface); closing");
            return;
        }
    };
    let mut tasks = tokio::task::JoinSet::new();
    // Streams refused since a task last ended.
    let mut refused = 0;
    let mut shutdown = ctx.shutdown.subscribe();
    let mut draining = false;
    loop {
        let next = tokio::select! {
            Some(_) = tasks.join_next() => {
                refused = 0;
                continue;
            }
            _ = shutdown.wait_for(|&d| d), if !draining => {
                draining = true;
                conn.graceful_shutdown();
                continue;
            }
            next = tokio::time::timeout(H2_IDLE_TIMEOUT, conn.accept()) => next,
        };
        let (req, mut respond) = match next {
            // Idle window elapsed. Close only if nothing is in flight.
            Err(_) if tasks.is_empty() => {
                tracing::debug!("h2 connection idle; closing");
                conn.graceful_shutdown();
                let closed = std::future::poll_fn(|cx| conn.poll_closed(cx));
                let _ = tokio::time::timeout(H2_GOAWAY_FLUSH_TIMEOUT, closed).await;
                break;
            }
            Err(_) => continue,
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                tracing::debug!(error = %e, "h2 connection failed");
                break;
            }
            Ok(Some(Ok(stream))) => stream,
        };
        // Too many fields to forward: answer as h2 answers an over-size head.
        if req.headers().len() > H2_MAX_HEADER_FIELDS {
            tracing::debug!("h2 request has too many header fields -> 431");
            send_local(&mut respond, &Local::status(431));
            continue;
        }
        // A task that ended since the last poll is still in `tasks`.
        while tasks.try_join_next().is_some() {
            refused = 0;
        }
        if tasks.len() >= H2_MAX_STREAM_TASKS {
            refused += 1;
            if refused > H2_MAX_CONCURRENT_STREAMS as usize {
                tracing::debug!("h2 client keeps opening streams over the task cap; closing");
                conn.abrupt_shutdown(Reason::ENHANCE_YOUR_CALM);
                let flush = std::future::poll_fn(|cx| conn.poll_closed(cx));
                let _ = tokio::time::timeout(H2_GOAWAY_FLUSH_TIMEOUT, flush).await;
                break;
            }
            respond.send_reset(Reason::REFUSED_STREAM);
            continue;
        }
        let ctx = ctx.clone();
        let info = info.clone();
        tasks.spawn(async move { handle(&ctx, req, respond, &info).await });
    }
}

/// Answer a stream with a response torii makes itself.
fn send_local(respond: &mut SendResponse<Bytes>, local: &Local) {
    let mut resp = Response::new(());
    *resp.status_mut() = http::StatusCode::from_u16(local.status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in &local.headers {
        if let Ok(value) = HeaderValue::from_str(value) {
            resp.headers_mut().append(*name, value);
        }
    }
    let _ = respond.send_response(resp, true);
}

/// Handle one stream.
async fn handle(ctx: &Arc<Ctx>, req: Request<RecvStream>, mut respond: SendResponse<Bytes>, info: &ConnInfo) {
    let (parts, recv) = req.into_parts();
    // Content-Length must be one value (h2 checks the body against the first only:
    // T022, two differing values were smuggled to the HTTP/1.1 backend).
    let mut lengths = parts.headers.get_all(http::header::CONTENT_LENGTH).iter();
    let length = match (lengths.next(), lengths.next()) {
        (None, _) => None,
        (Some(v), None) => match std::str::from_utf8(v.as_bytes())
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            Some(n) if v.as_bytes().iter().all(u8::is_ascii_digit) => Some(n),
            _ => {
                respond.send_reset(Reason::PROTOCOL_ERROR);
                return;
            }
        },
        (Some(_), Some(_)) => {
            respond.send_reset(Reason::PROTOCOL_ERROR);
            return;
        }
    };
    let Some(target) = parts.uri.path_and_query().map(|p| p.as_str().as_bytes()) else {
        send_local(&mut respond, &Local::status(400));
        return;
    };
    // Malformed requests (RFC 9113 §8.2.1, §8.3.1): a field value with leading or
    // trailing whitespace, or userinfo in :authority (T115).
    let padded = |v: &[u8]| matches!(v.first(), Some(b' ' | b'\t')) || matches!(v.last(), Some(b' ' | b'\t'));
    if parts.headers.values().any(|v| padded(v.as_bytes()))
        || parts.uri.authority().is_some_and(|a| a.as_str().contains('@'))
    {
        respond.send_reset(Reason::PROTOCOL_ERROR);
        return;
    }
    // `:authority` arrives as Host (RFC 9113 §8.3.1: it takes the place of Host).
    let authority = parts.uri.authority().map(|a| a.as_str().as_bytes());
    let fields = parts
        .headers
        .iter()
        .filter(|(n, _)| authority.is_none() || *n != http::header::HOST)
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .chain(authority.map(|a| (&b"host"[..], a)))
        .collect::<Vec<_>>();
    let head = RequestHead::from_parts(parts.method.as_str(), target, &fields);
    drop(fields);
    // The head is copied: let h2's decoded fields (and the frame buffer they
    // point into) go now.
    drop(parts);

    let expect_continue = !recv.is_end_stream()
        && head
            .fields
            .get("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"));
    let framing = if recv.is_end_stream() {
        UpstreamBody::None
    } else {
        match length {
            Some(n) => UpstreamBody::Length(n),
            None => UpstreamBody::Chunked,
        }
    };
    match proxy::decide(ctx, &head, info) {
        Decision::Local(local) => send_local(&mut respond, &local),
        Decision::Proxy(plan) => {
            // torii answers `Expect: 100-continue` itself, as it starts reading the
            // body (T114; the Expect field is not forwarded).
            if expect_continue {
                let mut cont = Response::new(());
                *cont.status_mut() = http::StatusCode::CONTINUE;
                let _ = respond.send_informational(cont);
            }
            exchange(ctx, &head, *plan, framing, recv, respond).await
        }
    }
}

/// Forward one stream to its backend over HTTP/1.1, and the response back.
async fn exchange(
    ctx: &Arc<Ctx>,
    head: &RequestHead,
    plan: Plan,
    framing: UpstreamBody,
    recv: RecvStream,
    mut respond: SendResponse<Bytes>,
) {
    let (source, encoder) = match framing {
        UpstreamBody::None => (ReqSource::None, Encoder::Raw),
        UpstreamBody::Length(_) => (ReqSource::H2 { recv, unreleased: 0 }, Encoder::Raw),
        UpstreamBody::Chunked => (ReqSource::H2 { recv, unreleased: 0 }, Encoder::Chunked),
    };
    // A POST or PUT with no body still tells the backend its length.
    let up_body = match framing {
        UpstreamBody::None if matches!(head.method(), "POST" | "PUT" | "PATCH") => UpstreamBody::Length(0),
        other => other,
    };
    let up_head = Bytes::from(proxy::upstream_head(head, &plan, up_body, None));
    let mut timers = Timers::new(plan.timeout, ctx.client_stall);
    let mut pump = ReqPump::new(source, encoder);

    // A rule's `timeouts` is also a deadline for the response head (T051).
    let head_phase = async {
        let mut fresh = false;
        loop {
            // A client that resets the stream while torii connects ends the task at
            // once, rather than when a slow connect ends (the task cap counts it).
            let connect = upstream::connect_http(&ctx.pool, &ctx.clients, &plan.endpoint, plan.connect_timeout, fresh);
            let mut up = tokio::select! {
                r = connect => r.map_err(RelayError::BackendIo)?,
                _ = std::future::poll_fn(|cx| respond.poll_reset(cx)) => {
                    return Err(RelayError::ClientIo(std::io::Error::other("stream reset while connecting")));
                }
            };
            match response_head(&mut up, &up_head, &mut pump, &mut timers, &mut respond).await {
                Ok(resp) => return Ok((up, resp)),
                Err(e) if up.reused && !fresh && framing == UpstreamBody::None && e.is_stale() => {
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
        Err(e) => return fail(&mut respond, e),
    };
    if resp.status == 101 {
        return fail(&mut respond, RelayError::BadResponse("101 to an HTTP/2 stream"));
    }
    let Some(resp_framing) = h1::response_framing(&resp, head.method()) else {
        return fail(&mut respond, RelayError::BadResponse("conflicting Content-Length"));
    };

    let mut response = Response::new(());
    let Ok(status) = http::StatusCode::from_u16(resp.status) else {
        return fail(&mut respond, RelayError::BadResponse("bad status"));
    };
    *response.status_mut() = status;
    let fields = proxy::response_fields(&resp, &plan);
    let headers = response.headers_mut();
    headers.reserve(fields.len() + 1);
    for (name, value) in &fields {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name), HeaderValue::from_bytes(value)) {
            headers.append(name, value);
        }
    }
    drop(fields);
    match resp_framing {
        ResponseFraming::Length(n) => {
            headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(n));
        }
        ResponseFraming::None if resp.status >= 200 && resp.status != 204 => {
            for v in resp.fields.get_all("content-length") {
                if let Ok(v) = HeaderValue::from_bytes(v) {
                    headers.append(http::header::CONTENT_LENGTH, v);
                }
            }
        }
        _ => {}
    }
    let backend_keeps_alive = resp.version == h1::Version::Http11
        && !resp.fields.has_token("connection", "close")
        && resp_framing != ResponseFraming::Eof;
    drop(resp);
    let end_of_stream = resp_framing == ResponseFraming::None || resp_framing == ResponseFraming::Length(0);
    let send = match respond.send_response(response, end_of_stream) {
        Ok(send) => send,
        Err(e) => {
            tracing::debug!(error = %e, "h2 response head failed");
            return;
        }
    };
    if end_of_stream {
        if pump.is_done() && backend_keeps_alive && up.buf.is_empty() {
            ctx.pool.put(up);
        }
        return;
    }

    let mut resp_pump = RespPump::new(Decoder::for_response(resp_framing), RespSink::H2(H2Send::new(send)));
    let done = std::future::poll_fn(|cx| {
        let mut down = Down::H2;
        if !pump.is_done() {
            match pump.poll(cx, &mut down, &mut up.stream, &mut timers) {
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
    match done {
        Ok(()) => {
            if backend_keeps_alive && pump.is_done() && !pump.is_abandoned() {
                ctx.pool.put(up);
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "h2 exchange failed after the response head");
            if let RespSink::H2(h2) = &mut resp_pump.sink {
                h2.send.send_reset(Reason::INTERNAL_ERROR);
            }
        }
    }
}

/// Send the request head (and body) to the backend and read its response head,
/// skipping interim (1xx) responses; a client reset of the stream ends it.
async fn response_head(
    up: &mut Upstream,
    up_head: &Bytes,
    pump: &mut ReqPump,
    timers: &mut Timers,
    respond: &mut SendResponse<Bytes>,
) -> Result<h1::ResponseHead, RelayError> {
    let mut head_out = Some(Outgoing::new(&[], up_head.clone(), b""));
    let mut interim = 0;
    loop {
        let mut reader = HeadReader::new(4096, MAX_RESPONSE_HEAD);
        let n = std::future::poll_fn(|cx| {
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
            if let Poll::Ready(r) = respond.poll_reset(cx) {
                let e = std::io::Error::other(format!("stream reset: {r:?}"));
                return Poll::Ready(Err(RelayError::ClientIo(e)));
            }
            if !pump.is_done()
                && let Poll::Ready(Err(e)) = pump.poll(cx, &mut Down::H2, &mut up.stream, timers)
            {
                return Poll::Ready(Err(e));
            }
            let before = up.buf.len();
            let event = reader.poll(cx, &mut up.stream, &mut up.buf);
            if up.buf.len() > before {
                timers.backend_progress();
            }
            match event {
                Poll::Ready(Ok(HeadEvent::Complete(n))) => Poll::Ready(Ok(n)),
                Poll::Ready(Ok(HeadEvent::Eof { .. })) => {
                    Poll::Ready(Err(RelayError::BackendIo(std::io::ErrorKind::UnexpectedEof.into())))
                }
                Poll::Ready(Ok(HeadEvent::TooLarge)) => {
                    Poll::Ready(Err(RelayError::BadResponse("response head too large")))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(RelayError::BackendIo(e))),
                Poll::Pending => {
                    if pump.is_done() {
                        timers.backend_waiting(cx)?;
                    }
                    Poll::Pending
                }
            }
        })
        .await?;
        let raw: BytesMut = up.buf.split_to(n);
        let resp = match h1::parse_response(&raw) {
            Ok(resp) => resp,
            Err(h1::HeadError::TooManyFields) => return Err(RelayError::BadResponse("too many response fields")),
            Err(h1::HeadError::Invalid) => return Err(RelayError::BadResponse("malformed response head")),
        };
        if resp.status >= 200 || resp.status == 101 {
            return Ok(resp);
        }
        interim += 1;
        if interim > 8 {
            return Err(RelayError::BadResponse("too many interim responses"));
        }
        // Pass on interim responses (103 Early Hints, 102), not a 100: torii answers
        // `Expect: 100-continue` itself.
        if resp.status != 100
            && let Ok(status) = http::StatusCode::from_u16(resp.status)
        {
            let mut info = Response::new(());
            *info.status_mut() = status;
            for (name, value) in proxy::interim_fields(&resp) {
                if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(&name), HeaderValue::from_bytes(&value)) {
                    info.headers_mut().append(name, value);
                }
            }
            let _ = respond.send_informational(info);
        }
    }
}

/// Answer a stream whose exchange failed before its response head; reset it if
/// there is nothing to answer (the client went away or stalled).
fn fail(respond: &mut SendResponse<Bytes>, e: RelayError) {
    tracing::debug!(error = %e, "h2 exchange failed");
    match e.status() {
        0 => respond.send_reset(Reason::CANCEL),
        status => send_local(respond, &Local::status(status)),
    }
}
