//! Moving bodies between a client and a backend.
//!
//! Pull-based: each direction holds at most one chunk (at most [`CHUNK`] bytes),
//! and reads the next only once the last is written. So what a request holds
//! while its client is slow is one chunk per direction, and the backend's own
//! socket buffers push back on it (nginx's `proxy_buffering off` works the same
//! way). Read buffers are allocated as data arrives and let go when they are
//! empty (see [`poll_read_lazy`]).
//!
//! Every wait is bounded by one of three clocks (see [`Timers`]): the backend's
//! (`--upstream-timeout`, or the rule's), the client's for accepting the
//! response, and the client's for sending the request body, which must bring
//! [`MIN_BODY_PROGRESS`] for each `CLIENT_STALL_TIMEOUT` torii waits on it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use super::MIN_BODY_PROGRESS;
use super::h1::{Decoder, Encoder};
use super::io::{Outgoing, Stream, Timer, poll_read_lazy};

/// Most body bytes read or sent at a time.
pub const CHUNK: usize = 16 * 1024;

/// Why an exchange ended early.
#[derive(Debug)]
pub enum RelayError {
    /// The client went away, or a write to it failed.
    ClientIo(io::Error),
    /// The client stopped accepting the response.
    ClientStalled,
    /// The client sent its request body too slowly.
    ClientBodyStalled,
    /// The request body is malformed.
    BadRequestBody,
    /// Connecting to, writing to or reading from the backend failed.
    BackendIo(io::Error),
    /// The backend made no progress for its timeout.
    BackendTimeout,
    /// The backend's response is malformed.
    BadResponse(&'static str),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::ClientIo(e) => write!(f, "client: {e}"),
            RelayError::ClientStalled => f.write_str("client stopped reading"),
            RelayError::ClientBodyStalled => f.write_str("client request body stalled"),
            RelayError::BadRequestBody => f.write_str("malformed request body"),
            RelayError::BackendIo(e) => write!(f, "backend: {e}"),
            RelayError::BackendTimeout => f.write_str("backend timed out"),
            RelayError::BadResponse(why) => write!(f, "bad backend response: {why}"),
        }
    }
}

impl RelayError {
    /// Whether a failure on a pooled connection looks like the backend had
    /// closed it before torii used it again.
    pub fn is_stale(&self) -> bool {
        match self {
            RelayError::BackendIo(e) => matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
            ),
            _ => false,
        }
    }

    /// The status to answer with, if no response has been sent yet; 0 for none
    /// (the client is gone or not reading). Upstream timeouts are 504 per Gateway
    /// API, other upstream failures 502.
    pub fn status(&self) -> u16 {
        match self {
            RelayError::ClientIo(_) | RelayError::ClientStalled => 0,
            RelayError::ClientBodyStalled => 408,
            RelayError::BadRequestBody => 400,
            RelayError::BackendTimeout => 504,
            RelayError::BackendIo(e) if e.kind() == io::ErrorKind::TimedOut => 504,
            RelayError::BackendIo(_) | RelayError::BadResponse(_) => 502,
        }
    }
}

/// The clocks of one exchange.
pub struct Timers {
    /// The backend's: runs while torii waits on the backend (to accept request
    /// data, or for its response), restarts on any progress.
    backend: Timer,
    backend_after: Option<Duration>,
    /// The client's for its request body (see [`Budget`]).
    body: Budget,
    /// What the client still owes of its current stretch of [`MIN_BODY_PROGRESS`].
    body_owed: u64,
    /// The client's for accepting the response: runs while a write to it waits,
    /// restarts on any progress.
    write: Timer,
    /// How long the client may stall (`Ctx::client_stall`).
    stall: Duration,
}

impl Timers {
    pub fn new(backend_after: Option<Duration>, stall: Duration) -> Timers {
        Timers {
            backend: Timer::new(),
            backend_after,
            body: Budget::new(stall),
            body_owed: MIN_BODY_PROGRESS,
            write: Timer::new(),
            stall,
        }
    }

    pub fn backend_waiting(&mut self, cx: &mut Context<'_>) -> Result<(), RelayError> {
        let Some(after) = self.backend_after else {
            return Ok(());
        };
        self.backend.arm(after);
        if self.backend.poll_expired(cx) {
            return Err(RelayError::BackendTimeout);
        }
        Ok(())
    }

    pub fn backend_progress(&mut self) {
        self.backend.disarm();
    }

    /// Torii waits on the client for request body.
    pub fn body_waiting(&mut self, cx: &mut Context<'_>) -> Result<(), RelayError> {
        if self.body.run(cx) {
            return Err(RelayError::ClientBodyStalled);
        }
        Ok(())
    }

    /// Torii does not wait on the client for request body (it waits on the
    /// backend to take it, or the body is complete): the clock stops.
    pub fn body_not_waiting(&mut self) {
        self.body.pause();
    }

    pub fn body_progress(&mut self, n: usize) {
        self.body_owed = self.body_owed.saturating_sub(n as u64);
        if self.body_owed == 0 {
            self.body_owed = MIN_BODY_PROGRESS;
            self.body.refill();
        }
    }

    pub fn write_waiting(&mut self, cx: &mut Context<'_>) -> Result<(), RelayError> {
        self.write.arm(self.stall);
        if self.write.poll_expired(cx) {
            return Err(RelayError::ClientStalled);
        }
        Ok(())
    }

    pub fn write_progress(&mut self) {
        self.write.disarm();
    }
}

/// A clock that only runs while torii waits on the client, and can be refilled.
struct Budget {
    timer: Timer,
    full: Duration,
    left: Duration,
    /// When the clock last started running, if it is running.
    since: Option<Instant>,
}

impl Budget {
    fn new(full: Duration) -> Budget {
        Budget {
            timer: Timer::new(),
            full,
            left: full,
            since: None,
        }
    }

    /// Run the clock; true once it has run out.
    fn run(&mut self, cx: &mut Context<'_>) -> bool {
        if self.since.is_none() {
            self.since = Some(Instant::now());
            self.timer.rearm(self.left);
        }
        self.timer.poll_expired(cx)
    }

    fn pause(&mut self) {
        if let Some(since) = self.since.take() {
            self.left = self.left.saturating_sub(since.elapsed());
            self.timer.disarm();
        }
    }

    fn refill(&mut self) {
        self.left = self.full;
        if self.since.is_some() {
            self.since = Some(Instant::now());
            self.timer.rearm(self.full);
        }
    }
}

/// A body written to an HTTP/1 connection.
#[derive(Debug)]
pub struct H1Sink {
    encoder: Encoder,
    out: Option<Outgoing>,
    finished: bool,
    /// Bytes were written since the last [`H1Sink::take_progress`].
    progressed: bool,
}

impl H1Sink {
    pub fn new(encoder: Encoder) -> H1Sink {
        H1Sink {
            encoder,
            out: None,
            finished: false,
            progressed: false,
        }
    }

    /// Write the chunk in flight; Ready once nothing is in flight.
    fn poll_out<S: AsyncWrite + Unpin + ?Sized>(&mut self, cx: &mut Context<'_>, io: &mut S) -> Poll<io::Result<()>> {
        while let Some(out) = &mut self.out {
            if out.is_done() {
                self.out = None;
                break;
            }
            ready!(out.poll_write(io, cx))?;
            self.progressed = true;
        }
        Poll::Ready(Ok(()))
    }

    fn take_progress(&mut self) -> bool {
        std::mem::take(&mut self.progressed)
    }

    fn start(&mut self, data: Bytes) {
        self.out = Some(self.encoder.frame(data));
    }

    /// Queue bytes to write as they are, outside the body's framing (a head).
    pub fn start_raw(&mut self, data: Bytes) {
        self.out = Some(Outgoing::new(&[], data, b""));
    }

    /// Queue the end of the body (once).
    fn queue_finish(&mut self) {
        if !self.finished {
            self.finished = true;
            self.out = self.encoder.finish();
        }
    }
}

/// The request body's source.
pub enum ReqSource {
    /// From an HTTP/1 client, through its connection's buffer.
    H1(Decoder),
    /// From an HTTP/2 stream. `unreleased`: the flow-control window of the chunk
    /// last handed on, given back once it is written to the backend, so the client
    /// can send no further ahead than torii forwards.
    H2 { recv: h2::RecvStream, unreleased: usize },
    /// No body.
    None,
}

/// The client side of an exchange, for [`ReqPump::poll`] and [`RespPump::poll`].
pub enum Down<'a> {
    H1 { io: &'a mut Stream, buf: &'a mut BytesMut },
    H2,
}

impl ReqSource {
    fn poll_chunk(&mut self, cx: &mut Context<'_>, down: &mut Down<'_>) -> Poll<Result<Option<Bytes>, RelayError>> {
        match self {
            ReqSource::None => Poll::Ready(Ok(None)),
            ReqSource::H1(decoder) => {
                let Down::H1 { io, buf } = down else {
                    return Poll::Ready(Ok(None));
                };
                loop {
                    match decoder.decode_gathered(buf, CHUNK) {
                        Err(e) => {
                            tracing::debug!(error = e.0, "malformed request body");
                            return Poll::Ready(Err(RelayError::BadRequestBody));
                        }
                        Ok(Some(data)) => return Poll::Ready(Ok(Some(data))),
                        Ok(None) if decoder.is_done() => return Poll::Ready(Ok(None)),
                        Ok(None) => {}
                    }
                    match ready!(poll_read_lazy(&mut **io, cx, buf, CHUNK)) {
                        Ok(0) => {
                            return Poll::Ready(Err(RelayError::ClientIo(io::ErrorKind::UnexpectedEof.into())));
                        }
                        Ok(_) => {}
                        Err(e) => return Poll::Ready(Err(RelayError::ClientIo(e))),
                    }
                }
            }
            ReqSource::H2 { recv, unreleased } => {
                if *unreleased > 0 {
                    let _ = recv.flow_control().release_capacity(*unreleased);
                    *unreleased = 0;
                }
                loop {
                    return match ready!(recv.poll_data(cx)) {
                        Some(Ok(data)) if data.is_empty() => continue,
                        Some(Ok(data)) => {
                            *unreleased = data.len();
                            Poll::Ready(Ok(Some(data)))
                        }
                        Some(Err(e)) => Poll::Ready(Err(RelayError::ClientIo(io::Error::other(e)))),
                        // Trailers, if any, are dropped.
                        None => Poll::Ready(Ok(None)),
                    };
                }
            }
        }
    }
}

/// The request body, from the client to the backend.
pub struct ReqPump {
    source: ReqSource,
    sink: H1Sink,
    done: bool,
    /// A write to the backend failed after its response began: the rest of the
    /// body is not sent, and neither connection can be reused.
    abandoned: bool,
}

impl ReqPump {
    pub fn new(source: ReqSource, encoder: Encoder) -> ReqPump {
        let done = matches!(source, ReqSource::None);
        ReqPump {
            source,
            sink: H1Sink::new(encoder),
            done,
            abandoned: false,
        }
    }

    /// The whole body was sent.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Stop sending (a write to the backend failed after its response began).
    pub fn abandon(&mut self) {
        self.done = true;
        self.abandoned = true;
    }

    pub fn is_abandoned(&self) -> bool {
        self.abandoned
    }

    /// Move the request body on. Ready(Ok(())) once all of it is sent.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        down: &mut Down<'_>,
        up: &mut Stream,
        timers: &mut Timers,
    ) -> Poll<Result<(), RelayError>> {
        loop {
            if self.done {
                timers.body_not_waiting();
                return Poll::Ready(Ok(()));
            }
            let out = self.sink.poll_out(cx, up);
            if self.sink.take_progress() {
                timers.backend_progress();
            }
            match out {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(RelayError::BackendIo(e))),
                Poll::Pending => {
                    timers.body_not_waiting();
                    timers.backend_waiting(cx)?;
                    return Poll::Pending;
                }
            }
            if self.sink.finished {
                match Pin::new(&mut *up).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(RelayError::BackendIo(e))),
                    Poll::Pending => {
                        timers.backend_waiting(cx)?;
                        return Poll::Pending;
                    }
                }
                self.done = true;
                continue;
            }
            match self.source.poll_chunk(cx, down) {
                Poll::Ready(Ok(Some(data))) => {
                    timers.body_progress(data.len());
                    self.sink.start(data);
                }
                Poll::Ready(Ok(None)) => {
                    self.sink.queue_finish();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    timers.body_waiting(cx)?;
                    return Poll::Pending;
                }
            }
        }
    }
}

/// An HTTP/2 stream's response body (see [`RespSink::H2`]).
pub struct H2Send {
    pub send: h2::SendStream<Bytes>,
    /// Data not handed to h2 yet: it waits for flow-control capacity.
    pending: Bytes,
    finished: bool,
    progressed: bool,
}

impl H2Send {
    pub fn new(send: h2::SendStream<Bytes>) -> H2Send {
        H2Send {
            send,
            pending: Bytes::new(),
            finished: false,
            progressed: false,
        }
    }

    /// Hand `pending` to h2 as the stream's flow-control window allows.
    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            self.send.reserve_capacity(self.pending.len());
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(0))) => {}
                Poll::Ready(Some(Ok(n))) => {
                    let part = self.pending.split_to(n.min(self.pending.len()));
                    self.send.send_data(part, false).map_err(io::Error::other)?;
                    self.progressed = true;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Pending => {
                    // Waiting for window: notice if the client resets the stream.
                    if let Poll::Ready(r) = self.send.poll_reset(cx) {
                        let reason = r.map_err(io::Error::other)?;
                        return Poll::Ready(Err(io::Error::other(format!("stream reset: {reason:?}"))));
                    }
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Where the response body goes.
pub enum RespSink {
    H1(H1Sink),
    H2(H2Send),
}

impl RespSink {
    /// Hand on the data in flight; Ready once none is left.
    fn poll_out(&mut self, cx: &mut Context<'_>, down: &mut Down<'_>) -> Poll<io::Result<()>> {
        match (self, down) {
            (RespSink::H1(sink), Down::H1 { io, .. }) => sink.poll_out(cx, &mut **io),
            (RespSink::H2(h2), _) => h2.poll_out(cx),
            (RespSink::H1(_), Down::H2) => Poll::Ready(Err(io::Error::other("HTTP/1 sink on an HTTP/2 stream"))),
        }
    }

    fn take_progress(&mut self) -> bool {
        match self {
            RespSink::H1(sink) => sink.take_progress(),
            RespSink::H2(h2) => std::mem::take(&mut h2.progressed),
        }
    }

    fn start(&mut self, data: Bytes) {
        match self {
            RespSink::H1(sink) => sink.start(data),
            RespSink::H2(h2) => h2.pending = data,
        }
    }

    /// End the body; Ready(Ok(())) once the end is handed on.
    fn poll_finish(&mut self, cx: &mut Context<'_>, down: &mut Down<'_>) -> Poll<io::Result<()>> {
        match self {
            RespSink::H1(sink) => {
                sink.queue_finish();
                let Down::H1 { io, .. } = down else {
                    return Poll::Ready(Ok(()));
                };
                ready!(sink.poll_out(cx, &mut **io))?;
                Pin::new(&mut **io).poll_flush(cx)
            }
            RespSink::H2(h2) => {
                if !h2.finished {
                    h2.finished = true;
                    h2.send.send_data(Bytes::new(), true).map_err(io::Error::other)?;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// The backend side of an exchange.
pub struct Up<'a> {
    pub io: &'a mut Stream,
    pub buf: &'a mut BytesMut,
}

/// The response body, from the backend to the client.
pub struct RespPump {
    decoder: Decoder,
    pub sink: RespSink,
    done: bool,
}

impl RespPump {
    pub fn new(decoder: Decoder, sink: RespSink) -> RespPump {
        RespPump {
            decoder,
            sink,
            done: false,
        }
    }

    /// Move the response body on. Ready(Ok(())) once all of it is handed to the
    /// client.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        down: &mut Down<'_>,
        up: &mut Up<'_>,
        timers: &mut Timers,
    ) -> Poll<Result<(), RelayError>> {
        loop {
            let out = self.sink.poll_out(cx, down);
            if self.sink.take_progress() {
                timers.write_progress();
            }
            match out {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(RelayError::ClientIo(e))),
                Poll::Pending => {
                    timers.write_waiting(cx)?;
                    return Poll::Pending;
                }
            }
            if self.done {
                return match self.sink.poll_finish(cx, down) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(RelayError::ClientIo(e))),
                    Poll::Pending => {
                        timers.write_waiting(cx)?;
                        Poll::Pending
                    }
                };
            }
            match self.decoder.decode_gathered(up.buf, CHUNK) {
                Err(e) => return Poll::Ready(Err(RelayError::BadResponse(e.0))),
                Ok(Some(data)) => {
                    self.sink.start(data);
                    continue;
                }
                Ok(None) if self.decoder.is_done() => {
                    self.done = true;
                    continue;
                }
                Ok(None) => {}
            }
            match poll_read_lazy(&mut *up.io, cx, up.buf, CHUNK) {
                Poll::Ready(Ok(0)) => {
                    if self.decoder.on_eof().is_err() {
                        return Poll::Ready(Err(RelayError::BadResponse(
                            "backend closed before the end of the body",
                        )));
                    }
                }
                Poll::Ready(Ok(_)) => timers.backend_progress(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(RelayError::BackendIo(e))),
                Poll::Pending => {
                    timers.backend_waiting(cx)?;
                    // While the backend works, notice an HTTP/2 client that resets
                    // the stream.
                    if let RespSink::H2(h2) = &mut self.sink
                        && let Poll::Ready(r) = h2.send.poll_reset(cx)
                    {
                        let e = io::Error::other(format!("stream reset: {r:?}"));
                        return Poll::Ready(Err(RelayError::ClientIo(e)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

/// Copy bytes both ways between `a` and `b` until both directions have ended
/// (EOF, then the other side's write half shut down), or no byte moved either way
/// for `idle`. Each direction holds a buffer only while it holds bytes; `a_buf`
/// and `b_buf` may start with bytes already read from `a` and `b`.
///
/// Used for TLSRoute connections and upgraded (WebSocket) requests.
pub async fn pipe<A, B>(
    a: &mut A,
    a_buf: &mut BytesMut,
    b: &mut B,
    b_buf: &mut BytesMut,
    idle: Option<Duration>,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = Half::default();
    let mut b_to_a = Half::default();
    let mut timer = Timer::new();
    std::future::poll_fn(|cx| {
        loop {
            let p1 = a_to_b.poll(cx, a, a_buf, b)?;
            let p2 = b_to_a.poll(cx, b, b_buf, a)?;
            if a_to_b.done && b_to_a.done {
                return Poll::Ready(Ok(()));
            }
            if p1 || p2 {
                timer.disarm();
                continue;
            }
            return match idle {
                Some(after) => timer.poll_stall(cx, after),
                None => Poll::Pending,
            };
        }
    })
    .await
}

/// One direction of [`pipe`].
#[derive(Default)]
struct Half {
    eof: bool,
    done: bool,
}

impl Half {
    /// Move bytes from `src` (through `buf`) to `dst`. Ok(true) if any moved.
    fn poll<S, D>(&mut self, cx: &mut Context<'_>, src: &mut S, buf: &mut BytesMut, dst: &mut D) -> io::Result<bool>
    where
        S: AsyncRead + Unpin + ?Sized,
        D: AsyncWrite + Unpin + ?Sized,
    {
        let mut progressed = false;
        while !self.done {
            if !buf.is_empty() {
                match Pin::new(&mut *dst).poll_write(cx, buf) {
                    Poll::Ready(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                    Poll::Ready(Ok(n)) => {
                        let _ = buf.split_to(n);
                        progressed = true;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Err(e),
                    Poll::Pending => break,
                }
            }
            if self.eof {
                match Pin::new(&mut *dst).poll_shutdown(cx) {
                    Poll::Ready(_) => {
                        self.done = true;
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
                break;
            }
            match Pin::new(&mut *dst).poll_flush(cx) {
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Ready(Ok(())) | Poll::Pending => {}
            }
            match poll_read_lazy(src, cx, buf, CHUNK) {
                Poll::Ready(Ok(0)) => {
                    self.eof = true;
                    progressed = true;
                }
                Poll::Ready(Ok(_)) => progressed = true,
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => break,
            }
        }
        Ok(progressed)
    }
}
