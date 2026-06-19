# TLSRoute implementation plan (SNI passthrough + terminate on a shared port)

Status: **IMPLEMENTED** (2026-06-20). The design below was followed as written and
needed no edits to vendored `pingora/`. Shipped as `lolgateway/src/tls_sni.rs`
(ClientHello SNI parser) + `lolgateway/src/tls_table.rs` (`TlsTable` SNI dispatch),
plus `GatewayTlsApp` in `dataplane.rs` and TLSRoute reconcile in `controller.rs`.
Conformance: **11/12** TLSRoute tests pass; the lone gap is
`TLSRouteHostnameIntersection`, which requires per-Gateway distinct addresses (we
advertise a single shared address — a pre-existing limitation shared with the HTTP
data path, not TLSRoute-specific).

Two implementation notes not in the original design:
- `Box<dyn IO>` (i.e. `protocols::Stream`) does **not** itself implement `IO`, so it
  can't be passed to `handshake_with_callback<S: IO>` / `ServerSession::new_http1`
  directly. We wrap it in a `BoxedStream` newtype that delegates every `IO`
  supertrait to the inner box; the blanket `impl IO for T` then applies.
- `flush_status` must apply patches with `join_all`, not `try_join_all` — one bad
  patch was aborting the whole status batch. And a `ProtocolConflict` listener must
  report **empty** `supportedKinds` (the suite's `gatewayListenersMatch` requires it).

Every Pingora API cited below was read directly in the vendored `pingora/` tree and
verified by file:line.

## 1. What we have to build (from conformance)

TLSRoute routes a raw TCP connection by the **SNI** in the TLS ClientHello. There
is **no** path / header / method matching — `TLSRouteSpec` is just `Hostnames`
(SNI globs) → `Rules[].BackendRefs` (weighted), per
`gateway-api/apis/v1alpha2/tlsroute_types.go:50`. The Rust `gateway-api` crate
(0.21.0) already ships the types: `gateway_api::apis::standard::tlsroutes` — **no
CRD codegen needed.**

Two modes, both of which bottom out in an **L4 byte pipe**, not HTTP:

| Mode | Gateway decrypts? | Data path | Conformance backend sees |
|---|---|---|---|
| **Passthrough** (`tls.mode: Passthrough`, Core) | No | peek SNI → bidirectional pipe of the *encrypted* bytes to the backend | `BackendIsTLS: true` (backend terminates TLS itself) |
| **Terminate** (`tls.mode: Terminate`, Extended) | Yes | peek SNI → terminate TLS here → bidirectional pipe of the *cleartext* TCP to the backend | `BackendIsTLS: false`, no SNI on the backend conn |

**Critical subtlety the conformance reading forced:** TLSRoute *terminate* is **not
HTTP**. The conformance TCP backend (`conformance/echo-basic/tcpserver/tcpserver.go:32`)
speaks a line protocol — it sends a welcome line **first**, then answers
`PING`→`PONG`, `IS_TLS`, `TEST`. The test harness
(`conformance/utils/tcp/tcp.go`, `MakeTCPRequestAndExpectEventuallyValidResponse`)
reads the welcome line before writing anything. So:

* Both modes need a **true full-duplex pipe** (`copy_bidirectional`-style, both
  directions armed concurrently). A half-duplex "request then response" copy
  deadlocks because the server talks first.
* Terminate mode does **not** reuse our existing `ProxyHttp` HTTP machinery. After
  TLS termination it is a plain TCP relay. (Our HTTPS *HTTPRoute* path is
  unaffected and unchanged.)

Matching tests in `gateway-api/conformance/tests/`:

* `tlsroute-simple-same-namespace` — passthrough, Core. **First target.**
* `tlsroute-terminate-simple-same-namespace` — terminate, Extended, `Provisional`.
* `tlsroute-mixed-termination-same-namespace` — terminate + passthrough on **one
  port**, Extended (`SupportTLSRouteModeMixed`, Experimental channel), `Provisional`.
* `tlsroute-listener-mixed-termination-not-supported` — if we *don't* claim
  `SupportTLSRouteModeMixed`, a listener with two TLS modes on one port MUST get
  `Accepted=False` / `Reason=ProtocolConflict`.
* `tlsroute-hostname-intersection`, `tlsroute-invalid-*`, `tlsroute-listener-*-supported-kinds`
  — status / attachment only (control-plane work, mirrors existing HTTPRoute logic).

The controller already has the listener scaffolding: it maps `protocol: "TLS"` →
`supportedKinds: ["TLSRoute"]` and detects `GatewayListenersTlsMode::Passthrough`
(`lolgateway/src/controller.rs:517,572`). It just never built a data path for it.

## 2. The Pingora integration point (verified — no `pingora/` edits required)

The clean seam is to run **our own `ServerApp` on a plain-TCP listener**, peek the
ClientHello ourselves, and branch. Pingora exposes everything we need publicly.

### 2.1 Why a custom `ServerApp` works

* `ServerApp::process_new(self: &Arc<Self>, session: Stream, shutdown: &ShutdownWatch) -> Option<Stream>`
  — `pingora-core/src/apps/mod.rs:50`. This is the lowest per-connection hook.
* `Stream = Box<dyn IO>` — `pingora-core/src/protocols/mod.rs:136`. (One research
  pass wrongly described `Stream` as a concrete struct with named fields — that is
  the *l4* `Stream`, a different type. Do **not** try to name fields on
  `protocols::Stream`; it is a trait object.)
* On a listener added with **`add_tcp`** (no TLS acceptor configured), the
  service's accept loop runs `io.handshake()` as a **no-op** and hands
  `process_new` the **raw, un-decrypted** L4 stream. The TLS handshake in
  `pingora-core/src/services/listening.rs:234` only does real work when the
  endpoint was added via `add_tls*`. So a plain-TCP endpoint + our `ServerApp` =
  we own the raw bytes. This is exactly the pattern Pingora itself uses to sniff
  the HTTP/2 cleartext preface (`apps/mod.rs:274-291` calls `try_peek`).

### 2.2 Non-destructive SNI peek

* `Peek::try_peek(&mut self, buf) -> io::Result<bool>` —
  `pingora-core/src/protocols/l4/stream.rs:630`. **Implementation detail that
  matters:** it is `read_exact(buf)` **then** `rewind(buf)` — i.e. "read exactly
  `buf.len()` bytes, then put them back." It is **not** `MSG_PEEK`.
* `Stream::rewind(&mut self, data)` — `stream.rs:510`, documented for the
  "detect a protocol then unread" use case. The `AsyncRead` impl drains
  `rewind_read_buf` (LIFO) before touching the socket (`stream.rs:731-743`), so
  after a peek the **full original byte stream replays intact** to whoever reads
  next — the backend pipe (passthrough) or the TLS acceptor (terminate).
* **Consequence (must respect):** because `try_peek` is `read_exact`, peeking a
  fixed oversized buffer **deadlocks** waiting for bytes a small ClientHello will
  never send. We must size the peek correctly:
  1. `try_peek` the **5-byte TLS record header**. Require `hdr[0] == 0x16`
     (handshake). `rec_len = u16::from_be_bytes(hdr[3..5])`.
  2. `try_peek` exactly `5 + rec_len` bytes (cap to a sane max, e.g. 16 KiB).
  3. Parse SNI from that buffer.
  4. Wrap the whole peek in a `tokio::time::timeout` so a stalled/partial
     handshake can't hang a task. On timeout / non-TLS / parse-failure → treat as
     "no SNI".
* **Pingora has no ClientHello/SNI parser** and vendors no `tls-parser`-style
  dependency (confirmed by grep). We write a small one (~60 lines): walk record →
  handshake → ClientHello → extensions → `server_name` (type 0). Unit-tested
  against real captures (TLS 1.2 with SNI, TLS 1.3, and no-SNI).

### 2.3 Terminate branch: drive TLS ourselves on the rewound stream

* `handshake_with_callback<S: IO>(ssl_acceptor: &SslAcceptor, io: S, callbacks: &TlsAcceptCallbacks) -> Result<SslStream<S>>`
  — `pingora-core/src/protocols/tls/boringssl_openssl/server.rs:49`, re-exported
  via `pub use boringssl_openssl::*` (`tls/mod.rs:24`). Runs the server handshake
  on **any `S: IO`**, including our rewound `Stream`, and invokes the **same
  `TlsAccept::certificate_callback`** we already use for per-SNI cert selection.
  So our existing `SniCertCallback` (`dataplane.rs:515`) is reused verbatim as the
  `callbacks` argument.
* `SslStream<S>: IO` (all required super-traits impl'd —
  `tls/boringssl_openssl/stream.rs` + shared `impl<S>` in `.../client.rs`), so
  `Box::new(tls_stream)` is a `Stream` again and feeds straight into the cleartext
  TCP relay.
* **The blocker, and the workaround:** Pingora's `Acceptor` and
  `TlsSettings::build()` are `pub(crate)`
  (`listeners/tls/boringssl_openssl/mod.rs:33,132`), so we can't reuse the
  acceptor object an `add_tls*` listener would build. Instead we **build the
  `SslAcceptor` ourselves**, once, at startup:
  `SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())` via
  `pingora_core::tls::ssl` (reachable: `tls = pingora_openssl`, which does
  `pub use ssl_lib::ssl`). Our existing ACME `set_alpn_select_callback` logic
  (`dataplane.rs:589`) moves onto that builder **unchanged** (same
  `SslAcceptorBuilder` method, reachable via `TlsSettings: DerefMut`). This is ~5
  lines, not a reimplementation.

### 2.4 Terminate-of-HTTPRoute vs terminate-of-TLSRoute

Two different terminate destinations share the SNI-dispatch front door:

* **TLSRoute terminate** → after `handshake_with_callback`, **byte-pipe the
  cleartext to the TLSRoute backend** (no HTTP parsing).
* **HTTPS HTTPRoute** (our existing feature) → after termination, run the HTTP
  proxy. For this we use the **new** factory
  `http_proxy(conf, GatewayProxy) -> HttpProxy<GatewayProxy>`
  (`pingora-proxy/src/lib.rs:43`) — its doc comment literally says it exists "for
  example when implementing SNI-based routing that decides between TLS passthrough
  and TLS termination on a single port" (`lib.rs:16`). It returns a fully
  initialized `HttpProxy` (init modules already run). We drive it with the public
  `process_new_http(self: &Arc<Self>, ServerSession, &ShutdownWatch) -> Option<ReusedHttpStream>`
  (`lib.rs:1281`), wrapping the `SslStream` via `ServerSession::new_http1(stream)`
  (`http/server.rs:65`), and replicate Pingora's own keepalive-reuse loop
  (verbatim from `apps/mod.rs:343-351`, using `ReusedHttpStream::consume()` at
  `apps/mod.rs:203`).

> **Scope note / simplification:** for the *first* TLSRoute milestone we do **not**
> have to fold HTTPS-HTTPRoute into the custom app. We can keep today's
> `http_proxy_service` + `add_tls_with_settings` exactly as-is for ports that have
> **only** HTTPRoute/HTTPS, and stand up the custom `ServerApp` **only on ports
> that carry at least one TLSRoute**. Merging both onto one app (so a single 443
> can mix HTTPS-HTTPRoute *and* TLSRoute) is a later step and only needed if a
> Gateway actually configures that combination. Start narrow.

### 2.5 Passthrough + terminate duplex pipe

Plain `tokio::io::copy_bidirectional(&mut downstream, &mut upstream)` — both
`Stream` and `SslStream<Stream>` are `AsyncRead + AsyncWrite + Unpin`. (Pingora
ships **no** `copy_bidirectional` helper of its own — confirmed by grep; an
earlier note citing `examples/app/proxy.rs` was wrong, that file does not exist in
this checkout. Use the tokio primitive, or a small `select!` loop if we want
custom idle-timeout handling.)

Upstream connection for the pipe: resolve the TLSRoute backendRef to `ip:port`
(reusing the existing Service→EndpointSlice resolution) and either
`tokio::net::TcpStream::connect` directly, or Pingora's
`TransportConnector::new_stream(&BasicPeer::new("ip:port"))`
(`connectors/mod.rs:226`, `upstreams/peer.rs:319`). Direct tokio is simplest and
has zero TLS involvement, which is what passthrough wants.

## 3. Per-connection control flow (the custom `ServerApp`)

```
process_new(stream: Stream /* raw L4, Box<dyn IO> */, shutdown):
    # 1. Peek SNI (record-header-first, length-bounded, timeout-wrapped).
    sni = peek_sni(&mut stream).await        # Option<String>; None on non-TLS / timeout / parse-fail

    # 2. Look up decision in the lock-free snapshot.
    snap = self.data_plane.load()
    match snap.tls_l4_lookup(self.port, sni.as_deref()):

      Passthrough(backend):                  # bytes already rewound, intact
        up = connect(backend).await?         # plain TcpStream to ip:port
        copy_bidirectional(&mut stream, &mut up).await
        return None

      TerminateTcp(backend):                 # TLSRoute terminate
        tls = handshake_with_callback(&self.ssl_acceptor, stream, &self.sni_cb).await?
        up  = connect(backend).await?
        copy_bidirectional(&mut Box::new(tls), &mut up).await
        return None

      TerminateHttp:                         # HTTPS HTTPRoute (only if this port is merged)
        tls  = handshake_with_callback(&self.ssl_acceptor, stream, &self.sni_cb).await?
        sess = ServerSession::new_http1(Box::new(tls))
        # keepalive-reuse loop, copied from apps/mod.rs:343-351
        let mut result = self.proxy.process_new_http(sess, shutdown).await
        while let Some((s, ps)) = result.map(|r| r.consume()):
            let mut sess = ServerSession::new_http1(s)
            if let Some(ps) = ps { ps.apply_to_session(&mut sess) }
            result = self.proxy.process_new_http(sess, shutdown).await
        return None

      NoRoute:
        return None                          # drop the connection (no SNI match)
```

`peek_sni` (the only genuinely new low-level code):

```
peek_sni(stream):
    hdr = [0u8; 5]
    timeout(T, stream.try_peek(&mut hdr)).await ?? -> None
    if hdr[0] != 0x16: return None                       # not a TLS handshake
    rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize
    n = min(5 + rec_len, MAX_CH)                          # cap, e.g. 16 KiB
    buf = vec![0u8; n]
    timeout(T, stream.try_peek(&mut buf)).await ?? -> None
    parse_client_hello_sni(&buf)                          # our parser, Option<String>
```

## 4. Route-table / snapshot data model

Add a per-port SNI map **inside the existing `ArcSwap<Snapshot>`** — no new swap
mechanism, published in the same atomic store as routes + certs
(`lolgateway/src/snapshot.rs`).

```rust
pub struct Snapshot {
    pub routes: RouteTable,          // existing: (port, host) HTTP index
    pub certs:  CertStore,           // existing
    pub tls_l4: HashMap<u16, TlsPortCfg>,   // NEW: per-port SNI dispatch
}

struct TlsPortCfg {
    // SNI → action. Mirrors the listener-isolation tiering we already do for HTTP:
    exact:    HashMap<String, TlsAction>,        // "test.example.com"
    wildcard: Vec<(String, TlsAction)>,          // (".example.com", action)
    // Does this port also terminate-for-HTTP (HTTPS HTTPRoute)? Only set when we
    // merge HTTPS onto the custom app (see §2.4 scope note).
    terminate_http_default: bool,
}

enum TlsAction {
    Passthrough(Backend),   // weighted backend set, like HTTP backendRefs
    TerminateTcp(Backend),  // TLSRoute terminate → cleartext TCP relay
}

enum TlsDecision { Passthrough(Backend), TerminateTcp(Backend), TerminateHttp, NoRoute }

impl Snapshot {
    fn tls_l4_lookup(&self, port: u16, sni: Option<&str>) -> TlsDecision {
        // exact SNI → wildcard-suffix (most-specific) → terminate_http_default → NoRoute
    }
}
```

* `Backend` reuses the existing weighted-endpoint type and the existing
  Service→EndpointSlice resolution + ReferenceGrant checks the HTTPRoute path
  already implements.
* Wildcard/most-specific selection reuses the same logic as
  `RouteTable::match_request`'s hostname tiers.

## 5. Control-plane work (status — mirrors existing HTTPRoute reconcile)

These are the bulk of the conformance tests and are ordinary reconciler work, not
data-plane:

1. **Watch `TLSRoute`** (add to the controller's watch set + reflector store; it is
   level-triggered like the rest — no resync).
2. **Attachment / `Accepted`:** parentRef + section/port match; **SNI hostname
   intersection** between the TLSRoute `hostnames` and the listener hostname
   (`tlsroute-hostname-intersection`, and the listener spec rules quoted in
   `tlsroute_types.go:53`). No intersection → `Accepted=False`.
3. **`ResolvedRefs`:** backendRef resolution, unknown kind, cross-namespace +
   ReferenceGrant (`tlsroute-invalid-backendref-*`, `tlsroute-invalid-reference-grant`).
   Reuse the HTTPRoute resolver.
4. **Listener `supportedKinds`** for `protocol: TLS` already returns `["TLSRoute"]`
   (`controller.rs:517`); the passthrough/terminate "supported-kinds" tests just
   assert that + `AttachedRoutes` counts.
5. **`AttachedRoutes`** counts per listener.
6. **Mixed-mode decision (see §6).**

## 6. Feature claims & the mixed-mode decision

The architecture **physically supports** terminate + passthrough on one port
(`tls_l4_lookup` returns a per-SNI action on the same custom app). That means we
*can* eventually claim the Extended feature **`SupportTLSRouteModeMixed`** instead
of being forced into `ProtocolConflict`. But:

* **Claim incrementally, gated on green tests.** Order:
  1. `SupportTLSRoute` (Core, passthrough) — the first milestone.
  2. `SupportTLSRouteModeTerminate` (Extended) — once the terminate relay passes.
  3. `SupportTLSRouteModeMixed` (Extended, **Experimental channel**) — last.
* **Until `Mixed` is claimed and tested:** a Gateway port carrying both a
  Terminate and a Passthrough TLS listener MUST report those listeners
  `Accepted=False` / `Reason=ProtocolConflict`
  (`tlsroute-listener-mixed-termination-not-supported`). The controller must
  implement that conflict detection now, and only relax it when we flip the
  `Mixed` feature on.
* **Profile / scope caution (per memory `conformance-gotchas`):** enabling
  TLSRoute pulls the suite into the **GATEWAY-TLS** profile, which also drags in
  out-of-scope routes (e.g. TLSRoute terminate's `Provisional` tests, and the TLS
  profile historically pulled TLSRoute-adjacent things). Today we run
  **GATEWAY-HTTP only** and it is fully green (405/0/87). **Do not** flip the
  profile wholesale; scope TLSRoute conformance runs to the specific TLSRoute
  tests (`--run-test=...`) while iterating, and decide deliberately before adding
  GATEWAY-TLS to the default profile set so we don't regress the green HTTP run.

## 7. Known risks / non-goals

* **`try_peek` is `read_exact`, not `MSG_PEEK`** — the record-header-first +
  timeout discipline in §2.2 is mandatory, not optional. This is the single
  sharpest correctness edge.
* **h2 over *terminated* TLSRoute path:** our manual loop uses `new_http1` only.
  This is **not a regression**: our existing ALPN callback NOACKs everything but
  `acme-tls/1`, so clients already fall back to HTTP/1.1 today. h2-over-terminated
  (replicating `apps/mod.rs:292-325`) is a deliberate later follow-up, and is
  irrelevant to TLSRoute (which never parses HTTP).
* **Client source IP on a future merged port:** if we later route *all* 443
  through the custom app, nothing is lost vs today (we terminate in-process, same
  as now). We are **not** adding a second-hop/loopback design (the rejected
  "sidecar" approach) precisely because it would lose client IP and double the
  sockets.
* **No `pingora/` edits.** Everything above is public API. The only friction
  (`Acceptor`/`build()` being `pub(crate)`) is sidestepped by self-building the
  `SslAcceptor` (§2.3). If we ever wanted to upstream a courtesy change, the
  minimal diff would be `pub`-ifying `Acceptor` + `TlsSettings::build()` — but it
  is **not required** for this work.

## 8. Implementation checklist (ordered)

1. **ClientHello SNI parser** `parse_client_hello_sni(&[u8]) -> Option<String>` +
   unit tests (TLS1.2+SNI, TLS1.3, no-SNI, truncated). Pure function, no Pingora.
2. **`peek_sni(&mut Stream)`** — record-header-first, length-bounded,
   `tokio::time::timeout`-wrapped; any failure → `None`.
3. **Self-built `Arc<SslAcceptor>`** in `dataplane::run` via
   `SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())`; move the existing
   `set_alpn_select_callback` ACME logic onto it; keep `SniCertCallback` as the
   `&TlsAcceptCallbacks`.
4. **`Snapshot.tls_l4` + `tls_l4_lookup`** data model (§4); control plane resolves
   TLSRoute backendRefs → `Backend`.
5. **`GatewayTlsApp: ServerApp`** implementing the §3 `process_new`
   (peek → lookup → passthrough pipe / terminate-tcp pipe / [terminate-http]).
   Duplex via `tokio::io::copy_bidirectional`.
6. **Wire it up in `dataplane::run`:** for ports carrying a TLSRoute, register a
   `Service::new("tlsroute:{port}", GatewayTlsApp{..})` + `add_tcp(port)` (raw
   TCP). Keep existing `http_proxy_service` path for HTTP/HTTPS-only ports.
7. **Control-plane TLSRoute reconcile:** watch + attachment/`Accepted` (SNI
   intersection) + `ResolvedRefs` + `AttachedRoutes` + mixed-mode `ProtocolConflict`
   (§5, §6). Reuse HTTPRoute resolvers.
8. **e2e:** a passthrough backend that **speaks first** (welcome + PING/PONG) to
   prove true full-duplex; then TLSRoute-scoped conformance
   (`--run-test=TLSRouteSimpleSameNamespace` first), expanding to terminate/mixed.
   Keep the GATEWAY-HTTP run green throughout (§6).

## 9. Key source citations (all verified in `pingora/`)

| API | Location |
|---|---|
| `ServerApp::process_new(.., Stream, ..) -> Option<Stream>` | `pingora-core/src/apps/mod.rs:50` |
| `Stream = Box<dyn IO>` (trait object) | `pingora-core/src/protocols/mod.rs:136` |
| TLS handshake runs in service accept loop (no-op for `add_tcp`) | `pingora-core/src/services/listening.rs:234` |
| Pingora's own peek-the-preface precedent | `pingora-core/src/apps/mod.rs:274-291` |
| `Peek::try_peek` = `read_exact` + `rewind` | `pingora-core/src/protocols/l4/stream.rs:630` |
| `Stream::rewind` ("detect protocol then unread") | `pingora-core/src/protocols/l4/stream.rs:510` |
| rewind replays before socket on next read | `pingora-core/src/protocols/l4/stream.rs:731-743` |
| `handshake_with_callback<S: IO>(&SslAcceptor, io, &TlsAcceptCallbacks)` | `pingora-core/src/protocols/tls/boringssl_openssl/server.rs:49` |
| `pub use boringssl_openssl::*` (re-export) | `pingora-core/src/protocols/tls/mod.rs:24` |
| `Acceptor` / `TlsSettings::build()` are `pub(crate)` (the blocker) | `pingora-core/src/listeners/tls/boringssl_openssl/mod.rs:33,132` |
| `http_proxy()` factory + "single port passthrough/terminate" doc | `pingora-proxy/src/lib.rs:43` (doc at `:16`) |
| `process_new_http(.., ServerSession, ..) -> Option<ReusedHttpStream>` | `pingora-proxy/src/lib.rs:1281` |
| `ReusedHttpStream::consume() -> (Stream, Option<HttpPersistentSettings>)` | `pingora-core/src/apps/mod.rs:203` |
| keepalive-reuse loop to copy | `pingora-core/src/apps/mod.rs:343-351` |
| `ServerSession::new_http1(stream: Stream)` | `pingora-core/src/protocols/http/server.rs:65` |
| `TransportConnector::new_stream(&BasicPeer)` (optional upstream conn) | `pingora-core/src/connectors/mod.rs:226`, `upstreams/peer.rs:319` |
| `TLSRouteSpec` (Hostnames + Rules, no path/header match) | `gateway-api/apis/v1alpha2/tlsroute_types.go:50` |
| Rust types already exist | `gateway-api` crate 0.21.0 `apis::standard::tlsroutes` |
| TCP backend line protocol (server speaks first) | `conformance/echo-basic/tcpserver/tcpserver.go:32` |
| TCP test reads welcome before writing (needs full-duplex) | `conformance/utils/tcp/tcp.go` |

### Corrections to the research (claims that did NOT hold up)
* `protocols::Stream` is **`Box<dyn IO>`**, not a concrete struct with fields — one
  reader confused it with the l4 `Stream`. Don't name fields on it.
* There is **no `examples/app/proxy.rs`** duplex template in this checkout; use
  `tokio::io::copy_bidirectional` (Pingora ships no bidi helper).
* A `PreTlsProcess` / `set_pre_tls_callback` pre-handshake hook *does* exist
  (`listeners/mod.rs`), but it is **not needed** for this design — our custom
  `ServerApp` on a plain-TCP listener owns the raw stream directly, which is
  simpler than threading a pre-TLS callback into an otherwise-TLS listener.
