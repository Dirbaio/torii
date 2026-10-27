# torii

A [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) controller implemented in
Rust, with its own data plane on tokio, rustls, httparse and a fork of h2. The
goal is to **pass the upstream Gateway API conformance suite**, starting with the
`GATEWAY-HTTP` profile.

## Status

Working: the controller and data plane pass the `GATEWAY-HTTP` profile except
`TLSRouteHostnameIntersection`'s "not matching" cases (an unmatched SNI on a TLS port
falls back to HTTPS). **Building from here** below is the original bring-up plan.

## Repository layout

```
torii/
├── CLAUDE.md            # this file
├── gateway-api/         # vendored Gateway API v1.5 — CRDs, docs, conformance suite (Go)
└── src/                 # our controller + data plane (src/dataplane/)
```

`gateway-api/` is a **read-only reference**. Treat it as an upstream dependency: read it
to understand required behavior, never modify it. The data plane's h2 is our fork, the
`torii` branch of https://github.com/Dirbaio/h2, pinned by rev in Cargo.toml: keep every
change there marked `torii fork` and listed in its TORII.md.

## Architecture (target)

A Gateway controller has two halves that run in one process:

1. **Control plane (the controller).** Watches Kubernetes resources (`GatewayClass`,
   `Gateway`, `HTTPRoute`, `ReferenceGrant`, `Service`, `EndpointSlice`, `Secret`, …),
   computes the desired routing config, and — critically — **writes `status` back** onto
   those resources (`Accepted`, `Programmed`, `ResolvedRefs` conditions,
   `observedGeneration`, attached-route counts, addresses). Conformance checks status
   just as much as it checks traffic.

2. **Data plane (`src/dataplane/`).** Our own proxy on tokio sockets, rustls (on
   ring), HTTP/1 on httparse, and HTTP/2 on our h2 fork. It receives the
   controller's computed config (via a shared, atomically-swapped snapshot —
   `ArcSwap<Snapshot>`) and, per request, matches the request against HTTPRoute rules
   and forwards it to a backend over HTTP/1.1.

The control plane mutates a config snapshot; the data plane reads it lock-free per
request. Keep these two concerns cleanly separated.

### Control-plane building blocks

- Use **`kube`** (kube-rs: `kube`, `kube-runtime`) for the client, watchers, and the
  `Controller`/reconciler pattern. Use **`k8s-openapi`** for core types (Service,
  EndpointSlice, Secret) and **`gateway-api`** (the Rust crate, not the Go dir) or
  generated types via `kube::CustomResource` for the Gateway CRDs.
- Reconcilers must be **idempotent** and **level-triggered**. Always recompute desired
  state from the full set of watched objects; never accumulate deltas.
- **Periodic resyncs are FORBIDDEN.** The reconcile loop is purely event-driven: it
  wakes only on watch events (each watcher updates its reflector Store *before* poking
  the wake channel, so no wake-up can be lost — a missed Store write always has a
  paired, still-queued poke that forces a re-reconcile). Do **not** add a timer-based
  resync, a "safety-net" tick, or a short timeout on the wake channel to "heal"
  convergence. If something doesn't converge, that is a **real bug** — find and fix the
  root cause (a missing watch, a dropped event, a non-idempotent reconcile, a status
  patch that silently no-ops). A periodic resync masks such bugs instead of fixing them
  and is never an acceptable fix.
- **Status reporting is load-bearing.** Many conformance tests only check conditions.
  Get `GatewayClass`/`Gateway`/`HTTPRoute` status conditions correct early —
  `observedGeneration` must track `metadata.generation` (there are explicit
  `*-observed-generation-bump` tests).

### Data-plane building blocks

- The goal is nginx's memory per connection. The rule that gets there: **no buffer is
  held while waiting on a peer.** Reads go through `io::poll_read_lazy`, which lets go of
  an empty buffer when a read would block; a request's state lives in a boxed future
  that exists only while the request does; the relay holds one chunk per direction.
  Keep `tests::connection_futures_are_small` passing.
- `mod.rs`: listeners, admission (`conn_limit`), TLS-port dispatch (rustls reads
  the ClientHello → TLSRoute pipe or TLS-terminated HTTP), shutdown drain. `serve_h1.rs` / `serve_h2.rs`:
  the client side. `proxy.rs`: routing and filters, and the head rewrites.
  `relay.rs`: bodies and their clocks. `upstream.rs`: backend connections and the pool.
  `h1.rs`: HTTP/1 heads, framing, chunked coding. `tls.rs`: the ClientHello, rustls
  configs and cert resolvers.
- HTTP/1 parsing is strict on purpose (request smuggling): one Transfer-Encoding
  `chunked`, at most one Content-Length, CRLF line ends in chunked bodies.
- Every wait on a client or backend is bounded by a clock; never add an unbounded wait.

## The conformance suite — the spec that matters

Everything we implement is in service of [gateway-api/conformance/](gateway-api/conformance/).
This is **Gateway API v1.5** (`CHANGELOG/1.5-CHANGELOG.md`).

### How it works

- The suite is a **Go test binary** run against a **real Kubernetes cluster**. It applies
  YAML manifests, polls resource status, then sends real HTTP requests through the
  gateway and asserts on responses.
- Conformance is organized into **profiles** (`conformance/utils/suite/profiles.go`):
  `GATEWAY-HTTP`, `GATEWAY-TLS`, `GATEWAY-TCP`, `GATEWAY-UDP`, `GATEWAY-GRPC`, plus mesh.
  **Target `GATEWAY-HTTP` first** — its core features are `Gateway`, `ReferenceGrant`,
  `HTTPRoute`.
- Each profile splits features into **Core** (mandatory) and **Extended** (opt-in; you
  declare which you support). An implementation reports `SupportedFeatures` and only the
  tests for those features run. Start by supporting the minimum core set, expand outward.
- Test cases live in [gateway-api/conformance/tests/](gateway-api/conformance/tests/)
  (`.go` test + matching `.yaml` manifest). Rough counts: ~54 httproute, ~22 gateway,
  ~13 tlsroute, ~9 udproute, ~8 tcproute, ~5 grpcroute, ~6 backendtlspolicy. Read the
  `.go` file to see what each asserts.

### What the controller must satisfy to even start

- The suite reads the **GatewayClass** named `gateway-conformance` (flag default,
  `conformance/utils/flags/flags.go`) and **discovers our controller name from that
  GatewayClass's `Accepted` condition** (`suite.go:374`,
  `GWCMustHaveAcceptedConditionTrue`). So: we must install a `GatewayClass` whose
  `spec.controllerName` is ours, and our controller must set its `Accepted=True`
  condition. Pick a stable controller name like `torii.dirba.io/controller`.

### The echo backend / response assertions

The conformance backends echo the request back as JSON
(`conformance/echo-basic/echo-basic.go`, `conformance/utils/http/http.go`). Assertions
check `Namespace`, `Pod` (must start with the expected backend service name), echoed
`Path`, `Host`, `Method`, request `Headers`, and response status. So routing to the
*correct* backend pod is what's actually verified — getting *a* 200 isn't enough.

### Running conformance locally (dev loop)

You need a cluster (kind/k3d). High level:
1. `kubectl apply` the CRDs from `gateway-api/config/crd/` (standard channel).
2. Run torii against the cluster (in-cluster or out-of-cluster via kubeconfig).
3. From `gateway-api/`, run the suite, scoping to one test while iterating, e.g.:
   ```
   go test ./conformance -run TestConformance \
     -args --gateway-class=gateway-conformance \
     --conformance-profiles=GATEWAY-HTTP \
     --run-test=HTTPRouteSimpleSameNamespace
   ```
   (Confirm exact flags in `conformance/utils/flags/flags.go` / `conformance_test.go`.)

Iterate one test at a time. `HTTPRouteSimpleSameNamespace`
(`conformance/tests/httproute-simple-same-namespace.go`) is the canonical first target.

## Building from here

1. Scaffold a Cargo workspace at the repo root. Suggested members: `torii`
   (binary), plus crates for control plane and data plane if it helps separation.
2. Data-plane dependencies: `rustls` + `tokio-rustls` (ring), `httparse`, `h2` (path dep on
   the `torii` branch of github.com/Dirbaio/h2), `socket2`.
3. Add `kube`, `kube-runtime`, `k8s-openapi` (pin the k8s version feature), `tokio`,
   `arc-swap`, `serde`. For Gateway CRD types, prefer the `gateway-api` Rust crate; if it
   lags v1.5, generate types from the CRDs in `gateway-api/config/crd/` with
   `kube::CustomResource`.
4. Milestone order:
   1. Controller skeleton: watch + accept `GatewayClass`, set its `Accepted` condition.
   2. `Gateway` reconcile: bind listeners, set `Accepted`/`Programmed`, addresses.
   3. `HTTPRoute` reconcile: attach to parents, resolve backend refs, set
      `ResolvedRefs`/`Accepted`, build the route table.
   4. Data plane: serve traffic, path/host/header/method matching → correct backend.
   5. Then expand: ReferenceGrant, filters (redirect/rewrite/header-mod), weighting,
      cross-namespace, listener isolation, etc.

## Conventions

- **Our crate is edition 2024, `rust-version = "1.96"`.** The h2 fork keeps its own
  edition (2021) — editions are per-crate. Keep `cargo clippy` clean.
- Never edit `gateway-api/`. If you think you need to, you've misunderstood the API —
  re-read the reference instead.
- Conformance is the source of truth for *behavior*. When unsure how something should
  behave, find the test that exercises it and read its assertions rather than guessing
  from the spec prose.
- Status correctness (conditions + `observedGeneration` + counts) is a first-class
  feature, not an afterthought — bake it into every reconciler.

## Key reference files

- Data plane overview: [src/dataplane/mod.rs](src/dataplane/mod.rs); the h2 fork's changes: [TORII.md on the `torii` branch](https://github.com/Dirbaio/h2/blob/torii/TORII.md)
- Conformance profiles & features: [gateway-api/conformance/utils/suite/profiles.go](gateway-api/conformance/utils/suite/profiles.go), [gateway-api/pkg/features/](gateway-api/pkg/features/)
- Conformance test cases: [gateway-api/conformance/tests/](gateway-api/conformance/tests/)
- Status-check helpers (what conditions tests expect): [gateway-api/conformance/utils/kubernetes/helpers.go](gateway-api/conformance/utils/kubernetes/helpers.go)
- HTTP request/response assertions: [gateway-api/conformance/utils/http/http.go](gateway-api/conformance/utils/http/http.go)
- Gateway API Go types (mirror of the CRDs): [gateway-api/apis/v1/](gateway-api/apis/v1/)
- CRDs to install: [gateway-api/config/crd/](gateway-api/config/crd/)
