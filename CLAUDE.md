# lolgateway

A [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) controller implemented in
Rust, with a data plane built on [Pingora](https://github.com/cloudflare/pingora). The
goal is to **pass the upstream Gateway API conformance suite**, starting with the
`GATEWAY-HTTP` profile.

## Status

Greenfield. No Rust crate exists yet — this repo currently contains only the two
vendored reference checkouts (`pingora/`, `gateway-api/`). The first task is to scaffold
the workspace; see **Building from here** below.

## Repository layout

```
lolgateway/
├── CLAUDE.md            # this file
├── pingora/             # vendored Pingora source — depend on via path, do NOT edit
├── gateway-api/         # vendored Gateway API v1.5 — CRDs, docs, conformance suite (Go)
└── src/ (TBD)           # our controller + data plane (does not exist yet)
```

`pingora/` and `gateway-api/` are **read-only references**. Treat them as upstream
dependencies: read them to understand APIs and required behavior, never modify them.

## Architecture (target)

A Gateway controller has two halves that run in one process:

1. **Control plane (the controller).** Watches Kubernetes resources (`GatewayClass`,
   `Gateway`, `HTTPRoute`, `ReferenceGrant`, `Service`, `EndpointSlice`, `Secret`, …),
   computes the desired routing config, and — critically — **writes `status` back** onto
   those resources (`Accepted`, `Programmed`, `ResolvedRefs` conditions,
   `observedGeneration`, attached-route counts, addresses). Conformance checks status
   just as much as it checks traffic.

2. **Data plane (Pingora).** A `pingora-proxy` server implementing the `ProxyHttp` trait.
   It receives the controller's computed config (via a shared, atomically-swapped
   snapshot — e.g. `ArcSwap<RouteTable>`) and, per request, matches the request against
   HTTPRoute rules and picks an upstream.

The control plane mutates a config snapshot; the data plane reads it lock-free per
request. Keep these two concerns cleanly separated.

### Control-plane building blocks

- Use **`kube`** (kube-rs: `kube`, `kube-runtime`) for the client, watchers, and the
  `Controller`/reconciler pattern. Use **`k8s-openapi`** for core types (Service,
  EndpointSlice, Secret) and **`gateway-api`** (the Rust crate, not the Go dir) or
  generated types via `kube::CustomResource` for the Gateway CRDs.
- Reconcilers must be **idempotent** and **level-triggered**. Always recompute desired
  state from the full set of watched objects; never accumulate deltas.
- **Status reporting is load-bearing.** Many conformance tests only check conditions.
  Get `GatewayClass`/`Gateway`/`HTTPRoute` status conditions correct early —
  `observedGeneration` must track `metadata.generation` (there are explicit
  `*-observed-generation-bump` tests).

### Data-plane building blocks

- The single most important Pingora API is the `ProxyHttp` trait in
  [pingora/pingora-proxy/src/proxy_trait.rs](pingora/pingora-proxy/src/proxy_trait.rs).
  Methods you'll lean on:
  - `request_filter` — return early responses (404 for no route match, 301/302
    redirects, `RequestRedirect`/`RequestHeaderModifier` filters). Return `Ok(true)`
    when you've already sent the response.
  - `upstream_peer` — pick the backend `HttpPeer` (the routing decision lives here or in
    a filter that stashes the choice on `CTX`).
  - `upstream_request_filter` / `response_filter` — header rewriting, hostname rewrite,
    response header modifiers.
- Per-request state lives on the associated `CTX` type (`new_ctx`). Put the matched
  route/backend decision there.
- Look at `pingora/pingora-proxy/examples/` and `pingora-load-balancing/` for upstream
  selection, health checks, and load-balancing primitives before writing your own.

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
  condition. Pick a stable controller name like `lolgateway.dev/controller`.

### The echo backend / response assertions

The conformance backends echo the request back as JSON
(`conformance/echo-basic/echo-basic.go`, `conformance/utils/http/http.go`). Assertions
check `Namespace`, `Pod` (must start with the expected backend service name), echoed
`Path`, `Host`, `Method`, request `Headers`, and response status. So routing to the
*correct* backend pod is what's actually verified — getting *a* 200 isn't enough.

### Running conformance locally (dev loop)

You need a cluster (kind/k3d). High level:
1. `kubectl apply` the CRDs from `gateway-api/config/crd/` (standard channel).
2. Run lolgateway against the cluster (in-cluster or out-of-cluster via kubeconfig).
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

1. Scaffold a Cargo workspace at the repo root. Suggested members: `lolgateway`
   (binary), plus crates for control plane and data plane if it helps separation.
2. Add **path** dependencies on Pingora, e.g.:
   ```toml
   pingora = { path = "pingora/pingora" }
   pingora-proxy = { path = "pingora/pingora-proxy" }
   pingora-core = { path = "pingora/pingora-core" }
   ```
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

- **Pingora's MSRV is 1.84** (`pingora-core/Cargo.toml`), edition 2021. Local toolchain
  is newer; stay edition-2021-compatible in our crates to match.
- Never edit `pingora/` or `gateway-api/`. If you think you need to, you've misunderstood
  the API — re-read the reference instead.
- Conformance is the source of truth for *behavior*. When unsure how something should
  behave, find the test that exercises it and read its assertions rather than guessing
  from the spec prose.
- Status correctness (conditions + `observedGeneration` + counts) is a first-class
  feature, not an afterthought — bake it into every reconciler.

## Key reference files

- Pingora request lifecycle: [pingora/pingora-proxy/src/proxy_trait.rs](pingora/pingora-proxy/src/proxy_trait.rs)
- Conformance profiles & features: [gateway-api/conformance/utils/suite/profiles.go](gateway-api/conformance/utils/suite/profiles.go), [gateway-api/pkg/features/](gateway-api/pkg/features/)
- Conformance test cases: [gateway-api/conformance/tests/](gateway-api/conformance/tests/)
- Status-check helpers (what conditions tests expect): [gateway-api/conformance/utils/kubernetes/helpers.go](gateway-api/conformance/utils/kubernetes/helpers.go)
- HTTP request/response assertions: [gateway-api/conformance/utils/http/http.go](gateway-api/conformance/utils/http/http.go)
- Gateway API Go types (mirror of the CRDs): [gateway-api/apis/v1/](gateway-api/apis/v1/)
- CRDs to install: [gateway-api/config/crd/](gateway-api/config/crd/)
