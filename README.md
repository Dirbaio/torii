# lolgateway

A [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) controller written in Rust,
with a data plane built on [Pingora](https://github.com/cloudflare/pingora). The goal is
to pass the upstream Gateway API conformance suite, starting with the `GATEWAY-HTTP`
profile.

See [CLAUDE.md](CLAUDE.md) for architecture, the conformance plan, and repository layout.

## Status

Working controller + data plane passing a broad slice of the `GATEWAY-HTTP`
conformance profile. Implemented and verified against the upstream suite:

- **Status reporting** — GatewayClass/Gateway/HTTPRoute conditions with correct
  `observedGeneration`, Gateway addresses, per-listener status, `attachedRoutes` counts,
  `supportedFeatures`.
- **HTTPRoute matching** — path (Exact/PathPrefix), header, method, query-param matches,
  with full Gateway API precedence ordering.
- **Backends** — Service → EndpointSlice resolution (port → targetPort), weighted
  selection across backends.
- **ReferenceGrant** — cross-namespace backendRef permission (incl. `RefNotPermitted`
  + 500 behavior).
- **Filters** — request/response header modifiers, request redirect (scheme/host/port/
  status/path), URL rewrite (host/path).
- **Listener attachment** — `sectionName`/port selection, `allowedRoutes` namespaces
  (Same/All/Selector) and kinds, hostname intersection, with correct `Accepted` reasons
  (`NoMatchingParent`, `NotAllowedByListeners`, `NoMatchingListenerHostname`).
- **Multi-port + extended HTTP** — per-port listeners (`HTTPRouteParentRefPort`,
  `GatewayPort8080`), HTTP-listener isolation, request/backend timeouts (→504), CORS,
  WebSocket upgrade passthrough.
- **TLS (GATEWAY-TLS, partial)** — HTTPS listener termination with **per-SNI certificate
  selection** (certs loaded in-memory from `kubernetes.io/tls` Secrets, cross-namespace
  via ReferenceGrant; OpenSSL `certificate_callback`), listener cert-ref status
  (`InvalidCertificateRef`/`RefNotPermitted`, with PEM validation), and **BackendTLSPolicy**
  upstream re-encryption (gateway→backend TLS with custom CA from a ConfigMap + SNI/hostname
  verification), including invalid-policy→5xx and conflict resolution.
- **TLSRoute (SNI passthrough + terminate)** — route raw TCP by ClientHello SNI: passthrough
  (encrypted bytes piped to a TLS backend) and terminate (decrypt here, pipe cleartext TCP),
  coexisting with HTTPS HTTPRoutes on one port. See [TLSRoute](#tlsroute-sni-passthrough--terminate).
- **Automatic TLS certs via ACME (opt-in)** — see [ACME](#automatic-tls-certificates-acme).

Architecture: a level-triggered kube controller computes the entire data-plane view —
route table + TLS cert store — and publishes both together in **one atomic
`ArcSwap<Snapshot>`** so readers never see a torn state; a Pingora `ProxyHttp` data plane
reads it lock-free per request. Request dispatch is indexed by `(port, listener hostname)`
— exact/wildcard/any tiers — so it scans only the routes serving the request's Host, not
the whole table. The Pingora TLS backend is **OpenSSL** (not rustls), because per-SNI cert
selection needs the OpenSSL/BoringSSL certificate callback. See the modules in
[src/](src/).

### Conformance results

The full `GATEWAY-HTTP` profile passes cleanly:

```
go test ./conformance -run TestConformance -count=1 \
  -args --gateway-class=gateway-conformance \
  --conformance-profiles=GATEWAY-HTTP --allow-crds-mismatch
```

→ **0 failed.** The skips are out-of-scope features we don't report in
`supportedFeatures` (UDP/TCP/gRPC routes, request mirroring, retries, ListenerSet, static
addresses, frontend client-cert validation, mesh, h2c). Everything we declare
support for passes — including TLS termination (HTTPS listeners, per-SNI certs,
cross-namespace cert ReferenceGrants) and the full BackendTLSPolicy surface (re-encrypt,
invalid-CA/invalid-kind → 5xx, and conflict resolution).

**TLSRoute** is exercised separately (see [TLSRoute](#tlsroute-sni-passthrough--terminate)):
11/12 of its tests pass, run with targeted `--run-test` against ports 443/8443/8883.

Notes:
- Use the `GATEWAY-HTTP` profile for the HTTP run. The `GATEWAY-TLS` profile also pulls in
  out-of-scope route types (UDP/TCP), so for TLSRoute we scope to individual tests with
  `--run-test=TLSRoute...` plus `--supported-features=Gateway,ReferenceGrant,TLSRoute,TLSRouteModeTerminate`
  rather than running the whole profile. TLS *termination* for HTTPRoute is exercised within
  `GATEWAY-HTTP` via `supportedFeatures`.
- Always pass `-count=1`: `go test` caches results, and a cached pass returns in ~20s
  without re-running against the cluster.
- Run one conformance invocation at a time — two at once fight over the shared base
  resources and fail spuriously.

### TLSRoute (SNI passthrough + terminate)

`TLSRoute` routes a raw TCP connection **by the ClientHello SNI**. Both of its modes are
implemented, coexisting with HTTPS HTTPRoutes on the same port:

- **Passthrough** — peek the SNI without decrypting, then a true full-duplex byte pipe to a
  backend that terminates TLS itself.
- **Terminate** — peek the SNI, terminate TLS here (cert selected per-SNI), then pipe the
  *cleartext* TCP to the backend (the conformance backend speaks a raw line protocol, not
  HTTP, and talks first — so the pipe must be bidirectional).

The data path is a custom Pingora `ServerApp` (`GatewayTlsApp`) on a plain-TCP listener: it
peeks the ClientHello (`Stream::try_peek` + a hand-written SNI parser — Pingora has no
built-in peek), looks up `(port, SNI)` in an `ArcSwap`-published `TlsTable`, and dispatches
to passthrough / terminate-to-TCP / (no TLSRoute match) TLS-terminate-then-HTTP. This last
fallback is what lets HTTPS HTTPRoutes keep working on the **same** socket — the demux the
old "not implemented" note called for. No edits to vendored `pingora/` were needed; see
[docs/tlsroute-plan.md](docs/tlsroute-plan.md). We report `TLSRoute` + `TLSRouteModeTerminate`;
mixing both TLS modes on one port is rejected with `Accepted=False`/`ProtocolConflict`
(`TLSRouteModeMixed` is not claimed).

Verified against the suite (11/12 TLSRoute tests): passthrough + terminate traffic, all
parent/listener status (attachment, `ResolvedRefs`, supported-kinds, `ProtocolConflict`).
The one gap is `TLSRouteHostnameIntersection`, which assigns each of several Gateways its own
address; we advertise a single shared address, so a broad `*.com` Gateway answers an SNI the
test expects rejected on a *different* Gateway. Per-Gateway addressing is a separate,
pre-existing limitation (the HTTP data path shares the same single-address model).

### Automatic TLS certificates (ACME)

lolgateway can obtain and renew TLS certificates automatically via **ACME TLS-ALPN-01**
(e.g. from Let's Encrypt). It is **off by default** and must be enabled with `--acme`.

The Gateway API v1.5 spec has **no official field** for ACME issuance — listeners only
reference a pre-existing `certificateRefs` Secret — so opt-in is an **annotation** on the
Gateway (the cert-manager convention):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: web
  annotations:
    lolgateway.dev/acme-issuer: "https://acme-v02.api.letsencrypt.org/directory"
    lolgateway.dev/acme-email: "you@example.com"
spec:
  gatewayClassName: lolgateway
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: app.example.com          # required; wildcards aren't supported by TLS-ALPN-01
      tls:
        mode: Terminate
        certificateRefs:
          - { kind: Secret, name: app-tls }   # we create/populate this Secret
```

How it works:
- Run with `--acme [--acme-namespace lolgateway-system] [--acme-email ...]`.
- For each opted-in HTTPS listener whose `certificateRefs` Secret is missing, invalid, or
  expiring (renewed ~30 days before `notAfter`), lolgateway runs an ACME order and writes
  the issued cert into that Secret — which then flows through the normal cert path.
- **All state lives in Kubernetes:** the ACME account key and in-flight challenge certs are
  Secrets in `--acme-namespace`; issued certs go in each listener's own `certificateRefs`
  Secret.
- **Multiple controller replicas are supported.** A `coordination.k8s.io` Lease elects one
  leader that drives all issuance/renewal. Because the TLS-ALPN-01 verification connection
  can land on **any** replica, the challenge validation cert is stored in a shared Secret
  that every replica serves — so validation works regardless of which replica is hit.

RBAC beyond the base controller: `create`/`update`/`patch` on `secrets` in
`--acme-namespace` and `get`/`create`/`update`/`patch` on `coordination.k8s.io/leases`.

End-to-end test against a local [pebble](https://github.com/letsencrypt/pebble) ACME
server: [`hack/acme-e2e.sh`](hack/acme-e2e.sh). The certificate crypto (the RFC 8737
`acme-tls/1` validation cert + CSR) is also covered by `cargo test`.

### Scope

The goal is to pass **all conformance tests in the `GATEWAY-HTTP` and `GATEWAY-TLS`
profiles** (Gateway, HTTPRoute, TLSRoute-via-Gateway, ReferenceGrant, BackendTLSPolicy,
and their extended features).

**Out of scope** (these profiles are not targeted and their tests are expected to be
skipped — lolgateway does not advertise their features):

- `GATEWAY-GRPC` — GRPCRoute
- `GATEWAY-TCP` — TCPRoute
- `GATEWAY-UDP` — UDPRoute
- `MESH-HTTP` / `MESH-GRPC` — service mesh (GAMMA): routes that attach to a `Service`
  and are enforced by per-pod sidecars, a fundamentally different architecture from this
  edge gateway.

Notes on a few out-of-scope / unimplemented items:

- **HTTPRoute `retry`** is an *experimental-channel* feature in Gateway API v1.5 (absent
  from the standard CRDs), so the retry tests are not part of the standard GATEWAY-HTTP
  profile.
- **HTTPRoute `RequestMirror`** (traffic shadowing) is not supported. A correct
  implementation must mirror the whole request *including the body* — teeing every body
  chunk to the mirror backend without stalling the primary request — which isn't worth the
  complexity here, so the feature is not advertised and its tests are skipped.
- **TLSRoute** (TLS passthrough) is designed but not implemented — see above.
- **`HTTPRouteBackendProtocolH2C`** (cleartext HTTP/2 to the backend) is not implemented;
  it is not part of the GATEWAY-HTTP profile's required feature set.

## Prerequisites

- Rust (edition 2021, MSRV 1.84 to match Pingora)
- Docker (for the local `kind` cluster)
- [`kind`](https://kind.sigs.k8s.io/) and `kubectl`

## Local dev cluster (kind)

We develop against a local single-node [kind](https://kind.sigs.k8s.io/) cluster. The key
trick is making the **Pod CIDR and Service CIDR routable from the host**, so lolgateway can
run on the host with `cargo run` and still open TCP connections directly to Service
ClusterIPs and backend Pod IPs — no `kubectl port-forward`, no building/pushing a container
image. This makes the iteration loop fast.

This works because, on **Linux**, the kind node is a plain container on the `kind` Docker
bridge, so its IP is directly routable from the host. We just add host routes for the Pod
and Service CIDRs via the node container's IP. (On macOS/Windows the node runs inside a VM
and is *not* host-routable — this approach is Linux-only.)

### Create the cluster

```bash
cat <<'EOF' | kind create cluster --name lol --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/16"
nodes:
  - role: control-plane
EOF
```

### Make Pod + Service CIDRs routable from the host

The node container IP can change on each recreate, so re-derive it every time:

```bash
NODE_IP=$(docker container inspect lol-control-plane --format '{{ .NetworkSettings.Networks.kind.IPAddress }}')
sudo ip route add 10.244.0.0/16 via "$NODE_IP"   # Pod CIDR
sudo ip route add 10.96.0.0/16  via "$NODE_IP"   # Service CIDR
```

> Don't hardcode these CIDRs blindly — confirm them against the cluster
> (`kubectl get node -o jsonpath='{.spec.podCIDR}'`, and the service CIDR from your kind
> config) and make sure they don't collide with the kind bridge (`172.18.0.0/16` by
> default) or your LAN.

To tear down, remove the routes and delete the cluster:

```bash
sudo ip route del 10.244.0.0/16
sudo ip route del 10.96.0.0/16
kind delete cluster --name lol
```

### Install the Gateway API CRDs

From the vendored v1.5 reference (standard channel):

```bash
kubectl apply -f gateway-api/config/crd/standard/
```

## Using kubectl with the cluster

`kind` normally merges credentials into `~/.kube/config`. If you want a standalone
kubeconfig (e.g. to keep it in this repo for tooling), export it:

```bash
kind get kubeconfig --name lol > kubeconfig
```

The `kubeconfig` filename is **gitignored** — it contains a client cert/key, so never
commit it.

Point `kubectl` (and lolgateway) at it via the `KUBECONFIG` env var:

```bash
export KUBECONFIG=$PWD/kubeconfig
kubectl get ns
kubectl get nodes
```

## Building & running

```bash
# build everything
cargo build

# verify connectivity to the cluster (reads KUBECONFIG, or ~/.kube/config, or in-cluster)
KUBECONFIG=$PWD/kubeconfig cargo run -- check
```

Expected output against a live cluster:

```
INFO connected to Kubernetes API server version=1.36 ...
INFO listed namespaces count=5
OK: connected to Kubernetes 1.36, 5 namespace(s) visible
```

Adjust log verbosity with `--log` or `RUST_LOG`, e.g. `--log lolgateway=debug,kube=info`.

## Running the controller

`lolgateway run` starts both planes in one process: the kube controller (on the tokio
runtime) and the Pingora proxy (on a dedicated thread).

```bash
export KUBECONFIG=$PWD/kubeconfig
cargo run -- run --bind-ip 0.0.0.0 --http-ports 80,8080,8090 --tls-ports 443 --advertise 127.0.0.1
```

- `--http-ports` are plain-HTTP listener ports; `--tls-ports` are HTTPS listeners that
  terminate TLS, selecting the server cert by SNI. The proxy routes per-port using the
  local socket port, so these should cover all Gateway listener ports in use.
- `--advertise` is the IP published in `Gateway.status.addresses`. The suite reads this
  + the listener port to know where to send traffic, so it must be reachable from where
  you run `go test` (the host). `127.0.0.1` works because the suite runs on the host.

### One-time host setup: allow binding port 80

The Gateway listeners use privileged ports (80/443) and Linux blocks binding ports
< 1024 by default. Lower the threshold once (reversible, resets on reboot):

```bash
sudo sysctl net.ipv4.ip_unprivileged_port_start=80
```

Without this, `--bind 0.0.0.0:80` fails and the conformance traffic stage gets
`connection refused`.

## Running the conformance suite

The conformance GatewayClass must exist (named `gateway-conformance`, controllerName
`lolgateway.dev/controller`) and our controller must be running and have set its
`Accepted=True` condition. Apply it once:

```bash
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: gateway-conformance
spec:
  controllerName: lolgateway.dev/controller
EOF
```

The suite applies (and cleans up) its own base + per-test manifests — do **not**
pre-apply them. With the controller running and port 80 bindable, from `gateway-api/`:

```bash
go test ./conformance -run TestConformance -timeout 30m -args \
  --gateway-class=gateway-conformance \
  --conformance-profiles=GATEWAY-HTTP \
  --run-test=HTTPRouteSimpleSameNamespace \
  --allow-crds-mismatch
```

`--run-test=<ShortName>` scopes to a single test for fast iteration. Drop it to run the
whole GATEWAY-HTTP profile. `--allow-crds-mismatch` avoids a hard failure when the
installed CRD bundle-version annotation doesn't match the suite's expected dev version.

### Fast iteration: `hack/run-tests.sh`

To run several specific tests one-by-one (with short timeouts so failures fail fast),
use the helper — it passes `--cleanup-base-resources=false` so backend pods stay warm
between tests (otherwise pod-readiness races cause spurious failures):

```bash
KUBECONFIG=$PWD/kubeconfig bash hack/run-tests.sh HTTPRouteMatching HTTPRouteWeight
```

There's also a [`d`](d) script wrapping the common tasks: `./d cluster-up`,
`./d run`, `./d conformance <Test...>`, `./d cluster-down`.

## Vendored references

This repo depends on two upstream checkouts **by path**, which are **not tracked in git**
(see [.gitignore](.gitignore)) — obtain them into the repo root before building:

- `pingora/` — the [Pingora](https://github.com/cloudflare/pingora) source (data-plane
  path deps: `pingora-core`, `pingora-proxy`, `pingora-http`).
- `gateway-api/` — the [Gateway API](https://github.com/kubernetes-sigs/gateway-api) v1.5
  checkout (CRDs in `config/crd/standard/`, conformance suite in `conformance/`).
