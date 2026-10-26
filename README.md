# ⛩️ torii

A [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) controller written in Rust,
with its own lean proxy (tokio, OpenSSL, HTTP/1 on httparse, HTTP/2 on a fork of h2).

Torii optimizes for simplicity. A single binary reads the gateway objects from the Kubernetes API
and proxies traffic accordingly. You can deploy it as a single pod, or scale up with multiple pods
behind a load balancer. It requires no supporting infrastructure other than Kubernetes itself.

## Features

- All of the core Gateway API is implemented: GatewayClass, Gateway, etc.
- **Status reporting**: The controller reports conditions and validation errors in the `status` field.
- **ReferenceGrants** are validated.
- **HTTPRoute**
  - Matching: path (Exact/PathPrefix), header, method, query-param matches,
  - Filters: request/response header modifiers, request redirect (scheme/host/port/status/path), URL rewrite (host/path).
  - CORS
  - WebSocket passthrough.
- **TLSRoute**
  - TLS passthrough mode (peek SNI from ClientHello, pipe encrypted TLS bytes to the backend)
  - Terminate mode (decrypt, pipe raw TCP bytes to the backend)
  - HTTPRoutes and TLSRoutes can coexist in the same TLS listen port.
- **BackendTLSPolicy** for speaking TLS to backends.
- Multiple listeners on multiple ports.
- **Integrated ACME client** for automatically obtaining certificates from CAs like Let's Encrypt. (opt-in)

## Deployment

1. Install the Gateway API CRDs:

    kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml

2. Review [`torii.yaml`](torii.yaml), edit it to match your deployment needs.
3. Apply it:

    kubectl apply -f torii.yaml

### Connection limits

torii caps what clients can hold open at once, so that a flood gets refused instead of using up the
pod's memory and getting it OOM-killed, controller included. An idle connection costs ~20-75 KB, and a
request to a backend ~1 MB while its client does not read the response.

| Flag (env var) | Default | Caps | Over it |
|---|---|---|---|
| `--max-connections-per-source` (`TORII_MAX_CONNECTIONS_PER_SOURCE`) | 256 | connections from one client | closed |
| `--max-requests-per-source` (`TORII_MAX_REQUESTS_PER_SOURCE`) | 128 | requests to backends in flight from one client | 503 |
| `--max-connections` (`TORII_MAX_CONNECTIONS`) | 1 per 128 KiB of `limits.memory` | connections in all | closed |
| `--max-requests` (`TORII_MAX_REQUESTS`) | 1 per 2 MiB of `limits.memory` | requests to backends in flight in all | 503 |

- A client is an IPv4 address or an IPv6 /64. If many clients share an address (a NAT, or a load balancer
  that does not keep client addresses, such as a Service without `externalTrafficPolicy: Local`), raise
  the per-source caps or set them to `0`, which disables a cap.
- The global defaults come from the pod's memory limit (read from cgroup v2). Without one there are no
  global caps unless set explicitly, and torii warns at startup.
- The last quarter of each global cap is kept for clients that hold less than 1/16 of their per-source
  cap, so a few clients cannot lock everyone else out.
- Refusals are logged as a warning at most once a minute, with how many there were since the last one.

### TLS handshakes

Each TLS handshake costs torii a key exchange and a signature, so a client that opens connections and
drops them makes it spend CPU. The plain-HTTP and the TLS ports each run on `--dataplane-threads`
(`TORII_DATAPLANE_THREADS`) worker threads, by default as many as the CPUs available to the pod (its CPU
limit included). Give it more than one CPU so that one client's handshakes cannot hold up everyone
else's. ECDSA certificates, as ACME issues, cost 5-6x less per handshake than RSA-4096 ones.

## Automatic TLS certificates (ACME)

torii can obtain and renew TLS certificates automatically via **ACME TLS-ALPN-01**
(e.g. from Let's Encrypt). 

- Set the following CLI args:
  - `--acme`: enables ACME support.
  - `--acme-namespace=torii-system` (the namespace you want Torii to store ACME state in secrets)
  - `--acme-issuer=https://acme-v02.api.letsencrypt.org/directory`
  - `--acme-email=you@example.com`
- Add the `torii.dirba.io/acme` annotation to a Gateway.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: web
  annotations:
    torii.dirba.io/acme: ""
spec:
  gatewayClassName: torii
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: app.example.com          # required; wildcards aren't supported by TLS-ALPN-01
      tls:
        mode: Terminate
        certificateRefs:
          # Torii creates/populates this Secret. It must be in --acme-namespace.
          - { kind: Secret, name: app-tls, namespace: torii-system }
```

- torii writes certificates only into Secrets in `--acme-namespace`, the only namespace where its RBAC allows
  writing Secrets. A listener whose certificateRef is elsewhere reports the ACME issuance as failed. A Gateway in
  another namespace needs a ReferenceGrant in `--acme-namespace` for its certificateRef, as for any
  cross-namespace Secret.

- Issuance status is reported in the `status` field of the `Gateway` and is visible with `kubectl describe`.
- Certificates are automatically renewed 30 days before expiry.
- Multiple controller replicas are supported. A leader election is done to prevent multiple replicas from trying to issue certs at the same time.

## Non-features

Not implemented yet. Pull requests welcome.

- GRPCRoute
- HTTPRoute `retry`
- HTTPRoute `RequestMirror`
- `HTTPRouteBackendProtocolH2C` (cleartext HTTP/2 to the backend)
- TCPRoute, UDPRoute. Unclear how valuable they are. Torii routes traffic itself, it doesn't control any cloud provider infrastructure. If you can get TCP traffic to reach it you can also get TCP traffic to reach the upstream directly.

