# ⛩️ torii

A [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) controller written in Rust
using [Pingora](https://github.com/cloudflare/pingora).

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
          - { kind: Secret, name: app-tls }   # Torii creates/populates this Secret
```

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

