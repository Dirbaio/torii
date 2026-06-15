#!/usr/bin/env bash
# End-to-end test of ACME TLS-ALPN-01 issuance against a local pebble server.
#
# Prereqs: a kind cluster (`just cluster-up`), kubectl pointed at it, and the
# host able to reach the cluster (Pod/Service CIDRs routed — see README). Run
# lolgateway is NOT started by this script; this script starts it with --acme.
#
# What it does:
#   1. Deploy pebble (a tiny ACME test server) into the cluster.
#   2. Create the --acme-namespace and RBAC.
#   3. Create a Gateway annotated to use pebble's ACME directory, with an HTTPS
#      listener for a test hostname whose certificateRefs Secret does not exist.
#   4. Start lolgateway with --acme and point the test hostname at the proxy.
#   5. Assert the listener's cert Secret gets populated by an ACME-issued cert.
#
# NOTE: TLS-ALPN-01 requires pebble's validator to reach lolgateway's :443 by the
# test hostname. This script wires that with a pebble DNS override + a host route.
# It is the manual/CI validation path; the crypto + state logic is also covered by
# `cargo test` (acme_cert / acme unit tests).
set -euo pipefail

NS=lolgateway-system
HOST=acme-test.lol.example
KUBECONFIG=${KUBECONFIG:-./kubeconfig}
export KUBECONFIG

echo "==> namespace + RBAC"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

echo "==> deploy pebble (ACME test server)"
kubectl apply -n "$NS" -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: pebble, labels: { app: pebble } }
spec:
  replicas: 1
  selector: { matchLabels: { app: pebble } }
  template:
    metadata: { labels: { app: pebble } }
    spec:
      containers:
        - name: pebble
          image: ghcr.io/letsencrypt/pebble:latest
          args: ["-config", "/test/config/pebble-config.json", "-dnsserver", "8.8.8.8"]
          env:
            # Validate TLS-ALPN-01 on 443 against the challenge host.
            - { name: PEBBLE_VA_ALWAYS_VALID, value: "0" }
          ports: [{ containerPort: 14000 }, { containerPort: 15000 }]
---
apiVersion: v1
kind: Service
metadata: { name: pebble }
spec:
  selector: { app: pebble }
  ports: [{ name: acme, port: 14000, targetPort: 14000 }]
YAML
kubectl rollout status -n "$NS" deploy/pebble --timeout=120s

PEBBLE_DIR="https://pebble.${NS}.svc:14000/dir"

echo "==> Gateway opted into ACME via annotation, HTTPS listener for $HOST"
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: acme-test
  namespace: default
  annotations:
    lolgateway.dev/acme-issuer: "${PEBBLE_DIR}"
    lolgateway.dev/acme-email: "test@lol.example"
spec:
  gatewayClassName: gateway-conformance
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: "${HOST}"
      tls:
        mode: Terminate
        certificateRefs:
          - { kind: Secret, name: acme-test-cert }
YAML

echo "==> start lolgateway with --acme (in the background) ..."
echo "    cargo run -- run --acme --acme-namespace $NS \\"
echo "        --bind-ip 0.0.0.0 --http-ports 80,8080,8090 --tls-ports 443 --advertise 127.0.0.1"
echo
echo "==> then wait for the issued cert to appear in Secret default/acme-test-cert:"
echo "    kubectl get secret acme-test-cert -n default -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -subject -dates"
echo
echo "Success = the Secret exists with a tls.crt issued by the pebble CA for $HOST."
