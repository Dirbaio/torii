#!/usr/bin/env bash
# End-to-end test of lolgateway's ACME TLS-ALPN-01 issuance, fully in-cluster.
#
# Everything runs inside the kind cluster, so there are no host<->cluster DNS or
# routing problems:
#
#   pebble              - a tiny ACME test CA (issues real certs from a test PKI).
#   pebble-challtestsrv - a mock DNS server pebble uses to resolve the challenge
#                         hostname; we point that name at lolgateway's Service so
#                         pebble's TLS-ALPN-01 validator reaches lolgateway:443.
#   lolgateway          - the controller under test, run with --acme and told to
#                         trust pebble's test CA (--acme-ca-cert).
#
# Flow:
#   1. (re)create the test namespace.
#   2. RBAC for lolgateway (watch gateway resources, write status, manage Secrets,
#      coordinate via Leases).
#   3. deploy challtestsrv + pebble (pebble validates TLS-ALPN-01 on :443 and
#      resolves names via challtestsrv).
#   4. fetch pebble's test CA, hand it to lolgateway (--acme-ca-cert) and curl.
#   5. deploy lolgateway with --acme.
#   6. an echo backend + a Gateway opted into ACME (annotation) with an HTTPS
#      listener for the test host, whose cert Secret does NOT exist yet.
#   7. point the test host at lolgateway's Service via challtestsrv.
#   8. assert: the cert Secret gets populated by an ACME-issued cert, and the
#      gateway serves HTTPS for the test host validating against pebble's CA.
#
# Prereqs: a kind cluster named "lol" (`just cluster-up`), kubectl pointed at it,
# docker (to build the lolgateway image), and `kind`. The lolgateway image is
# built + loaded by this script.
set -euo pipefail

cd "$(dirname "$0")/.."

NS=lolgateway-acme-e2e
HOST=acme-test.lol.example
IMAGE=lolgateway:e2e
KIND_CLUSTER=lol
KUBECONFIG=${KUBECONFIG:-./kubeconfig}
export KUBECONFIG

k() { kubectl -n "$NS" "$@"; }

# ---------------------------------------------------------------------------
echo "==> build + load lolgateway image ($IMAGE)"
docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER"

# ---------------------------------------------------------------------------
echo "==> reset namespace $NS"
kubectl delete namespace "$NS" --ignore-not-found --wait=true
kubectl create namespace "$NS"

# ---------------------------------------------------------------------------
echo "==> RBAC for lolgateway"
kubectl apply -f - <<YAML
apiVersion: v1
kind: ServiceAccount
metadata: { name: lolgateway, namespace: $NS }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: lolgateway-$NS }
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gatewayclasses","gateways","httproutes","referencegrants","backendtlspolicies"]
    verbs: ["get","list","watch"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gatewayclasses/status","gateways/status","httproutes/status","backendtlspolicies/status"]
    verbs: ["patch","update"]
  - apiGroups: [""]
    resources: ["services","secrets","configmaps","namespaces"]
    verbs: ["get","list","watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create","update","patch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get","list","watch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get","list","watch","create","update","patch","delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: lolgateway-$NS }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: lolgateway-$NS }
subjects:
  - { kind: ServiceAccount, name: lolgateway, namespace: $NS }
YAML

# ---------------------------------------------------------------------------
echo "==> deploy pebble-challtestsrv (mock DNS for the challenge host)"
# Only the DNS responder is needed (:8053); the management API (:8055) lets us
# set A records. -defaultIPv6 "" stops it returning AAAA records.
k apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: challtestsrv, labels: { app: challtestsrv } }
spec:
  replicas: 1
  selector: { matchLabels: { app: challtestsrv } }
  template:
    metadata: { labels: { app: challtestsrv } }
    spec:
      containers:
        - name: challtestsrv
          image: ghcr.io/letsencrypt/pebble-challtestsrv:latest
          imagePullPolicy: IfNotPresent
          # DNS responder on :8053; management API on :8055. Disable the HTTP/TLS
          # challenge responders (we only need DNS + management). -defaultIPv6 ""
          # stops it returning AAAA records.
          args: ["-dnsserver", ":8053", "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "", "-management", ":8055", "-defaultIPv6", ""]
          # challtestsrv serves DNS on BOTH udp and tcp 8053; pebble's resolver
          # uses tcp, so expose both.
          ports:
            - { containerPort: 8053, protocol: UDP }
            - { containerPort: 8053, protocol: TCP }
            - { containerPort: 8055, protocol: TCP }
---
apiVersion: v1
kind: Service
metadata: { name: challtestsrv }
spec:
  selector: { app: challtestsrv }
  ports:
    - { name: dns-udp, port: 8053, targetPort: 8053, protocol: UDP }
    - { name: dns-tcp, port: 8053, targetPort: 8053, protocol: TCP }
    - { name: mgmt, port: 8055, targetPort: 8055, protocol: TCP }
YAML

echo "==> mint pebble's ACME-API cert for its in-cluster FQDN (signed by minica)"
# Pebble's stock API cert (CN=localhost) is only valid for localhost/pebble/127.0.0.1,
# but lolgateway connects to pebble.$NS.svc:14000 — so we mint a replacement cert
# covering that FQDN, signed by pebble's baked-in minica root. lolgateway trusts
# the minica via --acme-ca-cert, so the in-cluster TLS connection to pebble verifies.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cid=$(docker create ghcr.io/letsencrypt/pebble:latest)
docker cp "$cid:/test/certs/pebble.minica.pem" - | tar -xO > "$TMP/minica.pem"
docker cp "$cid:/test/certs/pebble.minica.key.pem" - | tar -xO > "$TMP/minica.key.pem"
docker rm "$cid" >/dev/null

PEBBLE_FQDN="pebble.$NS.svc"
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TMP/pebble.key.pem" -out "$TMP/pebble.csr" \
  -subj "/CN=$PEBBLE_FQDN" >/dev/null 2>&1
openssl x509 -req -in "$TMP/pebble.csr" \
  -CA "$TMP/minica.pem" -CAkey "$TMP/minica.key.pem" -CAcreateserial \
  -days 3650 -out "$TMP/pebble.crt" \
  -extfile <(printf 'subjectAltName=DNS:%s,DNS:pebble,DNS:localhost,IP:127.0.0.1\n' "$PEBBLE_FQDN") \
  >/dev/null 2>&1
k create secret tls pebble-api-tls --cert="$TMP/pebble.crt" --key="$TMP/pebble.key.pem"

echo "==> deploy pebble (ACME test CA; validates TLS-ALPN-01 on :443)"
# Custom config: tlsPort 443 so the validator connects to lolgateway's :443, and
# the minted FQDN cert above for the ACME API endpoint.
k create configmap pebble-config --from-literal=pebble-config.json='{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "/api-tls/tls.crt",
    "privateKey": "/api-tls/tls.key",
    "httpPort": 80,
    "tlsPort": 443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}'
k apply -f - <<YAML
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
          imagePullPolicy: IfNotPresent
          # Resolve challenge hostnames via challtestsrv so TLS-ALPN-01 validation
          # reaches lolgateway's Service. Real PKI validation (not ALWAYS_VALID).
          # The image is distroless; its entrypoint binary is /app.
          command: ["/app"]
          args: ["-config", "/cfg/pebble-config.json", "-dnsserver", "challtestsrv.$NS.svc:8053"]
          volumeMounts:
            - { name: cfg, mountPath: /cfg }
            - { name: api-tls, mountPath: /api-tls, readOnly: true }
          ports: [{ containerPort: 14000 }, { containerPort: 15000 }]
      volumes:
        - name: cfg
          configMap: { name: pebble-config }
        - name: api-tls
          secret: { secretName: pebble-api-tls }
---
apiVersion: v1
kind: Service
metadata: { name: pebble }
spec:
  selector: { app: pebble }
  ports:
    - { name: acme, port: 14000, targetPort: 14000 }
    - { name: mgmt, port: 15000, targetPort: 15000 }
YAML

k rollout status deploy/challtestsrv --timeout=120s
k rollout status deploy/pebble --timeout=120s

# ---------------------------------------------------------------------------
# Pebble has TWO distinct test PKIs, and we need both:
#
#  (a) The ACME *API* endpoint (:14000) is served with a static cert (CN=localhost)
#      signed by pebble's baked-in "minica" root (test/certs/pebble.minica.pem).
#      lolgateway's ACME HTTP client must trust THIS to connect — that's what
#      --acme-ca-cert points at.
#
#  (b) The *issuance* root is generated fresh on each pebble start and served at
#      https://<mgmt>:15000/roots/0. It signs the certs pebble ISSUES, so curl
#      must trust THIS to validate the cert lolgateway gets and serves.
#
# (a) and (b) are different CAs; conflating them gives "UnknownIssuer".
echo "==> publish minica as the --acme-ca-cert (trusts pebble's ACME API TLS)"
k create configmap pebble-api-ca --from-file=ca.pem="$TMP/minica.pem"

echo "==> fetch pebble's issuance root (/roots/0), for curl to validate issued certs"
# pebble is distroless (no shell/wget), so fetch via a throwaway curl pod. Pipe
# through sed to keep ONLY the PEM block — `kubectl run -i` can interleave attach
# warnings into stdout, which would corrupt the captured cert.
k run pebble-ca-fetch-$RANDOM --rm -i --restart=Never --image=curlimages/curl:latest \
  --command -- curl -sS -k "https://pebble.$NS.svc:15000/roots/0" \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$TMP/root.pem"
grep -q 'BEGIN CERTIFICATE' "$TMP/root.pem" || { echo "FAIL: could not fetch pebble issuance root"; exit 1; }

# ---------------------------------------------------------------------------
echo "==> echo backend"
k apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: echo, labels: { app: echo } }
spec:
  replicas: 1
  selector: { matchLabels: { app: echo } }
  template:
    metadata: { labels: { app: echo } }
    spec:
      containers:
        - name: echo
          image: registry.k8s.io/gateway-api/echo-basic:v1.5.1
          imagePullPolicy: IfNotPresent
          env:
            - { name: POD_NAME, valueFrom: { fieldRef: { fieldPath: metadata.name } } }
            - { name: NAMESPACE, valueFrom: { fieldRef: { fieldPath: metadata.namespace } } }
          ports: [{ containerPort: 3000 }]
---
apiVersion: v1
kind: Service
metadata: { name: echo }
spec:
  selector: { app: echo }
  ports: [{ port: 80, targetPort: 3000 }]
YAML

# ---------------------------------------------------------------------------
# lolgateway's ACME leader scans for work every SCAN_INTERVAL (300s) and at
# startup. To keep the test fast and realistic (the common case is "Gateway
# already exists, controller starts"), we create the Service, seed DNS, and
# create the opted-in Gateway FIRST, then deploy lolgateway LAST so its startup
# scan issues immediately rather than waiting for the next poll.
echo "==> lolgateway Service (created early so we can resolve its ClusterIP)"
k apply -f - <<YAML
apiVersion: v1
kind: Service
metadata: { name: lolgateway }
spec:
  selector: { app: lolgateway }
  ports:
    - { name: http, port: 80, targetPort: 80 }
    - { name: https, port: 443, targetPort: 443 }
YAML

# ---------------------------------------------------------------------------
echo "==> point the challenge host at lolgateway's Service (via challtestsrv)"
LOLGW_IP=$(k get svc lolgateway -o jsonpath='{.spec.clusterIP}')
echo "    $HOST -> $LOLGW_IP"
# challtestsrv is distroless; POST to its management API from a throwaway pod.
# Body: {"host":"<fqdn-with-trailing-dot>","addresses":["<ip>"]}.
k run challtestsrv-seed-$RANDOM --rm -i --restart=Never --image=curlimages/curl:latest \
  --command -- curl -sS -X POST \
    --data "{\"host\":\"$HOST.\",\"addresses\":[\"$LOLGW_IP\"]}" \
    "http://challtestsrv.$NS.svc:8055/add-a"

# ---------------------------------------------------------------------------
echo "==> Gateway opted into ACME + HTTPRoute to the echo backend"
PEBBLE_DIR="https://pebble.$NS.svc:14000/dir"
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: acme-test
  namespace: $NS
  annotations:
    lolgateway.dev/acme-issuer: "$PEBBLE_DIR"
    lolgateway.dev/acme-email: "test@lol.example"
spec:
  gatewayClassName: gateway-conformance
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: "$HOST"
      allowedRoutes: { namespaces: { from: Same } }
      tls:
        mode: Terminate
        certificateRefs:
          - { kind: Secret, name: acme-test-cert }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: echo, namespace: $NS }
spec:
  parentRefs: [{ name: acme-test }]
  hostnames: ["$HOST"]
  rules:
    - backendRefs: [{ name: echo, port: 80 }]
YAML

# ---------------------------------------------------------------------------
echo "==> deploy lolgateway (--acme, trusting pebble's CA) — its startup scan"
echo "    finds the already-existing opted-in Gateway and issues immediately"
k apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: lolgateway, labels: { app: lolgateway } }
spec:
  replicas: 1
  selector: { matchLabels: { app: lolgateway } }
  template:
    metadata: { labels: { app: lolgateway } }
    spec:
      serviceAccountName: lolgateway
      containers:
        - name: lolgateway
          image: $IMAGE
          imagePullPolicy: Never
          args:
            - run
            - --bind-ip=0.0.0.0
            - --http-ports=80
            - --tls-ports=443
            - --acme
            - --acme-namespace=$NS
            - --acme-ca-cert=/pebble-ca/ca.pem
          env:
            # --log is a global flag (before the subcommand); set it via env instead.
            - { name: LOLGATEWAY_LOG, value: "info,lolgateway=debug" }
            - { name: POD_NAME, valueFrom: { fieldRef: { fieldPath: metadata.name } } }
          volumeMounts: [{ name: pebble-ca, mountPath: /pebble-ca, readOnly: true }]
          ports: [{ containerPort: 80 }, { containerPort: 443 }]
      volumes:
        - name: pebble-ca
          configMap: { name: pebble-api-ca }
YAML
k rollout status deploy/lolgateway --timeout=120s

# ---------------------------------------------------------------------------
echo "==> wait for the ACME-issued cert Secret ($NS/acme-test-cert)"
deadline=$(( $(date +%s) + 180 ))
while :; do
  if k get secret acme-test-cert >/dev/null 2>&1 \
     && [ -n "$(k get secret acme-test-cert -o jsonpath='{.data.tls\.crt}' 2>/dev/null)" ]; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "FAIL: cert Secret not issued within timeout"
    echo "----- lolgateway logs -----"; k logs deploy/lolgateway --tail=80 || true
    echo "----- pebble logs -----";     k logs deploy/pebble --tail=40 || true
    exit 1
  fi
  sleep 3
done

echo "==> cert issued. Subject + issuer + validity:"
k get secret acme-test-cert -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# ---------------------------------------------------------------------------
echo "==> curl the gateway over HTTPS, validating against pebble's issuance root"
# The host routes the cluster Service CIDR (see README), so curl straight from
# here. --resolve maps $HOST:443 to lolgateway's ClusterIP; --cacert is pebble's
# issuance root, so this validates the full chain (leaf + intermediate served by
# the gateway) up to that root.
RESULT=$(curl -sS --fail-with-body \
  --cacert "$TMP/root.pem" \
  --resolve "$HOST:443:$LOLGW_IP" \
  "https://$HOST/" 2>&1) \
  || { echo "FAIL: HTTPS request failed"; echo "$RESULT"; exit 1; }

# echo-basic pretty-prints, so match whitespace-tolerantly.
echo "$RESULT" | grep -qE "\"namespace\": *\"$NS\"" \
  || { echo "FAIL: unexpected echo response:"; echo "$RESULT"; exit 1; }
echo "    echo backend response verified (namespace=$NS, served over TLS)"

echo
echo "============================================================"
echo " PASS: lolgateway issued a cert via ACME TLS-ALPN-01 and"
echo "       served HTTPS for $HOST, validated against pebble's CA."
echo "============================================================"
