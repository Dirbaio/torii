#!/usr/bin/env bash
# torii dev tasks. Usage: ./d <task> [args]
set -euo pipefail
cd "$(dirname "$0")"

export KUBECONFIG="$PWD/kubeconfig"
POD_CIDR=10.244.0.0/16
SVC_CIDR=10.96.0.0/16

case "${1:-}" in

build)
    cargo build
    ;;

test)
    cargo test --bin torii
    ;;

check)
    cargo run -- check
    ;;

# Run the controller + proxy. HTTP on 80/8080/8090, HTTPS (TLS-terminate, per-SNI
# cert) on 443/8443/8883. Needs `sudo sysctl net.ipv4.ip_unprivileged_port_start=80`.
run)
    cargo run -- run --bind-ip 0.0.0.0 \
        --http-ports 80,8080,8090 --tls-ports 443,8443,8883 --advertise 127.0.0.1
    ;;

# Create the local kind cluster and make Pod/Service CIDRs host-routable.
cluster-up)
    kind create cluster --name lol --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "$POD_CIDR"
  serviceSubnet: "$SVC_CIDR"
nodes:
  - role: control-plane
EOF
    NODE_IP=$(docker container inspect lol-control-plane \
        --format '{{ .NetworkSettings.Networks.kind.IPAddress }}')
    sudo ip route add "$POD_CIDR" via "$NODE_IP"
    sudo ip route add "$SVC_CIDR" via "$NODE_IP"
    kind get kubeconfig --name lol > kubeconfig
    kubectl apply -f gateway-api/config/crd/standard/
    kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: gateway-conformance }
spec: { controllerName: torii.dirba.io/controller }
EOF
    ;;

# Tear down the kind cluster and remove host routes.
cluster-down)
    sudo ip route del "$POD_CIDR" || true
    sudo ip route del "$SVC_CIDR" || true
    kind delete cluster --name lol
    ;;

# Run one or more conformance tests by ShortName (controller must be running).
# Usage: ./d conformance HTTPRouteSimpleSameNamespace [More...]
conformance)
    shift
    bash hack/run-tests.sh "$@"
    ;;

# Run the whole GATEWAY-HTTP profile (controller must be running). -count=1 bypasses
# go's test cache (a cached run returns "ok" WITHOUT re-testing the cluster).
# GATEWAY-HTTP only: GATEWAY-TLS forces out-of-scope TLSRoute core tests.
conformance-all)
    cd gateway-api && go test ./conformance -run TestConformance -count=1 -timeout 30m -args \
        --gateway-class=gateway-conformance \
        --conformance-profiles=GATEWAY-HTTP \
        --allow-crds-mismatch
    ;;

*)
    echo "usage: ./d {build|test|check|run|cluster-up|cluster-down|conformance <Test...>|conformance-all}" >&2
    exit 1
    ;;
esac
