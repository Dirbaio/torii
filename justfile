# lolgateway dev tasks. Run `just <task>`. (Install: https://github.com/casey/just)

# Path to the local kubeconfig (kind cluster). Override with `just KUBECONFIG=... <task>`.
export KUBECONFIG := justfile_directory() + "/kubeconfig"

# Pod/Service CIDRs to route from the host (must match the kind cluster).
pod_cidr := "10.244.0.0/16"
svc_cidr := "10.96.0.0/16"

default:
    @just --list

# Build the workspace.
build:
    cargo build

# Run unit tests.
test:
    cargo test --bin lolgateway

# Verify connectivity to the cluster.
check:
    cargo run -- check

# Run the controller + proxy. HTTP listeners on 80/8080/8090, HTTPS (TLS-terminate,
# per-SNI cert) on 443. Requires `sudo sysctl net.ipv4.ip_unprivileged_port_start=80`.
run:
    cargo run -- run --bind-ip 0.0.0.0 --http-ports 80,8080,8090 --tls-ports 443 --advertise 127.0.0.1

# Create the local kind cluster and make Pod/Service CIDRs host-routable.
cluster-up:
    #!/usr/bin/env bash
    set -euo pipefail
    cat <<EOF | kind create cluster --name lol --config=-
    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    networking:
      podSubnet: "{{pod_cidr}}"
      serviceSubnet: "{{svc_cidr}}"
    nodes:
      - role: control-plane
    EOF
    NODE_IP=$(docker container inspect lol-control-plane --format '{{{{ .NetworkSettings.Networks.kind.IPAddress }}}}')
    sudo ip route add {{pod_cidr}} via "$NODE_IP"
    sudo ip route add {{svc_cidr}} via "$NODE_IP"
    kind get kubeconfig --name lol > kubeconfig
    kubectl apply -f gateway-api/config/crd/standard/
    kubectl apply -f - <<EOF
    apiVersion: gateway.networking.k8s.io/v1
    kind: GatewayClass
    metadata: { name: gateway-conformance }
    spec: { controllerName: lolgateway.dev/controller }
    EOF

# Tear down the kind cluster and remove host routes.
cluster-down:
    -sudo ip route del {{pod_cidr}}
    -sudo ip route del {{svc_cidr}}
    kind delete cluster --name lol

# Run one or more conformance tests by ShortName (controller must be running).
# Usage: just conformance HTTPRouteSimpleSameNamespace [More...]
conformance +tests:
    bash hack/run-tests.sh {{tests}}

# Run the whole GATEWAY-HTTP profile (controller must be running).
conformance-all:
    cd gateway-api && go test ./conformance -run TestConformance -timeout 30m -args \
      --gateway-class=gateway-conformance \
      --conformance-profiles=GATEWAY-HTTP \
      --allow-crds-mismatch
