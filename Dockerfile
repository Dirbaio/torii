# Build lolgateway. Multi-stage: a Debian-based Rust builder (so the binary's
# glibc/OpenSSL ABI matches the Debian runtime + the kind node), then a slim
# runtime image with just the shared libs Pingora's OpenSSL backend needs.
#
# Context is the repo root; .dockerignore trims it to Cargo.{toml,lock} + src/
# + the vendored pingora/ path deps.

FROM rust:1-bookworm AS builder

# Pingora's `openssl` feature links against system OpenSSL; the build needs the
# dev headers, pkg-config, and a C toolchain (cc/perl for some -sys crates).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake perl clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build only our binary (pingora/gateway-api are path/vendored, not members).
RUN cargo build --release --bin lolgateway \
    && cp target/release/lolgateway /lolgateway

FROM debian:bookworm-slim AS runtime

# Runtime needs OpenSSL shared libs + CA certs (for talking to the kube API / ACME).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /lolgateway /usr/local/bin/lolgateway

ENTRYPOINT ["/usr/local/bin/lolgateway"]
