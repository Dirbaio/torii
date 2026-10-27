# Build torii. Multi-stage: a Debian-based Rust builder (so the binary's glibc ABI
# matches the Debian runtime + the kind node), then a slim runtime image.
#
# Context is the repo root; .dockerignore trims it to Cargo.{toml,lock} + src/.
# Dependencies come from crates.io, except our h2 fork (a git dependency).

FROM rust:1-bookworm AS builder

# A C toolchain for the -sys crates (ring, jemalloc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake perl clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build our binary (all deps come from crates.io).
RUN cargo build --release --bin torii \
    && cp target/release/torii /torii

FROM debian:bookworm-slim AS runtime

# Runtime needs CA certs (for the kube API, ACME, and BackendTLSPolicy
# wellKnownCACertificates).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /torii /usr/local/bin/torii

ENTRYPOINT ["/usr/local/bin/torii"]
