//! torii — a Kubernetes Gateway API controller built on Pingora.
//!
//! The single entrypoint runs both planes: the kube controller (control plane) on
//! the tokio runtime, and the Pingora proxy (data plane) on a dedicated thread.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use kube::Client;

// Use jemalloc instead of the system glibc malloc. glibc malloc spawns up to
// 8*nCPU arenas and caches freed chunks per-arena without returning them to the
// OS, so under bursts of concurrent connections this proxy's RSS ratchets up to a
// fragmented high-water mark and never recedes — which OOM-killed it in prod with
// no actual code leak. jemalloc fragments far less and decays memory back to the
// OS, keeping steady-state RSS bounded.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod acme;
mod acme_cert;
mod cert_store;
mod conn_limit;
mod controller;
mod dataplane;
mod route_table;
mod snapshot;
mod tls_sni;
mod tls_table;

/// torii: a Kubernetes Gateway API controller built on Pingora. Running the binary
/// starts both the controller and the proxy; there are no subcommands.
#[derive(Parser, Debug)]
#[command(name = "torii", version, about)]
struct Cli {
    /// Log filter, e.g. `info`, `debug`, `torii=debug,kube=info`.
    #[arg(long, env = "TORII_LOG", default_value = "info")]
    log: String,

    /// IP the data-plane proxy binds to.
    #[arg(long, env = "TORII_BIND_IP", default_value = "0.0.0.0")]
    bind_ip: String,

    /// Plain-HTTP listener ports. The proxy routes per-port via the local socket.
    #[arg(
        long,
        env = "TORII_HTTP_PORTS",
        value_delimiter = ',',
        default_value = "80,8080,8090"
    )]
    http_ports: Vec<u16>,

    /// TLS listener ports. Each runs the SNI-dispatch app: TLSRoute passthrough /
    /// terminate-to-TCP per SNI, falling back to TLS-terminate + HTTP (HTTPS
    /// HTTPRoutes) when no TLSRoute matches. Includes the conformance TLSRoute
    /// ports (8443, 8883) alongside the standard 443.
    #[arg(
        long,
        env = "TORII_TLS_PORTS",
        value_delimiter = ',',
        default_value = "443,8443,8883"
    )]
    tls_ports: Vec<u16>,

    /// IP advertised in Gateway.status.addresses — must be reachable by the
    /// conformance suite. Defaults to the loopback address.
    #[arg(long, env = "TORII_ADVERTISE", default_value = "127.0.0.1")]
    advertise: String,

    /// How long to wait for a connection to a backend, TLS handshake included,
    /// before answering 504 (a TLSRoute connection is closed instead). An HTTPRoute
    /// rule's shorter `timeouts` shorten it. A duration like `10s` or `500ms`; `0s`
    /// disables it.
    #[arg(long, env = "TORII_UPSTREAM_CONNECT_TIMEOUT", default_value = "10s", value_parser = parse_duration)]
    upstream_connect_timeout: Duration,

    /// How long a backend may go without sending or accepting data during a request,
    /// the wait for its response included, before torii answers 504 (or cuts the
    /// response short). So a WebSocket or long poll whose backend stays silent this
    /// long is closed. An HTTPRoute rule's `timeouts` replace it, and `0s` there
    /// disables it. A duration like `60s` or `5m`; `0s` disables it.
    #[arg(long, env = "TORII_UPSTREAM_TIMEOUT", default_value = "60s", value_parser = parse_duration)]
    upstream_timeout: Duration,

    /// Forward request paths that contain an encoded `/` or `\` (`%2F`, `%5C`),
    /// which are otherwise answered with 400. torii keeps them encoded and routes
    /// them as data, but a backend that decodes them before it resolves `..` (nginx,
    /// Python's http.server) can then be led outside the paths its routes send it.
    /// Turn on only for backends that need them, such as an npm registry's
    /// `/@scope%2Fname`.
    #[arg(long, env = "TORII_ALLOW_ENCODED_SLASHES")]
    allow_encoded_slashes: bool,

    /// Most connections one client may have open at once, on all ports together. A
    /// client is an IPv4 address or an IPv6 /64; its connections over this are
    /// closed as they come. Raise it, or set `0` to disable it, if many clients
    /// share an address: behind a NAT, or a load balancer that does not keep client
    /// addresses.
    #[arg(long, env = "TORII_MAX_CONNECTIONS_PER_SOURCE", default_value_t = 256)]
    max_connections_per_source: usize,

    /// Most connections open at once, on all ports together; new ones over this are
    /// closed as they come. Defaults to one per 128 KiB of the memory limit
    /// (`limits.memory`, from cgroup v2), about twice what an idle TLS connection
    /// costs, so that connections cannot exhaust it. No limit without a memory
    /// limit, or with `0`.
    #[arg(long, env = "TORII_MAX_CONNECTIONS")]
    max_connections: Option<usize>,

    /// Enable automatic TLS certificate issuance via ACME (TLS-ALPN-01).
    /// OFF by default; even when on, a Gateway must opt in by carrying the
    /// `torii.dirba.io/acme` annotation. Requires a TLS listener port.
    #[arg(long, env = "TORII_ACME")]
    acme: bool,

    /// Namespace where ACME state Secrets are stored (account key, in-flight
    /// challenge cert). The issued certs go into each listener's own
    /// certificateRefs Secret, not here.
    #[arg(long, env = "TORII_ACME_NAMESPACE", default_value = "torii-system")]
    acme_namespace: String,

    /// Default ACME directory URL (e.g. Let's Encrypt) for all opted-in Gateways.
    /// A Gateway's `torii.dirba.io/acme-issuer` annotation overrides this. If
    /// neither is set, an opted-in listener reports an ACME failure. Optional.
    #[arg(long, env = "TORII_ACME_ISSUER")]
    acme_issuer: Option<String>,

    /// Default contact email for the ACME account. A Gateway's
    /// `torii.dirba.io/acme-email` annotation overrides this. If neither is set,
    /// an opted-in listener reports an ACME failure. Optional.
    #[arg(long, env = "TORII_ACME_EMAIL")]
    acme_email: Option<String>,

    /// Path to a PEM root CA the ACME client should trust. Only needed for ACME
    /// servers with a testing PKI (e.g. pebble); production CAs are publicly
    /// trusted. Optional.
    #[arg(long, env = "TORII_ACME_CA_CERT")]
    acme_ca_cert: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    init_tracing(&args.log);

    // kube's rustls-tls backend needs a process-wide CryptoProvider chosen explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    run(args).await
}

/// Run both planes: the kube controller on this tokio runtime, and the Pingora
/// proxy on a dedicated OS thread (it blocks and manages its own runtime).
async fn run(args: Cli) -> Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to build Kubernetes client")?;

    // One atomically-swapped snapshot (route table + cert store) shared between
    // the control plane (writer) and data plane (reader).
    let data_plane = snapshot::DataPlane::new();

    // Data plane on its own thread — run_forever() blocks and calls process::exit.
    let dp = data_plane.clone();
    let bind_ip = args.bind_ip.clone();
    let http_ports = args.http_ports.clone();
    let tls_ports = args.tls_ports.clone();
    let enabled = |d: Duration| Some(d).filter(|d| !d.is_zero());
    let timeouts = dataplane::UpstreamTimeouts {
        connect: enabled(args.upstream_connect_timeout),
        response: enabled(args.upstream_timeout),
    };
    let allow_encoded_slashes = args.allow_encoded_slashes;
    let limits = conn_limit::ConnLimits {
        per_source: Some(args.max_connections_per_source).filter(|&n| n > 0),
        total: match args.max_connections {
            Some(n) => Some(n).filter(|&n| n > 0),
            None => conn_limit::default_max_connections(),
        },
    };
    std::thread::Builder::new()
        .name("dataplane".into())
        .spawn(move || {
            dataplane::run(
                dp,
                &bind_ip,
                &http_ports,
                &tls_ports,
                timeouts,
                allow_encoded_slashes,
                limits,
            )
        })
        .context("failed to spawn data-plane thread")?;

    // ACME (optional): only spawned with --acme. When off, `acme_feed` is None and the
    // controller skips computing/publishing issuance targets entirely.
    let acme_feed = if args.acme {
        // The controller computes the desired issuance targets during reconcile and
        // pushes them through this feed; the ACME leader consumes them. So the
        // controller, not ACME, resolves issuer/email — ACME just acts on the set.
        let feed = acme::AcmeFeed::new();
        let acme_config = acme::AcmeConfig {
            namespace: args.acme_namespace.clone(),
            holder_id: acme_holder_id(),
            ca_cert_path: args.acme_ca_cert.clone(),
        };
        let acme_client = client.clone();
        let acme_dp = data_plane.clone();
        let acme_feed = feed.clone();
        tokio::spawn(async move {
            if let Err(e) = acme::run(acme_client, acme_dp, acme_feed, acme_config).await {
                tracing::error!(error = %e, "ACME subsystem exited");
            }
        });
        Some(feed)
    } else {
        None
    };

    // Control plane on this runtime.
    let config = controller::ControllerConfig {
        advertise_address: args.advertise,
        acme_feed,
        acme_default_issuer: args.acme_issuer,
        acme_default_email: args.acme_email,
    };
    controller::run(client, data_plane, config).await
}

/// Parse a duration flag, in the GEP-2257 format of HTTPRoute timeouts.
fn parse_duration(s: &str) -> Result<Duration, String> {
    controller::parse_gep2257_duration(s)
        .ok_or_else(|| format!("invalid duration {s:?} (expected e.g. 10s, 1m30s, 500ms)"))
}

/// A stable-per-process identity for ACME Lease leader election. Prefer the pod
/// name (downward API via `POD_NAME`/`HOSTNAME`); fall back to the hostname.
fn acme_holder_id() -> String {
    std::env::var("POD_NAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| format!("torii-{}", std::process::id()))
}

fn init_tracing(filter: &str) {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

    // CLI flag / env sets the default; RUST_LOG still wins if explicitly set.
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}
