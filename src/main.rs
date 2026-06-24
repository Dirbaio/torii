//! torii — a Kubernetes Gateway API controller built on Pingora.
//!
//! The single entrypoint runs both planes: the kube controller (control plane) on
//! the tokio runtime, and the Pingora proxy (data plane) on a dedicated thread.

use anyhow::{Context, Result};
use clap::Parser;
use kube::Client;

mod acme;
mod acme_cert;
mod cert_store;
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
    std::thread::Builder::new()
        .name("dataplane".into())
        .spawn(move || dataplane::run(dp, &bind_ip, &http_ports, &tls_ports))
        .context("failed to spawn data-plane thread")?;

    // ACME (optional): only spawned with --acme. When off, nothing changes.
    if args.acme {
        let acme_config = acme::AcmeConfig {
            namespace: args.acme_namespace.clone(),
            default_issuer: args.acme_issuer.clone(),
            default_email: args.acme_email.clone(),
            holder_id: acme_holder_id(),
            ca_cert_path: args.acme_ca_cert.clone(),
        };
        let acme_client = client.clone();
        let acme_dp = data_plane.clone();
        tokio::spawn(async move {
            if let Err(e) = acme::run(acme_client, acme_dp, acme_config).await {
                tracing::error!(error = %e, "ACME subsystem exited");
            }
        });
    }

    // Control plane on this runtime.
    let config = controller::ControllerConfig {
        advertise_address: args.advertise,
    };
    controller::run(client, data_plane, config).await
}

/// A stable-per-process identity for ACME Lease leader election. Prefer the pod
/// name (downward API via `POD_NAME`/`HOSTNAME`); fall back to the hostname.
fn acme_holder_id() -> String {
    std::env::var("POD_NAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| format!("torii-{}", std::process::id()))
}

fn init_tracing(filter: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // CLI flag / env sets the default; RUST_LOG still wins if explicitly set.
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}
