//! lolgateway — a Kubernetes Gateway API controller built on Pingora.
//!
//! This is the scaffolding entrypoint. Right now it only proves we can talk to
//! the Kubernetes API server; the controller and data plane come later.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use k8s_openapi::api::core::v1::Namespace;
use kube::{api::ListParams, Api, Client};

mod cert_store;
mod controller;
mod dataplane;
mod route_table;
mod snapshot;

/// lolgateway: a Kubernetes Gateway API controller built on Pingora.
#[derive(Parser, Debug)]
#[command(name = "lolgateway", version, about)]
struct Cli {
    /// Log filter, e.g. `info`, `debug`, `lolgateway=debug,kube=info`.
    #[arg(long, env = "LOLGATEWAY_LOG", default_value = "info")]
    log: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Connect to the Kubernetes API server and verify access.
    Check,
    /// Run the controller (control plane) and the proxy (data plane).
    Run(RunArgs),
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// IP the data-plane proxy binds to.
    #[arg(long, env = "LOLGATEWAY_BIND_IP", default_value = "0.0.0.0")]
    bind_ip: String,

    /// Plain-HTTP listener ports. The proxy routes per-port via the local socket.
    #[arg(
        long,
        env = "LOLGATEWAY_HTTP_PORTS",
        value_delimiter = ',',
        default_value = "80,8080,8090"
    )]
    http_ports: Vec<u16>,

    /// HTTPS listener ports (TLS terminated, cert selected by SNI).
    #[arg(
        long,
        env = "LOLGATEWAY_TLS_PORTS",
        value_delimiter = ',',
        default_value = "443"
    )]
    tls_ports: Vec<u16>,

    /// IP advertised in Gateway.status.addresses — must be reachable by the
    /// conformance suite. Defaults to the loopback address.
    #[arg(long, env = "LOLGATEWAY_ADVERTISE", default_value = "127.0.0.1")]
    advertise: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    // kube's rustls-tls backend needs a process-wide CryptoProvider chosen explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    match cli.command {
        Command::Check => check().await,
        Command::Run(args) => run(args).await,
    }
}

/// Run both planes: the kube controller on this tokio runtime, and the Pingora
/// proxy on a dedicated OS thread (it blocks and manages its own runtime).
async fn run(args: RunArgs) -> Result<()> {
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

    // Control plane on this runtime.
    let config = controller::ControllerConfig {
        advertise_address: args.advertise,
    };
    controller::run(client, data_plane, config).await
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

/// Verify we can reach the API server and read core resources.
///
/// Uses the ambient config: in-cluster service account if present, otherwise
/// the current kubeconfig context (`~/.kube/config` / `$KUBECONFIG`).
async fn check() -> Result<()> {
    let client = Client::try_default()
        .await
        .context("failed to build Kubernetes client (is a kubeconfig or in-cluster config available?)")?;

    tracing::info!(
        default_namespace = client.default_namespace(),
        "built Kubernetes client"
    );

    // 1. Hit the version endpoint — the cheapest proof the API server answers.
    let info = client
        .apiserver_version()
        .await
        .context("failed to query API server version")?;
    tracing::info!(
        version = %format!("{}.{}", info.major, info.minor),
        git_version = %info.git_version,
        platform = %info.platform,
        "connected to Kubernetes API server"
    );

    // 2. List namespaces — proves auth + RBAC let us actually read objects.
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let ns_list = namespaces
        .list(&ListParams::default())
        .await
        .context("failed to list namespaces (check RBAC permissions)")?;
    tracing::info!(count = ns_list.items.len(), "listed namespaces");
    for ns in &ns_list.items {
        tracing::debug!(name = ns.metadata.name.as_deref().unwrap_or("<unnamed>"), "namespace");
    }

    println!(
        "OK: connected to Kubernetes {}.{}, {} namespace(s) visible",
        info.major,
        info.minor,
        ns_list.items.len()
    );
    Ok(())
}
