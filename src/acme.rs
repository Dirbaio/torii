//! Automatic TLS certificate issuance via ACME (TLS-ALPN-01).
//!
//! Off by default; enabled with `--acme`. Even then, a Gateway must opt in with
//! the `lolgateway.dev/acme-issuer` annotation (the ACME directory URL). For each
//! HTTPS/TLS-terminate listener with a (single, non-wildcard) hostname and a
//! `certificateRefs` Secret, we obtain a cert and write it into that Secret — the
//! controller's existing Secret watcher + cert store then serve it, no special
//! data-plane path for the *issued* cert.
//!
//! ## Multi-instance
//! Issuance is driven by a single leader (a `coordination.k8s.io` Lease). But the
//! TLS-ALPN-01 verification connection may land on ANY instance, so the challenge
//! validation cert is published to a shared Secret that every instance reflects
//! into its data plane — any instance can answer the `acme-tls/1` handshake.
//!
//! ## State (all in k8s, in `--acme-namespace`)
//! - account key: Secret `lolgateway-acme-account` (`credentials.json`).
//! - in-flight challenge certs: Secret `lolgateway-acme-challenge` (`<host>.crt/.key`).
//! - issued certs: each listener's own `certificateRefs` Secret (`tls.crt/tls.key`).

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher::{watcher, Config};
use kube::runtime::WatchStreamExt;
use kube::{Client, ResourceExt};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};

use gateway_api::apis::standard::gateways::Gateway;

use crate::cert_store::CertKey;
use crate::snapshot::{ChallengeStore, DataPlane};

/// Gateway annotation naming the ACME directory URL (opt-in trigger). Public so the
/// controller can detect ACME-opted-in listeners and report their status.
pub const ANNO_ISSUER: &str = "lolgateway.dev/acme-issuer";
/// Gateway annotation overriding the ACME contact email.
const ANNO_EMAIL: &str = "lolgateway.dev/acme-email";

const ACCOUNT_SECRET: &str = "lolgateway-acme-account";
const CHALLENGE_SECRET: &str = "lolgateway-acme-challenge";
const FIELD_MANAGER: &str = "lolgateway-acme";
const LEASE_NAME: &str = "lolgateway-acme-leader";

/// Renew when the cert is within this window of expiry (Let's Encrypt issues
/// 90-day certs; ~30 days early is the conventional safety margin).
const RENEW_WINDOW: Duration = Duration::from_secs(30 * 24 * 3600);
/// How often the leader scans for issuance/renewal work.
const SCAN_INTERVAL: Duration = Duration::from_secs(300);
/// Lease lifetime; we renew well within it.
const LEASE_TTL: Duration = Duration::from_secs(15);
const LEASE_RENEW: Duration = Duration::from_secs(5);
/// Settle time after publishing a challenge cert before telling ACME to verify,
/// so the challenge Secret can propagate to followers (the validator may hit any).
const CHALLENGE_SETTLE: Duration = Duration::from_secs(2);

/// Failure backoff: after a failed issuance, wait at least this long before
/// retrying that host, doubling per consecutive failure up to [`BACKOFF_MAX`].
/// Without this, a host that can never validate (bad DNS, unreachable :443, typo'd
/// hostname) is re-ordered every [`SCAN_INTERVAL`] forever — unbounded CA churn that
/// burns the account's failed-validation budget. The backoff is reset on success.
const BACKOFF_BASE: Duration = Duration::from_secs(300);
const BACKOFF_MAX: Duration = Duration::from_secs(6 * 3600);

/// Runtime config for the ACME subsystem.
#[derive(Clone)]
pub struct AcmeConfig {
    pub namespace: String,
    pub default_email: Option<String>,
    /// A stable identity for this instance (Lease holder id). Pod name or a uuid.
    pub holder_id: String,
    /// Path to a PEM root CA the ACME client should trust, for ACME servers with a
    /// testing PKI (e.g. pebble). `None` → use the system trust roots.
    pub ca_cert_path: Option<String>,
}

/// Spawn the ACME subsystem: a challenge-Secret reflector (every instance, feeds
/// the data plane so any instance serves `acme-tls/1`) plus the leader loop
/// (issuance + renewal, gated by the Lease). Returns immediately; runs forever.
pub async fn run(client: Client, data_plane: DataPlane, config: AcmeConfig) -> Result<()> {
    // Every instance reflects the shared challenge Secret into the data plane.
    spawn_challenge_reflector(client.clone(), data_plane.clone(), config.namespace.clone());

    let lease = LeaseLock::new(
        client.clone(),
        &config.namespace,
        LeaseLockParams {
            lease_name: LEASE_NAME.to_string(),
            holder_id: config.holder_id.clone(),
            lease_ttl: LEASE_TTL,
        },
    );

    tracing::info!(namespace = %config.namespace, "ACME subsystem started");

    let gw_api: Api<Gateway> = Api::all(client.clone());
    let mut last_scan = std::time::Instant::now()
        .checked_sub(SCAN_INTERVAL)
        .unwrap_or_else(std::time::Instant::now);
    // Per-host failure backoff, persisted across scans for as long as we stay leader.
    let mut backoff = Backoff::default();

    loop {
        // Renew/acquire the lease on a tight cadence so leadership is fresh.
        let is_leader = match lease.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => true,
            Ok(LeaseLockResult::NotAcquired(_)) => false,
            Err(e) => {
                tracing::warn!(error = format!("{e:#}"), "ACME lease acquire/renew failed");
                false
            }
        };

        if is_leader && last_scan.elapsed() >= SCAN_INTERVAL {
            last_scan = std::time::Instant::now();
            if let Err(e) = scan_and_issue(&client, &gw_api, &config, &mut backoff).await {
                tracing::warn!(error = format!("{e:#}"), "ACME scan/issue failed");
            }
        }

        tokio::time::sleep(LEASE_RENEW).await;
    }
}

/// One certificate the leader needs to (re)issue.
struct CertNeed {
    /// ACME directory URL (from the Gateway annotation).
    directory: String,
    email: Option<String>,
    /// The single DNS hostname to validate.
    hostname: String,
    /// The listener's certificateRefs Secret (namespace, name) — issuance target.
    secret_ns: String,
    secret_name: String,
}

impl CertNeed {
    /// Backoff key: the issuance target. Distinct listeners back off independently.
    fn key(&self) -> (String, String, String) {
        (self.secret_ns.clone(), self.secret_name.clone(), self.hostname.clone())
    }
}

/// Per-host issuance-failure backoff (leader-local, in memory). On leader change the
/// new leader starts fresh — it then makes at most one attempt per host before the
/// backoff re-engages, so churn stays bounded across failovers too.
#[derive(Default)]
struct Backoff {
    entries: HashMap<(String, String, String), BackoffEntry>,
}

struct BackoffEntry {
    /// Consecutive failures so far (drives the exponential delay).
    fails: u32,
    /// Earliest instant at which this host may be attempted again.
    next_attempt: std::time::Instant,
}

impl Backoff {
    /// Should we attempt this need now, or is it still inside its backoff window?
    fn ready(&self, need: &CertNeed) -> bool {
        match self.entries.get(&need.key()) {
            Some(e) => std::time::Instant::now() >= e.next_attempt,
            None => true,
        }
    }

    /// Record a successful issuance — clear any backoff for this host.
    fn record_success(&mut self, need: &CertNeed) {
        self.entries.remove(&need.key());
    }

    /// Record a failure — bump the counter and schedule the next attempt with an
    /// exponential delay (BACKOFF_BASE * 2^(fails-1), capped at BACKOFF_MAX).
    fn record_failure(&mut self, need: &CertNeed) -> Duration {
        let e = self.entries.entry(need.key()).or_insert(BackoffEntry {
            fails: 0,
            next_attempt: std::time::Instant::now(),
        });
        e.fails = e.fails.saturating_add(1);
        let delay = backoff_delay(e.fails);
        e.next_attempt = std::time::Instant::now() + delay;
        delay
    }
}

/// Exponential backoff delay for the n-th consecutive failure (n >= 1):
/// BACKOFF_BASE * 2^(n-1), saturating at BACKOFF_MAX.
fn backoff_delay(fails: u32) -> Duration {
    let shift = fails.saturating_sub(1).min(16); // cap the shift to avoid overflow
    let mult = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let secs = BACKOFF_BASE.as_secs().saturating_mul(mult);
    Duration::from_secs(secs).min(BACKOFF_MAX)
}

/// Leader pass: find listeners needing a cert and issue/renew each, honoring the
/// per-host failure backoff so a permanently-failing host doesn't churn the CA.
async fn scan_and_issue(
    client: &Client,
    gw_api: &Api<Gateway>,
    config: &AcmeConfig,
    backoff: &mut Backoff,
) -> Result<()> {
    let needs = self::needs(client, gw_api, config).await?;
    if needs.is_empty() {
        return Ok(());
    }
    tracing::info!(count = needs.len(), "ACME: certs to issue/renew");
    for need in needs {
        // Skip hosts still inside their failure-backoff window.
        if !backoff.ready(&need) {
            tracing::debug!(host = %need.hostname, "ACME: in failure backoff, skipping this scan");
            continue;
        }
        match issue(client, config, &need).await {
            Ok(()) => backoff.record_success(&need),
            Err(e) => {
                let delay = backoff.record_failure(&need);
                tracing::warn!(
                    host = %need.hostname, error = format!("{e:#}"),
                    retry_in_s = delay.as_secs(), "ACME issuance failed; backing off",
                );
            }
        }
    }
    Ok(())
}

/// Compute the set of certs to issue/renew: opted-in Gateways' HTTPS listeners
/// whose cert Secret is missing, invalid, or expiring.
async fn needs(client: &Client, gw_api: &Api<Gateway>, config: &AcmeConfig) -> Result<Vec<CertNeed>> {
    use kube::api::ListParams;
    let gateways = gw_api.list(&ListParams::default()).await?;
    let mut out = Vec::new();
    for gw in gateways {
        let anns = gw.annotations();
        let Some(directory) = anns.get(ANNO_ISSUER) else { continue };
        let email = anns.get(ANNO_EMAIL).cloned().or_else(|| config.default_email.clone());
        let gw_ns = gw.namespace().unwrap_or_default();
        for l in &gw.spec.listeners {
            if !matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
                continue;
            }
            // TLS-ALPN-01 validates a concrete DNS name; skip absent/wildcard hosts.
            let Some(host) = l.hostname.as_deref() else { continue };
            if host.starts_with("*.") || host.is_empty() {
                continue;
            }
            let Some(tls) = l.tls.as_ref() else { continue };
            for r in tls.certificate_refs.clone().unwrap_or_default() {
                // Only manage core-Secret refs in the Gateway's namespace.
                if r.group.clone().unwrap_or_default() != ""
                    || r.kind.clone().unwrap_or_else(|| "Secret".into()) != "Secret"
                {
                    continue;
                }
                let secret_ns = r.namespace.clone().unwrap_or_else(|| gw_ns.clone());
                if cert_needs_work(client, &secret_ns, &r.name).await {
                    out.push(CertNeed {
                        directory: directory.clone(),
                        email: email.clone(),
                        hostname: host.to_string(),
                        secret_ns,
                        secret_name: r.name.clone(),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Does this cert Secret need (re)issuance? True if missing, unparseable, or
/// within the renewal window of expiry.
async fn cert_needs_work(client: &Client, ns: &str, name: &str) -> bool {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    let Ok(secret) = api.get(name).await else {
        return true; // missing → issue
    };
    let Some(crt) = secret.data.as_ref().and_then(|d| d.get("tls.crt")) else {
        return true;
    };
    match cert_not_after(&crt.0) {
        Some(not_after_unix) => {
            let now = now_unix();
            let renew_at = not_after_unix - RENEW_WINDOW.as_secs() as i64;
            now >= renew_at
        }
        None => true, // unparseable → reissue
    }
}

/// Drive one ACME order to completion and write the issued cert into its Secret.
async fn issue(client: &Client, config: &AcmeConfig, need: &CertNeed) -> Result<()> {
    tracing::info!(
        host = %need.hostname, directory = %need.directory, secret = %need.secret_name,
        "ACME: starting issuance"
    );
    let account = load_or_create_account(client, config, &need.directory, need.email.as_deref())
        .await
        .context("ACME account")?;
    tracing::debug!(host = %need.hostname, "ACME: account ready");

    let ids = [Identifier::Dns(need.hostname.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .context("new_order")?;
    let order_url = order.url().to_string();
    tracing::info!(host = %need.hostname, status = ?order.state().status, url = %order_url, "ACME: order created");

    // Walk authorizations; for each, publish a TLS-ALPN-01 challenge cert and arm it.
    let mut armed = 0u32;
    let mut authorizations = order.authorizations();
    while let Some(authz) = authorizations.next().await {
        let mut authz = authz?;
        let identifier = authz.identifier().to_string();
        // Skip already-valid authorizations (e.g. reused account).
        if matches!(authz.status, instant_acme::AuthorizationStatus::Valid) {
            tracing::debug!(host = %need.hostname, %identifier, "ACME: authorization already valid, skipping");
            continue;
        }
        tracing::info!(host = %need.hostname, %identifier, status = ?authz.status, "ACME: arming tls-alpn-01 challenge");
        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow!("ACME directory offers no tls-alpn-01 challenge"))?;
        let digest = challenge.key_authorization().digest();
        let (cert_pem, key_pem) = crate::acme_cert::alpn_cert(&identifier, digest.as_ref())
            .context("build challenge cert")?;
        publish_challenge(client, &config.namespace, &identifier, &cert_pem, &key_pem).await?;
        tracing::debug!(
            host = %need.hostname, %identifier, settle_ms = CHALLENGE_SETTLE.as_millis(),
            "ACME: published challenge cert, waiting for it to settle then signaling ready"
        );
        // Give the challenge Secret time to reach followers (validator may hit any).
        tokio::time::sleep(CHALLENGE_SETTLE).await;
        challenge.set_ready().await.context("set_ready")?;
        armed += 1;
    }
    tracing::info!(host = %need.hostname, armed, "ACME: challenges armed, polling order for validation");

    // Wait for the order to be ready, finalize with our own key, fetch the cert.
    let status = match order.poll_ready(&RetryPolicy::default()).await {
        Ok(s) => s,
        Err(e) => {
            // The order never reached Ready — almost always a challenge-validation
            // failure (CA couldn't reach :443 / got the wrong cert). Surface the
            // per-challenge error detail the CA recorded, which the bare timeout hides.
            log_authorization_failures(&mut order, &need.hostname).await;
            return Err(e).context("poll_ready");
        }
    };
    if status != OrderStatus::Ready {
        log_authorization_failures(&mut order, &need.hostname).await;
        return Err(anyhow!("ACME order not ready: {status:?}"));
    }
    tracing::info!(host = %need.hostname, "ACME: order validated, finalizing");
    let key_pair = rcgen::KeyPair::generate().context("gen cert key")?;
    let csr_der = crate::acme_cert::csr_der(&key_pair, &need.hostname).context("build CSR")?;
    order.finalize_csr(&csr_der).await.context("finalize_csr")?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("poll_certificate")?;
    tracing::debug!(host = %need.hostname, "ACME: certificate fetched");

    // Write the issued cert into the listener's certificateRefs Secret. The
    // controller's Secret watcher picks it up and the data plane serves it.
    write_tls_secret(
        client,
        &need.secret_ns,
        &need.secret_name,
        chain_pem.as_bytes(),
        key_pair.serialize_pem().as_bytes(),
    )
    .await
    .context("write issued cert Secret")?;

    // Best-effort: drop the now-unneeded challenge cert.
    let _ = unpublish_challenge(client, &config.namespace, &need.hostname).await;

    tracing::info!(host = %need.hostname, secret = %need.secret_name, "ACME: issued certificate");
    Ok(())
}

/// On a failed/stuck order, re-walk its authorizations and log each one's status
/// plus any per-challenge error the CA recorded. This is what turns an opaque
/// "poll_ready timed out" into the actual reason (e.g. connection refused on :443,
/// "Incorrect validation certificate"), which is otherwise lost.
async fn log_authorization_failures(order: &mut instant_acme::Order, host: &str) {
    let mut authorizations = order.authorizations();
    while let Some(authz) = authorizations.next().await {
        let authz = match authz {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(%host, error = %e, "ACME: failed to fetch authorization for diagnostics");
                continue;
            }
        };
        let identifier = authz.identifier().to_string();
        tracing::warn!(%host, %identifier, status = ?authz.status, "ACME: authorization not valid");
        for ch in &authz.challenges {
            match &ch.error {
                Some(problem) => tracing::warn!(
                    %host, %identifier, kind = ?ch.r#type, status = ?ch.status,
                    problem = %problem, "ACME: challenge failed"
                ),
                None => tracing::warn!(
                    %host, %identifier, kind = ?ch.r#type, status = ?ch.status,
                    "ACME: challenge incomplete (no error reported)"
                ),
            }
        }
    }
}

/// Build an ACME account builder, trusting a custom root CA when configured (for
/// testing PKIs like pebble); otherwise the default client with system roots.
fn account_builder(config: &AcmeConfig) -> Result<instant_acme::AccountBuilder> {
    match &config.ca_cert_path {
        Some(path) => Account::builder_with_root(path)
            .with_context(|| format!("load ACME CA cert from {path}")),
        None => Ok(Account::builder()?),
    }
}

/// Load the persisted ACME account, or create one and persist its credentials.
/// Keyed per directory URL so staging/prod accounts don't collide.
async fn load_or_create_account(
    client: &Client,
    config: &AcmeConfig,
    directory: &str,
    email: Option<&str>,
) -> Result<Account> {
    let api: Api<Secret> = Api::namespaced(client.clone(), &config.namespace);
    let key = account_key(directory);

    if let Ok(secret) = api.get(ACCOUNT_SECRET).await {
        if let Some(creds_raw) = secret.data.as_ref().and_then(|d| d.get(&key)) {
            let creds: AccountCredentials = serde_json::from_slice(&creds_raw.0)
                .context("parse stored ACME credentials")?;
            let account = account_builder(config)?.from_credentials(creds).await?;
            return Ok(account);
        }
    }

    let contact: Vec<String> = email.map(|e| format!("mailto:{e}")).into_iter().collect();
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
    let (account, creds) = account_builder(config)?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            None,
        )
        .await
        .context("create ACME account")?;

    // Persist credentials (merge-patch so multiple directory keys can coexist).
    let creds_json = serde_json::to_vec(&creds)?;
    let mut data = BTreeMap::new();
    data.insert(key, ByteString(creds_json));
    apply_secret(&api, ACCOUNT_SECRET, &config.namespace, "Opaque", data).await?;
    Ok(account)
}

/// Publish a challenge validation cert to the shared challenge Secret so any
/// instance can serve the `acme-tls/1` handshake for `host`.
async fn publish_challenge(
    client: &Client,
    ns: &str,
    host: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    // Read-modify-write the map so concurrent hosts don't clobber each other.
    let mut data: BTreeMap<String, ByteString> = api
        .get_opt(CHALLENGE_SECRET)
        .await?
        .and_then(|s| s.data)
        .unwrap_or_default();
    let hl = host.to_ascii_lowercase();
    data.insert(format!("{hl}.crt"), ByteString(cert_pem.to_vec()));
    data.insert(format!("{hl}.key"), ByteString(key_pem.to_vec()));
    apply_secret(&api, CHALLENGE_SECRET, ns, "Opaque", data).await
}

/// Remove a host's challenge cert from the shared challenge Secret.
async fn unpublish_challenge(client: &Client, ns: &str, host: &str) -> Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    let Some(mut data) = api.get_opt(CHALLENGE_SECRET).await?.and_then(|s| s.data) else {
        return Ok(());
    };
    let hl = host.to_ascii_lowercase();
    data.remove(&format!("{hl}.crt"));
    data.remove(&format!("{hl}.key"));
    apply_secret(&api, CHALLENGE_SECRET, ns, "Opaque", data).await
}

/// Write a `kubernetes.io/tls` Secret (tls.crt/tls.key) — the format the
/// controller's `load_tls_secret` reads.
async fn write_tls_secret(
    client: &Client,
    ns: &str,
    name: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    let mut data = BTreeMap::new();
    data.insert("tls.crt".to_string(), ByteString(cert_pem.to_vec()));
    data.insert("tls.key".to_string(), ByteString(key_pem.to_vec()));
    apply_secret(&api, name, ns, "kubernetes.io/tls", data).await
}

/// Server-side apply a Secret (idempotent; safe under the brief dual-leader window
/// since the field manager is fixed and issuance is idempotent).
async fn apply_secret(
    api: &Api<Secret>,
    name: &str,
    ns: &str,
    type_: &str,
    data: BTreeMap<String, ByteString>,
) -> Result<()> {
    let secret = Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        type_: Some(type_.to_string()),
        data: Some(data),
        ..Default::default()
    };
    api.patch(
        name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&secret),
    )
    .await?;
    Ok(())
}

/// Every instance: reflect the shared challenge Secret into the data plane's
/// challenge store, so any instance can serve `acme-tls/1` for a pending host.
fn spawn_challenge_reflector(client: Client, data_plane: DataPlane, ns: String) {
    tokio::spawn(async move {
        let api: Api<Secret> = Api::namespaced(client, &ns);
        let (store, writer) = reflector::store::<Secret>();
        // Watch only the single challenge Secret by name.
        let cfg = Config::default().fields(&format!("metadata.name={CHALLENGE_SECRET}"));
        let stream = watcher(api, cfg).reflect(writer).default_backoff().touched_objects();
        futures::pin_mut!(stream);
        while let Some(ev) = stream.next().await {
            match ev {
                Ok(_) => data_plane.store_challenges(build_challenge_store(&store)),
                Err(e) => tracing::warn!(error = %e, "ACME challenge watch error"),
            }
        }
    });
}

/// Build the in-memory challenge store (host → CertKey) from the challenge Secret.
fn build_challenge_store(store: &Store<Secret>) -> ChallengeStore {
    let mut out: HashMap<String, (Option<Vec<u8>>, Option<Vec<u8>>)> = HashMap::new();
    for secret in store.state() {
        let Some(data) = secret.data.as_ref() else { continue };
        for (k, v) in data {
            if let Some(host) = k.strip_suffix(".crt") {
                out.entry(host.to_string()).or_default().0 = Some(v.0.clone());
            } else if let Some(host) = k.strip_suffix(".key") {
                out.entry(host.to_string()).or_default().1 = Some(v.0.clone());
            }
        }
    }
    out.into_iter()
        .filter_map(|(host, (c, k))| {
            Some((host, CertKey { cert_pem: c?, key_pem: k? }))
        })
        .collect()
}

/// A per-directory data key inside the account Secret (so multiple ACME
/// directories — e.g. LE staging vs prod — can coexist in one Secret).
fn account_key(directory: &str) -> String {
    // A short stable hash of the directory URL → a filename-safe key.
    let mut h: u64 = 1469598103934665603; // FNV-1a
    for b in directory.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("credentials-{h:016x}.json")
}

/// Parse a PEM cert chain's leaf `notAfter` as a unix timestamp.
fn cert_not_after(pem: &[u8]) -> Option<i64> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem).ok()?;
    let cert = pem.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp())
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_is_stable_and_per_directory() {
        let a = account_key("https://acme-staging.example/dir");
        let b = account_key("https://acme-staging.example/dir");
        let c = account_key("https://acme-prod.example/dir");
        assert_eq!(a, b, "same directory → same key (stable)");
        assert_ne!(a, c, "different directory → different key");
        assert!(a.starts_with("credentials-") && a.ends_with(".json"));
    }

    #[test]
    fn cert_not_after_parses_validity() {
        // Generate a self-signed cert and confirm we read a plausible notAfter.
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["x.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem().into_bytes();
        let not_after = cert_not_after(&pem).expect("parse notAfter");
        // rcgen's default validity is in the future relative to now.
        assert!(not_after > now_unix(), "notAfter should be in the future");
    }

    #[test]
    fn cert_not_after_rejects_garbage() {
        assert!(cert_not_after(b"not a pem").is_none());
    }

    fn need(host: &str) -> CertNeed {
        CertNeed {
            directory: "https://acme.example/dir".into(),
            email: None,
            hostname: host.into(),
            secret_ns: "default".into(),
            secret_name: format!("{host}-tls"),
        }
    }

    #[test]
    fn backoff_delay_is_exponential_and_capped() {
        assert_eq!(backoff_delay(1), BACKOFF_BASE); // 5m
        assert_eq!(backoff_delay(2), BACKOFF_BASE * 2); // 10m
        assert_eq!(backoff_delay(3), BACKOFF_BASE * 4); // 20m
        assert_eq!(backoff_delay(8), BACKOFF_MAX); // saturates at the cap
        assert_eq!(backoff_delay(100), BACKOFF_MAX); // no overflow at large n
    }

    #[test]
    fn backoff_blocks_then_success_resets() {
        let mut b = Backoff::default();
        let n = need("a.example.com");
        // First attempt is always allowed.
        assert!(b.ready(&n));
        // After a failure, the host is blocked (next_attempt is in the future).
        let delay = b.record_failure(&n);
        assert_eq!(delay, BACKOFF_BASE);
        assert!(!b.ready(&n), "must back off after a failure");
        // A second failure doubles the delay.
        assert_eq!(b.record_failure(&n), BACKOFF_BASE * 2);
        // Success clears the backoff entirely.
        b.record_success(&n);
        assert!(b.ready(&n), "success must reset backoff");
    }

    #[test]
    fn backoff_is_per_host() {
        let mut b = Backoff::default();
        let (a, c) = (need("a.example.com"), need("c.example.com"));
        b.record_failure(&a);
        assert!(!b.ready(&a), "a is backed off");
        assert!(b.ready(&c), "c is independent and still ready");
    }
}
