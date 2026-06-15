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

/// Gateway annotation naming the ACME directory URL (opt-in trigger).
const ANNO_ISSUER: &str = "lolgateway.dev/acme-issuer";
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

/// Runtime config for the ACME subsystem.
#[derive(Clone)]
pub struct AcmeConfig {
    pub namespace: String,
    pub default_email: Option<String>,
    /// A stable identity for this instance (Lease holder id). Pod name or a uuid.
    pub holder_id: String,
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

    loop {
        // Renew/acquire the lease on a tight cadence so leadership is fresh.
        let is_leader = match lease.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => true,
            Ok(LeaseLockResult::NotAcquired(_)) => false,
            Err(e) => {
                tracing::warn!(error = %e, "ACME lease acquire/renew failed");
                false
            }
        };

        if is_leader && last_scan.elapsed() >= SCAN_INTERVAL {
            last_scan = std::time::Instant::now();
            if let Err(e) = scan_and_issue(&client, &gw_api, &config).await {
                tracing::warn!(error = %e, "ACME scan/issue failed");
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

/// Leader pass: find listeners needing a cert and issue/renew each.
async fn scan_and_issue(
    client: &Client,
    gw_api: &Api<Gateway>,
    config: &AcmeConfig,
) -> Result<()> {
    let needs = self::needs(client, gw_api, config).await?;
    if needs.is_empty() {
        return Ok(());
    }
    tracing::info!(count = needs.len(), "ACME: certs to issue/renew");
    for need in needs {
        if let Err(e) = issue(client, config, &need).await {
            tracing::warn!(host = %need.hostname, error = %e, "ACME issuance failed");
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
    let account = load_or_create_account(client, config, &need.directory, need.email.as_deref())
        .await
        .context("ACME account")?;

    let ids = [Identifier::Dns(need.hostname.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .context("new_order")?;

    // Walk authorizations; for each, publish a TLS-ALPN-01 challenge cert and arm it.
    let mut authorizations = order.authorizations();
    while let Some(authz) = authorizations.next().await {
        let mut authz = authz?;
        // Skip already-valid authorizations (e.g. reused account).
        if matches!(authz.status, instant_acme::AuthorizationStatus::Valid) {
            continue;
        }
        let identifier = authz.identifier().to_string();
        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow!("ACME directory offers no tls-alpn-01 challenge"))?;
        let digest = challenge.key_authorization().digest();
        let (cert_pem, key_pem) = crate::acme_cert::alpn_cert(&identifier, digest.as_ref())
            .context("build challenge cert")?;
        publish_challenge(client, &config.namespace, &identifier, &cert_pem, &key_pem).await?;
        // Give the challenge Secret time to reach followers (validator may hit any).
        tokio::time::sleep(CHALLENGE_SETTLE).await;
        challenge.set_ready().await.context("set_ready")?;
    }

    // Wait for the order to be ready, finalize with our own key, fetch the cert.
    let status = order.poll_ready(&RetryPolicy::default()).await.context("poll_ready")?;
    if status != OrderStatus::Ready {
        return Err(anyhow!("ACME order not ready: {status:?}"));
    }
    let key_pair = rcgen::KeyPair::generate().context("gen cert key")?;
    let csr_der = crate::acme_cert::csr_der(&key_pair, &need.hostname).context("build CSR")?;
    order.finalize_csr(&csr_der).await.context("finalize_csr")?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("poll_certificate")?;

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
            let account = Account::builder()?.from_credentials(creds).await?;
            return Ok(account);
        }
    }

    let contact: Vec<String> = email.map(|e| format!("mailto:{e}")).into_iter().collect();
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
    let (account, creds) = Account::builder()?
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
}
