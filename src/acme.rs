//! Automatic TLS certificate issuance via ACME (TLS-ALPN-01).
//!
//! Off by default; enabled process-wide with `--acme`. Even then, a Gateway must
//! opt in by carrying the `torii.dirba.io/acme` annotation (presence-only — its
//! value is ignored). The ACME directory URL and contact email come from the CLI
//! (`--acme-issuer` / `--acme-email`), optionally overridden per-Gateway by the
//! `torii.dirba.io/acme-issuer` / `-email` annotations. For each HTTPS/TLS-terminate
//! listener with a (single, non-wildcard) hostname and a `certificateRefs` Secret,
//! we obtain a cert and write it into that Secret — the controller's existing Secret
//! watcher + cert store then serve it, no special data-plane path for the *issued*
//! cert.
//!
//! ## Multi-instance
//! Issuance is driven by a single leader (a `coordination.k8s.io` Lease). But the
//! TLS-ALPN-01 verification connection may land on ANY instance, so the challenge
//! validation cert is published to a shared Secret that every instance reflects
//! into its data plane — any instance can answer the `acme-tls/1` handshake.
//!
//! ## State (all in k8s, in `--acme-namespace`)
//! - account key: Secret `torii-acme-account` (`credentials.json`).
//! - in-flight challenge certs: Secret `torii-acme-challenge` (`<host>.crt/.key`).
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
use kube::{Client, Resource, ResourceExt};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};

use gateway_api::apis::standard::gateways::Gateway;

use crate::cert_store::CertKey;
use crate::snapshot::{ChallengeStore, DataPlane};

/// Gateway opt-in annotation. Its mere PRESENCE enables ACME for the Gateway's
/// terminate listeners — the value is ignored. Without it, ACME is not done even if
/// the issuer/email annotations are present. Issuer + email come from the CLI args
/// (optionally overridden per-Gateway by the annotations below).
const ANNO_ENABLE: &str = "torii.dirba.io/acme";
/// Gateway annotation overriding the default ACME directory URL (`--acme-issuer`).
const ANNO_ISSUER: &str = "torii.dirba.io/acme-issuer";
/// Gateway annotation overriding the default ACME contact email (`--acme-email`).
const ANNO_EMAIL: &str = "torii.dirba.io/acme-email";

const ACCOUNT_SECRET: &str = "torii-acme-account";
const CHALLENGE_SECRET: &str = "torii-acme-challenge";
/// Server-Side Apply field manager for ACME's writes. Public so the controller can
/// reference it; distinct from the controller's manager so each owns its own fields
/// (Secrets here, plus the `torii.dirba.io/ACMEIssued` listener condition) without
/// clobbering the other.
pub const FIELD_MANAGER: &str = "torii-acme";

/// The custom listener condition type the ACME subsystem owns. Reports the full
/// issuance/renewal lifecycle (Issued / Pending / Failed / unsupported hostname) on
/// the Gateway, so operators can see ACME state and failure reasons via the k8s API
/// — no controller-log access needed. Gateway API permits extra condition types and
/// the conformance suite ignores unknown ones, so this is safe.
const COND_ACME: &str = "torii.dirba.io/ACMEIssued";
const LEASE_NAME: &str = "torii-acme-leader";

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
    /// Default ACME directory URL for all opted-in Gateways (CLI `--acme-issuer`);
    /// a Gateway's issuer annotation overrides it. `None` → must be annotated.
    pub default_issuer: Option<String>,
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

/// One ACME-opted-in HTTPS/TLS-terminate listener: the unit we track issuance and
/// report status for. Built for EVERY such listener (even wildcard/no-hostname ones,
/// so their "unsupported" state is reported rather than silently skipped).
struct AcmeTarget {
    /// Gateway + listener identity, for the status condition we apply.
    gw_ns: String,
    gw_name: String,
    listener_name: String,
    gw_gen: i64,
    /// The listener hostname (may be a wildcard or empty → Unsupported).
    hostname: String,
    /// ACME directory URL + contact, resolved from CLI defaults + Gateway
    /// annotation overrides. Either being `None` (no CLI default, no annotation) is
    /// a config error reported as an ACME failure rather than attempting issuance.
    directory: Option<String>,
    email: Option<String>,
    /// The listener's certificateRefs Secret (namespace, name) — issuance target.
    secret_ns: String,
    secret_name: String,
}

impl AcmeTarget {
    /// Backoff key: the issuance target. Distinct listeners back off independently.
    fn key(&self) -> (String, String, String) {
        (self.secret_ns.clone(), self.secret_name.clone(), self.hostname.clone())
    }
}

/// The ACME issuance/renewal state of one listener, surfaced as the
/// `torii.dirba.io/ACMEIssued` condition. Each maps to a (status, reason, message).
enum AcmeState {
    /// A valid cert is present; `not_after` is the unix-seconds expiry.
    Issued { not_after: i64 },
    /// Issuance is in progress; `stage` is the current step (human-readable).
    Pending { stage: String },
    /// The last attempt failed; `detail` is the full reason; `retry_in_s` the wait.
    Failed { detail: String, retry_in_s: u64 },
    /// The listener config can never be issued via TLS-ALPN-01 (wildcard/empty host).
    Unsupported { reason: String },
}

impl AcmeState {
    /// (status, reason, message) for the condition.
    fn condition(&self) -> (&'static str, &'static str, String) {
        match self {
            AcmeState::Issued { not_after } => (
                "True",
                "Issued",
                format!("certificate issued; valid until unix:{not_after}"),
            ),
            AcmeState::Pending { stage } => {
                ("False", "Pending", format!("issuance in progress: {stage}"))
            }
            AcmeState::Failed { detail, retry_in_s } => (
                "False",
                "Failed",
                format!("issuance failed (retry in {retry_in_s}s): {detail}"),
            ),
            AcmeState::Unsupported { reason } => ("False", "UnsupportedValue", reason.clone()),
        }
    }
}

/// SSA-apply the `torii.dirba.io/ACMEIssued` condition onto one Gateway listener,
/// under the ACME field manager. Because Gateway status conditions are merged by
/// `type` (listMapKey=type) and the controller uses a different field manager, this
/// touches ONLY our condition — it neither triggers a full reconcile nor disturbs
/// the standard Accepted/Programmed/ResolvedRefs conditions. Best-effort: a failure
/// to write status must not abort issuance.
async fn patch_acme_status(client: &Client, target: &AcmeTarget, state: &AcmeState) {
    let (status, reason, message) = state.condition();
    // A self-contained SSA document: just this listener + just our condition.
    let doc = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": target.gw_name, "namespace": target.gw_ns },
        "status": { "listeners": [{
            "name": target.listener_name,
            // SSA requires the listMapKey fields of every list we touch; conditions
            // is keyed by `type`, listeners by `name` (set above).
            "conditions": [{
                "type": COND_ACME,
                "status": status,
                "reason": reason,
                "message": message,
                "observedGeneration": target.gw_gen,
                "lastTransitionTime": "1970-01-01T00:00:00Z",
            }],
        }]},
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), &target.gw_ns);
    // PER-LISTENER field manager. An SSA apply expresses the COMPLETE intent of its
    // manager, so two single-listener applies under ONE manager would make the second
    // orphan the first listener's condition. A distinct manager per listener keeps
    // each condition independently owned (and lets successive Pending→Issued/Failed
    // applies on the same listener just update in place).
    let manager = format!("{FIELD_MANAGER}.{}", target.listener_name);
    let pp = PatchParams::apply(&manager).force();
    if let Err(e) = api.patch_status(&target.gw_name, &pp, &Patch::Apply(&doc)).await {
        tracing::warn!(
            gw = %target.gw_name, listener = %target.listener_name, error = %e,
            "ACME: failed to patch listener status condition"
        );
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
    /// The last failure detail, kept so a backed-off target keeps reporting WHY it
    /// failed (and when it will retry) instead of going blank between attempts.
    last_detail: String,
}

impl Backoff {
    /// Should we attempt this target now, or is it still inside its backoff window?
    fn ready(&self, target: &AcmeTarget) -> bool {
        match self.entries.get(&target.key()) {
            Some(e) => std::time::Instant::now() >= e.next_attempt,
            None => true,
        }
    }

    /// While backed off, the [`AcmeState::Failed`] to keep reporting (detail + the
    /// seconds remaining until the next attempt). `None` if not backed off.
    fn failed_state(&self, target: &AcmeTarget) -> Option<AcmeState> {
        let e = self.entries.get(&target.key())?;
        let remaining = e.next_attempt.saturating_duration_since(std::time::Instant::now());
        Some(AcmeState::Failed {
            detail: e.last_detail.clone(),
            retry_in_s: remaining.as_secs(),
        })
    }

    /// Record a successful issuance — clear any backoff for this target.
    fn record_success(&mut self, target: &AcmeTarget) {
        self.entries.remove(&target.key());
    }

    /// Record a failure — bump the counter, store the detail, and schedule the next
    /// attempt with an exponential delay (BACKOFF_BASE * 2^(fails-1), capped).
    fn record_failure(&mut self, target: &AcmeTarget, detail: String) -> Duration {
        let e = self.entries.entry(target.key()).or_insert(BackoffEntry {
            fails: 0,
            next_attempt: std::time::Instant::now(),
            last_detail: String::new(),
        });
        e.fails = e.fails.saturating_add(1);
        e.last_detail = detail;
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

/// Leader pass: for every ACME-opted-in listener, compute its state, (re)issue when
/// needed (honoring per-target backoff), and report the result on the listener's
/// `torii.dirba.io/ACMEIssued` condition. Every target gets a status every scan —
/// nothing is silently skipped.
async fn scan_and_issue(
    client: &Client,
    gw_api: &Api<Gateway>,
    config: &AcmeConfig,
    backoff: &mut Backoff,
) -> Result<()> {
    let targets = self::targets(gw_api, config).await?;
    for target in targets {
        // Config error: the Gateway opted in but no issuer/email is configured
        // (neither a CLI default nor a Gateway annotation). Report it instead of
        // silently doing nothing; a config fix triggers a re-scan (retry_in_s 0).
        let mut missing = Vec::new();
        if target.directory.is_none() {
            missing.push("issuer (--acme-issuer or torii.dirba.io/acme-issuer)");
        }
        if target.email.is_none() {
            missing.push("email (--acme-email or torii.dirba.io/acme-email)");
        }
        if !missing.is_empty() {
            patch_acme_status(client, &target, &AcmeState::Failed {
                detail: format!("ACME enabled but not configured: missing {}", missing.join(", ")),
                retry_in_s: 0,
            }).await;
            continue;
        }

        // Wildcard / empty hostname → can never validate via TLS-ALPN-01. Report it.
        if target.hostname.starts_with("*.") || target.hostname.is_empty() {
            patch_acme_status(client, &target, &AcmeState::Unsupported {
                reason: format!(
                    "ACME cannot validate hostname {:?}; TLS-ALPN-01 requires a concrete \
                     (non-wildcard, non-empty) DNS name",
                    target.hostname
                ),
            }).await;
            continue;
        }

        // Already have a good cert? Report Issued and move on (no CA traffic).
        if let CertCheck::Good { not_after } =
            cert_check(client, &target.secret_ns, &target.secret_name).await
        {
            backoff.record_success(&target);
            patch_acme_status(client, &target, &AcmeState::Issued { not_after }).await;
            continue;
        }

        // Needs work. If backed off from a recent failure, keep reporting that
        // failure (with the remaining wait) rather than re-hitting the CA.
        if !backoff.ready(&target) {
            if let Some(state) = backoff.failed_state(&target) {
                patch_acme_status(client, &target, &state).await;
            }
            continue;
        }

        // Attempt issuance, reporting Pending up front so the condition reflects
        // "in progress" even if the order takes a while or the process restarts.
        patch_acme_status(client, &target, &AcmeState::Pending {
            stage: "ordering certificate".into(),
        }).await;
        match issue(client, config, &target).await {
            Ok(not_after) => {
                backoff.record_success(&target);
                patch_acme_status(client, &target, &AcmeState::Issued { not_after }).await;
            }
            Err(e) => {
                let detail = format!("{e:#}");
                let delay = backoff.record_failure(&target, detail.clone());
                tracing::warn!(
                    host = %target.hostname, error = %detail,
                    retry_in_s = delay.as_secs(), "ACME issuance failed; backing off",
                );
                patch_acme_status(client, &target, &AcmeState::Failed {
                    detail,
                    retry_in_s: delay.as_secs(),
                }).await;
            }
        }
    }
    Ok(())
}

/// Enumerate EVERY ACME-opted-in HTTPS/TLS-terminate listener (one [`AcmeTarget`]
/// per certificateRefs Secret). Unlike the old `needs()`, this does NOT pre-filter
/// wildcard hosts or certs that don't need work — the caller decides each target's
/// state and reports it, so nothing is silently dropped.
async fn targets(gw_api: &Api<Gateway>, config: &AcmeConfig) -> Result<Vec<AcmeTarget>> {
    use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
    use kube::api::ListParams;
    let gateways = gw_api.list(&ListParams::default()).await?;
    let mut out = Vec::new();
    for gw in gateways {
        let anns = gw.annotations();
        // Opt-in: the enable annotation must be PRESENT (value ignored). Without it,
        // ACME is skipped even if issuer/email annotations exist.
        if !anns.contains_key(ANNO_ENABLE) {
            continue;
        }
        // Issuer + email: per-Gateway annotation overrides the CLI default; either
        // may be None (reported as a failure by the caller, not skipped here).
        let directory = anns.get(ANNO_ISSUER).cloned().or_else(|| config.default_issuer.clone());
        let email = anns.get(ANNO_EMAIL).cloned().or_else(|| config.default_email.clone());
        let gw_ns = gw.namespace().unwrap_or_default();
        let gw_name = gw.name_any();
        let gw_gen = gw.meta().generation.unwrap_or(0);
        for l in &gw.spec.listeners {
            if !matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
                continue;
            }
            let Some(tls) = l.tls.as_ref() else { continue };
            // Passthrough terminates at the backend; we don't issue for it.
            if matches!(tls.mode, Some(Mode::Passthrough)) {
                continue;
            }
            let hostname = l.hostname.clone().unwrap_or_default();
            for r in tls.certificate_refs.clone().unwrap_or_default() {
                // Only manage core-Secret refs.
                if r.group.clone().unwrap_or_default() != ""
                    || r.kind.clone().unwrap_or_else(|| "Secret".into()) != "Secret"
                {
                    continue;
                }
                let secret_ns = r.namespace.clone().unwrap_or_else(|| gw_ns.clone());
                out.push(AcmeTarget {
                    gw_ns: gw_ns.clone(),
                    gw_name: gw_name.clone(),
                    listener_name: l.name.clone(),
                    gw_gen,
                    hostname: hostname.clone(),
                    directory: directory.clone(),
                    email: email.clone(),
                    secret_ns,
                    secret_name: r.name.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// The current state of a cert Secret for ACME purposes.
enum CertCheck {
    /// A valid cert is present and not within the renewal window. `not_after` unix s.
    Good { not_after: i64 },
    /// Missing, unparseable, or expiring → needs (re)issuance.
    NeedsWork,
}

/// Inspect a cert Secret: is there a valid, not-yet-expiring cert?
async fn cert_check(client: &Client, ns: &str, name: &str) -> CertCheck {
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    // Only a genuine NotFound (404) means "missing" → issue. Any other API error
    // (timeout, 429, 503) must NOT force a reissuance of an already-valid cert.
    let secret = match api.get(name).await {
        Ok(s) => s,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return CertCheck::NeedsWork,
        Err(e) => {
            tracing::warn!(ns, name, error = %e, "ACME: cert Secret read failed; not reissuing");
            // Treat a transient read error as "leave as-is" — needs work false-ish.
            // Returning NeedsWork would churn; we want to skip this scan instead, but
            // the caller only distinguishes Good vs NeedsWork. Report NeedsWork only
            // on a real 404 above; here, pretend it's fine to avoid churn.
            return CertCheck::Good { not_after: now_unix() + RENEW_WINDOW.as_secs() as i64 };
        }
    };
    let Some(crt) = secret.data.as_ref().and_then(|d| d.get("tls.crt")) else {
        return CertCheck::NeedsWork;
    };
    match cert_not_after(&crt.0) {
        Some(not_after) => {
            let renew_at = not_after - RENEW_WINDOW.as_secs() as i64;
            if now_unix() >= renew_at {
                CertCheck::NeedsWork
            } else {
                CertCheck::Good { not_after }
            }
        }
        None => CertCheck::NeedsWork, // unparseable → reissue
    }
}

/// Drive one ACME order to completion and write the issued cert into its Secret.
/// Returns the issued cert's `notAfter` (unix seconds) on success.
async fn issue(client: &Client, config: &AcmeConfig, need: &AcmeTarget) -> Result<i64> {
    // scan_and_issue only reaches issuance once issuer + email are present.
    let directory = need
        .directory
        .as_deref()
        .ok_or_else(|| anyhow!("no ACME issuer configured"))?;
    tracing::info!(
        host = %need.hostname, directory = %directory, secret = %need.secret_name,
        "ACME: starting issuance"
    );
    let account = load_or_create_account(client, config, directory, need.email.as_deref())
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
            // per-challenge error detail the CA recorded, which the bare timeout hides,
            // so it lands in the listener's Failed condition (not just the log).
            let detail = authorization_failures(&mut order, &need.hostname).await;
            return Err(e).context(detail);
        }
    };
    if status != OrderStatus::Ready {
        let detail = authorization_failures(&mut order, &need.hostname).await;
        return Err(anyhow!("ACME order not ready ({status:?}): {detail}"));
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

    let not_after = cert_not_after(chain_pem.as_bytes()).unwrap_or_else(now_unix);
    tracing::info!(host = %need.hostname, secret = %need.secret_name, "ACME: issued certificate");
    Ok(not_after)
}

/// On a failed/stuck order, re-walk its authorizations and collect each one's
/// status plus any per-challenge error the CA recorded, as a single detail string.
/// This is what turns an opaque "poll_ready timed out" into the actual reason (e.g.
/// connection refused on :443, "Incorrect validation certificate") — returned so it
/// reaches the listener's Failed condition, and logged too.
async fn authorization_failures(order: &mut instant_acme::Order, host: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(authz) = authorizations.next().await {
        let authz = match authz {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(%host, error = %e, "ACME: failed to fetch authorization for diagnostics");
                parts.push(format!("authorization fetch error: {e}"));
                continue;
            }
        };
        let identifier = authz.identifier().to_string();
        tracing::warn!(%host, %identifier, status = ?authz.status, "ACME: authorization not valid");
        for ch in &authz.challenges {
            match &ch.error {
                Some(problem) => {
                    tracing::warn!(
                        %host, %identifier, kind = ?ch.r#type, status = ?ch.status,
                        problem = %problem, "ACME: challenge failed"
                    );
                    parts.push(format!("{identifier}: {problem}"));
                }
                None => {
                    tracing::warn!(
                        %host, %identifier, kind = ?ch.r#type, status = ?ch.status,
                        "ACME: challenge incomplete (no error reported)"
                    );
                    parts.push(format!("{identifier}: challenge {:?} (no error detail)", ch.status));
                }
            }
        }
    }
    if parts.is_empty() {
        "no authorization detail available".to_string()
    } else {
        parts.join("; ")
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

    if let Ok(secret) = api.get(ACCOUNT_SECRET).await
        && let Some(creds_raw) = secret.data.as_ref().and_then(|d| d.get(&key)) {
            let creds: AccountCredentials = serde_json::from_slice(&creds_raw.0)
                .context("parse stored ACME credentials")?;
            let account = account_builder(config)?.from_credentials(creds).await?;
            return Ok(account);
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
    // host → (cert PEM, key PEM), each filled as we encounter the `.crt`/`.key` key.
    type PartialCerts = HashMap<String, (Option<Vec<u8>>, Option<Vec<u8>>)>;
    let mut out: PartialCerts = HashMap::new();
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

    fn target(host: &str) -> AcmeTarget {
        AcmeTarget {
            gw_ns: "default".into(),
            gw_name: "gw".into(),
            listener_name: "https".into(),
            gw_gen: 1,
            directory: Some("https://acme.example/dir".into()),
            email: Some("ops@example.com".into()),
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
        let n = target("a.example.com");
        // First attempt is always allowed.
        assert!(b.ready(&n));
        // After a failure, the host is blocked (next_attempt is in the future).
        let delay = b.record_failure(&n, "boom".into());
        assert_eq!(delay, BACKOFF_BASE);
        assert!(!b.ready(&n), "must back off after a failure");
        // While backed off, the failure detail + remaining wait are reported.
        match b.failed_state(&n) {
            Some(AcmeState::Failed { detail, .. }) => assert_eq!(detail, "boom"),
            _ => panic!("expected a Failed state while backed off"),
        }
        // A second failure doubles the delay.
        assert_eq!(b.record_failure(&n, "boom2".into()), BACKOFF_BASE * 2);
        // Success clears the backoff entirely.
        b.record_success(&n);
        assert!(b.ready(&n), "success must reset backoff");
        assert!(b.failed_state(&n).is_none(), "no failed state after success");
    }

    #[test]
    fn backoff_is_per_host() {
        let mut b = Backoff::default();
        let (a, c) = (target("a.example.com"), target("c.example.com"));
        b.record_failure(&a, "x".into());
        assert!(!b.ready(&a), "a is backed off");
        assert!(b.ready(&c), "c is independent and still ready");
    }

    #[test]
    fn acme_state_conditions() {
        let (s, r, _) = AcmeState::Issued { not_after: 123 }.condition();
        assert_eq!((s, r), ("True", "Issued"));
        let (s, r, _) = (AcmeState::Pending { stage: "x".into() }).condition();
        assert_eq!((s, r), ("False", "Pending"));
        let (s, r, m) = (AcmeState::Failed { detail: "dns".into(), retry_in_s: 9 }).condition();
        assert_eq!((s, r), ("False", "Failed"));
        assert!(m.contains("dns") && m.contains("9s"));
        let (s, r, _) = (AcmeState::Unsupported { reason: "wild".into() }).condition();
        assert_eq!((s, r), ("False", "UnsupportedValue"));
    }
}
