//! Control plane: watch Gateway API + core resources, recompute desired state,
//! write status back, and publish the data-plane [`RouteTable`].
//!
//! Level-triggered and idempotent: any watched-object change triggers a full
//! recompute of the entire world from cached state. We never accumulate deltas.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use gateway_api::apis::standard::backendtlspolicies::{
    BackendTLSPolicy, BackendTlsPolicyStatus, BackendTlsPolicyStatusAncestors,
    BackendTlsPolicyStatusAncestorsAncestorRef,
};
use gateway_api::apis::standard::gatewayclasses::{
    GatewayClass, GatewayClassStatus, GatewayClassStatusSupportedFeatures,
};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayStatus, GatewayStatusAddresses, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteStatus, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
use gateway_api::apis::standard::referencegrants::ReferenceGrant;
use gateway_api::apis::standard::tlsroutes::{
    TLSRoute, TlsRouteStatus, TlsRouteStatusParents, TlsRouteStatusParentsParentRef,
};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Patch, PatchParams};
use kube::runtime::WatchStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher::{Config, watcher};
use kube::{Api, Client, Resource, ResourceExt};

use crate::cert_store::{CertKey, CertStore};
use crate::route_table::{
    Backend, Endpoint, Filters, HeaderMatch, HeaderMods, HeaderValueMatch, PathMatch, PathRewrite, QueryMatch,
    Redirect, RouteEntry, RouteMatch, RouteTable, UrlRewrite,
};
use crate::snapshot::{DataPlane, Snapshot};
use crate::tls_table::{TlsAction, TlsBackend, TlsBackends, TlsTable};

/// Our controller name. Must be DOMAIN/PATH and match GatewayClass.spec.controllerName.
pub const CONTROLLER_NAME: &str = "torii.dirba.io/controller";

/// Server-Side Apply field manager for the controller's status writes. Distinct
/// from the ACME subsystem's manager ([`crate::acme::FIELD_MANAGER`]) so the two
/// can own different conditions on the same object without clobbering each other.
const FIELD_MANAGER: &str = "torii-controller";

/// Features we report in GatewayClass.status.supportedFeatures. The conformance
/// suite uses this to decide which tests apply when running a whole profile
/// (without an explicit --supported-features flag). Grow this as features land.
const SUPPORTED_FEATURES: &[&str] = &[
    // Core.
    "Gateway",
    "HTTPRoute",
    "ReferenceGrant",
    // Gateway extended.
    "GatewayPort8080",
    "GatewayHTTPListenerIsolation",
    // HTTPRoute matching.
    "HTTPRouteMethodMatching",
    "HTTPRouteQueryParamMatching",
    "HTTPRouteNamedRouteRule",
    // HTTPRoute header modification.
    "HTTPRouteResponseHeaderModification",
    "HTTPRouteBackendRequestHeaderModification",
    // HTTPRoute redirect.
    "HTTPRoutePortRedirect",
    "HTTPRouteSchemeRedirect",
    "HTTPRoutePathRedirect",
    "HTTPRoute303RedirectStatusCode",
    "HTTPRoute307RedirectStatusCode",
    "HTTPRoute308RedirectStatusCode",
    // HTTPRoute rewrite.
    "HTTPRouteHostRewrite",
    "HTTPRoutePathRewrite",
    // HTTPRoute timeout.
    "HTTPRouteRequestTimeout",
    "HTTPRouteBackendTimeout",
    // HTTPRoute misc.
    "HTTPRouteParentRefPort",
    "HTTPRouteBackendProtocolWebSocket",
    "HTTPRouteCORS",
    // TLS.
    "BackendTLSPolicy",
    // TLSRoute: passthrough (core) + terminate (extended). We do NOT claim
    // TLSRouteModeMixed — two TLS modes on one port get Accepted=False/ProtocolConflict.
    "TLSRoute",
    "TLSRouteModeTerminate",
];

/// The address we advertise in Gateway.status.addresses — where our proxy listens,
/// reachable by the conformance suite running on the host.
pub struct ControllerConfig {
    pub advertise_address: String,
    /// Hand-off to the ACME subsystem: the desired issuance targets, republished after
    /// each reconcile. `None` when `--acme` is off — no targets are computed at all.
    pub acme_feed: Option<crate::acme::AcmeFeed>,
    /// Default ACME directory URL / contact, from `--acme-issuer` / `--acme-email`. A
    /// Gateway's `torii.dirba.io/acme-issuer` / `-email` annotation overrides each.
    pub acme_default_issuer: Option<String>,
    pub acme_default_email: Option<String>,
}

/// Cached stores for every resource we reconcile from.
struct Stores {
    gateway_classes: Store<GatewayClass>,
    gateways: Store<Gateway>,
    routes: Store<HTTPRoute>,
    tls_routes: Store<TLSRoute>,
    services: Store<Service>,
    endpoint_slices: Store<EndpointSlice>,
    reference_grants: Store<ReferenceGrant>,
    namespaces: Store<Namespace>,
    secrets: Store<Secret>,
    config_maps: Store<ConfigMap>,
    backend_tls_policies: Store<BackendTLSPolicy>,
}

/// Run the control plane forever: start watchers, and on any change recompute.
pub async fn run(client: Client, data_plane: DataPlane, config: ControllerConfig) -> Result<()> {
    // A change signal: every watcher event pokes this channel; a single consumer
    // debounces and runs a full reconcile.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

    // For each watched resource: create a reflector store, spawn a watcher that
    // feeds it and pokes `tx` on every event, and yield the store. One macro
    // expansion per resource keeps the wiring in one place. The `ready` future
    // waits for every store's first list before the initial reconcile.
    let mut ready: Vec<futures::future::BoxFuture<'static, ()>> = Vec::new();
    macro_rules! watch {
        ($ty:ty, $kind:literal) => {{
            let (store, writer) = reflector::store::<$ty>();
            let api: Api<$ty> = Api::all(client.clone());
            let tx = tx.clone();
            let stream = watcher(api, Config::default())
                .reflect(writer)
                .default_backoff()
                .touched_objects();
            tokio::spawn(async move {
                futures::pin_mut!(stream);
                while let Some(ev) = stream.next().await {
                    match ev {
                        // Non-blocking poke; a pending reconcile already covers us.
                        Ok(_) => { let _ = tx.try_send(()); }
                        Err(e) => tracing::warn!(kind = $kind, error = %e, "watch error"),
                    }
                }
            });
            let r = store.clone();
            ready.push(Box::pin(async move { let _ = r.wait_until_ready().await; }));
            store
        }};
    }

    let stores = Arc::new(Stores {
        gateway_classes: watch!(GatewayClass, "GatewayClass"),
        gateways: watch!(Gateway, "Gateway"),
        routes: watch!(HTTPRoute, "HTTPRoute"),
        tls_routes: watch!(TLSRoute, "TLSRoute"),
        services: watch!(Service, "Service"),
        endpoint_slices: watch!(EndpointSlice, "EndpointSlice"),
        reference_grants: watch!(ReferenceGrant, "ReferenceGrant"),
        namespaces: watch!(Namespace, "Namespace"),
        secrets: watch!(Secret, "Secret"),
        config_maps: watch!(ConfigMap, "ConfigMap"),
        backend_tls_policies: watch!(BackendTLSPolicy, "BackendTLSPolicy"),
    });

    // Wait for all caches to populate before the first reconcile.
    tokio::spawn(async move {
        futures::future::join_all(ready).await;
    });

    let gc_api: Api<GatewayClass> = Api::all(client.clone());
    tracing::info!(controller = CONTROLLER_NAME, "control plane started");

    let ctx = ReconcileCtx {
        client,
        gc_api,
        data_plane,
        config,
        stores,
    };

    // Reconcile loop: debounce bursts of events, then recompute everything.
    //
    // NO periodic resync — purely event-driven. Every watcher updates its
    // reflector Store *before* poking `rx` (`.reflect()` applies the change as
    // the stream item is produced, the poke fires after). So: if an event's
    // Store write lands before a reconcile reads that object, this pass sees it;
    // if it lands after, the paired poke is still queued in `rx` and triggers an
    // immediate re-reconcile that does see it. No wake-up can be lost, so no
    // timer is needed to "heal" convergence. If something fails to converge,
    // that is a real bug — fix the bug, never paper over it with a resync.
    loop {
        // Block until at least one event arrives.
        let _ = rx.recv().await;
        // Coalesce a short burst, then drain so events that arrive *after* this
        // point (e.g. during the reconcile) trigger a fresh pass next iteration.
        tokio::time::sleep(Duration::from_millis(100)).await;
        while rx.try_recv().is_ok() {}

        if let Err(e) = ctx.reconcile_all().await {
            tracing::error!(error = %e, "reconcile failed");
        }
    }
}

struct ReconcileCtx {
    client: Client,
    // GatewayClass is cluster-scoped; Gateway/HTTPRoute status use namespaced
    // APIs built inline per object.
    gc_api: Api<GatewayClass>,
    data_plane: DataPlane,
    config: ControllerConfig,
    stores: Arc<Stores>,
}

// ── Internal reconcile model ────────────────────────────────────────────────
//
// Validity is carried as plain DATA, computed once from spec. Conditions (status)
// are derived from this data — we never read a condition back to compute another.
// Each field is read + validated + USED in one place, which also produces the
// status outcome (no separate validate-for-status vs validate-for-use path).

/// The computed outcome for a single Gateway listener: validity as data, the
/// resolved supported kinds, attached-route count (filled during route
/// processing), and the validated+loaded certificate (the single TLS path —
/// both the listener status and the CertStore come from `resolved_cert`).
struct ListenerOutcome {
    name: String,
    /// Whether the listener's protocol is one we understand (HTTP/HTTPS/TLS).
    /// Drives the listener `Accepted` condition.
    protocol_supported: bool,
    /// A requested allowedRoutes.kind invalid for the protocol → InvalidRouteKinds.
    invalid_kind: bool,
    /// HTTPS/TLS cert-ref failure reason, or None if it resolved (or N/A).
    tls_failure: Option<&'static str>,
    supported_kinds: Vec<&'static str>,
    /// The validated cert for this listener, keyed by listener hostname ("" =
    /// default). Some only when the cert ref resolved AND parsed. Feeds CertStore.
    resolved_cert: Option<(String, CertKey)>,
    /// This listener's port (for grouping listeners that share a port).
    port: u16,
    /// For a `protocol: TLS` listener, its TLS mode; None for non-TLS protocols.
    tls_mode: Option<TlsListenerMode>,
    /// True when this listener shares its port with another TLS listener of a
    /// *different* mode (Terminate vs Passthrough) and we don't support mixed
    /// termination → Accepted=False/ProtocolConflict. Computed across the port.
    protocol_conflict: bool,
}

/// A `protocol: TLS` listener's mode, which decides the TLSRoute data path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TlsListenerMode {
    /// TLS passthrough — pipe encrypted bytes to the backend.
    Passthrough,
    /// TLS terminate — terminate here, pipe cleartext to the backend.
    Terminate,
}

/// The per-Gateway compute model: usability + per-listener outcomes. Holds the
/// `Arc<Gateway>` so route processing can compute attachment against it.
struct GatewayModel {
    gw: Arc<Gateway>,
    generation: i64,
    /// False when the Gateway is rejected (invalid parametersRef) — it must not
    /// serve traffic, and routes must not claim it as a parent.
    usable: bool,
    invalid_parameters: bool,
    listeners: Vec<ListenerOutcome>,
}

/// The result of validating one BackendTLSPolicy's CA bundle. Distinguishes the
/// two failure reasons the conformance suite checks.
enum CaResult {
    /// Valid CA PEM (empty = wellKnownCACertificates=System → system roots).
    Valid(Vec<u8>),
    /// A CACertificateRef has a non-ConfigMap group/kind → ResolvedRefs/InvalidKind.
    InvalidKind,
    /// Missing / wrong-key / unparseable CA, or no CA at all →
    /// ResolvedRefs/InvalidCACertificateRef.
    InvalidRef,
}

/// The status a BackendTLSPolicy should report (drives its Accepted + ResolvedRefs).
enum PolicyStatus {
    /// Accepted=True, ResolvedRefs=True.
    Accepted,
    /// Lost a conflict for a target it would otherwise win → Accepted=False/Conflicted
    /// (refs are valid, so ResolvedRefs stays True).
    Conflicted,
    /// Accepted=False/NoValidCACertificate, ResolvedRefs=False/InvalidKind.
    InvalidKind,
    /// Accepted=False/NoValidCACertificate, ResolvedRefs=False/InvalidCACertificateRef.
    InvalidCaRef,
}

/// Per-policy status outcome (status side). The usable artifact (re-encrypt or
/// "invalid → 5xx") lives in the [`UpstreamTlsMap`], keyed by target Service.
struct PolicyOutcome {
    status: PolicyStatus,
    /// Human-readable detail for a False condition (empty when Accepted).
    message: String,
}

/// (service-namespace, service-name, service-port) → backend TLS mode for the data
/// plane. Keyed by Service PORT (not just Service) because a BackendTLSPolicy's
/// `sectionName` targets one Service port — two policies on the same Service but
/// different ports both apply, each to its own port. A policy with no sectionName
/// covers every port of the Service. Built once (conflict tiebreak applied) so
/// route resolution and policy status agree. Only `ReEncrypt`/`Invalid` are stored
/// (no policy → absent → the route defaults the endpoint to Plaintext).
type UpstreamTlsMap = std::collections::HashMap<(String, String, u16), crate::route_table::BackendTls>;

/// Which API kind a deferred status patch targets (for building the right `Api<K>`).
enum PatchTarget {
    GatewayClass,
    Gateway,
    HttpRoute,
    TlsRoute,
    BackendTlsPolicy,
}

/// A status write deferred to the end of the pass. All fields owned, so the flush
/// phase borrows nothing from the compute phase.
struct StatusPatch {
    target: PatchTarget,
    ns: Option<String>,
    name: String,
    json: serde_json::Value,
}

impl ReconcileCtx {
    /// Full level-triggered recompute, in ONE pass:
    ///   stage 1 — per-Gateway model (validity as data) + CertStore,
    ///   stage 2 — policy CA artifacts, then routes (RouteTable + attach counts),
    ///   stage 3 — derive Gateway/Policy/Class status from the data,
    /// then publish the data plane and flush all status writes concurrently.
    /// Every condition is derived from spec-computed data — never from another
    /// condition — so the pass converges without any resync.
    async fn reconcile_all(&self) -> Result<()> {
        let mut patches: Vec<StatusPatch> = Vec::new();

        // GatewayClasses we own → Accepted=True (+ supportedFeatures).
        let owned_classes: Vec<Arc<GatewayClass>> = self
            .stores
            .gateway_classes
            .state()
            .into_iter()
            .filter(|gc| gc.spec.controller_name == CONTROLLER_NAME)
            .collect();
        let owned_class_names: Vec<String> = owned_classes.iter().map(|gc| gc.name_any()).collect();
        for gc in &owned_classes {
            patches.push(self.gatewayclass_patch(gc));
        }

        // Gateways whose class we own.
        let gateways: Vec<Arc<Gateway>> = self
            .stores
            .gateways
            .state()
            .into_iter()
            .filter(|gw| owned_class_names.contains(&gw.spec.gateway_class_name))
            .collect();

        // ── Stage 1: per-Gateway model + CertStore (single TLS validate path) ──
        let mut cert_store = CertStore::default();
        let mut models: Vec<GatewayModel> = Vec::with_capacity(gateways.len());
        for gw in &gateways {
            let model = self.build_gateway_model(gw);
            // Only a usable Gateway contributes certs to the data plane.
            if model.usable {
                for l in &model.listeners {
                    if let Some((host, ck)) = &l.resolved_cert {
                        cert_store.insert(host.clone(), ck.clone());
                    }
                }
            }
            models.push(model);
        }

        // ── Stage 2a: validate each policy's CA once → artifacts + status ──
        let routes: Vec<Arc<HTTPRoute>> = self.stores.routes.state();
        let (upstream_tls, policy_outcomes) = self.build_policy_artifacts();

        // ── Stage 2b: routes → RouteTable, parent status, attachment counts ──
        // Attachment is computed ONCE per (route, gateway, parentRef) and feeds
        // both the data plane and the per-listener attachedRoutes counts.
        let usable_gateways: Vec<Arc<Gateway>> = models.iter().filter(|m| m.usable).map(|m| m.gw.clone()).collect();
        let mut route_table = RouteTable::default();
        let mut tls_table = crate::tls_table::TlsTable::default();
        // (gw_ns, gw_name) → (listener_name → count).
        let mut attach_counts: BTreeMap<(String, String), BTreeMap<String, i32>> = BTreeMap::new();
        for route in &routes {
            if let Some(patch) = self.process_route(
                route,
                &usable_gateways,
                &upstream_tls,
                &mut route_table,
                &mut attach_counts,
            ) {
                patches.push(patch);
            }
        }

        // ── Stage 2c: TLSRoutes → TlsTable (SNI dispatch), parent status, counts.
        // Mirrors HTTPRoute processing but matches on SNI only and produces an L4
        // (passthrough / terminate-then-TCP) data path, not HTTP entries.
        let tls_routes: Vec<Arc<TLSRoute>> = self.stores.tls_routes.state();
        for route in &tls_routes {
            if let Some(patch) = self.process_tls_route(route, &models, &mut tls_table, &mut attach_counts) {
                patches.push(patch);
            }
        }

        // ── Stage 3: derive Gateway + Policy status from the computed data ──
        for model in &models {
            patches.push(self.gateway_patch(model, &attach_counts));
        }
        // Policy ancestors are only usable Gateways (a rejected Gateway isn't an
        // ancestor), matching the route-attachment gating above.
        patches.extend(self.policy_patches(&usable_gateways, &routes, &policy_outcomes));

        // ── Publish the data plane FIRST (convergence shouldn't wait on the API
        //    server), then flush all status writes concurrently. Route table and
        //    cert store swap together atomically — readers never see a torn state. ──
        route_table.sort();
        tracing::debug!(entries = route_table.entries.len(), "publishing snapshot");
        self.data_plane.store(Snapshot {
            routes: route_table,
            certs: cert_store,
            tls: tls_table,
        });

        // Compute the ACME issuance targets from the SAME data, but publish them AFTER
        // the status flush below — so the ACME leader only ever sees a target once this
        // listener's status (incl. attachedRoutes) is written, and its condition patch
        // can't race the controller. Cheap when --acme is off (feed is None).
        let acme_targets = self
            .config
            .acme_feed
            .as_ref()
            .map(|_| self.acme_targets(&models, &attach_counts));

        let flushed = self.flush_status(patches).await;

        if let (Some(feed), Some(targets)) = (&self.config.acme_feed, acme_targets) {
            feed.publish(targets);
        }
        flushed
    }

    /// Build the desired ACME issuance-target set from the reconcile's per-Gateway
    /// models: every ACME-opted-in (`torii.dirba.io/acme` annotation) HTTPS/TLS-terminate
    /// listener with a concrete core-Secret certificateRef. Issuer/email resolve from the
    /// Gateway annotations falling back to the CLI defaults; `attached_routes` comes from
    /// the counts we just computed (so ACME echoes the controller's value). Wildcard/empty
    /// hostnames and missing issuer/email are NOT filtered here — they're included so ACME
    /// reports their Unsupported/Failed state, matching the old self-listing behaviour.
    fn acme_targets(
        &self,
        models: &[GatewayModel],
        attach_counts: &BTreeMap<(String, String), BTreeMap<String, i32>>,
    ) -> Vec<crate::acme::AcmeTarget> {
        use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
        let mut out = Vec::new();
        for model in models {
            let gw = &model.gw;
            let anns = gw.metadata.annotations.clone().unwrap_or_default();
            // Opt-in: the enable annotation must be PRESENT (value ignored).
            if !anns.contains_key(crate::acme::ANNO_ENABLE) {
                continue;
            }
            let directory = anns
                .get(crate::acme::ANNO_ISSUER)
                .cloned()
                .or_else(|| self.config.acme_default_issuer.clone());
            let email = anns
                .get(crate::acme::ANNO_EMAIL)
                .cloned()
                .or_else(|| self.config.acme_default_email.clone());
            let gw_ns = gw.metadata.namespace.clone().unwrap_or_default();
            let gw_name = gw.metadata.name.clone().unwrap_or_default();
            let counts = attach_counts.get(&(gw_ns.clone(), gw_name.clone()));
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
                let attached_routes = counts.and_then(|c| c.get(&l.name)).copied().unwrap_or(0);
                // Does a usable cert currently exist for this listener? From the same
                // CertStore-resolution the controller just did. Flips when the cert
                // Secret is created/deleted, so a deletion changes the target set and
                // pokes ACME to re-issue immediately (the Secret name alone is static).
                let has_cert = model
                    .listeners
                    .iter()
                    .find(|o| o.name == l.name)
                    .is_some_and(|o| o.resolved_cert.is_some());
                for r in tls.certificate_refs.clone().unwrap_or_default() {
                    // Only manage core-Secret refs.
                    if r.group.clone().unwrap_or_default() != ""
                        || r.kind.clone().unwrap_or_else(|| "Secret".into()) != "Secret"
                    {
                        continue;
                    }
                    let secret_ns = r.namespace.clone().unwrap_or_else(|| gw_ns.clone());
                    out.push(crate::acme::AcmeTarget {
                        gw_ns: gw_ns.clone(),
                        gw_name: gw_name.clone(),
                        listener_name: l.name.clone(),
                        gw_gen: model.generation,
                        hostname: hostname.clone(),
                        directory: directory.clone(),
                        email: email.clone(),
                        secret_ns,
                        secret_name: r.name.clone(),
                        attached_routes,
                        has_cert,
                    });
                }
            }
        }
        out
    }

    /// Write all accumulated status patches concurrently. Each patch is applied
    /// INDEPENDENTLY: a single failing patch (transient API error, conflict) is
    /// logged but must NOT abort the others — otherwise one bad write would drop
    /// every other object's status for the pass. A genuinely failed write is
    /// retried on the next event-driven reconcile (level-triggered), so there is
    /// no lost convergence. (404 = object deleted mid-pass, already tolerated as
    /// Ok in `patch_status`.)
    async fn flush_status(&self, patches: Vec<StatusPatch>) -> Result<()> {
        let futs = patches.into_iter().map(|p| {
            let name = p.name.clone();
            async move {
                if let Err(e) = self.apply_patch(p).await {
                    tracing::warn!(name, error = %e, "status patch failed (will retry on next event)");
                }
            }
        });
        futures::future::join_all(futs).await;
        Ok(())
    }

    /// Apply one deferred status patch, building the right typed `Api` for its kind.
    /// Each kind supplies its apiVersion+kind so the patch is a self-contained
    /// Server-Side Apply document (see [`Self::patch_status`]).
    async fn apply_patch(&self, p: StatusPatch) -> Result<()> {
        let ns = p.ns.unwrap_or_default();
        match p.target {
            PatchTarget::GatewayClass => self.patch_status(&self.gc_api, &p.name, "GatewayClass", p.json).await,
            PatchTarget::Gateway => {
                let api: Api<Gateway> = Api::namespaced(self.client.clone(), &ns);
                self.patch_status(&api, &p.name, "Gateway", p.json).await
            }
            PatchTarget::HttpRoute => {
                let api: Api<HTTPRoute> = Api::namespaced(self.client.clone(), &ns);
                self.patch_status(&api, &p.name, "HTTPRoute", p.json).await
            }
            PatchTarget::TlsRoute => {
                let api: Api<TLSRoute> = Api::namespaced(self.client.clone(), &ns);
                self.patch_status(&api, &p.name, "TLSRoute", p.json).await
            }
            PatchTarget::BackendTlsPolicy => {
                let api: Api<BackendTLSPolicy> = Api::namespaced(self.client.clone(), &ns);
                self.patch_status(&api, &p.name, "BackendTLSPolicy", p.json).await
            }
        }
    }

    /// Load a kubernetes.io/tls Secret's cert+key (tls.crt / tls.key) as PEM.
    fn load_tls_secret(&self, ns: &str, name: &str) -> Option<CertKey> {
        let secret = find_in(&self.stores.secrets, ns, name)?;
        let data = secret.data.as_ref()?;
        let cert = data.get("tls.crt")?;
        let key = data.get("tls.key")?;
        Some(CertKey {
            cert_pem: cert.0.clone(),
            key_pem: key.0.clone(),
        })
    }

    fn gatewayclass_patch(&self, gc: &GatewayClass) -> StatusPatch {
        let generation = gc.meta().generation.unwrap_or(0);
        let status = GatewayClassStatus {
            conditions: Some(vec![condition("Accepted", "True", "Accepted", generation)]),
            supported_features: Some(
                SUPPORTED_FEATURES
                    .iter()
                    .map(|f| GatewayClassStatusSupportedFeatures { name: f.to_string() })
                    .collect(),
            ),
        };
        StatusPatch {
            target: PatchTarget::GatewayClass,
            ns: None,
            name: gc.name_any(),
            json: serde_json::json!({ "status": status }),
        }
    }

    /// STAGE 1: build the per-Gateway compute model — usability + per-listener
    /// outcomes (validity as data) + the validated cert. No status is read here;
    /// no status is written here. The cert is loaded ONCE (used for both the
    /// listener status and the CertStore).
    fn build_gateway_model(&self, gw: &Gateway) -> GatewayModel {
        let generation = gw.meta().generation.unwrap_or(0);

        // An invalid/unsupported `spec.infrastructure.parametersRef` makes the
        // whole Gateway unacceptable (Accepted=False/InvalidParameters) and unusable.
        // We support no parametersRef kinds, so *any* reference is invalid.
        let invalid_parameters = gw
            .spec
            .infrastructure
            .as_ref()
            .and_then(|i| i.parameters_ref.as_ref())
            .is_some();

        let mut listeners: Vec<ListenerOutcome> =
            gw.spec.listeners.iter().map(|l| self.listener_outcome(l, gw)).collect();

        // Mixed TLS termination is not supported (we don't claim
        // SupportTLSRouteModeMixed): if a port carries TLS listeners of BOTH modes
        // (Terminate and Passthrough), every TLS listener on that port is rejected
        // with Accepted=False/ProtocolConflict.
        let mut conflict_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for port in listeners.iter().map(|o| o.port).collect::<Vec<_>>() {
            let modes: std::collections::HashSet<TlsListenerMode> = listeners
                .iter()
                .filter(|o| o.port == port)
                .filter_map(|o| o.tls_mode)
                .collect();
            if modes.len() > 1 {
                conflict_ports.insert(port);
            }
        }
        for o in &mut listeners {
            if o.tls_mode.is_some() && conflict_ports.contains(&o.port) {
                o.protocol_conflict = true;
            }
        }

        GatewayModel {
            gw: Arc::new(gw.clone()),
            generation,
            usable: !invalid_parameters,
            invalid_parameters,
            listeners,
        }
    }

    /// Compute one listener's outcome: validity as data + supportedKinds + the
    /// validated+loaded certificate. This is the single TLS code path — it both
    /// decides the listener's ResolvedRefs status AND produces the cert the data
    /// plane will serve. A cert that fails to parse is neither served nor reported
    /// as resolved.
    fn listener_outcome(
        &self,
        l: &gateway_api::apis::standard::gateways::GatewayListeners,
        gw: &Gateway,
    ) -> ListenerOutcome {
        // Which route kinds are valid for this listener's protocol.
        let protocol_kinds: &[&str] = protocol_route_kinds(l.protocol.as_str());

        // Reconcile requested allowedRoutes.kinds against the protocol's valid set.
        // Any requested kind not valid → InvalidRouteKinds, dropped from supportedKinds.
        let mut invalid_kind = false;
        let supported_kinds: Vec<&'static str> = match l.allowed_routes.as_ref().and_then(|ar| ar.kinds.as_ref()) {
            Some(requested) => requested
                .iter()
                .filter_map(|k| match protocol_kinds.iter().find(|p| **p == k.kind) {
                    Some(p) => Some(*p),
                    None => {
                        invalid_kind = true;
                        None
                    }
                })
                .collect(),
            None => protocol_kinds.to_vec(),
        };

        let protocol_supported = matches!(l.protocol.as_str(), "HTTP" | "HTTPS" | "TLS");

        // Validate + load the cert once: (tls_failure, resolved_cert).
        let (tls_failure, resolved_cert) = self.listener_cert(l, gw);

        // A `protocol: TLS` listener's mode drives the TLSRoute data path.
        let tls_mode = if l.protocol == "TLS" {
            use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
            match l.tls.as_ref().and_then(|t| t.mode.as_ref()) {
                Some(Mode::Passthrough) => Some(TlsListenerMode::Passthrough),
                // Terminate is the default mode when unspecified.
                _ => Some(TlsListenerMode::Terminate),
            }
        } else {
            None
        };

        ListenerOutcome {
            name: l.name.clone(),
            protocol_supported,
            invalid_kind,
            tls_failure,
            supported_kinds,
            resolved_cert,
            port: l.port as u16,
            tls_mode,
            protocol_conflict: false, // filled in across the port in build_gateway_model
        }
    }

    /// The single read+validate+use path for an HTTPS/TLS listener's certificate
    /// ref. Returns `(failure_reason, loaded_cert)`:
    /// - `(None, Some((host, cert)))` — resolved + parsed; serve it (host "" = default).
    /// - `(None, None)` — N/A (non-TLS protocol, or passthrough needs no cert).
    /// - `(Some(reason), None)` — RefNotPermitted (cross-ns w/o grant) or
    ///   InvalidCertificateRef (missing/wrong-kind/malformed). Not served.
    fn listener_cert(
        &self,
        l: &gateway_api::apis::standard::gateways::GatewayListeners,
        gw: &Gateway,
    ) -> (Option<&'static str>, Option<(String, CertKey)>) {
        if !matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
            return (None, None);
        }
        use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
        let Some(tls) = l.tls.as_ref() else {
            return (Some("InvalidCertificateRef"), None);
        };
        let passthrough = matches!(tls.mode, Some(Mode::Passthrough));
        let refs = tls.certificate_refs.clone().unwrap_or_default();
        if refs.is_empty() {
            // Passthrough needs no cert; terminate without one is invalid.
            return if passthrough {
                (None, None)
            } else {
                (Some("InvalidCertificateRef"), None)
            };
        }
        let gw_ns = gw.namespace().unwrap_or_default();
        // Key by the listener hostname; "" is the default cert.
        let host = l.hostname.clone().unwrap_or_default();
        let mut loaded: Option<(String, CertKey)> = None;
        for r in &refs {
            // Only core Secrets are valid cert refs.
            let group = r.group.as_deref().unwrap_or("");
            let kind = r.kind.as_deref().unwrap_or("Secret");
            if !group.is_empty() || kind != "Secret" {
                return (Some("InvalidCertificateRef"), None);
            }
            let ref_ns = r.namespace.clone().unwrap_or_else(|| gw_ns.clone());
            // Cross-namespace cert Secret requires a permitting ReferenceGrant.
            if ref_ns != gw_ns && !self.ref_grant_permits(&gw_ns, "Gateway", &ref_ns, "Secret", &r.name) {
                return (Some("RefNotPermitted"), None);
            }
            // The Secret must exist AND contain a valid tls.crt + tls.key.
            match self.load_tls_secret(&ref_ns, &r.name) {
                Some(ck) if cert_key_is_valid(&ck) => {
                    // First valid cert is the one we serve for this listener host.
                    loaded.get_or_insert((host.clone(), ck));
                }
                _ => return (Some("InvalidCertificateRef"), None),
            }
        }
        (None, loaded)
    }

    /// STAGE 3: derive a Gateway's status from its computed model + attachment
    /// counts. Conditions come from `ListenerOutcome` DATA, never from conditions.
    fn gateway_patch(
        &self,
        model: &GatewayModel,
        attach_counts: &BTreeMap<(String, String), BTreeMap<String, i32>>,
    ) -> StatusPatch {
        let gw = &model.gw;
        let generation = model.generation;
        let ns = gw.namespace().unwrap_or_default();
        let counts = attach_counts.get(&(ns.clone(), gw.name_any()));

        // Per-listener status, derived from each ListenerOutcome.
        let listeners: Vec<GatewayStatusListeners> = model
            .listeners
            .iter()
            .map(|o| {
                let attached_routes = counts.and_then(|c| c.get(&o.name).copied()).unwrap_or(0);
                let accepted = if !o.protocol_supported {
                    condition("Accepted", "False", "UnsupportedProtocol", generation)
                } else if o.protocol_conflict {
                    // Two TLS modes share this port and we don't support mixed.
                    condition("Accepted", "False", "ProtocolConflict", generation)
                } else {
                    condition("Accepted", "True", "Accepted", generation)
                };
                // ResolvedRefs precedence: InvalidRouteKinds, then TLS ref issue.
                let resolved = if o.invalid_kind {
                    condition("ResolvedRefs", "False", "InvalidRouteKinds", generation)
                } else if let Some(reason) = o.tls_failure {
                    condition("ResolvedRefs", "False", reason, generation)
                } else {
                    condition("ResolvedRefs", "True", "ResolvedRefs", generation)
                };
                let programmed =
                    if o.protocol_supported && o.tls_failure.is_none() && !o.invalid_kind && !o.protocol_conflict {
                        condition("Programmed", "True", "Programmed", generation)
                    } else {
                        condition("Programmed", "False", "Invalid", generation)
                    };
                // A protocol-conflicted listener (mixed TLS termination, which we
                // don't support) is rejected and advertises NO supported kinds —
                // the conformance suite asserts an empty SupportedKinds for it.
                let supported_kinds: Vec<GatewayStatusListenersSupportedKinds> = if o.protocol_conflict {
                    Vec::new()
                } else {
                    o.supported_kinds
                        .iter()
                        .map(|k| GatewayStatusListenersSupportedKinds {
                            group: Some("gateway.networking.k8s.io".into()),
                            kind: k.to_string(),
                        })
                        .collect()
                };
                // The three standard conditions. The ACME subsystem separately owns
                // the `torii.dirba.io/ACMEIssued` listener condition via its own SSA
                // field manager (merged by condition type), so we never touch it.
                GatewayStatusListeners {
                    name: o.name.clone(),
                    attached_routes,
                    supported_kinds: Some(supported_kinds),
                    conditions: vec![accepted, programmed, resolved],
                }
            })
            .collect();

        // Gateway-level conditions from the OUTCOME DATA (not from the listener
        // conditions above). Listener Accepted depends on protocol_supported alone;
        // invalid_kind/tls_failure affect ResolvedRefs/Programmed, not Accepted.
        let conditions = if model.invalid_parameters {
            vec![
                condition("Accepted", "False", "InvalidParameters", generation),
                condition("Programmed", "False", "InvalidParameters", generation),
            ]
        } else {
            // A protocol-conflicted listener (mixed TLS termination, unsupported) is
            // itself Accepted=False/Programmed=False, so it must not count as accepted
            // or programmed in the Gateway-level rollup either.
            let any_accepted = model
                .listeners
                .iter()
                .any(|o| o.protocol_supported && !o.protocol_conflict);
            let all_accepted = model
                .listeners
                .iter()
                .all(|o| o.protocol_supported && !o.protocol_conflict);
            let all_programmed = model
                .listeners
                .iter()
                .all(|o| o.protocol_supported && o.tls_failure.is_none() && !o.invalid_kind && !o.protocol_conflict);
            let accepted = if any_accepted {
                let reason = if all_accepted { "Accepted" } else { "ListenersNotValid" };
                condition("Accepted", "True", reason, generation)
            } else {
                condition("Accepted", "False", "ListenersNotValid", generation)
            };
            let programmed = if all_programmed && any_accepted {
                condition("Programmed", "True", "Programmed", generation)
            } else {
                condition("Programmed", "False", "Invalid", generation)
            };
            vec![accepted, programmed]
        };

        let status = GatewayStatus {
            addresses: Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".into()),
                value: self.config.advertise_address.clone(),
            }]),
            conditions: Some(conditions),
            listeners: Some(listeners),
            attached_listener_sets: None,
        };
        StatusPatch {
            target: PatchTarget::Gateway,
            ns: Some(ns),
            name: gw.name_any(),
            json: serde_json::json!({ "status": status }),
        }
    }

    /// Is a cross-namespace reference permitted by a ReferenceGrant in the target
    /// namespace? The grant must have a `from` entry matching the referrer
    /// `{gateway.networking.k8s.io / from_kind, namespace: from_ns}` and a `to`
    /// entry matching the target `{core / to_kind}`, optionally restricted by
    /// `to_name`. Used for both cert Secret refs (Gateway→Secret) and backendRefs
    /// (HTTPRoute→Service).
    fn ref_grant_permits(&self, from_ns: &str, from_kind: &str, to_ns: &str, to_kind: &str, to_name: &str) -> bool {
        // Store::find iterates the reflector map under a read lock and short-circuits
        // on the first match, without cloning every grant into a Vec (as state() does).
        self.stores
            .reference_grants
            .find(|rg| {
                if rg.namespace().unwrap_or_default() != to_ns {
                    return false;
                }
                let from_ok =
                    rg.spec.from.iter().any(|f| {
                        f.group == "gateway.networking.k8s.io" && f.kind == from_kind && f.namespace == from_ns
                    });
                let to_ok = rg.spec.to.iter().any(|t| {
                    t.group.is_empty() && t.kind == to_kind && t.name.as_deref().map(|n| n == to_name).unwrap_or(true)
                });
                from_ok && to_ok
            })
            .is_some()
    }

    /// STAGE 2b: resolve a route's backends, build its RouteEntries, count its
    /// attachment per listener, and produce its parent status patch (or None if it
    /// has no parent we own). Attachment is computed ONCE here and used for both
    /// routing and the `attachedRoutes` counts (written into `attach_counts`).
    fn process_route(
        &self,
        route: &HTTPRoute,
        gateways: &[Arc<Gateway>],
        upstream_tls: &UpstreamTlsMap,
        table: &mut RouteTable,
        attach_counts: &mut BTreeMap<(String, String), BTreeMap<String, i32>>,
    ) -> Option<StatusPatch> {
        let generation = route.meta().generation.unwrap_or(0);
        let route_ns = route.namespace().unwrap_or_default();

        let mut parents: Vec<HttpRouteStatusParents> = Vec::new();

        for pref in route.spec.parent_refs.iter().flatten() {
            // Find the parent Gateway among the usable ones we own.
            let parent_ns = pref.namespace.clone().unwrap_or_else(|| route_ns.clone());
            let Some(gw) = gateways
                .iter()
                .find(|g| g.name_any() == pref.name && g.namespace().unwrap_or_default() == parent_ns)
            else {
                continue; // not ours / not found / not usable — don't claim status
            };

            // Determine which of the Gateway's listeners this route attaches to,
            // honoring sectionName, port, allowedRoutes (namespaces + kinds), and
            // listener hostname. Returns the attached listeners and, if none, the
            // Accepted=False reason. Computed ONCE; drives both counts and routing.
            let (attached_listeners, accept_reason) = self.attached_listeners(route, gw, pref);

            // attachedRoutes counts: ensure every listener has a 0 entry, then
            // increment the ones this route attached to.
            let gw_counts = attach_counts.entry((parent_ns.clone(), gw.name_any())).or_default();
            for l in &gw.spec.listeners {
                gw_counts.entry(l.name.clone()).or_insert(0);
            }
            for l in &attached_listeners {
                *gw_counts.entry(l.name.clone()).or_insert(0) += 1;
            }

            // Tiebreaker metadata for precedence ordering.
            let route_creation = route
                .meta()
                .creation_timestamp
                .as_ref()
                .map(|t| t.0.as_second())
                .unwrap_or(0);
            let route_key = format!("{}/{}", route_ns, route.name_any());
            let hostnames: &[String] = route.spec.hostnames.as_deref().unwrap_or_default();

            // Resolve backends across all rules, tracking the most specific
            // ResolvedRefs failure reason (RefNotPermitted takes priority).
            let mut refs_failure: Option<&'static str> = None;
            // First unsupported-value problem found in any rule. The offending rule
            // is skipped (not programmed) and the route is Accepted=False.
            let mut unsupported: Option<String> = None;
            for (rule_order, rule) in route.spec.rules.iter().flatten().enumerate() {
                // A rule with a CRD-valid but unsupported value is not programmed;
                // record the reason for the route's Accepted condition and skip it.
                if let Some(msg) = validate_http_rule(rule_order, rule) {
                    if unsupported.is_none() {
                        unsupported = Some(msg);
                    }
                    continue;
                }
                let mut backends = Vec::new();
                for backend_ref in rule.backend_refs.iter().flatten() {
                    let svc_port = backend_ref.port.unwrap_or(0) as u16;
                    let bns = backend_ref.namespace.clone().unwrap_or_else(|| route_ns.clone());

                    // Only core Services are supported backends. Any other
                    // group/kind → ResolvedRefs=False, InvalidKind.
                    let group = backend_ref.group.as_deref().unwrap_or("");
                    let kind = backend_ref.kind.as_deref().unwrap_or("Service");
                    if !group.is_empty() || kind != "Service" {
                        refs_failure = Some("InvalidKind");
                        continue;
                    }

                    // Cross-namespace backendRefs require a permitting ReferenceGrant.
                    if bns != route_ns
                        && !self.ref_grant_permits(&route_ns, "HTTPRoute", &bns, "Service", &backend_ref.name)
                    {
                        refs_failure = Some("RefNotPermitted");
                        continue; // no endpoints → 500 at the data plane
                    }

                    match self.resolve_endpoints(&bns, &backend_ref.name, svc_port) {
                        // Service exists (ResolvedRefs=True) — even with zero ready
                        // endpoints, the ref is resolved; an empty backend yields a
                        // 503 at traffic time, not BackendNotFound.
                        Some(mut endpoints) => {
                            // Apply any BackendTLSPolicy decision for this Service
                            // PORT (re-encrypt, or invalid→must-5xx), from the map.
                            if let Some(bt) = upstream_tls.get(&(bns.clone(), backend_ref.name.clone(), svc_port)) {
                                for ep in &mut endpoints {
                                    ep.tls = bt.clone();
                                }
                            }
                            backends.push(Backend {
                                weight: backend_ref.weight.unwrap_or(1).max(0) as u32,
                                endpoints,
                                filters: backend_filters_from(backend_ref.filters.as_deref().unwrap_or_default()),
                            });
                        }
                        // Service does not exist → BackendNotFound (don't downgrade
                        // a more specific failure like RefNotPermitted).
                        None => {
                            refs_failure.get_or_insert("BackendNotFound");
                        }
                    }
                }

                // Parse this rule's filters and timeouts once. Honor both
                // `request` (overall) and `backendRequest` (per-attempt); with no
                // retries they coincide, so use the smaller non-zero value. "0s"
                // disables that timeout.
                let rule_filters = rule.filters.as_deref().unwrap_or_default();
                let filters = filters_from(rule_filters);
                let request_timeout = rule.timeouts.as_ref().and_then(|t| {
                    let parse = |s: &Option<String>| {
                        s.as_ref()
                            .and_then(|v| parse_gep2257_duration(v))
                            .filter(|d| !d.is_zero())
                    };
                    [parse(&t.request), parse(&t.backend_request)]
                        .into_iter()
                        .flatten()
                        .min()
                });

                // Each `match` in the rule is an independent OR alternative. A rule
                // with no matches defaults to a single match-all (PathPrefix "/").
                let matches = rule.matches.as_deref().unwrap_or_default();
                let route_matches: Vec<RouteMatch> = if matches.is_empty() {
                    vec![RouteMatch::default()]
                } else {
                    matches.iter().map(route_match_from).collect()
                };

                // Contribute one RouteEntry per (match × attached HTTP(S) listener).
                // HTTPS listeners terminate TLS then route HTTP, so they carry
                // HTTPRoute entries too (keyed by the listener port, e.g. 443).
                for (match_order, rm) in route_matches.into_iter().enumerate() {
                    for l in &attached_listeners {
                        if l.protocol != "HTTP" && l.protocol != "HTTPS" {
                            continue;
                        }
                        // Effective hostnames = intersection of route hostnames and
                        // the listener hostname. Empty route hostnames inherit the
                        // listener's; a listener with no hostname matches any.
                        let effective_hosts = effective_hostnames(hostnames, l.hostname.as_deref());
                        table.entries.push(RouteEntry {
                            listener_port: l.port as u16,
                            listener_hostname: l.hostname.clone(),
                            hostnames: effective_hosts,
                            r#match: rm.clone(),
                            backends: backends.clone(),
                            filters: filters.clone(),
                            request_timeout,
                            route_creation,
                            route_key: route_key.clone(),
                            rule_order,
                            match_order,
                        });
                    }
                }
            }

            // Accepted: attachment failure (no listener took the route) wins; then a
            // rule with an unsupported value → UnsupportedValue + an explanatory
            // message; otherwise Accepted.
            let accepted = match (accept_reason, &unsupported) {
                (Some(reason), _) => condition("Accepted", "False", reason, generation),
                (None, Some(msg)) => condition_msg("Accepted", "False", "UnsupportedValue", msg, generation),
                (None, None) => condition("Accepted", "True", "Accepted", generation),
            };

            let resolved = match refs_failure {
                None => condition("ResolvedRefs", "True", "ResolvedRefs", generation),
                Some(reason) => condition("ResolvedRefs", "False", reason, generation),
            };

            parents.push(HttpRouteStatusParents {
                parent_ref: HttpRouteStatusParentsParentRef {
                    group: pref.group.clone().or_else(|| Some("gateway.networking.k8s.io".into())),
                    kind: pref.kind.clone().or_else(|| Some("Gateway".into())),
                    name: pref.name.clone(),
                    namespace: Some(parent_ns),
                    port: pref.port,
                    section_name: pref.section_name.clone(),
                },
                controller_name: CONTROLLER_NAME.to_string(),
                conditions: vec![accepted, resolved],
            });
        }

        if parents.is_empty() {
            return None; // nothing of ours to claim
        }

        let status = HttpRouteStatus { parents };
        Some(StatusPatch {
            target: PatchTarget::HttpRoute,
            ns: Some(route_ns),
            name: route.name_any(),
            json: serde_json::json!({ "status": status }),
        })
    }

    /// Compute which of a Gateway's listeners an HTTPRoute attaches to.
    ///
    /// Returns the attached listeners and, when none attach, the Accepted=False
    /// reason to report (NoMatchingParent for sectionName/port mismatch;
    /// NotAllowedByListeners for namespace/kind/hostname rejection).
    fn attached_listeners(
        &self,
        route: &HTTPRoute,
        gw: &Gateway,
        pref: &gateway_api::apis::standard::httproutes::HttpRouteParentRefs,
    ) -> (
        Vec<gateway_api::apis::standard::gateways::GatewayListeners>,
        Option<&'static str>,
    ) {
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames: &[String] = route.spec.hostnames.as_deref().unwrap_or_default();

        // First narrow by sectionName / port (a hard parentRef selector). If the
        // ref names a section/port that no listener has, that's NoMatchingParent.
        let candidates: Vec<_> = gw
            .spec
            .listeners
            .iter()
            .filter(|l| {
                pref.section_name.as_ref().map(|s| &l.name == s).unwrap_or(true)
                    && pref.port.map(|p| l.port == p).unwrap_or(true)
            })
            .cloned()
            .collect();

        if candidates.is_empty() {
            return (vec![], Some("NoMatchingParent"));
        }

        // Then filter by allowedRoutes (namespaces + kinds) and hostname overlap,
        // tracking why listeners were rejected to report the right Accepted reason.
        let mut attached = Vec::new();
        let mut rejected_by_allow = false; // namespace/kind → NotAllowedByListeners
        let mut rejected_by_hostname = false; // hostname → NoMatchingListenerHostname
        for l in candidates {
            if !self.listener_allows_namespace(&l, gw, &route_ns) {
                rejected_by_allow = true;
                continue;
            }
            if !listener_allows_kind(&l, "HTTPRoute") {
                rejected_by_allow = true;
                continue;
            }
            if !listener_hostname_overlaps(l.hostname.as_deref(), route_hostnames) {
                rejected_by_hostname = true;
                continue;
            }
            attached.push(l);
        }

        if attached.is_empty() {
            // Prefer NotAllowedByListeners over hostname (matches upstream behavior
            // when both apply); fall back to NoMatchingParent.
            let reason = if rejected_by_allow {
                "NotAllowedByListeners"
            } else if rejected_by_hostname {
                "NoMatchingListenerHostname"
            } else {
                "NoMatchingParent"
            };
            return (vec![], Some(reason));
        }
        (attached, None)
    }

    /// Process one TLSRoute: compute attachment + status across its parents, and
    /// populate the [`TlsTable`] with per-SNI passthrough/terminate actions.
    ///
    /// Mirrors [`Self::process_route`] but matches purely on the SNI hostname and
    /// produces an L4 data path (no HTTP). `models` is needed because attachment
    /// depends on each listener's TLS mode and protocol-conflict status.
    fn process_tls_route(
        &self,
        route: &TLSRoute,
        models: &[GatewayModel],
        tls_table: &mut TlsTable,
        attach_counts: &mut BTreeMap<(String, String), BTreeMap<String, i32>>,
    ) -> Option<StatusPatch> {
        let generation = route.meta().generation.unwrap_or(0);
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames = &route.spec.hostnames;

        let mut parents: Vec<TlsRouteStatusParents> = Vec::new();

        for pref in route.spec.parent_refs.iter().flatten() {
            let parent_ns = pref.namespace.clone().unwrap_or_else(|| route_ns.clone());
            // Find the parent among usable Gateways we own.
            let Some(model) = models.iter().find(|m| {
                m.usable && m.gw.name_any() == pref.name && m.gw.namespace().unwrap_or_default() == parent_ns
            }) else {
                continue; // not ours / not found / not usable
            };
            let gw = &model.gw;

            // Which TLS listeners this route attaches to (sectionName/port +
            // allowedRoutes + SNI hostname overlap + not protocol-conflicted).
            let (attached, accept_reason) = self.attached_tls_listeners(route, gw, model, pref);

            // attachedRoutes counts: ensure every listener has a 0, then bump ours.
            let gw_counts = attach_counts.entry((parent_ns.clone(), gw.name_any())).or_default();
            for l in &gw.spec.listeners {
                gw_counts.entry(l.name.clone()).or_insert(0);
            }
            for (l, _) in &attached {
                *gw_counts.entry(l.name.clone()).or_insert(0) += 1;
            }

            let accepted = match accept_reason {
                None => condition("Accepted", "True", "Accepted", generation),
                Some(reason) => condition("Accepted", "False", reason, generation),
            };

            // Resolve backends across all rules (shared by every matched SNI), and
            // track the ResolvedRefs failure reason (RefNotPermitted first).
            let mut refs_failure: Option<&'static str> = None;
            let mut backends = TlsBackends::default();
            for rule in &route.spec.rules {
                for backend_ref in &rule.backend_refs {
                    let svc_port = backend_ref.port.unwrap_or(0) as u16;
                    let bns = backend_ref.namespace.clone().unwrap_or_else(|| route_ns.clone());

                    let group = backend_ref.group.as_deref().unwrap_or("");
                    let kind = backend_ref.kind.as_deref().unwrap_or("Service");
                    if !group.is_empty() || kind != "Service" {
                        refs_failure = Some("InvalidKind");
                        continue;
                    }
                    if bns != route_ns
                        && !self.ref_grant_permits(&route_ns, "TLSRoute", &bns, "Service", &backend_ref.name)
                    {
                        refs_failure = Some("RefNotPermitted");
                        continue;
                    }
                    match self.resolve_endpoints(&bns, &backend_ref.name, svc_port) {
                        Some(endpoints) => backends.backends.push(TlsBackend {
                            weight: backend_ref.weight.unwrap_or(1).max(0) as u32,
                            endpoints,
                        }),
                        None => {
                            refs_failure.get_or_insert("BackendNotFound");
                        }
                    }
                }
            }

            // For each attached listener, add its effective SNIs to the dispatch
            // table with the listener's mode (Passthrough vs Terminate).
            for (l, mode) in &attached {
                let action = match mode {
                    TlsListenerMode::Passthrough => TlsAction::Passthrough(backends.clone()),
                    TlsListenerMode::Terminate => TlsAction::Terminate(backends.clone()),
                };
                for sni in effective_hostnames(route_hostnames, l.hostname.as_deref()) {
                    tls_table.insert(l.port as u16, &sni, action.clone());
                }
            }

            let resolved = match refs_failure {
                None => condition("ResolvedRefs", "True", "ResolvedRefs", generation),
                Some(reason) => condition("ResolvedRefs", "False", reason, generation),
            };

            parents.push(TlsRouteStatusParents {
                parent_ref: TlsRouteStatusParentsParentRef {
                    group: pref.group.clone().or_else(|| Some("gateway.networking.k8s.io".into())),
                    kind: pref.kind.clone().or_else(|| Some("Gateway".into())),
                    name: pref.name.clone(),
                    namespace: Some(parent_ns),
                    port: pref.port,
                    section_name: pref.section_name.clone(),
                },
                controller_name: CONTROLLER_NAME.to_string(),
                conditions: vec![accepted, resolved],
            });
        }

        if parents.is_empty() {
            return None;
        }
        let status = TlsRouteStatus { parents };
        Some(StatusPatch {
            target: PatchTarget::TlsRoute,
            ns: Some(route_ns),
            name: route.name_any(),
            json: serde_json::json!({ "status": status }),
        })
    }

    /// Compute which of a Gateway's `protocol: TLS` listeners a TLSRoute attaches
    /// to, returning each attached listener paired with its mode. When none
    /// attach, the Accepted=False reason. A listener in protocol-conflict (mixed
    /// termination, unsupported) cannot accept routes.
    fn attached_tls_listeners(
        &self,
        route: &TLSRoute,
        gw: &Gateway,
        model: &GatewayModel,
        pref: &gateway_api::apis::standard::tlsroutes::TlsRouteParentRefs,
    ) -> (
        Vec<(gateway_api::apis::standard::gateways::GatewayListeners, TlsListenerMode)>,
        Option<&'static str>,
    ) {
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames = &route.spec.hostnames;

        // Narrow by sectionName / port first (a hard parentRef selector).
        let candidates: Vec<_> = gw
            .spec
            .listeners
            .iter()
            .filter(|l| {
                pref.section_name.as_ref().map(|s| &l.name == s).unwrap_or(true)
                    && pref.port.map(|p| l.port == p).unwrap_or(true)
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return (vec![], Some("NoMatchingParent"));
        }

        let mut attached = Vec::new();
        let mut rejected_by_allow = false;
        let mut rejected_by_hostname = false;
        for l in candidates {
            // Only TLS listeners carry TLSRoutes. A non-TLS listener selected by
            // sectionName/port is "not allowed" for this kind.
            let Some(outcome) = model.listeners.iter().find(|o| o.name == l.name) else {
                rejected_by_allow = true;
                continue;
            };
            let Some(mode) = outcome.tls_mode else {
                rejected_by_allow = true; // non-TLS protocol
                continue;
            };
            // A protocol-conflicted listener (mixed termination) is Accepted=False
            // and accepts no routes.
            if outcome.protocol_conflict {
                rejected_by_allow = true;
                continue;
            }
            if !self.listener_allows_namespace(&l, gw, &route_ns) {
                rejected_by_allow = true;
                continue;
            }
            if !listener_allows_kind(&l, "TLSRoute") {
                rejected_by_allow = true;
                continue;
            }
            if !listener_hostname_overlaps(l.hostname.as_deref(), route_hostnames) {
                rejected_by_hostname = true;
                continue;
            }
            attached.push((l, mode));
        }

        if attached.is_empty() {
            let reason = if rejected_by_allow {
                "NotAllowedByListeners"
            } else if rejected_by_hostname {
                "NoMatchingListenerHostname"
            } else {
                "NoMatchingParent"
            };
            return (vec![], Some(reason));
        }
        (attached, None)
    }

    /// Does a listener's allowedRoutes.namespaces permit a route in `route_ns`?
    fn listener_allows_namespace(
        &self,
        listener: &gateway_api::apis::standard::gateways::GatewayListeners,
        gw: &Gateway,
        route_ns: &str,
    ) -> bool {
        use gateway_api::apis::standard::gateways::GatewayListenersAllowedRoutesNamespacesFrom as From;
        let gw_ns = gw.namespace().unwrap_or_default();
        let ns_cfg = listener.allowed_routes.as_ref().and_then(|ar| ar.namespaces.as_ref());
        let from = ns_cfg.and_then(|n| n.from.as_ref()).unwrap_or(&From::Same);
        match from {
            From::Same => route_ns == gw_ns,
            From::All => true,
            From::Selector => {
                let Some(selector) = ns_cfg.and_then(|n| n.selector.as_ref()) else {
                    return false;
                };
                // Find the route's namespace object and evaluate the LabelSelector
                // against its labels. A LabelSelector is matchLabels AND
                // matchExpressions; an empty selector matches everything.
                // Namespace is cluster-scoped, so key by name only (O(1) get).
                self.stores
                    .namespaces
                    .get(&reflector::ObjectRef::new(route_ns))
                    .map(|n| {
                        let ns_labels = n.labels();
                        // matchLabels: every (k, v) must be present and equal.
                        let labels_ok = selector
                            .match_labels
                            .iter()
                            .flatten()
                            .all(|(k, v)| ns_labels.get(k).map(|x| x == v).unwrap_or(false));
                        // matchExpressions: every expression must hold.
                        let exprs_ok = selector
                            .match_expressions
                            .iter()
                            .flatten()
                            .all(|e| label_expr_matches(&e.key, &e.operator, &e.values, ns_labels));
                        labels_ok && exprs_ok
                    })
                    .unwrap_or(false)
            }
        }
    }

    /// STAGE 2a: validate every BackendTLSPolicy's CA ONCE, producing both:
    ///   - the [`UpstreamTlsMap`] artifact (keyed by target Service) the data plane
    ///     uses to re-encrypt, and
    ///   - a per-policy [`PolicyOutcome`] (the validated status), keyed by (ns, name).
    ///
    /// The conflict tiebreak (oldest creationTimestamp, then name) is applied while
    /// building the map, so the use-side and the status-side agree on which policy
    /// wins for a given Service.
    fn build_policy_artifacts(&self) -> (UpstreamTlsMap, BTreeMap<(String, String), PolicyOutcome>) {
        use crate::route_table::BackendTls;
        let mut artifacts: UpstreamTlsMap = UpstreamTlsMap::new();
        let mut outcomes: BTreeMap<(String, String), PolicyOutcome> = BTreeMap::new();

        // Sort by the conflict tiebreak (oldest creationTimestamp, then name) so the
        // FIRST valid policy to claim a target wins; later ones are Conflicted.
        let mut policies = self.stores.backend_tls_policies.state();
        policies.sort_by_key(|p| {
            (
                p.meta()
                    .creation_timestamp
                    .as_ref()
                    .map(|t| t.0.as_second())
                    .unwrap_or(0),
                p.name_any(),
            )
        });

        // Conflict winner per (svc_ns, svc_name, sectionName) — the key the spec
        // conflicts on (two policies on the same Service but different/absent section
        // names do NOT conflict). Maps to the winning policy's (ns, name).
        let mut winners: std::collections::HashMap<(String, String, Option<String>), (String, String)> =
            std::collections::HashMap::new();
        // Per data-plane port: was its current artifact set by a section-specific
        // policy? A section-specific (sectionName) policy takes precedence over a
        // Service-wide (no sectionName) one for that port, regardless of sort order.
        let mut port_specific: std::collections::HashSet<(String, String, u16)> = std::collections::HashSet::new();

        for policy in &policies {
            let pol_ns = policy.namespace().unwrap_or_default();
            let pol_key = (pol_ns.clone(), policy.name_any());

            // A targetRef of an unknown/unsupported kind → ResolvedRefs=False/
            // InvalidKind (spec: backendtlspolicy_types.go). Previously such targets
            // were silently dropped, leaving the policy with no status at all.
            if let Some(bad) = policy
                .spec
                .target_refs
                .iter()
                .find(|t| !t.group.is_empty() || t.kind != "Service")
            {
                outcomes.insert(
                    pol_key,
                    PolicyOutcome {
                        status: PolicyStatus::InvalidKind,
                        message: format!(
                            "targetRef {}/{} is not a core Service",
                            if bad.group.is_empty() { "core" } else { &bad.group },
                            bad.kind
                        ),
                    },
                );
                continue;
            }

            let ca = self.resolve_policy_ca(policy, &pol_ns);

            // Invalid policies: emit the right ResolvedRefs reason, and mark every
            // Service PORT they target as Invalid so the data plane 5xxes (no
            // plaintext fallback) — but never overwrite a valid ReEncrypt artifact.
            let ca_pem = match ca {
                CaResult::Valid(pem) => pem,
                CaResult::InvalidKind | CaResult::InvalidRef => {
                    let (status, message) = match ca {
                        CaResult::InvalidKind => (
                            PolicyStatus::InvalidKind,
                            "a caCertificateRef is not a core ConfigMap".to_string(),
                        ),
                        _ => (
                            PolicyStatus::InvalidCaRef,
                            "no valid CA certificate could be resolved".to_string(),
                        ),
                    };
                    outcomes.insert(pol_key, PolicyOutcome { status, message });
                    for t in &policy.spec.target_refs {
                        if !t.group.is_empty() || t.kind != "Service" {
                            continue;
                        }
                        for port in self.target_ports(&pol_ns, &t.name, &t.section_name) {
                            artifacts
                                .entry((pol_ns.clone(), t.name.clone(), port))
                                .or_insert(BackendTls::Invalid);
                        }
                    }
                    continue;
                }
            };

            // Valid policy: claim each target section; first claimant wins, later
            // claimants are Conflicted. A policy is Conflicted only if it loses
            // every target it has (won_any wins).
            let hostname = policy.spec.validation.hostname.clone();
            let mut won_any = false;
            let mut lost_any = false;
            for t in &policy.spec.target_refs {
                if !t.group.is_empty() || t.kind != "Service" {
                    continue;
                }
                // Conflict key includes sectionName (per spec): two policies on the
                // same Service with different/absent sections do NOT conflict.
                let ckey = (pol_ns.clone(), t.name.clone(), t.section_name.clone());
                if winners.contains_key(&ckey) {
                    lost_any = true; // an earlier policy already owns this section
                    continue;
                }
                winners.insert(ckey, pol_key.clone());
                won_any = true;
                // Data-plane map is keyed by Service PORT (sectionName → port name →
                // number; absent section → all ports). Precedence per port: a
                // section-specific policy beats a Service-wide one (and beats an
                // Invalid placeholder); a Service-wide one only fills ports not yet
                // claimed by a section-specific policy.
                let specific = t.section_name.is_some();
                for port in self.target_ports(&pol_ns, &t.name, &t.section_name) {
                    let pkey = (pol_ns.clone(), t.name.clone(), port);
                    if !specific && port_specific.contains(&pkey) {
                        continue; // a section-specific policy already owns this port
                    }
                    artifacts.insert(
                        pkey.clone(),
                        BackendTls::ReEncrypt(crate::route_table::UpstreamTls {
                            hostname: hostname.clone(),
                            ca_pem: ca_pem.clone(),
                        }),
                    );
                    if specific {
                        port_specific.insert(pkey);
                    }
                }
            }
            let (status, message) = if lost_any && !won_any {
                (
                    PolicyStatus::Conflicted,
                    "another BackendTLSPolicy already targets this Service section".to_string(),
                )
            } else {
                (PolicyStatus::Accepted, String::new())
            };
            outcomes.insert(pol_key, PolicyOutcome { status, message });
        }
        (artifacts, outcomes)
    }

    /// The Service port NUMBERS a BackendTLSPolicy target covers. A target's
    /// `sectionName` is a Service port NAME → resolve it to that port's number; an
    /// absent sectionName covers every port of the Service. Returns empty if the
    /// Service (or named port) isn't found — that target then contributes nothing.
    fn target_ports(&self, ns: &str, svc_name: &str, section: &Option<String>) -> Vec<u16> {
        let Some(svc) = find_in(&self.stores.services, ns, svc_name) else {
            return Vec::new();
        };
        let ports = svc.spec.as_ref().and_then(|s| s.ports.as_ref());
        let Some(ports) = ports else {
            return Vec::new();
        };
        match section {
            // sectionName = a specific Service port name.
            Some(name) => ports
                .iter()
                .filter(|p| p.name.as_deref() == Some(name.as_str()))
                .map(|p| p.port as u16)
                .collect(),
            // No sectionName → all the Service's ports.
            None => ports.iter().map(|p| p.port as u16).collect(),
        }
    }

    /// Resolve + validate a policy's CA bundle. The single CA validation path —
    /// both the artifact and the status derive from its [`CaResult`], which
    /// distinguishes a wrong-kind ref (InvalidKind) from a missing/malformed CA
    /// (InvalidCACertificateRef).
    fn resolve_policy_ca(&self, policy: &BackendTLSPolicy, pol_ns: &str) -> CaResult {
        let v = &policy.spec.validation;
        match &v.ca_certificate_refs {
            None => {
                // No explicit CA refs: valid only if it uses well-known CAs.
                if v.well_known_ca_certificates.is_some() {
                    CaResult::Valid(Vec::new()) // system roots
                } else {
                    CaResult::InvalidRef
                }
            }
            Some(refs) => {
                let mut pem = Vec::new();
                for r in refs {
                    if !r.group.is_empty() || r.kind != "ConfigMap" {
                        return CaResult::InvalidKind;
                    }
                    let Some(bytes) = self.load_configmap_ca(pol_ns, &r.name) else {
                        return CaResult::InvalidRef;
                    };
                    if !ca_pem_is_valid(&bytes) {
                        return CaResult::InvalidRef;
                    }
                    pem.extend_from_slice(&bytes);
                    pem.push(b'\n');
                }
                CaResult::Valid(pem)
            }
        }
    }

    /// STAGE 3: build each BackendTLSPolicy's status patch. Ancestors are derived
    /// from raw route + gateway SPECS (never from route outcomes — that would make
    /// policy status depend on route processing and create a cycle). The per-policy
    /// Accepted/ResolvedRefs come from the already-computed [`PolicyOutcome`].
    fn policy_patches(
        &self,
        gateways: &[Arc<Gateway>],
        routes: &[Arc<HTTPRoute>],
        outcomes: &BTreeMap<(String, String), PolicyOutcome>,
    ) -> Vec<StatusPatch> {
        let mut patches = Vec::new();
        for policy in self.stores.backend_tls_policies.state() {
            let generation = policy.meta().generation.unwrap_or(0);
            let pol_ns = policy.namespace().unwrap_or_default();
            let outcome = outcomes.get(&(pol_ns.clone(), policy.name_any()));
            // The message explaining a False condition (empty when Accepted).
            let msg = outcome.map(|o| o.message.as_str()).unwrap_or("");
            // Map the computed PolicyStatus to its (ResolvedRefs, Accepted) pair.
            let (resolved, accepted) = match outcome.map(|o| &o.status) {
                Some(PolicyStatus::Accepted) => (
                    condition("ResolvedRefs", "True", "ResolvedRefs", generation),
                    condition("Accepted", "True", "Accepted", generation),
                ),
                Some(PolicyStatus::Conflicted) => (
                    // Conflicted policies have valid refs → ResolvedRefs stays True.
                    condition("ResolvedRefs", "True", "ResolvedRefs", generation),
                    condition_msg("Accepted", "False", "Conflicted", msg, generation),
                ),
                Some(PolicyStatus::InvalidKind) => (
                    condition_msg("ResolvedRefs", "False", "InvalidKind", msg, generation),
                    condition("Accepted", "False", "NoValidCACertificate", generation),
                ),
                // InvalidCaRef, or no outcome (shouldn't happen) → invalid-ref reason.
                _ => (
                    condition_msg("ResolvedRefs", "False", "InvalidCACertificateRef", msg, generation),
                    condition("Accepted", "False", "NoValidCACertificate", generation),
                ),
            };

            // Ancestors: Gateways that a route targeting this Service attaches to.
            let target_svcs: Vec<String> = policy
                .spec
                .target_refs
                .iter()
                .filter(|t| t.group.is_empty() && t.kind == "Service")
                .map(|t| t.name.clone())
                .collect();
            let mut ancestors: Vec<BackendTlsPolicyStatusAncestors> = Vec::new();
            for gw in gateways {
                let gw_ns = gw.namespace().unwrap_or_default();
                let routes_to_gw_target = routes.iter().any(|r| {
                    route_has_parent(r, &gw.name_any(), &gw_ns) && route_targets_service_in(r, &target_svcs, &pol_ns)
                });
                if routes_to_gw_target {
                    ancestors.push(BackendTlsPolicyStatusAncestors {
                        ancestor_ref: BackendTlsPolicyStatusAncestorsAncestorRef {
                            group: Some("gateway.networking.k8s.io".into()),
                            kind: Some("Gateway".into()),
                            name: gw.name_any(),
                            namespace: Some(gw_ns),
                            port: None,
                            section_name: None,
                        },
                        controller_name: CONTROLLER_NAME.to_string(),
                        conditions: vec![accepted.clone(), resolved.clone()],
                    });
                }
            }
            if ancestors.is_empty() {
                continue; // no ancestor → don't claim status
            }
            let status = BackendTlsPolicyStatus { ancestors };
            patches.push(StatusPatch {
                target: PatchTarget::BackendTlsPolicy,
                ns: Some(pol_ns),
                name: policy.name_any(),
                json: serde_json::json!({ "status": status }),
            });
        }
        patches
    }

    /// Read a CA bundle (ca.crt) from a ConfigMap.
    fn load_configmap_ca(&self, ns: &str, name: &str) -> Option<Vec<u8>> {
        let cm = find_in(&self.stores.config_maps, ns, name)?;
        let ca = cm.data.as_ref()?.get("ca.crt")?;
        Some(ca.clone().into_bytes())
    }

    /// Resolve a Service's backing pod endpoints, mapping the Service port to the
    /// pod targetPort via the Service spec, and finding ready pod IPs from
    /// EndpointSlices.
    fn resolve_endpoints(&self, ns: &str, svc_name: &str, svc_port: u16) -> Option<Vec<Endpoint>> {
        // Find the Service to map svc_port -> targetPort name/number.
        let svc = find_in(&self.stores.services, ns, svc_name)?;

        let port_spec = svc
            .spec
            .as_ref()?
            .ports
            .as_ref()?
            .iter()
            .find(|p| p.port == svc_port as i32)?
            .clone();

        // targetPort: if numeric, use it; if a name, resolve via EndpointSlice port name.
        let target_port_num: Option<i32> = match &port_spec.target_port {
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(n)) => Some(*n),
            _ => None, // named ports resolved per-endpoint-slice below
        };
        let target_port_name: Option<String> = match &port_spec.target_port {
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(s)) => Some(s.clone()),
            _ => None,
        };

        // Collect ready endpoint IPs from EndpointSlices for this service.
        let mut endpoints = Vec::new();
        for slice in self.stores.endpoint_slices.state() {
            if slice.namespace().unwrap_or_default() != ns {
                continue;
            }
            // Route to IP endpoints of either family. The data plane dials an
            // (IpAddr, port), which works for v4 and v6 alike. Skip FQDN slices:
            // their "addresses" are DNS names, not IPs, so they don't parse below
            // (and would need separate resolution we don't do).
            if slice.address_type != "IPv4" && slice.address_type != "IPv6" {
                continue;
            }
            let owner_svc = slice
                .labels()
                .get("kubernetes.io/service-name")
                .cloned()
                .unwrap_or_default();
            if owner_svc != svc_name {
                continue;
            }

            // Determine the port number on this slice.
            let port: Option<i32> = slice.ports.as_ref().and_then(|ports| {
                if let Some(n) = target_port_num {
                    Some(n)
                } else if let Some(name) = &target_port_name {
                    ports
                        .iter()
                        .find(|p| p.name.as_deref() == Some(name.as_str()))
                        .and_then(|p| p.port)
                } else {
                    ports.first().and_then(|p| p.port)
                }
            });
            let Some(port) = port else { continue };

            for ep in &slice.endpoints {
                let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);
                if !ready {
                    continue;
                }
                for addr in &ep.addresses {
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        endpoints.push(Endpoint {
                            ip,
                            port: port as u16,
                            // Plaintext by default; a BackendTLSPolicy targeting this
                            // Service overrides it (ReEncrypt or Invalid) in process_route.
                            tls: crate::route_table::BackendTls::Plaintext,
                        });
                    }
                }
            }
        }
        Some(endpoints)
    }

    /// Write an object's status via **Server-Side Apply** under our field manager.
    /// SSA (not a merge patch) is what lets a second writer — the ACME subsystem —
    /// own its own `torii.dirba.io/ACMEIssued` listener condition without our
    /// reconcile clobbering it: k8s merges the conditions list by `type`
    /// (listMapKey=type), so each manager's fields are preserved independently.
    /// `force` takes ownership of any field a previous manager held (e.g. after an
    /// upgrade), which is safe because the controller is the authoritative source
    /// for the standard conditions.
    ///
    /// `json` is the `{"status": {...}}` we computed; we wrap it into a full apply
    /// document (apiVersion/kind/metadata.name) as SSA requires.
    async fn patch_status<K>(&self, api: &Api<K>, name: &str, kind: &str, json: serde_json::Value) -> Result<()>
    where
        K: Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
        K::DynamicType: Default,
    {
        let mut doc = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": kind,
            "metadata": { "name": name },
        });
        // Merge the computed `{"status": ...}` into the apply document.
        if let (Some(obj), Some(extra)) = (doc.as_object_mut(), json.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        let pp = PatchParams::apply(FIELD_MANAGER).force();
        match api.patch_status(name, &pp, &Patch::Apply(&doc)).await {
            Ok(_) => Ok(()),
            // The object was deleted between our cache snapshot and this write —
            // there's nothing to update. Don't abort the whole reconcile pass.
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                tracing::debug!(name, "status target gone (404), skipping");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Validate one HTTPRoute rule for values that are CRD-valid but that torii
/// can't honor. Returns `Some(message)` describing the first such problem, or `None`
/// if the rule is fully supported. A rule that fails this is NOT programmed into the
/// data plane and the route reports `Accepted=False`/`UnsupportedValue` with this
/// message — never silently dropped.
fn validate_http_rule(
    rule_idx: usize,
    rule: &gateway_api::apis::standard::httproutes::HttpRouteRules,
) -> Option<String> {
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesFiltersType as FType, HttpRouteRulesMatchesHeadersType as HType,
        HttpRouteRulesMatchesPathType as PType, HttpRouteRulesMatchesQueryParamsType as QType,
    };
    let at = format!("rules[{rule_idx}]");

    for (mi, m) in rule.matches.iter().flatten().enumerate() {
        // Path: RegularExpression is implementation-specific and not implemented.
        if let Some(p) = &m.path
            && matches!(p.r#type, Some(PType::RegularExpression))
        {
            return Some(format!(
                "{at}.matches[{mi}].path: RegularExpression path matching is not supported"
            ));
        }
        // Header match: a RegularExpression value must compile.
        for (hi, h) in m.headers.iter().flatten().enumerate() {
            if matches!(h.r#type, Some(HType::RegularExpression))
                && let Err(e) = regex::Regex::new(&h.value)
            {
                return Some(format!(
                    "{at}.matches[{mi}].headers[{hi}]: invalid RegularExpression {:?}: {e}",
                    h.value
                ));
            }
        }
        // Query params: RegularExpression is not implemented (we match Exact only).
        for (qi, q) in m.query_params.iter().flatten().enumerate() {
            if matches!(q.r#type, Some(QType::RegularExpression)) {
                return Some(format!(
                    "{at}.matches[{mi}].queryParams[{qi}]: RegularExpression query matching is not supported"
                ));
            }
        }
    }

    // Filters: reject types we don't implement rather than silently ignoring them.
    for (fi, f) in rule.filters.iter().flatten().enumerate() {
        match f.r#type {
            FType::RequestHeaderModifier
            | FType::ResponseHeaderModifier
            | FType::RequestRedirect
            | FType::UrlRewrite
            | FType::Cors => {}
            FType::RequestMirror => {
                return Some(format!("{at}.filters[{fi}]: RequestMirror is not supported"));
            }
            FType::ExtensionRef => {
                return Some(format!("{at}.filters[{fi}]: ExtensionRef filters are not supported"));
            }
        }
        // Redirect status code must be a valid HTTP redirect code.
        if let Some(r) = &f.request_redirect
            && let Some(code) = r.status_code
            && !matches!(code, 301 | 302 | 303 | 307 | 308)
        {
            return Some(format!(
                "{at}.filters[{fi}].requestRedirect.statusCode: unsupported value {code}"
            ));
        }
    }

    // Timeouts: a present-but-unparseable GEP-2257 duration would otherwise be
    // silently dropped (no timeout enforced).
    if let Some(t) = &rule.timeouts {
        for (field, val) in [("request", &t.request), ("backendRequest", &t.backend_request)] {
            if let Some(s) = val
                && parse_gep2257_duration(s).is_none()
            {
                return Some(format!("{at}.timeouts.{field}: invalid duration {s:?}"));
            }
        }
    }

    None
}

/// Convert a Gateway API HTTPRouteMatch into our internal RouteMatch.
fn route_match_from(m: &gateway_api::apis::standard::httproutes::HttpRouteRulesMatches) -> RouteMatch {
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesMatchesHeadersType as HType, HttpRouteRulesMatchesPathType as PType,
    };

    let path = m.path.as_ref().map(|p| {
        let value = p.value.clone().unwrap_or_else(|| "/".into());
        match p.r#type {
            Some(PType::Exact) => PathMatch::Exact(value),
            _ => PathMatch::Prefix(value), // PathPrefix is the default
        }
    });

    let headers = m
        .headers
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|h| HeaderMatch {
            name: h.name,
            value: match h.r#type {
                Some(HType::RegularExpression) => match regex::Regex::new(&h.value) {
                    Ok(re) => HeaderValueMatch::Regex(re),
                    // An un-compilable pattern must not silently match the wrong
                    // thing. Fail closed: an Exact match against a value a header can
                    // never hold (NUL is rejected by the HTTP layer), so the route
                    // simply never matches on this header.
                    Err(e) => {
                        tracing::warn!(pattern = %h.value, error = %e, "invalid header-match regex; route will not match");
                        HeaderValueMatch::Exact("\0".to_string())
                    }
                },
                _ => HeaderValueMatch::Exact(h.value),
            },
        })
        .collect();

    let method = m.method.as_ref().map(method_to_string);

    let query_params = m
        .query_params
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|q| QueryMatch {
            name: q.name,
            value: q.value,
        })
        .collect();

    RouteMatch {
        path,
        headers,
        method,
        query_params,
    }
}

/// The route kinds a listener's protocol implicitly supports when
/// `allowedRoutes.kinds` is unset (Gateway API: kinds default from the protocol).
/// HTTP/HTTPS → HTTPRoute; TLS → TLSRoute; anything else → none.
fn protocol_route_kinds(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "HTTP" | "HTTPS" => &["HTTPRoute"],
        "TLS" => &["TLSRoute"],
        _ => &[],
    }
}

/// Does a listener's allowedRoutes.kinds permit the given route kind? An absent
/// `kinds` list does NOT mean "all kinds" — it means the kinds the listener's
/// PROTOCOL supports. So an HTTPRoute must not attach to a `protocol: TLS` listener
/// just because that listener omitted `kinds` (it would otherwise be reported
/// Accepted=True and inflate attachedRoutes, even though no traffic is served).
fn listener_allows_kind(listener: &gateway_api::apis::standard::gateways::GatewayListeners, kind: &str) -> bool {
    match listener.allowed_routes.as_ref().and_then(|ar| ar.kinds.as_ref()) {
        None => protocol_route_kinds(&listener.protocol).contains(&kind),
        Some(kinds) => kinds.iter().any(|k| k.kind == kind),
    }
}

/// Does the listener hostname overlap with the route's hostnames? A listener with
/// no hostname matches anything; route with no hostnames matches the listener.
fn listener_hostname_overlaps(listener_host: Option<&str>, route_hosts: &[String]) -> bool {
    let Some(lh) = listener_host else {
        return true;
    };
    if route_hosts.is_empty() {
        return true;
    }
    route_hosts.iter().any(|rh| hostnames_intersect(lh, rh))
}

/// Evaluate one Kubernetes `LabelSelectorRequirement` against a label set.
/// Operators (case-sensitive, per the API): In, NotIn, Exists, DoesNotExist.
/// An unknown operator never matches (fail closed).
fn label_expr_matches(
    key: &str,
    operator: &str,
    values: &Option<Vec<String>>,
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    let values = values.as_deref().unwrap_or_default();
    match operator {
        "In" => labels.get(key).map(|v| values.iter().any(|x| x == v)).unwrap_or(false),
        "NotIn" => labels.get(key).map(|v| !values.iter().any(|x| x == v)).unwrap_or(true),
        "Exists" => labels.contains_key(key),
        "DoesNotExist" => !labels.contains_key(key),
        _ => false,
    }
}

/// Two hostnames intersect if they're equal, or one's wildcard covers the other.
fn hostnames_intersect(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    wildcard_covers(a, b) || wildcard_covers(b, a)
}

/// Does wildcard pattern `pat` (e.g. `*.example.com`) cover hostname `host`?
fn wildcard_covers(pat: &str, host: &str) -> bool {
    if let Some(suffix) = pat.strip_prefix("*.") {
        host.strip_suffix(suffix)
            .map(|p| p.ends_with('.') && p.len() > 1)
            .unwrap_or(false)
    } else {
        false
    }
}

/// Effective route hostnames for a listener: the intersection of the route's
/// hostnames with the listener hostname. If the route has none, inherit the
/// listener's (or match-any if the listener has none too).
///
/// When both sides intersect, the effective host is the MORE SPECIFIC of the two
/// (e.g. route `*.specific.com` ∩ listener `very.specific.com` = `very.specific.com`),
/// so the data plane only serves the true intersection.
fn effective_hostnames(route_hosts: &[String], listener_host: Option<&str>) -> Vec<String> {
    match (route_hosts.is_empty(), listener_host) {
        (true, None) => vec![],                   // match any
        (true, Some(lh)) => vec![lh.to_string()], // inherit listener
        (false, None) => route_hosts.to_vec(),    // route's own
        (false, Some(lh)) => route_hosts
            .iter()
            .filter_map(|rh| hostname_intersection(lh, rh))
            .collect(),
    }
}

/// The intersection of two hostnames (one may be a `*.` wildcard), or None if
/// they don't intersect. The result is the more specific of the two.
fn hostname_intersection(a: &str, b: &str) -> Option<String> {
    if a.eq_ignore_ascii_case(b) {
        Some(a.to_string())
    } else if wildcard_covers(a, b) {
        Some(b.to_string()) // b is more specific
    } else if wildcard_covers(b, a) {
        Some(a.to_string()) // a is more specific
    } else {
        None
    }
}

/// Validate that a CA bundle PEM contains at least one parseable certificate.
fn ca_pem_is_valid(pem: &[u8]) -> bool {
    pingora_core::tls::x509::X509::stack_from_pem(pem)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// Validate that a cert/key pair parses as PEM (used to reject malformed cert
/// Secrets → InvalidCertificateRef). Uses the same OpenSSL backend as the proxy.
fn cert_key_is_valid(ck: &CertKey) -> bool {
    pingora_core::tls::x509::X509::from_pem(&ck.cert_pem).is_ok()
        && pingora_core::tls::pkey::PKey::private_key_from_pem(&ck.key_pem).is_ok()
}

/// Parse a Gateway API duration into a [`Duration`].
///
/// This is the **GEP-2257** format (`^([0-9]{1,5}(h|m|s|ms)){1,4}$`), a *strict
/// subset* of Go's `time.ParseDuration` — NOT the full Go format. Specifically:
/// only the units `h|m|s|ms` (no `ns`/`us`/`µs`), integer values only (no
/// fractions like `1.5h`), no sign, at most four `<int><unit>` segments. We parse
/// it directly rather than reusing a Go-style parser so we don't accept values the
/// CRD's own pattern validation would reject.
///
/// One to four concatenated `<int><unit>` segments are summed (e.g. `1h30m`,
/// `2m30s`, `500ms`, `0s`). Returns `None` on any parse failure. A previous version
/// matched the whole tail as a single unit, so a compound value like `1h30m` failed
/// and silently disabled the configured timeout.
fn parse_gep2257_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    // Tolerate a bare "0" even though GEP-2257 requires a unit (e.g. "0s").
    if s == "0" {
        return Some(Duration::ZERO);
    }
    if s.is_empty() {
        return None;
    }

    let mut total = Duration::ZERO;
    let mut rest = s;
    while !rest.is_empty() {
        // Digits of this segment's value.
        let digits_end = rest.find(|c: char| !c.is_ascii_digit())?;
        if digits_end == 0 {
            return None; // a unit with no preceding number
        }
        let value: u64 = rest[..digits_end].parse().ok()?;
        rest = &rest[digits_end..];

        // Unit: match the longest known unit at the start (ms before m/s).
        let (unit_secs_num, unit_secs_den, unit_len) = if rest.starts_with("ms") {
            (1u64, 1000u64, 2) // milliseconds
        } else if rest.starts_with('h') {
            (3600, 1, 1)
        } else if rest.starts_with('m') {
            (60, 1, 1)
        } else if rest.starts_with('s') {
            (1, 1, 1)
        } else {
            return None; // unknown / missing unit
        };
        rest = &rest[unit_len..];

        // value * unit, in nanoseconds, checked against overflow.
        let nanos = (value as u128)
            .checked_mul(unit_secs_num as u128)?
            .checked_mul(1_000_000_000u128)?
            / unit_secs_den as u128;
        total = total.checked_add(Duration::from_nanos(u64::try_from(nanos).ok()?))?;
    }
    Some(total)
}

/// Build a [`PathRewrite`] from a redirect/url-rewrite path config. `is_full_path`
/// selects ReplaceFullPath vs ReplacePrefixMatch; the two generated filter types
/// share these field shapes, so both call sites funnel through here.
fn path_rewrite(is_full_path: bool, replace_full: &Option<String>, replace_prefix: &Option<String>) -> PathRewrite {
    if is_full_path {
        PathRewrite::ReplaceFullPath(replace_full.clone().unwrap_or_default())
    } else {
        PathRewrite::ReplacePrefixMatch(replace_prefix.clone().unwrap_or_default())
    }
}

/// Parse a rule's filters into our pre-digested [`Filters`] form.
fn filters_from(filters: &[gateway_api::apis::standard::httproutes::HttpRouteRulesFilters]) -> Filters {
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesFiltersRequestRedirectPathType as RPType, HttpRouteRulesFiltersRequestRedirectScheme as RScheme,
        HttpRouteRulesFiltersUrlRewritePathType as RWType,
    };

    let mut out = Filters::default();
    for f in filters {
        if let Some(m) = &f.request_header_modifier {
            out.request_headers = header_mods(
                m.set.as_deref(),
                m.add.as_deref(),
                m.remove.as_deref(),
                |s| (s.name.clone(), s.value.clone()),
                |a| (a.name.clone(), a.value.clone()),
            );
        }
        if let Some(m) = &f.response_header_modifier {
            out.response_headers = header_mods(
                m.set.as_deref(),
                m.add.as_deref(),
                m.remove.as_deref(),
                |s| (s.name.clone(), s.value.clone()),
                |a| (a.name.clone(), a.value.clone()),
            );
        }
        if let Some(r) = &f.request_redirect {
            out.redirect = Some(Redirect {
                scheme: r.scheme.as_ref().map(|s| match s {
                    RScheme::Http => "http".to_string(),
                    RScheme::Https => "https".to_string(),
                }),
                hostname: r.hostname.clone(),
                port: r.port.map(|p| p as u16),
                status_code: r.status_code.map(|c| c as u16).unwrap_or(302),
                path: r.path.as_ref().map(|p| {
                    path_rewrite(
                        matches!(p.r#type, RPType::ReplaceFullPath),
                        &p.replace_full_path,
                        &p.replace_prefix_match,
                    )
                }),
            });
        }
        if let Some(c) = &f.cors {
            out.cors = Some(crate::route_table::Cors {
                allow_origins: c.allow_origins.clone().unwrap_or_default(),
                allow_methods: c.allow_methods.clone().unwrap_or_default(),
                allow_headers: c.allow_headers.clone().unwrap_or_default(),
                expose_headers: c.expose_headers.clone().unwrap_or_default(),
                allow_credentials: c.allow_credentials.unwrap_or(false),
                max_age: c.max_age,
            });
        }
        if let Some(rw) = &f.url_rewrite {
            out.url_rewrite = Some(UrlRewrite {
                hostname: rw.hostname.clone(),
                path: rw.path.as_ref().map(|p| {
                    path_rewrite(
                        matches!(p.r#type, RWType::ReplaceFullPath),
                        &p.replace_full_path,
                        &p.replace_prefix_match,
                    )
                }),
            });
        }
    }
    out
}

/// Parse per-backendRef filters into [`Filters`]. Covers the header modifiers
/// (the conformant per-backend filter case); redirect/rewrite/mirror/cors on a
/// backendRef are uncommon and not needed by the current tests.
fn backend_filters_from(
    filters: &[gateway_api::apis::standard::httproutes::HttpRouteRulesBackendRefsFilters],
) -> Filters {
    let mut out = Filters::default();
    for f in filters {
        if let Some(m) = &f.request_header_modifier {
            out.request_headers = header_mods(
                m.set.as_deref(),
                m.add.as_deref(),
                m.remove.as_deref(),
                |s| (s.name.clone(), s.value.clone()),
                |a| (a.name.clone(), a.value.clone()),
            );
        }
        if let Some(m) = &f.response_header_modifier {
            out.response_headers = header_mods(
                m.set.as_deref(),
                m.add.as_deref(),
                m.remove.as_deref(),
                |s| (s.name.clone(), s.value.clone()),
                |a| (a.name.clone(), a.value.clone()),
            );
        }
    }
    out
}

/// Build a [`HeaderMods`] from optional set/add/remove lists via field extractors.
fn header_mods<S, A>(
    set: Option<&[S]>,
    add: Option<&[A]>,
    remove: Option<&[String]>,
    set_kv: impl Fn(&S) -> (String, String),
    add_kv: impl Fn(&A) -> (String, String),
) -> HeaderMods {
    HeaderMods {
        set: set.unwrap_or_default().iter().map(set_kv).collect(),
        add: add.unwrap_or_default().iter().map(add_kv).collect(),
        remove: remove.unwrap_or_default().to_vec(),
    }
}

fn method_to_string(m: &gateway_api::apis::standard::httproutes::HttpRouteRulesMatchesMethod) -> String {
    use gateway_api::apis::standard::httproutes::HttpRouteRulesMatchesMethod as M;
    match m {
        M::Get => "GET",
        M::Head => "HEAD",
        M::Post => "POST",
        M::Put => "PUT",
        M::Delete => "DELETE",
        M::Connect => "CONNECT",
        M::Options => "OPTIONS",
        M::Trace => "TRACE",
        M::Patch => "PATCH",
    }
    .to_string()
}

/// Does an HTTPRoute have a parentRef pointing at the given Gateway (name + ns)?
fn route_has_parent(route: &HTTPRoute, gw_name: &str, gw_ns: &str) -> bool {
    let r_ns = route.namespace().unwrap_or_default();
    route
        .spec
        .parent_refs
        .iter()
        .flatten()
        .any(|p| p.name == gw_name && p.namespace.as_deref().unwrap_or(&r_ns) == gw_ns)
}

/// Does an HTTPRoute have a backendRef to one of `svc_names` in namespace `svc_ns`?
fn route_targets_service_in(route: &HTTPRoute, svc_names: &[String], svc_ns: &str) -> bool {
    let r_ns = route.namespace().unwrap_or_default();
    route
        .spec
        .rules
        .iter()
        .flatten()
        .flat_map(|rule| rule.backend_refs.iter().flatten())
        .any(|b| svc_names.contains(&b.name) && b.namespace.as_deref().unwrap_or(&r_ns) == svc_ns)
}

/// Find a namespaced object by name in a reflector store. Centralizes the
/// "scan store for name+namespace" lookup shared by the Secret/ConfigMap/Service
/// resolvers.
fn find_in<K>(store: &Store<K>, ns: &str, name: &str) -> Option<Arc<K>>
where
    K: Resource + Clone + 'static,
    K::DynamicType: Eq + std::hash::Hash + Clone + Default,
{
    // O(1) keyed lookup against the reflector's HashMap, instead of cloning the
    // whole store into a Vec and linear-scanning it on every call.
    store.get(&reflector::ObjectRef::new(name).within(ns))
}

/// Build a metav1 Condition with observedGeneration set and an empty message.
fn condition(type_: &str, status: &str, reason: &str, observed_generation: i64) -> Condition {
    condition_msg(type_, status, reason, "", observed_generation)
}

/// Build a metav1 Condition carrying a human-readable `message`. The Gateway API
/// `message` field is meant to explain WHY a condition is False — infra users see
/// it via `kubectl describe`/`get -o yaml` even without controller-log access. The
/// conformance suite matches only on type/status/reason (helpers.go), so a detailed
/// message is always safe to include and never breaks a test.
fn condition_msg(type_: &str, status: &str, reason: &str, message: &str, observed_generation: i64) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: Some(observed_generation),
        // A fixed timestamp is fine; the suite never inspects it. A stable value
        // keeps the merge patch deterministic (avoids needless status churn).
        // k8s-openapi 0.27 uses jiff (not chrono) for Time.
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_single_segment() {
        assert_eq!(parse_gep2257_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(parse_gep2257_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_gep2257_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_gep2257_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_gep2257_duration("0s"), Some(Duration::ZERO));
        assert_eq!(parse_gep2257_duration("0"), Some(Duration::ZERO));
    }

    #[test]
    fn duration_compound_segments() {
        // The bug this fixes: compound values used to parse to None.
        assert_eq!(parse_gep2257_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_gep2257_duration("2m30s"), Some(Duration::from_secs(150)));
        assert_eq!(
            parse_gep2257_duration("1h30m15s"),
            Some(Duration::from_secs(3600 + 1800 + 15))
        );
        assert_eq!(
            parse_gep2257_duration("1h0m0s500ms"),
            Some(Duration::from_millis(3_600_000 + 500))
        );
    }

    #[test]
    fn duration_rejects_garbage() {
        assert_eq!(parse_gep2257_duration(""), None);
        assert_eq!(parse_gep2257_duration("abc"), None);
        assert_eq!(parse_gep2257_duration("10"), None); // number without a unit
        assert_eq!(parse_gep2257_duration("s"), None); // unit without a number
        assert_eq!(parse_gep2257_duration("1x"), None); // unknown unit
        assert_eq!(parse_gep2257_duration("1us"), None); // not a GEP-2257 unit
        assert_eq!(parse_gep2257_duration("1.5s"), None); // GEP-2257 is integer-only
    }

    fn lbls(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn label_expr_operators() {
        let l = lbls(&[("env", "prod"), ("team", "core")]);
        let v = |xs: &[&str]| Some(xs.iter().map(|s| s.to_string()).collect());

        // In
        assert!(label_expr_matches("env", "In", &v(&["prod", "stage"]), &l));
        assert!(!label_expr_matches("env", "In", &v(&["dev"]), &l));
        assert!(!label_expr_matches("missing", "In", &v(&["x"]), &l));
        // NotIn (absent key counts as NotIn-match, per k8s semantics)
        assert!(label_expr_matches("env", "NotIn", &v(&["dev"]), &l));
        assert!(!label_expr_matches("env", "NotIn", &v(&["prod"]), &l));
        assert!(label_expr_matches("missing", "NotIn", &v(&["x"]), &l));
        // Exists / DoesNotExist (values ignored)
        assert!(label_expr_matches("team", "Exists", &None, &l));
        assert!(!label_expr_matches("missing", "Exists", &None, &l));
        assert!(label_expr_matches("missing", "DoesNotExist", &None, &l));
        assert!(!label_expr_matches("team", "DoesNotExist", &None, &l));
        // Unknown operator fails closed.
        assert!(!label_expr_matches("env", "Bogus", &v(&["prod"]), &l));
    }
}
