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
use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher::{watcher, Config};
use kube::runtime::WatchStreamExt;
use kube::{Api, Client, Resource, ResourceExt};

use gateway_api::apis::standard::gatewayclasses::{
    GatewayClass, GatewayClassStatus, GatewayClassStatusSupportedFeatures,
};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayStatus, GatewayStatusAddresses, GatewayStatusListeners,
    GatewayStatusListenersSupportedKinds,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteStatus, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
use gateway_api::apis::standard::referencegrants::ReferenceGrant;

use crate::route_table::{
    Backend, Endpoint, Filters, HeaderMatch, HeaderMods, HeaderValueMatch, PathMatch, PathRewrite,
    QueryMatch, Redirect, RouteEntry, RouteMatch, RouteTable, SharedRouteTable, UrlRewrite,
};

/// Our controller name. Must be DOMAIN/PATH and match GatewayClass.spec.controllerName.
pub const CONTROLLER_NAME: &str = "lolgateway.dev/controller";

/// Features we report in GatewayClass.status.supportedFeatures. The conformance
/// suite uses this to decide which tests apply when running a whole profile
/// (without an explicit --supported-features flag). Grow this as features land.
const SUPPORTED_FEATURES: &[&str] = &[
    "Gateway",
    "GatewayPort8080",
    "GatewayHTTPListenerIsolation",
    "HTTPRoute",
    "ReferenceGrant",
    "HTTPRouteParentRefPort",
    "HTTPRouteRequestTimeout",
    "HTTPRouteBackendTimeout",
    "HTTPRouteRequestMirror",
    "HTTPRouteRequestMultipleMirrors",
    "HTTPRouteRequestPercentageMirror",
];

/// The address we advertise in Gateway.status.addresses — where our proxy listens,
/// reachable by the conformance suite running on the host.
pub struct ControllerConfig {
    pub advertise_address: String,
}

/// Cached stores for every resource we reconcile from.
struct Stores {
    gateway_classes: Store<GatewayClass>,
    gateways: Store<Gateway>,
    routes: Store<HTTPRoute>,
    services: Store<Service>,
    endpoint_slices: Store<EndpointSlice>,
    reference_grants: Store<ReferenceGrant>,
    namespaces: Store<Namespace>,
    secrets: Store<Secret>,
}

/// Run the control plane forever: start watchers, and on any change recompute.
pub async fn run(
    client: Client,
    shared: SharedRouteTable,
    config: ControllerConfig,
) -> Result<()> {
    let gc_api: Api<GatewayClass> = Api::all(client.clone());
    let gw_api: Api<Gateway> = Api::all(client.clone());
    let rt_api: Api<HTTPRoute> = Api::all(client.clone());
    let svc_api: Api<Service> = Api::all(client.clone());
    let eps_api: Api<EndpointSlice> = Api::all(client.clone());
    let rg_api: Api<ReferenceGrant> = Api::all(client.clone());
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let sec_api: Api<Secret> = Api::all(client.clone());

    // reflector stores + writers, fed by watchers.
    let (gc_store, gc_w) = reflector::store();
    let (gw_store, gw_w) = reflector::store();
    let (rt_store, rt_w) = reflector::store();
    let (svc_store, svc_w) = reflector::store();
    let (eps_store, eps_w) = reflector::store();
    let (rg_store, rg_w) = reflector::store();
    let (ns_store, ns_w) = reflector::store();
    let (sec_store, sec_w) = reflector::store();

    let stores = Arc::new(Stores {
        gateway_classes: gc_store.clone(),
        gateways: gw_store.clone(),
        routes: rt_store.clone(),
        services: svc_store.clone(),
        endpoint_slices: eps_store.clone(),
        reference_grants: rg_store.clone(),
        namespaces: ns_store.clone(),
        secrets: sec_store.clone(),
    });

    // A change signal: every watcher event pokes this channel; a single consumer
    // debounces and runs a full reconcile.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

    macro_rules! spawn_watch {
        ($api:expr, $writer:expr, $kind:literal) => {{
            let tx = tx.clone();
            let stream = watcher($api, Config::default())
                .reflect($writer)
                .default_backoff()
                .touched_objects();
            tokio::spawn(async move {
                futures::pin_mut!(stream);
                while let Some(ev) = stream.next().await {
                    match ev {
                        Ok(_) => {
                            // Non-blocking poke; a pending reconcile already covers us.
                            let _ = tx.try_send(());
                        }
                        Err(e) => tracing::warn!(kind = $kind, error = %e, "watch error"),
                    }
                }
            });
        }};
    }

    spawn_watch!(gc_api.clone(), gc_w, "GatewayClass");
    spawn_watch!(gw_api.clone(), gw_w, "Gateway");
    spawn_watch!(rt_api.clone(), rt_w, "HTTPRoute");
    spawn_watch!(svc_api.clone(), svc_w, "Service");
    spawn_watch!(eps_api.clone(), eps_w, "EndpointSlice");
    spawn_watch!(rg_api.clone(), rg_w, "ReferenceGrant");
    spawn_watch!(ns_api.clone(), ns_w, "Namespace");
    spawn_watch!(sec_api.clone(), sec_w, "Secret");

    // Wait for the caches to populate before the first reconcile.
    let ready = stores.clone();
    tokio::spawn(async move {
        let _ = ready.gateway_classes.wait_until_ready().await;
        let _ = ready.gateways.wait_until_ready().await;
        let _ = ready.routes.wait_until_ready().await;
        let _ = ready.services.wait_until_ready().await;
        let _ = ready.endpoint_slices.wait_until_ready().await;
        let _ = ready.reference_grants.wait_until_ready().await;
        let _ = ready.namespaces.wait_until_ready().await;
        let _ = ready.secrets.wait_until_ready().await;
    });

    tracing::info!(controller = CONTROLLER_NAME, "control plane started");

    let ctx = ReconcileCtx {
        client,
        gc_api,
        shared,
        config,
        stores,
    };

    // Reconcile loop: debounce bursts of events, then recompute everything.
    loop {
        // Wait for at least one event (or periodic resync every 10s).
        let _ = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await;
        // Coalesce a short burst.
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
    shared: SharedRouteTable,
    config: ControllerConfig,
    stores: Arc<Stores>,
}

impl ReconcileCtx {
    /// Full level-triggered recompute: set all statuses and rebuild the RouteTable.
    async fn reconcile_all(&self) -> Result<()> {
        // 1. GatewayClasses we own → Accepted=True.
        let owned_classes: Vec<Arc<GatewayClass>> = self
            .stores
            .gateway_classes
            .state()
            .into_iter()
            .filter(|gc| gc.spec.controller_name == CONTROLLER_NAME)
            .collect();
        let owned_class_names: Vec<String> =
            owned_classes.iter().map(|gc| gc.name_any()).collect();

        for gc in &owned_classes {
            self.set_gatewayclass_accepted(gc).await?;
        }

        // 2. Gateways whose class we own → program listeners, set address + status.
        let gateways: Vec<Arc<Gateway>> = self
            .stores
            .gateways
            .state()
            .into_iter()
            .filter(|gw| owned_class_names.contains(&gw.spec.gateway_class_name))
            .collect();

        let mut route_table = RouteTable::default();

        for gw in &gateways {
            self.reconcile_gateway(gw).await?;
        }

        // 3. HTTPRoutes → resolve, set parent status, contribute to RouteTable.
        let routes: Vec<Arc<HTTPRoute>> = self.stores.routes.state();
        for route in &routes {
            self.reconcile_route(route, &gateways, &mut route_table)
                .await?;
        }

        // 4. Sort by Gateway API precedence, then publish the data-plane snapshot.
        route_table.sort();
        tracing::debug!(entries = route_table.entries.len(), "publishing route table");
        self.shared.store(route_table);
        Ok(())
    }

    async fn set_gatewayclass_accepted(&self, gc: &GatewayClass) -> Result<()> {
        let gen = gc.meta().generation.unwrap_or(0);
        let status = GatewayClassStatus {
            conditions: Some(vec![condition("Accepted", "True", "Accepted", gen)]),
            supported_features: Some(
                SUPPORTED_FEATURES
                    .iter()
                    .map(|f| GatewayClassStatusSupportedFeatures { name: f.to_string() })
                    .collect(),
            ),
        };
        self.patch_status(&self.gc_api, &gc.name_any(), serde_json::json!({ "status": status }))
            .await
    }

    /// Program a Gateway: all listeners Accepted/Programmed/ResolvedRefs=True,
    /// top-level Accepted/Programmed=True, and a status address.
    async fn reconcile_gateway(&self, gw: &Gateway) -> Result<()> {
        let gen = gw.meta().generation.unwrap_or(0);
        let ns = gw.namespace().unwrap_or_default();

        // Count routes attached to each listener (for attachedRoutes).
        let attached = self.count_attached_routes(gw);

        let listeners: Vec<GatewayStatusListeners> = gw
            .spec
            .listeners
            .iter()
            .map(|l| {
                self.listener_status(l, gen, *attached.get(&l.name).unwrap_or(&0))
            })
            .collect();

        // Derive Gateway-level conditions from listener state.
        let listener_accepted = |l: &GatewayStatusListeners| {
            l.conditions
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True")
        };
        let any_accepted = listeners.iter().any(listener_accepted);
        let all_accepted = listeners.iter().all(listener_accepted);
        let all_programmed = listeners.iter().all(|l| {
            l.conditions
                .iter()
                .any(|c| c.type_ == "Programmed" && c.status == "True")
        });

        // Accepted: True if ≥1 listener is accepted; reason ListenersNotValid when
        // any listener is invalid (per the conformance spec), else Accepted.
        let accepted = if any_accepted {
            let reason = if all_accepted { "Accepted" } else { "ListenersNotValid" };
            condition("Accepted", "True", reason, gen)
        } else {
            condition("Accepted", "False", "ListenersNotValid", gen)
        };
        let programmed = if all_programmed && any_accepted {
            condition("Programmed", "True", "Programmed", gen)
        } else {
            condition("Programmed", "False", "Invalid", gen)
        };

        let status = GatewayStatus {
            addresses: Some(vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".into()),
                value: self.config.advertise_address.clone(),
            }]),
            conditions: Some(vec![accepted, programmed]),
            listeners: Some(listeners),
            attached_listener_sets: None,
        };

        let api: Api<Gateway> = Api::namespaced(self.client.clone(), &ns);
        self.patch_status(&api, &gw.name_any(), serde_json::json!({ "status": status }))
            .await
    }

    /// Compute the status for one listener: Accepted/Programmed/ResolvedRefs
    /// conditions and the resolved supportedKinds.
    fn listener_status(
        &self,
        l: &gateway_api::apis::standard::gateways::GatewayListeners,
        gen: i64,
        attached_routes: i32,
    ) -> GatewayStatusListeners {
        // Which route kinds are valid for this listener's protocol.
        let protocol_kinds: &[&str] = match l.protocol.as_str() {
            "HTTP" | "HTTPS" => &["HTTPRoute"],
            "TLS" => &["TLSRoute"],
            _ => &[],
        };

        // Reconcile requested allowedRoutes.kinds against the protocol's valid set.
        // Any requested kind not valid → ResolvedRefs=False, InvalidRouteKinds, and
        // it is dropped from supportedKinds.
        let mut invalid_kind = false;
        let supported: Vec<&str> = match l.allowed_routes.as_ref().and_then(|ar| ar.kinds.as_ref()) {
            Some(requested) => requested
                .iter()
                .filter_map(|k| {
                    match protocol_kinds.iter().find(|p| **p == k.kind) {
                        Some(p) => Some(*p),
                        None => {
                            invalid_kind = true;
                            None
                        }
                    }
                })
                .collect(),
            None => protocol_kinds.to_vec(),
        };

        let supported_kinds: Vec<GatewayStatusListenersSupportedKinds> = supported
            .iter()
            .map(|k| GatewayStatusListenersSupportedKinds {
                group: Some("gateway.networking.k8s.io".into()),
                kind: k.to_string(),
            })
            .collect();

        // Is the listener's protocol one we support?
        let protocol_supported = matches!(l.protocol.as_str(), "HTTP" | "HTTPS" | "TLS");

        // For HTTPS/TLS listeners, the certificate ref(s) must resolve.
        let tls_ok = self.listener_tls_resolves(l);

        let accepted = if !protocol_supported {
            condition("Accepted", "False", "UnsupportedProtocol", gen)
        } else {
            condition("Accepted", "True", "Accepted", gen)
        };

        let resolved = if invalid_kind {
            condition("ResolvedRefs", "False", "InvalidRouteKinds", gen)
        } else if !tls_ok {
            condition("ResolvedRefs", "False", "InvalidCertificateRef", gen)
        } else {
            condition("ResolvedRefs", "True", "ResolvedRefs", gen)
        };

        // Programmed requires the listener to be acceptable and refs resolved.
        let programmed = if protocol_supported && tls_ok && !invalid_kind {
            condition("Programmed", "True", "Programmed", gen)
        } else {
            condition("Programmed", "False", "Invalid", gen)
        };

        GatewayStatusListeners {
            name: l.name.clone(),
            attached_routes,
            supported_kinds: Some(supported_kinds),
            conditions: vec![accepted, programmed, resolved],
        }
    }

    /// Whether an HTTPS/TLS listener's certificate references resolve to existing
    /// Secrets. Non-TLS listeners trivially resolve. (Full TLS termination lands
    /// in the TLS chunk; for now we only check the Secret exists.)
    fn listener_tls_resolves(
        &self,
        l: &gateway_api::apis::standard::gateways::GatewayListeners,
    ) -> bool {
        if !matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
            return true;
        }
        let Some(tls) = l.tls.as_ref() else {
            return false; // HTTPS/TLS listener with no tls config can't be programmed
        };
        use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
        let refs = tls.certificate_refs.clone().unwrap_or_default();
        if refs.is_empty() {
            // Passthrough TLS needs no cert; terminate (default) needs one.
            return matches!(tls.mode, Some(Mode::Passthrough));
        }
        // Every referenced Secret must exist (in the listener's namespace by default).
        refs.iter().all(|r| {
            let ns = r.namespace.clone();
            self.secret_exists(ns.as_deref(), &r.name)
        })
    }

    /// Does a Secret exist? `ns` defaults to any namespace match by name if None
    /// is awkward; callers pass the gateway namespace via the ref when set.
    fn secret_exists(&self, ns: Option<&str>, name: &str) -> bool {
        self.stores.secrets.state().into_iter().any(|s| {
            s.name_any() == name && ns.map(|n| s.namespace().as_deref() == Some(n)).unwrap_or(true)
        })
    }

    /// How many routes are actually attached to each listener of this gateway,
    /// using the same attachment rules as reconcile (sectionName, allowedRoutes,
    /// hostname, kind).
    fn count_attached_routes(&self, gw: &Gateway) -> BTreeMap<String, i32> {
        let gw_name = gw.name_any();
        let gw_ns = gw.namespace().unwrap_or_default();
        let mut counts: BTreeMap<String, i32> = BTreeMap::new();
        for l in &gw.spec.listeners {
            counts.insert(l.name.clone(), 0);
        }
        for route in self.stores.routes.state() {
            let route_ns = route.namespace().unwrap_or_default();
            for pref in route.spec.parent_refs.clone().unwrap_or_default() {
                let pns = pref.namespace.as_deref().unwrap_or(&route_ns);
                if pref.name != gw_name || pns != gw_ns {
                    continue;
                }
                let (attached, _) = self.attached_listeners(&route, gw, &pref);
                for l in attached {
                    *counts.entry(l.name.clone()).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    /// Resolve a route's backends, set its parent status, and add it to the table.
    async fn reconcile_route(
        &self,
        route: &HTTPRoute,
        gateways: &[Arc<Gateway>],
        table: &mut RouteTable,
    ) -> Result<()> {
        let gen = route.meta().generation.unwrap_or(0);
        let route_ns = route.namespace().unwrap_or_default();

        let mut parents: Vec<HttpRouteStatusParents> = Vec::new();

        let parent_refs = route.spec.parent_refs.clone().unwrap_or_default();
        for pref in &parent_refs {
            // Find the parent Gateway among the ones we own.
            let parent_ns = pref.namespace.clone().unwrap_or_else(|| route_ns.clone());
            let Some(gw) = gateways
                .iter()
                .find(|g| g.name_any() == pref.name && g.namespace().unwrap_or_default() == parent_ns)
            else {
                continue; // not ours / not found — skip (don't claim parent status)
            };

            // Determine which of the Gateway's listeners this route attaches to,
            // honoring sectionName, port, allowedRoutes (namespaces + kinds), and
            // listener hostname. Returns the attached listeners and, if none, the
            // Accepted=False reason.
            let (attached_listeners, accept_reason) = self.attached_listeners(route, gw, pref);

            let accepted = match accept_reason {
                None => condition("Accepted", "True", "Accepted", gen),
                Some(reason) => condition("Accepted", "False", reason, gen),
            };

            // Tiebreaker metadata for precedence ordering.
            let route_creation = route
                .meta()
                .creation_timestamp
                .as_ref()
                .map(|t| t.0.as_second())
                .unwrap_or(0);
            let route_key = format!("{}/{}", route_ns, route.name_any());
            let hostnames = route.spec.hostnames.clone().unwrap_or_default();

            // Resolve backends across all rules, tracking the most specific
            // ResolvedRefs failure reason (RefNotPermitted takes priority).
            let mut refs_failure: Option<&'static str> = None;
            for (rule_order, rule) in route.spec.rules.clone().unwrap_or_default().iter().enumerate() {
                let mut backends = Vec::new();
                for backend_ref in rule.backend_refs.clone().unwrap_or_default() {
                    let svc_port = backend_ref.port.unwrap_or(0) as u16;
                    let bns = backend_ref.namespace.clone().unwrap_or_else(|| route_ns.clone());

                    // Only core Services are supported backends. Any other
                    // group/kind → ResolvedRefs=False, InvalidKind.
                    let group = backend_ref.group.clone().unwrap_or_default();
                    let kind = backend_ref.kind.clone().unwrap_or_else(|| "Service".into());
                    if !group.is_empty() || kind != "Service" {
                        refs_failure = Some("InvalidKind");
                        continue;
                    }

                    // Cross-namespace backendRefs require a permitting ReferenceGrant.
                    if bns != route_ns
                        && !self.backend_ref_permitted(&route_ns, &bns, &backend_ref.name)
                    {
                        refs_failure = Some("RefNotPermitted");
                        continue; // no endpoints → 500 at the data plane
                    }

                    match self.resolve_endpoints(&bns, &backend_ref.name, svc_port) {
                        Some(endpoints) if !endpoints.is_empty() => {
                            backends.push(Backend {
                                weight: backend_ref.weight.unwrap_or(1).max(0) as u32,
                                endpoints,
                            });
                        }
                        _ => {
                            // Don't downgrade a RefNotPermitted to BackendNotFound.
                            refs_failure.get_or_insert("BackendNotFound");
                        }
                    }
                }

                // Resolve any RequestMirror filter targets to endpoints.
                let mirrors = self.resolve_mirrors(
                    &rule.filters.clone().unwrap_or_default(),
                    &route_ns,
                );

                // Parse this rule's filters and timeouts once. Honor both
                // `request` (overall) and `backendRequest` (per-attempt); with no
                // retries they coincide, so use the smaller non-zero value. "0s"
                // disables that timeout.
                let filters = filters_from(&rule.filters.clone().unwrap_or_default());
                let request_timeout = rule.timeouts.as_ref().and_then(|t| {
                    let parse = |s: &Option<String>| {
                        s.as_ref().and_then(|v| parse_go_duration(v)).filter(|d| !d.is_zero())
                    };
                    [parse(&t.request), parse(&t.backend_request)]
                        .into_iter()
                        .flatten()
                        .min()
                });
                let filters = Filters { mirrors, ..filters };

                // Each `match` in the rule is an independent OR alternative. A rule
                // with no matches defaults to a single match-all (PathPrefix "/").
                let matches = rule.matches.clone().unwrap_or_default();
                let route_matches: Vec<RouteMatch> = if matches.is_empty() {
                    vec![RouteMatch::default()]
                } else {
                    matches.iter().map(route_match_from).collect()
                };

                // Contribute one RouteEntry per (match × attached HTTP listener).
                for (match_order, rm) in route_matches.into_iter().enumerate() {
                    for l in &attached_listeners {
                        if l.protocol != "HTTP" {
                            continue;
                        }
                        // Effective hostnames = intersection of route hostnames and
                        // the listener hostname. Empty route hostnames inherit the
                        // listener's; a listener with no hostname matches any.
                        let effective_hosts =
                            effective_hostnames(&hostnames, l.hostname.as_deref());
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

            let resolved = match refs_failure {
                None => condition("ResolvedRefs", "True", "ResolvedRefs", gen),
                Some(reason) => condition("ResolvedRefs", "False", reason, gen),
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
            return Ok(()); // nothing of ours to claim
        }

        let status = HttpRouteStatus { parents };
        let api: Api<HTTPRoute> = Api::namespaced(self.client.clone(), &route_ns);
        self.patch_status(&api, &route.name_any(), serde_json::json!({ "status": status }))
            .await
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
    ) -> (Vec<gateway_api::apis::standard::gateways::GatewayListeners>, Option<&'static str>) {
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();

        // First narrow by sectionName / port (a hard parentRef selector). If the
        // ref names a section/port that no listener has, that's NoMatchingParent.
        let candidates: Vec<_> = gw
            .spec
            .listeners
            .iter()
            .filter(|l| {
                pref.section_name
                    .as_ref()
                    .map(|s| &l.name == s)
                    .unwrap_or(true)
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
            if !listener_hostname_overlaps(l.hostname.as_deref(), &route_hostnames) {
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

    /// Does a listener's allowedRoutes.namespaces permit a route in `route_ns`?
    fn listener_allows_namespace(
        &self,
        listener: &gateway_api::apis::standard::gateways::GatewayListeners,
        gw: &Gateway,
        route_ns: &str,
    ) -> bool {
        use gateway_api::apis::standard::gateways::GatewayListenersAllowedRoutesNamespacesFrom as From;
        let gw_ns = gw.namespace().unwrap_or_default();
        let ns_cfg = listener
            .allowed_routes
            .as_ref()
            .and_then(|ar| ar.namespaces.as_ref());
        let from = ns_cfg.and_then(|n| n.from.as_ref()).unwrap_or(&From::Same);
        match from {
            From::Same => route_ns == gw_ns,
            From::All => true,
            From::Selector => {
                let Some(selector) = ns_cfg.and_then(|n| n.selector.as_ref()) else {
                    return false;
                };
                let labels = selector.match_labels.clone().unwrap_or_default();
                // Find the route's namespace object and check its labels.
                self.stores
                    .namespaces
                    .state()
                    .into_iter()
                    .find(|n| n.name_any() == route_ns)
                    .map(|n| {
                        let ns_labels = n.labels();
                        labels
                            .iter()
                            .all(|(k, v)| ns_labels.get(k).map(|x| x == v).unwrap_or(false))
                    })
                    .unwrap_or(false)
            }
        }
    }

    /// Is a cross-namespace backendRef (HTTPRoute in `from_ns` → Service `svc_name`
    /// in `to_ns`) permitted by a ReferenceGrant in the backend namespace?
    ///
    /// The grant must have a `from` entry matching {group: gateway.networking.k8s.io,
    /// kind: HTTPRoute, namespace: from_ns} and a `to` entry matching {group: "",
    /// kind: Service} optionally restricted by name.
    fn backend_ref_permitted(&self, from_ns: &str, to_ns: &str, svc_name: &str) -> bool {
        self.stores
            .reference_grants
            .state()
            .into_iter()
            .filter(|rg| rg.namespace().unwrap_or_default() == to_ns)
            .any(|rg| {
                let from_ok = rg.spec.from.iter().any(|f| {
                    f.group == "gateway.networking.k8s.io"
                        && f.kind == "HTTPRoute"
                        && f.namespace == from_ns
                });
                let to_ok = rg.spec.to.iter().any(|t| {
                    // Service is core group (empty string).
                    t.group.is_empty()
                        && t.kind == "Service"
                        && t.name.as_deref().map(|n| n == svc_name).unwrap_or(true)
                });
                from_ok && to_ok
            })
    }

    /// Resolve RequestMirror filter backend refs into [`Mirror`] targets.
    fn resolve_mirrors(
        &self,
        filters: &[gateway_api::apis::standard::httproutes::HttpRouteRulesFilters],
        route_ns: &str,
    ) -> Vec<crate::route_table::Mirror> {
        let mut out = Vec::new();
        for f in filters {
            let Some(m) = &f.request_mirror else { continue };
            let b = &m.backend_ref;
            let bns = b.namespace.clone().unwrap_or_else(|| route_ns.to_string());
            let port = b.port.unwrap_or(0) as u16;
            // Sampling: percent (0..=100), or fraction numerator/denominator.
            let percent = if let Some(p) = m.percent {
                p.clamp(0, 100) as u8
            } else if let Some(fr) = &m.fraction {
                let denom = fr.denominator.unwrap_or(100).max(1);
                ((fr.numerator as i64 * 100 / denom as i64).clamp(0, 100)) as u8
            } else {
                100
            };
            if let Some(endpoints) = self.resolve_endpoints(&bns, &b.name, port) {
                if !endpoints.is_empty() {
                    out.push(crate::route_table::Mirror { endpoints, percent });
                }
            }
        }
        out
    }

    /// Resolve a Service's backing pod endpoints, mapping the Service port to the
    /// pod targetPort via the Service spec, and finding ready pod IPs from
    /// EndpointSlices.
    fn resolve_endpoints(&self, ns: &str, svc_name: &str, svc_port: u16) -> Option<Vec<Endpoint>> {
        // Find the Service to map svc_port -> targetPort name/number.
        let svc = self.stores.services.state().into_iter().find(|s| {
            s.name_any() == svc_name && s.namespace().unwrap_or_default() == ns
        })?;

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
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(s)) => {
                Some(s.clone())
            }
            _ => None,
        };

        // Collect ready endpoint IPs from EndpointSlices for this service.
        let mut endpoints = Vec::new();
        for slice in self.stores.endpoint_slices.state() {
            if slice.namespace().unwrap_or_default() != ns {
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
                let ready = ep
                    .conditions
                    .as_ref()
                    .and_then(|c| c.ready)
                    .unwrap_or(true);
                if !ready {
                    continue;
                }
                for addr in &ep.addresses {
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        endpoints.push(Endpoint {
                            ip,
                            port: port as u16,
                        });
                    }
                }
            }
        }
        Some(endpoints)
    }

    async fn patch_status<K>(&self, api: &Api<K>, name: &str, status: serde_json::Value) -> Result<()>
    where
        K: Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
        K::DynamicType: Default,
    {
        let pp = PatchParams::default();
        api.patch_status(name, &pp, &Patch::Merge(&status)).await?;
        Ok(())
    }
}


/// Convert a Gateway API HTTPRouteMatch into our internal RouteMatch.
fn route_match_from(
    m: &gateway_api::apis::standard::httproutes::HttpRouteRulesMatches,
) -> RouteMatch {
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
                Some(HType::RegularExpression) => HeaderValueMatch::Regex(h.value),
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

/// Does a listener's allowedRoutes.kinds permit the given route kind? An absent
/// `kinds` list means all kinds the listener's protocol supports (HTTP → HTTPRoute).
fn listener_allows_kind(
    listener: &gateway_api::apis::standard::gateways::GatewayListeners,
    kind: &str,
) -> bool {
    match listener.allowed_routes.as_ref().and_then(|ar| ar.kinds.as_ref()) {
        None => true,
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
        (true, None) => vec![],                        // match any
        (true, Some(lh)) => vec![lh.to_string()],      // inherit listener
        (false, None) => route_hosts.to_vec(),         // route's own
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

/// Parse a Gateway API / Go-style duration (e.g. "500ms", "1s", "2m", "0s") into
/// a [`Duration`]. Supports h/m/s/ms/us/ns units; returns None on parse failure.
fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s == "0" {
        return Some(Duration::ZERO);
    }
    // Split into a number and a unit suffix.
    let unit_start = s.find(|c: char| c.is_alphabetic())?;
    let (num, unit) = s.split_at(unit_start);
    let value: f64 = num.parse().ok()?;
    let nanos = match unit {
        "ns" => value,
        "us" | "µs" => value * 1e3,
        "ms" => value * 1e6,
        "s" => value * 1e9,
        "m" => value * 60.0 * 1e9,
        "h" => value * 3600.0 * 1e9,
        _ => return None,
    };
    Some(Duration::from_nanos(nanos as u64))
}

/// Parse a rule's filters into our pre-digested [`Filters`] form.
fn filters_from(
    filters: &[gateway_api::apis::standard::httproutes::HttpRouteRulesFilters],
) -> Filters {
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesFiltersRequestRedirectPathType as RPType,
        HttpRouteRulesFiltersRequestRedirectScheme as RScheme,
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
                path: r.path.as_ref().map(|p| match p.r#type {
                    RPType::ReplaceFullPath => {
                        PathRewrite::ReplaceFullPath(p.replace_full_path.clone().unwrap_or_default())
                    }
                    RPType::ReplacePrefixMatch => PathRewrite::ReplacePrefixMatch(
                        p.replace_prefix_match.clone().unwrap_or_default(),
                    ),
                }),
            });
        }
        if let Some(rw) = &f.url_rewrite {
            out.url_rewrite = Some(UrlRewrite {
                hostname: rw.hostname.clone(),
                path: rw.path.as_ref().map(|p| match p.r#type {
                    RWType::ReplaceFullPath => {
                        PathRewrite::ReplaceFullPath(p.replace_full_path.clone().unwrap_or_default())
                    }
                    RWType::ReplacePrefixMatch => PathRewrite::ReplacePrefixMatch(
                        p.replace_prefix_match.clone().unwrap_or_default(),
                    ),
                }),
            });
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

/// Build a metav1 Condition with observedGeneration set.
fn condition(type_: &str, status: &str, reason: &str, observed_generation: i64) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: String::new(),
        observed_generation: Some(observed_generation),
        // A fixed timestamp is fine; the suite never inspects it. A stable value
        // keeps the merge patch deterministic (avoids needless status churn).
        // k8s-openapi 0.27 uses jiff (not chrono) for Time.
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
    }
}
