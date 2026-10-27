//! Control plane: watch Gateway API + core resources, recompute desired state,
//! write status back, and publish the data-plane [`RouteTable`].
//!
//! Level-triggered and idempotent: any watched-object change triggers a full
//! recompute of the entire world from cached state. We never accumulate deltas.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use futures::{Stream, StreamExt, TryStreamExt};
use gateway_api::apis::standard::backendtlspolicies::{
    BackendTLSPolicy, BackendTlsPolicyStatusAncestors, BackendTlsPolicyStatusAncestorsAncestorRef,
};
use gateway_api::apis::standard::gatewayclasses::{
    GatewayClass, GatewayClassStatus, GatewayClassStatusSupportedFeatures,
};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayStatus, GatewayStatusAddresses, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use gateway_api::apis::standard::httproutes::{HTTPRoute, HttpRouteStatusParents, HttpRouteStatusParentsParentRef};
use gateway_api::apis::standard::referencegrants::ReferenceGrant;
use gateway_api::apis::standard::tlsroutes::{TLSRoute, TlsRouteStatusParents, TlsRouteStatusParentsParentRef};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{ApiResource, DynamicObject, ObjectMeta, PartialObjectMeta, Patch, PatchParams};
use kube::runtime::WatchStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher::{self, Config, metadata_watcher, watcher};
use kube::{Api, Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::cert_store::{CertKey, CertStore};
use crate::route_table::{
    Backend, Endpoint, Filters, HeaderMatch, HeaderMods, HeaderValueMatch, PathMatch, PathRewrite, QueryMatch,
    Redirect, RouteEntry, RouteMatch, RouteTable, Rule, UrlRewrite, normalize_path,
};
use crate::snapshot::{DataPlane, Snapshot};
use crate::tls_table::{TlsAction, TlsBackend, TlsBackends, TlsTable};

/// Our controller name. Must be DOMAIN/PATH and match GatewayClass.spec.controllerName.
pub const CONTROLLER_NAME: &str = "torii.dirba.io/controller";

/// Server-Side Apply field manager for the controller's status writes. Distinct
/// from the ACME subsystem's manager ([`crate::acme::FIELD_MANAGER`]) so the two
/// can own different conditions on the same object without clobbering each other.
const FIELD_MANAGER: &str = "torii-controller";

/// Annotation on the in-memory stand-in for a route that does not decode (see
/// [`route_stand_in`]), holding why the route is rejected. Never written to the
/// API server.
const UNDECODABLE_ANNOTATION: &str = "torii.dirba.io/undecodable";

/// Features we report in GatewayClass.status.supportedFeatures, sorted by name as
/// the spec requires. The conformance suite uses this to decide which tests apply
/// when running a whole profile (without an explicit --supported-features flag).
/// Grow this as features land. [`ReconcileCtx::supported_features`] leaves out
/// the ones the configured ports cannot serve.
///
/// TLSRoute covers passthrough (core) and TLSRouteModeTerminate terminate
/// (extended). We do NOT claim TLSRouteModeMixed: two TLS modes on one port get
/// Accepted=False/ProtocolConflict.
const SUPPORTED_FEATURES: &[&str] = &[
    "BackendTLSPolicy",
    "Gateway",
    "GatewayHTTPListenerIsolation",
    "GatewayPort8080",
    "HTTPRoute",
    "HTTPRoute303RedirectStatusCode",
    "HTTPRoute307RedirectStatusCode",
    "HTTPRoute308RedirectStatusCode",
    "HTTPRouteBackendProtocolWebSocket",
    "HTTPRouteBackendRequestHeaderModification",
    "HTTPRouteBackendTimeout",
    "HTTPRouteCORS",
    "HTTPRouteHostRewrite",
    "HTTPRouteMethodMatching",
    "HTTPRouteNamedRouteRule",
    "HTTPRouteParentRefPort",
    "HTTPRoutePathRedirect",
    "HTTPRoutePathRewrite",
    "HTTPRoutePortRedirect",
    "HTTPRouteQueryParamMatching",
    "HTTPRouteRequestTimeout",
    "HTTPRouteResponseHeaderModification",
    "HTTPRouteSchemeRedirect",
    "ReferenceGrant",
    "TLSRoute",
    "TLSRouteModeTerminate",
];

/// The address we advertise in Gateway.status.addresses — where our proxy listens,
/// reachable by the conformance suite running on the host.
pub struct ControllerConfig {
    pub advertise_address: String,
    /// The ports the data plane serves plain HTTP on (`--http-ports`) and TLS on
    /// (`--tls-ports`). A listener on any other port, or on a port of the other
    /// kind, cannot be served.
    pub http_ports: Vec<u16>,
    pub tls_ports: Vec<u16>,
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
    /// Secrets and ConfigMaps by name and version only: torii needs the data of
    /// the few that listeners and BackendTLSPolicies reference, and reads those
    /// itself (see [`Referenced`]).
    secrets: Store<PartialObjectMeta<Secret>>,
    config_maps: Store<PartialObjectMeta<ConfigMap>>,
    backend_tls_policies: Store<BackendTLSPolicy>,
}

/// The data of the Secrets and ConfigMaps that listeners and BackendTLSPolicies
/// reference, read with a GET whenever the metadata watch shows a new version, and
/// kept only while referenced. Watching every Secret and ConfigMap in full kept
/// every one in the cluster in memory, whatever its size, in the process that
/// faces the internet.
#[derive(Default)]
struct Referenced {
    /// A listener certificate: a Secret's tls.crt and tls.key, parsed, if it has
    /// both.
    secrets: FetchedObjects<Option<CertKey>>,
    /// A BackendTLSPolicy CA bundle: a ConfigMap's ca.crt, if it has one.
    config_maps: FetchedObjects<Option<Arc<[u8]>>>,
}

/// What torii read of some objects, by (namespace, name).
type FetchedObjects<T> = Mutex<HashMap<(String, String), Fetched<T>>>;

/// What torii read of an object, and of which version.
struct Fetched<T> {
    version: Option<String>,
    data: T,
}

/// Run the control plane forever: start watchers, and on any change recompute.
pub async fn run(client: Client, data_plane: DataPlane, config: ControllerConfig) -> Result<()> {
    // A change signal: every watcher event pokes this channel; a single consumer
    // debounces and runs a full reconcile.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

    // For each watched resource: create a reflector store, spawn a watcher that
    // feeds it and pokes `tx` on every event, and yield the store. One macro
    // expansion per resource keeps the wiring in one place. Gateway API kinds
    // (`per_object`) are decoded one object at a time, see [`decoded_watcher`].
    // The `ready` future waits for every store's first list before the initial
    // reconcile. A kind whose list the API server refuses with 404 or 403 (a CRD
    // that is not installed, like TLSRoute or BackendTLSPolicy on an older Gateway
    // API install, or a missing RBAC rule) counts as ready and empty, so it can't
    // hold startup forever; its watcher keeps retrying and fills the store if the
    // kind shows up later.
    let mut ready: Vec<futures::future::BoxFuture<'static, ()>> = Vec::new();
    macro_rules! watch {
        (@reflect $ty:ty, $kind:literal, $events:expr) => {{
            let (store, writer) = reflector::store::<$ty>();
            let tx = tx.clone();
            let absent = Arc::new(tokio::sync::Notify::new());
            let absent_tx = absent.clone();
            let stream = $events.reflect(writer).default_backoff().touched_objects();
            tokio::spawn(async move {
                futures::pin_mut!(stream);
                while let Some(ev) = stream.next().await {
                    match ev {
                        // Non-blocking poke; a pending reconcile already covers us.
                        Ok(_) => { let _ = tx.try_send(()); }
                        Err(e) => {
                            if list_refused(&e) {
                                absent_tx.notify_one();
                            }
                            tracing::warn!(kind = $kind, error = %e, "watch error")
                        }
                    }
                }
            });
            let r = store.clone();
            ready.push(Box::pin(async move {
                tokio::select! {
                    _ = r.wait_until_ready() => {}
                    _ = absent.notified() => tracing::warn!(kind = $kind, "cannot list; starting without it"),
                }
            }));
            store
        }};
        ($ty:ty, $kind:literal, per_object) => {
            watch!(@reflect $ty, $kind, decoded_watcher::<$ty>(client.clone()))
        };
        ($ty:ty, $kind:literal, metadata) => {
            watch!(
                @reflect PartialObjectMeta<$ty>,
                $kind,
                metadata_watcher(Api::<$ty>::all(client.clone()), Config::default()).modify(identity_only)
            )
        };
        ($ty:ty, $kind:literal) => {
            watch!(@reflect $ty, $kind, watcher(Api::<$ty>::all(client.clone()), Config::default()))
        };
    }

    let stores = Arc::new(Stores {
        gateway_classes: watch!(GatewayClass, "GatewayClass", per_object),
        gateways: watch!(Gateway, "Gateway", per_object),
        routes: watch!(HTTPRoute, "HTTPRoute", per_object),
        tls_routes: watch!(TLSRoute, "TLSRoute", per_object),
        services: watch!(Service, "Service"),
        endpoint_slices: watch!(EndpointSlice, "EndpointSlice"),
        reference_grants: watch!(ReferenceGrant, "ReferenceGrant", per_object),
        namespaces: watch!(Namespace, "Namespace"),
        secrets: watch!(Secret, "Secret", metadata),
        config_maps: watch!(ConfigMap, "ConfigMap", metadata),
        backend_tls_policies: watch!(BackendTLSPolicy, "BackendTLSPolicy", per_object),
    });

    // Wait for all caches to populate before the first reconcile. A store fills only
    // when its whole list is in, so a pass before then sees that kind as empty: it
    // would publish a snapshot without its objects (no certificates, no endpoints)
    // and write status as if they did not exist, which the next pass flips back.
    // The data plane binds its ports only after this first snapshot is published.
    futures::future::join_all(ready).await;
    let _ = tx.try_send(());

    tracing::info!(controller = CONTROLLER_NAME, "control plane started");

    let ctx = ReconcileCtx {
        client,
        data_plane,
        config,
        stores,
        referenced: Referenced::default(),
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
        // Block until at least one event arrives, or ACME reports a new state for a
        // listener (which only the controller writes).
        tokio::select! {
            _ = rx.recv() => {}
            () = acme_reported(ctx.config.acme_feed.as_ref()) => {}
        }
        // Coalesce a short burst, then drain so events that arrive *after* this
        // point (e.g. during the reconcile) trigger a fresh pass next iteration.
        tokio::time::sleep(Duration::from_millis(100)).await;
        while rx.try_recv().is_ok() {}

        if let Err(e) = ctx.reconcile_all().await {
            tracing::error!(error = %e, "reconcile failed");
        }
    }
}

/// Keep of a watched object's metadata what identifies it and its version: a
/// tenant can give each Secret and ConfigMap 256 KiB of labels and annotations.
fn identity_only<K>(obj: &mut PartialObjectMeta<K>) {
    let meta = std::mem::take(&mut obj.metadata);
    obj.metadata = ObjectMeta {
        name: meta.name,
        namespace: meta.namespace,
        resource_version: meta.resource_version,
        ..Default::default()
    };
}

/// Resolves when the ACME task reports a changed state; never without `--acme`.
async fn acme_reported(feed: Option<&crate::acme::AcmeFeed>) {
    match feed {
        Some(feed) => feed.reported().await,
        None => std::future::pending().await,
    }
}

/// Whether a watcher error is the API server refusing the initial list for good:
/// the kind does not exist (404) or torii may not list it (403).
fn list_refused(e: &watcher::Error) -> bool {
    matches!(e, watcher::Error::InitialListFailed(kube::Error::Api(ae)) if ae.code == 404 || ae.code == 403)
}

/// Watch every object of a Gateway API kind, decoding each one on its own.
///
/// A typed watcher decodes a whole LIST page as one `ObjectList<K>`, so a single
/// object that the gateway-api types cannot represent (a value only a newer or
/// experimental-channel CRD allows, like an `ExternalAuth` filter or a v1alpha2
/// TLSRoute without `hostnames`) fails every LIST: the store stays empty after a
/// start, or frozen after a re-list, and torii serves none of that kind for
/// anyone. Here the LIST and the watch carry `DynamicObject`s, and
/// [`decode_event`] confines a failure to its own object. Core kinds keep the
/// typed watcher: k8s-openapi models their enums as strings, ignores unknown
/// fields, and the API server enforces their required ones.
fn decoded_watcher<K>(client: Client) -> impl Stream<Item = watcher::Result<watcher::Event<K>>> + Send
where
    K: Resource<DynamicType = ()> + Default + Serialize + DeserializeOwned + Send + 'static,
{
    let api = Api::<DynamicObject>::all_with(client, &ApiResource::erase::<K>(&()));
    watcher(api, Config::default()).try_filter_map(|event| futures::future::ready(Ok(decode_event(event))))
}

/// Decode one event of a [`decoded_watcher`]. An object that does not decode is
/// logged, and then:
/// - a route (an object with `spec.parentRefs`) is replaced by its
///   [`route_stand_in`], so that the Gateways it targets report it;
/// - an object of any other kind is left out, and its `Apply` deletes the older
///   version from the store.
fn decode_event<K>(event: watcher::Event<DynamicObject>) -> Option<watcher::Event<K>>
where
    K: Resource<DynamicType = ()> + Default + Serialize + DeserializeOwned,
{
    use watcher::Event;
    Some(match event {
        Event::Init => Event::Init,
        Event::InitApply(obj) => Event::InitApply(decode_object(obj)?),
        Event::InitDone => Event::InitDone,
        Event::Apply(obj) => {
            let gone = Event::Delete(bare_object(&obj));
            decode_object(obj).map_or(gone, Event::Apply)
        }
        // The store removes by name and namespace only.
        Event::Delete(obj) => Event::Delete(bare_object(&obj)),
    })
}

/// Decode one watched object into `K`, or into its [`route_stand_in`].
fn decode_object<K>(obj: DynamicObject) -> Option<K>
where
    K: Resource<DynamicType = ()> + Default + Serialize + DeserializeOwned,
{
    match serde_json::to_value(&obj).and_then(serde_json::from_value::<K>) {
        Ok(mut k) => {
            // The marker is torii's alone: a copy set by a user rejects nothing.
            if let Some(annotations) = k.meta_mut().annotations.as_mut() {
                annotations.remove(UNDECODABLE_ANNOTATION);
            }
            Some(k)
        }
        Err(e) => {
            tracing::warn!(
                kind = %K::kind(&()),
                namespace = obj.namespace().unwrap_or_default(),
                name = obj.name_any(),
                error = %e,
                "object does not decode"
            );
            route_stand_in(obj, &e)
        }
    }
}

/// The stand-in kept for a route (an object with `spec.parentRefs`) that does not
/// decode: `K`'s default with the route's metadata and parentRefs, and the decode
/// error in [`UNDECODABLE_ANNOTATION`]. It has no rules, so none of it is
/// programmed, and each torii Gateway it targets reports it
/// `Accepted=False`/`UnsupportedValue`, as the spec prescribes for unknown values.
/// None for any other kind, or when the parentRefs do not decode either.
fn route_stand_in<K>(obj: DynamicObject, error: &serde_json::Error) -> Option<K>
where
    K: Resource + Default + Serialize + DeserializeOwned,
{
    let parent_refs = obj.data.get("spec")?.get("parentRefs")?.clone();
    let mut stand_in = serde_json::to_value(K::default()).ok()?;
    stand_in
        .get_mut("spec")?
        .as_object_mut()?
        .insert("parentRefs".into(), parent_refs);
    let mut k: K = serde_json::from_value(stand_in).ok()?;
    *k.meta_mut() = obj.metadata;
    let reason = format!("torii cannot decode this route, so none of it is programmed: {error}");
    k.meta_mut()
        .annotations
        .get_or_insert_default()
        .insert(UNDECODABLE_ANNOTATION.into(), reason);
    Some(k)
}

/// An empty `K` with `obj`'s name and namespace: enough to remove it from a store.
fn bare_object<K: Resource + Default>(obj: &DynamicObject) -> K {
    let mut k = K::default();
    k.meta_mut().name = obj.metadata.name.clone();
    k.meta_mut().namespace = obj.metadata.namespace.clone();
    k
}

struct ReconcileCtx {
    client: Client,
    data_plane: DataPlane,
    config: ControllerConfig,
    stores: Arc<Stores>,
    referenced: Referenced,
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
    protocol: String,
    /// Whether the listener's protocol is one we understand (HTTP/HTTPS/TLS).
    /// Drives the listener `Accepted` condition.
    protocol_supported: bool,
    /// The requested allowedRoutes.kinds invalid for the protocol →
    /// InvalidRouteKinds.
    invalid_kinds: Vec<String>,
    /// The data plane does not serve the listener's protocol on its port (see
    /// [`ControllerConfig::http_ports`]) → Accepted=False/PortUnavailable.
    port_unavailable: bool,
    /// HTTPS/TLS cert-ref failure (reason, message), or None if it resolved (or
    /// N/A).
    tls_failure: Option<Failure>,
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
    /// The Gateway's `spec.tls.frontend` asks for client-certificate validation on
    /// this HTTPS listener (see [`frontend_validation_requested`]). torii does not
    /// implement it, so instead of serving the listener to every client it rejects
    /// it (Accepted=False/UnsupportedValue) and serves none of it: no certificate,
    /// no routes.
    frontend_validation: bool,
}

impl ListenerOutcome {
    /// Accepted: torii can serve the listener as specified.
    fn accepted(&self) -> bool {
        self.protocol_supported && !self.port_unavailable && !self.protocol_conflict && !self.frontend_validation
    }

    /// Why torii does not accept the listener, as (reason, message); None when it
    /// does.
    fn rejection(&self, config: &ControllerConfig) -> Option<Failure> {
        if !self.protocol_supported {
            let msg = format!(
                "protocol {} is not supported: torii serves HTTP, HTTPS and TLS",
                self.protocol
            );
            Some(("UnsupportedProtocol", msg))
        } else if self.port_unavailable {
            let msg = format!(
                "torii serves HTTP on ports {:?} and TLS on ports {:?} (its --http-ports and --tls-ports), so not \
                 this listener on port {}: the listener is not served",
                config.http_ports, config.tls_ports, self.port
            );
            Some(("PortUnavailable", msg))
        } else if self.protocol_conflict {
            let msg = format!(
                "port {} has TLS listeners in both Terminate and Passthrough mode, which torii does not support \
                 on one port",
                self.port
            );
            Some(("ProtocolConflict", msg))
        } else if self.frontend_validation {
            let msg = format!(
                "spec.tls.frontend asks for client certificate validation on port {}, which torii does not \
                 support: the listener is not served",
                self.port
            );
            Some(("UnsupportedValue", msg))
        } else {
            None
        }
    }

    /// Why the listener's references do not resolve, as (reason, message); None
    /// when they do. InvalidRouteKinds first, then the certificate.
    fn refs_failure(&self) -> Option<Failure> {
        if !self.invalid_kinds.is_empty() {
            let msg = format!(
                "allowedRoutes.kinds: torii attaches no {} to a {} listener",
                self.invalid_kinds.join(", "),
                self.protocol
            );
            return Some(("InvalidRouteKinds", msg));
        }
        self.tls_failure.clone()
    }

    /// Why the listener is not programmed, as (reason, message); None when it is:
    /// accepted, with its route kinds and certificate refs valid.
    fn not_programmed(&self, config: &ControllerConfig) -> Option<Failure> {
        self.rejection(config).or_else(|| self.refs_failure())
    }
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
    /// serve traffic, and none of its listeners accepts a route.
    usable: bool,
    invalid_parameters: bool,
    listeners: Vec<ListenerOutcome>,
}

/// A BackendTLSPolicy's CA bundle, from its CA references that resolve, and why
/// each of the others does not.
struct CaBundle {
    /// The PEM of the CAs (empty = wellKnownCACertificates: the system roots), or
    /// None when no reference resolves.
    pem: Option<Vec<u8>>,
    /// Each reference that does not resolve: InvalidKind for a kind other than
    /// ConfigMap, InvalidCACertificateRef for a missing or malformed CA.
    broken: Vec<Failure>,
}

impl CaBundle {
    /// The policy's ResolvedRefs failure: every broken reference, InvalidKind
    /// first.
    fn refs_failure(&self) -> Option<Failure> {
        let reason = ["InvalidKind", "InvalidCACertificateRef"]
            .into_iter()
            .find(|reason| self.broken.iter().any(|(r, _)| r == reason))?;
        let msg: Vec<&str> = self.broken.iter().map(|(_, m)| m.as_str()).collect();
        Some((reason, msg.join("; ")))
    }
}

/// Per-policy status outcome (status side): why the policy is not accepted, and
/// why its references do not resolve (None: True). The usable artifact
/// (re-encrypt or "invalid → 5xx") lives in the [`UpstreamTlsMap`], keyed by
/// target Service.
struct PolicyOutcome {
    not_accepted: Option<Failure>,
    refs_failure: Option<Failure>,
}

/// The Gateways each Service is used through: (namespace, Service name) →
/// (namespace, name) of each Gateway that accepts a route whose backendRef to the
/// Service resolves. These are the ancestors of the Service's BackendTLSPolicies.
type PolicyAncestors = HashMap<(String, String), BTreeSet<(String, String)>>;

/// At most this many ancestors in a BackendTLSPolicy's status (the CRD's limit;
/// the API server refuses a status with more).
const MAX_ANCESTORS: usize = 16;

/// (service-namespace, service-name, service-port) → backend TLS mode for the data
/// plane. Keyed by Service PORT (not just Service) because a BackendTLSPolicy's
/// `sectionName` targets one Service port — two policies on the same Service but
/// different ports both apply, each to its own port. A policy with no sectionName
/// covers every port of the Service. Built once (conflict tiebreak applied) so
/// route resolution and policy status agree. Only `ReEncrypt`/`Invalid` are stored
/// (no policy → absent → the route defaults the endpoint to Plaintext).
type UpstreamTlsMap = HashMap<ServicePort, crate::route_table::BackendTls>;

/// Why a condition is False: its reason and message.
type Failure = (&'static str, String);

/// The attachedRoutes of each listener: (Gateway namespace, Gateway name) →
/// listener name → count.
type AttachCounts = BTreeMap<(String, String), BTreeMap<String, i32>>;

/// A Service port: (namespace, Service name, port number).
type ServicePort = (String, String, u16);

/// The Services that routes send to, as one pass sees them. Each Service port is
/// resolved once per pass, into one list of endpoints that every backendRef to it
/// shares (see [`ReconcileCtx::service_endpoints`]).
struct BackendIndex {
    /// Each Service's EndpointSlices, by (namespace, Service name).
    slices: HashMap<(String, String), Vec<Arc<EndpointSlice>>>,
    /// The BackendTLSPolicy decision for each Service port one covers.
    upstream_tls: UpstreamTlsMap,
    /// The Service ports resolved so far; None for a Service or port that does
    /// not exist.
    resolved: HashMap<ServicePort, Option<Arc<[Endpoint]>>>,
}

impl BackendIndex {
    fn new(slices: Vec<Arc<EndpointSlice>>, upstream_tls: UpstreamTlsMap) -> Self {
        let mut by_service: HashMap<(String, String), Vec<Arc<EndpointSlice>>> = HashMap::new();
        for slice in slices {
            let ns = slice.metadata.namespace.clone().unwrap_or_default();
            let Some(svc) = slice.labels().get("kubernetes.io/service-name").cloned() else {
                continue;
            };
            by_service.entry((ns, svc)).or_default().push(slice);
        }
        BackendIndex {
            slices: by_service,
            upstream_tls,
            resolved: HashMap::new(),
        }
    }
}

/// An HTTPRoute's rules as the data plane runs them, and what they report in the
/// route's status: the same for each of the route's parents.
struct RouteRules {
    /// The rules torii programs: those it implements, and those whose requests get
    /// a 500 because it cannot do what they ask (see [`InvalidRule`]).
    rules: Vec<RouteRule>,
    /// Why none of the route is programmed: it does not decode, or two of its
    /// rules have one name.
    rejected: Option<String>,
    /// How many of the route's rules torii implements.
    implemented: usize,
    /// Why each rule torii does not implement is dropped.
    dropped: Vec<String>,
    /// The backendRefs that did not resolve, for the route's ResolvedRefs.
    broken_refs: BrokenRefs,
    /// The Services its implemented rules' backendRefs resolve to, as (namespace,
    /// name), for the ancestors of their BackendTLSPolicies.
    services: BTreeSet<(String, String)>,
}

impl RouteRules {
    /// Why the route is not accepted where it attaches, if it is not: torii
    /// implements none of it. (A route of which torii implements some rules is
    /// accepted, and PartiallyInvalid.)
    fn rejection(&self) -> Option<String> {
        if let Some(why) = &self.rejected {
            return Some(why.clone());
        }
        (self.implemented == 0 && !self.dropped.is_empty()).then(|| self.dropped.join("; "))
    }
}

/// A route's backendRefs that did not resolve, for its ResolvedRefs condition:
/// (reason, message) for each.
#[derive(Default)]
struct BrokenRefs(Vec<Failure>);

impl BrokenRefs {
    fn add(&mut self, reason: &'static str, message: String) {
        self.0.push((reason, message));
    }

    /// The route's ResolvedRefs condition: one reason, the first of a fixed order
    /// that any broken reference has, and every broken reference in the message.
    fn condition(&self, generation: i64) -> Condition {
        const ORDER: [&str; 4] = [
            "RefNotPermitted",
            "InvalidKind",
            "BackendNotFound",
            "UnsupportedProtocol",
        ];
        match ORDER.into_iter().find(|reason| self.0.iter().any(|(r, _)| r == reason)) {
            None => condition("ResolvedRefs", "True", "ResolvedRefs", "", generation),
            Some(reason) => {
                let msg: Vec<&str> = self.0.iter().map(|(_, m)| m.as_str()).collect();
                condition("ResolvedRefs", "False", reason, &msg.join("; "), generation)
            }
        }
    }
}

/// Why a route attaches to none of the listeners its parentRef selects, from each
/// listener's reason, for its Accepted=False reason and message.
#[derive(Default)]
struct NotAttached {
    /// Listeners that do not allow the route: torii does not serve them, or
    /// their allowedRoutes do not admit it.
    not_allowed: Vec<String>,
    /// Listeners whose hostname matches none of the route's.
    no_hostname: Vec<String>,
}

impl NotAttached {
    /// NotAllowedByListeners wins over NoMatchingListenerHostname (as upstream
    /// when both apply).
    fn reason(self, gw: &Gateway) -> Failure {
        let reason = if !self.not_allowed.is_empty() {
            "NotAllowedByListeners"
        } else if !self.no_hostname.is_empty() {
            "NoMatchingListenerHostname"
        } else {
            "NoMatchingParent"
        };
        let why: Vec<String> = self.not_allowed.into_iter().chain(self.no_hostname).collect();
        (
            reason,
            format!(
                "no listener of Gateway {} takes the route: {}",
                object_name(gw),
                why.join("; ")
            ),
        )
    }
}

/// A TLSRoute's backends, shared by all its SNIs, what they report in its
/// ResolvedRefs, and the Services they are (see [`RouteRules::services`]).
struct TlsRouteBackends {
    backends: Arc<TlsBackends>,
    broken_refs: BrokenRefs,
    services: BTreeSet<(String, String)>,
}

/// A route's backendRef, of either route kind.
struct BackendRef<'a> {
    group: Option<&'a str>,
    kind: Option<&'a str>,
    namespace: Option<&'a str>,
    name: &'a str,
    port: Option<i32>,
}

/// One programmed HTTPRoute rule: what it does, shared by all its entries, and
/// its matches, each shared by its listeners.
struct RouteRule {
    /// The rule's index in the route, for precedence.
    order: usize,
    rule: Arc<Rule>,
    matches: Vec<Arc<RouteMatch>>,
}

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
    /// The apply document's body: `{"status": ...}`, or nothing, which releases
    /// every field the manager owns.
    json: serde_json::Value,
    /// The field manager to apply as.
    manager: String,
    /// The object's version the write was computed from, when it must not
    /// overwrite a newer one (see [`list_status_patch`]).
    resource_version: Option<String>,
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
            patches.extend(self.gatewayclass_patch(gc));
        }

        // Release what torii wrote before that nothing computes any more: its
        // status on a Gateway that left its classes (the class changed, or is
        // gone), and the ACMEIssued conditions that the ACME task used to write
        // under a field manager per listener (the controller writes them now).
        // Applying an empty document under a manager drops the fields it owned,
        // and the CRD defaults come back.
        for gw in self.stores.gateways.state() {
            let owned = owned_class_names.contains(&gw.spec.gateway_class_name);
            for fields in gw.managed_fields() {
                let manager = fields.manager.as_deref().unwrap_or_default();
                let stale = (manager == FIELD_MANAGER && !owned) || manager.starts_with(LEGACY_ACME_MANAGERS);
                if stale && fields.subresource.as_deref() == Some("status") {
                    patches.push(StatusPatch {
                        target: PatchTarget::Gateway,
                        ns: gw.namespace(),
                        name: gw.name_any(),
                        json: serde_json::json!({}),
                        manager: manager.to_string(),
                        resource_version: None,
                    });
                }
            }
        }

        // Gateways whose class we own.
        let gateways: Vec<Arc<Gateway>> = self
            .stores
            .gateways
            .state()
            .into_iter()
            .filter(|gw| owned_class_names.contains(&gw.spec.gateway_class_name))
            .collect();
        self.fetch_referenced(&gateways).await;

        // ── Stage 1: per-Gateway model + CertStore (single TLS validate path) ──
        let mut cert_store = CertStore::default();
        let mut models: Vec<GatewayModel> = Vec::with_capacity(gateways.len());
        for gw in &gateways {
            let model = self.build_gateway_model(gw);
            // Only a usable Gateway contributes certs to the data plane, and only for
            // the listeners it accepts (not one on a port that serves no TLS, or that
            // asks for client-certificate validation).
            if model.usable {
                for l in model.listeners.iter().filter(|l| l.accepted()) {
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
        let mut route_table = RouteTable::default();
        // Every HTTP(S) listener torii serves takes the requests for its hostname
        // on its port, also before (or without) any route: listener isolation.
        for model in models.iter().filter(|m| m.usable) {
            for (l, o) in model.gw.spec.listeners.iter().zip(&model.listeners) {
                if o.accepted() && matches!(l.protocol.as_str(), "HTTP" | "HTTPS") {
                    route_table.listeners.push((o.port, l.hostname.clone()));
                }
            }
        }
        let mut tls_table = crate::tls_table::TlsTable::default();
        let mut backends = BackendIndex::new(self.stores.endpoint_slices.state(), upstream_tls);
        let mut attach_counts = AttachCounts::new();
        let mut ancestors = PolicyAncestors::new();
        for route in &routes {
            let patch = self.process_route(
                route,
                &models,
                &mut backends,
                &mut route_table,
                &mut attach_counts,
                &mut ancestors,
            );
            patches.extend(patch);
        }

        // ── Stage 2c: TLSRoutes → TlsTable (SNI dispatch), parent status, counts.
        // Mirrors HTTPRoute processing but matches on SNI only and produces an L4
        // (passthrough / terminate-then-TCP) data path, not HTTP entries.
        let tls_routes: Vec<Arc<TLSRoute>> = self.stores.tls_routes.state();
        for route in &tls_routes {
            let patch = self.process_tls_route(
                route,
                &models,
                &mut backends,
                &mut tls_table,
                &mut attach_counts,
                &mut ancestors,
            );
            patches.extend(patch);
        }

        // ── Stage 3: derive Gateway + Policy status from the computed data ──
        // The ACME issuance targets come from the same data; their listeners show
        // what ACME last reported for them. Cheap when --acme is off (no feed).
        let acme_targets = self.config.acme_feed.as_ref().map(|_| self.acme_targets(&models));
        let acme_reports = match (&self.config.acme_feed, &acme_targets) {
            (Some(feed), Some(targets)) => feed.reports(targets),
            _ => HashMap::new(),
        };
        for model in &models {
            patches.extend(self.gateway_patch(model, &attach_counts, &acme_reports));
        }
        // Policy ancestors: the Gateways that accept routes to their Services (a
        // rejected Gateway accepts none).
        patches.extend(self.policy_patches(&ancestors, &policy_outcomes));

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

        let flushed = self.flush_status(patches).await;

        if let (Some(feed), Some(targets)) = (&self.config.acme_feed, acme_targets) {
            feed.publish(targets);
        }
        flushed
    }

    /// Build the desired ACME issuance-target set from the reconcile's per-Gateway
    /// models: every ACME-opted-in (`torii.dirba.io/acme` annotation) HTTPS/TLS-terminate
    /// listener with a concrete core-Secret certificateRef. Issuer/email resolve from the
    /// Gateway annotations falling back to the CLI defaults. Wildcard/empty hostnames and
    /// missing issuer/email are NOT filtered here — they're included so ACME reports their
    /// Unsupported/Failed state, matching the old self-listing behaviour.
    fn acme_targets(&self, models: &[GatewayModel]) -> Vec<crate::acme::AcmeTarget> {
        use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
        let mut out = Vec::new();
        // A rejected Gateway serves no certificate.
        for model in models.iter().filter(|m| m.usable) {
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
            for l in &gw.spec.listeners {
                if !matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
                    continue;
                }
                let Some(tls) = l.tls.as_ref() else { continue };
                // Passthrough terminates at the backend; we don't issue for it.
                if matches!(tls.mode, Some(Mode::Passthrough)) {
                    continue;
                }
                // A listener torii does not serve gets no certificate either.
                let Some(outcome) = model.listeners.iter().find(|o| o.name == l.name && o.accepted()) else {
                    continue;
                };
                let hostname = l.hostname.clone().unwrap_or_default();
                // Does a usable cert currently exist for this listener? From the same
                // CertStore-resolution the controller just did. Flips when the cert
                // Secret is created/deleted, so a deletion changes the target set and
                // pokes ACME to re-issue immediately (the Secret name alone is static).
                let has_cert = outcome.resolved_cert.is_some();
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

    /// Apply one deferred status patch to an object of its kind. Each kind supplies
    /// its apiVersion+kind so the patch is a self-contained Server-Side Apply
    /// document (see [`Self::patch_status`]).
    async fn apply_patch(&self, p: StatusPatch) -> Result<()> {
        match p.target {
            PatchTarget::GatewayClass => self.patch_status::<GatewayClass>(p).await,
            PatchTarget::Gateway => self.patch_status::<Gateway>(p).await,
            PatchTarget::HttpRoute => self.patch_status::<HTTPRoute>(p).await,
            PatchTarget::TlsRoute => self.patch_status::<TLSRoute>(p).await,
            PatchTarget::BackendTlsPolicy => self.patch_status::<BackendTLSPolicy>(p).await,
        }
    }

    /// A Secret's cert+key (tls.crt / tls.key), as [`Self::fetch_referenced`] read
    /// it, or why there is none.
    fn load_tls_secret(&self, ns: &str, name: &str) -> Result<CertKey, &'static str> {
        let secrets = self.referenced.secrets.lock().unwrap_or_else(|e| e.into_inner());
        let fetched = secrets
            .get(&(ns.to_string(), name.to_string()))
            .ok_or("was not found")?;
        let ck = fetched.data.clone().ok_or("has no tls.crt and tls.key")?;
        // The same OpenSSL parse the proxy serves.
        ck.parsed()
            .ok_or("does not hold a PEM certificate and key that parse")?;
        Ok(ck)
    }

    /// Bring [`Referenced`] up to date for this pass: the Secrets that `gateways`'
    /// listeners may load (their own namespace's, or another's that a
    /// ReferenceGrant allows), and the ConfigMaps BackendTLSPolicies name.
    async fn fetch_referenced(&self, gateways: &[Arc<Gateway>]) {
        let mut secrets = BTreeSet::new();
        for gw in gateways {
            let gw_ns = gw.namespace().unwrap_or_default();
            let refs = gw
                .spec
                .listeners
                .iter()
                .filter(|l| matches!(l.protocol.as_str(), "HTTPS" | "TLS"))
                .flat_map(|l| l.tls.iter().flat_map(|t| t.certificate_refs.iter().flatten()));
            for r in refs {
                if !r.group.as_deref().unwrap_or("").is_empty() || r.kind.as_deref().unwrap_or("Secret") != "Secret" {
                    continue;
                }
                let ns = r.namespace.clone().unwrap_or_else(|| gw_ns.clone());
                if ns == gw_ns || self.ref_grant_permits(&gw_ns, "Gateway", &ns, "Secret", &r.name) {
                    secrets.insert((ns, r.name.clone()));
                }
            }
        }
        let mut config_maps = BTreeSet::new();
        for policy in self.stores.backend_tls_policies.state() {
            let ns = policy.namespace().unwrap_or_default();
            for r in policy.spec.validation.ca_certificate_refs.iter().flatten() {
                if r.group.is_empty() && r.kind == "ConfigMap" {
                    config_maps.insert((ns.clone(), r.name.clone()));
                }
            }
        }
        futures::join!(
            fetch_referenced(
                &self.client,
                &self.stores.secrets,
                &self.referenced.secrets,
                secrets,
                |s: Secret| {
                    let data = s.data?;
                    Some(CertKey::new(&data.get("tls.crt")?.0, &data.get("tls.key")?.0))
                }
            ),
            fetch_referenced(
                &self.client,
                &self.stores.config_maps,
                &self.referenced.config_maps,
                config_maps,
                |cm: ConfigMap| Some(Arc::from(cm.data?.remove("ca.crt")?.into_bytes())),
            ),
        );
    }

    /// The [`SUPPORTED_FEATURES`] the configured ports can serve: GatewayPort8080
    /// needs 8080 among the HTTP ports, and the TLSRoute features a TLS port.
    fn supported_features(&self) -> Vec<&'static str> {
        SUPPORTED_FEATURES
            .iter()
            .copied()
            .filter(|f| match *f {
                "GatewayPort8080" => self.config.http_ports.contains(&8080),
                "TLSRoute" | "TLSRouteModeTerminate" => !self.config.tls_ports.is_empty(),
                _ => true,
            })
            .collect()
    }

    fn gatewayclass_patch(&self, gc: &GatewayClass) -> Option<StatusPatch> {
        let generation = gc.meta().generation.unwrap_or(0);
        let status = GatewayClassStatus {
            conditions: Some(vec![condition("Accepted", "True", "Accepted", "", generation)]),
            supported_features: Some(
                self.supported_features()
                    .into_iter()
                    .map(|f| GatewayClassStatusSupportedFeatures { name: f.to_string() })
                    .collect(),
            ),
        };
        status_patch(
            PatchTarget::GatewayClass,
            gc.meta(),
            json_of(&gc.status),
            json_of(&status),
        )
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
        let mut invalid_kinds = Vec::new();
        let supported_kinds: Vec<&'static str> = match l.allowed_routes.as_ref().and_then(|ar| ar.kinds.as_ref()) {
            Some(requested) => requested
                .iter()
                .filter_map(|k| match protocol_kinds.iter().find(|p| **p == k.kind) {
                    Some(p) => Some(*p),
                    None => {
                        invalid_kinds.push(k.kind.clone());
                        None
                    }
                })
                .collect(),
            None => protocol_kinds.to_vec(),
        };

        let protocol_supported = matches!(l.protocol.as_str(), "HTTP" | "HTTPS" | "TLS");
        // The data plane serves HTTP on --http-ports and TLS on --tls-ports, and
        // binds nothing else.
        let port = l.port as u16;
        let port_unavailable = match l.protocol.as_str() {
            "HTTP" => !self.config.http_ports.contains(&port),
            "HTTPS" | "TLS" => !self.config.tls_ports.contains(&port),
            _ => false,
        };

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
            protocol: l.protocol.clone(),
            protocol_supported,
            port_unavailable,
            invalid_kinds,
            tls_failure,
            supported_kinds,
            resolved_cert,
            port,
            tls_mode,
            protocol_conflict: false, // filled in across the port in build_gateway_model
            frontend_validation: frontend_validation_requested(gw, l),
        }
    }

    /// The single read+validate+use path for an HTTPS/TLS listener's certificate
    /// ref. Returns `(failure, loaded_cert)`:
    /// - `(None, Some((host, cert)))` — resolved + parsed; serve it (host "" = default).
    /// - `(None, None)` — N/A (non-TLS protocol, or passthrough needs no cert).
    /// - `(Some((reason, message)), None)` — RefNotPermitted (cross-ns w/o grant)
    ///   or InvalidCertificateRef (missing/wrong-kind/malformed). Not served.
    fn listener_cert(
        &self,
        l: &gateway_api::apis::standard::gateways::GatewayListeners,
        gw: &Gateway,
    ) -> (Option<Failure>, Option<(String, CertKey)>) {
        if !matches!(l.protocol.as_str(), "HTTPS" | "TLS") {
            return (None, None);
        }
        use gateway_api::apis::standard::gateways::GatewayListenersTlsMode as Mode;
        let missing = || {
            let msg = format!(
                "a {} listener that terminates TLS needs tls.certificateRefs",
                l.protocol
            );
            (Some(("InvalidCertificateRef", msg)), None)
        };
        let Some(tls) = l.tls.as_ref() else {
            return missing();
        };
        let passthrough = matches!(tls.mode, Some(Mode::Passthrough));
        let refs = tls.certificate_refs.clone().unwrap_or_default();
        if refs.is_empty() {
            // Passthrough needs no cert; terminate without one is invalid.
            return if passthrough { (None, None) } else { missing() };
        }
        let gw_ns = gw.namespace().unwrap_or_default();
        // Key by the listener hostname; "" is the default cert.
        let host = l.hostname.clone().unwrap_or_default();
        let mut loaded: Option<(String, CertKey)> = None;
        for (i, r) in refs.iter().enumerate() {
            // Only core Secrets are valid cert refs.
            let group = r.group.as_deref().unwrap_or("");
            let kind = r.kind.as_deref().unwrap_or("Secret");
            if !group.is_empty() || kind != "Secret" {
                let msg = format!(
                    "certificateRefs[{i}]: {group}/{kind} {} is not a Secret, the only kind torii reads \
                     certificates from",
                    r.name
                );
                return (Some(("InvalidCertificateRef", msg)), None);
            }
            let ref_ns = r.namespace.clone().unwrap_or_else(|| gw_ns.clone());
            // Cross-namespace cert Secret requires a permitting ReferenceGrant.
            if ref_ns != gw_ns && !self.ref_grant_permits(&gw_ns, "Gateway", &ref_ns, "Secret", &r.name) {
                let msg = format!(
                    "certificateRefs[{i}]: Secret {ref_ns}/{} is in another namespace, and no ReferenceGrant there \
                     allows Gateways in {gw_ns} to use it",
                    r.name
                );
                return (Some(("RefNotPermitted", msg)), None);
            }
            // The Secret must exist AND contain a valid tls.crt + tls.key.
            match self.load_tls_secret(&ref_ns, &r.name) {
                Ok(ck) => {
                    // First valid cert is the one we serve for this listener host.
                    loaded.get_or_insert((host.clone(), ck));
                }
                Err(why) => {
                    let msg = format!("certificateRefs[{i}]: Secret {ref_ns}/{} {why}", r.name);
                    return (Some(("InvalidCertificateRef", msg)), None);
                }
            }
        }
        (None, loaded)
    }

    /// STAGE 3: derive a Gateway's status from its computed model + attachment
    /// counts. Conditions come from `ListenerOutcome` DATA, never from conditions.
    fn gateway_patch(
        &self,
        model: &GatewayModel,
        attach_counts: &AttachCounts,
        acme_reports: &crate::acme::AcmeReports,
    ) -> Option<StatusPatch> {
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
                let accepted = match o.rejection(&self.config) {
                    Some((reason, msg)) => condition("Accepted", "False", reason, &msg, generation),
                    None => condition("Accepted", "True", "Accepted", "", generation),
                };
                let resolved = match o.refs_failure() {
                    Some((reason, msg)) => condition("ResolvedRefs", "False", reason, &msg, generation),
                    None => condition("ResolvedRefs", "True", "ResolvedRefs", "", generation),
                };
                // A rejected Gateway serves none of its listeners.
                let programmed = if !model.usable {
                    condition(
                        "Programmed",
                        "False",
                        "Invalid",
                        "the Gateway is not accepted (InvalidParameters), so none of its listeners is served",
                        generation,
                    )
                } else if let Some((reason, msg)) = o.not_programmed(&self.config) {
                    condition(
                        "Programmed",
                        "False",
                        "Invalid",
                        &format!("{reason}: {msg}"),
                        generation,
                    )
                } else {
                    condition("Programmed", "True", "Programmed", "", generation)
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
                // The three standard conditions, and for a listener ACME issues for,
                // `torii.dirba.io/ACMEIssued` as the ACME task last reported it.
                let mut conditions = vec![accepted, programmed, resolved];
                if let Some(r) = acme_reports.get(&(ns.clone(), gw.name_any(), o.name.clone())) {
                    conditions.push(condition(
                        crate::acme::COND_ACME,
                        r.status,
                        r.reason,
                        &r.message,
                        r.generation,
                    ));
                }
                GatewayStatusListeners {
                    name: o.name.clone(),
                    attached_routes,
                    supported_kinds: Some(supported_kinds),
                    conditions,
                }
            })
            .collect();

        // Gateway-level conditions from the OUTCOME DATA (not from the listener
        // conditions above), with the same `accepted`/`programmed` as each listener's:
        // invalid kinds and certificates affect ResolvedRefs/Programmed, not Accepted.
        // A message names the listeners at fault, and why.
        let conditions = if model.invalid_parameters {
            let msg = "spec.infrastructure.parametersRef: torii supports no parameters, so it serves none of this \
                       Gateway";
            vec![
                condition("Accepted", "False", "InvalidParameters", msg, generation),
                condition("Programmed", "False", "InvalidParameters", msg, generation),
            ]
        } else {
            let at_fault = |why: &dyn Fn(&ListenerOutcome) -> Option<Failure>| {
                let names: Vec<String> = model
                    .listeners
                    .iter()
                    .filter_map(|o| why(o).map(|(reason, _)| format!("{} ({reason})", o.name)))
                    .collect();
                names.join(", ")
            };
            let not_accepted = at_fault(&|o| o.rejection(&self.config));
            let not_programmed = at_fault(&|o| o.not_programmed(&self.config));
            let any_accepted = model.listeners.iter().any(ListenerOutcome::accepted);
            let accepted = if !not_accepted.is_empty() {
                let msg = format!("listeners not accepted: {not_accepted}");
                let status = if any_accepted { "True" } else { "False" };
                condition("Accepted", status, "ListenersNotValid", &msg, generation)
            } else {
                condition("Accepted", "True", "Accepted", "", generation)
            };
            let programmed = if not_programmed.is_empty() && any_accepted {
                condition("Programmed", "True", "Programmed", "", generation)
            } else {
                let msg = format!("listeners not programmed: {not_programmed}");
                condition("Programmed", "False", "Invalid", &msg, generation)
            };
            vec![accepted, programmed]
        };

        // The addresses bound for the Gateway: none for a rejected one.
        let addresses = model.usable.then(|| {
            vec![GatewayStatusAddresses {
                r#type: Some("IPAddress".into()),
                value: self.config.advertise_address.clone(),
            }]
        });
        let status = GatewayStatus {
            addresses,
            conditions: Some(conditions),
            listeners: Some(listeners),
            attached_listener_sets: None,
        };
        status_patch(PatchTarget::Gateway, gw.meta(), json_of(&gw.status), json_of(&status))
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

    /// STAGE 2b: build a route's RouteEntries, count its attachment per listener,
    /// and produce its parent status patch (or None if it has no parent we own).
    /// Attachment is computed ONCE here and used for both routing and the
    /// `attachedRoutes` counts (written into `attach_counts`). The rules are the
    /// same for every parent, so they are built once, for the first parent we own.
    fn process_route(
        &self,
        route: &HTTPRoute,
        models: &[GatewayModel],
        backends: &mut BackendIndex,
        table: &mut RouteTable,
        attach_counts: &mut AttachCounts,
        ancestors: &mut PolicyAncestors,
    ) -> Option<StatusPatch> {
        let generation = route.meta().generation.unwrap_or(0);
        let route_ns = route.namespace().unwrap_or_default();

        // Tiebreaker metadata for precedence ordering.
        let route_creation = route
            .meta()
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.as_second())
            .unwrap_or(0);
        let route_key: Arc<str> = format!("{}/{}", route_ns, route.name_any()).into();
        let hostnames: &[String] = route.spec.hostnames.as_deref().unwrap_or_default();

        let mut rules: Option<RouteRules> = None;
        let mut parents: Vec<HttpRouteStatusParents> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        // The listeners the route is programmed on and counted in, once each,
        // however many of its parentRefs select them.
        let mut attached_to = std::collections::HashSet::new();

        for pref in route.spec.parent_refs.iter().flatten() {
            if !is_gateway_ref(pref.group.as_deref(), pref.kind.as_deref()) {
                continue; // a Service (GAMMA) or other kind of parent, not ours
            }
            let parent_ns = pref.namespace.clone().unwrap_or_else(|| route_ns.clone());
            // `{name: gw}` and `{name: gw, namespace: <the route's>}` are one parent:
            // it gets one status entry.
            if !seen.insert((parent_ns.clone(), &pref.name, &pref.section_name, pref.port)) {
                continue;
            }
            // Find the parent Gateway among the ones we own (a rejected one too:
            // the route then learns it is not accepted there).
            let Some(model) = models
                .iter()
                .find(|m| m.gw.name_any() == pref.name && m.gw.namespace().unwrap_or_default() == parent_ns)
            else {
                continue; // not ours / not found — don't claim status
            };
            let gw = &model.gw;

            // Determine which of the Gateway's listeners this route attaches to,
            // honoring sectionName, port, allowedRoutes (namespaces + kinds), and
            // listener hostname. Returns the attached listeners and, if none, the
            // Accepted=False reason. Computed ONCE; drives both counts and routing.
            let (attached_listeners, accept_reason) = self.attached_listeners(route, model, pref);
            let rules = rules.get_or_insert_with(|| self.route_rules(route, backends));
            let rejection = rules.rejection();

            // attachedRoutes counts: ensure every listener has a 0 entry, then
            // increment the ones this route attached to, if it is accepted there
            // (the spec counts only routes with Accepted=True).
            let gw_counts = attach_counts.entry((parent_ns.clone(), gw.name_any())).or_default();
            for l in &gw.spec.listeners {
                gw_counts.entry(l.name.clone()).or_insert(0);
            }
            let attached_listeners: Vec<_> = attached_listeners
                .into_iter()
                .filter(|l| attached_to.insert((parent_ns.clone(), gw.name_any(), l.name.clone())))
                .collect();
            if rejection.is_none() {
                for l in &attached_listeners {
                    *gw_counts.entry(l.name.clone()).or_insert(0) += 1;
                }
            }
            // The Gateway accepts the route: the Services it sends to are used
            // through it.
            if accept_reason.is_none() && rejection.is_none() {
                for svc in &rules.services {
                    ancestors
                        .entry(svc.clone())
                        .or_default()
                        .insert((parent_ns.clone(), gw.name_any()));
                }
            }

            // Contribute one RouteEntry per (attached HTTP(S) listener × match).
            // HTTPS listeners terminate TLS then route HTTP, so they carry
            // HTTPRoute entries too (keyed by the listener port, e.g. 443).
            for l in &attached_listeners {
                if l.protocol != "HTTP" && l.protocol != "HTTPS" {
                    continue;
                }
                // The route's hostnames that overlap the listener's: the data plane
                // matches requests and ranks routes by them. None when the route
                // names none: it then takes any host its listener does, below the
                // routes that name it.
                let route_hosts: Arc<[String]> = hostnames
                    .iter()
                    .filter(|h| l.hostname.as_deref().is_none_or(|lh| hostnames_intersect(lh, h)))
                    .cloned()
                    .collect();
                for r in &rules.rules {
                    for (match_order, m) in r.matches.iter().enumerate() {
                        table.entries.push(RouteEntry {
                            listener_port: l.port as u16,
                            listener_hostname: l.hostname.clone(),
                            hostnames: route_hosts.clone(),
                            r#match: m.clone(),
                            rule: r.rule.clone(),
                            route_creation,
                            route_key: route_key.clone(),
                            rule_order: r.order,
                            match_order,
                        });
                    }
                }
            }

            // Accepted: attachment failure (no listener took the route) wins; then a
            // route torii implements none of → UnsupportedValue + an explanatory
            // message; otherwise Accepted, and PartiallyInvalid if torii dropped
            // some rules (the spec's "Dropped Rule" approach).
            let accepted = match (&accept_reason, &rejection) {
                (Some((reason, msg)), _) => condition("Accepted", "False", reason, msg, generation),
                (None, Some(msg)) => condition("Accepted", "False", "UnsupportedValue", msg, generation),
                (None, None) => condition("Accepted", "True", "Accepted", "", generation),
            };
            let mut conditions = vec![accepted, rules.broken_refs.condition(generation)];
            if accept_reason.is_none() && rejection.is_none() && !rules.dropped.is_empty() {
                let msg = format!("Dropped Rule(s): {}", rules.dropped.join("; "));
                conditions.push(condition(
                    "PartiallyInvalid",
                    "True",
                    "UnsupportedValue",
                    &msg,
                    generation,
                ));
            }

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
                conditions,
            });
        }

        // Other controllers' parents stay; torii's that it no longer has go.
        let parents = parents.iter().map(json_of).collect();
        list_status_patch(
            PatchTarget::HttpRoute,
            route.meta(),
            json_of(&route.status),
            "parents",
            "parentRef",
            parents,
        )
    }

    /// Build an HTTPRoute's rules as the data plane runs them: each rule's backends
    /// resolved and its filters and matches parsed, once for all of the route's
    /// parents and listeners, which share them.
    fn route_rules(&self, route: &HTTPRoute, backends: &mut BackendIndex) -> RouteRules {
        let route_ns = route.namespace().unwrap_or_default();
        let rules = route.spec.rules.as_deref().unwrap_or_default();
        // A route torii cannot decode is a stand-in with no rules (see
        // `route_stand_in`). Rule names must be unique within a route: the
        // experimental channel's CRD rejects such a route, and so does torii.
        let rejected = route
            .annotations()
            .get(UNDECODABLE_ANNOTATION)
            .cloned()
            .or_else(|| duplicate_rule_name(rules.iter().map(|r| r.name.as_deref())));
        let mut out = RouteRules {
            rules: Vec::new(),
            rejected,
            implemented: 0,
            dropped: Vec::new(),
            broken_refs: BrokenRefs::default(),
            services: BTreeSet::new(),
        };
        if out.rejected.is_some() {
            return out;
        }
        for (rule_order, rule) in rules.iter().enumerate() {
            match validate_http_rule(rule_order, rule) {
                None => {}
                // The requests the rule matches cannot be told: they go to other
                // rules (the spec's "Dropped Rule").
                Some(InvalidRule::Unmatchable(why)) => {
                    out.dropped.push(why);
                    continue;
                }
                // torii cannot do what the rule asks of the requests it matches:
                // they get a 500, rather than other rules' treatment without it
                // (an ExtensionRef filter, say an authentication one, MUST NOT be
                // skipped). A rule with no backends or filters answers 500.
                Some(InvalidRule::Unsupported(why)) => {
                    out.dropped.push(format!("{why}, so its requests get HTTP 500"));
                    out.rules.push(RouteRule {
                        order: rule_order,
                        rule: Arc::default(),
                        matches: rule_matches(rule),
                    });
                    continue;
                }
            }
            // Resolve the rule's backends, noting each one that does not resolve.
            let mut rule_backends = Vec::new();
            let mut services = Vec::new();
            for (ref_idx, backend_ref) in rule.backend_refs.iter().flatten().enumerate() {
                let at = format!("rules[{rule_order}].backendRefs[{ref_idx}]");
                let backend = BackendRef {
                    group: backend_ref.group.as_deref(),
                    kind: backend_ref.kind.as_deref(),
                    namespace: backend_ref.namespace.as_deref(),
                    name: &backend_ref.name,
                    port: backend_ref.port,
                };
                match self.resolve_backend(backends, "HTTPRoute", &route_ns, &backend) {
                    // A port whose appProtocol torii cannot speak is invalid (the
                    // spec asks for ResolvedRefs=False/UnsupportedProtocol).
                    Ok((ns, endpoints)) => {
                        let port = backend.port.unwrap_or(0) as u16;
                        if let Some(why) = self.unsupported_app_protocol(backends, &ns, backend.name, port) {
                            out.broken_refs.add("UnsupportedProtocol", format!("{at}: {why}"));
                            continue;
                        }
                        // Service exists (ResolvedRefs=True) — even with zero ready
                        // endpoints, the ref is resolved; an empty backend yields a
                        // 5xx at traffic time, not BackendNotFound.
                        rule_backends.push(Backend {
                            weight: backend_ref.weight.unwrap_or(1).max(0) as u32,
                            endpoints,
                            filters: backend_filters_from(backend_ref.filters.as_deref().unwrap_or_default()),
                        });
                        services.push((ns, backend.name.to_string()));
                    }
                    // Not resolved: no endpoints → 500 at the data plane.
                    Err((reason, why)) => out.broken_refs.add(reason, format!("{at}: {why}")),
                }
            }

            out.implemented += 1;
            out.services.extend(services);
            out.rules.push(RouteRule {
                order: rule_order,
                rule: Arc::new(Rule {
                    backends: rule_backends,
                    filters: filters_from(rule.filters.as_deref().unwrap_or_default()),
                    request_timeout: rule.timeouts.as_ref().and_then(request_timeout_from),
                }),
                matches: rule_matches(rule),
            });
        }
        out
    }

    /// Compute which of a Gateway's listeners an HTTPRoute attaches to.
    ///
    /// Returns the attached listeners and, when none attach, the Accepted=False
    /// reason to report (NoMatchingParent for sectionName/port mismatch;
    /// NotAllowedByListeners for namespace/kind/hostname rejection). A listener
    /// torii does not accept (on a port that does not serve its protocol, or that
    /// asks for client-certificate validation) takes no routes.
    fn attached_listeners(
        &self,
        route: &HTTPRoute,
        model: &GatewayModel,
        pref: &gateway_api::apis::standard::httproutes::HttpRouteParentRefs,
    ) -> (
        Vec<gateway_api::apis::standard::gateways::GatewayListeners>,
        Option<Failure>,
    ) {
        let gw = &model.gw;
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames: &[String] = route.spec.hostnames.as_deref().unwrap_or_default();
        // A rejected Gateway serves nothing, so none of its listeners takes routes.
        if let Some(why) = gateway_not_accepted(model) {
            return (vec![], Some(why));
        }

        // First narrow by sectionName / port (a hard parentRef selector). If the
        // ref names a section/port that no listener has, that's NoMatchingParent.
        let Some(candidates) = selected_listeners(gw, pref.section_name.as_deref(), pref.port) else {
            return (
                vec![],
                Some(no_matching_parent(gw, pref.section_name.as_deref(), pref.port)),
            );
        };

        // Then filter by allowedRoutes (namespaces + kinds) and hostname overlap,
        // noting why each listener was rejected to report the right Accepted reason.
        let mut attached = Vec::new();
        let mut not_attached = NotAttached::default();
        for l in candidates {
            let outcome = model.listeners.iter().find(|o| o.name == l.name);
            if let Some((reason, _)) = outcome.and_then(|o| o.rejection(&self.config)) {
                not_attached
                    .not_allowed
                    .push(format!("{}: not served ({reason})", l.name));
            } else if !self.listener_allows_namespace(&l, gw, &route_ns) {
                let why = format!(
                    "{}: allowedRoutes does not admit routes from namespace {route_ns}",
                    l.name
                );
                not_attached.not_allowed.push(why);
            } else if !listener_allows_kind(&l, "HTTPRoute") {
                let why = format!("{}: allowedRoutes.kinds does not include HTTPRoute", l.name);
                not_attached.not_allowed.push(why);
            } else if !listener_hostname_overlaps(l.hostname.as_deref(), route_hostnames) {
                let why = format!(
                    "{}: its hostname {} matches none of the route's",
                    l.name,
                    l.hostname.as_deref().unwrap_or_default()
                );
                not_attached.no_hostname.push(why);
            } else {
                attached.push(l);
            }
        }

        if attached.is_empty() {
            return (vec![], Some(not_attached.reason(gw)));
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
        backends: &mut BackendIndex,
        tls_table: &mut TlsTable,
        attach_counts: &mut AttachCounts,
        ancestors: &mut PolicyAncestors,
    ) -> Option<StatusPatch> {
        let generation = route.meta().generation.unwrap_or(0);
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames = &route.spec.hostnames;
        // A route torii cannot decode is a stand-in (see `route_stand_in`): it
        // attaches like any other, but programs nothing and reports why. So does a
        // route that names two rules alike (the spec wants rule names unique).
        let rejected = route
            .annotations()
            .get(UNDECODABLE_ANNOTATION)
            .cloned()
            .or_else(|| duplicate_rule_name(route.spec.rules.iter().map(|r| r.name.as_deref())));

        // The backends of all the rules, shared by every matched SNI of every
        // parent: built once, for the first parent we own.
        let mut route_backends: Option<TlsRouteBackends> = None;
        let mut parents: Vec<TlsRouteStatusParents> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut attached_to = std::collections::HashSet::new();

        for pref in route.spec.parent_refs.iter().flatten() {
            if !is_gateway_ref(pref.group.as_deref(), pref.kind.as_deref()) {
                continue;
            }
            let parent_ns = pref.namespace.clone().unwrap_or_else(|| route_ns.clone());
            // One parent named two ways gets one status entry (see process_route).
            if !seen.insert((parent_ns.clone(), &pref.name, &pref.section_name, pref.port)) {
                continue;
            }
            // Find the parent among the Gateways we own.
            let Some(model) = models
                .iter()
                .find(|m| m.gw.name_any() == pref.name && m.gw.namespace().unwrap_or_default() == parent_ns)
            else {
                continue; // not ours / not found
            };
            let gw = &model.gw;

            // Which TLS listeners this route attaches to (sectionName/port +
            // allowedRoutes + SNI hostname overlap + not protocol-conflicted).
            let (attached, accept_reason) = self.attached_tls_listeners(route, gw, model, pref);
            let attached: Vec<_> = attached
                .into_iter()
                .filter(|(l, _)| attached_to.insert((parent_ns.clone(), gw.name_any(), l.name.clone())))
                .collect();

            // attachedRoutes counts: ensure every listener has a 0, then bump ours
            // if the route is accepted.
            let gw_counts = attach_counts.entry((parent_ns.clone(), gw.name_any())).or_default();
            for l in &gw.spec.listeners {
                gw_counts.entry(l.name.clone()).or_insert(0);
            }
            if rejected.is_none() {
                for (l, _) in &attached {
                    *gw_counts.entry(l.name.clone()).or_insert(0) += 1;
                }
            }

            let accepted = match (&accept_reason, &rejected) {
                (Some((reason, msg)), _) => condition("Accepted", "False", reason, msg, generation),
                (None, Some(msg)) => condition("Accepted", "False", "UnsupportedValue", msg, generation),
                (None, None) => condition("Accepted", "True", "Accepted", "", generation),
            };

            let route_backends = route_backends.get_or_insert_with(|| self.tls_route_backends(route, backends));
            if accept_reason.is_none() && rejected.is_none() {
                for svc in &route_backends.services {
                    ancestors
                        .entry(svc.clone())
                        .or_default()
                        .insert((parent_ns.clone(), gw.name_any()));
                }
            }

            // For each attached listener, add its effective SNIs to the dispatch
            // table with the listener's mode (Passthrough vs Terminate). A rejected
            // route must not take its listeners' SNIs.
            if rejected.is_none() {
                for (l, mode) in &attached {
                    let action = match mode {
                        TlsListenerMode::Passthrough => TlsAction::Passthrough(route_backends.backends.clone()),
                        TlsListenerMode::Terminate => TlsAction::Terminate(route_backends.backends.clone()),
                    };
                    for sni in effective_hostnames(route_hostnames, l.hostname.as_deref()) {
                        tls_table.insert(l.port as u16, &sni, action.clone());
                    }
                }
            }

            let resolved = route_backends.broken_refs.condition(generation);

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

        let parents = parents.iter().map(json_of).collect();
        list_status_patch(
            PatchTarget::TlsRoute,
            route.meta(),
            json_of(&route.status),
            "parents",
            "parentRef",
            parents,
        )
    }

    /// Resolve a TLSRoute's backends across all its rules, noting each backendRef
    /// that does not resolve.
    fn tls_route_backends(&self, route: &TLSRoute, backends: &mut BackendIndex) -> TlsRouteBackends {
        let route_ns = route.namespace().unwrap_or_default();
        let mut broken_refs = BrokenRefs::default();
        let mut services = BTreeSet::new();
        let mut out = TlsBackends::default();
        for (rule_idx, rule) in route.spec.rules.iter().enumerate() {
            for (ref_idx, backend_ref) in rule.backend_refs.iter().enumerate() {
                let backend = BackendRef {
                    group: backend_ref.group.as_deref(),
                    kind: backend_ref.kind.as_deref(),
                    namespace: backend_ref.namespace.as_deref(),
                    name: &backend_ref.name,
                    port: backend_ref.port,
                };
                // The endpoints carry any BackendTLSPolicy decision for this Service
                // PORT, as for an HTTPRoute. Only a Terminate listener uses it:
                // Passthrough forwards the client's own TLS.
                match self.resolve_backend(backends, "TLSRoute", &route_ns, &backend) {
                    Ok((ns, endpoints)) => {
                        out.backends.push(TlsBackend {
                            weight: backend_ref.weight.unwrap_or(1).max(0) as u32,
                            endpoints,
                        });
                        services.insert((ns, backend_ref.name.clone()));
                    }
                    Err((reason, why)) => {
                        broken_refs.add(reason, format!("rules[{rule_idx}].backendRefs[{ref_idx}]: {why}"));
                    }
                }
            }
        }
        TlsRouteBackends {
            backends: Arc::new(out),
            broken_refs,
            services,
        }
    }

    /// Compute which of a Gateway's `protocol: TLS` listeners a TLSRoute attaches
    /// to, returning each attached listener paired with its mode. When none
    /// attach, the Accepted=False reason. A listener torii does not accept cannot
    /// accept routes.
    fn attached_tls_listeners(
        &self,
        route: &TLSRoute,
        gw: &Gateway,
        model: &GatewayModel,
        pref: &gateway_api::apis::standard::tlsroutes::TlsRouteParentRefs,
    ) -> (
        Vec<(gateway_api::apis::standard::gateways::GatewayListeners, TlsListenerMode)>,
        Option<Failure>,
    ) {
        let route_ns = route.namespace().unwrap_or_default();
        let route_hostnames = &route.spec.hostnames;
        if let Some(why) = gateway_not_accepted(model) {
            return (vec![], Some(why));
        }

        // Narrow by sectionName / port first (a hard parentRef selector).
        let Some(candidates) = selected_listeners(gw, pref.section_name.as_deref(), pref.port) else {
            return (
                vec![],
                Some(no_matching_parent(gw, pref.section_name.as_deref(), pref.port)),
            );
        };

        let mut attached = Vec::new();
        let mut not_attached = NotAttached::default();
        for l in candidates {
            let outcome = model.listeners.iter().find(|o| o.name == l.name);
            // Only TLS listeners carry TLSRoutes. A non-TLS listener selected by
            // sectionName/port is "not allowed" for this kind.
            let Some((outcome, mode)) = outcome.and_then(|o| Some((o, o.tls_mode?))) else {
                not_attached.not_allowed.push(format!("{}: not a TLS listener", l.name));
                continue;
            };
            // A listener torii does not accept (mixed termination on its port, or a
            // port that serves no TLS) accepts no routes. Nor does a Terminate one
            // whose certificate did not resolve: it is not programmed, and must not
            // terminate its routes' TLS with another certificate.
            if let Some((reason, _)) = outcome.rejection(&self.config) {
                not_attached
                    .not_allowed
                    .push(format!("{}: not served ({reason})", l.name));
            } else if let (TlsListenerMode::Terminate, Some((reason, _))) = (mode, &outcome.tls_failure) {
                let why = format!("{}: its certificate did not resolve ({reason})", l.name);
                not_attached.not_allowed.push(why);
            } else if !self.listener_allows_namespace(&l, gw, &route_ns) {
                let why = format!(
                    "{}: allowedRoutes does not admit routes from namespace {route_ns}",
                    l.name
                );
                not_attached.not_allowed.push(why);
            } else if !listener_allows_kind(&l, "TLSRoute") {
                let why = format!("{}: allowedRoutes.kinds does not include TLSRoute", l.name);
                not_attached.not_allowed.push(why);
            } else if !listener_hostname_overlaps(l.hostname.as_deref(), route_hostnames) {
                let why = format!(
                    "{}: its hostname {} matches none of the route's",
                    l.name,
                    l.hostname.as_deref().unwrap_or_default()
                );
                not_attached.no_hostname.push(why);
            } else {
                attached.push((l, mode));
            }
        }

        if attached.is_empty() {
            return (vec![], Some(not_attached.reason(gw)));
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
                let msg = format!(
                    "targetRef {}/{} {} is not a core Service",
                    if bad.group.is_empty() { "core" } else { &bad.group },
                    bad.kind,
                    bad.name,
                );
                let outcome = PolicyOutcome {
                    not_accepted: Some(("NoValidCACertificate", msg.clone())),
                    refs_failure: Some(("InvalidKind", msg)),
                };
                outcomes.insert(pol_key, outcome);
                continue;
            }

            let ca = self.resolve_policy_ca(policy, &pol_ns);
            let refs_failure = ca.refs_failure();

            // No CA resolves: report it, and mark every Service PORT the policy
            // targets as Invalid so the data plane 5xxes (no plaintext fallback) —
            // but never overwrite a valid ReEncrypt artifact.
            let Some(ca_pem) = ca.pem else {
                let msg = refs_failure.as_ref().map(|(_, m)| m.as_str()).unwrap_or_default();
                let outcome = PolicyOutcome {
                    not_accepted: Some(("NoValidCACertificate", format!("no CA certificate resolves: {msg}"))),
                    refs_failure,
                };
                outcomes.insert(pol_key, outcome);
                for t in &policy.spec.target_refs {
                    for port in self.target_ports(&pol_ns, &t.name, &t.section_name) {
                        artifacts
                            .entry((pol_ns.clone(), t.name.clone(), port))
                            .or_insert(BackendTls::Invalid);
                    }
                }
                continue;
            };

            // Valid policy: claim each target section; first claimant wins. A policy
            // that loses any target is Conflicted (the spec: one that does not take
            // precedence), and still applies to the targets it won.
            let upstream = Arc::new(crate::route_table::UpstreamTls {
                hostname: policy.spec.validation.hostname.clone(),
                ca_pem,
            });
            let mut lost = Vec::new();
            for t in &policy.spec.target_refs {
                // Conflict key includes sectionName (per spec): two policies on the
                // same Service with different/absent sections do NOT conflict.
                let ckey = (pol_ns.clone(), t.name.clone(), t.section_name.clone());
                if let Some((winner_ns, winner)) = winners.get(&ckey) {
                    let section = t
                        .section_name
                        .as_ref()
                        .map(|s| format!(" port {s}"))
                        .unwrap_or_default();
                    lost.push(format!(
                        "Service {pol_ns}/{}{section}: BackendTLSPolicy {winner_ns}/{winner} takes precedence (it is \
                         older, or first by name)",
                        t.name
                    ));
                    continue;
                }
                winners.insert(ckey, pol_key.clone());
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
                    artifacts.insert(pkey.clone(), BackendTls::ReEncrypt(upstream.clone()));
                    if specific {
                        port_specific.insert(pkey);
                    }
                }
            }
            let outcome = PolicyOutcome {
                not_accepted: (!lost.is_empty()).then(|| ("Conflicted", lost.join("; "))),
                refs_failure,
            };
            outcomes.insert(pol_key, outcome);
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
        // Only TCP ports: routes reach backends over TCP, and a UDP port may share
        // its number with the TCP one the policy does not name.
        tcp_service_ports(&svc)
            // sectionName = a specific Service port name; none → all its ports.
            .filter(|p| section.is_none() || p.name.as_ref() == section.as_ref())
            .map(|p| p.port as u16)
            .collect()
    }

    /// Resolve + validate a policy's CA bundle. The single CA validation path —
    /// both the artifact and the status derive from its [`CaBundle`]: the CAs of
    /// the references that resolve, and why each of the others does not.
    fn resolve_policy_ca(&self, policy: &BackendTLSPolicy, pol_ns: &str) -> CaBundle {
        let v = &policy.spec.validation;
        let Some(refs) = &v.ca_certificate_refs else {
            // No explicit CA refs: valid only if it uses well-known CAs.
            return if v.well_known_ca_certificates.is_some() {
                CaBundle {
                    pem: Some(Vec::new()), // system roots
                    broken: Vec::new(),
                }
            } else {
                let msg = "neither caCertificateRefs nor wellKnownCACertificates is set".to_string();
                CaBundle {
                    pem: None,
                    broken: vec![("InvalidCACertificateRef", msg)],
                }
            };
        };
        let mut pem = Vec::new();
        let mut resolved = false;
        let mut broken = Vec::new();
        for (i, r) in refs.iter().enumerate() {
            if !r.group.is_empty() || r.kind != "ConfigMap" {
                let group = if r.group.is_empty() { "core" } else { &r.group };
                let msg = format!(
                    "caCertificateRefs[{i}]: {group}/{} {} is not a ConfigMap, the only kind torii reads CA \
                     certificates from",
                    r.kind, r.name
                );
                broken.push(("InvalidKind", msg));
                continue;
            }
            match self.load_configmap_ca(pol_ns, &r.name) {
                Err(why) => {
                    let msg = format!("caCertificateRefs[{i}]: ConfigMap {pol_ns}/{} {why}", r.name);
                    broken.push(("InvalidCACertificateRef", msg));
                }
                Ok(bytes) if !ca_pem_is_valid(&bytes) => {
                    let msg = format!(
                        "caCertificateRefs[{i}]: ca.crt of ConfigMap {pol_ns}/{} holds no PEM certificate",
                        r.name
                    );
                    broken.push(("InvalidCACertificateRef", msg));
                }
                Ok(bytes) => {
                    pem.extend_from_slice(&bytes);
                    pem.push(b'\n');
                    resolved = true;
                }
            }
        }
        CaBundle {
            pem: resolved.then_some(pem),
            broken,
        }
    }

    /// STAGE 3: build each BackendTLSPolicy's status patch. Its ancestors are the
    /// Gateways that route processing found its target Services used through
    /// (`ancestors`): they accept a route whose backendRef to the Service resolves,
    /// so is allowed by a ReferenceGrant where it crosses namespaces. Attachment
    /// and grants depend on no policy, so this makes no cycle. The per-policy
    /// Accepted/ResolvedRefs come from the already-computed [`PolicyOutcome`].
    fn policy_patches(
        &self,
        ancestors: &PolicyAncestors,
        outcomes: &BTreeMap<(String, String), PolicyOutcome>,
    ) -> Vec<StatusPatch> {
        let mut patches = Vec::new();
        for policy in self.stores.backend_tls_policies.state() {
            let generation = policy.meta().generation.unwrap_or(0);
            let pol_ns = policy.namespace().unwrap_or_default();
            let Some(outcome) = outcomes.get(&(pol_ns.clone(), policy.name_any())) else {
                continue;
            };
            let accepted = match &outcome.not_accepted {
                None => condition("Accepted", "True", "Accepted", "", generation),
                Some((reason, msg)) => condition("Accepted", "False", reason, msg, generation),
            };
            let resolved = match &outcome.refs_failure {
                None => condition("ResolvedRefs", "True", "ResolvedRefs", "", generation),
                Some((reason, msg)) => condition("ResolvedRefs", "False", reason, msg, generation),
            };

            // In (namespace, name) order, and no more than the CRD allows: GEP-713
            // says to add no further entries once the list is full.
            let gateways: BTreeSet<&(String, String)> = policy
                .spec
                .target_refs
                .iter()
                .filter_map(|t| ancestors.get(&(pol_ns.clone(), t.name.clone())))
                .flatten()
                .collect();
            if gateways.len() > MAX_ANCESTORS {
                tracing::warn!(
                    namespace = pol_ns,
                    name = policy.name_any(),
                    ancestors = gateways.len(),
                    "BackendTLSPolicy has more ancestors than its status can list; listing the first {MAX_ANCESTORS}"
                );
            }
            let ancestors: Vec<BackendTlsPolicyStatusAncestors> = gateways
                .into_iter()
                .take(MAX_ANCESTORS)
                .map(|(gw_ns, gw_name)| BackendTlsPolicyStatusAncestors {
                    ancestor_ref: BackendTlsPolicyStatusAncestorsAncestorRef {
                        group: Some("gateway.networking.k8s.io".into()),
                        kind: Some("Gateway".into()),
                        name: gw_name.clone(),
                        namespace: Some(gw_ns.clone()),
                        port: None,
                        section_name: None,
                    },
                    controller_name: CONTROLLER_NAME.to_string(),
                    conditions: vec![accepted.clone(), resolved.clone()],
                })
                .collect();
            // Other controllers' ancestors stay; torii's that it no longer has go.
            patches.extend(list_status_patch(
                PatchTarget::BackendTlsPolicy,
                policy.meta(),
                json_of(&policy.status),
                "ancestors",
                "ancestorRef",
                ancestors.iter().map(json_of).collect(),
            ));
        }
        patches
    }

    /// A ConfigMap's CA bundle (ca.crt), as [`Self::fetch_referenced`] read it, or
    /// why there is none.
    fn load_configmap_ca(&self, ns: &str, name: &str) -> Result<Arc<[u8]>, &'static str> {
        let config_maps = self.referenced.config_maps.lock().unwrap_or_else(|e| e.into_inner());
        let fetched = config_maps
            .get(&(ns.to_string(), name.to_string()))
            .ok_or("was not found")?;
        fetched.data.clone().ok_or("has no ca.crt")
    }

    /// The endpoints of Service port `ns/name:port`, with the port's BackendTLSPolicy
    /// decision. Resolved once per pass (see [`BackendIndex`]); None when the
    /// Service or the port does not exist.
    fn service_endpoints(&self, index: &mut BackendIndex, ns: &str, name: &str, port: u16) -> Option<Arc<[Endpoint]>> {
        let key = (ns.to_string(), name.to_string(), port);
        if let Some(endpoints) = index.resolved.get(&key) {
            return endpoints.clone();
        }
        let endpoints = self.resolve_endpoints(index, ns, name, port).map(Arc::from);
        index.resolved.insert(key, endpoints.clone());
        endpoints
    }

    /// Resolve a route's backendRef, from a route of `route_kind` in `route_ns`:
    /// its namespace and the endpoints of its Service port, or why it does not
    /// resolve, as (ResolvedRefs reason, message).
    fn resolve_backend(
        &self,
        index: &mut BackendIndex,
        route_kind: &str,
        route_ns: &str,
        backend: &BackendRef,
    ) -> Result<(String, Arc<[Endpoint]>), Failure> {
        let name = backend.name;
        let ns = backend.namespace.unwrap_or(route_ns);
        // Only core Services are supported backends.
        let group = backend.group.unwrap_or("");
        let kind = backend.kind.unwrap_or("Service");
        if !group.is_empty() || kind != "Service" {
            let msg = format!("{group}/{kind} {name} is not a Service, the only kind of backend torii supports");
            return Err(("InvalidKind", msg));
        }
        // Cross-namespace backendRefs require a permitting ReferenceGrant.
        if ns != route_ns && !self.ref_grant_permits(route_ns, route_kind, ns, "Service", name) {
            let msg = format!(
                "Service {ns}/{name} is in another namespace, and no ReferenceGrant there allows {route_kind}s in \
                 {route_ns} to use it"
            );
            return Err(("RefNotPermitted", msg));
        }
        let port = backend.port.unwrap_or(0) as u16;
        match self.service_endpoints(index, ns, name, port) {
            Some(endpoints) => Ok((ns.to_string(), endpoints)),
            None if find_in(&self.stores.services, ns, name).is_none() => {
                Err(("BackendNotFound", format!("Service {ns}/{name} was not found")))
            }
            None => Err(("BackendNotFound", format!("Service {ns}/{name} has no TCP port {port}"))),
        }
    }

    /// Why an HTTPRoute cannot send to Service port `ns/name:port` with the protocol
    /// its `appProtocol` names, if it cannot: torii speaks HTTP/1.1 to backends,
    /// over TLS only where a BackendTLSPolicy covers the port. None also when the
    /// port does not exist (that is reported as a missing backend).
    fn unsupported_app_protocol(&self, index: &BackendIndex, ns: &str, name: &str, port: u16) -> Option<String> {
        let svc = find_in(&self.stores.services, ns, name)?;
        let app = tcp_service_ports(&svc)
            .find(|p| p.port == port as i32)?
            .app_protocol
            .clone()?;
        let tls = index
            .upstream_tls
            .contains_key(&(ns.to_string(), name.to_string(), port));
        match app.to_ascii_lowercase().as_str() {
            "http" | "kubernetes.io/ws" => None,
            "https" | "kubernetes.io/wss" if tls => None,
            "https" | "kubernetes.io/wss" => Some(format!(
                "Service {ns}/{name} port {port} has appProtocol {app}, and no BackendTLSPolicy for it tells torii how \
                 to verify the backend's TLS"
            )),
            _ => Some(format!(
                "Service {ns}/{name} port {port} has appProtocol {app}, which torii does not speak to backends"
            )),
        }
    }

    /// Resolve a Service port's ready endpoints from the Service's EndpointSlices,
    /// as kube-proxy does: in each slice, the port named like the Service port (the
    /// EndpointSlice controller names slice ports after Service ports, and resolves
    /// `targetPort` into their numbers per pod). `targetPort` is never read here: a
    /// named one is a container port name, and a selector-less Service's slices are
    /// written by hand with any port.
    fn resolve_endpoints(
        &self,
        index: &BackendIndex,
        ns: &str,
        svc_name: &str,
        svc_port: u16,
    ) -> Option<Vec<Endpoint>> {
        // Find the Service port, for its name and protocol.
        let svc = find_in(&self.stores.services, ns, svc_name)?;

        let port_spec = tcp_service_ports(&svc).find(|p| p.port == svc_port as i32)?;
        let port_name = port_spec.name.as_deref().unwrap_or_default();
        // Plaintext by default; a BackendTLSPolicy targeting this Service port
        // re-encrypts (or, when invalid, fails every request).
        let tls = index
            .upstream_tls
            .get(&(ns.to_string(), svc_name.to_string(), svc_port))
            .cloned()
            .unwrap_or_default();

        // Collect ready endpoint IPs from EndpointSlices for this service.
        let mut endpoints = Vec::new();
        let slices = index.slices.get(&(ns.to_string(), svc_name.to_string()));
        for slice in slices.into_iter().flatten() {
            // Route to IP endpoints of either family. The data plane dials an
            // (IpAddr, port), which works for v4 and v6 alike. Skip FQDN slices:
            // their "addresses" are DNS names, not IPs, so they don't parse below
            // (and would need separate resolution we don't do).
            if slice.address_type != "IPv4" && slice.address_type != "IPv6" {
                continue;
            }

            // The Service port's number on this slice; a slice without it serves
            // other ports of the Service only.
            let port = slice.ports.iter().flatten().find(|p| {
                p.name.as_deref().unwrap_or_default() == port_name && p.protocol.as_deref().unwrap_or("TCP") == "TCP"
            });
            let Some(port) = port.and_then(|p| p.port) else {
                continue;
            };

            for ep in &slice.endpoints {
                let ready = ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);
                if !ready {
                    continue;
                }
                // An endpoint's addresses are fungible, and consumers may use only
                // the first (EndpointSlice API); an endpoint may list 100.
                if let Some(ip) = ep.addresses.first().and_then(|a| a.parse::<IpAddr>().ok()) {
                    endpoints.push(Endpoint {
                        ip,
                        port: port as u16,
                        tls: tls.clone(),
                    });
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
    /// document (apiVersion/kind/metadata.name) as SSA requires. The API server
    /// answers with the whole object, read as a `DynamicObject`: a route that
    /// torii keeps as a stand-in does not decode into `K` (see [`route_stand_in`]).
    async fn patch_status<K>(&self, p: StatusPatch) -> Result<()>
    where
        K: Resource<DynamicType = ()>,
    {
        let resource = ApiResource::erase::<K>(&());
        let api: Api<DynamicObject> = match &p.ns {
            Some(ns) => Api::namespaced_with(self.client.clone(), ns, &resource),
            None => Api::all_with(self.client.clone(), &resource),
        };
        let mut doc = serde_json::json!({
            "apiVersion": resource.api_version,
            "kind": resource.kind,
            "metadata": { "name": p.name },
        });
        // A precondition: the API server refuses the write if the object changed.
        if let Some(version) = &p.resource_version {
            doc["metadata"]["resourceVersion"] = version.clone().into();
        }
        // Merge the computed `{"status": ...}` into the apply document.
        if let (Some(obj), Some(extra)) = (doc.as_object_mut(), p.json.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        let pp = PatchParams::apply(&p.manager).force();
        let name = &p.name;
        match api.patch_status(name, &pp, &Patch::Apply(&doc)).await {
            Ok(_) => Ok(()),
            // The object was deleted between our cache snapshot and this write —
            // there's nothing to update. Don't abort the whole reconcile pass.
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                tracing::debug!(name, "status target gone (404), skipping");
                Ok(())
            }
            // Someone wrote the object since the pass read it: that write's event
            // starts a new pass, which writes from the newer version.
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                tracing::debug!(name, "status target changed meanwhile (409), skipping");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Why torii does not implement an HTTPRoute rule whose values the CRD accepts.
#[derive(Debug, PartialEq)]
enum InvalidRule {
    /// A match torii cannot evaluate: which requests the rule takes cannot be
    /// told, so it is left out and they go to other rules.
    Unmatchable(String),
    /// torii can tell which requests the rule takes, but not do what the rule asks
    /// of them (a filter it does not implement, or a value it cannot use): they
    /// get a 500.
    Unsupported(String),
}

/// Validate one HTTPRoute rule for values that are CRD-valid but that torii
/// can't honor, and say why for the first one found. The route then reports the
/// rule dropped (`PartiallyInvalid`, or `Accepted=False`/`UnsupportedValue` when
/// it has no rule torii implements) — never silently.
fn validate_http_rule(
    rule_idx: usize,
    rule: &gateway_api::apis::standard::httproutes::HttpRouteRules,
) -> Option<InvalidRule> {
    use InvalidRule::{Unmatchable, Unsupported};
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesBackendRefsFiltersType as BType, HttpRouteRulesFiltersType as FType,
        HttpRouteRulesMatchesHeadersType as HType, HttpRouteRulesMatchesPathType as PType,
        HttpRouteRulesMatchesQueryParamsType as QType,
    };
    let at = format!("rules[{rule_idx}]");

    for (mi, m) in rule.matches.iter().flatten().enumerate() {
        // Path: RegularExpression is implementation-specific and not implemented.
        if let Some(p) = &m.path
            && matches!(p.r#type, Some(PType::RegularExpression))
        {
            return Some(Unmatchable(format!(
                "{at}.matches[{mi}].path: RegularExpression path matching is not supported"
            )));
        }
        // Path: the data plane refuses a request whose `;params` decide its route (see
        // `proxy::decide`), so a value with them would only refuse.
        if let Some(p) = &m.path
            && p.value.as_deref().is_some_and(|v| v.contains(';'))
        {
            return Some(Unmatchable(format!(
                "{at}.matches[{mi}].path: ';' path parameters are not supported"
            )));
        }
        // Header match: a RegularExpression value must compile. The message
        // quotes the start of the value and the error's last line only: the value
        // can be 4096 characters, and the error repeats it.
        for (hi, h) in m.headers.iter().flatten().enumerate() {
            if matches!(h.r#type, Some(HType::RegularExpression))
                && let Err(e) = regex::Regex::new(&h.value)
            {
                let start: String = h.value.chars().take(64).collect();
                let more = if start.len() < h.value.len() { "…" } else { "" };
                let e = e.to_string();
                let why = e.lines().rfind(|l| !l.trim().is_empty()).unwrap_or_default().trim();
                return Some(Unmatchable(format!(
                    "{at}.matches[{mi}].headers[{hi}]: invalid RegularExpression {start:?}{more}: {why}"
                )));
            }
        }
        // Query params: RegularExpression is not implemented (we match Exact only).
        for (qi, q) in m.query_params.iter().flatten().enumerate() {
            if matches!(q.r#type, Some(QType::RegularExpression)) {
                return Some(Unmatchable(format!(
                    "{at}.matches[{mi}].queryParams[{qi}]: RegularExpression query matching is not supported"
                )));
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
                return Some(Unsupported(format!(
                    "{at}.filters[{fi}]: RequestMirror is not supported"
                )));
            }
            FType::ExtensionRef => {
                return Some(Unsupported(format!(
                    "{at}.filters[{fi}]: ExtensionRef filters are not supported"
                )));
            }
        }
        // Redirect status code must be a valid HTTP redirect code.
        if let Some(r) = &f.request_redirect
            && let Some(code) = r.status_code
            && !matches!(code, 301 | 302 | 303 | 307 | 308)
        {
            return Some(Unsupported(format!(
                "{at}.filters[{fi}].requestRedirect.statusCode: unsupported value {code}"
            )));
        }
    }
    // A backendRef's own filters: torii applies the header modifiers only.
    for (bi, b) in rule.backend_refs.iter().flatten().enumerate() {
        for (fi, f) in b.filters.iter().flatten().enumerate() {
            if !matches!(f.r#type, BType::RequestHeaderModifier | BType::ResponseHeaderModifier) {
                let ty = serde_json::to_value(&f.r#type).unwrap_or_default();
                let ty = ty.as_str().unwrap_or_default();
                return Some(Unsupported(format!(
                    "{at}.backendRefs[{bi}].filters[{fi}]: {ty} filters on a backendRef are not supported"
                )));
            }
        }
    }

    // Timeouts: a present-but-unparseable GEP-2257 duration would otherwise be
    // silently dropped (no timeout enforced).
    if let Some(t) = &rule.timeouts {
        for (field, val) in [("request", &t.request), ("backendRequest", &t.backend_request)] {
            if let Some(s) = val
                && parse_gep2257_duration(s).is_none()
            {
                return Some(Unsupported(format!("{at}.timeouts.{field}: invalid duration {s:?}")));
            }
        }
    }

    None
}

/// The first rule name that an earlier rule of the route has too, as a message:
/// the spec wants them unique within a route.
fn duplicate_rule_name<'a>(names: impl Iterator<Item = Option<&'a str>>) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    names.enumerate().find_map(|(i, name)| {
        let name = name?;
        (!seen.insert(name)).then(|| format!("rules[{i}].name: an earlier rule is named {name:?} too"))
    })
}

/// A rule's matches. Each `match` in the rule is an independent OR alternative;
/// a rule with no matches defaults to a single match-all (PathPrefix "/").
fn rule_matches(rule: &gateway_api::apis::standard::httproutes::HttpRouteRules) -> Vec<Arc<RouteMatch>> {
    match rule.matches.as_deref() {
        None | Some([]) => vec![Arc::default()],
        Some(matches) => matches.iter().map(|m| Arc::new(route_match_from(m))).collect(),
    }
}

/// Convert a Gateway API HTTPRouteMatch into our internal RouteMatch.
fn route_match_from(m: &gateway_api::apis::standard::httproutes::HttpRouteRulesMatches) -> RouteMatch {
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesMatchesHeadersType as HType, HttpRouteRulesMatchesPathType as PType,
    };

    let path = m.path.as_ref().map(|p| {
        let value = p.value.clone().unwrap_or_else(|| "/".into());
        // Requests are matched in their normal form, so the value must be in it too:
        // `/%61dmin` is `/admin`. Values that have none match no request anyway.
        let value = normalize_path(value.as_bytes(), true).unwrap_or(value);
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

/// `namespace/name` of an object, for messages.
fn object_name(obj: &impl Resource) -> String {
    format!("{}/{}", obj.namespace().unwrap_or_default(), obj.name_any())
}

/// Why a Gateway takes no routes because torii rejected it, as an Accepted=False
/// reason and message for them.
fn gateway_not_accepted(model: &GatewayModel) -> Option<Failure> {
    let msg = format!(
        "Gateway {} is not accepted, so none of its listeners takes routes",
        object_name(&*model.gw)
    );
    (!model.usable).then_some(("NotAllowedByListeners", msg))
}

/// The listeners of `gw` that a parentRef's sectionName and port select, or None
/// when it selects none.
fn selected_listeners(
    gw: &Gateway,
    section_name: Option<&str>,
    port: Option<i32>,
) -> Option<Vec<gateway_api::apis::standard::gateways::GatewayListeners>> {
    let selected: Vec<_> = gw
        .spec
        .listeners
        .iter()
        .filter(|l| section_name.is_none_or(|s| l.name == s) && port.is_none_or(|p| l.port == p))
        .cloned()
        .collect();
    (!selected.is_empty()).then_some(selected)
}

/// The Accepted=False reason and message for a parentRef that selects none of
/// `gw`'s listeners.
fn no_matching_parent(gw: &Gateway, section_name: Option<&str>, port: Option<i32>) -> Failure {
    let named = section_name.map(|s| format!(" named {s}")).unwrap_or_default();
    let on_port = port.map(|p| format!(" on port {p}")).unwrap_or_default();
    let msg = format!("Gateway {} has no listener{named}{on_port}", object_name(gw));
    ("NoMatchingParent", msg)
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

/// Does the Gateway's `spec.tls.frontend` ask for client-certificate validation
/// (mutual TLS) on this listener? It covers the HTTPS listeners of a port: by the
/// `perPort` entry for that port when there is one, which replaces the default even
/// without a `validation`, and by the `default` otherwise (GEP-91).
fn frontend_validation_requested(
    gw: &Gateway,
    listener: &gateway_api::apis::standard::gateways::GatewayListeners,
) -> bool {
    let Some(frontend) = gw.spec.tls.as_ref().and_then(|t| t.frontend.as_ref()) else {
        return false;
    };
    if listener.protocol != "HTTPS" {
        return false;
    }
    match frontend.per_port.iter().flatten().find(|p| p.port == listener.port) {
        Some(p) => p.tls.validation.is_some(),
        None => frontend.default.validation.is_some(),
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
    openssl::x509::X509::stack_from_pem(pem)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
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
pub fn parse_gep2257_duration(s: &str) -> Option<Duration> {
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

/// A rule's request timeout for the data plane (`RouteEntry::request_timeout`).
/// Honor both `request` (overall) and `backendRequest` (per-attempt); with no
/// retries they coincide, so use the smaller non-zero value. "0s" disables that
/// timeout, and when no other is set the result is zero, so that the data plane's
/// default does not apply either.
fn request_timeout_from(
    timeouts: &gateway_api::apis::standard::httproutes::HttpRouteRulesTimeouts,
) -> Option<Duration> {
    [&timeouts.request, &timeouts.backend_request]
        .into_iter()
        .flatten()
        .filter_map(|v| parse_gep2257_duration(v))
        // Zero sorts after every non-zero value.
        .min_by_key(|d| (d.is_zero(), *d))
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

/// Whether a parentRef of this group and kind (defaults: a Gateway's) names a
/// Gateway: a route's parent may also be a Service (GAMMA) or another kind,
/// which torii does not serve, whatever its name.
fn is_gateway_ref(group: Option<&str>, kind: Option<&str>) -> bool {
    group.unwrap_or("gateway.networking.k8s.io") == "gateway.networking.k8s.io"
        && kind.unwrap_or("Gateway") == "Gateway"
}

/// One kind's part of [`ReconcileCtx::fetch_referenced`]: of the objects in
/// `wanted`, GET those whose version in the metadata store `meta` is not the one in
/// `cache`, and keep `extract` of each. Forget what is no longer wanted or gone.
/// A failed GET keeps what was read before, and is tried again on the next pass.
async fn fetch_referenced<K, T>(
    client: &Client,
    meta: &Store<PartialObjectMeta<K>>,
    cache: &FetchedObjects<T>,
    wanted: BTreeSet<(String, String)>,
    extract: impl Fn(K) -> T,
) where
    K: Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + DeserializeOwned
        + std::fmt::Debug,
{
    let lock = || cache.lock().unwrap_or_else(|e| e.into_inner());
    let mut stale = Vec::new();
    {
        let mut cache = lock();
        cache.retain(|key, _| wanted.contains(key));
        for (ns, name) in wanted {
            let key = (ns, name);
            match meta.get(&reflector::ObjectRef::new(&key.1).within(&key.0)) {
                None => {
                    cache.remove(&key);
                }
                Some(m)
                    if cache
                        .get(&key)
                        .is_some_and(|f| f.version == m.metadata.resource_version) => {}
                Some(_) => stale.push(key),
            }
        }
    }
    let fetched = futures::future::join_all(stale.into_iter().map(|(ns, name)| async move {
        let got = Api::<K>::namespaced(client.clone(), &ns).get_opt(&name).await;
        ((ns, name), got)
    }))
    .await;
    let mut cache = lock();
    for (key, got) in fetched {
        match got {
            Ok(Some(obj)) => {
                let version = obj.meta().resource_version.clone();
                cache.insert(
                    key,
                    Fetched {
                        version,
                        data: extract(obj),
                    },
                );
            }
            Ok(None) => {
                cache.remove(&key);
            }
            Err(e) => {
                tracing::warn!(kind = %K::kind(&()), namespace = key.0, name = key.1, error = %e, "cannot read a referenced object")
            }
        }
    }
}

/// A Service's TCP ports (a port without a protocol is TCP): routes reach their
/// backends over TCP.
fn tcp_service_ports(svc: &Service) -> impl Iterator<Item = &k8s_openapi::api::core::v1::ServicePort> {
    svc.spec
        .iter()
        .flat_map(|s| s.ports.iter().flatten())
        .filter(|p| p.protocol.as_deref().unwrap_or("TCP") == "TCP")
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

/// The field managers the ACME task wrote listener conditions under, one per
/// listener: `torii-acme.<listener>`.
const LEGACY_ACME_MANAGERS: &str = "torii-acme.";

/// `value` as JSON (null for None).
fn json_of(value: &impl Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

/// The write that gives an object the status `desired`, computed from spec, with
/// each condition's lastTransitionTime carried over from `cached` (the status the
/// object has, as the store holds it) while the condition's status is the same
/// (see [`carry_transition_times`]). None when the object has that status already:
/// a pass writes only what changed.
fn status_patch(
    target: PatchTarget,
    meta: &ObjectMeta,
    cached: serde_json::Value,
    mut desired: serde_json::Value,
) -> Option<StatusPatch> {
    let now = json_of(&Time(
        k8s_openapi::jiff::Timestamp::now()
            .round(k8s_openapi::jiff::Unit::Second)
            .ok()?,
    ));
    carry_transition_times(&mut desired, &cached, &now);
    if desired == cached {
        return None;
    }
    Some(StatusPatch {
        target,
        ns: meta.namespace.clone(),
        name: meta.name.clone().unwrap_or_default(),
        json: serde_json::json!({ "status": desired }),
        manager: FIELD_MANAGER.to_string(),
        resource_version: None,
    })
}

/// The write that makes the list `field` of an object's status (a route's
/// `parents`, a policy's `ancestors`) hold `ours` as torii's entries. Several
/// controllers write these lists, each the entries with its controllerName, but
/// they are atomic: an apply replaces one whole. So torii writes the cached list
/// with its own entries replaced in place (matched by `key`), the others' kept as
/// they are, and its entries for parents it no longer has gone: the spec's
/// read-modify-write that updates only torii's entries, and cleans them up. The
/// write carries the cached resourceVersion, so that it cannot undo another
/// controller's write since; that write's event starts a new pass. None when
/// there is nothing to change.
fn list_status_patch(
    target: PatchTarget,
    meta: &ObjectMeta,
    cached: serde_json::Value,
    field: &str,
    key: &str,
    ours: Vec<serde_json::Value>,
) -> Option<StatusPatch> {
    let cached = cached
        .get(field)
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default();
    let mut ours: Vec<Option<serde_json::Value>> = ours.into_iter().map(Some).collect();
    let mut list = Vec::new();
    for entry in &cached {
        if entry["controllerName"] != CONTROLLER_NAME {
            list.push(entry.clone());
        } else if let Some(new) = ours
            .iter_mut()
            .find(|o| o.as_ref().is_some_and(|o| o[key] == entry[key]))
        {
            list.extend(new.take());
        }
    }
    list.extend(ours.into_iter().flatten());
    let mut patch = status_patch(
        target,
        meta,
        serde_json::json!({ field: cached }),
        serde_json::json!({ field: list }),
    )?;
    patch.resource_version = meta.resource_version.clone();
    Some(patch)
}

/// Give each condition in `new` (a status torii computed) the lastTransitionTime
/// of the same condition in `old` (the status the object has) if their status is
/// the same, else `now`: the time a condition last changed status. A condition is
/// the same by type, in the list entry that is the same by the fields that
/// identify it: a listener's name, a route parent's parentRef and controllerName,
/// a policy ancestor's ancestorRef and controllerName. An old time in 1970 is the
/// placeholder that torii once wrote, and counts as unknown.
fn carry_transition_times(new: &mut serde_json::Value, old: &serde_json::Value, now: &serde_json::Value) {
    use serde_json::Value;
    match new {
        Value::Object(fields) => {
            for (name, value) in fields.iter_mut() {
                let old = old.get(name).unwrap_or(&Value::Null);
                if name != "conditions" {
                    carry_transition_times(value, old, now);
                    continue;
                }
                for c in value.as_array_mut().into_iter().flatten() {
                    let same = old.as_array().into_iter().flatten().find(|o| o["type"] == c["type"]);
                    c["lastTransitionTime"] = match same {
                        Some(o) if o["status"] == c["status"] && o["lastTransitionTime"] != "1970-01-01T00:00:00Z" => {
                            o["lastTransitionTime"].clone()
                        }
                        _ => now.clone(),
                    };
                }
            }
        }
        Value::Array(entries) => {
            for entry in entries {
                let same = |o: &&Value| {
                    ["name", "parentRef", "ancestorRef", "controllerName"]
                        .iter()
                        .all(|k| entry.get(k) == o.get(k))
                };
                let old = old.as_array().into_iter().flatten().find(same).unwrap_or(&Value::Null);
                carry_transition_times(entry, old, now);
            }
        }
        _ => {}
    }
}

/// The longest condition message torii writes, in bytes. The API server refuses
/// a whole status with a message over 32768, and some are built from what users
/// wrote (a regex, the list of a route's broken backendRefs).
const MAX_MESSAGE: usize = 1024;

/// Build a metav1 Condition with observedGeneration set. The `message` says why a
/// False condition is False: infra users see it via `kubectl describe`/`get -o
/// yaml` even without controller-log access. The conformance suite matches only
/// on type/status/reason (helpers.go), so a detailed message never breaks a test.
fn condition(type_: &str, status: &str, reason: &str, message: &str, observed_generation: i64) -> Condition {
    let mut message = message.to_string();
    if message.len() > MAX_MESSAGE {
        let mut end = MAX_MESSAGE - '…'.len_utf8();
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message,
        observed_generation: Some(observed_generation),
        // A placeholder: the status write gives each condition the time it last
        // changed status (see `carry_transition_times`).
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH),
    }
}

#[cfg(test)]
mod tests {
    use gateway_api::apis::standard::backendtlspolicies::BackendTlsPolicyStatus;
    use gateway_api::apis::standard::httproutes::HttpRouteStatus;

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

    // The smaller non-zero timeout wins. "0s" alone must stay distinct from no
    // timeouts at all: it disables the data plane's default response timeout.
    #[test]
    fn rule_request_timeout() {
        use gateway_api::apis::standard::httproutes::HttpRouteRulesTimeouts;
        let timeout = |request: Option<&str>, backend_request: Option<&str>| {
            request_timeout_from(&HttpRouteRulesTimeouts {
                request: request.map(Into::into),
                backend_request: backend_request.map(Into::into),
            })
        };
        assert_eq!(timeout(None, None), None);
        assert_eq!(timeout(Some("10s"), None), Some(Duration::from_secs(10)));
        assert_eq!(timeout(Some("10s"), Some("2s")), Some(Duration::from_secs(2)));
        assert_eq!(timeout(Some("0s"), Some("2s")), Some(Duration::from_secs(2)));
        assert_eq!(timeout(Some("1m"), Some("0s")), Some(Duration::from_secs(60)));
        assert_eq!(timeout(Some("0s"), None), Some(Duration::ZERO));
        assert_eq!(timeout(None, Some("0s")), Some(Duration::ZERO));
    }

    // Requests are matched in their normal form, so path values are normalized too. A
    // value with `;params` could only get its requests refused: it is unsupported.
    #[test]
    fn route_path_values() {
        use gateway_api::apis::standard::httproutes::{HttpRouteRules, HttpRouteRulesMatches};

        let path = |r#type: &str, value: &str| {
            let m: HttpRouteRulesMatches =
                serde_json::from_value(serde_json::json!({ "path": { "type": r#type, "value": value } })).unwrap();
            route_match_from(&m).path
        };
        assert!(matches!(path("PathPrefix", "/%61dmin/%7e"), Some(PathMatch::Prefix(p)) if p == "/admin/~"));
        assert!(matches!(path("Exact", "/a%3fb"), Some(PathMatch::Exact(p)) if p == "/a%3Fb"));

        let rule = |value: &str| {
            let rule: HttpRouteRules =
                serde_json::from_value(serde_json::json!({ "matches": [{ "path": { "value": value } }] })).unwrap();
            validate_http_rule(0, &rule)
        };
        assert_eq!(rule("/a"), None);
        assert!(rule("/a;b").is_some());
    }

    fn http_route(name: &str, filter: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {
                "name": name,
                "namespace": "ns",
                "generation": 3,
                "annotations": { UNDECODABLE_ANNOTATION: "set by a user" },
            },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "rules": [{ "filters": [filter], "backendRefs": [{ "name": "app", "port": 80 }] }],
            },
        })
    }

    // One route that the gateway-api types cannot represent (here an
    // experimental-channel ExternalAuth filter) used to fail the whole LIST page,
    // so torii served no HTTPRoute at all. Now only that route is left out of the
    // data plane, as a stand-in that keeps its parentRefs for status.
    #[test]
    fn undecodable_route_does_not_fail_the_list() {
        let ext_auth = serde_json::json!({
            "type": "ExternalAuth",
            "externalAuth": { "protocol": "HTTP", "http": {}, "backendRef": { "name": "auth", "port": 8080 } },
        });
        let page = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRouteList",
            "metadata": { "resourceVersion": "1" },
            "items": [
                http_route("good", serde_json::json!({ "type": "RequestHeaderModifier" })),
                http_route("extauth", ext_auth),
            ],
        });
        // A typed LIST decodes the page as a whole, and fails.
        assert!(serde_json::from_value::<kube::core::ObjectList<HTTPRoute>>(page.clone()).is_err());

        let page: kube::core::ObjectList<DynamicObject> = serde_json::from_value(page).unwrap();
        let (store, mut writer) = reflector::store::<HTTPRoute>();
        writer.apply_watcher_event(&watcher::Event::Init);
        for obj in page.items {
            writer.apply_watcher_event(&decode_event(watcher::Event::InitApply(obj)).unwrap());
        }
        writer.apply_watcher_event(&watcher::Event::InitDone);

        let good = find_in(&store, "ns", "good").unwrap();
        assert_eq!(good.spec.rules.as_ref().map(Vec::len), Some(1));
        assert!(!good.annotations().contains_key(UNDECODABLE_ANNOTATION));

        let stand_in = find_in(&store, "ns", "extauth").unwrap();
        assert_eq!(stand_in.spec.rules, None);
        assert_eq!(stand_in.spec.parent_refs.as_ref().unwrap()[0].name, "gw");
        assert_eq!(stand_in.meta().generation, Some(3));
        assert!(stand_in.annotations()[UNDECODABLE_ANNOTATION].contains("unknown variant `ExternalAuth`"));
    }

    // A v1alpha2 TLSRoute may omit hostnames, which v1 (and so the Rust type)
    // requires.
    #[test]
    fn tls_route_without_hostnames_is_a_stand_in() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "TLSRoute",
            "metadata": { "name": "nohostnames", "namespace": "ns" },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "rules": [{ "backendRefs": [{ "name": "app", "port": 443 }] }],
            },
        }))
        .unwrap();
        let Some(watcher::Event::Apply(stand_in)) = decode_event::<TLSRoute>(watcher::Event::Apply(obj)) else {
            panic!("expected an Apply of the stand-in");
        };
        assert!(stand_in.spec.rules.is_empty());
        assert_eq!(stand_in.spec.parent_refs.as_ref().unwrap()[0].name, "gw");
        assert!(stand_in.annotations()[UNDECODABLE_ANNOTATION].contains("missing field `hostnames`"));
    }

    // Any other kind that does not decode is left out: an update removes the
    // older version from the store, and a re-list skips it.
    #[test]
    fn undecodable_object_leaves_the_store() {
        let gateway = |mode: &str| -> DynamicObject {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "Gateway",
                "metadata": { "name": "gw", "namespace": "ns" },
                "spec": {
                    "gatewayClassName": "torii",
                    "listeners": [{ "name": "tls", "port": 443, "protocol": "TLS", "tls": { "mode": mode } }],
                },
            }))
            .unwrap()
        };
        let (store, mut writer) = reflector::store::<Gateway>();
        writer.apply_watcher_event(&decode_event(watcher::Event::Apply(gateway("Passthrough"))).unwrap());
        assert!(find_in(&store, "ns", "gw").is_some());
        writer.apply_watcher_event(&decode_event(watcher::Event::Apply(gateway("Bogus"))).unwrap());
        assert!(find_in(&store, "ns", "gw").is_none());
        assert!(decode_event::<Gateway>(watcher::Event::InitApply(gateway("Bogus"))).is_none());
    }

    /// A store holding `objects`.
    fn store_of<K>(objects: Vec<K>) -> Store<K>
    where
        K: Resource + Clone + 'static,
        K::DynamicType: Eq + std::hash::Hash + Clone + Default,
    {
        let (store, mut writer) = reflector::store::<K>();
        for obj in objects {
            writer.apply_watcher_event(&watcher::Event::Apply(obj));
        }
        store
    }

    /// Stores with no objects, for a test to fill in the kinds it needs.
    fn no_objects() -> Stores {
        Stores {
            gateway_classes: store_of(vec![]),
            gateways: store_of(vec![]),
            routes: store_of(vec![]),
            tls_routes: store_of(vec![]),
            services: store_of(vec![]),
            endpoint_slices: store_of(vec![]),
            reference_grants: store_of(vec![]),
            namespaces: store_of(vec![]),
            secrets: store_of(vec![]),
            config_maps: store_of(vec![]),
            backend_tls_policies: store_of(vec![]),
        }
    }

    /// A reconcile over `stores`, by a torii serving HTTP on `http_ports` and TLS
    /// on `tls_ports`. Its API server is a closed port: the status writes fail, and
    /// are only logged.
    fn test_ctx(stores: Stores, http_ports: &[u16], tls_ports: &[u16]) -> ReconcileCtx {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let client = Client::try_from(kube::Config::new(format!("http://{closed}").parse().unwrap())).unwrap();
        ReconcileCtx {
            client,
            data_plane: DataPlane::new(),
            config: ControllerConfig {
                advertise_address: "127.0.0.1".into(),
                http_ports: http_ports.to_vec(),
                tls_ports: tls_ports.to_vec(),
                acme_feed: None,
                acme_default_issuer: None,
                acme_default_email: None,
            },
            stores: Arc::new(stores),
            referenced: Referenced::default(),
        }
    }

    /// The status a pass computes for `gw`, with these attachedRoutes counts.
    fn gateway_status(ctx: &ReconcileCtx, gw: &Gateway, counts: &AttachCounts) -> GatewayStatus {
        let model = ctx.build_gateway_model(gw);
        let mut patch = ctx.gateway_patch(&model, counts, &HashMap::new()).unwrap();
        serde_json::from_value(patch.json["status"].take()).unwrap()
    }

    /// The metadata of a Secret or ConfigMap in the store, at version "1".
    fn meta_of<K>(ns: &str, name: &str) -> PartialObjectMeta<K> {
        use kube::core::PartialObjectMetaExt;
        ObjectMeta {
            name: Some(name.into()),
            namespace: Some(ns.into()),
            resource_version: Some("1".into()),
            ..Default::default()
        }
        .into_response_partial()
    }

    /// Make the certificate of Secret `ns/name` (whose metadata the store has, see
    /// [`meta_of`]) read already, as no test can GET it.
    fn read_secret(ctx: &ReconcileCtx, ns: &str, name: &str, cert: CertKey) {
        let fetched = Fetched {
            version: Some("1".into()),
            data: Some(cert),
        };
        ctx.referenced
            .secrets
            .lock()
            .unwrap()
            .insert((ns.into(), name.into()), fetched);
    }

    /// The GatewayClass `torii`, of this controller.
    fn torii_class() -> GatewayClass {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayClass",
            "metadata": { "name": "torii" },
            "spec": { "controllerName": CONTROLLER_NAME },
        }))
        .unwrap()
    }

    /// `type: reason` of each condition.
    fn reasons(conditions: &[Condition]) -> Vec<String> {
        conditions
            .iter()
            .map(|c| format!("{}={}/{}", c.type_, c.status, c.reason))
            .collect()
    }

    // GEP-91 client-certificate validation is not implemented, so torii must not
    // serve the HTTPS listeners it covers to clients without a certificate: they
    // are rejected and get neither their certificate nor routes. A `perPort` entry
    // replaces the default for its port, and HTTP listeners are not covered.
    #[tokio::test]
    async fn frontend_validation_rejects_the_https_listeners() {
        let ca_refs = serde_json::json!([{ "group": "", "kind": "ConfigMap", "name": "ca" }]);
        let https = |name: &str, port: u16, hostname: &str| {
            serde_json::json!({
                "name": name, "port": port, "protocol": "HTTPS", "hostname": hostname,
                "tls": { "certificateRefs": [{ "name": "cert" }] },
            })
        };
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "ns", "generation": 2 },
            "spec": {
                "gatewayClassName": "torii",
                "tls": { "frontend": {
                    "default": { "validation": { "caCertificateRefs": ca_refs } },
                    "perPort": [
                        { "port": 8443, "tls": {} },
                        { "port": 9443, "tls": { "validation": {
                            "caCertificateRefs": ca_refs, "mode": "AllowInsecureFallback",
                        } } },
                    ],
                } },
                "listeners": [
                    https("https", 443, "a.example"),
                    https("https-8443", 8443, "b.example"),
                    https("https-9443", 9443, "c.example"),
                    { "name": "http", "port": 80, "protocol": "HTTP" },
                ],
            },
        }))
        .unwrap();
        let route: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route", "namespace": "ns" },
            "spec": { "parentRefs": [{ "name": "gw" }], "rules": [{}] },
        }))
        .unwrap();
        let stores = Stores {
            gateway_classes: store_of(vec![torii_class()]),
            gateways: store_of(vec![gw.clone()]),
            routes: store_of(vec![route]),
            secrets: store_of(vec![meta_of("ns", "cert")]),
            ..no_objects()
        };
        let ctx = test_ctx(stores, &[80], &[443, 8443, 9443]);
        read_secret(&ctx, "ns", "cert", CertKey::generate_self_signed().unwrap());

        // Served: only the HTTP listener and the HTTPS one on the port whose
        // `perPort` entry turns validation off.
        ctx.reconcile_all().await.unwrap();
        let snapshot = ctx.data_plane.load();
        let ports: std::collections::BTreeSet<u16> = snapshot.routes.entries.iter().map(|e| e.listener_port).collect();
        assert_eq!(ports, [80, 8443].into());
        assert!(snapshot.certs.select(Some("b.example")).is_some());
        assert!(snapshot.certs.select(Some("a.example")).is_none());
        assert!(snapshot.certs.select(Some("c.example")).is_none());

        // Reported: the others are not accepted, so neither is the whole Gateway.
        let status = gateway_status(&ctx, &gw, &BTreeMap::new());
        let listener = |name: &str| {
            let listeners = status.listeners.as_deref().unwrap();
            reasons(&listeners.iter().find(|l| l.name == name).unwrap().conditions)
        };
        let rejected = [
            "Accepted=False/UnsupportedValue",
            "Programmed=False/Invalid",
            "ResolvedRefs=True/ResolvedRefs",
        ];
        let served = [
            "Accepted=True/Accepted",
            "Programmed=True/Programmed",
            "ResolvedRefs=True/ResolvedRefs",
        ];
        assert_eq!(listener("https"), rejected);
        assert_eq!(listener("https-8443"), served);
        assert_eq!(listener("https-9443"), rejected);
        assert_eq!(listener("http"), served);
        assert_eq!(
            reasons(status.conditions.as_deref().unwrap()),
            ["Accepted=True/ListenersNotValid", "Programmed=False/Invalid"]
        );
    }

    /// A Gateway `gw` in namespace `ns` with an HTTP listener `http` on port 80.
    fn http_gateway() -> Gateway {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "ns", "generation": 1 },
            "spec": {
                "gatewayClassName": "torii",
                "listeners": [{ "name": "http", "port": 80, "protocol": "HTTP" }],
            },
        }))
        .unwrap()
    }

    /// An HTTPRoute `name` in namespace `ns` with `spec`.
    fn http_route_with(name: &str, spec: serde_json::Value) -> HTTPRoute {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": name, "namespace": "ns", "generation": 1 },
            "spec": spec,
        }))
        .unwrap()
    }

    /// `route`'s pass on the Gateways in `ctx`: its status, its entries in the
    /// route table, and the attachedRoutes counts.
    fn route_pass(ctx: &ReconcileCtx, route: &HTTPRoute) -> (Option<HttpRouteStatus>, RouteTable, AttachCounts) {
        let models: Vec<GatewayModel> = ctx
            .stores
            .gateways
            .state()
            .iter()
            .map(|gw| ctx.build_gateway_model(gw))
            .collect();
        let mut backends = BackendIndex::new(ctx.stores.endpoint_slices.state(), UpstreamTlsMap::new());
        let mut table = RouteTable::default();
        let mut counts = BTreeMap::new();
        let patch = ctx.process_route(
            route,
            &models,
            &mut backends,
            &mut table,
            &mut counts,
            &mut PolicyAncestors::new(),
        );
        let status = patch.map(|mut p| serde_json::from_value(p.json["status"].take()).unwrap());
        table.sort();
        (status, table, counts)
    }

    /// The conditions of a route's first parent, as `type=status/reason`, and
    /// their messages.
    fn parent_conditions(status: &HttpRouteStatus) -> (Vec<String>, Vec<String>) {
        let conditions = &status.parents[0].conditions;
        (
            reasons(conditions),
            conditions.iter().map(|c| c.message.clone()).collect(),
        )
    }

    // A rule torii cannot honor is dropped with a reason, and the route is
    // accepted for the rules it implements (PartiallyInvalid, T161), or not at all
    // when it implements none. A dropped rule that says which requests it takes
    // keeps them, with a 500, instead of letting other rules take them without
    // its filter (T049, T048). Only an accepted route counts in attachedRoutes
    // (T154), and rule names must be unique (T199).
    #[tokio::test]
    async fn invalid_rules_are_dropped_and_fail_closed() {
        let ctx = test_ctx(
            Stores {
                gateways: store_of(vec![http_gateway()]),
                ..no_objects()
            },
            &[80],
            &[],
        );
        let ext_auth = serde_json::json!({
            "type": "ExtensionRef",
            "extensionRef": { "group": "auth.example", "kind": "BasicAuth", "name": "admins" },
        });
        let rewrite = serde_json::json!({ "type": "URLRewrite", "urlRewrite": { "hostname": "internal.example" } });
        let admin = serde_json::json!({ "path": { "type": "PathPrefix", "value": "/admin" } });
        let regex = serde_json::json!({ "path": { "type": "RegularExpression", "value": "/r.*" } });
        let counted = |counts: &AttachCounts| counts[&("ns".to_string(), "gw".to_string())]["http"];

        // One implemented rule, one guarded by an ExtensionRef filter, one with a
        // backendRef filter torii does not apply, one it cannot match.
        let route = http_route_with(
            "partial",
            serde_json::json!({
                "parentRefs": [{ "name": "gw" }],
                "rules": [
                    { "matches": [admin], "filters": [ext_auth] },
                    { "matches": [{ "path": { "value": "/rw" } }],
                      "backendRefs": [{ "name": "app", "port": 80, "filters": [rewrite] }] },
                    { "matches": [regex] },
                    {},
                ],
            }),
        );
        let (status, table, counts) = route_pass(&ctx, &route);
        let (conditions, messages) = parent_conditions(&status.unwrap());
        assert_eq!(
            conditions,
            [
                "Accepted=True/Accepted",
                "ResolvedRefs=True/ResolvedRefs",
                "PartiallyInvalid=True/UnsupportedValue"
            ]
        );
        assert!(messages[2].starts_with("Dropped Rule(s): rules[0].filters[0]: ExtensionRef"));
        assert!(messages[2].contains("rules[1].backendRefs[0].filters[0]: URLRewrite"));
        assert!(messages[2].contains("rules[2].matches[0].path: RegularExpression"));
        assert_eq!(counted(&counts), 1);
        let h = http::HeaderMap::new();
        let rule_of = |path: &str| {
            let entry = table.match_request(80, "a.example", path, "GET", &h, "").unwrap();
            (
                entry.rule_order,
                entry.rule.backends.len(),
                entry.rule.filters.url_rewrite.is_some(),
            )
        };
        // The guarded rules keep their requests, with nothing to send them to.
        assert_eq!(rule_of("/admin/x"), (0, 0, false));
        assert_eq!(rule_of("/rw"), (1, 0, false));
        assert_eq!(rule_of("/r1"), (3, 0, false));

        // No rule implemented: not accepted, not counted, its guard still holds.
        let route = http_route_with(
            "guard",
            serde_json::json!({ "parentRefs": [{ "name": "gw" }], "rules": [{ "matches": [admin], "filters": [ext_auth] }] }),
        );
        let (status, table, counts) = route_pass(&ctx, &route);
        let (conditions, _) = parent_conditions(&status.unwrap());
        assert_eq!(
            conditions,
            ["Accepted=False/UnsupportedValue", "ResolvedRefs=True/ResolvedRefs"]
        );
        assert_eq!(counted(&counts), 0);
        assert_eq!(table.entries.len(), 1);

        // Two rules named alike: none of the route is programmed.
        let route = http_route_with(
            "dup",
            serde_json::json!({ "parentRefs": [{ "name": "gw" }], "rules": [{ "name": "a" }, { "name": "a" }] }),
        );
        let (status, table, counts) = route_pass(&ctx, &route);
        let (conditions, messages) = parent_conditions(&status.unwrap());
        assert_eq!(conditions[0], "Accepted=False/UnsupportedValue");
        assert!(messages[0].contains("rules[1].name"), "{}", messages[0]);
        assert_eq!(counted(&counts), 0);
        assert!(table.entries.is_empty());
    }

    // A rejected Gateway serves nothing: its listeners are not Programmed, it has
    // no address, and its routes learn they are not accepted there (T151).
    #[tokio::test]
    async fn a_rejected_gateway_reports_its_listeners_and_routes_unserved() {
        let mut gw = http_gateway();
        gw.spec.infrastructure = serde_json::from_value(serde_json::json!({
            "parametersRef": { "group": "example.com", "kind": "Nope", "name": "x" },
        }))
        .unwrap();
        let ctx = test_ctx(
            Stores {
                gateways: store_of(vec![gw.clone()]),
                ..no_objects()
            },
            &[80],
            &[],
        );
        let route = http_route_with(
            "r",
            serde_json::json!({ "parentRefs": [{ "name": "gw" }], "rules": [{}] }),
        );
        let (status, table, counts) = route_pass(&ctx, &route);
        let (conditions, _) = parent_conditions(&status.unwrap());
        assert_eq!(conditions[0], "Accepted=False/NotAllowedByListeners");
        assert!(table.entries.is_empty());
        assert_eq!(counts[&("ns".to_string(), "gw".to_string())]["http"], 0);

        let status = gateway_status(&ctx, &gw, &counts);
        assert_eq!(status.addresses, None);
        let listener = &status.listeners.unwrap()[0];
        assert_eq!(reasons(&listener.conditions)[1], "Programmed=False/Invalid");
    }

    // A TLS Terminate listener whose certificate did not resolve is not programmed,
    // and must not terminate its routes with another certificate (T152).
    #[tokio::test]
    async fn tls_routes_need_their_terminate_listener_certificate() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "ns", "generation": 1 },
            "spec": {
                "gatewayClassName": "torii",
                "listeners": [{ "name": "tls", "port": 443, "protocol": "TLS",
                    "tls": { "mode": "Terminate", "certificateRefs": [{ "name": "missing" }] } }],
            },
        }))
        .unwrap();
        let route: TLSRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "TLSRoute",
            "metadata": { "name": "t", "namespace": "ns", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "hostnames": ["x.example"],
                "rules": [{ "backendRefs": [{ "name": "app", "port": 443 }] }],
            },
        }))
        .unwrap();
        let ctx = test_ctx(
            Stores {
                gateway_classes: store_of(vec![torii_class()]),
                gateways: store_of(vec![gw]),
                tls_routes: store_of(vec![route]),
                ..no_objects()
            },
            &[],
            &[443],
        );
        ctx.reconcile_all().await.unwrap();
        let decision = ctx.data_plane.load().tls.lookup(443, Some("x.example"), 0);
        assert!(
            matches!(decision, crate::tls_table::TlsDecision::NoRoute),
            "{decision:?}"
        );
    }

    // A False condition says what is wrong: a route's ResolvedRefs names every
    // broken backendRef, under the reason that comes first in a fixed order, not
    // the last one seen (T158). Messages are bounded (T157).
    #[tokio::test]
    async fn conditions_say_what_is_wrong() {
        let ctx = test_ctx(
            Stores {
                gateways: store_of(vec![http_gateway()]),
                ..no_objects()
            },
            &[80],
            &[],
        );
        let route = http_route_with(
            "bad",
            serde_json::json!({
                "parentRefs": [{ "name": "gw" }],
                "rules": [
                    { "backendRefs": [{ "name": "elsewhere", "namespace": "other", "port": 80 }] },
                    { "backendRefs": [{ "group": "example.com", "kind": "Foo", "name": "foo" }] },
                    { "backendRefs": [{ "name": "missing", "port": 80 }] },
                ],
            }),
        );
        let (status, _, _) = route_pass(&ctx, &route);
        let (conditions, messages) = parent_conditions(&status.unwrap());
        assert_eq!(conditions[1], "ResolvedRefs=False/RefNotPermitted");
        for part in [
            "rules[0].backendRefs[0]: Service other/elsewhere is in another namespace",
            "rules[1].backendRefs[0]: example.com/Foo foo is not a Service",
            "rules[2].backendRefs[0]: Service ns/missing was not found",
        ] {
            assert!(messages[1].contains(part), "{}", messages[1]);
        }

        let unmatched = http_route_with(
            "nomatch",
            serde_json::json!({ "parentRefs": [{ "name": "gw", "sectionName": "nope" }], "rules": [{}] }),
        );
        let (status, _, _) = route_pass(&ctx, &unmatched);
        let (conditions, messages) = parent_conditions(&status.unwrap());
        assert_eq!(conditions[0], "Accepted=False/NoMatchingParent");
        assert_eq!(messages[0], "Gateway ns/gw has no listener named nope");

        let long = condition("Accepted", "False", "UnsupportedValue", &"é".repeat(MAX_MESSAGE), 1);
        assert!(long.message.len() <= MAX_MESSAGE && long.message.ends_with('…'));
    }

    /// The policies' status after a pass over every route in `ctx`, by policy name.
    fn policy_pass(ctx: &ReconcileCtx) -> BTreeMap<String, BackendTlsPolicyStatus> {
        let models: Vec<GatewayModel> = ctx
            .stores
            .gateways
            .state()
            .iter()
            .map(|gw| ctx.build_gateway_model(gw))
            .collect();
        let (upstream_tls, outcomes) = ctx.build_policy_artifacts();
        let mut backends = BackendIndex::new(ctx.stores.endpoint_slices.state(), upstream_tls);
        let mut ancestors = PolicyAncestors::new();
        for route in ctx.stores.routes.state() {
            let (mut table, mut counts) = (RouteTable::default(), AttachCounts::new());
            ctx.process_route(&route, &models, &mut backends, &mut table, &mut counts, &mut ancestors);
        }
        ctx.policy_patches(&ancestors, &outcomes)
            .into_iter()
            .map(|mut p| (p.name, serde_json::from_value(p.json["status"].take()).unwrap()))
            .collect()
    }

    // A policy's ancestors are the Gateways that accept a route to its Service
    // with a backendRef that resolves: not any Gateway some route names (T155).
    // Each CA reference is checked: a policy with one valid CA is accepted, and
    // ResolvedRefs names the broken ones. A policy that loses any target to an
    // older one is Conflicted (T156).
    #[tokio::test]
    async fn backend_tls_policy_status() {
        let gateway = |name: &str, from: &str| -> Gateway {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "Gateway",
                "metadata": { "name": name, "namespace": "ns", "generation": 1 },
                "spec": {
                    "gatewayClassName": "torii",
                    "listeners": [{ "name": "http", "port": 80, "protocol": "HTTP",
                        "allowedRoutes": { "namespaces": { "from": from } } }],
                },
            }))
            .unwrap()
        };
        let service = |name: &str| -> Service {
            serde_json::from_value(serde_json::json!({
                "metadata": { "name": name, "namespace": "ns" },
                "spec": { "ports": [{ "name": "https", "port": 443 }] },
            }))
            .unwrap()
        };
        let route = |ns: &str, name: &str, gateways: &[&str], svc: &str| -> HTTPRoute {
            let parents: Vec<_> = gateways
                .iter()
                .map(|gw| serde_json::json!({ "name": gw, "namespace": "ns" }))
                .collect();
            serde_json::from_value(serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "HTTPRoute",
                "metadata": { "name": name, "namespace": ns, "generation": 1 },
                "spec": { "parentRefs": parents,
                    "rules": [{ "backendRefs": [{ "name": svc, "namespace": "ns", "port": 443 }] }] },
            }))
            .unwrap()
        };
        let policy = |name: &str, created: &str, targets: &[&str], cas: &[&str]| -> BackendTLSPolicy {
            let targets: Vec<_> = targets
                .iter()
                .map(|t| serde_json::json!({ "group": "", "kind": "Service", "name": t }))
                .collect();
            let cas: Vec<_> = cas
                .iter()
                .map(|c| serde_json::json!({ "group": "", "kind": "ConfigMap", "name": c }))
                .collect();
            serde_json::from_value(serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "BackendTLSPolicy",
                "metadata": { "name": name, "namespace": "ns", "generation": 1, "creationTimestamp": created },
                "spec": { "targetRefs": targets,
                    "validation": { "hostname": "s.example", "caCertificateRefs": cas } },
            }))
            .unwrap()
        };
        let stores = Stores {
            gateways: store_of(vec![gateway("open", "All"), gateway("own", "Same")]),
            services: store_of(vec![service("s1"), service("s2"), service("s3")]),
            routes: store_of(vec![
                route("ns", "mine", &["open"], "s1"),
                route("ns", "both", &["open"], "s2"),
                route("ns", "three", &["open"], "s3"),
                // Another tenant: no listener of `own` admits it, and no grant lets
                // it send to `ns`.
                route("other", "spoof", &["open", "own"], "s1"),
            ]),
            backend_tls_policies: store_of(vec![
                policy("multi-ca", "2026-01-01T00:00:00Z", &["s1"], &["good", "missing"]),
                policy("a-old", "2026-01-01T00:00:00Z", &["s2"], &["good"]),
                policy("b-new", "2026-01-02T00:00:00Z", &["s2", "s3"], &["good"]),
            ]),
            ..no_objects()
        };
        let ctx = test_ctx(stores, &[80], &[]);
        let (ca, _) = CertKey::generate_self_signed_pem().unwrap();
        let fetched = Fetched {
            version: None,
            data: Some(Arc::from(ca)),
        };
        ctx.referenced
            .config_maps
            .lock()
            .unwrap()
            .insert(("ns".into(), "good".into()), fetched);

        let status = policy_pass(&ctx);
        let summary = |name: &str| -> Vec<(String, Vec<String>)> {
            status[name]
                .ancestors
                .iter()
                .map(|a| (a.ancestor_ref.name.clone(), reasons(&a.conditions)))
                .collect()
        };
        assert_eq!(
            summary("multi-ca"),
            [(
                "open".to_string(),
                vec![
                    "Accepted=True/Accepted".to_string(),
                    "ResolvedRefs=False/InvalidCACertificateRef".to_string()
                ]
            )]
        );
        assert!(
            status["multi-ca"].ancestors[0].conditions[1]
                .message
                .contains("caCertificateRefs[1]: ConfigMap ns/missing was not found")
        );
        assert_eq!(summary("a-old")[0].1[0], "Accepted=True/Accepted");
        assert_eq!(summary("b-new")[0].1[0], "Accepted=False/Conflicted");
    }

    // Route parents (and policy ancestors) are written by several controllers,
    // each its own entries, in a list that an apply replaces whole: torii keeps
    // the others' entries, replaces its own in place, withdraws those it no longer
    // has (T068, T162), and writes nothing when nothing changed. A condition keeps
    // its lastTransitionTime while its status does not change (T153).
    #[test]
    fn route_parents_are_merged_with_other_controllers() {
        let parent = |gw: &str, controller: &str, status: &str, time: &str| {
            serde_json::json!({
                "parentRef": { "name": gw },
                "controllerName": controller,
                "conditions": [{ "type": "Accepted", "status": status, "reason": "R", "message": "",
                    "observedGeneration": 1, "lastTransitionTime": time }],
            })
        };
        let placeholder = "1970-01-01T00:00:00Z";
        let then = "2026-01-01T00:00:00Z";
        let meta = ObjectMeta {
            name: Some("r".into()),
            namespace: Some("ns".into()),
            resource_version: Some("7".into()),
            ..Default::default()
        };
        let cached = serde_json::json!({ "parents": [
            parent("other-gw", "example.com/other", "True", then),
            parent("gw", CONTROLLER_NAME, "True", then),
            parent("gone", CONTROLLER_NAME, "True", then),
        ] });
        let patch = |ours: Vec<serde_json::Value>| {
            list_status_patch(
                PatchTarget::HttpRoute,
                &meta,
                cached.clone(),
                "parents",
                "parentRef",
                ours,
            )
        };

        // Unchanged: no write, the other controller's entry and the times kept.
        let ours = vec![
            parent("gw", CONTROLLER_NAME, "True", placeholder),
            parent("gone", CONTROLLER_NAME, "True", placeholder),
        ];
        assert!(patch(ours).is_none());

        // `gone` withdrawn, `gw` changed status: a new time, written over version 7.
        let p = patch(vec![parent("gw", CONTROLLER_NAME, "False", placeholder)]).unwrap();
        assert_eq!(p.resource_version.as_deref(), Some("7"));
        let parents = p.json["status"]["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 2);
        assert_eq!(parents[0], cached["parents"][0]);
        let time = parents[1]["conditions"][0]["lastTransitionTime"].as_str().unwrap();
        assert!(time != then && time != placeholder, "{time}");

        // No parent of torii's left: only the other controller's entry stays.
        let p = patch(vec![]).unwrap();
        assert_eq!(p.json["status"]["parents"], serde_json::json!([cached["parents"][0]]));

        // Nothing of torii's, before or now: nothing to write.
        let foreign = serde_json::json!({ "parents": [cached["parents"][0]] });
        assert!(list_status_patch(PatchTarget::HttpRoute, &meta, foreign, "parents", "parentRef", vec![]).is_none());
    }

    // A parent named twice (namespace left out, then set to the route's) is one
    // parent: one status entry, counted and programmed once (T163). A parentRef
    // to a Service or another kind is not a Gateway of the same name (T142).
    #[tokio::test]
    async fn a_parent_counts_once_however_it_is_named() {
        let ctx = test_ctx(
            Stores {
                gateways: store_of(vec![http_gateway()]),
                ..no_objects()
            },
            &[80],
            &[],
        );
        let route = http_route_with(
            "r",
            serde_json::json!({
                "parentRefs": [
                    { "name": "gw" },
                    { "name": "gw", "namespace": "ns" },
                    { "name": "gw", "sectionName": "http" },
                ],
                "rules": [{}],
            }),
        );
        let (status, table, counts) = route_pass(&ctx, &route);
        let parents: Vec<Option<&str>> = status
            .as_ref()
            .unwrap()
            .parents
            .iter()
            .map(|p| p.parent_ref.section_name.as_deref())
            .collect();
        assert_eq!(parents, [None, Some("http")]);
        assert_eq!(counts[&("ns".to_string(), "gw".to_string())]["http"], 1);
        assert_eq!(table.entries.len(), 1);

        let mesh = http_route_with(
            "mesh",
            serde_json::json!({ "parentRefs": [{ "group": "", "kind": "Service", "name": "gw" }], "rules": [{}] }),
        );
        let (status, table, _) = route_pass(&ctx, &mesh);
        assert!(status.is_none());
        assert!(table.entries.is_empty());
    }

    // The data plane serves HTTP on --http-ports and TLS on --tls-ports, nothing
    // else: a listener on another port, or on a port of the other kind, is not
    // served, and must say so instead of taking routes (T069).
    #[tokio::test]
    async fn listeners_on_ports_torii_does_not_serve_are_rejected() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "ns", "generation": 1 },
            "spec": {
                "gatewayClassName": "torii",
                "listeners": [
                    { "name": "http", "port": 80, "protocol": "HTTP" },
                    { "name": "http-on-tls", "port": 443, "protocol": "HTTP" },
                    { "name": "unbound", "port": 8080, "protocol": "HTTP" },
                    { "name": "https-on-http", "port": 80, "protocol": "HTTPS", "hostname": "s.example",
                      "tls": { "certificateRefs": [{ "name": "cert" }] } },
                ],
            },
        }))
        .unwrap();
        let route: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route", "namespace": "ns" },
            "spec": { "parentRefs": [{ "name": "gw" }], "rules": [{}] },
        }))
        .unwrap();
        let stores = Stores {
            gateway_classes: store_of(vec![torii_class()]),
            gateways: store_of(vec![gw.clone()]),
            routes: store_of(vec![route]),
            ..no_objects()
        };
        let ctx = test_ctx(stores, &[80], &[443]);
        ctx.reconcile_all().await.unwrap();
        let snapshot = ctx.data_plane.load();
        let listeners: Vec<(u16, Option<String>)> = snapshot
            .routes
            .entries
            .iter()
            .map(|e| (e.listener_port, e.listener_hostname.clone()))
            .collect();
        assert_eq!(listeners, [(80, None)]);

        let status = gateway_status(&ctx, &gw, &BTreeMap::new());
        let listener = |name: &str| {
            let listeners = status.listeners.as_deref().unwrap();
            reasons(&listeners.iter().find(|l| l.name == name).unwrap().conditions)[..2].to_vec()
        };
        assert_eq!(
            listener("http"),
            ["Accepted=True/Accepted", "Programmed=True/Programmed"]
        );
        for name in ["http-on-tls", "unbound", "https-on-http"] {
            assert_eq!(
                listener(name),
                ["Accepted=False/PortUnavailable", "Programmed=False/Invalid"],
                "{name}"
            );
        }
        assert_eq!(
            reasons(status.conditions.as_deref().unwrap()),
            ["Accepted=True/ListenersNotValid", "Programmed=False/Invalid"]
        );
    }

    // The spec wants supportedFeatures sorted by name, and torii claims only what
    // its ports can serve (T159).
    #[tokio::test]
    async fn supported_features_are_sorted_and_follow_the_ports() {
        assert!(SUPPORTED_FEATURES.is_sorted());
        let features = |http: &[u16], tls: &[u16]| test_ctx(no_objects(), http, tls).supported_features();
        let all = features(&[80, 8080], &[443]);
        assert_eq!(all, SUPPORTED_FEATURES);
        let shipped = features(&[80], &[443]);
        assert_eq!(shipped.len(), SUPPORTED_FEATURES.len() - 1);
        assert!(!shipped.contains(&"GatewayPort8080"));
        let plain = features(&[80, 8080], &[]);
        assert!(!plain.contains(&"TLSRoute") && !plain.contains(&"TLSRouteModeTerminate"));
    }

    // A Service port's endpoints come from the slice port named like it, with that
    // slice port's number, as in kube-proxy; never from `targetPort`.
    #[tokio::test]
    async fn endpoints_follow_the_slice_port_named_like_the_service_port() {
        let service = |name: &str, ports: serde_json::Value| -> Service {
            serde_json::from_value(serde_json::json!({
                "metadata": { "name": name, "namespace": "ns" },
                "spec": { "ports": ports },
            }))
            .unwrap()
        };
        let slice = |svc: &str, ip: &str, ports: serde_json::Value| -> EndpointSlice {
            serde_json::from_value(serde_json::json!({
                "metadata": {
                    "name": format!("{svc}-{ip}"),
                    "namespace": "ns",
                    "labels": { "kubernetes.io/service-name": svc },
                },
                "addressType": "IPv4",
                "endpoints": [{ "addresses": [ip], "conditions": { "ready": true } }],
                "ports": ports,
            }))
            .unwrap()
        };
        let services = vec![
            // A named targetPort, under another name: the slice port is "http".
            service(
                "named",
                serde_json::json!([{ "name": "http", "port": 80, "targetPort": "web" }]),
            ),
            // An unnamed port with a named targetPort: the slice port is "".
            service("unnamed", serde_json::json!([{ "port": 80, "targetPort": "http" }])),
            // Names crossed with targetPorts.
            service(
                "crossed",
                serde_json::json!([
                    { "name": "a", "port": 80, "targetPort": "b" },
                    { "name": "b", "port": 81, "targetPort": "a" },
                ]),
            ),
            // Selector-less, with a hand-written slice on another port.
            service(
                "external",
                serde_json::json!([{ "name": "http", "port": 80, "targetPort": 80 }]),
            ),
        ];
        let slices = vec![
            slice(
                "named",
                "10.0.0.1",
                serde_json::json!([{ "name": "http", "port": 8080 }]),
            ),
            // Pods whose named port resolves to another number are in their own slice.
            slice(
                "named",
                "10.0.0.2",
                serde_json::json!([{ "name": "http", "port": 9090 }]),
            ),
            slice("unnamed", "10.0.0.3", serde_json::json!([{ "name": "", "port": 8081 }])),
            slice(
                "crossed",
                "10.0.0.4",
                serde_json::json!([{ "name": "b", "port": 7002 }, { "name": "a", "port": 7001 }]),
            ),
            slice(
                "external",
                "10.0.0.5",
                serde_json::json!([{ "name": "http", "port": 8443 }]),
            ),
            // A slice for another protocol of the port's name is not used.
            slice(
                "external",
                "10.0.0.6",
                serde_json::json!([{ "name": "http", "port": 53, "protocol": "UDP" }]),
            ),
        ];

        let stores = Stores {
            services: store_of(services),
            endpoint_slices: store_of(slices),
            ..no_objects()
        };
        let ctx = test_ctx(stores, &[80], &[443]);
        let endpoints = |svc: &str, port: u16| {
            let mut index = BackendIndex::new(ctx.stores.endpoint_slices.state(), UpstreamTlsMap::new());
            ctx.service_endpoints(&mut index, "ns", svc, port)
        };
        let resolve = |svc: &str, port: u16| -> Vec<String> {
            let mut eps: Vec<String> = endpoints(svc, port)
                .unwrap()
                .iter()
                .map(|e| format!("{}:{}", e.ip, e.port))
                .collect();
            eps.sort();
            eps
        };
        assert_eq!(resolve("named", 80), ["10.0.0.1:8080", "10.0.0.2:9090"]);
        assert_eq!(resolve("unnamed", 80), ["10.0.0.3:8081"]);
        assert_eq!(resolve("crossed", 80), ["10.0.0.4:7001"]);
        assert_eq!(resolve("crossed", 81), ["10.0.0.4:7002"]);
        assert_eq!(resolve("external", 80), ["10.0.0.5:8443"]);
        assert!(endpoints("named", 81).is_none());
    }

    // Routes reach backends over TCP: a UDP port with the same number is not theirs
    // (T091). A port whose appProtocol torii cannot speak is invalid (T147).
    #[tokio::test]
    async fn backends_are_tcp_ports_in_a_protocol_torii_speaks() {
        let service = |name: &str, ports: serde_json::Value| -> Service {
            serde_json::from_value(serde_json::json!({
                "metadata": { "name": name, "namespace": "ns" },
                "spec": { "ports": ports },
            }))
            .unwrap()
        };
        let services = vec![
            service(
                "dns",
                serde_json::json!([
                    { "name": "dns-udp", "port": 53, "protocol": "UDP" },
                    { "name": "dns-tcp", "port": 53, "protocol": "TCP" },
                ]),
            ),
            service(
                "apps",
                serde_json::json!([
                    { "name": "plain", "port": 80 },
                    { "name": "http", "port": 81, "appProtocol": "http" },
                    { "name": "ws", "port": 82, "appProtocol": "kubernetes.io/ws" },
                    { "name": "h2c", "port": 83, "appProtocol": "kubernetes.io/h2c" },
                    { "name": "https", "port": 443, "appProtocol": "HTTPS" },
                ]),
            ),
        ];
        let slice: EndpointSlice = serde_json::from_value(serde_json::json!({
            "metadata": { "name": "dns", "namespace": "ns", "labels": { "kubernetes.io/service-name": "dns" } },
            "addressType": "IPv4",
            "endpoints": [{ "addresses": ["10.0.0.1", "10.0.0.2"] }],
            "ports": [
                { "name": "dns-udp", "port": 5353, "protocol": "UDP" },
                { "name": "dns-tcp", "port": 8053, "protocol": "TCP" },
            ],
        }))
        .unwrap();
        let stores = Stores {
            services: store_of(services),
            endpoint_slices: store_of(vec![slice]),
            ..no_objects()
        };
        let ctx = test_ctx(stores, &[80], &[443]);
        let mut index = BackendIndex::new(ctx.stores.endpoint_slices.state(), UpstreamTlsMap::new());
        let endpoints = ctx.service_endpoints(&mut index, "ns", "dns", 53).unwrap();
        let endpoints: Vec<String> = endpoints.iter().map(|e| format!("{}:{}", e.ip, e.port)).collect();
        // The TCP slice port, and only an endpoint's first address.
        assert_eq!(endpoints, ["10.0.0.1:8053"]);

        let unsupported = |index: &BackendIndex, port: u16| ctx.unsupported_app_protocol(index, "ns", "apps", port);
        for port in [80, 81, 82] {
            assert_eq!(unsupported(&index, port), None, "{port}");
        }
        assert!(unsupported(&index, 83).unwrap().contains("kubernetes.io/h2c"));
        assert!(unsupported(&index, 443).unwrap().contains("BackendTLSPolicy"));
        index.upstream_tls.insert(
            ("ns".into(), "apps".into(), 443),
            crate::route_table::BackendTls::Invalid,
        );
        assert_eq!(unsupported(&index, 443), None);
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
