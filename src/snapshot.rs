//! The single control-plane → data-plane snapshot.
//!
//! The control plane recomputes the entire data-plane view — the [`RouteTable`]
//! and the TLS [`CertStore`] — from the full set of watched objects, then
//! publishes both together in ONE atomic swap. Publishing them together means a
//! reader never observes a torn state (e.g. new routes paired with stale certs).
//! The data plane reads the current snapshot lock-free on every request/handshake.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::cert_store::{CertKey, CertStore};
use crate::route_table::RouteTable;
use crate::tls_table::TlsTable;

/// Everything the data plane needs, published atomically as a unit.
#[derive(Default)]
pub struct Snapshot {
    pub routes: RouteTable,
    pub certs: CertStore,
    /// SNI dispatch for TLSRoute (passthrough / terminate-then-TCP). Empty unless
    /// a `protocol: TLS` listener with attached TLSRoutes exists.
    pub tls: TlsTable,
}

/// In-flight ACME TLS-ALPN-01 challenge certs, keyed by SNI hostname (lowercased).
/// Served by the data plane ONLY for connections negotiating the `acme-tls/1`
/// ALPN protocol. Published independently of the [`Snapshot`] because it churns on
/// a different rhythm (during issuance, not on every route change) and any instance
/// — not just the ACME leader — must serve it.
pub type ChallengeStore = HashMap<String, CertKey>;

/// Lock-free, atomically-swappable handles the data plane reads. Cheap to clone
/// (Arc-backed); shared between the control plane, the ACME task, and the proxy.
#[derive(Clone)]
pub struct DataPlane {
    snapshot: Arc<ArcSwap<Snapshot>>,
    challenges: Arc<ArcSwap<ChallengeStore>>,
    /// Whether the control plane has published a snapshot yet.
    published: Arc<tokio::sync::watch::Sender<bool>>,
}

impl Default for DataPlane {
    fn default() -> Self {
        Self {
            snapshot: Default::default(),
            challenges: Default::default(),
            published: Arc::new(tokio::sync::watch::Sender::new(false)),
        }
    }
}

impl DataPlane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new routing/cert snapshot. Readers see it on their next `load`.
    pub fn store(&self, snapshot: Snapshot) {
        self.snapshot.store(Arc::new(snapshot));
        self.published.send_if_modified(|p| !std::mem::replace(p, true));
    }

    /// Wait until the first snapshot is published. Runs on any executor.
    pub async fn wait_published(&self) {
        let _ = self.published.subscribe().wait_for(|&p| p).await;
    }

    /// Load the current snapshot (cheap, lock-free).
    pub fn load(&self) -> arc_swap::Guard<Arc<Snapshot>> {
        self.snapshot.load()
    }

    /// Publish the current set of ACME challenge certs.
    pub fn store_challenges(&self, challenges: ChallengeStore) {
        self.challenges.store(Arc::new(challenges));
    }

    /// Load the current challenge certs (cheap, lock-free).
    pub fn load_challenges(&self) -> arc_swap::Guard<Arc<ChallengeStore>> {
        self.challenges.load()
    }
}
