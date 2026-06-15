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

/// Everything the data plane needs, published atomically as a unit.
#[derive(Default)]
pub struct Snapshot {
    pub routes: RouteTable,
    pub certs: CertStore,
}

/// In-flight ACME TLS-ALPN-01 challenge certs, keyed by SNI hostname (lowercased).
/// Served by the data plane ONLY for connections negotiating the `acme-tls/1`
/// ALPN protocol. Published independently of the [`Snapshot`] because it churns on
/// a different rhythm (during issuance, not on every route change) and any instance
/// — not just the ACME leader — must serve it.
pub type ChallengeStore = HashMap<String, CertKey>;

/// Lock-free, atomically-swappable handles the data plane reads. Cheap to clone
/// (Arc-backed); shared between the control plane, the ACME task, and the proxy.
#[derive(Clone, Default)]
pub struct DataPlane {
    snapshot: Arc<ArcSwap<Snapshot>>,
    challenges: Arc<ArcSwap<ChallengeStore>>,
}

impl DataPlane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new routing/cert snapshot. Readers see it on their next `load`.
    pub fn store(&self, snapshot: Snapshot) {
        self.snapshot.store(Arc::new(snapshot));
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
