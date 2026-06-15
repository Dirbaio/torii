//! The single control-plane → data-plane snapshot.
//!
//! The control plane recomputes the entire data-plane view — the [`RouteTable`]
//! and the TLS [`CertStore`] — from the full set of watched objects, then
//! publishes both together in ONE atomic swap. Publishing them together means a
//! reader never observes a torn state (e.g. new routes paired with stale certs).
//! The data plane reads the current snapshot lock-free on every request/handshake.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::cert_store::CertStore;
use crate::route_table::RouteTable;

/// Everything the data plane needs, published atomically as a unit.
#[derive(Default)]
pub struct Snapshot {
    pub routes: RouteTable,
    pub certs: CertStore,
}

/// Lock-free, atomically-swappable handle to the current [`Snapshot`]. Cheap to
/// clone (it's an `Arc`); share one between the control plane and data plane.
#[derive(Clone, Default)]
pub struct DataPlane(Arc<ArcSwap<Snapshot>>);

impl DataPlane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new snapshot. Readers see it on their next `load`.
    pub fn store(&self, snapshot: Snapshot) {
        self.0.store(Arc::new(snapshot));
    }

    /// Load the current snapshot (cheap, lock-free).
    pub fn load(&self) -> arc_swap::Guard<Arc<Snapshot>> {
        self.0.load()
    }
}
