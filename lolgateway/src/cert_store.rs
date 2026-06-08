//! TLS certificate store shared from the control plane to the data plane.
//!
//! The control plane resolves HTTPS-listener certificate Secrets into PEM
//! cert+key pairs keyed by the listener hostname, and atomically swaps in a new
//! [`CertStore`]. The data plane's TLS `certificate_callback` reads it per
//! handshake to select a cert by SNI.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// A resolved server certificate (PEM-encoded chain + private key).
#[derive(Clone)]
pub struct CertKey {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// SNI-hostname → certificate mapping, plus a default for connections with no
/// (or no matching) SNI.
#[derive(Default, Clone)]
pub struct CertStore {
    /// Exact hostname → cert. The empty string "" holds the default cert.
    by_host: HashMap<String, CertKey>,
}

impl CertStore {
    pub fn insert(&mut self, host: impl Into<String>, cert: CertKey) {
        self.by_host.insert(host.into(), cert);
    }

    /// Select a cert for the given SNI: exact match, then a wildcard parent
    /// (`*.example.com` for `a.example.com`), then the default ("").
    pub fn select(&self, sni: Option<&str>) -> Option<&CertKey> {
        if let Some(host) = sni {
            if let Some(c) = self.by_host.get(host) {
                return Some(c);
            }
            // Try a wildcard cert covering this host.
            if let Some((_, rest)) = host.split_once('.') {
                let wild = format!("*.{rest}");
                if let Some(c) = self.by_host.get(&wild) {
                    return Some(c);
                }
            }
        }
        // Fall back to the default cert, or any single cert if there's exactly one.
        self.by_host
            .get("")
            .or_else(|| if self.by_host.len() == 1 { self.by_host.values().next() } else { None })
    }
}

/// Lock-free, atomically-swappable handle to the current [`CertStore`].
#[derive(Clone)]
pub struct SharedCertStore(Arc<ArcSwap<CertStore>>);

impl SharedCertStore {
    pub fn new() -> Self {
        SharedCertStore(Arc::new(ArcSwap::from_pointee(CertStore::default())))
    }

    pub fn store(&self, store: CertStore) {
        self.0.store(Arc::new(store));
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<CertStore>> {
        self.0.load()
    }
}

impl Default for SharedCertStore {
    fn default() -> Self {
        Self::new()
    }
}
