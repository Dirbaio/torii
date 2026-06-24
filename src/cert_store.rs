//! TLS certificate store the control plane builds for the data plane.
//!
//! The control plane resolves HTTPS-listener certificate Secrets into PEM
//! cert+key pairs keyed by the listener hostname; it's published to the data plane
//! (with the route table) via the atomic [`crate::snapshot::Snapshot`]. The data
//! plane's TLS `certificate_callback` reads it per handshake to select a cert by SNI.

use std::collections::HashMap;

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
