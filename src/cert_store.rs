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

impl CertKey {
    /// Generate a self-signed "fallback" certificate, served as a last resort when
    /// no real cert matches a TLS connection (no SNI match, Secret missing, ACME
    /// not issued yet — or no real certs configured at all). It will NOT validate,
    /// so clients see a security warning, but the handshake completes: a user can
    /// click through and reach the upstream instead of getting an opaque
    /// `SSL_ERROR_NO_CYPHER_OVERLAP`. Generated once at startup; always available,
    /// independent of whether ACME is configured.
    pub fn generate_self_signed() -> Result<CertKey, rcgen::Error> {
        let key = rcgen::KeyPair::generate()?;
        let mut params =
            rcgen::CertificateParams::new(vec!["lolgateway-fallback.invalid".to_string()])?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "lolgateway fallback certificate");
        dn.push(rcgen::DnType::OrganizationName, "lolgateway");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key)?;
        Ok(CertKey {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_fallback_parses_as_cert_and_key() {
        let ck = CertKey::generate_self_signed().unwrap();
        assert!(ck.cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(ck.key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        // The data plane installs it the same way; ensure both halves parse.
        let (_, pem) = x509_parser::pem::parse_x509_pem(&ck.cert_pem).unwrap();
        assert!(pem.parse_x509().is_ok(), "fallback cert must parse as X.509");
    }

    #[test]
    fn select_returns_none_when_empty() {
        // With no certs the callback gets None and serves the fallback instead.
        assert!(CertStore::default().select(Some("home.dirba.io")).is_none());
    }
}
