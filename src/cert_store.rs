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
            rcgen::CertificateParams::new(vec!["torii-fallback.invalid".to_string()])?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "torii fallback certificate");
        dn.push(rcgen::DnType::OrganizationName, "torii");
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
    /// (`*.example.com` for `a.example.com`), then the explicit default ("" — a
    /// listener configured with no hostname). Returns `None` when nothing matches;
    /// the caller then serves the self-signed fallback rather than a cert for some
    /// *other* host. We deliberately do NOT serve "the lone configured cert" for a
    /// non-matching SNI — presenting a cert whose name the client didn't ask for is
    /// a least-surprise / info-leak quirk (it leaks that cert's SANs), and a
    /// validating client rejects it anyway.
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
        // Fall back only to an EXPLICIT default cert (the "" key, a no-hostname
        // listener). No match → None → the self-signed fallback.
        self.by_host.get("")
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

    fn dummy_cert() -> CertKey {
        CertKey { cert_pem: b"c".to_vec(), key_pem: b"k".to_vec() }
    }

    #[test]
    fn select_matches_exact_wildcard_and_default() {
        let mut s = CertStore::default();
        s.insert("a.example.com", dummy_cert());
        s.insert("*.wild.com", dummy_cert());
        s.insert("", dummy_cert()); // explicit default (no-hostname listener)
        assert!(s.select(Some("a.example.com")).is_some(), "exact");
        assert!(s.select(Some("x.wild.com")).is_some(), "wildcard parent");
        assert!(s.select(Some("anything.else")).is_some(), "falls to explicit default");
        assert!(s.select(None).is_some(), "no SNI → explicit default");
    }

    #[test]
    fn select_does_not_serve_lone_cert_for_nonmatching_sni() {
        // L10: with a single configured cert and a non-matching SNI (and no explicit
        // "" default), selection must return None — NOT the lone cert for some other
        // host. The caller then serves the self-signed fallback.
        let mut s = CertStore::default();
        s.insert("only.example.com", dummy_cert());
        assert!(s.select(Some("only.example.com")).is_some(), "exact still matches");
        assert!(s.select(Some("other.host")).is_none(), "must not serve the lone cert");
        assert!(s.select(None).is_none(), "no SNI, no default → None");
    }
}
