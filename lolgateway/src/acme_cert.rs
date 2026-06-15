//! ACME certificate helpers (rcgen): the TLS-ALPN-01 validation cert and the CSR
//! for the issued cert. Pure functions, no I/O.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, CustomExtension, KeyPair};

/// Build the self-signed TLS-ALPN-01 validation certificate for `host`, carrying
/// the critical `id-pe-acmeIdentifier` extension (RFC 8737) whose value is the
/// SHA-256 of the ACME key authorization. Returned as (cert PEM, key PEM); served
/// ONLY for connections negotiating the `acme-tls/1` ALPN protocol.
pub fn alpn_cert(host: &str, key_auth_digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = KeyPair::generate().context("gen ALPN cert key")?;
    let mut params = CertificateParams::new(vec![host.to_string()])
        .context("ALPN cert params")?;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(key_auth_digest));
    let cert = params.self_signed(&key).context("self-sign ALPN cert")?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

/// Build a DER-encoded CSR for `host`, signed by `key` (whose private key we keep
/// and pair with the issued cert).
pub fn csr_der(key: &KeyPair, host: &str) -> Result<Vec<u8>> {
    let params = CertificateParams::new(vec![host.to_string()]).context("CSR params")?;
    let csr = params.serialize_request(key).context("serialize CSR")?;
    Ok(csr.der().to_vec())
}
