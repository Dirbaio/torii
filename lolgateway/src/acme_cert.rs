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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_cert_has_acme_identifier_and_san() {
        // A 32-byte digest (SHA-256 of a key authorization).
        let digest = [0xABu8; 32];
        let (cert_pem, key_pem) = alpn_cert("test.example.com", &digest).unwrap();
        assert!(cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));

        // Parse it back: the SAN must be the host, and the critical
        // id-pe-acmeIdentifier extension (1.3.6.1.5.5.7.1.31) must be present and
        // contain the digest (DER: OCTET STRING tag 0x04, len 0x20, then 32 bytes).
        let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem).unwrap();
        let cert = pem.parse_x509().unwrap();
        let san = cert
            .subject_alternative_name()
            .unwrap()
            .expect("SAN present");
        let has_host = san.value.general_names.iter().any(|n| {
            matches!(n, x509_parser::extensions::GeneralName::DNSName(h) if *h == "test.example.com")
        });
        assert!(has_host, "SAN must contain the host");

        let acme_oid = x509_parser::der_parser::oid!(1.3.6.1.5.5.7.1.31);
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid == acme_oid)
            .expect("id-pe-acmeIdentifier extension present");
        assert!(ext.critical, "acmeIdentifier must be critical");
        // value = DER OCTET STRING wrapping the 32-byte digest.
        let mut expected = vec![0x04, 0x20];
        expected.extend_from_slice(&digest);
        assert_eq!(ext.value, expected.as_slice(), "extension must carry the digest");
    }

    #[test]
    fn csr_is_valid_der_for_host() {
        use x509_parser::prelude::FromDer;
        let key = KeyPair::generate().unwrap();
        let der = csr_der(&key, "csr.example.com").unwrap();
        // Round-trips as a parseable PKCS#10 CSR with the host as a SAN.
        let (rest, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der)
                .expect("valid CSR DER");
        assert!(rest.is_empty(), "CSR consumes all DER");
        let der_str = String::from_utf8_lossy(&der);
        // The requested SAN/subject hostname appears in the encoded request.
        assert!(
            der.windows(b"csr.example.com".len()).any(|w| w == b"csr.example.com"),
            "CSR encodes the host"
        );
        let _ = (csr, der_str); // parsed successfully
    }
}
