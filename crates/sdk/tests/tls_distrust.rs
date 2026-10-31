#![cfg(feature = "network")]

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, IsCa, KeyPair, PublicKeyData, SignatureAlgorithm,
};
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{ServerName, UnixTime},
    CertificateError, RootCertStore,
};

// Public EMDVTLSCAG3B key from rustls/webpki's src/data/distrusted fixture.
// Only the public EC point is needed; no compromised private key is used.
struct EmSignKey;

impl PublicKeyData for EmSignKey {
    fn der_bytes(&self) -> &[u8] {
        &[
            0x04, 0xe7, 0x9e, 0xd9, 0xc0, 0x4a, 0x97, 0x73, 0xc4, 0x73, 0x5e, 0x51, 0x11, 0x1d,
            0xa8, 0x5a, 0xc2, 0xbd, 0x5e, 0x64, 0xab, 0x37, 0x4b, 0x80, 0xe1, 0x2c, 0xbc, 0x20,
            0x38, 0xec, 0x1e, 0x4f, 0x0e, 0x3b, 0x81, 0x2f, 0xc9, 0x85, 0x9e, 0x1e, 0x67, 0xaf,
            0xb0, 0x4e, 0x2f, 0x8b, 0xc9, 0x7f, 0x74, 0x85, 0xba, 0x65, 0xaa, 0x91, 0x1e, 0xe8,
            0xa4, 0xe4, 0x5b, 0x62, 0xd5, 0xcc, 0x03, 0xd5, 0x6b, 0xe6, 0x78, 0xb3, 0xc3, 0x8c,
            0xb4, 0xdc, 0x93, 0x7c, 0xa2, 0x46, 0x0e, 0x23, 0x84, 0x53, 0xc8, 0x92, 0x93, 0x5d,
            0x29, 0xd4, 0x4f, 0x91, 0xe1, 0x56, 0x06, 0xb6, 0x3c, 0xce, 0xda, 0xb4, 0x68,
        ]
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P384_SHA384
    }
}

#[test]
fn rejects_emsign_key_even_when_cross_signed_by_a_trusted_ca() {
    for issuer in ["first issuer", "second issuer"] {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![issuer.into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let name = ServerName::try_from("localhost").unwrap();

        let ordinary_key = KeyPair::generate().unwrap();
        let ordinary = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&ordinary_key, &ca, &ca_key)
            .unwrap();
        verifier.verify_server_cert(ordinary.der(), &[], &name, &[], UnixTime::now()).unwrap();

        // A valid issuer signature must not restore trust in a blocked subject key.
        let distrusted = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&EmSignKey, &ca, &ca_key)
            .unwrap();
        let error = verifier
            .verify_server_cert(distrusted.der(), &[], &name, &[], UnixTime::now())
            .unwrap_err();
        let rustls::Error::InvalidCertificate(CertificateError::Other(error)) = error else {
            panic!("expected explicit public-key distrust, got {error:?}");
        };
        assert_eq!(error.0.downcast_ref::<webpki::Error>(), Some(&webpki::Error::CertDistrusted));
    }
}

#[test]
fn builtin_roots_exclude_emsign_g3() {
    assert!(!webpki_roots::TLS_SERVER_ROOTS.iter().any(|root| {
        root.subject
            .as_ref()
            .windows(b"emSign ECC Root CA - G3".len())
            .any(|name| name == b"emSign ECC Root CA - G3")
    }));
}
