use ayssh::auth::signature::SshSignature;
use ayssh::host_key_verify::{
    AcceptAll, HostKeyAction, HostKeyVerifier, StrictFileStore, TofuFileStore, TofuStore,
};
use ayssh::transport::handshake::{
    generate_client_kexinit_with_prefs, generate_client_kexinit_with_x509, parse_server_kexinit,
};
use ayssh::x509::{CertificateHostKey, ALGORITHM};
use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

const CERT: &[u8] = include_bytes!("vectors/x509/rsa2048.der");
const MESSAGE: &[u8] = include_bytes!("vectors/x509/message.bin");
const SIGNATURE: &[u8] = include_bytes!("vectors/x509/signature.bin");

fn string(blob: &mut Vec<u8>, value: &[u8]) {
    blob.extend_from_slice(&(value.len() as u32).to_be_bytes());
    blob.extend_from_slice(value);
}
fn blob(certs: &[&[u8]], ocsp: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    string(&mut result, ALGORITHM.as_bytes());
    result.extend_from_slice(&(certs.len() as u32).to_be_bytes());
    for cert in certs {
        string(&mut result, cert);
    }
    result.extend_from_slice(&(ocsp.len() as u32).to_be_bytes());
    for response in ocsp {
        string(&mut result, response);
    }
    result
}

#[test]
fn certificate_blob_round_trip() {
    // OCSP unsuccessful response: SEQUENCE { ENUMERATED tryLater(3) }.
    let input = blob(&[CERT], &[b"\x30\x03\x0a\x01\x03"]);
    let key = CertificateHostKey::parse(&input).unwrap();
    assert_eq!(key.encode(), input);
    assert_eq!(key.public_key.n().bits(), 2048);
    assert!(key.subject.contains("ayssh RFC6187 test vector"));
    assert_eq!(key.certificates(), &[CERT.to_vec()]);
    assert_eq!(key.ocsp_responses().len(), 1);
    assert_eq!(key.fingerprint_bytes(), Sha256::digest(CERT).to_vec());
}

#[test]
fn malformed_blobs_are_errors() {
    let good = blob(&[CERT], &[]);
    for length in 0..good.len() {
        assert!(
            CertificateHostKey::parse(&good[..length]).is_err(),
            "prefix {length}"
        );
    }
    assert!(CertificateHostKey::parse(&blob(&[], &[])).is_err());
    assert!(CertificateHostKey::parse(&blob(&[&CERT[..CERT.len() - 1]], &[])).is_err());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(CertificateHostKey::parse(&trailing).is_err());
    let count_offset = 4 + ALGORITHM.len();
    let mut too_many = good.clone();
    too_many[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CertificateHostKey::parse(&too_many).is_err());
    let mut too_many_ocsp = good.clone();
    let len = too_many_ocsp.len();
    too_many_ocsp[len - 4..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CertificateHostKey::parse(&too_many_ocsp).is_err());
    let mut huge_string = good.clone();
    huge_string[count_offset + 4..count_offset + 8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CertificateHostKey::parse(&huge_string).is_err());
    assert!(CertificateHostKey::parse(&vec![0; 1024 * 1024 + 1]).is_err());
    assert!(CertificateHostKey::parse(&blob(&[&vec![0; 256 * 1024 + 1]], &[])).is_err());
    assert!(CertificateHostKey::parse(&blob(&[CERT], &[b"garbage"])).is_err());
    let mut wrong_algorithm = good;
    wrong_algorithm[4] = b'!';
    assert!(CertificateHostKey::parse(&wrong_algorithm).is_err());
}

#[test]
fn known_good_sha1_signature_and_failures() {
    let key = CertificateHostKey::parse(&blob(&[CERT], &[])).unwrap();
    let signature = SshSignature::new("ssh-rsa", SIGNATURE).encode();
    key.verify_signature(MESSAGE, &signature).unwrap();
    assert!(key
        .verify_signature(b"changed exchange hash", &signature)
        .is_err());
    for length in 0..signature.len() {
        assert!(key.verify_signature(MESSAGE, &signature[..length]).is_err());
    }
    let mut bad = signature.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(key.verify_signature(MESSAGE, &bad).is_err());
    let mut trailing = signature;
    trailing.push(0);
    assert!(key.verify_signature(MESSAGE, &trailing).is_err());
    for algorithm in [ALGORITHM, "rsa-sha2-256"] {
        assert!(key
            .verify_signature(MESSAGE, &SshSignature::new(algorithm, SIGNATURE).encode())
            .is_err());
    }
}

#[test]
fn negotiation_is_opt_in_and_defaults_are_unchanged() {
    let original =
        parse_server_kexinit(&generate_client_kexinit_with_prefs(None, None, None)).unwrap();
    let disabled =
        parse_server_kexinit(&generate_client_kexinit_with_x509(None, None, None, false)).unwrap();
    assert_eq!(
        original.server_host_key_algorithms,
        disabled.server_host_key_algorithms
    );
    assert!(!disabled
        .server_host_key_algorithms
        .iter()
        .any(|a| a == ALGORITHM));
    let enabled =
        parse_server_kexinit(&generate_client_kexinit_with_x509(None, None, None, true)).unwrap();
    assert_eq!(enabled.server_host_key_algorithms[0], ALGORITHM);
    assert_eq!(
        enabled.server_host_key_algorithms[1..],
        original.server_host_key_algorithms
    );
    let mut server = original.clone();
    server.server_host_key_algorithms = vec![ALGORITHM.into()];
    assert!(disabled.select_common_algorithms(&server).is_err());
    assert_eq!(
        enabled.select_common_algorithms(&server).unwrap().host_key,
        ALGORITHM
    );
}

#[tokio::test]
async fn tofu_and_strict_stores_pin_leaf_fingerprint() {
    let input = blob(&[CERT], &[]);
    let changed_chain = blob(&[CERT, CERT], &[b"\x30\x03\x0a\x01\x03"]);
    let store = TofuStore::new();
    assert_eq!(
        store.verify("test-host", 2222, ALGORITHM, &input).await,
        HostKeyAction::AcceptNew
    );
    assert_eq!(
        store
            .verify("test-host", 2222, ALGORITHM, &changed_chain)
            .await,
        HostKeyAction::Accept
    );
    assert_eq!(
        store.verify("test-host", 2222, ALGORITHM, b"bad").await,
        HostKeyAction::Reject
    );
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("known_hosts");
    let file = TofuFileStore::new(&path).unwrap();
    assert_eq!(
        file.verify("test-host", 2222, ALGORITHM, &input).await,
        HostKeyAction::AcceptNew
    );
    let digest = Sha256::digest(CERT);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap().trim(),
        format!("[test-host]:2222 {ALGORITHM} {}", STANDARD.encode(digest))
    );
    let strict = StrictFileStore::new(&path).unwrap();
    assert_eq!(
        strict
            .verify("test-host", 2222, ALGORITHM, &changed_chain)
            .await,
        HostKeyAction::Accept
    );
    assert_eq!(
        strict.verify("unknown", 2222, ALGORITHM, &input).await,
        HostKeyAction::RejectUnknown
    );
    std::fs::write(
        &path,
        format!(
            "[test-host]:2222 {ALGORITHM} {}\n",
            STANDARD.encode([0u8; 32])
        ),
    )
    .unwrap();
    let wrong_pin = StrictFileStore::new(&path).unwrap();
    assert_eq!(
        wrong_pin.verify("test-host", 2222, ALGORITHM, &input).await,
        HostKeyAction::Reject
    );
    let reloaded = TofuFileStore::new(&path).unwrap();
    assert_eq!(
        reloaded.verify("test-host", 2222, ALGORITHM, &input).await,
        HostKeyAction::Reject
    );
    assert!(AcceptAll
        .verify("test-host", 2222, ALGORITHM, &input)
        .await
        .is_accepted());
}
