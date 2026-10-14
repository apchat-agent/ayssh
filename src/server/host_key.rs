//! SSH server host key management
//!
//! Supports generating, loading, and signing with host keys.
//! Used by the test SSH server for KEXDH_REPLY signatures.

use crate::error::SshError;
use bytes::{BufMut, BytesMut};

/// ECDSA curve for host keys
#[derive(Debug, Clone, Copy)]
pub enum EcdsaCurve {
    Nistp256,
    Nistp384,
    Nistp521,
}

/// A server host key pair (private + public)
#[derive(Clone)]
pub enum HostKeyPair {
    /// Ed25519 host key (fast generation, recommended for testing)
    Ed25519(ed25519_dalek::SigningKey),
    /// RSA host key
    Rsa(Box<rsa::RsaPrivateKey>),
    /// ECDSA host key (curve + signing key bytes)
    Ecdsa(EcdsaCurve, Vec<u8>),
}

impl HostKeyPair {
    /// Generate a new Ed25519 host key pair (instant, no entropy concerns)
    pub fn generate_ed25519() -> Self {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        Self::Ed25519(signing_key)
    }

    /// Generate a new RSA host key pair (slow - ~100ms for 2048 bits)
    pub fn generate_rsa(bits: usize) -> Result<Self, SshError> {
        use rand::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| SshError::CryptoError(format!("RSA key generation failed: {}", e)))?;
        Ok(Self::Rsa(Box::new(private_key)))
    }

    /// Generate a new ECDSA P-256 host key pair
    pub fn generate_ecdsa_p256() -> Self {
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        Self::Ecdsa(EcdsaCurve::Nistp256, secret.to_bytes().to_vec())
    }

    /// Generate a new ECDSA P-384 host key pair
    pub fn generate_ecdsa_p384() -> Self {
        let secret = p384::SecretKey::random(&mut rand::rngs::OsRng);
        Self::Ecdsa(EcdsaCurve::Nistp384, secret.to_bytes().to_vec())
    }

    /// Generate a new ECDSA P-521 host key pair
    pub fn generate_ecdsa_p521() -> Self {
        let secret = p521::SecretKey::random(&mut rand::rngs::OsRng);
        Self::Ecdsa(EcdsaCurve::Nistp521, secret.to_bytes().to_vec())
    }

    /// Load an ECDSA key from OpenSSH private key format
    pub fn load_openssh_ecdsa(path: &std::path::Path) -> Result<Self, SshError> {
        let key_data = std::fs::read(path)
            .map_err(|e| SshError::IoError(e))?;
        let pem_content = String::from_utf8_lossy(&key_data);
        let private_key = crate::auth::key::PrivateKey::parse_pem(&pem_content)?;
        match private_key {
            crate::auth::key::PrivateKey::Ecdsa(curve, scalar) => {
                let host_curve = match curve {
                    crate::auth::key::EcdsaCurve::Nistp256 => EcdsaCurve::Nistp256,
                    crate::auth::key::EcdsaCurve::Nistp384 => EcdsaCurve::Nistp384,
                    crate::auth::key::EcdsaCurve::Nistp521 => EcdsaCurve::Nistp521,
                };
                Ok(Self::Ecdsa(host_curve, scalar))
            }
            _ => Err(SshError::CryptoError("Expected ECDSA key".to_string())),
        }
    }

    /// Load an RSA key from OpenSSH private key format
    pub fn load_openssh_rsa(path: &std::path::Path) -> Result<Self, SshError> {
        let key_data = std::fs::read(path)
            .map_err(|e| SshError::IoError(e))?;
        let pem_content = String::from_utf8_lossy(&key_data);
        let private_key = crate::auth::key::PrivateKey::parse_pem(&pem_content)?;
        match private_key {
            crate::auth::key::PrivateKey::Rsa(rsa_key) => Ok(Self::Rsa(Box::new(rsa_key))),
            _ => Err(SshError::CryptoError("Expected RSA key".to_string())),
        }
    }

    /// Get the SSH algorithm name for this key type
    pub fn algorithm_name(&self) -> &str {
        match self {
            Self::Ed25519(_) => "ssh-ed25519",
            Self::Rsa(_) => "ssh-rsa",
            Self::Ecdsa(EcdsaCurve::Nistp256, _) => "ecdsa-sha2-nistp256",
            Self::Ecdsa(EcdsaCurve::Nistp384, _) => "ecdsa-sha2-nistp384",
            Self::Ecdsa(EcdsaCurve::Nistp521, _) => "ecdsa-sha2-nistp521",
        }
    }

    /// Host-key algorithms available with this loaded key.
    pub fn supported_algorithms(&self) -> &'static [&'static str] {
        match self {
            Self::Rsa(_) => &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
            Self::Ed25519(_) => &["ssh-ed25519"],
            Self::Ecdsa(EcdsaCurve::Nistp256, _) => &["ecdsa-sha2-nistp256"],
            Self::Ecdsa(EcdsaCurve::Nistp384, _) => &["ecdsa-sha2-nistp384"],
            Self::Ecdsa(EcdsaCurve::Nistp521, _) => &["ecdsa-sha2-nistp521"],
        }
    }

    /// Encode the public key in SSH wire format (for KEXDH_REPLY K_S field)
    /// Format: string(algorithm_name) || key-specific-data
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        match self {
            Self::Ed25519(signing_key) => {
                let algorithm = b"ssh-ed25519";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                let public_key = signing_key.verifying_key();
                let pk_bytes = public_key.to_bytes();
                buf.put_u32(pk_bytes.len() as u32);
                buf.put_slice(&pk_bytes);
            }
            Self::Rsa(private_key) => {
                use rsa::traits::PublicKeyParts;
                let algorithm = b"ssh-rsa";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                // Exponent e (as mpint)
                let e = private_key.e().to_bytes_be();
                put_mpint(&mut buf, &e);
                // Modulus n (as mpint)
                let n = private_key.n().to_bytes_be();
                put_mpint(&mut buf, &n);
            }
            Self::Ecdsa(curve, scalar) => {
                let (algo, curve_name, pubkey_bytes) = match curve {
                    EcdsaCurve::Nistp256 => {
                        use p256::elliptic_curve::sec1::ToEncodedPoint;
                        let secret = p256::SecretKey::from_slice(scalar)
                            .expect("Invalid P-256 host key");
                        let point = secret.public_key().to_encoded_point(false);
                        ("ecdsa-sha2-nistp256", "nistp256", point.as_bytes().to_vec())
                    }
                    EcdsaCurve::Nistp384 => {
                        use p384::elliptic_curve::sec1::ToEncodedPoint;
                        let secret = p384::SecretKey::from_slice(scalar)
                            .expect("Invalid P-384 host key");
                        let point = secret.public_key().to_encoded_point(false);
                        ("ecdsa-sha2-nistp384", "nistp384", point.as_bytes().to_vec())
                    }
                    EcdsaCurve::Nistp521 => {
                        use p521::elliptic_curve::sec1::ToEncodedPoint;
                        let secret = p521::SecretKey::from_slice(scalar)
                            .expect("Invalid P-521 host key");
                        let point = secret.public_key().to_encoded_point(false);
                        ("ecdsa-sha2-nistp521", "nistp521", point.as_bytes().to_vec())
                    }
                };
                put_string(&mut buf, algo.as_bytes());
                put_string(&mut buf, curve_name.as_bytes());
                put_string(&mut buf, &pubkey_bytes);
            }
        }
        buf.to_vec()
    }

    /// Sign data with this host key, returning SSH wire-format signature.
    /// For KEXDH_REPLY, the data is the exchange hash H.
    /// Returns: string(algorithm) || string(signature_blob)
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SshError> {
        self.sign_with_algorithm(data, self.algorithm_name())
    }

    /// Sign H with the host-key algorithm selected during negotiation.
    pub fn sign_with_algorithm(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, SshError> {
        let valid = algorithm == self.algorithm_name() ||
            (matches!(self, Self::Rsa(_)) && matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512"));
        if !valid {
            return Err(SshError::CryptoError("Host key cannot sign with negotiated algorithm".into()));
        }
        let mut buf = BytesMut::new();
        match self {
            Self::Ed25519(signing_key) => {
                use ed25519_dalek::Signer;
                let signature = signing_key.sign(data);
                let sig_bytes = signature.to_bytes();

                let algorithm = b"ssh-ed25519";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                buf.put_u32(sig_bytes.len() as u32);
                buf.put_slice(&sig_bytes);
            }
            Self::Rsa(private_key) => {
                use sha1::Digest;
                use rsa::Pkcs1v15Sign;
                let (scheme, hash) = match algorithm {
                    "rsa-sha2-256" => (Pkcs1v15Sign::new::<sha2::Sha256>(), sha2::Sha256::digest(data).to_vec()),
                    "rsa-sha2-512" => (Pkcs1v15Sign::new::<sha2::Sha512>(), sha2::Sha512::digest(data).to_vec()),
                    _ => (Pkcs1v15Sign::new::<sha1::Sha1>(), sha1::Sha1::digest(data).to_vec()),
                };
                let sig_bytes = private_key.sign(scheme, &hash)
                    .map_err(|e| SshError::CryptoError(format!("RSA signing failed: {}", e)))?;
                let algorithm = algorithm.as_bytes();
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                buf.put_u32(sig_bytes.len() as u32);
                buf.put_slice(&sig_bytes);
            }
            Self::Ecdsa(curve, scalar) => {
                use signature::Signer;

                let (algo, sig_blob) = match curve {
                    EcdsaCurve::Nistp256 => {
                        let secret = p256::SecretKey::from_slice(scalar)
                            .map_err(|e| SshError::CryptoError(format!("P-256: {}", e)))?;
                        let signing_key = p256::ecdsa::SigningKey::from(secret);
                        let sig: p256::ecdsa::Signature = signing_key.sign(data);
                        let r = sig.r().to_bytes();
                        let s = sig.s().to_bytes();
                        ("ecdsa-sha2-nistp256", encode_rs_mpint(&r, &s))
                    }
                    EcdsaCurve::Nistp384 => {
                        let secret = p384::SecretKey::from_slice(scalar)
                            .map_err(|e| SshError::CryptoError(format!("P-384: {}", e)))?;
                        let signing_key = p384::ecdsa::SigningKey::from(secret);
                        let sig: p384::ecdsa::Signature = signing_key.sign(data);
                        let r = sig.r().to_bytes();
                        let s = sig.s().to_bytes();
                        ("ecdsa-sha2-nistp384", encode_rs_mpint(&r, &s))
                    }
                    EcdsaCurve::Nistp521 => {
                        let signing_key = p521::ecdsa::SigningKey::from_slice(scalar)
                            .map_err(|e| SshError::CryptoError(format!("P-521: {}", e)))?;
                        let sig: p521::ecdsa::Signature = signing_key.sign(data);
                        let r = sig.r().to_bytes();
                        let s = sig.s().to_bytes();
                        ("ecdsa-sha2-nistp521", encode_rs_mpint(&r, &s))
                    }
                };

                buf.put_u32(algo.len() as u32);
                buf.put_slice(algo.as_bytes());
                buf.put_u32(sig_blob.len() as u32);
                buf.put_slice(&sig_blob);
            }
        }
        Ok(buf.to_vec())
    }
}

impl std::fmt::Debug for HostKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519(_) => write!(f, "HostKeyPair::Ed25519(...)"),
            Self::Rsa(_) => write!(f, "HostKeyPair::Rsa(...)"),
            Self::Ecdsa(curve, _) => write!(f, "HostKeyPair::Ecdsa({:?}, ...)", curve),
        }
    }
}

/// Encode an SSH string: 4-byte length prefix + data
fn put_string(buf: &mut BytesMut, data: &[u8]) {
    buf.put_u32(data.len() as u32);
    buf.put_slice(data);
}

/// Encode ECDSA r and s values as mpint(r) || mpint(s)
fn encode_rs_mpint(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut blob = BytesMut::new();
    put_mpint(&mut blob, r);
    put_mpint(&mut blob, s);
    blob.to_vec()
}

/// Encode a big-endian byte array as SSH mpint (with 0x00 prefix if high bit set)
fn put_mpint(buf: &mut BytesMut, value: &[u8]) {
    if !value.is_empty() && (value[0] & 0x80) != 0 {
        buf.put_u32((value.len() + 1) as u32);
        buf.put_u8(0x00);
        buf.put_slice(value);
    } else {
        buf.put_u32(value.len() as u32);
        buf.put_slice(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519() {
        let key = HostKeyPair::generate_ed25519();
        assert_eq!(key.algorithm_name(), "ssh-ed25519");

        let blob = key.public_key_blob();
        // ssh-ed25519 blob: [4+11 algorithm] + [4+32 key] = 51 bytes
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(&blob[4..15], b"ssh-ed25519");
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let key = HostKeyPair::generate_ed25519();
        let data = b"test exchange hash data for signing";
        let sig = key.sign(data).unwrap();

        // Verify signature structure: string("ssh-ed25519") || string(64-byte sig)
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 11);
        assert_eq!(&sig[4..15], b"ssh-ed25519");
        let sig_len = u32::from_be_bytes([sig[15], sig[16], sig[17], sig[18]]) as usize;
        assert_eq!(sig_len, 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_ed25519_different_keys_different_sigs() {
        let key1 = HostKeyPair::generate_ed25519();
        let key2 = HostKeyPair::generate_ed25519();
        let data = b"same data different keys";
        let sig1 = key1.sign(data).unwrap();
        let sig2 = key2.sign(data).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_load_rsa_from_test_keys() {
        let path = std::path::Path::new("tests/keys/test_rsa_2048");
        if !path.exists() {
            return; // Skip if keys not available
        }
        let key = HostKeyPair::load_openssh_rsa(path).unwrap();
        assert_eq!(key.algorithm_name(), "ssh-rsa");

        let blob = key.public_key_blob();
        // RSA blob starts with string("ssh-rsa")
        let alg_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(alg_len, 7);
        assert_eq!(&blob[4..11], b"ssh-rsa");
    }

    #[test]
    fn test_rsa_sign() {
        let path = std::path::Path::new("tests/keys/test_rsa_2048");
        if !path.exists() {
            return;
        }
        let key = HostKeyPair::load_openssh_rsa(path).unwrap();
        let data = b"test exchange hash";
        let sig = key.sign(data).unwrap();

        // Verify structure: string("ssh-rsa") || string(256-byte sig)
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 7);
        assert_eq!(&sig[4..11], b"ssh-rsa");
        let sig_len = u32::from_be_bytes([sig[11], sig[12], sig[13], sig[14]]) as usize;
        assert_eq!(sig_len, 256); // RSA-2048 signature
    }

    #[test]
    fn test_generate_ecdsa_p256() {
        let key = HostKeyPair::generate_ecdsa_p256();
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp256");

        let blob = key.public_key_blob();
        let alg_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(alg_len, 19); // "ecdsa-sha2-nistp256"
        assert_eq!(&blob[4..23], b"ecdsa-sha2-nistp256");
    }

    #[test]
    fn test_generate_ecdsa_p384() {
        let key = HostKeyPair::generate_ecdsa_p384();
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp384");
    }

    #[test]
    fn test_ecdsa_p256_sign() {
        let key = HostKeyPair::generate_ecdsa_p256();
        let data = b"test exchange hash for ECDSA";
        let sig = key.sign(data).unwrap();

        // Verify structure: string("ecdsa-sha2-nistp256") || string(mpint(r) || mpint(s))
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 19);
        assert_eq!(&sig[4..23], b"ecdsa-sha2-nistp256");
        // sig_blob follows
        let sig_blob_len = u32::from_be_bytes([sig[23], sig[24], sig[25], sig[26]]) as usize;
        assert!(sig_blob_len > 0);
    }

    #[test]
    fn test_ecdsa_p384_sign() {
        let key = HostKeyPair::generate_ecdsa_p384();
        let data = b"test exchange hash for P-384";
        let sig = key.sign(data).unwrap();
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 19); // "ecdsa-sha2-nistp384"
    }

    #[test]
    fn test_load_ecdsa_from_test_keys() {
        let path = std::path::Path::new("tests/keys/test_ecdsa_256");
        let key = HostKeyPair::load_openssh_ecdsa(path).unwrap();
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp256");
        let blob = key.public_key_blob();
        assert!(!blob.is_empty());
    }

    #[test]
    fn test_ecdsa_different_keys_different_sigs() {
        let key1 = HostKeyPair::generate_ecdsa_p256();
        let key2 = HostKeyPair::generate_ecdsa_p256();
        let data = b"same data different keys";
        let sig1 = key1.sign(data).unwrap();
        let sig2 = key2.sign(data).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_generate_ecdsa_p521() {
        let key = HostKeyPair::generate_ecdsa_p521();
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp521");

        let blob = key.public_key_blob();
        let alg_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(alg_len, 19); // "ecdsa-sha2-nistp521"
        assert_eq!(&blob[4..23], b"ecdsa-sha2-nistp521");
    }

    #[test]
    fn test_ecdsa_p521_sign() {
        let key = HostKeyPair::generate_ecdsa_p521();
        let data = b"test exchange hash for P-521";
        let sig = key.sign(data).unwrap();
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 19); // "ecdsa-sha2-nistp521"
        assert_eq!(&sig[4..23], b"ecdsa-sha2-nistp521");
        // sig_blob follows
        let sig_blob_len = u32::from_be_bytes([sig[23], sig[24], sig[25], sig[26]]) as usize;
        assert!(sig_blob_len > 0);
    }

    #[test]
    fn test_ed25519_public_key_blob_deterministic() {
        let key = HostKeyPair::generate_ed25519();
        let blob1 = key.public_key_blob();
        let blob2 = key.public_key_blob();
        assert_eq!(blob1, blob2);
    }
}
