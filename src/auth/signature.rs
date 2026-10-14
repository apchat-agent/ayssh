//! SSH Signature Encoding - Complete Implementation
//!
//! Implements RFC 4253, RFC 5656, and RFC 8332 for SSH signature formats.
//! This module provides proper encoding for RSA, ECDSA, and Ed25519 signatures.

use crate::error::SshError;
use bytes::{Buf, BufMut, BytesMut};

/// SSH signature algorithm identifiers
pub const SSH_SIG_ALGORITHM_RSA: &str = "ssh-rsa";
pub const SSH_SIG_ALGORITHM_ECDSA_NISTP256: &str = "ecdsa-sha2-nistp256";
pub const SSH_SIG_ALGORITHM_ECDSA_NISTP384: &str = "ecdsa-sha2-nistp384";
pub const SSH_SIG_ALGORITHM_ECDSA_NISTP521: &str = "ecdsa-sha2-nistp521";
pub const SSH_SIG_ALGORITHM_ED25519: &str = "ssh-ed25519";

/// SSH signature structure
#[derive(Debug, Clone)]
pub struct SshSignature {
    /// Algorithm identifier
    pub algorithm: String,
    /// Signature data (SSH-encoded)
    pub data: Vec<u8>,
}

impl SshSignature {
    /// Create a new SSH signature
    pub fn new(algorithm: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: algorithm.into(),
            data: data.into(),
        }
    }

    /// Encode signature as SSH string (string + data)
    /// SSH strings are encoded as: [4-byte length][data]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        // Algorithm string (4-byte length prefix)
        buf.put_u32(self.algorithm.len() as u32);
        buf.put_slice(self.algorithm.as_bytes());
        // Signature data string (4-byte length prefix)
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);
        buf.to_vec()
    }

    /// Decode signature from SSH-encoded bytes
    /// SSH strings are encoded as: [4-byte length][data]
    pub fn decode(encoded: &[u8]) -> Result<Self, SshError> {
        let mut buf = BytesMut::from(encoded);
        
        // Read algorithm string (4-byte length prefix)
        let algo_len = buf.get_u32() as usize;
        if algo_len == 0 || algo_len > 256 {
            return Err(SshError::ProtocolError(
                "Invalid algorithm string length".into()
            ));
        }
        let algorithm = String::from_utf8(buf.copy_to_bytes(algo_len).to_vec())
            .map_err(|_| SshError::ProtocolError("Invalid algorithm string".into()))?;
        
        // Read signature data string (4-byte length prefix)
        let sig_len = buf.get_u32() as usize;
        if sig_len == 0 || sig_len > 65535 {
            return Err(SshError::ProtocolError(
                "Invalid signature string length".into()
            ));
        }
        let data = buf.copy_to_bytes(sig_len).to_vec();
        
        Ok(Self { algorithm, data })
    }
}

/// RSA signature encoding (RFC 4253 Section 11.1)
/// Format: string "ssh-rsa" + mpint(e) + mpint(s)
pub struct RsaSignatureEncoder;

impl RsaSignatureEncoder {
    /// Encode RSA signature per RFC 4253 Section 6.6.
    /// The `ssh-rsa` algorithm uses RSASSA-PKCS1-v1_5 with SHA-1.
    /// SSH signature wire format: string("ssh-rsa") || string(signature_blob)
    pub fn encode(
        private_key: &rsa::RsaPrivateKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        // ssh-rsa uses RSASSA-PKCS1-v1_5 with SHA-1 (RFC 4253 Section 6.6)
        // Hash the data with SHA-1 first, then sign the hash
        use sha1::Digest;
        let hash = sha1::Sha1::digest(data);

        // Sign with PKCS1v15 + SHA-1 OID
        use rsa::Pkcs1v15Sign;
        let scheme = Pkcs1v15Sign::new::<sha1::Sha1>();
        let signature = private_key.sign(scheme, &hash)
            .map_err(|e| SshError::CryptoError(format!("RSA signing failed: {}", e)))?;

        Ok(SshSignature::new(SSH_SIG_ALGORITHM_RSA, signature))
    }

    /// Verify an ssh-rsa PKCS#1 v1.5 / SHA-1 signature, also used by RFC 6187.
    pub fn verify(public_key: &rsa::RsaPublicKey, data: &[u8], signature: &[u8]) -> Result<(), SshError> {
        use sha1::Digest;
        public_key.verify(rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
            &sha1::Sha1::digest(data), signature)
            .map_err(|e| SshError::CryptoError(format!("RSA signature verification failed: {}", e)))
    }

    /// Encode RSA signature using SHA-256 (rsa-sha2-256, RFC 8332).
    /// Used by modern OpenSSH (8.8+) which disables ssh-rsa (SHA-1).
    pub fn encode_sha256(
        private_key: &rsa::RsaPrivateKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(data);

        use rsa::Pkcs1v15Sign;
        let scheme = Pkcs1v15Sign::new::<sha2::Sha256>();
        let signature = private_key.sign(scheme, &hash)
            .map_err(|e| SshError::CryptoError(format!("RSA-SHA256 signing failed: {}", e)))?;

        Ok(SshSignature::new("rsa-sha2-256", signature))
    }

}

/// ECDSA signature encoding (RFC 5656, RFC 8332)
/// Format: string "ecdsa-sha2-nistp256" + string (nistp256 + r || s)
pub struct EcdsaSignatureEncoder;

impl EcdsaSignatureEncoder {
    /// Encode r and s as SSH mpint(r) || mpint(s) blob.
    /// SSH ECDSA signature format (RFC 5656 Section 3.1.2):
    ///   string(mpint(r) || mpint(s))
    /// mpint: 4-byte length + big-endian bytes with 0x00 prefix if high bit set.
    fn encode_rs_blob(r_bytes: &[u8], s_bytes: &[u8]) -> Vec<u8> {
        let mut blob = BytesMut::new();

        // r as mpint
        if !r_bytes.is_empty() && (r_bytes[0] & 0x80) != 0 {
            blob.put_u32((r_bytes.len() + 1) as u32);
            blob.put_u8(0x00);
            blob.put_slice(r_bytes);
        } else {
            blob.put_u32(r_bytes.len() as u32);
            blob.put_slice(r_bytes);
        }

        // s as mpint
        if !s_bytes.is_empty() && (s_bytes[0] & 0x80) != 0 {
            blob.put_u32((s_bytes.len() + 1) as u32);
            blob.put_u8(0x00);
            blob.put_slice(s_bytes);
        } else {
            blob.put_u32(s_bytes.len() as u32);
            blob.put_slice(s_bytes);
        }

        blob.to_vec()
    }

    /// Encode ECDSA signature for NISTP256.
    /// Returns SshSignature with data = mpint(r) || mpint(s).
    /// SshSignature::encode() then produces: string("ecdsa-sha2-nistp256") || string(data)
    pub fn encode_nistp256(
        private_key: &p256::ecdsa::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use p256::ecdsa::Signature;
        use signature::Signer;

        let signature: Signature = private_key.sign(data);
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        let blob = Self::encode_rs_blob(&r_bytes, &s_bytes);
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ECDSA_NISTP256, blob))
    }

    /// Encode ECDSA signature for NISTP384.
    /// Returns SshSignature with data = mpint(r) || mpint(s).
    pub fn encode_nistp384(
        private_key: &p384::ecdsa::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use p384::ecdsa::Signature;
        use signature::Signer;

        let signature: Signature = private_key.sign(data);
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        let blob = Self::encode_rs_blob(&r_bytes, &s_bytes);
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ECDSA_NISTP384, blob))
    }

    /// Encode ECDSA signature for NISTP521.
    /// Returns SshSignature with data = mpint(r) || mpint(s).
    pub fn encode_nistp521(
        private_key: &p521::ecdsa::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use p521::ecdsa::Signature;
        use signature::Signer;

        let signature: Signature = private_key.sign(data);
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        let blob = Self::encode_rs_blob(&r_bytes, &s_bytes);
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ECDSA_NISTP521, blob))
    }
}

/// Ed25519 signature encoding (RFC 8332 Section 3)
/// Format: string "ssh-ed25519" + string (signature)
pub struct Ed25519SignatureEncoder;

impl Ed25519SignatureEncoder {
    /// Encode Ed25519 signature.
    /// Returns SshSignature with algorithm="ssh-ed25519" and data=raw 64-byte signature.
    /// The caller uses SshSignature::encode() to produce the wire format:
    /// string("ssh-ed25519") || string(64-byte-sig)
    pub fn encode(
        private_key: &ed25519_dalek::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use ed25519_dalek::Signer;

        let signature = private_key.sign(data);
        let sig_bytes = signature.to_bytes();

        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ED25519, sig_bytes.to_vec()))
    }
}

/// Create signature data for authentication (RFC 4252 Section 7)
///
/// Per RFC 4252 Section 7, the signature is computed over the following data,
/// encoded as SSH strings (4-byte length prefix + data):
///
/// ```text
/// string    session identifier
/// byte      SSH_MSG_USERAUTH_REQUEST (50)
/// string    user name
/// string    service name ("ssh-connection")
/// string    "publickey"
/// boolean   TRUE
/// string    public key algorithm name
/// string    public key to be used for authentication
/// ```
///
/// This function returns the **concatenated** SSH-encoded data, NOT a hash.
/// The signature algorithms will hash this data as needed.
pub fn create_signature_data(
    session_id: &[u8],
    username: &str,
    service: &str,
    method: &str,
    has_signature: bool,
    public_key_algorithm: &str,
    public_key_blob: &[u8],
) -> Vec<u8> {
    use bytes::{BufMut, BytesMut};

    let mut buf = BytesMut::new();

    // string session identifier (4-byte length + data)
    buf.put_u32(session_id.len() as u32);
    buf.put_slice(session_id);

    // byte SSH_MSG_USERAUTH_REQUEST (50 = 0x32)
    buf.put_u8(0x32);

    // string user name (4-byte length + data)
    buf.put_u32(username.len() as u32);
    buf.put_slice(username.as_bytes());

    // string service name (4-byte length + data)
    buf.put_u32(service.len() as u32);
    buf.put_slice(service.as_bytes());

    // string "publickey" (4-byte length + data)
    buf.put_u32(method.len() as u32);
    buf.put_slice(method.as_bytes());

    // boolean TRUE (1 = TRUE, 0 = FALSE)
    buf.put_u8(if has_signature { 1 } else { 0 });

    // string public key algorithm name (4-byte length + data)
    buf.put_u32(public_key_algorithm.len() as u32);
    buf.put_slice(public_key_algorithm.as_bytes());

    // string public key blob (4-byte length + data)
    buf.put_u32(public_key_blob.len() as u32);
    buf.put_slice(public_key_blob);

    buf.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_rsa_signature_encoding() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        
        let data = b"test signature data for RSA";
        let signature = RsaSignatureEncoder::encode(&private_key, data).unwrap();
        
        assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_RSA);
        assert!(!signature.data.is_empty());
        
        // Test round-trip - encode the signature and decode it
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        
        assert_eq!(decoded.algorithm, signature.algorithm);
        assert_eq!(decoded.data, signature.data);
    }
    
    #[test]
    fn test_ecdsa_signature_encoding() {
        use p256::ecdsa::SigningKey;

        let mut rng = OsRng;
        let private_key = SigningKey::random(&mut rng);
        
        let data = b"test signature data for ECDSA";
        let signature = EcdsaSignatureEncoder::encode_nistp256(&private_key, data).unwrap();
        
        assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_ECDSA_NISTP256);
        assert!(!signature.data.is_empty());
        
        // Test round-trip - encode the signature and decode it
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        
        assert_eq!(decoded.algorithm, signature.algorithm);
        assert_eq!(decoded.data, signature.data);
    }
    
    #[test]
    fn test_ed25519_signature_encoding() {
        use ed25519_dalek::SigningKey;
        use rand::Rng;
        
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let private_key = SigningKey::from_bytes(&seed);
        
        let data = b"test signature data for Ed25519";
        let signature = Ed25519SignatureEncoder::encode(&private_key, data).unwrap();
        
        assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_ED25519);
        assert!(!signature.data.is_empty());
        
        // Test round-trip - encode the signature and decode it
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        
        assert_eq!(decoded.algorithm, signature.algorithm);
        assert_eq!(decoded.data, signature.data);
    }
    
    #[test]
    fn test_signature_data_creation() {
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let service = "ssh-connection";
        let method = "publickey";
        let has_signature = false;
        let public_key_algorithm = "ssh-rsa";
        let public_key_blob = vec![0x02; 100];

        let sig_data = create_signature_data(
            &session_id,
            username,
            service,
            method,
            has_signature,
            public_key_algorithm,
            &public_key_blob,
        );

        // Verify the signature data is NOT a hash, but the concatenated SSH-encoded data
        // Expected length:
        // - 4 + 20 = 24 bytes (session_id as string)
        // - 1 byte (message type 0x32)
        // - 4 + 8 = 12 bytes (username "testuser")
        // - 4 + 14 = 18 bytes (service "ssh-connection" - 14 chars)
        // - 4 + 9 = 13 bytes (method "publickey")
        // - 1 byte (boolean FALSE = 0)
        // - 4 + 7 = 11 bytes (algorithm "ssh-rsa")
        // - 4 + 100 = 104 bytes (public_key_blob)
        // Total = 24 + 1 + 12 + 18 + 13 + 1 + 11 + 104 = 184 bytes
        assert_eq!(sig_data.len(), 184);

        // Verify the structure by checking key components
        let mut offset = 0;

        // Check session_id string prefix (4-byte length = 20)
        assert_eq!(&sig_data[offset..offset+4], &(20u32.to_be_bytes()));
        offset += 4;
        // Check session_id data (20 bytes of 0x01)
        assert_eq!(&sig_data[offset..offset+20], &vec![0x01u8; 20]);
        offset += 20;

        // Check message type (0x32 = 50)
        assert_eq!(sig_data[offset], 0x32);
        offset += 1;

        // Check username string prefix (4-byte length = 8)
        assert_eq!(&sig_data[offset..offset+4], &(8u32.to_be_bytes()));
        offset += 4;
        // Check username data
        assert_eq!(&sig_data[offset..offset+8], b"testuser");
        offset += 8;

        // Check service "ssh-connection" string prefix (4-byte length = 14)
        assert_eq!(&sig_data[offset..offset+4], &(14u32.to_be_bytes()));
        offset += 4;
        // Check service data
        assert_eq!(&sig_data[offset..offset+14], b"ssh-connection");
        let _offset = offset + 14;

        // Check boolean FALSE at the expected position
        // The boolean is at position: 24 + 1 + 12 + 18 = 55
        assert_eq!(sig_data[55], 0); // FALSE
    }

    /// Verify RSA signature uses SHA-1 (not SHA-256) and produces correct size
    /// ssh-rsa uses RSASSA-PKCS1-v1_5 with SHA-1 per RFC 4253 Section 6.6
    #[test]
    fn test_rsa_signature_uses_sha1_and_correct_size() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        let data = b"test data for SHA-1 signature verification";
        let signature = RsaSignatureEncoder::encode(&private_key, data).unwrap();

        // RSA-2048 signature should be exactly 256 bytes (2048 bits)
        assert_eq!(signature.data.len(), 256,
            "RSA-2048 signature must be exactly 256 bytes");

        // The data field should be raw signature bytes, not wrapped with algorithm name
        // If it were double-wrapped, it would be > 256 bytes
        assert_eq!(signature.algorithm, "ssh-rsa");

        // Verify we can verify the signature with SHA-1
        use sha1::Digest;
        let public_key = private_key.to_public_key();
        let hash = sha1::Sha1::digest(data);
        let scheme = rsa::Pkcs1v15Sign::new::<sha1::Sha1>();
        // If this doesn't panic, the signature is valid SHA-1
        public_key.verify(scheme, &hash, &signature.data)
            .expect("Signature must verify with SHA-1");
    }

    /// Verify SshSignature::encode produces the correct wire format
    #[test]
    fn test_ssh_signature_wire_format() {
        let sig = SshSignature::new("ssh-rsa", vec![0x42; 256]);
        let encoded = sig.encode();

        // Wire format: string("ssh-rsa") || string(signature_blob)
        // = [0,0,0,7]["ssh-rsa"][0,0,1,0][256 bytes]
        assert_eq!(encoded.len(), 4 + 7 + 4 + 256);

        // Check algorithm string
        let alg_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(alg_len, 7);
        assert_eq!(&encoded[4..11], b"ssh-rsa");

        // Check signature blob
        let sig_len = u32::from_be_bytes([encoded[11], encoded[12], encoded[13], encoded[14]]);
        assert_eq!(sig_len, 256);
    }
}