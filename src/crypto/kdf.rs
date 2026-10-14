//! Key Derivation Function (KDF) for SSH
//!
//! This module implements the Key Derivation Function as defined in RFC 4253 Section 7.
//! The KDF is used to derive cryptographic keys from the shared secret (DH exchange output).
//!
//! # SSH KDF Specification
//!
//! The KDF takes the following inputs:
//! - `shared_secret` (Z): The shared secret from Diffie-Hellman exchange
//! - `session_id`: The session ID (hash of exchange)
//! - `counter`: The counter value (1 for encryption key, 2 for MAC key, etc.)
//! - `desired_length`: The length of the output key in bytes
//!
//! The KDF function is defined as:
//! ```text
//! KDF(N, S, H, C, L) =
//!     K[1] = H(S || C || N || 0x00000001)
//!     K[2] = H(S || C || N || 0x00000002)
//!     ...
//!     KDF = K[1] || K[2] || ... || K[m]
//! ```
//!
//! Where:
//! - H = SHA-256 (in our implementation)
//! - S = shared secret
//! - C = session ID
//! - N = counter (1, 2, 3, ...)
//! - L = desired output length
//! - m = ceil(L / H.len)

use ring::digest::{self, SHA256};
use sha1::{Digest, Sha1};

/// Hash algorithm for KDF
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// Derive cryptographic keys using the SSH KDF
///
/// This function implements the Key Derivation Function as defined in RFC 4253 Section 7.
/// It derives keys from the shared secret using SHA-256 as the hash function.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret from Diffie-Hellman exchange (Z)
/// * `session_id` - The session ID (hash of exchange)
/// * `counter` - The counter value (1 for encryption key, 2 for MAC key, etc.)
/// * `desired_length` - The length of the output key in bytes
///
/// # Returns
///
/// A vector containing the derived key of the specified length.
///
/// # Example
///
/// ```
/// use ayssh::crypto::kdf::kdf;
/// use ayssh::crypto::HashAlgorithm;
///
/// // Derive an AES-256 encryption key using SHA-256
/// let shared_secret = b"dh_shared_secret";
/// let session_id = b"session_id";
/// let counter = 1u32;
/// let key = kdf(shared_secret, session_id, counter, 32, HashAlgorithm::Sha256);
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Security Considerations
///
/// - The shared secret should be securely erased after key derivation
/// - Different counters produce different keys from the same inputs
/// - The session ID ensures keys are unique per session
pub fn kdf(
    shared_secret: &[u8],
    session_id: &[u8],
    counter: u32,
    desired_length: usize,
    hash_algo: HashAlgorithm,
) -> Vec<u8> {
    if desired_length == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(desired_length);
    let hash_len = match hash_algo {
        HashAlgorithm::Sha1 => 20,   // SHA-1 produces 20 bytes
        HashAlgorithm::Sha256 => 32, // SHA-256 produces 32 bytes
        HashAlgorithm::Sha384 => 48,
        HashAlgorithm::Sha512 => 64,
    };
    let num_blocks = (desired_length + hash_len - 1) / hash_len;

    for i in 1..=num_blocks {
        let hash_output = match hash_algo {
            HashAlgorithm::Sha1 => {
                // RFC 4253 Section 7.2:
                // K1 = HASH(K || H || X || session_id)
                // K2 = HASH(K || H || K1)           ← NO X here!
                // K3 = HASH(K || H || K1 || K2)     ← NO X here!
                // key = K1 || K2 || K3 || ...

                let mut hasher = Sha1::new();
                let k_mpint = crate::crypto::dh::Mpint::encode_length_prefixed(
                    &num_bigint::BigUint::from_bytes_be(shared_secret),
                );
                hasher.update(&k_mpint); // K
                hasher.update(session_id); // H

                if i == 1 {
                    hasher.update(&[(counter as u8)]); // X (only in K1!)
                    hasher.update(session_id); // session_id
                } else {
                    hasher.update(&result); // K1 || K2 || ... (NO X)
                }

                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => {
                let algorithm = match hash_algo {
                    HashAlgorithm::Sha384 => &digest::SHA384,
                    HashAlgorithm::Sha512 => &digest::SHA512,
                    _ => &SHA256,
                };
                let mut hasher = digest::Context::new(algorithm);
                let k_mpint = crate::crypto::dh::Mpint::encode_length_prefixed(
                    &num_bigint::BigUint::from_bytes_be(shared_secret),
                );
                hasher.update(&k_mpint); // K
                hasher.update(session_id); // H

                if i == 1 {
                    hasher.update(&[(counter as u8)]); // X (only in K1!)
                    hasher.update(session_id); // session_id
                } else {
                    hasher.update(&result); // K1 || K2 || ... (NO X)
                }

                hasher.finish().as_ref().to_vec()
            }
        };

        // Add full block or truncate to desired length
        let remaining = desired_length - result.len();
        if remaining >= hash_len {
            result.extend_from_slice(&hash_output);
        } else {
            result.extend_from_slice(&hash_output[..remaining]);
        }
    }

    result.truncate(desired_length);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_simple() {
        let shared_secret = b"shared_secret_data";
        let session_id = b"session_id_data";
        let counter = 1u32;
        let desired_length = 32;

        let result = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        assert_eq!(result.len(), desired_length);
    }

    #[test]
    fn test_kdf_multiblock() {
        let shared_secret = b"shared_secret_data";
        let session_id = b"session_id_data";
        let counter = 1u32;
        let desired_length = 64; // More than one SHA256 block

        let result = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        assert_eq!(result.len(), desired_length);
    }

    #[test]
    fn test_kdf_empty_secret() {
        let shared_secret = b"";
        let session_id = b"session_id";
        let counter = 1u32;
        let desired_length = 32;

        let result = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        assert_eq!(result.len(), desired_length);
    }

    #[test]
    fn test_kdf_counter_increment() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let result1 = kdf(shared_secret, session_id, 1, 32, HashAlgorithm::Sha256);
        let result2 = kdf(shared_secret, session_id, 2, 32, HashAlgorithm::Sha256);

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_determinism() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 32;

        let result1 = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        let result2 = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_kdf_zero_length() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 0;

        let result = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_kdf_one_byte() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 1;

        let result = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_kdf_different_session_id() {
        let shared_secret = b"secret";
        let session_id1 = b"session1";
        let session_id2 = b"session2";
        let counter = 1u32;
        let desired_length = 32;

        let result1 = kdf(
            shared_secret,
            session_id1,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );
        let result2 = kdf(
            shared_secret,
            session_id2,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_non_zero_output() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 32;

        let result = kdf(
            shared_secret,
            session_id,
            counter,
            desired_length,
            HashAlgorithm::Sha256,
        );

        // Should not be all zeros
        assert!(!result.iter().all(|&b| b == 0));
    }
}
