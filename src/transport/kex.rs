//! Key Exchange (KEX) Implementation
//!
//! Implements various key exchange algorithms as defined in RFC 4253 Section 7.
//! Supports:
//! - diffie-hellman-group14-sha256 (RFC 8731)
//! - diffie-hellman-group-exchange-sha256 (RFC 4253)
//! - curve25519-sha256 (RFC 8731)
//! - ecdh-sha2-nistp256/384/521 (RFC 5656)

use crate::crypto::dh::{DhGroup, Mpint};
use crate::crypto::ecdh::{CurveType, EcdhKeyPair};
use crate::crypto::kdf;
use crate::protocol;
use bytes::{BufMut, BytesMut};
use rand::{Rng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use tracing::debug;

/// Key exchange context
#[derive(Debug)]
pub struct KexContext {
    /// Selected algorithm
    pub algorithm: protocol::KexAlgorithm,
    /// Client's ephemeral key
    pub client_ephemeral: Option<Vec<u8>>,
    /// Server's ephemeral key
    pub server_ephemeral: Option<Vec<u8>>,
    /// Client's private key (for DH)
    client_private: Option<num_bigint::BigUint>,
    /// Server's public key (for DH)
    server_public: Option<num_bigint::BigUint>,
    /// Client's ECDH key pair (for ECDH algorithms)
    client_ecdh_keypair: Option<EcdhKeyPair>,
    /// Server's ECDH public key
    server_ecdh_public: Option<Vec<u8>>,
    /// Shared secret (if computed)
    pub shared_secret: Option<Vec<u8>>,
    /// Session ID (if computed)
    pub session_id: Option<Vec<u8>>,
    /// Client version string (V_C)
    client_version: Option<Vec<u8>>,
    /// Server version string (V_S)
    server_version: Option<Vec<u8>>,
    /// Client KEXINIT payload (I_C)
    client_kexinit: Option<Vec<u8>>,
    /// Server KEXINIT payload (I_S)
    server_kexinit: Option<Vec<u8>>,
    /// Server host key (H_S)
    server_host_key: Option<Vec<u8>>,
}

impl KexContext {
    /// Create a new KEX context
    pub fn new(algorithm: protocol::KexAlgorithm) -> Self {
        Self {
            algorithm,
            client_ephemeral: None,
            server_ephemeral: None,
            client_private: None,
            server_public: None,
            client_ecdh_keypair: None,
            server_ecdh_public: None,
            shared_secret: None,
            session_id: None,
            client_version: None,
            server_version: None,
            client_kexinit: None,
            server_kexinit: None,
            server_host_key: None,
        }
    }

    /// Set the version strings and KEXINIT payloads
    pub fn set_exchange_info(
        &mut self,
        client_version: &[u8],
        server_version: &[u8],
        client_kexinit: &[u8],
        server_kexinit: &[u8],
    ) {
        self.client_version = Some(client_version.to_vec());
        self.server_version = Some(server_version.to_vec());
        self.client_kexinit = Some(client_kexinit.to_vec());
        self.server_kexinit = Some(server_kexinit.to_vec());
    }

    /// Set the server host key
    pub fn set_server_host_key(&mut self, host_key: &[u8]) {
        self.server_host_key = Some(host_key.to_vec());
    }

    /// Determine the curve type for an ECDH algorithm
    fn get_curve_type(&self) -> Option<CurveType> {
        match self.algorithm {
            protocol::KexAlgorithm::Curve25519Sha256 => Some(CurveType::Curve25519),
            protocol::KexAlgorithm::EcdhSha2Nistp256 => Some(CurveType::Nistp256),
            protocol::KexAlgorithm::EcdhSha2Nistp384 => Some(CurveType::Nistp384),
            protocol::KexAlgorithm::EcdhSha2Nistp521 => Some(CurveType::Nistp521),
            _ => None,
        }
    }

   /// Generate client's ephemeral key for the selected algorithm
    pub fn generate_client_key(&mut self, rng: &mut impl RngCore) -> anyhow::Result<()> {
        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup1Sha1 => {
                let group = DhGroup::group1();
                tracing::debug!("DH Group1 prime bits: {}", group.p.bits());
                // For 1024-bit group, use 1024 bits for private key
                let private_x = group.generate_private_key(rng, 1024);
                let public_y = group.compute_public_key(&private_x);
                
                tracing::debug!("DH Group1: private key bits={}, public key bits={}", private_x.bits(), public_y.bits());
                
                self.client_private = Some(private_x);
                self.client_ephemeral = Some(Mpint::encode(&public_y));
                tracing::debug!("DH Group1: ephemeral encoded size={} bytes", self.client_ephemeral.as_ref().unwrap().len());
                Ok(())
            }
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha1 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
            protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha384 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup16Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup18Sha512 => {
                let group = DhGroup::group14();
                let private_x = group.generate_private_key(rng, 256);
                let public_y = group.compute_public_key(&private_x);

                self.client_private = Some(private_x);
                self.client_ephemeral = Some(Mpint::encode(&public_y));
                Ok(())
            }
            protocol::KexAlgorithm::EcdhSha2Nistp256 |
            protocol::KexAlgorithm::EcdhSha2Nistp384 |
            protocol::KexAlgorithm::EcdhSha2Nistp521 |
            protocol::KexAlgorithm::Curve25519Sha256 => {
                // Generate real ECDH key pair
                if let Some(curve) = self.get_curve_type() {
                    let keypair = EcdhKeyPair::generate(curve, rng);
                    self.client_ecdh_keypair = Some(keypair.clone());
                    self.client_ephemeral = Some(keypair.encode_public_key());
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Unknown ECDH algorithm"))
                }
            }
        }
    }

    /// Process server's key exchange message
    /// For DH algorithms, expects length-prefixed MPINT (f) from KEXDH_REPLY
    /// For ECDH algorithms, expects the encoded public key
    pub fn process_server_kex_init(&mut self, data: &[u8]) -> anyhow::Result<()> {
        // Check if this is an ECDH algorithm
        if let Some(curve) = self.get_curve_type() {
            // For ECDH, data starts with SSH string Q_S (length-prefixed public key)
            if data.len() < 4 {
                return Err(anyhow::anyhow!("ECDH server key too short"));
            }
            let qs_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if data.len() < 4 + qs_len {
                return Err(anyhow::anyhow!("ECDH server key truncated"));
            }
            let qs_raw = &data[4..4 + qs_len];
            let decoded = EcdhKeyPair::decode_public_key(curve, qs_raw)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            self.server_ecdh_public = Some(decoded);
            // Store as length-prefixed SSH string for exchange hash
            self.server_ephemeral = Some(data[..4 + qs_len].to_vec());
        } else {
            // For DH, data starts with length-prefixed MPINT (f)
            // The rest (signature) is ignored here
            let (server_public, _remaining) = Mpint::decode_length_prefixed(data)?;

            // RFC 4253 Section 8: "Values of 'e' or 'f' that are not in the range
            // [1, p-1] MUST NOT be sent or accepted by either side."
            let one = num_bigint::BigUint::from(1u8);
            let group_p = self.get_dh_group_prime();
            if server_public < one || server_public >= group_p {
                return Err(anyhow::anyhow!(
                    "Server DH public key out of range [1, p-1] (RFC 4253 Section 8)"
                ));
            }

            self.server_public = Some(server_public);
            
            // Store the encoded MPINT as server_ephemeral for session hash computation
            if data.len() >= 4 {
                let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if data.len() >= 4 + len {
                    self.server_ephemeral = Some(data[..4+len].to_vec());
                }
            }
        }
        Ok(())
    }

    /// Get the DH group prime p for the current algorithm
    fn get_dh_group_prime(&self) -> num_bigint::BigUint {
        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup1Sha1 => {
                DhGroup::group1().p
            }
            _ => {
                // All other DH algorithms use group14 or larger
                DhGroup::group14().p
            }
        }
    }

    /// Compute the shared secret and session ID
    pub fn compute_shared_secret(&mut self) -> anyhow::Result<()> {
        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup1Sha1 => {
                // For DH, compute shared secret: s = server_public^client_private mod p
                if let (Some(ref server_pub), Some(ref client_priv)) = 
                    (&self.server_public, &self.client_private) {
                    let group = DhGroup::group1();
                    let shared = group.compute_shared_secret(server_pub, client_priv);
                    // Store shared secret as raw bytes (not MPINT encoded)
                    self.shared_secret = Some(shared.to_bytes_be());
                } else {
                    return Err(anyhow::anyhow!("Missing private or public key for DH"));
                }
            }
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha1 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
            protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha384 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup16Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup18Sha512 => {
                // For DH, compute shared secret: s = server_public^client_private mod p
                if let (Some(ref server_pub), Some(ref client_priv)) =
                    (&self.server_public, &self.client_private) {
                    let group = DhGroup::group14();
                    let shared = group.compute_shared_secret(server_pub, client_priv);
                    // Store shared secret as raw bytes (not MPINT encoded)
                    self.shared_secret = Some(shared.to_bytes_be());
                } else {
                    return Err(anyhow::anyhow!("Missing private or public key for DH"));
                }
            }
            protocol::KexAlgorithm::Curve25519Sha256 |
            protocol::KexAlgorithm::EcdhSha2Nistp256 |
            protocol::KexAlgorithm::EcdhSha2Nistp384 |
            protocol::KexAlgorithm::EcdhSha2Nistp521 => {
                // For ECDH, compute shared secret using elliptic curve multiplication
                if let (Some(ref keypair), Some(ref server_pub)) = 
                    (&self.client_ecdh_keypair, &self.server_ecdh_public) {
                    if self.algorithm == protocol::KexAlgorithm::Curve25519Sha256 && server_pub.len() != 32 {
                        return Err(anyhow::anyhow!("Invalid X25519 public key length"));
                    }
                    let shared = keypair.compute_shared_secret(server_pub);
                    if self.algorithm == protocol::KexAlgorithm::Curve25519Sha256 {
                        use subtle::ConstantTimeEq;
                        if bool::from(shared.as_slice().ct_eq(&[0u8; 32])) {
                            return Err(anyhow::anyhow!("Non-contributory X25519 shared secret"));
                        }
                    }
                    self.shared_secret = Some(shared);
                } else {
                    return Err(anyhow::anyhow!("Missing ECDH keypair or server public key"));
                }
            }
        }
        
        // After computing shared secret, compute the session ID
        // According to RFC 4253, the session ID is the exchange hash H for the first key exchange
        let session_id = self.compute_session_id()?;
        debug!("Session ID (first 16 bytes): {:?}", &session_id[..std::cmp::min(16, session_id.len())]);
        debug!("Shared secret (first 16 bytes): {:?}", self.shared_secret.as_ref().map(|s| &s[..std::cmp::min(16, s.len())]).unwrap_or(&[]));
        self.session_id = Some(session_id);
        
        Ok(())
    }

    /// Compute the exchange hash (H) and set it as session ID
    /// According to RFC 4253 Section 8:
    /// H = Hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
    pub fn compute_session_id(&mut self) -> anyhow::Result<Vec<u8>> {
        let hash_input = self.build_hash_input()?;
        debug!("Exchange hash input: {} bytes", hash_input.len());

        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup1Sha1 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(&hash_input);
                Ok(hasher.finalize().to_vec())
            }
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
            protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha384 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup16Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup18Sha512 => {
                let mut hasher = Sha256::new();
                self.update_session_hash(&mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
            protocol::KexAlgorithm::Curve25519Sha256 => {
                let mut hasher = Sha256::new();
                self.update_session_hash(&mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
            protocol::KexAlgorithm::EcdhSha2Nistp256 => {
                let mut hasher = Sha256::new();
                self.update_session_hash(&mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
            protocol::KexAlgorithm::EcdhSha2Nistp384 => {
                let mut hasher = Sha384::new();
                self.update_session_hash(&mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
            protocol::KexAlgorithm::EcdhSha2Nistp521 => {
                // SHA-512 for p521
                use sha2::Sha512;
                let mut hasher = Sha512::new();
                self.update_session_hash(&mut hasher)?;
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// Update a hasher with the session hash components per RFC 4253 Section 8.
    /// H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
    ///
    /// All fields are encoded as SSH strings (4-byte length prefix + data) or
    /// SSH mpints (4-byte length prefix + value with sign handling).
    /// Build the raw hash input for debugging and for direct hashing
    fn build_hash_input(&self) -> anyhow::Result<Vec<u8>> {
        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(4 + data.len());
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }

        let mut input = Vec::new();

        if let Some(ref vc) = self.client_version {
            let vc_clean = vc.strip_suffix(b"\r\n").unwrap_or(vc.strip_suffix(b"\n").unwrap_or(vc));
            input.extend_from_slice(&ssh_string(vc_clean));
        }
        if let Some(ref vs) = self.server_version {
            let vs_clean = vs.strip_suffix(b"\r\n").unwrap_or(vs.strip_suffix(b"\n").unwrap_or(vs));
            input.extend_from_slice(&ssh_string(vs_clean));
        }
        if let Some(ref ic) = self.client_kexinit {
            input.extend_from_slice(&ssh_string(ic));
        }
        if let Some(ref is_payload) = self.server_kexinit {
            input.extend_from_slice(&ssh_string(is_payload));
        }
        if let Some(ref hs) = self.server_host_key {
            input.extend_from_slice(&ssh_string(hs));
        }
        if let Some(ref ec) = self.client_ephemeral {
            input.extend_from_slice(&ssh_string(ec));
        }
        if let Some(ref es) = self.server_ephemeral {
            input.extend_from_slice(es); // already length-prefixed
        }
        if let Some(ref ss) = self.shared_secret {
            let biguint = num_bigint::BigUint::from_bytes_be(ss);
            let mpint = crate::crypto::dh::Mpint::encode_length_prefixed(&biguint);
            input.extend_from_slice(&mpint);
        } else {
            return Err(anyhow::anyhow!("Shared secret not computed"));
        }

        Ok(input)
    }

    fn update_session_hash<H: Digest>(&mut self, hasher: &mut H) -> anyhow::Result<()> {
        // Helper: encode as SSH string (4-byte big-endian length + data)
        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(4 + data.len());
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }

        if let Some(ref vc) = self.client_version {
            let vc_clean = vc.strip_suffix(b"\r\n").unwrap_or(vc.strip_suffix(b"\n").unwrap_or(vc));
            hasher.update(&ssh_string(vc_clean));
        }
        if let Some(ref vs) = self.server_version {
            let vs_clean = vs.strip_suffix(b"\r\n").unwrap_or(vs.strip_suffix(b"\n").unwrap_or(vs));
            hasher.update(&ssh_string(vs_clean));
        }
        if let Some(ref ic) = self.client_kexinit {
            hasher.update(&ssh_string(ic));
        }
        if let Some(ref is_payload) = self.server_kexinit {
            hasher.update(&ssh_string(is_payload));
        }
        if let Some(ref hs) = self.server_host_key {
            hasher.update(&ssh_string(hs));
        }
        if let Some(ref ec) = self.client_ephemeral {
            hasher.update(&ssh_string(ec));
        }
        if let Some(ref es) = self.server_ephemeral {
            // server_ephemeral is already length-prefixed from wire data
            hasher.update(es);
        }
        if let Some(ref ss) = self.shared_secret {
            let biguint = num_bigint::BigUint::from_bytes_be(ss);
            let mpint = crate::crypto::dh::Mpint::encode_length_prefixed(&biguint);
            hasher.update(&mpint);
        } else {
            return Err(anyhow::anyhow!("Shared secret not computed"));
        }

        Ok(())
    }

    /// Generate the session hash (H) - deprecated, use compute_session_id instead
    #[deprecated(note = "Use compute_session_id instead")]
    pub fn generate_session_hash(&mut self, _session_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.compute_session_id()
    }

    /// Derive session keys from shared secret and session hash
    /// 
    /// Key derivation follows RFC 4253 Section 7.2:
    /// String K = SSH_KEX_ALG || E_C || E_S || K_S || H
    /// String V = session_id
    /// Key = Hash(K || V || A) || Hash(K || V || B) || ...
    /// where A, B, C, ... are single bytes starting with 1
    pub fn derive_session_keys(&mut self, hash: &[u8]) -> anyhow::Result<SessionKeys> {
        // Use default key sizes (for backward compat with tests)
        self.derive_session_keys_for(hash, None, None)
    }

    /// Derive session keys with explicit negotiated algorithm info.
    /// Key lengths are determined by the actual negotiated cipher and MAC,
    /// not by the KEX algorithm (which only determines the hash function).
    pub fn derive_session_keys_for(
        &mut self,
        hash: &[u8],
        enc_algorithm: Option<&str>,
        mac_algorithm: Option<&str>,
    ) -> anyhow::Result<SessionKeys> {
        if let Some(ref shared_secret) = self.shared_secret {
            // Determine key lengths from negotiated algorithms
            let enc_key_len = match enc_algorithm {
                Some("aes128-cbc") | Some("aes128-ctr") | Some("aes128-gcm@openssh.com") => 16,
                Some("aes192-cbc") | Some("aes192-ctr") => 24,
                Some("aes256-cbc") | Some("aes256-ctr") | Some("aes256-gcm@openssh.com") => 32,
                Some("chacha20-poly1305@openssh.com") => 64, // 2x 32-byte keys
                _ => 16,
            };
            let iv_len = match enc_algorithm {
                Some("aes128-gcm@openssh.com") | Some("aes256-gcm@openssh.com") => 12, // GCM nonce
                Some("chacha20-poly1305@openssh.com") => 0, // no IV for chacha20
                _ => 16, // AES block size for CBC and CTR
            };
            let mac_key_len = match mac_algorithm {
                Some("hmac-sha1") | Some("hmac-sha1-96")
                | Some("hmac-sha1-etm@openssh.com") => 20,
                Some("hmac-md5") | Some("hmac-md5-96") => 16,
                Some("hmac-sha2-256") | Some("hmac-sha2-256-etm@openssh.com") => 32,
                Some("hmac-sha2-512") | Some("hmac-sha2-512-etm@openssh.com") => 64,
                _ => {
                    // Fallback: use old hardcoded defaults per KEX algorithm
                    match self.algorithm {
                        protocol::KexAlgorithm::DiffieHellmanGroup1Sha1 |
                        protocol::KexAlgorithm::DiffieHellmanGroup14Sha1 => 20,
                        protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
                        protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 => 32,
                        _ => 32,
                    }
                }
            };
            
            let hash_algo = match self.algorithm {
                protocol::KexAlgorithm::DiffieHellmanGroup1Sha1 |
                protocol::KexAlgorithm::DiffieHellmanGroup14Sha1 => kdf::HashAlgorithm::Sha1,
                _ => kdf::HashAlgorithm::Sha256,
            };
            
            let enc_key_c2s = kdf::kdf(shared_secret, hash, b'C' as u32, enc_key_len, hash_algo);
            let enc_key_s2c = kdf::kdf(shared_secret, hash, b'D' as u32, enc_key_len, hash_algo);
            let mac_key_c2s = kdf::kdf(shared_secret, hash, b'E' as u32, mac_key_len, hash_algo);
            let mac_key_s2c = kdf::kdf(shared_secret, hash, b'F' as u32, mac_key_len, hash_algo);
            let client_iv = kdf::kdf(shared_secret, hash, b'A' as u32, iv_len, hash_algo);
            let server_iv = kdf::kdf(shared_secret, hash, b'B' as u32, iv_len, hash_algo);
            
            Ok(SessionKeys {
                enc_key_c2s,
                enc_key_s2c,
                mac_key_c2s,
                mac_key_s2c,
                client_iv,
                server_iv,
            })
        } else {
            Err(anyhow::anyhow!("Shared secret not computed yet"))
        }
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("enc_key_c2s", &format!("[{} bytes]", self.enc_key_c2s.len()))
            .field("enc_key_s2c", &format!("[{} bytes]", self.enc_key_s2c.len()))
            .field("mac_key_c2s", &format!("[{} bytes]", self.mac_key_c2s.len()))
            .field("mac_key_s2c", &format!("[{} bytes]", self.mac_key_s2c.len()))
            .field("client_iv", &format!("[{} bytes]", self.client_iv.len()))
            .field("server_iv", &format!("[{} bytes]", self.server_iv.len()))
            .finish()
    }
}

/// Session keys derived from key exchange
#[derive(Clone)]
pub struct SessionKeys {
    /// Encryption key client to server
    pub enc_key_c2s: Vec<u8>,
    /// Encryption key server to client
    pub enc_key_s2c: Vec<u8>,
    /// MAC key client to server
    pub mac_key_c2s: Vec<u8>,
    /// MAC key server to client
    pub mac_key_s2c: Vec<u8>,
    /// Client IV
    pub client_iv: Vec<u8>,
    /// Server IV
    pub server_iv: Vec<u8>,
}

/// Encode a KEX_INIT message (client -> server)
pub fn encode_kex_init(client_kexinit: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1 + client_kexinit.len());
    buf.put_u8(protocol::MessageType::KexInit.value());
    buf.put_slice(client_kexinit);
    buf.to_vec()
}

/// Encode a server's key exchange reply (KEX_DH_GEX_REQUEST or KEXDH_REPLY)
pub fn encode_kex_reply(server_ephemeral: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1 + server_ephemeral.len());
    buf.put_u8(protocol::MessageType::KexInit.value());
    buf.put_slice(server_ephemeral);
    buf.to_vec()
}

/// Encode a NEWKEYS message as a properly framed SSH binary packet.
/// According to RFC 4253 Section 6, SSH packets have format:
/// [packet_length (4 bytes)][padding_length (1 byte)][payload][padding]
/// NEWKEYS is sent with old keys (unencrypted) but still needs proper packet format.
pub fn encode_newkeys() -> Vec<u8> {
    // SSH_MSG_NEWKEYS payload is just a single-byte message type (RFC 4253 Section 7)
    let payload = vec![protocol::MessageType::Newkeys.value()];
    let payload_len = payload.len();

    // Calculate padding to ensure 8-byte alignment per RFC 4253 Section 6
    // Total size (4 + 1 + payload + padding) must be multiple of 8
    // Minimum padding is 4 bytes
    let total_without_padding = 4 + 1 + payload_len; // length field + padding_length field + payload
    let remainder = total_without_padding % 8;
    let mut padding_length = if remainder == 0 {
        // Already aligned, use 8 bytes of padding to maintain alignment
        // while satisfying the minimum 4-byte padding requirement
        8u8
    } else {
        (8 - remainder) as u8
    };

    // Ensure minimum padding of 4 bytes per RFC 4253
    if padding_length < 4 {
        padding_length += 8;
    }

    // packet_length = padding_length_byte(1) + payload + padding
    let packet_length = payload_len as u32 + padding_length as u32 + 1;

    let mut msg = Vec::with_capacity(4 + packet_length as usize);
    msg.extend_from_slice(&packet_length.to_be_bytes()); // 4-byte length
    msg.push(padding_length); // 1-byte padding length
    msg.extend_from_slice(&payload); // payload (message type byte)

    // RFC 4253 Section 6: padding SHOULD be random bytes
    let mut padding = vec![0u8; padding_length as usize];
    rand::rngs::OsRng.fill(&mut padding[..]);
    msg.extend_from_slice(&padding);

    msg
}

/// Decode a KEX message and extract the server's ephemeral key
pub fn decode_kex_message(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("Empty KEX message"));
    }
    
    let msg_type = data[0];
    if msg_type != protocol::MessageType::KexInit.value() {
        return Err(anyhow::anyhow!("Expected KEX_INIT message, got {}", msg_type));
    }
    
    // Skip message type byte, return the rest (server's ephemeral key)
    Ok(data[1..].to_vec())
}

/// Perform key exchange with given algorithm
pub async fn perform_kex(
    _algorithm: protocol::KexAlgorithm,
    context: &mut KexContext,
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    _server_host_key: &[u8],
) -> anyhow::Result<SessionKeys> {
    // Step 1: Generate client's ephemeral key
    let mut rng = rand::rngs::OsRng;
    context.generate_client_key(&mut rng)?;
    
    // Step 2: Send KEX_INIT to server (simulated - in real implementation, this would be sent over the network)
    let _client_kex_msg = encode_kex_init(client_kexinit);
    
    // Step 3: Receive server's KEX_INIT and server key
    let server_kex_msg = encode_kex_init(server_kexinit);
    
    // Extract server's ephemeral key from the message
    let server_ephemeral = decode_kex_message(&server_kex_msg)?;
    context.process_server_kex_init(&server_ephemeral)?;
    
    // Step 4: Compute shared secret
    context.compute_shared_secret()?;
    
    // Step 5: Compute session hash (H)
    // The session_id is typically the server's host key hash or a negotiated value
    let _session_id = server_kexinit; // Use server KEXINIT as session identifier
    let hash = context.compute_session_id()?;
    
    // Store session ID
    context.session_id = Some(hash.clone());
    
    // Step 6: Derive session keys
    let session_keys = context.derive_session_keys(&hash)?;
    
    // Step 7: Send NEWKEYS message
    let _newkeys_msg = encode_newkeys();
    
    Ok(session_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::crypto::dh::{DhGroup, Mpint};
    use num_bigint::BigUint;

    #[test]
    fn x25519_zero_secret() {
        let mut ctx = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        ctx.generate_client_key(&mut rand::rngs::OsRng).unwrap();
        ctx.server_ecdh_public = Some(vec![0; 32]);
        assert!(ctx.compute_shared_secret().is_err());
        assert!(ctx.shared_secret.is_none());
        assert!(ctx.session_id.is_none());
    }

    #[test]
    fn test_kex_context_creation() {
        let context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        assert_eq!(context.algorithm, protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        assert!(context.client_ephemeral.is_none());
    }

    #[test]
    fn test_dh_group14_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        
        assert!(context.client_ephemeral.is_some());
        assert!(!context.client_ephemeral.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_curve25519_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        
        assert!(context.client_ephemeral.is_some());
        assert_eq!(context.client_ephemeral.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_dh_shared_secret_computation() {
        let group = DhGroup::group14();
        
        // Generate client's key pair
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        
        // Generate server's key pair
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Compute shared secret from both sides
        let client_shared = group.compute_shared_secret(&server_public, &client_private);
        let server_shared = group.compute_shared_secret(&client_public, &server_private);
        
        // Both sides should compute the same shared secret
        assert_eq!(client_shared, server_shared);
        assert!(client_shared > BigUint::from(0u8));
    }

    #[test]
    fn test_dh_shared_secret_with_mpint() {
        let group = DhGroup::group14();
        
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Encode public keys as MPINT (as sent over the wire)
        let client_mpint = Mpint::encode(&client_public);
        let server_mpint = Mpint::encode(&server_public);
        
        // Decode MPINTs back to BigUint
        let client_public_decoded = Mpint::decode(&client_mpint).unwrap();
        let server_public_decoded = Mpint::decode(&server_mpint).unwrap();
        
        // Compute shared secret using decoded values
        // Client computes: s = server_public^client_private mod p
        let client_shared = group.compute_shared_secret(&server_public_decoded, &client_private);
        // Server computes: s = client_public^server_private mod p
        let server_shared = group.compute_shared_secret(&client_public_decoded, &server_private);
        
        assert_eq!(client_shared, server_shared);
        assert!(client_shared > BigUint::from(0u8));
    }

    #[test]
    fn test_session_hash_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // Generate key pairs
        let group = DhGroup::group14();
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Set up context
        context.client_private = Some(client_private.clone());
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode(&server_public));
        
        // Compute shared secret
        context.compute_shared_secret().unwrap();
        
        // Generate session hash
        let hash = context.compute_session_id().unwrap();
        
        assert_eq!(hash.len(), 32); // SHA256 output
    }

    #[test]
    fn test_session_hash_deterministic() {
        let mut context1 = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let mut context2 = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // Use the same inputs for both
        let group = DhGroup::group14();
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        context1.client_private = Some(client_private.clone());
        context1.client_ephemeral = Some(Mpint::encode(&client_public));
        context1.server_public = Some(server_public.clone());
        context1.server_ephemeral = Some(Mpint::encode(&server_public));
        
        context2.client_private = Some(client_private.clone());
        context2.client_ephemeral = Some(Mpint::encode(&client_public));
        context2.server_public = Some(server_public.clone());
        context2.server_ephemeral = Some(Mpint::encode(&server_public));
        
        context1.compute_shared_secret().unwrap();
        context2.compute_shared_secret().unwrap();
        
        let hash1 = context1.compute_session_id().unwrap();
        let hash2 = context2.compute_session_id().unwrap();
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_session_key_derivation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // Generate key pairs
        let group = DhGroup::group14();
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Set up context
        context.client_private = Some(client_private.clone());
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode(&server_public));
        
        // Compute shared secret
        context.compute_shared_secret().unwrap();
        
        // Generate session hash
        let hash = context.compute_session_id().unwrap();
        
        // Derive session keys
        let keys = context.derive_session_keys(&hash).unwrap();

        // DiffieHellmanGroup14Sha256 uses AES-128-CBC (16-byte key) with 16-byte IV
        // The cipher is determined by the KEX algorithm's default configuration
        assert_eq!(keys.enc_key_c2s.len(), 16); // AES-128
        assert_eq!(keys.mac_key_c2s.len(), 32); // SHA-256
        assert_eq!(keys.client_iv.len(), 16);  // CBC mode IV
        assert_eq!(keys.server_iv.len(), 16);  // CBC mode IV
    }

    #[test]
    fn test_encode_kex_init() {
        let client_kexinit = vec![0x00, 0x01, 0x02, 0x03];
        let encoded = encode_kex_init(&client_kexinit);
        
        assert_eq!(encoded[0], protocol::MessageType::KexInit.value());
        assert_eq!(&encoded[1..], &client_kexinit);
    }

    #[test]
    fn test_encode_kex_reply() {
        let server_ephemeral = vec![0x04, 0x05, 0x06, 0x07];
        let encoded = encode_kex_reply(&server_ephemeral);
        
        assert_eq!(encoded[0], protocol::MessageType::KexInit.value());
        assert_eq!(&encoded[1..], &server_ephemeral);
    }

    #[test]
    fn test_encode_newkeys() {
        let encoded = encode_newkeys();
        // NEWKEYS must be a properly framed SSH binary packet per RFC 4253 Section 6
        // Format: [packet_length (4 bytes)][padding_length (1 byte)][payload][padding]
        // With payload = [21] (SSH_MSG_NEWKEYS), the total must be a multiple of 8 and >= 16
        assert!(encoded.len() >= 16, "NEWKEYS packet must be at least 16 bytes (minimum SSH packet size)");
        assert_eq!(encoded.len() % 8, 0, "NEWKEYS packet total size must be 8-byte aligned");

        // Check the packet_length field (first 4 bytes)
        let packet_length = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        let padding_length = encoded[4] as usize;

        // packet_length = padding_length_byte(1) + payload_len + padding_len
        // Total wire bytes = 4 + packet_length
        assert_eq!(encoded.len(), 4 + packet_length, "Total wire size must be 4 + packet_length");
        assert_eq!(packet_length, 1 + 1 + padding_length, "packet_length = 1(padlen byte) + 1(payload) + padding");

        // The message type (payload) is at byte index 5
        assert_eq!(encoded[5], protocol::MessageType::Newkeys.value(), "Payload must be SSH_MSG_NEWKEYS (21)");

        // Padding must be at least 4 bytes per RFC 4253
        assert!(padding_length >= 4, "Padding must be at least 4 bytes per RFC 4253");
    }

    #[test]
    fn test_encode_newkeys_rfc4253_compliance() {
        let encoded = encode_newkeys();

        // RFC 4253 Section 6 compliance checks:
        // 1. Total packet (packet_length || padding_length || payload || random padding)
        //    must be a multiple of the cipher block size or 8, whichever is larger
        assert_eq!(encoded.len() % 8, 0, "RFC 4253: total must be multiple of 8");

        // 2. Minimum size of a packet is 16 bytes
        assert!(encoded.len() >= 16, "RFC 4253: minimum packet size is 16 bytes");

        // 3. Padding length must be between 4 and 255 bytes
        let padding_length = encoded[4] as usize;
        assert!(padding_length >= 4, "RFC 4253: padding must be at least 4 bytes");
        assert!(padding_length <= 255, "RFC 4253: padding must be at most 255 bytes");

        // 4. The packet_length field does NOT include MAC or itself
        let packet_length = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        // packet_length = padding_length(1 byte) + payload_length + padding
        assert_eq!(4 + packet_length, encoded.len(), "Wire size = 4 + packet_length");

        // Verify the structure can be parsed back correctly
        // Extract payload from the framed packet
        let payload_len = packet_length - 1 - padding_length; // subtract padlen byte and padding
        assert_eq!(payload_len, 1, "NEWKEYS payload should be exactly 1 byte");
        let payload_byte = encoded[5]; // byte after packet_length(4) and padding_length(1)
        assert_eq!(payload_byte, 21, "NEWKEYS message type must be 21");
    }

    #[test]
    fn test_decode_kex_message() {
        let server_ephemeral = vec![0x04, 0x05, 0x06, 0x07];
        let mut msg = Vec::new();
        msg.push(protocol::MessageType::KexInit.value());
        msg.extend_from_slice(&server_ephemeral);
        
        let decoded = decode_kex_message(&msg).unwrap();
        assert_eq!(decoded, server_ephemeral);
    }

    #[test]
    fn test_decode_kex_message_invalid_type() {
        let invalid_msg = vec![0x99, 0x01, 0x02]; // Wrong message type
        
        assert!(decode_kex_message(&invalid_msg).is_err());
    }

    #[test]
    fn test_decode_kex_message_empty() {
        let empty_msg = vec![];
        
        assert!(decode_kex_message(&empty_msg).is_err());
    }

    #[test]
    fn test_perform_kex_full_flow() {
        // Simulate a full DH Group14 key exchange between client and server
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let group = DhGroup::group14();

        // Step 1: Client generates its ephemeral key pair
        context.generate_client_key(&mut OsRng).unwrap();
        assert!(context.client_ephemeral.is_some());

        // Step 2: Simulate server side - generate server key pair
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);

        // Step 3: Feed the server's public key (as length-prefixed MPINT) to the client
        let server_pub_mpint = Mpint::encode_length_prefixed(&server_public);
        context.process_server_kex_init(&server_pub_mpint).unwrap();

        // Step 4: Set exchange info (version strings, KEXINIT payloads)
        context.set_exchange_info(
            b"SSH-2.0-ayssh_test",
            b"SSH-2.0-TestServer_1.0",
            b"client-kexinit-placeholder",
            b"server-kexinit-placeholder",
        );
        context.set_server_host_key(b"server-host-key-placeholder");

        // Step 5: Compute shared secret and session ID
        context.compute_shared_secret().unwrap();
        assert!(context.shared_secret.is_some());
        assert!(context.session_id.is_some());

        // Step 6: Derive session keys
        let hash = context.session_id.clone().unwrap();
        let keys = context.derive_session_keys(&hash).unwrap();

        // DiffieHellmanGroup14Sha256 uses AES-128-CBC (16-byte key) with 16-byte IV
        assert_eq!(keys.enc_key_c2s.len(), 16);  // AES-128
        assert_eq!(keys.mac_key_c2s.len(), 32);  // HMAC-SHA256
        assert_eq!(keys.client_iv.len(), 16);     // CBC mode IV
        assert_eq!(keys.server_iv.len(), 16);     // CBC mode IV
    }

    /// Verify exchange hash input uses SSH string encoding (4-byte length prefix)
    /// per RFC 4253 Section 8
    #[test]
    fn test_exchange_hash_uses_ssh_string_encoding() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup1Sha1);

        // Set up minimal exchange info
        context.set_exchange_info(
            b"SSH-2.0-TestClient",
            b"SSH-2.0-TestServer",
            b"\x14test_client_kexinit",  // starts with msg type 20
            b"\x14test_server_kexinit",
        );
        context.set_server_host_key(b"test_host_key");
        context.client_ephemeral = Some(vec![0x42; 32]); // fake client DH pub

        // Set a fake server ephemeral (need length-prefixed for exchange hash)
        let mut server_eph = Vec::new();
        server_eph.extend_from_slice(&32u32.to_be_bytes());
        server_eph.extend_from_slice(&[0x43; 32]);
        context.server_ephemeral = Some(server_eph);
        context.shared_secret = Some(vec![0x44; 128]);

        let hash_input = context.build_hash_input().unwrap();

        // Verify V_C starts with 4-byte length prefix
        let vc_len = u32::from_be_bytes([hash_input[0], hash_input[1], hash_input[2], hash_input[3]]);
        assert_eq!(vc_len, 18, "V_C length should be 18 for 'SSH-2.0-TestClient'");
        assert_eq!(&hash_input[4..4+18], b"SSH-2.0-TestClient");

        // Verify V_S starts with 4-byte length prefix after V_C
        let vs_offset = 4 + 18;
        let vs_len = u32::from_be_bytes([
            hash_input[vs_offset], hash_input[vs_offset+1],
            hash_input[vs_offset+2], hash_input[vs_offset+3],
        ]);
        assert_eq!(vs_len, 18, "V_S length should be 18 for 'SSH-2.0-TestServer'");

        // Verify hash input is non-empty and has reasonable size
        assert!(hash_input.len() > 100, "Hash input should be substantial");
    }

    /// Verify that exchange hash is deterministic with the same inputs
    #[test]
    fn test_exchange_hash_deterministic() {
        fn make_context() -> KexContext {
            let group = DhGroup::group1();
            let mut ctx = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup1Sha1);

            // Use fixed keys for reproducibility
            let private_key = BigUint::from(12345u64);
            let public_key = group.compute_public_key(&private_key);
            let server_private = BigUint::from(67890u64);
            let server_public = group.compute_public_key(&server_private);

            ctx.client_private = Some(private_key);
            ctx.client_ephemeral = Some(Mpint::encode(&public_key));
            ctx.server_public = Some(server_public.clone());
            ctx.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
            ctx.set_exchange_info(
                b"SSH-2.0-Client",
                b"SSH-2.0-Server",
                b"\x14client_kexinit_data",
                b"\x14server_kexinit_data",
            );
            ctx.set_server_host_key(b"host_key_blob");
            ctx.compute_shared_secret().unwrap();
            ctx
        }

        let ctx1 = make_context();
        let ctx2 = make_context();

        let hash1 = ctx1.build_hash_input().unwrap();
        let hash2 = ctx2.build_hash_input().unwrap();

        assert_eq!(hash1, hash2, "Exchange hash input must be deterministic");
    }

    #[test]
    fn test_dh_group1_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup1Sha1);
        context.generate_client_key(&mut OsRng).unwrap();
        assert!(context.client_ephemeral.is_some());
        assert!(!context.client_ephemeral.as_ref().unwrap().is_empty());
        assert!(context.client_private.is_some());
    }

    #[test]
    fn test_ecdh_nistp256_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp256);
        context.generate_client_key(&mut OsRng).unwrap();
        assert!(context.client_ephemeral.is_some());
        assert!(context.client_ecdh_keypair.is_some());
    }

    #[test]
    fn test_ecdh_nistp384_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp384);
        context.generate_client_key(&mut OsRng).unwrap();
        assert!(context.client_ephemeral.is_some());
        assert!(context.client_ecdh_keypair.is_some());
    }

    #[test]
    fn test_ecdh_nistp521_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp521);
        context.generate_client_key(&mut OsRng).unwrap();
        assert!(context.client_ephemeral.is_some());
        assert!(context.client_ecdh_keypair.is_some());
    }

    #[test]
    fn test_get_curve_type() {
        assert_eq!(
            KexContext::new(protocol::KexAlgorithm::Curve25519Sha256).get_curve_type(),
            Some(CurveType::Curve25519)
        );
        assert_eq!(
            KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp256).get_curve_type(),
            Some(CurveType::Nistp256)
        );
        assert_eq!(
            KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp384).get_curve_type(),
            Some(CurveType::Nistp384)
        );
        assert_eq!(
            KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp521).get_curve_type(),
            Some(CurveType::Nistp521)
        );
        assert_eq!(
            KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256).get_curve_type(),
            None
        );
        assert_eq!(
            KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup1Sha1).get_curve_type(),
            None
        );
    }

    #[test]
    fn test_process_server_kex_init_ecdh_too_short() {
        let mut context = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        // Data too short (less than 4 bytes)
        let result = context.process_server_kex_init(&[0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_server_kex_init_ecdh_truncated() {
        let mut context = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        // Length says 32 bytes but only 4 bytes of data follow
        let mut data = Vec::new();
        data.extend_from_slice(&32u32.to_be_bytes());
        data.extend_from_slice(&[0x42; 4]); // only 4 instead of 32
        let result = context.process_server_kex_init(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_server_kex_init_dh_out_of_range() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        // Server public key = 0 (out of range [1, p-1])
        let zero = BigUint::from(0u8);
        let encoded = Mpint::encode_length_prefixed(&zero);
        let result = context.process_server_kex_init(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_shared_secret_missing_keys() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        // No keys set
        let result = context.compute_shared_secret();
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_shared_secret_ecdh_missing_keys() {
        let mut context = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        // No keys set
        let result = context.compute_shared_secret();
        assert!(result.is_err());
    }

    #[test]
    fn test_dh_group1_full_exchange() {
        let group = DhGroup::group1();
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup1Sha1);
        context.generate_client_key(&mut OsRng).unwrap();

        // Simulate server
        let server_private = group.generate_private_key(&mut OsRng, 1024);
        let server_public = group.compute_public_key(&server_private);
        let server_pub_mpint = Mpint::encode_length_prefixed(&server_public);
        context.process_server_kex_init(&server_pub_mpint).unwrap();

        context.set_exchange_info(
            b"SSH-2.0-Client",
            b"SSH-2.0-Server",
            b"client_kexinit",
            b"server_kexinit",
        );
        context.set_server_host_key(b"host_key");

        context.compute_shared_secret().unwrap();
        assert!(context.shared_secret.is_some());
        assert!(context.session_id.is_some());

        // DH Group1 uses SHA-1, so session hash should be 20 bytes
        assert_eq!(context.session_id.as_ref().unwrap().len(), 20);
    }

    #[test]
    fn test_curve25519_full_exchange() {
        use crate::crypto::ecdh::EcdhKeyPair;

        let mut client_ctx = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        client_ctx.generate_client_key(&mut OsRng).unwrap();

        // Simulate server side
        let server_keypair = EcdhKeyPair::generate(CurveType::Curve25519, &mut OsRng);
        let server_pub = server_keypair.encode_public_key();
        // Wrap in SSH string format (length-prefixed)
        let mut server_data = Vec::new();
        server_data.extend_from_slice(&(server_pub.len() as u32).to_be_bytes());
        server_data.extend_from_slice(&server_pub);
        client_ctx.process_server_kex_init(&server_data).unwrap();

        client_ctx.set_exchange_info(
            b"SSH-2.0-Client\r\n",
            b"SSH-2.0-Server\r\n",
            b"client_kexinit",
            b"server_kexinit",
        );
        client_ctx.set_server_host_key(b"host_key");

        client_ctx.compute_shared_secret().unwrap();
        assert!(client_ctx.shared_secret.is_some());
        assert!(client_ctx.session_id.is_some());

        // Curve25519-SHA256 uses SHA-256
        assert_eq!(client_ctx.session_id.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_nistp256_session_hash_is_sha256() {
        use crate::crypto::ecdh::EcdhKeyPair;

        let mut ctx = KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp256);
        ctx.generate_client_key(&mut OsRng).unwrap();

        let server_keypair = EcdhKeyPair::generate(CurveType::Nistp256, &mut OsRng);
        let server_pub = server_keypair.encode_public_key();
        let mut server_data = Vec::new();
        server_data.extend_from_slice(&(server_pub.len() as u32).to_be_bytes());
        server_data.extend_from_slice(&server_pub);
        ctx.process_server_kex_init(&server_data).unwrap();

        ctx.set_exchange_info(b"VC", b"VS", b"IC", b"IS");
        ctx.set_server_host_key(b"HK");
        ctx.compute_shared_secret().unwrap();

        // nistp256 uses SHA-256 -> 32 bytes
        assert_eq!(ctx.session_id.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_nistp384_session_hash_is_sha384() {
        use crate::crypto::ecdh::EcdhKeyPair;

        let mut ctx = KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp384);
        ctx.generate_client_key(&mut OsRng).unwrap();

        let server_keypair = EcdhKeyPair::generate(CurveType::Nistp384, &mut OsRng);
        let server_pub = server_keypair.encode_public_key();
        let mut server_data = Vec::new();
        server_data.extend_from_slice(&(server_pub.len() as u32).to_be_bytes());
        server_data.extend_from_slice(&server_pub);
        ctx.process_server_kex_init(&server_data).unwrap();

        ctx.set_exchange_info(b"VC", b"VS", b"IC", b"IS");
        ctx.set_server_host_key(b"HK");
        ctx.compute_shared_secret().unwrap();

        // nistp384 uses SHA-384 -> 48 bytes
        assert_eq!(ctx.session_id.as_ref().unwrap().len(), 48);
    }

    #[test]
    fn test_nistp521_session_hash_is_sha512() {
        use crate::crypto::ecdh::EcdhKeyPair;

        let mut ctx = KexContext::new(protocol::KexAlgorithm::EcdhSha2Nistp521);
        ctx.generate_client_key(&mut OsRng).unwrap();

        let server_keypair = EcdhKeyPair::generate(CurveType::Nistp521, &mut OsRng);
        let server_pub = server_keypair.encode_public_key();
        let mut server_data = Vec::new();
        server_data.extend_from_slice(&(server_pub.len() as u32).to_be_bytes());
        server_data.extend_from_slice(&server_pub);
        ctx.process_server_kex_init(&server_data).unwrap();

        ctx.set_exchange_info(b"VC", b"VS", b"IC", b"IS");
        ctx.set_server_host_key(b"HK");
        ctx.compute_shared_secret().unwrap();

        // nistp521 uses SHA-512 -> 64 bytes
        assert_eq!(ctx.session_id.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn test_derive_session_keys_for_aes256_ctr() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let group = DhGroup::group14();

        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);

        context.client_private = Some(client_private);
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
        context.compute_shared_secret().unwrap();

        let hash = context.session_id.clone().unwrap();
        let keys = context.derive_session_keys_for(
            &hash,
            Some("aes256-ctr"),
            Some("hmac-sha2-512"),
        ).unwrap();

        assert_eq!(keys.enc_key_c2s.len(), 32); // AES-256
        assert_eq!(keys.enc_key_s2c.len(), 32);
        assert_eq!(keys.mac_key_c2s.len(), 64); // HMAC-SHA2-512
        assert_eq!(keys.mac_key_s2c.len(), 64);
        assert_eq!(keys.client_iv.len(), 16); // AES block size
        assert_eq!(keys.server_iv.len(), 16);
    }

    #[test]
    fn test_derive_session_keys_for_aes128_gcm() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let group = DhGroup::group14();

        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);

        context.client_private = Some(client_private);
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
        context.compute_shared_secret().unwrap();

        let hash = context.session_id.clone().unwrap();
        let keys = context.derive_session_keys_for(
            &hash,
            Some("aes128-gcm@openssh.com"),
            Some("hmac-sha2-256"),
        ).unwrap();

        assert_eq!(keys.enc_key_c2s.len(), 16); // AES-128
        assert_eq!(keys.client_iv.len(), 12); // GCM nonce
        assert_eq!(keys.mac_key_c2s.len(), 32); // HMAC-SHA2-256
    }

    #[test]
    fn test_derive_session_keys_for_chacha20() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let group = DhGroup::group14();

        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);

        context.client_private = Some(client_private);
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
        context.compute_shared_secret().unwrap();

        let hash = context.session_id.clone().unwrap();
        let keys = context.derive_session_keys_for(
            &hash,
            Some("chacha20-poly1305@openssh.com"),
            None,
        ).unwrap();

        assert_eq!(keys.enc_key_c2s.len(), 64); // 2x 32-byte keys
        assert_eq!(keys.client_iv.len(), 0); // No IV for chacha20
    }

    #[test]
    fn test_derive_session_keys_for_hmac_sha1() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let group = DhGroup::group14();

        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);

        context.client_private = Some(client_private);
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
        context.compute_shared_secret().unwrap();

        let hash = context.session_id.clone().unwrap();
        let keys = context.derive_session_keys_for(
            &hash,
            Some("aes128-cbc"),
            Some("hmac-sha1"),
        ).unwrap();

        assert_eq!(keys.enc_key_c2s.len(), 16); // AES-128
        assert_eq!(keys.mac_key_c2s.len(), 20); // HMAC-SHA1
    }

    #[test]
    fn test_derive_session_keys_no_shared_secret() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let result = context.derive_session_keys(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_hash_input_no_shared_secret() {
        let context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let result = context.build_hash_input();
        assert!(result.is_err());
    }

    #[test]
    fn test_session_keys_debug() {
        let keys = SessionKeys {
            enc_key_c2s: vec![0u8; 16],
            enc_key_s2c: vec![0u8; 16],
            mac_key_c2s: vec![0u8; 32],
            mac_key_s2c: vec![0u8; 32],
            client_iv: vec![0u8; 16],
            server_iv: vec![0u8; 16],
        };
        let debug_str = format!("{:?}", keys);
        assert!(debug_str.contains("16 bytes"));
        assert!(debug_str.contains("32 bytes"));
    }

    #[test]
    fn test_session_keys_clone() {
        let keys = SessionKeys {
            enc_key_c2s: vec![1u8; 16],
            enc_key_s2c: vec![2u8; 16],
            mac_key_c2s: vec![3u8; 32],
            mac_key_s2c: vec![4u8; 32],
            client_iv: vec![5u8; 16],
            server_iv: vec![6u8; 16],
        };
        let cloned = keys.clone();
        assert_eq!(keys.enc_key_c2s, cloned.enc_key_c2s);
        assert_eq!(keys.mac_key_s2c, cloned.mac_key_s2c);
    }

    #[test]
    fn test_set_exchange_info() {
        let mut ctx = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        ctx.set_exchange_info(b"vc", b"vs", b"ic", b"is");
        assert_eq!(ctx.client_version.as_deref(), Some(b"vc".as_slice()));
        assert_eq!(ctx.server_version.as_deref(), Some(b"vs".as_slice()));
        assert_eq!(ctx.client_kexinit.as_deref(), Some(b"ic".as_slice()));
        assert_eq!(ctx.server_kexinit.as_deref(), Some(b"is".as_slice()));
    }

    #[test]
    fn test_set_server_host_key() {
        let mut ctx = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        ctx.set_server_host_key(b"host-key-blob");
        assert_eq!(ctx.server_host_key.as_deref(), Some(b"host-key-blob".as_slice()));
    }

    #[test]
    fn test_version_string_crlf_stripping_in_hash() {
        let group = DhGroup::group1();
        let mut ctx = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup1Sha1);

        let private_key = BigUint::from(12345u64);
        let public_key = group.compute_public_key(&private_key);
        let server_private = BigUint::from(67890u64);
        let server_public = group.compute_public_key(&server_private);

        ctx.client_private = Some(private_key);
        ctx.client_ephemeral = Some(Mpint::encode(&public_key));
        ctx.server_public = Some(server_public.clone());
        ctx.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
        ctx.set_server_host_key(b"hk");
        ctx.compute_shared_secret().unwrap();

        // With CRLF
        ctx.set_exchange_info(
            b"SSH-2.0-C\r\n",
            b"SSH-2.0-S\r\n",
            b"ic", b"is",
        );
        let hash_crlf = ctx.build_hash_input().unwrap();

        // Without trailing CRLF
        ctx.set_exchange_info(
            b"SSH-2.0-C",
            b"SSH-2.0-S",
            b"ic", b"is",
        );
        let hash_clean = ctx.build_hash_input().unwrap();

        // Both should produce the same hash input (CRLF stripped)
        assert_eq!(hash_crlf, hash_clean);
    }

    #[test]
    fn test_dh_group14_sha1_session_hash_length() {
        let group = DhGroup::group14();
        let mut ctx = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha1);

        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);

        ctx.client_private = Some(client_private);
        ctx.client_ephemeral = Some(Mpint::encode(&client_public));
        ctx.server_public = Some(server_public.clone());
        ctx.server_ephemeral = Some(Mpint::encode_length_prefixed(&server_public));
        ctx.set_exchange_info(b"VC", b"VS", b"IC", b"IS");
        ctx.set_server_host_key(b"HK");
        ctx.compute_shared_secret().unwrap();

        // DH Group14 SHA-1 -> 20 byte hash
        assert_eq!(ctx.session_id.as_ref().unwrap().len(), 20);
    }
}