//! SSH Protocol Algorithms
//!
//! Defines supported cryptographic algorithms and their identifiers.

use crate::protocol::errors::ProtocolError;
use std::fmt;
use std::str::FromStr;

/// Algorithm proposal for SSH negotiation (RFC 4253 Section 7.1)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlgorithmProposal {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_c2s: Vec<String>,
    pub encryption_algorithms_s2c: Vec<String>,
    pub mac_algorithms_c2s: Vec<String>,
    pub mac_algorithms_s2c: Vec<String>,
    pub compression_algorithms: Vec<String>,
    pub languages_c2s: String,
    pub languages_s2c: String,
    pub first_kex_packet_follows: bool,
}

impl AlgorithmProposal {
    /// Create a new client proposal with default client preferences
    pub fn client_proposal() -> Self {
        Self {
            kex_algorithms: Self::default_kex_algorithms(),
            server_host_key_algorithms: Self::default_host_key_algorithms(),
            encryption_algorithms_c2s: Self::default_encryption_algorithms_c2s(),
            encryption_algorithms_s2c: Self::default_encryption_algorithms_s2c(),
            mac_algorithms_c2s: Self::default_mac_algorithms_c2s(),
            mac_algorithms_s2c: Self::default_mac_algorithms_s2c(),
            compression_algorithms: Self::default_compression_algorithms(),
            languages_c2s: String::new(),
            languages_s2c: String::new(),
            first_kex_packet_follows: false,
        }
    }

    /// Create a server proposal with server preferences
    pub fn server_proposal() -> Self {
        Self {
            kex_algorithms: Self::default_kex_algorithms(),
            server_host_key_algorithms: Self::default_host_key_algorithms(),
            encryption_algorithms_c2s: Self::default_encryption_algorithms_c2s(),
            encryption_algorithms_s2c: Self::default_encryption_algorithms_s2c(),
            mac_algorithms_c2s: Self::default_mac_algorithms_c2s(),
            mac_algorithms_s2c: Self::default_mac_algorithms_s2c(),
            compression_algorithms: Self::default_compression_algorithms(),
            languages_c2s: String::new(),
            languages_s2c: String::new(),
            first_kex_packet_follows: false,
        }
    }

    /// Default key exchange algorithms (server preference order)
    fn default_kex_algorithms() -> Vec<String> {
        vec![
            "curve25519-sha256".to_string(),
            "diffie-hellman-group14-sha256".to_string(),
            "diffie-hellman-group16-sha512".to_string(),
            "diffie-hellman-group18-sha512".to_string(),
            "ecdh-sha2-nistp256".to_string(),
            "ecdh-sha2-nistp384".to_string(),
            "ecdh-sha2-nistp521".to_string(),
        ]
    }

    /// Default host key algorithms
    fn default_host_key_algorithms() -> Vec<String> {
        vec![
            "ssh-ed25519".to_string(),
            "ecdsa-sha2-nistp256".to_string(),
            "ecdsa-sha2-nistp384".to_string(),
            "ecdsa-sha2-nistp521".to_string(),
            "ssh-rsa".to_string(),
        ]
    }

    /// Default client-to-server encryption algorithms
    fn default_encryption_algorithms_c2s() -> Vec<String> {
        vec![
            "aes256-gcm@openssh.com".to_string(),
            "aes128-gcm@openssh.com".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
        ]
    }

    /// Default server-to-client encryption algorithms
    fn default_encryption_algorithms_s2c() -> Vec<String> {
        vec![
            "aes256-gcm@openssh.com".to_string(),
            "aes128-gcm@openssh.com".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
        ]
    }

    /// Default client-to-server MAC algorithms
    fn default_mac_algorithms_c2s() -> Vec<String> {
        vec![
            "hmac-sha2-512-etm@openssh.com".to_string(),
            "hmac-sha2-256-etm@openssh.com".to_string(),
            "hmac-sha2-512".to_string(),
            "hmac-sha2-256".to_string(),
        ]
    }

    /// Default server-to-client MAC algorithms
    fn default_mac_algorithms_s2c() -> Vec<String> {
        vec![
            "hmac-sha2-512-etm@openssh.com".to_string(),
            "hmac-sha2-256-etm@openssh.com".to_string(),
            "hmac-sha2-512".to_string(),
            "hmac-sha2-256".to_string(),
        ]
    }

    /// Default compression algorithms
    fn default_compression_algorithms() -> Vec<String> {
        vec![
            "none".to_string(),
            "zlib@openssh.com".to_string(),
        ]
    }

    /// Select common algorithms from client and server proposals.
    ///
    /// Per RFC 4253 Section 7.1: The chosen algorithm MUST be the first algorithm
    /// on the client's name-list that is also on the server's name-list.
    ///
    /// `self` is the client proposal, `server_proposal` is the server proposal.
    pub fn select_common_algorithms(&self, server_proposal: &Self) -> Result<NegotiatedAlgorithms, ProtocolError> {
        let kex = self.select_first_matching_client_preference("kex", &server_proposal.kex_algorithms)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common key exchange algorithm".to_string()
            ))?;
        
        let host_key = self.select_first_matching_client_preference("host_key", &server_proposal.server_host_key_algorithms)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common host key algorithm".to_string()
            ))?;
        
        let enc_c2s = self.select_first_matching_client_preference("enc_c2s", &server_proposal.encryption_algorithms_c2s)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common client-to-server encryption algorithm".to_string()
            ))?;
        
        let enc_s2c = self.select_first_matching_client_preference("enc_s2c", &server_proposal.encryption_algorithms_s2c)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common server-to-client encryption algorithm".to_string()
            ))?;
        
        let mac_c2s = self.select_first_matching_client_preference("mac_c2s", &server_proposal.mac_algorithms_c2s)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common client-to-server MAC algorithm".to_string()
            ))?;
        
        let mac_s2c = self.select_first_matching_client_preference("mac_s2c", &server_proposal.mac_algorithms_s2c)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common server-to-client MAC algorithm".to_string()
            ))?;
        
        let compression = self.select_first_matching_client_preference("compression", &server_proposal.compression_algorithms)
            .ok_or_else(|| ProtocolError::AlgorithmNegotiationFailed(
                "No common compression algorithm".to_string()
            ))?;

        Ok(NegotiatedAlgorithms {
            kex,
            host_key,
            enc_c2s,
            enc_s2c,
            mac_c2s,
            mac_s2c,
            compression,
        })
    }

    /// Find the first algorithm from the client's list (self) that appears in the server's list
    /// Per RFC 4253 Section 7.1: "The first algorithm on the client's name-list
    /// that is also on the server's name-list MUST be chosen"
    fn select_first_matching_client_preference(&self, category: &str, server_list: &[String]) -> Option<String> {
        let client_list = match category {
            "kex" => &self.kex_algorithms,
            "host_key" => &self.server_host_key_algorithms,
            "enc_c2s" => &self.encryption_algorithms_c2s,
            "enc_s2c" => &self.encryption_algorithms_s2c,
            "mac_c2s" => &self.mac_algorithms_c2s,
            "mac_s2c" => &self.mac_algorithms_s2c,
            "compression" => &self.compression_algorithms,
            _ => return None,
        };

        for algo in client_list {
            // RFC 8308 section 2 and OpenSSH strict KEX markers are capabilities,
            // never actual methods that can be selected for key exchange.
            if category == "kex" && matches!(algo.as_str(), "ext-info-c" | "ext-info-s" | "kex-strict-c-v00@openssh.com" | "kex-strict-s-v00@openssh.com") {
                continue;
            }
            if server_list.contains(algo) {
                return Some(algo.clone());
            }
        }
        None
    }

    /// Get the selected algorithm from a specific category
    pub fn select_from_list(&self, category: &str, other_list: &[String]) -> Option<String> {
        let list = match category {
            "kex" => &self.kex_algorithms,
            "host_key" => &self.server_host_key_algorithms,
            "enc_c2s" => &self.encryption_algorithms_c2s,
            "enc_s2c" => &self.encryption_algorithms_s2c,
            "mac_c2s" => &self.mac_algorithms_c2s,
            "mac_s2c" => &self.mac_algorithms_s2c,
            "compression" => &self.compression_algorithms,
            _ => return None,
        };

        for algo in list {
            if other_list.contains(algo) {
                return Some(algo.clone());
            }
        }
        None
    }
}

/// Negotiated algorithms after KEXINIT exchange
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedAlgorithms {
    pub kex: String,
    pub host_key: String,
    pub enc_c2s: String,
    pub enc_s2c: String,
    pub mac_c2s: String,
    pub mac_s2c: String,
    pub compression: String,
}

impl Default for NegotiatedAlgorithms {
    fn default() -> Self {
        Self {
            kex: String::new(),
            host_key: String::new(),
            enc_c2s: String::new(),
            enc_s2c: String::new(),
            mac_c2s: String::new(),
            mac_s2c: String::new(),
            compression: String::new(),
        }
    }
}

impl fmt::Display for NegotiatedAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NegotiatedAlgorithms {{")?;
        write!(f, "kex: {}, ", self.kex)?;
        write!(f, "host_key: {}, ", self.host_key)?;
        write!(f, "enc_c2s: {}, ", self.enc_c2s)?;
        write!(f, "enc_s2c: {}, ", self.enc_s2c)?;
        write!(f, "mac_c2s: {}, ", self.mac_c2s)?;
        write!(f, "mac_s2c: {}, ", self.mac_s2c)?;
        write!(f, "compression: {} }}", self.compression)
    }
}

/// Supported hash algorithms for DH key exchange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1 (used for diffie-hellman-group1-sha1)
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl HashAlgorithm {
    /// Get the hash output size in bytes
    pub const fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// Supported key exchange algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexAlgorithm {
    /// diffie-hellman-group1-sha1 (Oakley Group 2, 1024-bit MODP)
    DiffieHellmanGroup1Sha1,
    /// diffie-hellman-group14-sha1 (2048-bit MODP, SHA-1 hash)
    DiffieHellmanGroup14Sha1,
    /// diffie-hellman-group14-sha256
    DiffieHellmanGroup14Sha256,
    /// diffie-hellman-group14-sha384
    DiffieHellmanGroup14Sha384,
    /// diffie-hellman-group14-sha512
    DiffieHellmanGroup14Sha512,
    /// diffie-hellman-group16-sha512
    DiffieHellmanGroup16Sha512,
    /// diffie-hellman-group18-sha512
    DiffieHellmanGroup18Sha512,
    /// diffie-hellman-group-exchange-sha256
    DiffieHellmanGroupExchangeSha256,
    /// curve25519-sha256
    Curve25519Sha256,
    /// ecdh-sha2-nistp256
    EcdhSha2Nistp256,
    /// ecdh-sha2-nistp384
    EcdhSha2Nistp384,
    /// ecdh-sha2-nistp521
    EcdhSha2Nistp521,
}

impl KexAlgorithm {
    /// Get the algorithm name as defined in SSH spec
    pub const fn name(&self) -> &'static str {
        match self {
            KexAlgorithm::DiffieHellmanGroup1Sha1 => "diffie-hellman-group1-sha1",
            KexAlgorithm::DiffieHellmanGroup14Sha1 => "diffie-hellman-group14-sha1",
            KexAlgorithm::DiffieHellmanGroup14Sha256 => "diffie-hellman-group14-sha256",
            KexAlgorithm::DiffieHellmanGroup14Sha384 => "diffie-hellman-group14-sha384",
            KexAlgorithm::DiffieHellmanGroup14Sha512 => "diffie-hellman-group14-sha512",
            KexAlgorithm::DiffieHellmanGroup16Sha512 => "diffie-hellman-group16-sha512",
            KexAlgorithm::DiffieHellmanGroup18Sha512 => "diffie-hellman-group18-sha512",
            KexAlgorithm::DiffieHellmanGroupExchangeSha256 => "diffie-hellman-group-exchange-sha256",
            KexAlgorithm::Curve25519Sha256 => "curve25519-sha256",
            KexAlgorithm::EcdhSha2Nistp256 => "ecdh-sha2-nistp256",
            KexAlgorithm::EcdhSha2Nistp384 => "ecdh-sha2-nistp384",
            KexAlgorithm::EcdhSha2Nistp521 => "ecdh-sha2-nistp521",
        }
    }
}

impl FromStr for KexAlgorithm {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "diffie-hellman-group1-sha1" => Ok(KexAlgorithm::DiffieHellmanGroup1Sha1),
            "diffie-hellman-group14-sha1" => Ok(KexAlgorithm::DiffieHellmanGroup14Sha1),
            "diffie-hellman-group14-sha256" => Ok(KexAlgorithm::DiffieHellmanGroup14Sha256),
            "diffie-hellman-group14-sha384" => Ok(KexAlgorithm::DiffieHellmanGroup14Sha384),
            "diffie-hellman-group14-sha512" => Ok(KexAlgorithm::DiffieHellmanGroup14Sha512),
            "diffie-hellman-group16-sha512" => Ok(KexAlgorithm::DiffieHellmanGroup16Sha512),
            "diffie-hellman-group18-sha512" => Ok(KexAlgorithm::DiffieHellmanGroup18Sha512),
            "diffie-hellman-group-exchange-sha256" => Ok(KexAlgorithm::DiffieHellmanGroupExchangeSha256),
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Ok(KexAlgorithm::Curve25519Sha256),
            "ecdh-sha2-nistp256" => Ok(KexAlgorithm::EcdhSha2Nistp256),
            "ecdh-sha2-nistp384" => Ok(KexAlgorithm::EcdhSha2Nistp384),
            "ecdh-sha2-nistp521" => Ok(KexAlgorithm::EcdhSha2Nistp521),
            _ => Err(ProtocolError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

/// Supported encryption algorithms (ciphers)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    /// aes128-gcm@openssh.com
    Aes128Gcm,
    /// aes256-gcm@openssh.com
    Aes256Gcm,
    /// chacha20-poly1305@openssh.com
    ChaCha20Poly1305,
}

impl CipherAlgorithm {
    /// Get the algorithm name as defined in SSH spec
    pub const fn name(&self) -> &'static str {
        match self {
            CipherAlgorithm::Aes128Gcm => "aes128-gcm@openssh.com",
            CipherAlgorithm::Aes256Gcm => "aes256-gcm@openssh.com",
            CipherAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
        }
    }
}

/// Supported MAC algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    /// hmac-sha2-256-etm@openssh.com
    HmacSha256EtM,
    /// hmac-sha2-512-etm@openssh.com
    HmacSha512EtM,
    /// hmac-sha2-256
    HmacSha256,
    /// hmac-sha2-512
    HmacSha512,
}

impl MacAlgorithm {
    /// Get the algorithm name as defined in SSH spec
    pub const fn name(&self) -> &'static str {
        match self {
            MacAlgorithm::HmacSha256EtM => "hmac-sha2-256-etm@openssh.com",
            MacAlgorithm::HmacSha512EtM => "hmac-sha2-512-etm@openssh.com",
            MacAlgorithm::HmacSha256 => "hmac-sha2-256",
            MacAlgorithm::HmacSha512 => "hmac-sha2-512",
        }
    }
}

/// Supported host key algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyAlgorithm {
    /// ssh-rsa
    Rsa,
    /// ssh-ed25519
    Ed25519,
    /// ecdsa-sha2-nistp256
    EcdsaNistp256,
    /// ecdsa-sha2-nistp384
    EcdsaNistp384,
    /// ecdsa-sha2-nistp521
    EcdsaNistp521,
}

impl HostKeyAlgorithm {
    /// Get the algorithm name as defined in SSH spec
    pub const fn name(&self) -> &'static str {
        match self {
            HostKeyAlgorithm::Rsa => "ssh-rsa",
            HostKeyAlgorithm::Ed25519 => "ssh-ed25519",
            HostKeyAlgorithm::EcdsaNistp256 => "ecdsa-sha2-nistp256",
            HostKeyAlgorithm::EcdsaNistp384 => "ecdsa-sha2-nistp384",
            HostKeyAlgorithm::EcdsaNistp521 => "ecdsa-sha2-nistp521",
        }
    }
}

/// Supported authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// none
    None,
    /// password
    Password,
    /// publickey
    PublicKey,
}

impl AuthMethod {
    /// Get the method name as defined in SSH spec
    pub const fn name(&self) -> &'static str {
        match self {
            AuthMethod::None => "none",
            AuthMethod::Password => "password",
            AuthMethod::PublicKey => "publickey",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_proposal_defaults() {
        let proposal = AlgorithmProposal::client_proposal();
        
        assert!(!proposal.kex_algorithms.is_empty());
        assert!(!proposal.server_host_key_algorithms.is_empty());
        assert!(!proposal.encryption_algorithms_c2s.is_empty());
        assert!(!proposal.encryption_algorithms_s2c.is_empty());
        assert!(!proposal.mac_algorithms_c2s.is_empty());
        assert!(!proposal.mac_algorithms_s2c.is_empty());
        assert!(!proposal.compression_algorithms.is_empty());
        assert_eq!(proposal.languages_c2s, "");
        assert_eq!(proposal.languages_s2c, "");
        assert!(!proposal.first_kex_packet_follows);
    }

    #[test]
    fn test_select_common_algorithms_success() {
        let client = AlgorithmProposal::client_proposal();
        let server = AlgorithmProposal::server_proposal();
        
        let negotiated = client.select_common_algorithms(&server).unwrap();
        
        assert!(!negotiated.kex.is_empty());
        assert!(!negotiated.host_key.is_empty());
        assert!(!negotiated.enc_c2s.is_empty());
        assert!(!negotiated.enc_s2c.is_empty());
        assert!(!negotiated.mac_c2s.is_empty());
        assert!(!negotiated.mac_s2c.is_empty());
        assert!(!negotiated.compression.is_empty());
    }

    #[test]
    fn test_select_common_algorithms_no_match() {
        let client = AlgorithmProposal {
            kex_algorithms: vec!["unknown-kex".to_string()],
            ..AlgorithmProposal::client_proposal()
        };
        let server = AlgorithmProposal::server_proposal();
        
        let result = client.select_common_algorithms(&server);
        
        assert!(result.is_err());
        if let Err(ProtocolError::AlgorithmNegotiationFailed(msg)) = result {
            assert!(msg.contains("No common key exchange algorithm"));
        } else {
            panic!("Expected AlgorithmNegotiationFailed error");
        }
    }

    #[test]
    fn test_select_from_list() {
        let client = AlgorithmProposal::client_proposal();
        let server = AlgorithmProposal::server_proposal();
        
        let kex = client.select_from_list("kex", &server.kex_algorithms).unwrap();
        assert!(!kex.is_empty());
        
        let host_key = client.select_from_list("host_key", &server.server_host_key_algorithms).unwrap();
        assert!(!host_key.is_empty());
        
        let enc_c2s = client.select_from_list("enc_c2s", &server.encryption_algorithms_c2s).unwrap();
        assert!(!enc_c2s.is_empty());
        
        let enc_s2c = client.select_from_list("enc_s2c", &server.encryption_algorithms_s2c).unwrap();
        assert!(!enc_s2c.is_empty());
        
        let mac_c2s = client.select_from_list("mac_c2s", &server.mac_algorithms_c2s).unwrap();
        assert!(!mac_c2s.is_empty());
        
        let mac_s2c = client.select_from_list("mac_s2c", &server.mac_algorithms_s2c).unwrap();
        assert!(!mac_s2c.is_empty());
        
        let compression = client.select_from_list("compression", &server.compression_algorithms).unwrap();
        assert!(!compression.is_empty());
        
        // Invalid category should return None
        let invalid = client.select_from_list("invalid", &server.kex_algorithms);
        assert!(invalid.is_none());
    }

    #[test]
    fn test_negotiated_algorithms_default() {
        let negotiated = NegotiatedAlgorithms::default();
        
        assert!(negotiated.kex.is_empty());
        assert!(negotiated.host_key.is_empty());
        assert!(negotiated.enc_c2s.is_empty());
        assert!(negotiated.enc_s2c.is_empty());
        assert!(negotiated.mac_c2s.is_empty());
        assert!(negotiated.mac_s2c.is_empty());
        assert!(negotiated.compression.is_empty());
    }

    #[test]
    fn test_negotiated_algorithms_display() {
        let negotiated = NegotiatedAlgorithms {
            kex: "curve25519-sha256".to_string(),
            host_key: "ssh-ed25519".to_string(),
            enc_c2s: "aes256-gcm@openssh.com".to_string(),
            enc_s2c: "aes256-gcm@openssh.com".to_string(),
            mac_c2s: "hmac-sha2-512-etm@openssh.com".to_string(),
            mac_s2c: "hmac-sha2-512-etm@openssh.com".to_string(),
            compression: "none".to_string(),
        };
        
        let display = format!("{}", negotiated);
        assert!(display.contains("curve25519-sha256"));
        assert!(display.contains("ssh-ed25519"));
        assert!(display.contains("aes256-gcm@openssh.com"));
        assert!(display.contains("hmac-sha2-512-etm@openssh.com"));
        assert!(display.contains("none"));
    }

    #[test]
    fn test_negotiated_algorithms_partial_mismatch() {
        // Client prefers different order than server
        let client = AlgorithmProposal {
            kex_algorithms: vec![
                "diffie-hellman-group14-sha256".to_string(),
                "curve25519-sha256".to_string(),
            ],
            ..AlgorithmProposal::client_proposal()
        };
        let server = AlgorithmProposal::server_proposal();
        
        let negotiated = client.select_common_algorithms(&server).unwrap();
        
        // RFC 4253 Section 7.1: Client's preference should win
        // "The first algorithm on the client's name-list that is also on the server's name-list"
        assert_eq!(negotiated.kex, "diffie-hellman-group14-sha256");
    }

    #[test]
    fn test_negotiated_algorithms_all_categories() {
        let client = AlgorithmProposal::client_proposal();
        let server = AlgorithmProposal::server_proposal();
        
        let negotiated = client.select_common_algorithms(&server).unwrap();
        
        // Verify all selected algorithms are from both client's and server's lists
        assert!(client.kex_algorithms.contains(&negotiated.kex));
        assert!(server.kex_algorithms.contains(&negotiated.kex));
        assert!(client.server_host_key_algorithms.contains(&negotiated.host_key));
        assert!(server.server_host_key_algorithms.contains(&negotiated.host_key));
        assert!(client.encryption_algorithms_c2s.contains(&negotiated.enc_c2s));
        assert!(server.encryption_algorithms_c2s.contains(&negotiated.enc_c2s));
        assert!(client.encryption_algorithms_s2c.contains(&negotiated.enc_s2c));
        assert!(server.encryption_algorithms_s2c.contains(&negotiated.enc_s2c));
        assert!(client.mac_algorithms_c2s.contains(&negotiated.mac_c2s));
        assert!(server.mac_algorithms_c2s.contains(&negotiated.mac_c2s));
        assert!(client.mac_algorithms_s2c.contains(&negotiated.mac_s2c));
        assert!(server.mac_algorithms_s2c.contains(&negotiated.mac_s2c));
        assert!(client.compression_algorithms.contains(&negotiated.compression));
        assert!(server.compression_algorithms.contains(&negotiated.compression));
    }

    #[test]
    fn test_negotiated_algorithms_single_common_algorithm() {
        // Only one common algorithm in each category
        let client = AlgorithmProposal {
            kex_algorithms: vec!["curve25519-sha256".to_string()],
            server_host_key_algorithms: vec!["ssh-ed25519".to_string()],
            encryption_algorithms_c2s: vec!["aes256-gcm@openssh.com".to_string()],
            encryption_algorithms_s2c: vec!["aes256-gcm@openssh.com".to_string()],
            mac_algorithms_c2s: vec!["hmac-sha2-512-etm@openssh.com".to_string()],
            mac_algorithms_s2c: vec!["hmac-sha2-512-etm@openssh.com".to_string()],
            compression_algorithms: vec!["none".to_string()],
            ..Default::default()
        };
        
        let server = AlgorithmProposal::server_proposal();
        
        let negotiated = client.select_common_algorithms(&server).unwrap();
        
        assert_eq!(negotiated.kex, "curve25519-sha256");
        assert_eq!(negotiated.host_key, "ssh-ed25519");
        assert_eq!(negotiated.enc_c2s, "aes256-gcm@openssh.com");
        assert_eq!(negotiated.enc_s2c, "aes256-gcm@openssh.com");
        assert_eq!(negotiated.mac_c2s, "hmac-sha2-512-etm@openssh.com");
        assert_eq!(negotiated.mac_s2c, "hmac-sha2-512-etm@openssh.com");
        assert_eq!(negotiated.compression, "none");
    }

    #[test]
    fn test_negotiated_algorithms_empty_proposals() {
        let client = AlgorithmProposal::default();
        let server = AlgorithmProposal::default();
        
        let result = client.select_common_algorithms(&server);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_kex_algorithm_names() {
        assert_eq!(KexAlgorithm::Curve25519Sha256.name(), "curve25519-sha256");
        assert_eq!(KexAlgorithm::DiffieHellmanGroup14Sha256.name(), "diffie-hellman-group14-sha256");
        assert_eq!(KexAlgorithm::DiffieHellmanGroup16Sha512.name(), "diffie-hellman-group16-sha512");
        assert_eq!(KexAlgorithm::DiffieHellmanGroup18Sha512.name(), "diffie-hellman-group18-sha512");
        assert_eq!(KexAlgorithm::EcdhSha2Nistp256.name(), "ecdh-sha2-nistp256");
        assert_eq!(KexAlgorithm::EcdhSha2Nistp384.name(), "ecdh-sha2-nistp384");
        assert_eq!(KexAlgorithm::EcdhSha2Nistp521.name(), "ecdh-sha2-nistp521");
    }

    #[test]
    fn test_cipher_algorithm_names() {
        assert_eq!(CipherAlgorithm::Aes128Gcm.name(), "aes128-gcm@openssh.com");
        assert_eq!(CipherAlgorithm::Aes256Gcm.name(), "aes256-gcm@openssh.com");
        assert_eq!(CipherAlgorithm::ChaCha20Poly1305.name(), "chacha20-poly1305@openssh.com");
    }

    #[test]
    fn test_mac_algorithm_names() {
        assert_eq!(MacAlgorithm::HmacSha256EtM.name(), "hmac-sha2-256-etm@openssh.com");
        assert_eq!(MacAlgorithm::HmacSha512EtM.name(), "hmac-sha2-512-etm@openssh.com");
        assert_eq!(MacAlgorithm::HmacSha256.name(), "hmac-sha2-256");
        assert_eq!(MacAlgorithm::HmacSha512.name(), "hmac-sha2-512");
    }

    #[test]
    fn test_host_key_algorithm_names() {
        assert_eq!(HostKeyAlgorithm::Ed25519.name(), "ssh-ed25519");
        assert_eq!(HostKeyAlgorithm::Rsa.name(), "ssh-rsa");
        assert_eq!(HostKeyAlgorithm::EcdsaNistp256.name(), "ecdsa-sha2-nistp256");
        assert_eq!(HostKeyAlgorithm::EcdsaNistp384.name(), "ecdsa-sha2-nistp384");
        assert_eq!(HostKeyAlgorithm::EcdsaNistp521.name(), "ecdsa-sha2-nistp521");
    }

    #[test]
    fn test_auth_method_names() {
        assert_eq!(AuthMethod::None.name(), "none");
        assert_eq!(AuthMethod::Password.name(), "password");
        assert_eq!(AuthMethod::PublicKey.name(), "publickey");
    }

    #[test]
    fn test_algorithm_proposal_equality() {
        let p1 = AlgorithmProposal::client_proposal();
        let p2 = AlgorithmProposal::client_proposal();
        let p3 = AlgorithmProposal::server_proposal();
        
        assert_eq!(p1, p2);
        assert_eq!(p1, p3); // They have the same defaults
    }

    #[test]
    fn test_algorithm_proposal_modification() {
        let mut proposal = AlgorithmProposal::client_proposal();
        
        // Modify some values
        proposal.kex_algorithms.insert(0, "custom-kex".to_string());
        proposal.first_kex_packet_follows = true;
        
        assert_eq!(proposal.kex_algorithms[0], "custom-kex");
        assert!(proposal.first_kex_packet_follows);
    }

    #[test]
    fn test_rfc4253_client_preference_wins() {
        // RFC 4253 Section 7.1: "The first algorithm on the client's name-list
        // that is also on the server's name-list MUST be chosen."
        let client = AlgorithmProposal {
            kex_algorithms: vec![
                "diffie-hellman-group14-sha256".to_string(), // client prefers this
                "curve25519-sha256".to_string(),
            ],
            encryption_algorithms_c2s: vec![
                "aes128-gcm@openssh.com".to_string(), // client prefers this
                "aes256-gcm@openssh.com".to_string(),
            ],
            encryption_algorithms_s2c: vec![
                "aes128-gcm@openssh.com".to_string(),
                "aes256-gcm@openssh.com".to_string(),
            ],
            ..AlgorithmProposal::client_proposal()
        };
        let server = AlgorithmProposal {
            kex_algorithms: vec![
                "curve25519-sha256".to_string(),  // server prefers this
                "diffie-hellman-group14-sha256".to_string(),
            ],
            encryption_algorithms_c2s: vec![
                "aes256-gcm@openssh.com".to_string(), // server prefers this
                "aes128-gcm@openssh.com".to_string(),
            ],
            encryption_algorithms_s2c: vec![
                "aes256-gcm@openssh.com".to_string(),
                "aes128-gcm@openssh.com".to_string(),
            ],
            ..AlgorithmProposal::server_proposal()
        };

        let negotiated = client.select_common_algorithms(&server).unwrap();

        // Client preference MUST win per RFC
        assert_eq!(negotiated.kex, "diffie-hellman-group14-sha256");
        assert_eq!(negotiated.enc_c2s, "aes128-gcm@openssh.com");
        assert_eq!(negotiated.enc_s2c, "aes128-gcm@openssh.com");
    }
}
