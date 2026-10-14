//! Known Hosts Database
//!
//! Implements host key verification and storage as defined in SSH known_hosts format.
//! Supports parsing OpenSSH known_hosts files and matching hostnames with wildcards.

use std::collections::HashMap;
use std::fmt;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Host key types supported by SSH
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostKeyType {
    /// RFC 6187 RSA certificate: key_data contains its 32-byte SHA-256 digest.
    X509Rsa,
    /// RSA keys (ssh-rsa)
    Rsa,
    /// ECDSA keys (ecdsa-sha2-nistp256/384/521)
    Ecdsa,
    /// Ed25519 keys (ssh-ed25519)
    Ed25519,
}

impl HostKeyType {
    /// Get the SSH algorithm string for this key type
    pub fn key_type_str(&self) -> &'static str {
        match self {
            HostKeyType::X509Rsa => "x509v3-ssh-rsa",
            HostKeyType::Rsa => "ssh-rsa",
            HostKeyType::Ecdsa => "ecdsa-sha2-nistp256",
            HostKeyType::Ed25519 => "ssh-ed25519",
        }
    }

    /// Parse a key type from an SSH algorithm string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "x509v3-ssh-rsa" => Some(HostKeyType::X509Rsa),
            "ssh-rsa" => Some(HostKeyType::Rsa),
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                Some(HostKeyType::Ecdsa)
            }
            "ssh-ed25519" => Some(HostKeyType::Ed25519),
            _ => None,
        }
    }
}

/// A host key entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// The type of key
    pub key_type: HostKeyType,
    /// The base64-encoded key data
    pub key_data: Vec<u8>,
}

/// Pattern matching for hostnames (supports wildcards)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchPattern {
    /// The pattern string (e.g., "*.example.com" or "example.com")
    pattern: String,
    /// Whether this is a wildcard pattern
    is_wildcard: bool,
}

impl MatchPattern {
    /// Create a new match pattern
    pub fn new(pattern: &str) -> Self {
        let is_wildcard = pattern.starts_with('*') || pattern.contains("*,");
        Self {
            pattern: pattern.to_string(),
            is_wildcard,
        }
    }

    /// Check if a hostname matches this pattern
    pub fn matches(&self, hostname: &str) -> bool {
        if !self.is_wildcard {
            return hostname == self.pattern;
        }

        // Handle wildcard patterns
        if self.pattern.starts_with("*,") {
            // Pattern like "*,example.com" - match any host in example.com domain
            let domain = &self.pattern[2..];
            return hostname == domain || hostname.ends_with(&format!(".{}", domain));
        }

        if self.pattern.starts_with('*') {
            // Pattern like "*.example.com" - match subdomains
            let suffix = &self.pattern[1..];
            return hostname == suffix || hostname.ends_with(suffix);
        }

        false
    }
}

/// Known hosts database
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    /// Map of hostnames to their keys
    pub hosts: HashMap<String, HostKey>,
    /// Map of patterns to their keys (for wildcard matching)
    pub patterns: Vec<(MatchPattern, HostKey)>,
}

impl KnownHosts {
    /// Create a new empty known hosts database
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            patterns: Vec::new(),
        }
    }

    /// Add a host key
    pub fn add_host(&mut self, hostname: &str, key: HostKey) {
        // Check if it's a pattern (contains wildcard)
        if hostname.contains('*') {
            self.patterns.push((MatchPattern::new(hostname), key));
        } else {
            self.hosts.insert(hostname.to_string(), key);
        }
    }

    /// Get a host key by exact hostname
    pub fn get_host(&self, hostname: &str) -> Option<&HostKey> {
        // First check exact match
        if let Some(key) = self.hosts.get(hostname) {
            return Some(key);
        }

        // Then check pattern matches
        for (pattern, key) in &self.patterns {
            if pattern.matches(hostname) {
                return Some(key);
            }
        }

        None
    }

    /// Verify a host key against known hosts
    pub fn verify_host(&self, hostname: &str, expected_key: &HostKey) -> bool {
        if let Some(known_key) = self.get_host(hostname) {
            return known_key.key_type == expected_key.key_type
                && known_key.key_data == expected_key.key_data;
        }
        false
    }

    /// Parse a single known_hosts line
    ///
    /// Format: `<hostname> <key-type> <base64-key-data>`
    /// Comments start with '#' and are ignored
    pub fn parse_line(&mut self, line: &str) -> Result<(), String> {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }

        // Parse the line
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(format!("Invalid known_hosts line: {}", line));
        }

        let hostname = parts[0];
        let key_type_str = parts[1];
        let key_data_b64 = parts[2];

        // Parse key type
        let key_type = HostKeyType::from_str(key_type_str)
            .ok_or_else(|| format!("Unknown key type: {}", key_type_str))?;

        // Decode base64 key data (simplified - in real implementation would use proper base64)
        let key_data = self.decode_base64(key_data_b64)?;

        let key = HostKey { key_type, key_data };

        self.add_host(hostname, key);

        Ok(())
    }

    /// Decode base64 key data
    fn decode_base64(&self, data: &str) -> Result<Vec<u8>, String> {
        BASE64
            .decode(data)
            .map_err(|e| format!("Failed to decode base64: {}", e))
    }

    /// Parse known hosts from a string (multiple lines)
    pub fn parse(&mut self, content: &str) -> Result<(), String> {
        for line in content.lines() {
            self.parse_line(line)?;
        }
        Ok(())
    }

    /// Create known hosts from a string
    pub fn from_string(content: &str) -> Result<Self, String> {
        let mut hosts = Self::new();
        hosts.parse(content)?;
        Ok(hosts)
    }

    /// Convert known hosts to OpenSSH format string
    pub fn to_string(&self) -> String {
        let mut lines = Vec::new();

        // Add exact matches
        for (hostname, key) in &self.hosts {
            let line = format!(
                "{} {} {}",
                hostname,
                key.key_type.key_type_str(),
                self.encode_base64(&key.key_data)
            );
            lines.push(line);
        }

        // Add pattern matches
        for (pattern, key) in &self.patterns {
            let line = format!(
                "{} {} {}",
                pattern.pattern,
                key.key_type.key_type_str(),
                self.encode_base64(&key.key_data)
            );
            lines.push(line);
        }

        lines.join("\n")
    }

    /// Encode key data to base64
    fn encode_base64(&self, data: &[u8]) -> String {
        BASE64.encode(data)
    }

    /// Remove a host from the database
    pub fn remove_host(&mut self, hostname: &str) {
        self.hosts.remove(hostname);
        // Note: Pattern removal is not implemented in this simple version
    }

    /// Get the number of known hosts
    pub fn count(&self) -> usize {
        self.hosts.len() + self.patterns.len()
    }
}

impl fmt::Display for KnownHosts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_hosts_create() {
        let hosts = KnownHosts::new();
        assert_eq!(hosts.hosts.len(), 0);
    }

    #[test]
    fn test_known_hosts_add_host() {
        let mut hosts = KnownHosts::new();

        let host_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        hosts.add_host("example.com", host_key.clone());

        assert_eq!(hosts.hosts.len(), 1);
        assert!(hosts.get_host("example.com").is_some());
    }

    #[test]
    fn test_known_hosts_add_multiple_hosts() {
        let mut hosts = KnownHosts::new();

        let ed25519_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        let rsa_key = HostKey {
            key_type: HostKeyType::Rsa,
            key_data: vec![0x05, 0x06, 0x07, 0x08],
        };

        hosts.add_host("example.com", ed25519_key);
        hosts.add_host("github.com", rsa_key);

        assert_eq!(hosts.hosts.len(), 2);
        assert!(hosts.get_host("example.com").is_some());
        assert!(hosts.get_host("github.com").is_some());
        assert!(hosts.get_host("nonexistent.com").is_none());
    }

    #[test]
    fn test_known_hosts_verify_host() {
        let mut hosts = KnownHosts::new();

        let host_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        hosts.add_host("example.com", host_key.clone());

        // Verify correct key
        assert!(hosts.verify_host("example.com", &host_key));

        // Verify incorrect key
        let wrong_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x05, 0x06, 0x07, 0x08],
        };
        assert!(!hosts.verify_host("example.com", &wrong_key));

        // Verify non-existent host
        assert!(!hosts.verify_host("nonexistent.com", &host_key));
    }

    #[test]
    fn test_known_hosts_parse_openssh_format() {
        let mut hosts = KnownHosts::new();

        // Parse a sample known_hosts line
        let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

        hosts.parse_line(line).expect("Should parse line");

        assert_eq!(hosts.hosts.len(), 1);
        assert!(hosts.get_host("example.com").is_some());
    }

    #[test]
    fn test_known_hosts_parse_wildcard_host() {
        let mut hosts = KnownHosts::new();

        // Parse a wildcard host pattern
        let line = "*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

        hosts.parse_line(line).expect("Should parse line");

        assert_eq!(hosts.patterns.len(), 1);

        // Should match wildcard
        assert!(hosts.get_host("foo.example.com").is_some());
        assert!(hosts.get_host("bar.example.com").is_some());

        // Should not match non-wildcard
        assert!(hosts.get_host("example.com").is_none());
        assert!(hosts.get_host("evil.com").is_none());
    }

    #[test]
    fn test_known_hosts_parse_comment() {
        let mut hosts = KnownHosts::new();

        // Parse a line with comment
        let line = "# This is a comment";

        hosts.parse_line(line).expect("Should parse comment");

        // Comments should not add hosts
        assert_eq!(hosts.hosts.len(), 0);
    }

    #[test]
    fn test_known_hosts_parse_empty_line() {
        let mut hosts = KnownHosts::new();

        // Parse an empty line
        let line = "";

        hosts.parse_line(line).expect("Should parse empty line");

        // Empty lines should not add hosts
        assert_eq!(hosts.hosts.len(), 0);
    }

    #[test]
    fn test_known_hosts_parse_invalid_line() {
        let mut hosts = KnownHosts::new();

        // Parse an invalid line
        let line = "invalid line without enough fields";

        // Should return an error for invalid line
        assert!(hosts.parse_line(line).is_err());
    }

    #[test]
    fn test_known_hosts_match_pattern() {
        // Test match pattern matching
        let pattern = MatchPattern::new("*.example.com");

        assert!(pattern.matches("foo.example.com"));
        assert!(pattern.matches("bar.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("evil.com"));

        let pattern = MatchPattern::new("example.com");

        assert!(pattern.matches("example.com"));
        assert!(!pattern.matches("foo.example.com"));
    }

    #[test]
    fn test_known_hosts_host_key_types() {
        // Test different host key types
        let ed25519_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        let rsa_key = HostKey {
            key_type: HostKeyType::Rsa,
            key_data: vec![0x05, 0x06, 0x07, 0x08],
        };

        let ecdsa_key = HostKey {
            key_type: HostKeyType::Ecdsa,
            key_data: vec![0x09, 0x0a, 0x0b, 0x0c],
        };

        assert_eq!(ed25519_key.key_type.key_type_str(), "ssh-ed25519");
        assert_eq!(rsa_key.key_type.key_type_str(), "ssh-rsa");
        assert_eq!(ecdsa_key.key_type.key_type_str(), "ecdsa-sha2-nistp256");
    }

    #[test]
    fn test_known_hosts_serialization() {
        let mut hosts = KnownHosts::new();

        let host_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        hosts.add_host("example.com", host_key.clone());

        // Serialize to string
        let serialized = hosts.to_string();

        // Should contain the host and key
        assert!(serialized.contains("example.com"));
        assert!(serialized.contains("ssh-ed25519"));
    }

    #[test]
    fn test_known_hosts_from_string() {
        let known_hosts_content = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ssh-rsa dGVzdF9yc2Ffa2V5X2RhdGFfaGVyZQ==";

        let hosts = KnownHosts::from_string(known_hosts_content).expect("Should parse content");

        assert_eq!(hosts.hosts.len(), 2);
        assert!(hosts.get_host("example.com").is_some());
        assert!(hosts.get_host("github.com").is_some());
    }

    #[test]
    fn test_known_hosts_update_host() {
        let mut hosts = KnownHosts::new();

        let old_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        let new_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x05, 0x06, 0x07, 0x08],
        };

        hosts.add_host("example.com", old_key.clone());
        assert!(hosts.verify_host("example.com", &old_key));

        // Update the host key
        hosts.add_host("example.com", new_key.clone());

        // Old key should no longer verify
        assert!(!hosts.verify_host("example.com", &old_key));

        // New key should verify
        assert!(hosts.verify_host("example.com", &new_key));
    }

    #[test]
    fn test_known_hosts_remove_host() {
        let mut hosts = KnownHosts::new();

        let host_key = HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: vec![0x01, 0x02, 0x03, 0x04],
        };

        hosts.add_host("example.com", host_key.clone());
        assert!(hosts.get_host("example.com").is_some());

        hosts.remove_host("example.com");
        assert!(hosts.get_host("example.com").is_none());
    }
}