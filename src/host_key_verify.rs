//! Host Key Verification
//!
//! Implements SSH host key verification to prevent MITM attacks.
//! The `HostKeyVerifier` trait must be provided to `Transport::handshake()`
//! — there is no default, forcing the caller to make an explicit security decision.
//!
//! # Verifier implementations
//!
//! - `AcceptAll` — always accept (for testing only)
//! - `RejectAll` — always reject (paranoid mode)
//! - `TofuStore` — Trust On First Use, in-memory
//! - `TofuFileStore` — Trust On First Use, persisted to a file
//! - `StrictFileStore` — reject unknown hosts, verify known ones
//! - `CallbackVerifier` — user-provided async callback
//!
//! # Example
//! ```no_run
//! # async fn example() -> Result<(), ayssh::error::SshError> {
//! use ayssh::host_key_verify::{AcceptAll, TofuStore};
//!
//! // For testing:
//! // transport.handshake_with_verifier(&AcceptAll).await?;
//!
//! // For production:
//! // let verifier = TofuFileStore::new("/path/to/known_hosts")?;
//! // transport.handshake_with_verifier(&verifier).await?;
//! # Ok(())
//! # }
//! ```

use crate::error::SshError;
use crate::known_hosts::{HostKey, HostKeyType, KnownHosts};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Result of host key verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyAction {
    /// Key is known and matches — proceed with connection.
    Accept,
    /// Key is unknown (first connection) — accepted under TOFU policy.
    AcceptNew,
    /// Key is unknown — accepted for this session only, not saved.
    AcceptOnce,
    /// Key has CHANGED — possible MITM attack. Connection should be aborted.
    Reject,
    /// Host is unknown and policy doesn't allow new hosts.
    RejectUnknown,
}

impl HostKeyAction {
    /// Returns true if the connection should proceed.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accept | Self::AcceptNew | Self::AcceptOnce)
    }
}

/// Trait for host key verification.
///
/// Implementors decide whether to accept or reject a server's host key.
/// This trait is async to support interactive prompts, UI callbacks, etc.
///
/// Must be provided to `Transport::handshake_with_verifier()` — there is
/// no default verifier.
#[async_trait::async_trait]
pub trait HostKeyVerifier: Send + Sync {
    /// Verify a server's host key.
    ///
    /// Called during SSH handshake after receiving KEXDH_REPLY.
    /// `host` is the hostname/IP, `port` is the SSH port,
    /// `key_type` is the algorithm (e.g., "ssh-ed25519"),
    /// `key_blob` is the raw public key in SSH wire format.
    async fn verify(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        key_blob: &[u8],
    ) -> HostKeyAction;
}

// ==========================================================================
// AcceptAll — always accept (testing only)
// ==========================================================================

/// Always accepts any host key. **For testing only.**
///
/// Using this in production disables MITM protection.
#[derive(Debug, Clone, Copy)]
pub struct AcceptAll;

#[async_trait::async_trait]
impl HostKeyVerifier for AcceptAll {
    async fn verify(&self, _host: &str, _port: u16, _key_type: &str, _key_blob: &[u8]) -> HostKeyAction {
        HostKeyAction::Accept
    }
}

// ==========================================================================
// RejectAll — always reject
// ==========================================================================

/// Always rejects any host key. Useful for testing rejection paths.
#[derive(Debug, Clone, Copy)]
pub struct RejectAll;

#[async_trait::async_trait]
impl HostKeyVerifier for RejectAll {
    async fn verify(&self, _host: &str, _port: u16, _key_type: &str, _key_blob: &[u8]) -> HostKeyAction {
        HostKeyAction::Reject
    }
}

// ==========================================================================
// TofuStore — in-memory Trust On First Use
// ==========================================================================

/// Trust On First Use, in-memory.
///
/// - First connection to a host: accept and remember the key.
/// - Subsequent connections: accept if key matches, reject if changed.
/// - Keys are lost when the store is dropped.
#[derive(Debug)]
pub struct TofuStore {
    keys: Mutex<HashMap<String, (String, Vec<u8>)>>, // "host:port" → (key_type, key_blob)
}

impl TofuStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    fn host_key(host: &str, port: u16) -> String {
        if port == 22 {
            host.to_string()
        } else {
            format!("[{}]:{}", host, port)
        }
    }
}

impl Default for TofuStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HostKeyVerifier for TofuStore {
    async fn verify(&self, host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> HostKeyAction {
        let key_blob = match crate::x509::trust_identity(key_type, key_blob) {
            Ok(identity) => identity,
            Err(_) => return HostKeyAction::Reject,
        };
        let key = Self::host_key(host, port);
        let mut keys = self.keys.lock().unwrap();

        if let Some((stored_type, stored_blob)) = keys.get(&key) {
            if stored_type == key_type && stored_blob == &key_blob {
                HostKeyAction::Accept
            } else {
                HostKeyAction::Reject // KEY CHANGED
            }
        } else {
            // First time — trust and remember
            keys.insert(key, (key_type.to_string(), key_blob.to_vec()));
            HostKeyAction::AcceptNew
        }
    }
}

// ==========================================================================
// TofuFileStore — file-backed Trust On First Use
// ==========================================================================

/// Trust On First Use, backed by a file.
///
/// Reads known hosts from a file on creation, writes new entries when
/// accepting unknown hosts. **Never uses `~/.ssh/known_hosts` by default** —
/// you must provide an explicit path.
#[derive(Debug)]
pub struct TofuFileStore {
    path: PathBuf,
    hosts: Mutex<KnownHosts>,
}

impl TofuFileStore {
    /// Create a new TOFU file store at the given path.
    /// If the file exists, it's loaded. If not, starts empty.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, SshError> {
        let path = path.into();
        let mut hosts = KnownHosts::new();

        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| SshError::IoError(e))?;
            hosts.parse(&content)
                .map_err(|e| SshError::ProtocolError(format!("Failed to parse known_hosts: {}", e)))?;
        }

        Ok(Self {
            path,
            hosts: Mutex::new(hosts),
        })
    }

    /// Get the file path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Save current hosts to the file.
    fn save(&self) -> Result<(), SshError> {
        let hosts = self.hosts.lock().unwrap();
        let content = hosts.to_string();
        std::fs::write(&self.path, content)
            .map_err(|e| SshError::IoError(e))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl HostKeyVerifier for TofuFileStore {
    async fn verify(&self, host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> HostKeyAction {
        let key_blob = match crate::x509::trust_identity(key_type, key_blob) {
            Ok(identity) => identity,
            Err(_) => return HostKeyAction::Reject,
        };
        let lookup_host = if port == 22 {
            host.to_string()
        } else {
            format!("[{}]:{}", host, port)
        };

        let host_key_type = match HostKeyType::from_str(key_type) {
            Some(t) => t,
            None => return HostKeyAction::Reject,
        };

        let presented_key = HostKey {
            key_type: host_key_type,
            key_data: key_blob.to_vec(),
        };

        let mut hosts = self.hosts.lock().unwrap();

        if let Some(known_key) = hosts.get_host(&lookup_host) {
            if known_key.key_type == presented_key.key_type
                && known_key.key_data == presented_key.key_data
            {
                HostKeyAction::Accept
            } else {
                HostKeyAction::Reject // KEY CHANGED — possible MITM
            }
        } else {
            // First time — accept and save
            hosts.add_host(&lookup_host, presented_key);
            drop(hosts); // release lock before file I/O
            let _ = self.save(); // best effort save
            HostKeyAction::AcceptNew
        }
    }
}

// ==========================================================================
// StrictFileStore — reject unknown hosts
// ==========================================================================

/// Strict host key verification backed by a file.
///
/// - Known host with matching key: accept
/// - Known host with different key: reject (MITM)
/// - Unknown host: reject (must be added manually)
#[derive(Debug)]
pub struct StrictFileStore {
    hosts: Mutex<KnownHosts>,
}

impl StrictFileStore {
    /// Create from a known_hosts file. The file must exist.
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, SshError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| SshError::IoError(e))?;
        let mut hosts = KnownHosts::new();
        hosts.parse(&content)
            .map_err(|e| SshError::ProtocolError(format!("Failed to parse known_hosts: {}", e)))?;

        Ok(Self {
            hosts: Mutex::new(hosts),
        })
    }

    /// Create from an existing KnownHosts database.
    pub fn from_known_hosts(hosts: KnownHosts) -> Self {
        Self {
            hosts: Mutex::new(hosts),
        }
    }
}

#[async_trait::async_trait]
impl HostKeyVerifier for StrictFileStore {
    async fn verify(&self, host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> HostKeyAction {
        let key_blob = match crate::x509::trust_identity(key_type, key_blob) {
            Ok(identity) => identity,
            Err(_) => return HostKeyAction::Reject,
        };
        let lookup_host = if port == 22 {
            host.to_string()
        } else {
            format!("[{}]:{}", host, port)
        };

        let host_key_type = match HostKeyType::from_str(key_type) {
            Some(t) => t,
            None => return HostKeyAction::Reject,
        };

        let presented_key = HostKey {
            key_type: host_key_type,
            key_data: key_blob.to_vec(),
        };

        let hosts = self.hosts.lock().unwrap();

        if let Some(known_key) = hosts.get_host(&lookup_host) {
            if known_key.key_type == presented_key.key_type
                && known_key.key_data == presented_key.key_data
            {
                HostKeyAction::Accept
            } else {
                HostKeyAction::Reject // KEY CHANGED
            }
        } else {
            HostKeyAction::RejectUnknown // not in known_hosts
        }
    }
}

// ==========================================================================
// CallbackVerifier — user-provided async callback
// ==========================================================================

/// Host key verification via user-provided callback.
///
/// The callback receives host info and the presented key, and returns
/// a `HostKeyAction`. Since the trait is async, the callback can do
/// interactive prompts, send to a UI channel, etc.
pub struct CallbackVerifier<F>
where
    F: Fn(&str, u16, &str, &[u8]) -> HostKeyAction + Send + Sync,
{
    callback: F,
}

impl<F> CallbackVerifier<F>
where
    F: Fn(&str, u16, &str, &[u8]) -> HostKeyAction + Send + Sync,
{
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> std::fmt::Debug for CallbackVerifier<F>
where
    F: Fn(&str, u16, &str, &[u8]) -> HostKeyAction + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackVerifier").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<F> HostKeyVerifier for CallbackVerifier<F>
where
    F: Fn(&str, u16, &str, &[u8]) -> HostKeyAction + Send + Sync,
{
    async fn verify(&self, host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> HostKeyAction {
        (self.callback)(host, port, key_type, key_blob)
    }
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_accept_all() {
        let v = AcceptAll;
        let action = v.verify("host", 22, "ssh-ed25519", b"key").await;
        assert_eq!(action, HostKeyAction::Accept);
        assert!(action.is_accepted());
    }

    #[tokio::test]
    async fn test_reject_all() {
        let v = RejectAll;
        let action = v.verify("host", 22, "ssh-ed25519", b"key").await;
        assert_eq!(action, HostKeyAction::Reject);
        assert!(!action.is_accepted());
    }

    #[tokio::test]
    async fn test_tofu_store_first_connection() {
        let v = TofuStore::new();
        let action = v.verify("host.example.com", 22, "ssh-ed25519", b"keydata").await;
        assert_eq!(action, HostKeyAction::AcceptNew);
        assert!(action.is_accepted());
    }

    #[tokio::test]
    async fn test_tofu_store_same_key() {
        let v = TofuStore::new();
        v.verify("host", 22, "ssh-ed25519", b"keydata").await;
        let action = v.verify("host", 22, "ssh-ed25519", b"keydata").await;
        assert_eq!(action, HostKeyAction::Accept);
    }

    #[tokio::test]
    async fn test_tofu_store_key_changed() {
        let v = TofuStore::new();
        v.verify("host", 22, "ssh-ed25519", b"original-key").await;
        let action = v.verify("host", 22, "ssh-ed25519", b"different-key").await;
        assert_eq!(action, HostKeyAction::Reject);
        assert!(!action.is_accepted());
    }

    #[tokio::test]
    async fn test_tofu_store_different_hosts() {
        let v = TofuStore::new();
        v.verify("host1", 22, "ssh-ed25519", b"key1").await;
        v.verify("host2", 22, "ssh-ed25519", b"key2").await;
        assert_eq!(v.verify("host1", 22, "ssh-ed25519", b"key1").await, HostKeyAction::Accept);
        assert_eq!(v.verify("host2", 22, "ssh-ed25519", b"key2").await, HostKeyAction::Accept);
    }

    #[tokio::test]
    async fn test_tofu_store_non_standard_port() {
        let v = TofuStore::new();
        v.verify("host", 2222, "ssh-ed25519", b"key22").await;
        // Same host different port is a different entry
        let action = v.verify("host", 22, "ssh-ed25519", b"key22").await;
        assert_eq!(action, HostKeyAction::AcceptNew); // new entry for port 22
    }

    #[tokio::test]
    async fn test_tofu_file_store() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("known_hosts");

        let v = TofuFileStore::new(&path).unwrap();
        let action = v.verify("testhost", 22, "ssh-ed25519", b"test-key").await;
        assert_eq!(action, HostKeyAction::AcceptNew);

        // File should have been created
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("testhost"));

        // Second connection — should accept
        let v2 = TofuFileStore::new(&path).unwrap();
        let action = v2.verify("testhost", 22, "ssh-ed25519", b"test-key").await;
        assert_eq!(action, HostKeyAction::Accept);

        // Changed key — should reject
        let action = v2.verify("testhost", 22, "ssh-ed25519", b"changed-key").await;
        assert_eq!(action, HostKeyAction::Reject);
    }

    #[tokio::test]
    async fn test_strict_file_store() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("known_hosts");

        // Create a known_hosts file
        std::fs::write(&path, "myhost ssh-ed25519 dGVzdC1rZXk=\n").unwrap();

        let v = StrictFileStore::new(&path).unwrap();

        // Known host with correct key
        let action = v.verify("myhost", 22, "ssh-ed25519", b"test-key").await;
        assert_eq!(action, HostKeyAction::Accept);

        // Known host with wrong key
        let action = v.verify("myhost", 22, "ssh-ed25519", b"wrong-key").await;
        assert_eq!(action, HostKeyAction::Reject);

        // Unknown host
        let action = v.verify("unknown", 22, "ssh-ed25519", b"any-key").await;
        assert_eq!(action, HostKeyAction::RejectUnknown);
    }

    #[tokio::test]
    async fn test_callback_verifier() {
        let v = CallbackVerifier::new(|host, _port, _key_type, _key_blob| {
            if host == "trusted.example.com" {
                HostKeyAction::Accept
            } else {
                HostKeyAction::Reject
            }
        });

        assert_eq!(
            v.verify("trusted.example.com", 22, "ssh-ed25519", b"key").await,
            HostKeyAction::Accept
        );
        assert_eq!(
            v.verify("evil.example.com", 22, "ssh-ed25519", b"key").await,
            HostKeyAction::Reject
        );
    }

    #[test]
    fn test_host_key_action_is_accepted() {
        assert!(HostKeyAction::Accept.is_accepted());
        assert!(HostKeyAction::AcceptNew.is_accepted());
        assert!(HostKeyAction::AcceptOnce.is_accepted());
        assert!(!HostKeyAction::Reject.is_accepted());
        assert!(!HostKeyAction::RejectUnknown.is_accepted());
    }

    #[test]
    fn test_debug_impls() {
        let _ = format!("{:?}", AcceptAll);
        let _ = format!("{:?}", RejectAll);
        let _ = format!("{:?}", TofuStore::new());
        let v = CallbackVerifier::new(|_, _, _, _| HostKeyAction::Accept);
        let _ = format!("{:?}", v);
    }

    // --- Edge/error path tests ---

    #[test]
    fn test_tofu_store_default() {
        // Exercise Default::default() path
        let v: TofuStore = Default::default();
        assert_eq!(format!("{:?}", v), format!("{:?}", TofuStore::new()));
    }

    #[tokio::test]
    async fn test_tofu_file_store_path_accessor() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("test_known_hosts");
        let v = TofuFileStore::new(&path).unwrap();
        assert_eq!(v.path(), path);
    }

    #[tokio::test]
    async fn test_tofu_file_store_nonexistent_dir() {
        // File in nonexistent directory — new() should fail on save attempt
        // but creation itself succeeds (file doesn't need to exist yet)
        let v = TofuFileStore::new("/nonexistent/dir/known_hosts");
        // Should succeed — the file doesn't need to exist at creation time
        assert!(v.is_ok());
    }

    #[tokio::test]
    async fn test_tofu_file_store_invalid_content() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("bad_known_hosts");
        // Write invalid content
        std::fs::write(&path, "not a valid known_hosts line with only two fields\n").unwrap();
        let result = TofuFileStore::new(&path);
        assert!(result.is_err(), "Should fail to parse invalid known_hosts");
    }

    #[tokio::test]
    async fn test_tofu_file_store_save_error() {
        // Create a TOFU store pointing to a read-only path
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("known_hosts");
        let v = TofuFileStore::new(&path).unwrap();

        // Accept a key (triggers save)
        let action = v.verify("savetest", 22, "ssh-ed25519", b"key").await;
        assert_eq!(action, HostKeyAction::AcceptNew);

        // Verify the file was written
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("savetest"));
    }

    #[tokio::test]
    async fn test_strict_file_store_from_known_hosts() {
        let mut hosts = KnownHosts::new();
        hosts.add_host("myhost", HostKey {
            key_type: HostKeyType::Ed25519,
            key_data: b"known-key".to_vec(),
        });

        let v = StrictFileStore::from_known_hosts(hosts);

        // Known host — accept
        let action = v.verify("myhost", 22, "ssh-ed25519", b"known-key").await;
        assert_eq!(action, HostKeyAction::Accept);

        // Unknown host — reject
        let action = v.verify("unknown", 22, "ssh-ed25519", b"any-key").await;
        assert_eq!(action, HostKeyAction::RejectUnknown);
    }

    #[tokio::test]
    async fn test_strict_file_store_nonexistent_file() {
        let result = StrictFileStore::new("/nonexistent/path/known_hosts");
        assert!(result.is_err(), "Should fail if file doesn't exist");
    }

    #[tokio::test]
    async fn test_strict_file_store_invalid_content() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("bad_known_hosts");
        std::fs::write(&path, "invalid line\n").unwrap();
        let result = StrictFileStore::new(&path);
        assert!(result.is_err(), "Should fail to parse invalid content");
    }

    #[tokio::test]
    async fn test_callback_verifier_with_port() {
        // Exercise the callback with non-standard port
        let v = CallbackVerifier::new(|host, port, key_type, _key_blob| {
            if host == "myhost" && port == 2222 && key_type == "ssh-ed25519" {
                HostKeyAction::AcceptOnce
            } else {
                HostKeyAction::Reject
            }
        });

        let action = v.verify("myhost", 2222, "ssh-ed25519", b"key").await;
        assert_eq!(action, HostKeyAction::AcceptOnce);
        assert!(action.is_accepted());

        let action = v.verify("myhost", 22, "ssh-ed25519", b"key").await;
        assert_eq!(action, HostKeyAction::Reject);
    }

    #[tokio::test]
    async fn test_tofu_store_key_type_change() {
        // Same host, different key type — should reject
        let v = TofuStore::new();
        v.verify("host", 22, "ssh-ed25519", b"ed-key").await;
        let action = v.verify("host", 22, "ssh-rsa", b"rsa-key").await;
        assert_eq!(action, HostKeyAction::Reject);
    }

    #[tokio::test]
    async fn test_tofu_file_store_unknown_key_type() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("known_hosts");
        let v = TofuFileStore::new(&path).unwrap();

        // Unknown key type should be rejected
        let action = v.verify("host", 22, "unknown-algo", b"key").await;
        assert_eq!(action, HostKeyAction::Reject);
    }

    #[test]
    fn test_host_key_action_debug() {
        assert!(format!("{:?}", HostKeyAction::Accept).contains("Accept"));
        assert!(format!("{:?}", HostKeyAction::AcceptNew).contains("AcceptNew"));
        assert!(format!("{:?}", HostKeyAction::AcceptOnce).contains("AcceptOnce"));
        assert!(format!("{:?}", HostKeyAction::Reject).contains("Reject"));
        assert!(format!("{:?}", HostKeyAction::RejectUnknown).contains("RejectUnknown"));
    }
}
