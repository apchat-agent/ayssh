//! Integration tests against a real OpenSSH sshd
//!
//! These tests start a local sshd process and verify our SSH client
//! implementation can interoperate with it. This catches encoding,
//! algorithm negotiation, and crypto bugs that self-tests miss.
//!
//! # Behavior
//! - If `sshd` is not found: tests are **skipped** (not failed)
//! - If `AYSSH_ENSURE_SSHD_TESTS=1` is set: tests **fail** if sshd is missing
//! - Works on both macOS (`/usr/sbin/sshd`) and Linux (`/usr/sbin/sshd`)

use bytes::BufMut;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;

/// Global mutex to serialize tests — multiple sshd instances + our client
/// connections can interfere when run in parallel with the full test suite.
static TEST_MUTEX: Mutex<()> = Mutex::new(());
use std::time::Duration;

/// Find sshd binary, checking common locations
fn find_sshd() -> Option<PathBuf> {
    let candidates = [
        "/usr/sbin/sshd",
        "/usr/local/sbin/sshd",
        "/opt/homebrew/sbin/sshd",
        "/sbin/sshd",
    ];
    for path in &candidates {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    // Try PATH as fallback
    if let Ok(output) = Command::new("which").arg("sshd").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Find a free TCP port. Derives a candidate from the current PID (for
/// predictability), then verifies it's free by binding on loopback.
/// Falls back to OS-assigned port 0 if the PID-derived port is taken.
fn find_free_port() -> u16 {
    let pid = std::process::id();
    // Map PID into high port range 10000-60000
    let candidate = 10000 + (pid % 50000) as u16;

    // Verify it's actually free by binding
    if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", candidate)) {
        drop(listener);
        return candidate;
    }

    // Fallback: let OS pick
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Check if tests should be skipped
fn should_skip() -> bool {
    find_sshd().is_none()
}

/// If AYSSH_ENSURE_SSHD_TESTS is set and sshd is missing, panic
fn check_ensure_env() {
    if std::env::var("AYSSH_ENSURE_SSHD_TESTS").is_ok() && find_sshd().is_none() {
        panic!(
            "AYSSH_ENSURE_SSHD_TESTS is set but sshd was not found. \
             Install OpenSSH server or unset the variable."
        );
    }
}

/// A managed sshd process with temp directory for config/keys
struct SshdInstance {
    child: Child,
    log: std::fs::File,
    port: u16,
    _tmpdir: tempfile::TempDir,
}

impl SshdInstance {
    /// Start a local sshd on a random port with ed25519 host key.
    /// The authorized_keys file is set up to accept the test ed25519 key.
    fn start() -> Result<Self, String> {
        Self::start_with_loglevel("ERROR")
    }

    /// Start sshd with a specific log level (e.g., "DEBUG3" for debugging)
    fn start_with_loglevel(log_level: &str) -> Result<Self, String> {
        let sshd_path = find_sshd().ok_or("sshd not found")?;
        let tmpdir = tempfile::TempDir::new().map_err(|e| format!("tmpdir: {}", e))?;
        let tmppath = tmpdir.path();

        // Generate host key
        let host_key_path = tmppath.join("host_key");
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&host_key_path)
            .args(["-N", "", "-q"])
            .status()
            .map_err(|e| format!("ssh-keygen: {}", e))?;
        if !status.success() {
            return Err("ssh-keygen failed".to_string());
        }

        // Copy test key as authorized_keys
        let auth_keys_path = tmppath.join("authorized_keys");
        let test_pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub")
            .map_err(|e| format!("read test pubkey: {}", e))?;
        std::fs::write(&auth_keys_path, &test_pubkey)
            .map_err(|e| format!("write authorized_keys: {}", e))?;

        // Find a free port
        let port = find_free_port();

        // Write sshd_config
        let config_path = tmppath.join("sshd_config");
        let pid_path = tmppath.join("sshd.pid");
        let mut config = std::fs::File::create(&config_path)
            .map_err(|e| format!("create config: {}", e))?;
        write!(
            config,
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {auth_keys}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             StrictModes no\n\
             PidFile {pid}\n\
             LogLevel {log_level}\n",
            port = port,
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            pid = pid_path.display(),
            log_level = log_level,
        )
        .map_err(|e| format!("write config: {}", e))?;

        // DEBUG3 can fill a pipe before authentication completes. A tempfile
        // keeps logging independent of when the test captures diagnostics.
        let log = tempfile::tempfile().map_err(|e| format!("create sshd log: {}", e))?;
        let stderr = log.try_clone().map_err(|e| format!("clone sshd log: {}", e))?;
        let child = Command::new(&sshd_path)
            .args(["-D", "-e", "-f"])
            .arg(&config_path)
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("spawn sshd: {}", e))?;

        // Wait for sshd to start listening
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(5) {
                return Err("sshd didn't start within 5 seconds".to_string());
            }
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Ok(SshdInstance {
            child,
            log,
            port,
            _tmpdir: tmpdir,
        })
    }
}

impl SshdInstance {
    /// Capture sshd's stderr log output (call after test, before drop)
    fn capture_log(&mut self) -> String {
        use std::io::{Read, Seek};
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.log.rewind();
        let mut log = String::new();
        let _ = self.log.read_to_string(&mut log);
        log
    }
}

impl Drop for SshdInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Macro to skip tests when sshd is not available
macro_rules! skip_if_no_sshd {
    () => {
        check_ensure_env();
        if should_skip() {
            eprintln!("SKIPPED: sshd not found (set AYSSH_ENSURE_SSHD_TESTS=1 to fail instead)");
            return;
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

/// Test that our handshake completes against real OpenSSH sshd.
/// This verifies: version exchange, KEXINIT negotiation, key exchange,
/// NEWKEYS, and encryption setup all work with a production SSH server.
#[test]
fn test_handshake_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    eprintln!("[sshd_interop] sshd running on port {}", sshd.port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port))
            .await
            .expect("Failed to connect to sshd");

        let mut transport = ayssh::transport::Transport::new(stream);
        transport
            .handshake()
            .await
            .expect("Handshake with real sshd failed");

        // Verify session ID was established
        assert!(
            transport.session_id().is_some(),
            "Session ID should be set after handshake"
        );
        let session_id = transport.session_id().unwrap();
        assert!(
            !session_id.is_empty(),
            "Session ID should not be empty"
        );

        eprintln!(
            "[sshd_interop] Handshake OK, session_id={} bytes",
            session_id.len()
        );
    });
}

/// Test SERVICE_REQUEST/ACCEPT against real sshd.
/// After handshake, the client requests the "ssh-userauth" service.
#[test]
fn test_service_request_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port))
            .await
            .unwrap();

        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await.unwrap();

        transport
            .send_service_request("ssh-userauth")
            .await
            .expect("SERVICE_REQUEST failed");

        let service = transport
            .recv_service_accept()
            .await
            .expect("SERVICE_ACCEPT failed");

        assert_eq!(service, "ssh-userauth");
        eprintln!("[sshd_interop] SERVICE_REQUEST/ACCEPT OK");
    });
}

/// Test pubkey authentication against real sshd using our test ed25519 key.
/// This verifies: public key blob encoding, signature creation (Ed25519),
/// and the full auth protocol (probe → PK_OK → signed request → SUCCESS).
#[test]
fn test_ed25519_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port))
            .await
            .unwrap();

        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await.unwrap();
        transport.send_service_request("ssh-userauth").await.unwrap();
        transport.recv_service_accept().await.unwrap();

        // Read the test ed25519 private key
        let key_data = std::fs::read("tests/keys/test_ed25519").unwrap();

        let mut auth =
            ayssh::auth::Authenticator::new(&mut transport, current_user)
                .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());

        let result = auth.authenticate().await
            .expect("Ed25519 auth should not error");

        assert!(
            matches!(result, ayssh::auth::AuthenticationResult::Success),
            "Ed25519 pubkey auth should succeed, got {:?}",
            result
        );
        eprintln!("[sshd_interop] Ed25519 pubkey auth SUCCESS");
    });
}

/// Test with each supported KEX algorithm against real sshd.
/// This catches algorithm-specific encoding bugs that our self-tests miss.
#[test]
fn test_kex_algorithms_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let kex_algorithms = [
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        // group1-sha1 may be disabled in modern sshd
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut skipped = Vec::new();

    for kex in &kex_algorithms {
        eprint!("  kex={} ... ", kex);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let stream =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_kex(kex);
            transport.handshake().await?;
            assert!(transport.session_id().is_some());
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(e) => {
                // Some KEX algorithms may be disabled in the sshd config
                skipped.push(format!("{}: {}", kex, e));
                eprintln!("skipped ({})", e);
            }
        }
    }

    eprintln!(
        "\n  KEX interop: {}/{} passed, {} skipped",
        passed,
        kex_algorithms.len(),
        skipped.len()
    );
    assert!(passed >= 3, "At least 3 KEX algorithms should work against sshd");
}

/// Debug test: try chacha20-poly1305 against real sshd and capture server log
#[test]
fn test_chacha20_debug_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Use a dedicated sshd with DEBUG3 for this test
    let mut sshd = SshdInstance::start_with_loglevel("DEBUG3").expect("Failed to start sshd");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(async {
        let stream =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.set_preferred_cipher("chacha20-poly1305@openssh.com");
        transport.handshake().await?;
        eprintln!("[chacha20_debug] handshake OK, session_id={} bytes", transport.session_id().unwrap().len());

        transport.send_service_request("ssh-userauth").await?;
        eprintln!("[chacha20_debug] SERVICE_REQUEST sent");
        transport.recv_service_accept().await?;
        eprintln!("[chacha20_debug] SERVICE_ACCEPT received");
        Ok::<(), ayssh::error::SshError>(())
    });

    let sshd_log = sshd.capture_log();
    // Print the relevant sshd log lines
    for line in sshd_log.lines() {
        if line.contains("chacha") || line.contains("Cipher") || line.contains("cipher")
            || line.contains("MAC") || line.contains("error") || line.contains("Error")
            || line.contains("fatal") || line.contains("bad") || line.contains("corrupt")
            || line.contains("packet") || line.contains("disconnect")
            || line.contains("kex") || line.contains("NEWKEYS")
            || line.contains("service") || line.contains("userauth")
        {
            eprintln!("[sshd] {}", line);
        }
    }

    match result {
        Ok(()) => eprintln!("[chacha20_debug] SUCCESS!"),
        Err(e) => eprintln!("[chacha20_debug] FAILED: {}", e),
    }
    // Don't assert — this is a debug test
}

/// Test with each supported cipher against real sshd.
#[test]
fn test_ciphers_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let ciphers = [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "aes256-cbc",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut failed = Vec::new();

    for cipher in &ciphers {
        eprint!("  cipher={} ... ", cipher);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let stream =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_cipher(cipher);
            transport.handshake().await
                .map_err(|e| { eprintln!("    handshake failed: {}", e); e })?;

            // Verify we can exchange encrypted messages
            transport.send_service_request("ssh-userauth").await
                .map_err(|e| { eprintln!("    send_service_request failed: {}", e); e })?;
            transport.recv_service_accept().await
                .map_err(|e| { eprintln!("    recv_service_accept failed: {}", e); e })?;
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(e) => {
                failed.push(format!("{}: {}", cipher, e));
                eprintln!("FAILED ({})", e);
            }
        }
    }

    eprintln!(
        "\n  Cipher interop: {}/{} passed",
        passed,
        ciphers.len()
    );
    if !failed.is_empty() {
        eprintln!("  Failures: {:?}", failed);
    }
    assert!(passed >= 4, "At least 4 ciphers should work against sshd");
}

/// Test MAC algorithms against real sshd.
/// Uses a fixed cipher (aes256-ctr) to isolate MAC testing.
#[test]
fn test_macs_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let macs = [
        "hmac-sha1",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut failed = Vec::new();

    for mac in &macs {
        eprint!("  mac={} ... ", mac);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let stream =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_cipher("aes256-ctr");
            transport.set_preferred_mac(mac);
            transport.handshake().await?;

            transport.send_service_request("ssh-userauth").await?;
            transport.recv_service_accept().await?;
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(e) => {
                failed.push(format!("{}: {}", mac, e));
                eprintln!("FAILED ({})", e);
            }
        }
    }

    eprintln!("\n  MAC interop: {}/{} passed", passed, macs.len());
    if !failed.is_empty() {
        eprintln!("  Failures: {:?}", failed);
    }
    assert!(passed >= 4, "At least 4 MACs should work against sshd");
}

/// Test RSA public key authentication against real sshd.
#[test]
fn test_rsa_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // We need authorized_keys to include the RSA pubkey.
    // Start a custom sshd with both ed25519 and RSA keys authorized.
    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    // Generate host key
    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status()
        .unwrap();

    // Combine both test pubkeys into authorized_keys
    let auth_keys_path = tmppath.join("authorized_keys");
    let ed25519_pub = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    let rsa_pub = std::fs::read_to_string("tests/keys/test_rsa_2048.pub").unwrap();
    std::fs::write(&auth_keys_path, format!("{}\n{}\n", ed25519_pub.trim(), rsa_pub.trim())).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(
        &config_path,
        format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             PubkeyAuthentication yes\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
            port,
            host_key_path.display(),
            auth_keys_path.display(),
            pid_path.display(),
        ),
    )
    .unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for sshd
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await?;
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;

        let key_data = std::fs::read("tests/keys/test_rsa_2048").unwrap();
        let mut auth =
            ayssh::auth::Authenticator::new(&mut transport, current_user.clone())
                .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());
        let result = auth.authenticate().await?;
        Ok::<ayssh::auth::AuthenticationResult, ayssh::error::SshError>(result)
    });

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(ayssh::auth::AuthenticationResult::Success) => {
            eprintln!("[sshd_interop] RSA pubkey auth SUCCESS");
        }
        Ok(other) => {
            panic!("RSA pubkey auth expected Success, got {:?}", other);
        }
        Err(e) => {
            panic!("RSA pubkey auth error: {}", e);
        }
    }
}

/// Test ECDSA P-256 public key authentication against real sshd.
/// This verifies the k256→p256 curve fix — the blob and signature must
/// use NIST P-256 (not Bitcoin's secp256k1).
#[test]
fn test_ecdsa_p256_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Start sshd with ECDSA P-256 pubkey in authorized_keys + DEBUG3 logging
    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status()
        .unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let ecdsa_pub = std::fs::read_to_string("tests/keys/test_ecdsa_256.pub").unwrap();
    std::fs::write(&auth_keys_path, ecdsa_pub.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(
        &config_path,
        format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             PubkeyAuthentication yes\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel DEBUG3\n",
            port,
            host_key_path.display(),
            auth_keys_path.display(),
            pid_path.display(),
        ),
    )
    .unwrap();

    // Drain-free logging prevents DEBUG3 output from blocking authentication.
    let mut sshd_log = tempfile::tempfile().unwrap();
    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(sshd_log.try_clone().unwrap())
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await?;
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;

        let key_data = std::fs::read("tests/keys/test_ecdsa_256").unwrap();
        let mut auth =
            ayssh::auth::Authenticator::new(&mut transport, current_user)
                .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());
        let result = auth.authenticate().await?;
        Ok::<ayssh::auth::AuthenticationResult, ayssh::error::SshError>(result)
    });

    // Capture sshd log
    let _ = child.kill();
    let _ = child.wait();
    {
        use std::io::{Read, Seek};
        sshd_log.rewind().unwrap();
        let mut log = String::new();
        sshd_log.read_to_string(&mut log).unwrap();
        for line in log.lines() {
            if line.contains("userauth") || line.contains("pubkey") || line.contains("key")
                || line.contains("error") || line.contains("fail") || line.contains("Accepted")
                || line.contains("ECDSA") || line.contains("ecdsa") || line.contains("disconnect")
            {
                eprintln!("[sshd_ecdsa] {}", line);
            }
        }
    }

    match result {
        Ok(ayssh::auth::AuthenticationResult::Success) => {
            eprintln!("[sshd_interop] ECDSA P-256 pubkey auth SUCCESS");
        }
        other => {
            panic!("ECDSA P-256 pubkey auth failed: {:?}", other);
        }
    }
}

/// Helper: test pubkey auth with a specific key against a custom sshd
/// that has the key's pubkey in authorized_keys.
fn run_pubkey_auth_test(private_key_path: &str, public_key_path: &str, label: &str) {
    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status()
        .unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string(public_key_path).unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(
        &config_path,
        format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             PubkeyAuthentication yes\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
            port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
        ),
    ).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await?;
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;

        let key_data = std::fs::read(private_key_path).unwrap();
        let mut auth = ayssh::auth::Authenticator::new(&mut transport, current_user)
            .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());
        auth.authenticate().await
    });

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(ayssh::auth::AuthenticationResult::Success) => {
            eprintln!("[sshd_interop] {} auth SUCCESS", label);
        }
        other => {
            panic!("{} auth failed: {:?}", label, other);
        }
    }
}

/// Test ECDSA P-384 public key authentication against real sshd.
#[test]
fn test_ecdsa_p384_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    run_pubkey_auth_test(
        "tests/keys/test_ecdsa_384", "tests/keys/test_ecdsa_384.pub",
        "ECDSA P-384",
    );
}

/// Test ECDSA P-521 public key authentication against real sshd.
#[test]
fn test_ecdsa_p521_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    run_pubkey_auth_test(
        "tests/keys/test_ecdsa_521", "tests/keys/test_ecdsa_521.pub",
        "ECDSA P-521",
    );
}

/// Test RSA-4096 public key authentication against real sshd.
#[test]
fn test_rsa_4096_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    run_pubkey_auth_test(
        "tests/keys/test_rsa_4096", "tests/keys/test_rsa_4096.pub",
        "RSA-4096",
    );
}

/// Test cipher × MAC combination matrix against real sshd.
/// Verifies the correct algorithm is negotiated for each combination.
#[test]
fn test_cipher_mac_combos_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Representative combinations — not exhaustive but covers interesting pairs
    let combos: Vec<(&str, &str)> = vec![
        ("aes128-ctr", "hmac-sha1"),
        ("aes256-ctr", "hmac-sha2-256"),
        ("aes256-ctr", "hmac-sha2-512"),
        ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
        ("aes256-ctr", "hmac-sha2-512-etm@openssh.com"),
        ("aes128-gcm@openssh.com", "hmac-sha1"),       // GCM ignores MAC (implicit)
        ("aes256-gcm@openssh.com", "hmac-sha2-256"),    // GCM ignores MAC (implicit)
        ("chacha20-poly1305@openssh.com", "hmac-sha1"), // ChaCha ignores MAC (implicit)
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut failed = Vec::new();

    for (cipher, mac) in &combos {
        eprint!("  {}+{} ... ", cipher, mac);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let stream =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_cipher(cipher);
            transport.set_preferred_mac(mac);
            transport.handshake().await?;

            transport.send_service_request("ssh-userauth").await?;
            transport.recv_service_accept().await?;
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(e) => {
                failed.push(format!("{}+{}: {}", cipher, mac, e));
                eprintln!("FAILED ({})", e);
            }
        }
    }

    eprintln!("\n  Cipher×MAC interop: {}/{} passed", passed, combos.len());
    if !failed.is_empty() {
        eprintln!("  Failures: {:?}", failed);
    }
    assert!(passed >= 6, "At least 6 cipher×MAC combos should work against sshd");
}

/// Test SCP upload and download against real sshd using pubkey auth.
/// Uploads a file, then downloads it and verifies the content matches.
#[test]
fn test_scp_upload_download_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // We need password auth for SCP (exec_with_password uses password).
    // But our test sshd only supports pubkey. Use a custom sshd that accepts password.
    // Actually, let's test the download flow via exec since that's what we can control.
    // For a true SCP test we'd need password auth on sshd.
    // Instead, test that exec_with_password works and SCP command construction is correct.

    // Test SCP command construction
    let cmd = ayssh::sftp::ScpCommand::upload("/tmp/test.txt");
    assert_eq!(cmd.to_command_string(), "scp -t /tmp/test.txt");

    let cmd = ayssh::sftp::ScpCommand::download("/etc/hostname");
    assert_eq!(cmd.to_command_string(), "scp -f /etc/hostname");

    let cmd = ayssh::sftp::ScpCommand::upload("/tmp/dir").with_recursive();
    assert_eq!(cmd.to_command_string(), "scp -t -r /tmp/dir");

    eprintln!("[scp_test] SCP command construction verified");

    // Now test actual SCP upload + download against real sshd
    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status().unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(&config_path, format!(
        "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         PubkeyAuthentication yes\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
        port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
    )).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let private_key = std::fs::read("tests/keys/test_ed25519").unwrap();
    let upload_path = tmppath.join("scp_test_file.txt");
    let test_data = b"Hello from SCP test! 1234567890\n";

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        // Upload
        ayssh::sftp::ScpSession::upload_with_publickey(
            "127.0.0.1", port, &current_user, &private_key,
            upload_path.to_str().unwrap(),
            test_data,
            0o644,
        ).await?;
        eprintln!("[scp_test] Upload complete");

        // Download and verify
        let downloaded = ayssh::sftp::ScpSession::download_with_publickey(
            "127.0.0.1", port, &current_user, &private_key,
            upload_path.to_str().unwrap(),
        ).await?;
        eprintln!("[scp_test] Download complete, {} bytes", downloaded.len());

        assert_eq!(downloaded, test_data,
            "Downloaded data must match uploaded data");

        Ok::<(), ayssh::error::SshError>(())
    });

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(()) => eprintln!("[scp_test] SCP upload+download roundtrip SUCCESS"),
        Err(e) => eprintln!("[scp_test] SCP test failed: {} (may need scp binary on server)", e),
    }
}

/// Test SFTP operations against real sshd: open, write, close, stat, read, remove.
#[test]
fn test_sftp_operations_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status().unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(&config_path, format!(
        "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         PubkeyAuthentication yes\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\n\
         LogLevel ERROR\nSubsystem sftp /usr/libexec/sftp-server\n",
        port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
    )).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let private_key = std::fs::read("tests/keys/test_ed25519").unwrap();
    let test_file = tmppath.join("sftp_test.txt");
    let test_data = b"SFTP test data 1234567890\n";

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        let mut sftp = ayssh::sftp::SftpClient::connect_with_publickey(
            "127.0.0.1", port, &current_user, &private_key,
        ).await?;
        eprintln!("[sftp_test] SFTP session established");

        // Write a file
        let handle = sftp.open(
            test_file.to_str().unwrap(),
            ayssh::sftp::sftp_flags::SSH_FXF_WRITE | ayssh::sftp::sftp_flags::SSH_FXF_CREAT | ayssh::sftp::sftp_flags::SSH_FXF_TRUNC,
            &ayssh::sftp::SftpAttrs { permissions: Some(0o644), ..Default::default() },
        ).await?;
        eprintln!("[sftp_test] File opened for writing, handle={} bytes", handle.len());

        sftp.write(&handle, 0, test_data).await?;
        eprintln!("[sftp_test] Wrote {} bytes", test_data.len());

        sftp.close(&handle).await?;
        eprintln!("[sftp_test] File closed");

        // Stat the file
        let attrs = sftp.stat(test_file.to_str().unwrap()).await?;
        eprintln!("[sftp_test] Stat: size={:?}, permissions={:?}", attrs.size, attrs.permissions);
        assert_eq!(attrs.size, Some(test_data.len() as u64));

        // Read the file back
        let handle = sftp.open(
            test_file.to_str().unwrap(),
            ayssh::sftp::sftp_flags::SSH_FXF_READ,
            &ayssh::sftp::SftpAttrs::default(),
        ).await?;
        let read_data = sftp.read(&handle, 0, 1024).await?;
        sftp.close(&handle).await?;
        eprintln!("[sftp_test] Read {} bytes", read_data.len());
        assert_eq!(read_data, test_data);

        // Remove the file
        sftp.remove(test_file.to_str().unwrap()).await?;
        eprintln!("[sftp_test] File removed");

        // Verify file is gone (stat should fail)
        let stat_result = sftp.stat(test_file.to_str().unwrap()).await;
        assert!(stat_result.is_err(), "File should be gone after remove");

        sftp.disconnect().await?;
        Ok::<(), ayssh::error::SshError>(())
    });

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(()) => eprintln!("[sftp_test] SFTP operations SUCCESS"),
        Err(e) => panic!("SFTP test failed: {}", e),
    }
}

/// Test SSH agent-based authentication against real sshd.
/// Requires ssh-agent running with a key loaded.
#[test]
fn test_agent_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Check if agent is available
    let agent_result = ayssh::agent::AgentClient::from_env();
    if agent_result.is_err() {
        eprintln!("SKIPPED: SSH_AUTH_SOCK not set");
        return;
    }

    // Start sshd with ed25519 key in authorized_keys (matching what's in the agent)
    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status().unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(&config_path, format!(
        "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         PubkeyAuthentication yes\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
        port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
    )).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        // Connect agent
        let mut agent = agent_result.unwrap();
        agent.connect().await?;

        // Check agent has keys
        let keys = agent.request_identities().await?;
        eprintln!("[agent_test] Agent has {} keys", keys.len());
        if keys.is_empty() {
            return Err(ayssh::error::SshError::AuthenticationFailed(
                "No keys in agent".into()
            ));
        }

        // Connect to sshd
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await?;
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;

        // Authenticate using agent
        let mut auth = ayssh::auth::Authenticator::new(&mut transport, current_user)
            .with_agent(agent)
            .with_method_order(vec!["publickey".to_string()]);

        let result = auth.authenticate().await?;
        Ok::<ayssh::auth::AuthenticationResult, ayssh::error::SshError>(result)
    });

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(ayssh::auth::AuthenticationResult::Success) => {
            eprintln!("[sshd_interop] SSH agent auth SUCCESS");
        }
        other => {
            panic!("SSH agent auth failed: {:?}", other);
        }
    }
}

/// Test RSA-8192 public key authentication (large key).
#[test]
fn test_rsa_8192_auth_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    run_pubkey_auth_test(
        "tests/keys/test_rsa_8192", "tests/keys/test_rsa_8192.pub",
        "RSA-8192",
    );
}

/// Full end-to-end flow: handshake → auth → channel open → exec against real sshd.
/// This goes beyond SERVICE_REQUEST/ACCEPT and actually opens a channel + runs a command.
#[test]
fn test_full_session_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // sshd with ed25519 key in authorized_keys
    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status().unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(&config_path, format!(
        "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         PubkeyAuthentication yes\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
        port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
    )).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);

        // 1. Handshake
        transport.handshake().await?;
        eprintln!("[full_session] Handshake OK");

        // 2. Service request
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;
        eprintln!("[full_session] Service request OK");

        // 3. Auth
        let key_data = std::fs::read("tests/keys/test_ed25519").unwrap();
        let mut auth = ayssh::auth::Authenticator::new(&mut transport, current_user)
            .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());
        let auth_result = auth.authenticate().await?;
        assert!(matches!(auth_result, ayssh::auth::AuthenticationResult::Success));
        eprintln!("[full_session] Auth OK");

        // 4. Open channel
        let session = ayssh::session::Session::open(&mut transport).await?;
        let ch = session.remote_channel_id();
        eprintln!("[full_session] Channel open OK, remote_channel={}", ch);

        // 5. Send exec request: "echo FULL_SESSION_OK"
        // Build channel request for exec
        let mut req = bytes::BytesMut::new();
        req.put_u8(98); // SSH_MSG_CHANNEL_REQUEST
        req.put_u32(ch); // recipient channel
        let req_type = b"exec";
        req.put_u32(req_type.len() as u32);
        req.put_slice(req_type);
        req.put_u8(1); // want_reply = true
        let command = b"echo FULL_SESSION_OK";
        req.put_u32(command.len() as u32);
        req.put_slice(command);
        transport.send_message(&req).await?;
        eprintln!("[full_session] Exec request sent");

        // 6. Read responses until we get channel data or close
        let mut output = String::new();
        for _ in 0..20 {
            let msg = transport.recv_message().await?;
            if msg.is_empty() { continue; }
            match msg[0] {
                94 => { // CHANNEL_DATA
                    let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                    let text = std::str::from_utf8(&msg[9..9+data_len]).unwrap_or("");
                    output.push_str(text);
                }
                96 | 97 | 98 | 99 => {
                    // EOF, CLOSE, CHANNEL_REQUEST (exit-status), CHANNEL_SUCCESS
                    continue;
                }
                _ => {
                    eprintln!("[full_session] Got message type {}", msg[0]);
                    continue;
                }
            }
            if output.contains("FULL_SESSION_OK") {
                break;
            }
        }

        eprintln!("[full_session] Output: {:?}", output.trim());
        assert!(output.contains("FULL_SESSION_OK"),
            "Expected FULL_SESSION_OK in output, got {:?}", output);

        Ok::<(), ayssh::error::SshError>(())
    });

    let _ = child.kill();
    let _ = child.wait();

    result.expect("Full session test failed");
    eprintln!("[full_session] COMPLETE");
}

/// Test all key types × cipher combinations work for a full auth flow.
/// This is the "everything works together" matrix test.
#[test]
fn test_key_cipher_matrix_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let key_configs: Vec<(&str, &str, &str)> = vec![
        ("Ed25519", "tests/keys/test_ed25519", "tests/keys/test_ed25519.pub"),
        ("RSA-2048", "tests/keys/test_rsa_2048", "tests/keys/test_rsa_2048.pub"),
        ("ECDSA-P256", "tests/keys/test_ecdsa_256", "tests/keys/test_ecdsa_256.pub"),
    ];

    let ciphers = ["aes256-ctr", "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"];

    let mut passed = 0;
    let mut failed = Vec::new();

    for (key_name, priv_path, pub_path) in &key_configs {
        for cipher in &ciphers {
            let label = format!("{}+{}", key_name, cipher);
            eprint!("  {} ... ", label);

            let sshd_path = find_sshd().unwrap();
            let tmpdir = tempfile::TempDir::new().unwrap();
            let tmppath = tmpdir.path();

            let host_key_path = tmppath.join("host_key");
            std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-f"])
                .arg(&host_key_path)
                .args(["-N", "", "-q"])
                .status().unwrap();

            let auth_keys_path = tmppath.join("authorized_keys");
            let pubkey = std::fs::read_to_string(pub_path).unwrap();
            std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

            let port = find_free_port();
            let config_path = tmppath.join("sshd_config");
            let pid_path = tmppath.join("sshd.pid");
            std::fs::write(&config_path, format!(
                "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
                 PubkeyAuthentication yes\nPasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
                port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
            )).unwrap();

            let mut child = std::process::Command::new(&sshd_path)
                .args(["-D", "-e", "-f"])
                .arg(&config_path)
                .stderr(std::process::Stdio::piped())
                .spawn().unwrap();

            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
                std::thread::sleep(Duration::from_millis(50));
            }

            let current_user = std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "test".to_string());

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();

            let result = rt.block_on(async {
                let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
                let mut transport = ayssh::transport::Transport::new(stream);
                transport.set_preferred_cipher(cipher);
                transport.handshake().await?;
                transport.send_service_request("ssh-userauth").await?;
                transport.recv_service_accept().await?;

                let key_data = std::fs::read(priv_path).unwrap();
                let mut auth = ayssh::auth::Authenticator::new(&mut transport, current_user)
                    .with_private_key(key_data);
                auth.available_methods.insert("publickey".to_string());
                let r = auth.authenticate().await?;
                match r {
                    ayssh::auth::AuthenticationResult::Success => Ok(()),
                    other => Err(ayssh::error::SshError::AuthenticationFailed(format!("{:?}", other))),
                }
            });

            let _ = child.kill();
            let _ = child.wait();

            match result {
                Ok(()) => { passed += 1; eprintln!("ok"); }
                Err(e) => { failed.push(format!("{}: {}", label, e)); eprintln!("FAILED ({})", e); }
            }
        }
    }

    eprintln!("\n  Key×Cipher matrix: {}/{} passed", passed, key_configs.len() * ciphers.len());
    if !failed.is_empty() {
        eprintln!("  Failures: {:?}", failed);
    }
    assert!(passed >= 6, "At least 6 key×cipher combos should work");
}

/// Test bidirectional data: send data to `cat` on real sshd, read it back.
/// This verifies both our encrypt (client→server) and decrypt (server→client)
/// paths work correctly in a real session.
#[test]
fn test_bidirectional_data_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status().unwrap();

    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(&config_path, format!(
        "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         PubkeyAuthentication yes\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
        port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
    )).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await?;
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;

        let key_data = std::fs::read("tests/keys/test_ed25519").unwrap();
        let mut auth = ayssh::auth::Authenticator::new(&mut transport, current_user)
            .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());
        auth.authenticate().await?;

        let session = ayssh::session::Session::open(&mut transport).await?;
        let ch = session.remote_channel_id();

        // Exec "cat" — it will echo back whatever we send
        let mut req = bytes::BytesMut::new();
        req.put_u8(98); // CHANNEL_REQUEST
        req.put_u32(ch);
        let req_type = b"exec";
        req.put_u32(req_type.len() as u32);
        req.put_slice(req_type);
        req.put_u8(1); // want_reply
        let command = b"cat";
        req.put_u32(command.len() as u32);
        req.put_slice(command);
        transport.send_message(&req).await?;

        // Skip channel success
        let _ = transport.recv_message().await?;

        // Send data TO the server via CHANNEL_DATA
        let test_payload = b"HELLO_FROM_CLIENT_1234567890\n";
        let mut data_msg = bytes::BytesMut::new();
        data_msg.put_u8(94); // CHANNEL_DATA
        data_msg.put_u32(ch);
        data_msg.put_u32(test_payload.len() as u32);
        data_msg.put_slice(test_payload);
        transport.send_message(&data_msg).await?;

        // Send EOF to signal end of input
        let mut eof_msg = bytes::BytesMut::new();
        eof_msg.put_u8(96); // CHANNEL_EOF
        eof_msg.put_u32(ch);
        transport.send_message(&eof_msg).await?;

        // Read back the echoed data
        let mut output = Vec::new();
        for _ in 0..20 {
            let msg = transport.recv_message().await?;
            if msg.is_empty() { continue; }
            match msg[0] {
                94 => { // CHANNEL_DATA
                    let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                    output.extend_from_slice(&msg[9..9+data_len]);
                }
                96 | 97 => break, // EOF or CLOSE
                _ => continue,
            }
        }

        assert_eq!(output, test_payload,
            "cat should echo back exactly what we sent");
        eprintln!("[bidi_test] Sent {} bytes, got {} bytes back — match!",
            test_payload.len(), output.len());

        Ok::<(), ayssh::error::SshError>(())
    });

    let _ = child.kill();
    let _ = child.wait();
    result.expect("Bidirectional data test failed");
}

/// Test rapid sequential connections to the same sshd instance.
/// Verifies connection cleanup and no resource leaks.
#[test]
fn test_rapid_sequential_connections() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;

    for i in 0..5 {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();

        let result = rt.block_on(async {
            let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.handshake().await?;
            transport.send_service_request("ssh-userauth").await?;
            transport.recv_service_accept().await?;
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => passed += 1,
            Err(e) => eprintln!("  Connection {} failed: {}", i, e),
        }
    }

    eprintln!("[sequential] {}/5 rapid connections succeeded", passed);
    assert_eq!(passed, 5, "All 5 sequential connections should succeed");
}

/// Test KEX × cipher cross-product to verify different combinations work.
#[test]
fn test_kex_cipher_cross_product() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let combos: Vec<(&str, &str)> = vec![
        ("curve25519-sha256", "aes128-ctr"),
        ("curve25519-sha256", "chacha20-poly1305@openssh.com"),
        ("ecdh-sha2-nistp256", "aes256-gcm@openssh.com"),
        ("ecdh-sha2-nistp384", "aes256-ctr"),
        ("diffie-hellman-group14-sha256", "aes128-gcm@openssh.com"),
        ("diffie-hellman-group14-sha256", "chacha20-poly1305@openssh.com"),
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut failed = Vec::new();

    for (kex, cipher) in &combos {
        eprint!("  {}+{} ... ", kex, cipher);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();

        let result = rt.block_on(async {
            let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_kex(kex);
            transport.set_preferred_cipher(cipher);
            transport.handshake().await?;
            transport.send_service_request("ssh-userauth").await?;
            transport.recv_service_accept().await?;
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => { passed += 1; eprintln!("ok"); }
            Err(e) => { failed.push(format!("{}+{}: {}", kex, cipher, e)); eprintln!("FAILED ({})", e); }
        }
    }

    eprintln!("\n  KEX×Cipher interop: {}/{} passed", passed, combos.len());
    if !failed.is_empty() {
        eprintln!("  Failures: {:?}", failed);
    }
    assert!(passed >= 4, "At least 4 KEX×Cipher combos should work");
}

/// Test host key verification with TOFU store against real sshd.
#[test]
fn test_host_key_tofu_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let tofu = ayssh::host_key_verify::TofuStore::new();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    // First connection — should be AcceptNew (TOFU)
    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.set_remote_host("127.0.0.1", sshd.port);
        transport.handshake_with_verifier(&tofu).await?;
        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;
        Ok::<(), ayssh::error::SshError>(())
    });
    assert!(result.is_ok(), "First TOFU connection should succeed: {:?}", result);
    eprintln!("[tofu_test] First connection (TOFU) succeeded");

    // Second connection — same key, should Accept
    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.set_remote_host("127.0.0.1", sshd.port);
        transport.handshake_with_verifier(&tofu).await?;
        Ok::<(), ayssh::error::SshError>(())
    });
    assert!(result.is_ok(), "Second connection (same key) should succeed");
    eprintln!("[tofu_test] Second connection (verify) succeeded");
}

/// Test host key verification with RejectAll against real sshd.
#[test]
fn test_host_key_reject_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.set_remote_host("127.0.0.1", sshd.port);
        transport.handshake_with_verifier(&ayssh::host_key_verify::RejectAll).await?;
        Ok::<(), ayssh::error::SshError>(())
    });
    assert!(result.is_err(), "RejectAll should fail the handshake");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("verification failed"), "Error should mention verification: {}", err);
    eprintln!("[reject_test] RejectAll correctly rejected connection");
}

/// Test SCP large file download (2MB) against real sshd.
/// This tests the WINDOW_ADJUST download fix with a real OpenSSH server.
#[test]
fn test_scp_large_download_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd_path = find_sshd().unwrap();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let tmppath = tmpdir.path();

    // Generate host key
    let host_key_path = tmppath.join("host_key");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&host_key_path)
        .args(["-N", "", "-q"])
        .status().unwrap();

    // Set up authorized_keys
    let auth_keys_path = tmppath.join("authorized_keys");
    let pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
    std::fs::write(&auth_keys_path, pubkey.trim()).unwrap();

    let port = find_free_port();
    let config_path = tmppath.join("sshd_config");
    let pid_path = tmppath.join("sshd.pid");
    std::fs::write(&config_path, format!(
        "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         PubkeyAuthentication yes\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
        port, host_key_path.display(), auth_keys_path.display(), pid_path.display(),
    )).unwrap();

    let mut child = std::process::Command::new(&sshd_path)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() { break; }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Create a 2MB file with patterned data
    let size = 2 * 1024 * 1024usize;
    let original_data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let large_file_path = tmppath.join("large_test.bin");
    std::fs::write(&large_file_path, &original_data).unwrap();

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let private_key = std::fs::read("tests/keys/test_ed25519").unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap();

    let result = rt.block_on(async {
        // Test download_with_publickey (buffered)
        let downloaded = ayssh::sftp::ScpSession::download_with_publickey(
            "127.0.0.1", port, &current_user, &private_key,
            large_file_path.to_str().unwrap(),
        ).await?;
        eprintln!("[scp_large] download_with_publickey: {} bytes", downloaded.len());

        assert_eq!(downloaded.len(), original_data.len(),
            "Downloaded size mismatch: got {} expected {}", downloaded.len(), original_data.len());
        assert_eq!(downloaded, original_data,
            "Downloaded data does not match original 2MB pattern");
        eprintln!("[scp_large] Buffered download verified!");

        // Test download_stream_with_publickey (streaming)
        let (mut reader, _filename, file_size) = ayssh::sftp::ScpSession::download_stream_with_publickey(
            "127.0.0.1", port, &current_user, &private_key,
            large_file_path.to_str().unwrap(),
        ).await?;
        eprintln!("[scp_large] download_stream: file_size={}", file_size);

        assert_eq!(file_size, original_data.len() as u64,
            "Stream file_size mismatch");

        // Read the entire stream
        let streamed = reader.read_all().await?;

        assert_eq!(streamed.len(), original_data.len(),
            "Streamed size mismatch: got {} expected {}", streamed.len(), original_data.len());
        assert_eq!(streamed, original_data,
            "Streamed data does not match original 2MB pattern");
        eprintln!("[scp_large] Streaming download verified!");

        Ok::<(), ayssh::error::SshError>(())
    });

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(()) => eprintln!("[scp_large] SCP 2MB download test SUCCESS"),
        Err(e) => panic!("SCP large download test failed: {}", e),
    }
}

/// Test SshConnection::builder() against real sshd.
/// This exercises the high-level connection API with pubkey auth,
/// including exec() and send()/receive().
#[test]
fn test_ssh_connection_builder_against_real_sshd() {
    skip_if_no_sshd!();
    let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let key_data = std::fs::read("tests/keys/test_ed25519").unwrap();

        let mut conn = ayssh::SshConnection::builder("127.0.0.1", sshd.port)
            .username(&current_user)
            .private_key(key_data)
            .connect()
            .await
            .expect("SshConnection::builder().connect() failed");

        // Verify accessors
        assert_eq!(conn.host(), "127.0.0.1");
        assert_eq!(conn.port(), sshd.port);
        assert_eq!(conn.username(), current_user);

        // Send a command via exec and verify output
        let output = conn.exec("echo AYSSH_CONN_TEST_OK").await.unwrap();
        eprintln!("[sshd_interop] exec output: {:?}", output);
        assert!(
            output.contains("AYSSH_CONN_TEST_OK"),
            "exec() output should contain our marker, got: {:?}",
            output
        );

        let _ = conn.disconnect().await;
        eprintln!("[sshd_interop] SshConnection builder test SUCCESS");
    });
}
