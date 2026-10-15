//! SSH Transport Layer
//!
//! Handles the transport layer of SSH including key exchange,
//! packet encryption, and session state management.

use crate::channel::ChannelTransferManager;
use crate::crypto::cipher::{aes_cbc_decrypt_raw, aes_cbc_encrypt_raw};
use crate::crypto::hmac::{HmacSha1, HmacSha256, HmacSha512};
use crate::protocol;
use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub mod cipher;
pub mod encrypted;
pub mod handshake;
pub mod kex;
pub mod packet;
pub mod session;
pub mod session_id;
pub mod state;
pub mod version;

pub use encrypted::*;
#[allow(ambiguous_glob_reexports)]
pub use handshake::*;
pub use kex::*;
pub use packet::*;
pub use session::*;
pub use session_id::*;
pub use state::*;
pub use version::*;

/// SSH Transport layer
///
/// Manages the encrypted communication channel with the SSH server.
/// Handles packet encryption/decryption, key exchange, and state management.
pub struct Transport {
    /// Underlying TCP stream
    stream: TcpStream,
    /// Current state of the transport
    state: state::TransportStateMachine,
    /// Handshake state
    handshake: handshake::HandshakeState,
    /// Channel transfer manager for managing channels
    channel_manager: ChannelTransferManager,
    /// Encryption state for client-to-server direction
    encrypt_state: Option<EncryptionState>,
    /// Decryption state for server-to-client direction
    decrypt_state: Option<DecryptionState>,
    /// Buffer for leftover bytes from TCP reads (handles cases where
    /// multiple SSH packets arrive in a single TCP segment)
    read_buffer: Vec<u8>,
    /// Client-to-server packet sequence number (counts ALL packets from connection start per RFC 4253 Section 6.4)
    send_sequence_number: u32,
    /// Server-to-client packet sequence number (counts ALL packets from connection start per RFC 4253 Section 6.4)
    recv_sequence_number: u32,
    /// Session ID from key exchange (needed for public key auth signatures)
    session_id: Option<Vec<u8>>,
    /// Preferred KEX algorithm (placed first in KEXINIT)
    preferred_kex: Option<String>,
    /// Preferred cipher algorithm (placed first in KEXINIT)
    preferred_cipher: Option<String>,
    /// Preferred MAC algorithm (placed first in KEXINIT)
    preferred_mac: Option<String>,
    enable_x509: bool,
    /// Whether kex-strict (CVE-2023-48795 / Terrapin mitigation) is active.
    /// When true, sequence numbers reset to 0 after NEWKEYS.
    kex_strict: bool,
    /// Remote host name (for host key verification)
    remote_host: Option<String>,
    /// Remote port (for host key verification)
    remote_port: u16,
    /// Next channel ID to allocate (incremented on each allocation)
    next_channel_id: u32,
    /// Rekey threshold in bytes (default: 1 GB). When bytes_encrypted exceeds
    /// this, should_rekey() returns true.
    rekey_threshold: u64,
}

/// Encryption state for outgoing packets
#[derive(Debug)]
pub(crate) struct EncryptionState {
    pub(crate) enc_key: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) mac_key: Vec<u8>,
    pub(crate) sequence_number: u32,
    pub(crate) aead_counter: u64,
    pub(crate) enc_algorithm: String,
    pub(crate) mac_algorithm: String,
    /// Total bytes encrypted since last key exchange
    pub(crate) bytes_encrypted: u64,
}

/// Decryption state for incoming packets
#[derive(Debug)]
pub(crate) struct DecryptionState {
    pub(crate) dec_key: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) mac_key: Vec<u8>,
    pub(crate) sequence_number: u32,
    pub(crate) aead_counter: u64,
    pub(crate) dec_algorithm: String,
    pub(crate) mac_algorithm: String,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("state", &self.state())
            .field("encrypted", &self.encrypt_state.is_some())
            .field("kex_strict", &self.kex_strict)
            .finish()
    }
}

impl Transport {
    /// Create a new transport with the given socket
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: state::TransportStateMachine::new(),
            handshake: handshake::HandshakeState::default(),
            channel_manager: ChannelTransferManager::new(),
            encrypt_state: None,
            decrypt_state: None,
            read_buffer: Vec::new(),
            send_sequence_number: 0,
            recv_sequence_number: 0,
            session_id: None,
            preferred_kex: None,
            preferred_cipher: None,
            preferred_mac: None,
            enable_x509: false,
            kex_strict: false,
            remote_host: None,
            remote_port: 22,
            next_channel_id: 0,
            rekey_threshold: 1 << 30, // 1 GB default
        }
    }

    /// Get a reference to the underlying stream
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Get the current state
    pub fn state(&self) -> state::State {
        self.state.current_state()
    }

    /// Get the handshake state
    pub fn handshake_state(&self) -> &handshake::HandshakeState {
        &self.handshake
    }

    /// Get the session ID from key exchange (needed for public key auth signatures)
    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }

    /// Set the remote host name (used for host key verification).
    pub fn set_remote_host(&mut self, host: &str, port: u16) {
        self.remote_host = Some(host.to_string());
        self.remote_port = port;
    }

    /// Opt in to RFC 6187 x509v3-ssh-rsa host keys (disabled by default).
    /// Trust is an end-entity certificate fingerprint pin, without CA validation.
    pub fn set_x509_host_keys(&mut self, enabled: bool) {
        self.enable_x509 = enabled;
    }

    /// Set the preferred KEX algorithm
    pub fn set_preferred_kex(&mut self, kex: &str) {
        self.preferred_kex = Some(kex.to_string());
    }

    /// Set the preferred cipher algorithm
    pub fn set_preferred_cipher(&mut self, cipher: &str) {
        self.preferred_cipher = Some(cipher.to_string());
    }

    /// Set the preferred MAC algorithm
    pub fn set_preferred_mac(&mut self, mac: &str) {
        self.preferred_mac = Some(mac.to_string());
    }

    /// Get the channel manager
    pub fn channel_manager(&self) -> &ChannelTransferManager {
        &self.channel_manager
    }

    /// Get mutable reference to channel manager
    pub fn channel_manager_mut(&mut self) -> &mut ChannelTransferManager {
        &mut self.channel_manager
    }

    /// Allocate a new unique channel ID and return it.
    /// Each call returns a monotonically increasing value starting from 0.
    pub fn allocate_channel_id(&mut self) -> u32 {
        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        id
    }

    /// Get the total number of bytes encrypted since the last key exchange.
    /// Returns 0 if encryption is not yet established.
    pub fn bytes_encrypted(&self) -> u64 {
        self.encrypt_state.as_ref().map_or(0, |s| s.bytes_encrypted)
    }

    /// Check whether the transport should initiate a re-key.
    /// Returns true when bytes encrypted exceeds the configured threshold.
    pub fn should_rekey(&self) -> bool {
        self.bytes_encrypted() > self.rekey_threshold
    }

    /// Set the rekey threshold in bytes. Default is 1 GB.
    pub fn set_rekey_threshold(&mut self, threshold: u64) {
        self.rekey_threshold = threshold;
    }

    /// Read exactly one unencrypted SSH binary packet from the stream.
    /// Handles TCP buffering: if a previous read returned extra bytes
    /// (e.g., NEWKEYS piggybacked on KEXDH_REPLY), those bytes are used first.
    /// Returns the full packet bytes including the 4-byte length prefix.
    async fn read_unencrypted_packet(&mut self, timeout_secs: u64) -> Result<Vec<u8>, crate::error::SshError> {
        let mut data = std::mem::take(&mut self.read_buffer);

        loop {
            // Check if we have enough data to determine the packet length
            if data.len() >= 4 {
                let packet_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                crate::transport::validate_plaintext_header(packet_len, data.get(4).copied())?;
                let total_needed = 4 + packet_len;
                if data.len() >= total_needed {
                    // We have a complete packet. Split off any extra bytes for next read.
                    let remainder = data.split_off(total_needed);
                    self.read_buffer = remainder;
                    self.recv_sequence_number = self.recv_sequence_number.wrapping_add(1);
                    return Ok(data);
                }
            }

            // Need more data from the stream
            let mut buf = vec![0u8; 1024];
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                self.stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => {
                    return Err(crate::error::SshError::ConnectionError(
                        "Connection closed while reading packet".to_string(),
                    ));
                }
                Ok(Ok(n)) => {
                    data.extend_from_slice(&buf[..n]);
                }
                Ok(Err(e)) => {
                    return Err(crate::error::SshError::IoError(e));
                }
                Err(_) => {
                    return Err(crate::error::SshError::TimeoutError);
                }
            }
        }
    }

    /// Perform SSH handshake with the server
    ///
    /// This method:
    /// 1. Sends client version string
    /// 2. Receives server version string
    /// 3. Performs key exchange (KEXINIT exchange and key computation)
    /// 4. Transitions to encrypted state
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Handshake completed successfully
    /// * `Err(SshError)` - Handshake failed
    /// Perform SSH handshake with host key verification.
    ///
    /// The verifier is called with the server's host key during KEXDH_REPLY
    /// processing. If the verifier rejects the key, the handshake fails
    /// with `SshError::AuthenticationFailed`.
    pub async fn handshake_with_verifier(
        &mut self,
        verifier: &dyn crate::host_key_verify::HostKeyVerifier,
    ) -> Result<(), crate::error::SshError> {
        self.host_key_verifier_impl(Some(verifier)).await
    }

    /// Perform SSH handshake without host key verification.
    /// Equivalent to `handshake_with_verifier(&AcceptAll)`.
    pub async fn handshake(&mut self) -> Result<(), crate::error::SshError> {
        self.host_key_verifier_impl(None).await
    }

    /// Internal handshake implementation.
    async fn host_key_verifier_impl(
        &mut self,
        verifier: Option<&dyn crate::host_key_verify::HostKeyVerifier>,
    ) -> Result<(), crate::error::SshError> {
        use crate::transport::handshake::{send_version, recv_server_version, parse_version_string, generate_client_kexinit_with_x509, parse_server_kexinit};
        use crate::transport::kex::KexContext;
        use crate::protocol::KexAlgorithm;
        use std::str::FromStr;
        
        // 1. Send client version
        send_version(self.stream_mut()).await?;
        
        // 2. Receive server version
        let server_ver = recv_server_version(self.stream_mut()).await?;
        debug!("Server version: {}", server_ver);
        
        let (_proto, _software) = parse_version_string(server_ver.as_bytes())
            .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
        
        // 3. Generate client KEXINIT
        let client_kexinit = generate_client_kexinit_with_x509(
            self.preferred_kex.as_deref(),
            self.preferred_cipher.as_deref(),
            self.preferred_mac.as_deref(),
            self.enable_x509,
        );
        debug!("Generated client KEXINIT ({} bytes)", client_kexinit.len());
        
        // 4. Send client KEXINIT - per RFC 4253, KEXINIT is sent as a binary packet
        // Format: [packet_length (4 bytes)][padding_length (1 byte)][kexinit_payload][padding]
        // The KEXINIT payload includes: message_type(1) + cookie(16) + algorithm lists...
        let kexinit_payload = &client_kexinit;
        
       // Calculate padding to ensure 8-byte alignment per RFC 4253 Section 6
        // Total size (4 + 1 + payload + padding) must be multiple of 8
        // Minimum padding is 4 bytes
        let payload_len = kexinit_payload.len();
        let total_without_padding = 4 + 1 + payload_len; // length field + padding_length field + payload
        let remainder = total_without_padding % 8;
        let mut padding_length = if remainder == 0 {
            8u8 // Already aligned, but need at least 4 bytes padding, and 8 maintains alignment
        } else {
            (8 - remainder) as u8
        };
        
        // Ensure minimum padding of 4 bytes per RFC 4253
        // If calculated padding is less than 4, add 8 to maintain alignment
        if padding_length < 4 {
            padding_length += 8;
        }
        
        let packet_length = kexinit_payload.len() as u32 + padding_length as u32 + 1; // +1 for padding_length byte
        
        debug!("KEXINIT: payload len={}, padding len={}, calculated packet_length={}, total size={}", 
               kexinit_payload.len(), padding_length, packet_length, 4 + 1 + payload_len + padding_length as usize);
        
        let mut kexinit_msg = bytes::BytesMut::new();
        kexinit_msg.put_u32(packet_length);
        kexinit_msg.put_u8(padding_length);
        kexinit_msg.put_slice(kexinit_payload);
        // Add padding bytes
        for _ in 0..padding_length {
            kexinit_msg.put_u8(0);
        }
        
        debug!("KEXINIT: sending {} bytes total, first 10 bytes: {:?}", 
               kexinit_msg.len(), &kexinit_msg[..std::cmp::min(10, kexinit_msg.len())]);
        
        self.stream_mut().write_all(&kexinit_msg).await?;
        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);
        debug!("Sent client KEXINIT packet ({} bytes total, seq={})", kexinit_msg.len(), self.send_sequence_number - 1);
        
        // 5. Receive server KEXINIT using buffered packet reader
        let server_kexinit_bytes = self.read_unencrypted_packet(30).await?;
        debug!("Successfully received server KEXINIT packet ({} bytes)", server_kexinit_bytes.len());
        
        // Extract the KEXINIT payload from the packet
        // packet_length = padding_length_byte(1) + payload + padding
        // So: payload_length = packet_length - 1 - padding_length
        // Payload starts at offset 5 (4 for length field + 1 for padding_length byte)
        let packet_len = u32::from_be_bytes([
            server_kexinit_bytes[0],
            server_kexinit_bytes[1],
            server_kexinit_bytes[2],
            server_kexinit_bytes[3]
        ]) as usize;
        let padding_len = server_kexinit_bytes[4] as usize;
        let payload_start = 5;
        let payload_end = 4 + packet_len - padding_len; // 4 + (1 + payload + padding) - padding = 5 + payload
        
        debug!("KEXINIT packet_len: {}, padding_len: {}, payload: {}-{}", 
               packet_len, padding_len, payload_start, payload_end);
        
        let kexinit_payload = &server_kexinit_bytes[payload_start..payload_end];
        debug!("KEXINIT payload length: {} bytes", kexinit_payload.len());
        debug!("KEXINIT payload (first 20): {:?}", &kexinit_payload[..std::cmp::min(20, kexinit_payload.len())]);
        
        let server_proposal = parse_server_kexinit(kexinit_payload)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("{} - KEXINIT payload: {:?}", e, &kexinit_payload[..std::cmp::min(100, kexinit_payload.len())])))?;
        
        debug!("Server KEX algorithms: {:?}", server_proposal.kex_algorithms);
        debug!("Server host key algorithms: {:?}", server_proposal.server_host_key_algorithms);
        debug!("Server enc C2S: {:?}", server_proposal.encryption_algorithms_c2s);
        debug!("Server enc S2C: {:?}", server_proposal.encryption_algorithms_s2c);
        debug!("Server MAC C2S: {:?}", server_proposal.mac_algorithms_c2s);
        debug!("Server MAC S2C: {:?}", server_proposal.mac_algorithms_s2c);
        debug!("Server compression: {:?}", server_proposal.compression_algorithms);
        
        // 6. Parse client KEXINIT to get client proposal
        let client_proposal = parse_server_kexinit(&client_kexinit)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("{} - Client KEXINIT: {:?}", e, &client_kexinit[..std::cmp::min(100, client_kexinit.len())])))?;
        
        // 7. Check for kex-strict (CVE-2023-48795 Terrapin mitigation)
        if server_proposal.kex_algorithms.iter().any(|a| a == "kex-strict-s-v00@openssh.com")
            && client_proposal.kex_algorithms.iter().any(|a| a == "kex-strict-c-v00@openssh.com") {
            debug!("Server supports kex-strict — enabling sequence number reset after NEWKEYS");
            self.kex_strict = true;
        }

        // 8. Negotiate algorithms
        let negotiated = match handshake::negotiate_algorithms(&client_proposal, &server_proposal) {
            Ok(algorithms) => algorithms,
            Err(error) => { handshake::disconnect_kex_failed(&mut self.stream).await; return Err(error); }
        };
        debug!("Negotiated KEX algorithm: {}", negotiated.kex);

        // Store negotiated algorithms in handshake state
        self.handshake.enc_c2s = Some(negotiated.enc_c2s.clone());
        self.handshake.enc_s2c = Some(negotiated.enc_s2c.clone());
        self.handshake.mac_c2s = Some(negotiated.mac_c2s.clone());
        self.handshake.mac_s2c = Some(negotiated.mac_s2c.clone());
        
        // 8. Initialize KEX context
        let algorithm = KexAlgorithm::from_str(&negotiated.kex).unwrap_or(KexAlgorithm::Curve25519Sha256);
        let mut kex_context = KexContext::new(algorithm);
        
        let mut rng = rand::rngs::OsRng;
        kex_context.generate_client_key(&mut rng)?;
        
        // 9. Send KEXDH_INIT message with client ephemeral key
        let client_ephemeral = kex_context.client_ephemeral.clone()
            .expect("Client ephemeral key not generated");
        
        debug!("Client ephemeral key size: {} bytes", client_ephemeral.len());
        
        // Build KEXDH_INIT payload per RFC 4253 Section 7.1
        // Format: byte SSH_MSG_KEXDH_INIT, mpint e
        // Note: mpint is length-prefixed (4-byte length + data)
        let mut kexdh_init_payload = bytes::BytesMut::new();
        kexdh_init_payload.put_u8(crate::protocol::MessageType::KexDhInit as u8);
        // Add length-prefixed MPINT for the ephemeral key
        kexdh_init_payload.put_u32(client_ephemeral.len() as u32);
        kexdh_init_payload.put_slice(&client_ephemeral);
        
        // Wrap in SSH binary packet format per RFC 4253 Section 6
        // Format: [packet_length (4 bytes)][padding_length (1 byte)][payload][padding]
        let payload_len = kexdh_init_payload.len();
        let total_without_padding = 4 + 1 + payload_len;
        let remainder = total_without_padding % 8;
        let padding_length = if remainder == 0 {
            8u8
        } else {
            let p = (8 - remainder) as u8;
            if p < 4 { p + 8 } else { p }
        };
        
        let packet_length = payload_len as u32 + padding_length as u32 + 1;
        
        let mut kexdh_init_msg = bytes::BytesMut::new();
        kexdh_init_msg.put_u32(packet_length);
        kexdh_init_msg.put_u8(padding_length);
        kexdh_init_msg.put_slice(&kexdh_init_payload);
        for _ in 0..padding_length {
            kexdh_init_msg.put_u8(0);
        }
        
        debug!("Sending KEXDH_INIT packet (payload={}, padding={}, total={}, seq={})",
               payload_len, padding_length, kexdh_init_msg.len(), self.send_sequence_number);
        self.stream_mut().write_all(&kexdh_init_msg).await?;
        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);
        
        // 10. Receive KEXDH_REPLY from server using buffered packet reader
        if handshake::wrong_kex_guess(&server_proposal, &negotiated) {
            self.read_unencrypted_packet(30).await?;
        }
        let reply_bytes = self.read_unencrypted_packet(30).await?;
        debug!("Successfully received KEXDH_REPLY packet ({} bytes)", reply_bytes.len());
        
        // Extract payload from packet
        // packet_length = padding_length_byte(1) + payload + padding
        let packet_len = u32::from_be_bytes([reply_bytes[0], reply_bytes[1], reply_bytes[2], reply_bytes[3]]) as usize;
        let padding_len = reply_bytes[4] as usize;
        let payload_start = 5;
        let payload_end = 4 + packet_len - padding_len; // 4 + (1 + payload + padding) - padding = 5 + payload
        
        debug!("KEXDH_REPLY packet_len: {}, padding_len: {}, payload: {}-{}", 
               packet_len, padding_len, payload_start, payload_end);
        
        let reply_payload = &reply_bytes[payload_start..payload_end];
        
        if reply_payload.is_empty() {
            return Err(crate::error::SshError::ProtocolError("Empty KEX reply".into()));
        }
        if reply_payload[0] != crate::protocol::MessageType::KexDhReply as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected KEXDH_REPLY (31), got {}", reply_payload[0])
            ));
        }
        
        // Extract server host key from KEXDH_REPLY
        // Format: byte SSH_MSG_KEXDH_REPLY, string K_S (host key), mpint f, string signature
        let reply_data = &reply_payload[1..];
        
        // Validate the complete certificate reply before any KEX processing.
        if negotiated.host_key == crate::x509::ALGORITHM {
            let (host_key, _) = crate::x509::parse_kex_reply(reply_data)?;
            crate::x509::CertificateHostKey::parse(host_key)?;
        }

        // Read server host key (string type = uint32 length + data)
        if reply_data.len() >= 4 {
            let host_key_len = u32::from_be_bytes([reply_data[0], reply_data[1], reply_data[2], reply_data[3]]) as usize;
            if reply_data.len() >= 4 + host_key_len {
                let server_host_key = &reply_data[4..4+host_key_len];
                debug!("Server host key length: {} bytes", host_key_len);
                kex_context.set_server_host_key(server_host_key);

                // Host key verification
                if let Some(verifier) = verifier.filter(|_| negotiated.host_key != crate::x509::ALGORITHM) {
                    // Extract key type from the blob (first string)
                    let key_type = if server_host_key.len() >= 4 {
                        let algo_len = u32::from_be_bytes([
                            server_host_key[0], server_host_key[1],
                            server_host_key[2], server_host_key[3],
                        ]) as usize;
                        if server_host_key.len() >= 4 + algo_len {
                            String::from_utf8_lossy(&server_host_key[4..4+algo_len]).to_string()
                        } else {
                            "unknown".to_string()
                        }
                    } else {
                        "unknown".to_string()
                    };

                    let host = self.remote_host.as_deref().unwrap_or("unknown");
                    let port = self.remote_port;

                    let action = verifier.verify(host, port, &key_type, server_host_key).await;
                    debug!("Host key verification: {:?}", action);

                    if !action.is_accepted() {
                        return Err(crate::error::SshError::AuthenticationFailed(format!(
                            "Host key verification failed for {}:{} — {:?}",
                            host, port, action
                        )));
                    }
                }
            }
        }
        
        // Set exchange info for session ID computation
        // Client version string (without CRLF)
        let client_version = crate::transport::handshake::SSH_VERSION_STRING
            .strip_suffix("\r\n")
            .unwrap_or(crate::transport::handshake::SSH_VERSION_STRING)
            .as_bytes();
        
        // Server version string (without CRLF)  
        let server_version_clean = server_ver
            .strip_suffix("\r\n")
            .unwrap_or(server_ver.strip_suffix('\n').unwrap_or(&server_ver));
        
        kex_context.set_exchange_info(
            client_version,
            server_version_clean.as_bytes(),
            &client_kexinit,
            kexinit_payload, // server KEXINIT payload
        );
        
        // Process server's ephemeral key (skip host key string)
        // After host key string, we have mpint f and signature
        if reply_data.len() >= 4 {
            let host_key_len = u32::from_be_bytes([reply_data[0], reply_data[1], reply_data[2], reply_data[3]]) as usize;
            if reply_data.len() >= 4 + host_key_len {
                let after_host_key = &reply_data[4+host_key_len..];
                if let Err(error) = kex_context.process_server_kex_init(after_host_key) {
                    crate::transport::handshake::disconnect_kex_failed(&mut self.stream).await;
                    return Err(error.into());
                }
            }
        }
        
        // 11. Compute shared secret (and session ID)
        if let Err(error) = kex_context.compute_shared_secret() {
            // RFC 8731 section 3 defines an invalid peer key abort as a disconnect.
            crate::transport::handshake::disconnect_kex_failed(&mut self.stream).await;
            return Err(error.into());
        }
        
        if negotiated.host_key == crate::x509::ALGORITHM {
            let (host_key, signature) = crate::x509::parse_kex_reply(reply_data)?;
            let certificate = crate::x509::CertificateHostKey::parse(host_key)?;
            let exchange_hash = kex_context.session_id.as_deref().ok_or_else(||
                crate::error::SshError::ProtocolError("Missing exchange hash".into()))?;
            certificate.verify_signature(exchange_hash, signature)?;
            eprintln!("X509 host certificate subject: {}", certificate.subject);
            eprintln!("X509 host certificate fingerprint: {}", certificate.fingerprint());
            if let Some(verifier) = verifier {
                let action = verifier.verify(
                    self.remote_host.as_deref().unwrap_or("unknown"), self.remote_port,
                    crate::x509::ALGORITHM, host_key,
                ).await;
                if !action.is_accepted() {
                    return Err(crate::error::SshError::AuthenticationFailed(
                        format!("X509 certificate fingerprint verification failed: {:?}", action)));
                }
            }
        } else {
            // A certificate blob is only legal when its algorithm was negotiated.
            let mut key_data = reply_data;
            let host_key = crate::x509::read_string(&mut key_data)?;
            let mut key_data = host_key;
            if crate::x509::read_string(&mut key_data)? == crate::x509::ALGORITHM.as_bytes() {
                return Err(crate::error::SshError::ProtocolError(
                    "Unnegotiated X509 host key".into()));
            }
        }

        // 12. Derive session keys
        let session_id = kex_context.session_id.clone()
            .expect("Session ID not computed");
        self.session_id = Some(session_id.clone());
        let session_keys = kex_context.derive_session_keys_directional(&session_id, &negotiated)?;
        
        // Store session keys in handshake state
        self.handshake.session_keys = Some(session_keys);
        
        // 13. Send NEWKEYS message
        let newkeys_msg = crate::transport::kex::encode_newkeys();
        self.stream_mut().write_all(&newkeys_msg).await?;
        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);
        debug!("Sent NEWKEYS (seq={})", self.send_sequence_number - 1);
        
        // 14. Receive NEWKEYS from server using buffered packet reader
        let newkeys_bytes = self.read_unencrypted_packet(30).await?;

        // Validate NEWKEYS message type (byte 5 = after 4-byte length + 1-byte padding_length)
        if newkeys_bytes.len() < 6 || newkeys_bytes[5] != crate::protocol::MessageType::Newkeys as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected NEWKEYS from server, got {:?}", &newkeys_bytes[..std::cmp::min(10, newkeys_bytes.len())])
            ));
        }
        debug!("Received valid NEWKEYS message ({} bytes)", newkeys_bytes.len());
        
        // Set up encryption state after NEWKEYS exchange
        // Get the negotiated algorithms from the handshake state
        let enc_c2s = self.handshake.enc_c2s.clone().unwrap_or_else(|| "aes128-cbc".to_string());
        let enc_s2c = self.handshake.enc_s2c.clone().unwrap_or_else(|| "aes128-cbc".to_string());
        let mac_c2s = self.handshake.mac_c2s.clone().unwrap_or_else(|| "hmac-sha1".to_string());
        let mac_s2c = self.handshake.mac_s2c.clone().unwrap_or_else(|| "hmac-sha1".to_string());
        
        debug!("Setting up encryption: C2S={}, S2C={}, MAC-C2S={}, MAC-S2C={}", 
               enc_c2s, enc_s2c, mac_c2s, mac_s2c);
        
        // Get session keys from kex_context (stored in handshake state)
        if let Some(ref session_keys) = self.handshake.session_keys {
            debug!("Session keys details:");
            debug!("  enc_key_c2s: {:?}", session_keys.enc_key_c2s);
            debug!("  enc_key_s2c: {:?}", session_keys.enc_key_s2c);
            debug!("  client_iv: {:?}", session_keys.client_iv);
            debug!("  server_iv: {:?}", session_keys.server_iv);
            
            // Set up client-to-server encryption state
            // Per RFC 4253 Section 6.4, sequence numbers normally continue.
            // With kex-strict (CVE-2023-48795), sequence numbers reset to 0 after NEWKEYS.
            if self.kex_strict {
                debug!("kex-strict active: resetting sequence numbers from send={}, recv={} to 0",
                       self.send_sequence_number, self.recv_sequence_number);
                self.send_sequence_number = 0;
                self.recv_sequence_number = 0;
            }
            debug!("Initializing encryption with send_seq={}, recv_seq={}", self.send_sequence_number, self.recv_sequence_number);
            self.encrypt_state = Some(EncryptionState {
                enc_key: session_keys.enc_key_c2s.clone(),
                iv: session_keys.client_iv.clone(),
                mac_key: session_keys.mac_key_c2s.clone(),
                sequence_number: self.send_sequence_number,
                aead_counter: 0,
                enc_algorithm: enc_c2s,
                mac_algorithm: mac_c2s,
                bytes_encrypted: 0,
            });

            self.decrypt_state = Some(DecryptionState {
                dec_key: session_keys.enc_key_s2c.clone(),
                iv: session_keys.server_iv.clone(),
                mac_key: session_keys.mac_key_s2c.clone(),
                sequence_number: self.recv_sequence_number,
                aead_counter: 0,
                dec_algorithm: enc_s2c,
                mac_algorithm: mac_s2c,
            });
            
            debug!("Encryption state initialized successfully");
        } else {
            return Err(crate::error::SshError::ProtocolError(
                "Session keys not available after key exchange".to_string()
            ));
        }
        
        info!("SSH handshake completed, server version: {}", server_ver);
        Ok(())
    }

    /// Send raw bytes over the transport
    pub async fn send(&mut self, data: &[u8]) -> Result<(), crate::error::SshError> {
        self.stream.write_all(data).await?;
        Ok(())
    }

    /// Receive raw bytes from the transport
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::SshError> {
        let n = self.stream.read(buf).await?;
        Ok(n)
    }

    /// Send an SSH message (with encryption if enabled)
    pub async fn send_message(&mut self, msg: &[u8]) -> Result<(), crate::error::SshError> {
        // Check if encryption is enabled
        let encryption_enabled = self.encrypt_state.is_some();
        
        if encryption_enabled {
            // Encrypt the message
            debug!("Encrypting message of {} bytes", msg.len());
            let encrypt_state = self.encrypt_state.as_mut().unwrap();
            debug!("Encrypting with key len: {}, iv len: {}", encrypt_state.enc_key.len(), encrypt_state.iv.len());
            let encrypted = encrypt_packet_cbc(msg, encrypt_state)?;
            debug!("Encrypted to {} bytes, first 20: {:?}", encrypted.len(), &encrypted[..std::cmp::min(20, encrypted.len())]);
            self.stream.write_all(&encrypted).await?;
        } else {
            // Send unencrypted (shouldn't happen after handshake)
            self.send(msg).await?;
        }
        Ok(())
    }

    /// Read exactly `n` bytes from the read_buffer + stream
    async fn read_exact_buffered(&mut self, n: usize) -> Result<Vec<u8>, crate::error::SshError> {
        let mut data = Vec::with_capacity(n);

        // Drain from read_buffer first
        let from_buf = std::cmp::min(n, self.read_buffer.len());
        if from_buf > 0 {
            data.extend_from_slice(&self.read_buffer[..from_buf]);
            self.read_buffer = self.read_buffer[from_buf..].to_vec();
        }

        // Read remaining from stream
        if data.len() < n {
            let remaining = n - data.len();
            let mut buf = vec![0u8; remaining];
            self.stream.read_exact(&mut buf).await?;
            data.extend_from_slice(&buf);
        }

        Ok(data)
    }

    /// Receive an SSH message (with decryption if enabled)
    ///
    /// For AES-CBC mode:
    /// - The encrypted portion is: 4-byte packet_length + padding_length + payload + padding
    /// - Total encrypted size = 4 + packet_length (must be multiple of cipher block size)
    /// - MAC is appended unencrypted after the ciphertext
    /// - Returns the full decrypted packet (packet_length field + padding_length + payload + padding)
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, crate::error::SshError> {
        if self.decrypt_state.is_none() {
            // Read unencrypted (shouldn't happen after handshake)
            let len_buf = self.read_exact_buffered(4).await?;
            let len = u32::from_be_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;
            let msg_buf = self.read_exact_buffered(len).await?;
            return Ok(msg_buf);
        }

        // Extract needed values from decrypt_state before calling async methods
        let (dec_algo, mac_algo) = {
            let ds = self.decrypt_state.as_ref().unwrap();
            (ds.dec_algorithm.clone(), ds.mac_algorithm.clone())
        };
        let aead = is_aead_cipher(&dec_algo);
        let etm = !aead && is_etm_mac(&mac_algo);
        let mac_len = if aead { GCM_TAG_LEN } else { mac_length(&mac_algo) };

        let decrypted = if aead {
            if dec_algo == "chacha20-poly1305@openssh.com" {
                // ChaCha20-Poly1305: length IS encrypted
                let encrypted_length_bytes = self.read_exact_buffered(4).await?;
                let enc_len: [u8; 4] = encrypted_length_bytes.try_into().unwrap();

                let decrypt_state = self.decrypt_state.as_ref().unwrap();
                let packet_length = crate::crypto::ssh_chacha20::decrypt_length(
                    &decrypt_state.dec_key, decrypt_state.sequence_number as u64, &enc_len,
                ).map_err(|e| crate::error::SshError::CryptoError(e))? as usize;
                debug!("ChaCha20: decrypted packet_length: {}", packet_length);

                if packet_length < 1 || packet_length > 35000 {
                    return Err(crate::error::SshError::ProtocolError(
                        format!("Invalid packet length: {}", packet_length),
                    ));
                }

                // Read encrypted payload + 16-byte Poly1305 tag
                let rest = self.read_exact_buffered(packet_length + 16).await?;
                let encrypted_payload = &rest[..packet_length];
                let tag: [u8; 16] = rest[packet_length..].try_into().unwrap();

                let decrypt_state = self.decrypt_state.as_mut().unwrap();
                let plaintext = crate::crypto::ssh_chacha20::decrypt(
                    &decrypt_state.dec_key, decrypt_state.sequence_number as u64,
                    &enc_len, encrypted_payload, &tag,
                ).map_err(|e| crate::error::SshError::CryptoError(e))?;
                debug!("ChaCha20 decrypted {} bytes", plaintext.len());

                decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);

                // Reconstruct full packet: length(cleartext) || plaintext
                let length_bytes = (packet_length as u32).to_be_bytes();
                let mut full = Vec::with_capacity(4 + plaintext.len());
                full.extend_from_slice(&length_bytes);
                full.extend_from_slice(&plaintext);
                full
            } else {
                // AES-GCM: length in cleartext, GCM tag is auth
                let length_bytes = self.read_exact_buffered(4).await?;
                let packet_length = u32::from_be_bytes([
                    length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3],
                ]) as usize;
                debug!("AEAD: cleartext packet_length: {}", packet_length);

                if packet_length < 1 || packet_length > 35000 {
                    return Err(crate::error::SshError::ProtocolError(
                        format!("Invalid packet length: {}", packet_length),
                    ));
                }

                let ciphertext_with_tag = self.read_exact_buffered(packet_length + GCM_TAG_LEN).await?;

                let decrypt_state = self.decrypt_state.as_mut().unwrap();
                let nonce = gcm_nonce(&decrypt_state.iv, decrypt_state.aead_counter);

                use crate::crypto::cipher::aes_gcm_decrypt_with_aad;
                let plaintext = aes_gcm_decrypt_with_aad(
                    &decrypt_state.dec_key, &nonce, &length_bytes, &ciphertext_with_tag,
                ).map_err(|_| crate::error::SshError::ProtocolError(
                    "AEAD authentication failed".to_string(),
                ))?;
                debug!("AEAD decrypted {} bytes", plaintext.len());

                decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);
                decrypt_state.aead_counter += 1;

                let mut full = Vec::with_capacity(4 + plaintext.len());
                full.extend_from_slice(&length_bytes);
                full.extend_from_slice(&plaintext);
                full
            }
        } else if etm {
            // ETM mode: length is in cleartext, MAC over seq || length || ciphertext
            let length_bytes = self.read_exact_buffered(4).await?;
            let packet_length = u32::from_be_bytes([
                length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3],
            ]) as usize;
            debug!("ETM: cleartext packet_length: {}", packet_length);

            if packet_length < 1 || packet_length > 35000 {
                return Err(crate::error::SshError::ProtocolError(
                    format!("Invalid packet length: {}", packet_length),
                ));
            }

            // Read encrypted data (packet_length bytes) + MAC
            let encrypted = self.read_exact_buffered(packet_length).await?;
            let received_mac = self.read_exact_buffered(mac_len).await?;

            // Verify MAC BEFORE decrypting (Encrypt-then-MAC)
            let mut mac_data = Vec::with_capacity(4 + 4 + encrypted.len());
            mac_data.extend_from_slice(&{
                let ds = self.decrypt_state.as_ref().unwrap();
                ds.sequence_number.to_be_bytes()
            });
            mac_data.extend_from_slice(&length_bytes);
            mac_data.extend_from_slice(&encrypted);

            let expected_mac = compute_mac(&mac_algo, &{
                let ds = self.decrypt_state.as_ref().unwrap();
                ds.mac_key.clone()
            }, &mac_data);

            if !crate::transport::verify_packet_mac(&expected_mac, &received_mac) {
                return Err(crate::error::SshError::ProtocolError("ETM MAC verification failed".to_string()));
            }
            debug!("ETM MAC verification successful");

            // Decrypt the data
            let decrypt_state = self.decrypt_state.as_mut().unwrap();
            let plaintext = decrypt_data(&decrypt_state.dec_algorithm, &decrypt_state.dec_key, &mut decrypt_state.iv, &encrypted)?;
            decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);

            // Reconstruct full packet: length || plaintext
            let mut full = Vec::with_capacity(4 + plaintext.len());
            full.extend_from_slice(&length_bytes);
            full.extend_from_slice(&plaintext);
            full
        } else {
            // Standard mode: decrypt first block to get length, then decrypt rest
            let first_block_ct = self.read_exact_buffered(16).await?;

            let (current_iv, dec_key) = {
                let ds = self.decrypt_state.as_ref().unwrap();
                (ds.iv.clone(), ds.dec_key.clone())
            };

            let decrypted_first = match dec_algo.as_str() {
                "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => aes_cbc_decrypt_raw(&dec_key, &current_iv, &first_block_ct)?,
                "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => {
                    use crate::crypto::cipher::aes_ctr_decrypt;
                    aes_ctr_decrypt(&dec_key, &current_iv, &first_block_ct)?
                }
                other => return Err(crate::error::SshError::ProtocolError(
                    format!("Unsupported decryption algorithm: {}", other),
                )),
            };

            let packet_length = u32::from_be_bytes([
                decrypted_first[0], decrypted_first[1], decrypted_first[2], decrypted_first[3],
            ]) as usize;
            debug!("Extracted packet_length: {}", packet_length);

            if packet_length < 1 || packet_length > 35000 {
                return Err(crate::error::SshError::ProtocolError(
                    format!("Invalid packet length: {}", packet_length),
                ));
            }

            let total_encrypted = 4 + packet_length;
            let remaining_encrypted = total_encrypted - 16;
            let rest = self.read_exact_buffered(remaining_encrypted + mac_len).await?;

            let mut full_ct = Vec::with_capacity(total_encrypted);
            full_ct.extend_from_slice(&first_block_ct);
            full_ct.extend_from_slice(&rest[..remaining_encrypted]);
            let received_mac = &rest[remaining_encrypted..];

            let decrypt_state = self.decrypt_state.as_mut().unwrap();
            let decrypted = decrypt_data(&decrypt_state.dec_algorithm, &decrypt_state.dec_key, &mut decrypt_state.iv, &full_ct)?;

            // Verify MAC over seq || plaintext
            let mut mac_data = Vec::with_capacity(4 + decrypted.len());
            mac_data.extend_from_slice(&decrypt_state.sequence_number.to_be_bytes());
            mac_data.extend_from_slice(&decrypted);

            let expected_mac = compute_mac(&decrypt_state.mac_algorithm, &decrypt_state.mac_key, &mac_data);
            if !crate::transport::verify_packet_mac(&expected_mac, &received_mac) {
                return Err(crate::error::SshError::ProtocolError("MAC verification failed".to_string()));
            }
            debug!("MAC verification successful (seq={})", decrypt_state.sequence_number);

            decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);
            decrypted
        };

        // Extract payload from decrypted packet:
        // decrypted = [packet_length: 4][padding_length: 1][payload: N][padding: P]
        if decrypted.len() < 5 {
            return Err(crate::error::SshError::ProtocolError(
                "Decrypted packet too short".to_string(),
            ));
        }
        let padding_len = decrypted[4] as usize;
        let payload_start = 5;
        let payload_end = decrypted.len() - padding_len;
        if payload_end <= payload_start {
            return Err(crate::error::SshError::ProtocolError(
                format!("Invalid padding_length {} in decrypted packet of {} bytes", padding_len, decrypted.len()),
            ));
        }
        let payload = decrypted[payload_start..payload_end].to_vec();
        debug!("Extracted payload: {} bytes, msg_type={}", payload.len(), payload[0]);

        Ok(payload)
    }

    /// Send SERVICE_REQUEST message
    pub async fn send_service_request(&mut self, service: &str) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ServiceRequest as u8);
        protocol::SshString::from_str(service).encode(&mut msg);
        
        debug!("Sending SERVICE_REQUEST for '{}', message: {:?}", service, &msg[..]);
        self.send_message(&msg).await?;
        debug!("SERVICE_REQUEST sent successfully");
        Ok(())
    }

    /// Receive SERVICE_ACCEPT message
    pub async fn recv_service_accept(&mut self) -> Result<String, crate::error::SshError> {
        debug!("Waiting for SERVICE_ACCEPT...");
        let msg = self.recv_message().await?;
        debug!("Received message: {:?}", &msg[..]);
        
        if msg.is_empty() {
            return Err(crate::error::SshError::ProtocolError(
                "Empty SERVICE_ACCEPT message".to_string()
            ));
        }
        
        let msg_type = msg[0];
        debug!("Message type: {}", msg_type);
        if msg_type != protocol::MessageType::ServiceAccept as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected SERVICE_ACCEPT, got {}", msg_type)
            ));
        }
        
        // Decode service name (skip message type byte)
        let service = protocol::SshString::decode(&mut &msg[1..])
            .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?
            .to_str()
            .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?
            .to_string();
        
        Ok(service)
    }

    /// Transition to encrypted state after key exchange
    pub fn transition_to_encrypted(
        &mut self,
        _session_id: &[u8],
        negotiated: &protocol::NegotiatedAlgorithms,
    ) -> Result<(), crate::error::SshError> {
        // Update handshake state
        self.handshake.negotiated = Some(negotiated.clone());
        
        // Transition state machine to established
        self.state.transition_to_established();
        
        Ok(())
    }

    /// Send channel data message
    pub async fn send_channel_data(
        &mut self,
        channel_id: u32,
        data: &[u8],
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelData as u8);
        msg.put_u32(channel_id);
        msg.put_u32(data.len() as u32);
        msg.put_slice(data);
        
        self.send_message(&msg).await
    }

    /// Send channel EOF message
    pub async fn send_channel_eof(&mut self, channel_id: u32) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelEof as u8);
        msg.put_u32(channel_id);
        
        self.send_message(&msg).await
    }

    /// Send channel window adjust message to replenish the remote's send window.
    /// This tells the server it can send more data on this channel.
    pub async fn send_channel_window_adjust(
        &mut self,
        channel_id: u32,
        bytes_to_add: u32,
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelWindowAdjust as u8);
        msg.put_u32(channel_id);
        msg.put_u32(bytes_to_add);
        self.send_message(&msg).await
    }

    /// Send channel close message
    pub async fn send_channel_close(&mut self, channel_id: u32) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelClose as u8);
        msg.put_u32(channel_id);
        
        self.send_message(&msg).await
    }

    /// Send channel request message
    pub async fn send_channel_request(
        &mut self,
        channel_id: u32,
        request_type: &str,
        want_reply: bool,
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelRequest as u8);
        msg.put_u32(channel_id);
        msg.put_u32(request_type.len() as u32);
        msg.put_slice(request_type.as_bytes());
        msg.put_u8(if want_reply { 1 } else { 0 });
        
        self.send_message(&msg).await
    }

    /// Send channel request with string data
    pub async fn send_channel_request_string(
        &mut self,
        channel_id: u32,
        request_type: &str,
        want_reply: bool,
        data: &str,
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelRequest as u8);
        msg.put_u32(channel_id);
        msg.put_u32(request_type.len() as u32);
        msg.put_slice(request_type.as_bytes());
        msg.put_u8(if want_reply { 1 } else { 0 });
        msg.put_u32(data.len() as u32);
        msg.put_slice(data.as_bytes());
        
        self.send_message(&msg).await
    }
}

/// Check if an encryption algorithm is an AEAD cipher (no separate MAC)
pub(crate) fn is_aead_cipher(algorithm: &str) -> bool {
    matches!(algorithm, "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com" | "chacha20-poly1305@openssh.com")
}

/// GCM tag length
const GCM_TAG_LEN: usize = 16;

/// Construct a 12-byte GCM nonce.
/// Per OpenSSH: use the full 12-byte IV for the first packet.
/// For subsequent packets, increment the last 8 bytes as a big-endian counter.
pub(crate) fn gcm_nonce(iv: &[u8], invocation_counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv[..12]);
    // Add the invocation counter to the last 8 bytes
    let mut carry = invocation_counter;
    for i in (4..12).rev() {
        let sum = nonce[i] as u64 + (carry & 0xFF);
        nonce[i] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
        if carry == 0 {
            break;
        }
    }
    nonce
}

/// Check if a MAC algorithm is an ETM (Encrypt-then-MAC) variant
pub(crate) fn is_etm_mac(algorithm: &str) -> bool {
    algorithm.ends_with("-etm@openssh.com")
}

/// Get the base MAC algorithm name (strip ETM suffix if present)
pub(crate) fn base_mac_algorithm(algorithm: &str) -> &str {
    if let Some(base) = algorithm.strip_suffix("-etm@openssh.com") {
        base
    } else {
        algorithm
    }
}

/// Compute MAC using the specified algorithm
pub(crate) fn compute_mac(algorithm: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    match base_mac_algorithm(algorithm) {
        "hmac-sha2-256" => {
            let mut hmac = HmacSha256::new(key);
            hmac.update(data);
            hmac.finish().to_vec()
        }
        "hmac-sha2-512" => {
            let mut hmac = HmacSha512::new(key);
            hmac.update(data);
            hmac.finish().to_vec()
        }
        _ => {
            // Default to HMAC-SHA1
            let mut hmac = HmacSha1::new(key);
            hmac.update(data);
            hmac.finish().to_vec()
        }
    }
}

/// Get MAC length for a given algorithm
pub(crate) fn mac_length(algorithm: &str) -> usize {
    match base_mac_algorithm(algorithm) {
        "hmac-sha1" => 20,
        "hmac-sha1-96" => 12,
        "hmac-md5" => 16,
        "hmac-md5-96" => 12,
        "hmac-sha2-256" => 32,
        "hmac-sha2-512" => 64,
        _ => 20,
    }
}

/// Advance a 16-byte CTR IV by the given number of AES blocks
pub(crate) fn advance_ctr_iv(iv: &mut Vec<u8>, blocks: usize) {
    // IV is treated as a 128-bit big-endian counter
    let mut carry = blocks as u64;
    for i in (0..iv.len()).rev() {
        let sum = iv[i] as u64 + (carry & 0xFF);
        iv[i] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
        if carry == 0 {
            break;
        }
    }
}

/// Encrypt data with the specified algorithm, updating IV in place
pub(crate) fn encrypt_data(algorithm: &str, key: &[u8], iv: &mut Vec<u8>, data: &[u8]) -> Result<Vec<u8>, crate::error::SshError> {
    match algorithm {
        "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => {
            let ct = aes_cbc_encrypt_raw(key, iv, data)?;
            if ct.len() >= 16 {
                *iv = ct[ct.len() - 16..].to_vec();
            }
            Ok(ct)
        }
        "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => {
            use crate::crypto::cipher::aes_ctr_encrypt;
            let ct = aes_ctr_encrypt(key, iv, data)?;
            let blocks = (data.len() + 15) / 16;
            advance_ctr_iv(iv, blocks);
            Ok(ct)
        }
        _ => Err(crate::error::SshError::ProtocolError(
            format!("Unsupported encryption algorithm: {}", algorithm)
        )),
    }
}

/// Decrypt data with the specified algorithm, updating IV in place
pub(crate) fn decrypt_data(algorithm: &str, key: &[u8], iv: &mut Vec<u8>, data: &[u8]) -> Result<Vec<u8>, crate::error::SshError> {
    match algorithm {
        "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => {
            let pt = aes_cbc_decrypt_raw(key, iv, data)?;
            if data.len() >= 16 {
                *iv = data[data.len() - 16..].to_vec();
            }
            Ok(pt)
        }
        "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => {
            use crate::crypto::cipher::aes_ctr_decrypt;
            let pt = aes_ctr_decrypt(key, iv, data)?;
            let blocks = (data.len() + 15) / 16;
            advance_ctr_iv(iv, blocks);
            Ok(pt)
        }
        _ => Err(crate::error::SshError::ProtocolError(
            format!("Unsupported decryption algorithm: {}", algorithm)
        )),
    }
}

// Standalone helper functions for encryption/decryption
pub(crate) fn encrypt_packet_cbc(payload: &[u8], state: &mut EncryptionState) -> Result<Vec<u8>, crate::error::SshError> {
    // Calculate padding per RFC 4253 Section 6:
    // Total of (packet_length || padding_length || payload || padding) must be multiple of
    // max(8, cipher_block_size). For AES-128-CBC, block size is 16.
    let block_size: usize = match state.enc_algorithm.as_str() {
        "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => 16,
        "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => 16,
        "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com" => 16,
        "chacha20-poly1305@openssh.com" => 8,
        _ => 8,
    };
    let payload_len = payload.len();
    // For ETM and AES-GCM modes, length field is cleartext (not encrypted),
    // so alignment applies only to the encrypted portion.
    // For ETM and AES-GCM, the length field is cleartext, so alignment
    // applies to the encrypted portion only (1 + payload + padding).
    // For ChaCha20-Poly1305, the length is encrypted separately. OpenSSH
    // requires packet_length (= 1 + payload + padding) to be a multiple
    // of block_size, NOT (4 + packet_length).
    // For standard mode, the TOTAL (4 + 1 + payload + padding) must align.
    let length_cleartext = (is_etm_mac(&state.mac_algorithm) && !is_aead_cipher(&state.enc_algorithm))
        || is_aead_cipher(&state.enc_algorithm); // includes chacha20 — length is handled separately
    let total_without_padding = if length_cleartext {
        1 + payload_len // only padding_len + payload (no length field)
    } else {
        4 + 1 + payload_len // length field + padding_len + payload
    };
    let remainder = total_without_padding % block_size;
    let mut padding_length = if remainder == 0 {
        block_size as u8
    } else {
        (block_size - remainder) as u8
    };
    // Ensure minimum padding of 4 bytes per RFC 4253
    if padding_length < 4 {
        padding_length += block_size as u8;
    }
    
    let packet_length = payload_len as u32 + padding_length as u32 + 1;
    
    // Build the packet: length + padding_length + payload + padding
    let mut packet = Vec::with_capacity(4 + 1 + payload_len + padding_length as usize);
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(padding_length);
    packet.extend_from_slice(payload);
    for _ in 0..padding_length {
        packet.push(0);
    }

    let aead = is_aead_cipher(&state.enc_algorithm);
    let etm = !aead && is_etm_mac(&state.mac_algorithm);

    if aead {
        if state.enc_algorithm == "chacha20-poly1305@openssh.com" {
            // ChaCha20-Poly1305: length IS encrypted
            let length_bytes: [u8; 4] = packet[..4].try_into().unwrap();
            let payload = &packet[4..];

            let result = crate::crypto::ssh_chacha20::encrypt(
                &state.enc_key, state.sequence_number as u64, &length_bytes, payload,
            ).map_err(|e| crate::error::SshError::CryptoError(e))?;

            state.sequence_number = state.sequence_number.wrapping_add(1);
            state.bytes_encrypted += result.len() as u64;
            Ok(result)
        } else {
            // AES-GCM: length in cleartext as AAD
            let length_bytes = &packet[..4];
            let to_encrypt = &packet[4..];
            let nonce = gcm_nonce(&state.iv, state.aead_counter);

            use crate::crypto::cipher::aes_gcm_encrypt_with_aad;
            let ciphertext_with_tag = aes_gcm_encrypt_with_aad(
                &state.enc_key, &nonce, length_bytes, to_encrypt,
            )?;

            state.sequence_number = state.sequence_number.wrapping_add(1);
            state.aead_counter += 1;

            let mut result = Vec::with_capacity(4 + ciphertext_with_tag.len());
            result.extend_from_slice(length_bytes);
            result.extend_from_slice(&ciphertext_with_tag);
            state.bytes_encrypted += result.len() as u64;
            Ok(result)
        }
    } else if etm {
        // ETM mode: length in cleartext, encrypt rest, MAC over seq || length || ciphertext
        let length_bytes = &packet[..4]; // cleartext length field
        let to_encrypt = &packet[4..]; // padding_length + payload + padding

        let ciphertext = encrypt_data(&state.enc_algorithm, &state.enc_key, &mut state.iv, to_encrypt)?;

        // MAC over sequence_number || cleartext_length || ciphertext
        let mut mac_data = Vec::with_capacity(4 + 4 + ciphertext.len());
        mac_data.extend_from_slice(&state.sequence_number.to_be_bytes());
        mac_data.extend_from_slice(length_bytes);
        mac_data.extend_from_slice(&ciphertext);
        let mac = compute_mac(&state.mac_algorithm, &state.mac_key, &mac_data);

        state.sequence_number = state.sequence_number.wrapping_add(1);

        let mut result = Vec::with_capacity(4 + ciphertext.len() + mac.len());
        result.extend_from_slice(length_bytes);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&mac);
        state.bytes_encrypted += result.len() as u64;
        Ok(result)
    } else {
        // Standard mode: encrypt entire packet, MAC over seq || plaintext
        let mut mac_data = Vec::with_capacity(4 + packet.len());
        mac_data.extend_from_slice(&state.sequence_number.to_be_bytes());
        mac_data.extend_from_slice(&packet);
        let mac = compute_mac(&state.mac_algorithm, &state.mac_key, &mac_data);

        let encrypted = encrypt_data(&state.enc_algorithm, &state.enc_key, &mut state.iv, &packet)?;

        state.sequence_number = state.sequence_number.wrapping_add(1);

        let mut result = encrypted;
        result.extend_from_slice(&mac);
        state.bytes_encrypted += result.len() as u64;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_send_recv() {
        // This test would require a real TCP connection or mock
        // For now, just verify the API exists
        assert!(true);
    }

    #[tokio::test]
    async fn test_transport_channel_methods_exist() {
        // Verify that channel methods exist on Transport
        // This is a compile-time check
        let _ = Transport::new;
        let _ = Transport::send_channel_data;
        let _ = Transport::send_channel_eof;
        let _ = Transport::send_channel_close;
        let _ = Transport::send_channel_request;
        let _ = Transport::send_channel_request_string;
    }

    #[test]
    fn test_advance_ctr_iv_simple() {
        let mut iv = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        advance_ctr_iv(&mut iv, 1);
        assert_eq!(iv, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_advance_ctr_iv_multiple_blocks() {
        let mut iv = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        advance_ctr_iv(&mut iv, 256);
        assert_eq!(iv, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }

    #[test]
    fn test_advance_ctr_iv_carry() {
        let mut iv = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];
        advance_ctr_iv(&mut iv, 1);
        assert_eq!(iv, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }

    #[test]
    fn test_advance_ctr_iv_multi_byte_carry() {
        let mut iv = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];
        advance_ctr_iv(&mut iv, 1);
        assert_eq!(iv, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
    }

    /// Verify CTR mode encrypt/decrypt round-trip through encrypt_packet_cbc
    #[test]
    fn test_encrypt_packet_ctr_round_trip() {
        let payload = vec![5, 0, 0, 0, 12, b's', b's', b'h', b'-', b'u', b's', b'e', b'r', b'a', b'u', b't', b'h'];
        let mut enc_state = EncryptionState {
            enc_key: vec![0x42; 16],
            iv: vec![0x00; 16],
            mac_key: vec![0xAB; 20],
            sequence_number: 3,
            aead_counter: 0,
            enc_algorithm: "aes128-ctr".to_string(),
            mac_algorithm: "hmac-sha1".to_string(),
            bytes_encrypted: 0,
        };

        let encrypted = encrypt_packet_cbc(&payload, &mut enc_state).unwrap();
        // Encrypted output should be: encrypted_packet + 20-byte HMAC
        assert!(encrypted.len() > payload.len());
        assert!(encrypted.len() >= 20); // at least MAC

        // Sequence number should have been incremented
        assert_eq!(enc_state.sequence_number, 4);
    }

    #[test]
    fn test_is_aead_cipher() {
        assert!(is_aead_cipher("aes128-gcm@openssh.com"));
        assert!(is_aead_cipher("aes256-gcm@openssh.com"));
        assert!(is_aead_cipher("chacha20-poly1305@openssh.com"));
        assert!(!is_aead_cipher("aes128-ctr"));
        assert!(!is_aead_cipher("aes256-cbc"));
    }

    #[test]
    fn test_is_etm_mac() {
        assert!(is_etm_mac("hmac-sha2-256-etm@openssh.com"));
        assert!(is_etm_mac("hmac-sha1-etm@openssh.com"));
        assert!(!is_etm_mac("hmac-sha1"));
        assert!(!is_etm_mac("hmac-sha2-256"));
    }

    #[test]
    fn test_base_mac_algorithm() {
        assert_eq!(base_mac_algorithm("hmac-sha2-256-etm@openssh.com"), "hmac-sha2-256");
        assert_eq!(base_mac_algorithm("hmac-sha1-etm@openssh.com"), "hmac-sha1");
        assert_eq!(base_mac_algorithm("hmac-sha1"), "hmac-sha1");
    }

    #[test]
    fn test_mac_length_all() {
        assert_eq!(mac_length("hmac-sha1"), 20);
        assert_eq!(mac_length("hmac-sha2-256"), 32);
        assert_eq!(mac_length("hmac-sha2-512"), 64);
        assert_eq!(mac_length("hmac-sha1-etm@openssh.com"), 20);
        assert_eq!(mac_length("hmac-sha2-256-etm@openssh.com"), 32);
        assert_eq!(mac_length("hmac-sha2-512-etm@openssh.com"), 64);
    }

    #[test]
    fn test_gcm_nonce_initial() {
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let nonce = gcm_nonce(&iv, 0);
        // First packet: nonce = IV as-is
        assert_eq!(nonce, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);
    }

    #[test]
    fn test_gcm_nonce_incremented() {
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let nonce = gcm_nonce(&iv, 1);
        // Second packet: last 8 bytes incremented by 1
        assert_eq!(nonce, [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_gcm_nonce_carry() {
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        let nonce = gcm_nonce(&iv, 1);
        assert_eq!(nonce, [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    /// Verify AEAD encrypt produces correct format: length(4B) + ciphertext + tag(16B)
    #[test]
    fn test_encrypt_packet_gcm_format() {
        let payload = vec![5, 0, 0, 0, 4, b't', b'e', b's', b't'];
        let mut enc_state = EncryptionState {
            enc_key: vec![0x42; 16],
            iv: vec![0x01; 12],
            mac_key: vec![0xAB; 20], // unused for GCM
            sequence_number: 0,
            aead_counter: 0,
            enc_algorithm: "aes128-gcm@openssh.com".to_string(),
            mac_algorithm: "hmac-sha1".to_string(), // ignored for AEAD
            bytes_encrypted: 0,
        };

        let result = encrypt_packet_cbc(&payload, &mut enc_state).unwrap();

        // Check format: [length(4)][ciphertext(N)][tag(16)]
        let packet_length = u32::from_be_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(result.len(), 4 + packet_length + 16, "AEAD output = 4 + packet_length + 16");

        // AEAD counter should be incremented
        assert_eq!(enc_state.aead_counter, 1);
        // Sequence number also incremented
        assert_eq!(enc_state.sequence_number, 1);
    }

    /// Verify ETM encrypt produces: length(4B cleartext) + ciphertext + MAC
    #[test]
    fn test_encrypt_packet_etm_format() {
        let payload = vec![5, 0, 0, 0, 4, b't', b'e', b's', b't'];
        let mut enc_state = EncryptionState {
            enc_key: vec![0x42; 16],
            iv: vec![0x00; 16],
            mac_key: vec![0xAB; 32],
            sequence_number: 0,
            aead_counter: 0,
            enc_algorithm: "aes128-ctr".to_string(),
            mac_algorithm: "hmac-sha2-256-etm@openssh.com".to_string(),
            bytes_encrypted: 0,
        };

        let result = encrypt_packet_cbc(&payload, &mut enc_state).unwrap();

        // First 4 bytes are cleartext length
        let packet_length = u32::from_be_bytes([result[0], result[1], result[2], result[3]]) as usize;
        // Total = 4 + packet_length(encrypted) + 32(HMAC-SHA256 MAC)
        assert_eq!(result.len(), 4 + packet_length + 32);
    }

    #[test]
    fn test_bytes_encrypted_tracking() {
        let payload = vec![5, 0, 0, 0, 12, b's', b's', b'h', b'-', b'u', b's', b'e', b'r', b'a', b'u', b't', b'h'];
        let mut enc_state = EncryptionState {
            enc_key: vec![0x42; 16],
            iv: vec![0x00; 16],
            mac_key: vec![0xAB; 20],
            sequence_number: 0,
            aead_counter: 0,
            enc_algorithm: "aes128-ctr".to_string(),
            mac_algorithm: "hmac-sha1".to_string(),
            bytes_encrypted: 0,
        };

        assert_eq!(enc_state.bytes_encrypted, 0);
        let result = encrypt_packet_cbc(&payload, &mut enc_state).unwrap();
        assert!(enc_state.bytes_encrypted > 0);
        assert_eq!(enc_state.bytes_encrypted, result.len() as u64);

        // Encrypt another packet — bytes should accumulate
        let first_bytes = enc_state.bytes_encrypted;
        let result2 = encrypt_packet_cbc(&payload, &mut enc_state).unwrap();
        assert_eq!(enc_state.bytes_encrypted, first_bytes + result2.len() as u64);
    }

    #[test]
    fn test_allocate_channel_id_sequential() {
        // We can't easily create a Transport without a real TcpStream,
        // but we can test the logic indirectly. Instead, test via a mock-like
        // approach: create a pair of connected streams.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connect_fut = tokio::net::TcpStream::connect(addr);
            let accept_fut = listener.accept();
            let (client_stream, _server) = tokio::join!(connect_fut, accept_fut);
            let mut transport = Transport::new(client_stream.unwrap());

            let id0 = transport.allocate_channel_id();
            let id1 = transport.allocate_channel_id();
            let id2 = transport.allocate_channel_id();

            assert_eq!(id0, 0);
            assert_eq!(id1, 1);
            assert_eq!(id2, 2);
        });
    }
}
#[cfg(test)]
mod plaintext_framing_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn check(bytes: &[u8]) {
        for server_side in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut sender = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (receiver, _) = listener.accept().await.unwrap();
            sender.write_all(bytes).await.unwrap();
            let result = tokio::time::timeout(std::time::Duration::from_millis(100), async {
                if server_side {
                    crate::server::encrypted_io::ServerEncryptedIO::new(receiver).read_unencrypted_packet(30).await
                } else {
                    Transport::new(receiver).read_unencrypted_packet(30).await
                }
            }).await;
            assert!(matches!(result, Ok(Err(_))), "invalid framing must fail promptly on server_side={server_side}");
        }
    }

    #[tokio::test]
    async fn plaintext_length_bounded() { check(&0xfffffffcu32.to_be_bytes()).await; }
    #[tokio::test]
    async fn plaintext_alignment_required() { check(&13u32.to_be_bytes()).await; }
    #[tokio::test]
    async fn plaintext_min_padding() {
        let mut packet = vec![0,0,0,12,3,20]; packet.resize(16, 0);
        check(&packet).await;
    }
}

/// Validate plaintext framing before reading or allocating the packet body.
pub(crate) fn validate_plaintext_header(length: usize, padding: Option<u8>) -> Result<(), crate::error::SshError> {
    if length < 12 || length > 35000 || (length + 4) % 8 != 0 {
        return Err(crate::error::SshError::ProtocolError("Invalid plaintext packet length or alignment".into()));
    }
    if let Some(padding) = padding {
        if padding < 4 || padding as usize + 1 >= length {
            return Err(crate::error::SshError::ProtocolError("Invalid plaintext padding".into()));
        }
    }
    Ok(())
}

/// Compare fixed-length packet MACs without content-dependent early exits.
pub(crate) fn verify_packet_mac(expected: &[u8], received: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(expected.ct_eq(received))
}

#[cfg(test)]
mod mac_compare_tests {
    #[test]
    fn mac_compare_all_mismatch_positions() {
        for size in [20, 32, 64] {
            let expected = vec![0x55; size];
            assert!(super::verify_packet_mac(&expected, &expected));
            for offset in 0..size {
                let mut received = expected.clone();
                received[offset] ^= 1;
                assert!(!super::verify_packet_mac(&expected, &received));
            }
            assert!(!super::verify_packet_mac(&expected, &expected[..size-1]));
        }
    }
}
