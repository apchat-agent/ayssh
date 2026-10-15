//! SSH Transport Handshake
//!
//! Implements the initial key exchange and authentication handshake.

use crate::protocol;
use crate::protocol::KexAlgorithm;
use crate::transport::kex::SessionKeys;
use crate::transport::TransportSession;
use bytes::{Buf, BufMut, BytesMut};
use rand::RngCore;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug};

/// SSH protocol version string with CRLF terminator
/// Format: SSH-2.0-software_version\r\n
/// Cisco devices expect CRLF-terminated version strings
pub const SSH_VERSION_STRING: &str = "SSH-2.0-OpenSSH_7.4\r\n";

/// Transport handshake state
#[derive(Debug, Clone)]
pub struct HandshakeState {
    /// Client's KEXINIT message
    pub client_kexinit: Option<Vec<u8>>,
    /// Server's KEXINIT message
    pub server_kexinit: Option<Vec<u8>>,
    /// Negotiated algorithms
    pub negotiated: Option<protocol::NegotiatedAlgorithms>,
    /// Session keys after key exchange
    pub session_keys: Option<SessionKeys>,
    /// Client-to-server encryption algorithm
    pub enc_c2s: Option<String>,
    /// Server-to-client encryption algorithm
    pub enc_s2c: Option<String>,
    /// Client-to-server MAC algorithm
    pub mac_c2s: Option<String>,
    /// Server-to-client MAC algorithm
    pub mac_s2c: Option<String>,
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self {
            client_kexinit: None,
            server_kexinit: None,
            negotiated: None,
            session_keys: None,
            enc_c2s: None,
            enc_s2c: None,
            mac_c2s: None,
            mac_s2c: None,
        }
    }
}

/// Parse SSH version string
pub fn parse_version_string(data: &[u8]) -> Result<(u32, String), &'static str> {
    let version = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 in version string")?;
    
    if !version.starts_with("SSH-") {
        return Err("Invalid version string prefix");
    }
    
    let parts: Vec<&str> = version.split('-').collect();
    if parts.len() < 2 {
        return Err("Invalid version string format");
    }
    
    // parts[1] contains the protocol version (e.g., "2.0" -> extract "2")
    let protocol_version_str = parts[1].split('.').next().ok_or("Invalid protocol version")?;
    let protocol_version: u32 = protocol_version_str.parse().map_err(|_| "Invalid protocol version")?;
    
    // Accept SSH-2.0 or SSH-1.99 (RFC 4253 Section 5.1: Clients using protocol 2.0
    // MUST be able to identify "1.99" as identical to "2.0")
    // Cisco devices send SSH-1.99-Cisco-1.25 for their SSH2-compatible implementation.
    let full_proto_version = parts[1]; // e.g. "2.0" or "1.99"
    if protocol_version == 2 || full_proto_version == "1.99" {
        // OK - SSH 2.0 compatible
    } else {
        return Err("Only SSH protocol version 2.0 or 1.99 supported");
    }
    
    let software_version = parts[2..].join("-");
    
    Ok((protocol_version, software_version))
}

/// Generate client KEXINIT message
/// Generate a client KEXINIT with preferred cipher and MAC placed first.
/// If `preferred_cipher` or `preferred_mac` is None, uses default ordering.
pub fn generate_client_kexinit_with_prefs(
    preferred_kex: Option<&str>,
    preferred_cipher: Option<&str>,
    preferred_mac: Option<&str>,
) -> Vec<u8> {
    generate_client_kexinit_with_x509(preferred_kex, preferred_cipher, preferred_mac, false)
}

/// Generate a proposal with optional RFC 6187 RSA certificate host keys.
/// When enabled, prefer the certificate algorithm; defaults remain unchanged.
pub fn generate_client_kexinit_with_x509(
    preferred_kex: Option<&str>,
    preferred_cipher: Option<&str>,
    preferred_mac: Option<&str>,
    enable_x509: bool,
) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(200);

    buf.put_u8(20);

    let mut cookie = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut cookie);
    buf.put(&cookie[..]);

    let default_kex = "diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,kex-strict-c-v00@openssh.com";
    let kex_list = if let Some(pref) = preferred_kex {
        let others: Vec<&str> = default_kex.split(',').filter(|k| *k != pref).collect();
        format!("{},{}", pref, others.join(","))
    } else {
        default_kex.to_string()
    };
    let kex_algorithms = &kex_list;
    let host_key_algorithms = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256";

    let host_key_list = if enable_x509 {
        format!("x509v3-ssh-rsa,{}", host_key_algorithms)
    } else {
        host_key_algorithms.to_string()
    };
    let host_key_algorithms = &host_key_list;

    let default_ciphers = "aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com";
    let default_macs = "hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com";

    // Put preferred algorithm first if specified
    let enc_list = if let Some(pref) = preferred_cipher {
        let others: Vec<&str> = default_ciphers.split(',').filter(|c| *c != pref).collect();
        format!("{},{}", pref, others.join(","))
    } else {
        default_ciphers.to_string()
    };
    let mac_list = if let Some(pref) = preferred_mac {
        let others: Vec<&str> = default_macs.split(',').filter(|m| *m != pref).collect();
        format!("{},{}", pref, others.join(","))
    } else {
        default_macs.to_string()
    };

    let enc_c2s = &enc_list;
    let enc_s2c = &enc_list;
    let mac_c2s = &mac_list;
    let mac_s2c = &mac_list;
    let comp_c2s = "none,zlib@openssh.com";
    let comp_s2c = "none,zlib@openssh.com";
    let lang_c2s = "";
    let lang_s2c = "";
    
    // Encode each algorithm list as a string
    protocol::SshString::from_str(kex_algorithms).encode(&mut buf);
    protocol::SshString::from_str(host_key_algorithms).encode(&mut buf);
    protocol::SshString::from_str(enc_c2s).encode(&mut buf);
    protocol::SshString::from_str(enc_s2c).encode(&mut buf);
    protocol::SshString::from_str(mac_c2s).encode(&mut buf);
    protocol::SshString::from_str(mac_s2c).encode(&mut buf);
    protocol::SshString::from_str(comp_c2s).encode(&mut buf);
    protocol::SshString::from_str(comp_s2c).encode(&mut buf);
    protocol::SshString::from_str(lang_c2s).encode(&mut buf);
    protocol::SshString::from_str(lang_s2c).encode(&mut buf);
    
    // first_kex_packet_follows (1 byte boolean, typically 0)
    buf.put_u8(0);
    
    // Reserved uint32 (always 0)
    buf.put_u32(0);
    
    buf.to_vec()
}

/// Generate a client KEXINIT with default algorithm ordering
pub fn generate_client_kexinit() -> Vec<u8> {
    generate_client_kexinit_with_prefs(None, None, None)
}

/// Parse server KEXINIT message
pub fn parse_server_kexinit(data: &[u8]) -> Result<protocol::AlgorithmProposal, &'static str> {
    let mut buf = data;
    
    // Skip message type byte (SSH_MSG_KEXINIT = 20)
    if buf.len() < 1 {
        return Err("KEXINIT too short");
    }
    let msg_type = buf.get_u8();
    if msg_type != 20 {
        return Err("Expected SSH_MSG_KEXINIT (20)");
    }
    
    // Skip 16 bytes of cookie
    if buf.len() < 16 {
        return Err("KEXINIT too short for cookie");
    }
    buf.advance(16);
    
    // Parse algorithm lists (each is a comma-separated string)
    let kex_algorithms_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode kex_algorithms")?
        .to_str()
        .map_err(|_| "Invalid kex_algorithms UTF-8")?
        .to_string();
    
    let host_key_algorithms_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode host_key_algorithms")?
        .to_str()
        .map_err(|_| "Invalid host_key_algorithms UTF-8")?
        .to_string();
    
    let enc_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode enc_c2s")?
        .to_str()
        .map_err(|_| "Invalid enc_c2s UTF-8")?
        .to_string();
    
    let enc_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode enc_s2c")?
        .to_str()
        .map_err(|_| "Invalid enc_s2c UTF-8")?
        .to_string();
    
    let mac_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode mac_c2s")?
        .to_str()
        .map_err(|_| "Invalid mac_c2s UTF-8")?
        .to_string();
    
    let mac_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode mac_s2c")?
        .to_str()
        .map_err(|_| "Invalid mac_s2c UTF-8")?
        .to_string();
    
    let comp_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode comp_c2s")?
        .to_str()
        .map_err(|_| "Invalid comp_c2s UTF-8")?
        .to_string();
    
    let _comp_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode comp_s2c")?
        .to_str()
        .map_err(|_| "Invalid comp_s2c UTF-8")?
        .to_string();
    
    let lang_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode lang_c2s")?
        .to_str()
        .map_err(|_| "Invalid lang_c2s UTF-8")?
        .to_string();
    
    let lang_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode lang_s2c")?
        .to_str()
        .map_err(|_| "Invalid lang_s2c UTF-8")?
        .to_string();
    
    // Parse first_kex_packet_follows (1 byte boolean) per RFC 4253
    if buf.len() < 1 {
        return Err("KEXINIT too short for first_kex_packet_follows");
    }
    let first_kex_packet_follows = buf.get_u8() != 0;
    
    // Skip reserved uint32 (4 bytes) per RFC 4253
    if buf.len() < 4 {
        return Err("KEXINIT too short for reserved uint32");
    }
    buf.advance(4);
    
    // Convert comma-separated strings to Vec<String>
    let kex_algorithms: Vec<String> = kex_algorithms_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let server_host_key_algorithms: Vec<String> = host_key_algorithms_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let encryption_algorithms_c2s: Vec<String> = enc_c2s_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let encryption_algorithms_s2c: Vec<String> = enc_s2c_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let mac_algorithms_c2s: Vec<String> = mac_c2s_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let mac_algorithms_s2c: Vec<String> = mac_s2c_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let compression_algorithms: Vec<String> = comp_c2s_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    Ok(protocol::AlgorithmProposal {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_c2s,
        encryption_algorithms_s2c,
        mac_algorithms_c2s,
        mac_algorithms_s2c,
        compression_algorithms,
        languages_c2s: lang_c2s_str,
        languages_s2c: lang_s2c_str,
        first_kex_packet_follows,
    })
}

/// Generate a server proposal with the OpenSSH strict KEX server marker.
pub fn generate_server_kexinit_with_prefs(kex: Option<&str>, cipher: Option<&str>, mac: Option<&str>, host_algorithms: &[&str]) -> Vec<u8> {
    let mut payload = generate_client_kexinit_with_prefs(kex, cipher, mac);
    let marker = b"kex-strict-c-v00@openssh.com";
    if let Some(offset) = payload.windows(marker.len()).position(|w| w == marker) {
        payload[offset + 11] = b's';
    }
    // The second name-list must describe keys that the server can actually use.
    let kex_length = u32::from_be_bytes(payload[17..21].try_into().unwrap()) as usize;
    let offset = 21 + kex_length;
    let old_length = u32::from_be_bytes(payload[offset..offset+4].try_into().unwrap()) as usize;
    let host_list = host_algorithms.join(",");
    let mut encoded = (host_list.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(host_list.as_bytes());
    payload.splice(offset..offset + 4 + old_length, encoded);
    payload
}

/// Select the first matching algorithm from a list
pub fn select_algorithm(preferred: &[String], server_list: &[String]) -> Option<String> {
    for algo in preferred {
        if server_list.contains(algo) {
            return Some(algo.clone());
        }
    }
    None
}

/// Negotiate algorithms from client and server proposals
pub fn negotiate_algorithms(client: &protocol::AlgorithmProposal, server: &protocol::AlgorithmProposal) -> Result<protocol::NegotiatedAlgorithms, crate::error::SshError> {
    client.select_common_algorithms(server)
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))
}

/// RFC 4253 section 11.1: terminate unsuccessful algorithm negotiation.
pub(crate) async fn disconnect_kex_failed<T: AsyncWriteExt + Unpin>(stream: &mut T) {
    let mut payload = BytesMut::new();
    payload.put_u8(1);
    payload.put_u32(3); // SSH_DISCONNECT_KEY_EXCHANGE_FAILED
    let description = b"Key exchange negotiation failed";
    payload.put_u32(description.len() as u32);
    payload.put_slice(description);
    payload.put_u32(0); // language tag
    let _ = stream.write_all(&crate::server::encrypted_io::build_unencrypted_packet(&payload)).await;
}

/// RFC 4253 section 7: guesses include both KEX and host key algorithms.
pub(crate) fn wrong_kex_guess(proposal: &protocol::AlgorithmProposal, selected: &protocol::NegotiatedAlgorithms) -> bool {
    proposal.first_kex_packet_follows &&
        (proposal.kex_algorithms.first() != Some(&selected.kex) ||
         proposal.server_host_key_algorithms.first() != Some(&selected.host_key))
}

pub(crate) async fn read_plaintext_payload<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<Vec<u8>, crate::error::SshError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    crate::transport::validate_plaintext_header(length, None)?;
    let mut pad = [0u8; 1];
    stream.read_exact(&mut pad).await?;
    crate::transport::validate_plaintext_header(length, Some(pad[0]))?;
    let mut body = vec![0u8; length - 1];
    stream.read_exact(&mut body).await?;
    body.truncate(length - 1 - pad[0] as usize);
    Ok(body)
}

/// Send SSH version string
pub async fn send_version<T: AsyncWriteExt + Unpin>(stream: &mut T) -> Result<(), crate::error::SshError> {
    send_version_custom(stream, SSH_VERSION_STRING).await
}

/// Send a custom SSH version string (for server use)
pub async fn send_version_custom<T: AsyncWriteExt + Unpin>(stream: &mut T, version: &str) -> Result<(), crate::error::SshError> {
    let version_bytes = version.as_bytes();
    debug!("Sending version string: {:?}", std::str::from_utf8(version_bytes));
    stream.write_all(version_bytes).await?;
    stream.flush().await?;
    debug!("Version string sent successfully");
    Ok(())
}

/// Server version string
pub const SSH_SERVER_VERSION_STRING: &str = "SSH-2.0-ayssh_test_server\r\n";

/// Receive a server identification, discarding preceding informational lines.
/// RFC 4253 section 4.2 permits these lines only before the SSH identification.
/// Discard banners as a stream so their length does not affect the version
/// limit or require buffering, and leave the following binary packet untouched.
pub async fn recv_server_version<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<String, crate::error::SshError> {
    loop {
        let mut prefix = Vec::with_capacity(4);
        while prefix.len() < 4 {
            let byte = stream.read_u8().await?;
            prefix.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        if prefix == b"SSH-" {
            return recv_version(&mut AsyncReadExt::chain(prefix.as_slice(), stream)).await;
        }
        if prefix.last() != Some(&b'\n') {
            while stream.read_u8().await? != b'\n' {}
        }
    }
}

/// Receive SSH version string
pub async fn recv_version<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<String, crate::error::SshError> {
    // Read version string byte-by-byte to avoid BufReader consuming
    // bytes from the next SSH packet (KEXINIT). A BufReader would
    // buffer extra bytes and lose them when dropped.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        match stream.read_exact(&mut byte).await {
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > 255 {
                    return Err(crate::error::SshError::ProtocolError(
                        "Version string too long".to_string()
                    ));
                }
            }
            Err(e) => {
                debug!("Error reading version byte: {}", e);
                return Err(e.into());
            }
        }
    }

    debug!("Read {} bytes from version line", buf.len());
    debug!("Raw version bytes: {:?}", &buf);

    let mut version = String::from_utf8(buf)
        .map_err(|e| crate::error::SshError::ProtocolError(
            format!("Invalid UTF-8 in version: {}", e)
        ))?;

    // Remove CRLF terminator
    if version.ends_with("\r\n") {
        version.pop();
        version.pop();
    } else if version.ends_with('\n') {
        version.pop();
    }

    debug!("Cleaned version string: {:?}", version);

    // Validate SSH version prefix (RFC 4253 §4.2)
    if !version.starts_with("SSH-") {
        return Err(crate::error::SshError::ProtocolError(format!(
            "Invalid SSH identification string: {:?}", version
        )));
    }

    Ok(version)
}

/// Perform the key exchange handshake
pub async fn perform_handshake<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: T,
    _server_version: &str,
) -> Result<(TransportSession<T>, protocol::NegotiatedAlgorithms), crate::error::SshError> {
    // 1. Send client version
    send_version(&mut stream).await?;
    
    // 2. Receive server version
    let server_ver = recv_server_version(&mut stream).await?;
    let (_proto, _software) = parse_version_string(server_ver.as_bytes())
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
    
    // 3. Generate and send client KEXINIT
    let client_kexinit = generate_client_kexinit();
    stream.write_all(&crate::server::encrypted_io::build_unencrypted_packet(&client_kexinit)).await?;
    
    // 4. Receive and parse server KEXINIT
    let server_kexinit_bytes = read_plaintext_payload(&mut stream).await?;

    let server_proposal = parse_server_kexinit(&server_kexinit_bytes)
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
    
    // 5. Negotiate algorithms
    let client_proposal = parse_server_kexinit(&client_kexinit)
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
    let negotiated = match negotiate_algorithms(&client_proposal, &server_proposal) {
        Ok(algorithms) => algorithms,
        Err(error) => { disconnect_kex_failed(&mut stream).await; return Err(error); }
    };
    
    if wrong_kex_guess(&server_proposal, &negotiated) {
        read_plaintext_payload(&mut stream).await?;
    }

    // 6. Create transport session and initiate KEX
    let mut transport_session = TransportSession::new(stream, KexAlgorithm::from_str(&negotiated.kex).unwrap_or(KexAlgorithm::Curve25519Sha256));
    transport_session.init_kex()?;
    
    // 7. Send KEXINIT message (with client ephemeral key)
    let client_ephemeral = transport_session.kex_context().client_ephemeral.clone()
        .expect("Client ephemeral key not generated");
    
    let mut kexinit_msg = BytesMut::new();
    kexinit_msg.put_u8(protocol::MessageType::KexInit as u8);
    kexinit_msg.put_u32(client_ephemeral.len() as u32);
    kexinit_msg.put_slice(&client_ephemeral);
    transport_session.stream_mut().write_all(&kexinit_msg).await?;
    
    // 8. Receive KEX_REPLY from server (server ephemeral key)
    let reply_bytes = read_plaintext_payload(transport_session.stream_mut()).await?;

    if reply_bytes[0] != protocol::MessageType::KexInit as u8 {
        return Err(crate::error::SshError::ProtocolError(
            "Expected KEX_INIT from server".to_string()
        ));
    }
    
    transport_session.kex_context_mut().process_server_kex_init(&reply_bytes[1..])?;
    
    // 9. Compute shared secret
    transport_session.kex_context_mut().compute_shared_secret()?;
    
    // 10. Derive session keys
    let session_id = transport_session.session_id().cloned()
        .expect("Session ID not set");
    transport_session.kex_context_mut().derive_session_keys_directional(&session_id, &negotiated)?;
    
    // 11. Send NEWKEYS message to transition to encrypted mode
    let newkeys_msg = crate::transport::kex::encode_newkeys();
    transport_session.stream_mut().write_all(&newkeys_msg).await?;
    
    // 12. Receive NEWKEYS from server
    let newkeys_bytes = read_plaintext_payload(transport_session.stream_mut()).await?;
    if newkeys_bytes.as_slice() != [protocol::MessageType::Newkeys as u8] {
        return Err(crate::error::SshError::ProtocolError("Expected NEWKEYS from server".into()));
    }

    // 13. Transition to encrypted state
    transport_session.transition_to_encrypted()?;
    
    Ok((transport_session, negotiated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kex_markers_not_selectable() {
        let mut client = parse_server_kexinit(&generate_client_kexinit()).unwrap();
        for marker in ["ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"] {
            client.kex_algorithms = vec![marker.to_string()];
            assert!(negotiate_algorithms(&client, &client).is_err());
        }
    }

    #[test]
    fn group1_requires_opt_in() {
        let default = parse_server_kexinit(&generate_client_kexinit()).unwrap();
        assert!(!default.kex_algorithms.iter().any(|a| a == "diffie-hellman-group1-sha1"));
        let explicit = parse_server_kexinit(&generate_client_kexinit_with_prefs(Some("diffie-hellman-group1-sha1"), None, None)).unwrap();
        assert_eq!(explicit.kex_algorithms[0], "diffie-hellman-group1-sha1");
    }

    #[test]
    fn no_common_algorithm_errors() {
        for category in 0..7 {
            let mut client = parse_server_kexinit(&generate_client_kexinit()).unwrap();
            let server = client.clone();
            match category {
                0 => client.kex_algorithms.clear(),
                1 => client.server_host_key_algorithms.clear(),
                2 => client.encryption_algorithms_c2s.clear(),
                3 => client.encryption_algorithms_s2c.clear(),
                4 => client.mac_algorithms_c2s.clear(),
                5 => client.mac_algorithms_s2c.clear(),
                _ => client.compression_algorithms.clear(),
            }
            assert!(negotiate_algorithms(&client, &server).is_err());
        }
    }

    #[test]
    fn test_parse_version_string_valid() {
        let version = b"SSH-2.0-libssh_0.9.6";
        let (proto, software) = parse_version_string(version).unwrap();
        assert_eq!(proto, 2);
        assert_eq!(software, "libssh_0.9.6");
    }

    #[test]
    fn test_parse_version_string_with_dash_in_software() {
        let version = b"SSH-2.0-OpenSSH_8.0";
        let (proto, software) = parse_version_string(version).unwrap();
        assert_eq!(proto, 2);
        assert_eq!(software, "OpenSSH_8.0");
    }

    #[test]
    fn test_parse_version_string_invalid_prefix() {
        let version = b"SSH-1.0-invalid";
        assert!(parse_version_string(version).is_err());
    }

    #[test]
    fn test_parse_version_string_invalid_protocol() {
        // SSH-1.99 MUST be accepted as identical to 2.0 per RFC 4253 Section 5.1
        let version = b"SSH-1.99-Cisco-1.25";
        let (proto, software) = parse_version_string(version).unwrap();
        assert_eq!(proto, 1); // major version is 1, but 1.99 is accepted
        assert_eq!(software, "Cisco-1.25");

        // SSH-1.0 should be rejected
        let version_old = b"SSH-1.0-OldServer";
        assert!(parse_version_string(version_old).is_err());
    }

    #[test]
    fn test_parse_version_string_invalid_utf8() {
        let version = b"SSH-2.0-\xFF\xFE";
        assert!(parse_version_string(version).is_err());
    }

    #[test]
    fn test_generate_client_kexinit() {
        let kexinit = generate_client_kexinit();
        assert!(!kexinit.is_empty());
        assert!(kexinit.len() >= 16); // At least cookie + some data
    }

    #[test]
    fn test_kexinit_round_trip() {
        let client_kexinit = generate_client_kexinit();
        let proposal = parse_server_kexinit(&client_kexinit).unwrap();
        
        assert!(!proposal.kex_algorithms.is_empty());
        assert!(!proposal.server_host_key_algorithms.is_empty());
        assert!(!proposal.encryption_algorithms_c2s.is_empty());
        assert!(!proposal.encryption_algorithms_s2c.is_empty());
    }

    #[test]
    fn test_kexinit_parse_too_short() {
        let short_data = vec![0u8; 10];
        assert!(parse_server_kexinit(&short_data).is_err());
    }

    #[test]
    fn test_handshake_state_default() {
        let state = HandshakeState::default();
        assert!(state.client_kexinit.is_none());
        assert!(state.server_kexinit.is_none());
        assert!(state.negotiated.is_none());
    }

    #[test]
    fn test_handshake_state_update() {
        let mut state = HandshakeState::default();
        state.client_kexinit = Some(vec![1, 2, 3]);
        state.server_kexinit = Some(vec![4, 5, 6]);
        
        assert_eq!(state.client_kexinit, Some(vec![1, 2, 3]));
        assert_eq!(state.server_kexinit, Some(vec![4, 5, 6]));
    }

    #[test]
    fn test_select_algorithm() {
        let preferred = vec!["aes256-gcm".to_string(), "aes128-gcm".to_string()];
        let server_list = vec!["aes128-gcm".to_string(), "chacha20-poly1305".to_string()];
        
        let result = select_algorithm(&preferred, &server_list);
        assert_eq!(result, Some("aes128-gcm".to_string()));
    }

    #[test]
    fn test_select_algorithm_no_match() {
        let preferred = vec!["aes256-gcm".to_string()];
        let server_list = vec!["chacha20-poly1305".to_string()];
        
        let result = select_algorithm(&preferred, &server_list);
        assert!(result.is_none());
    }

    #[test]
    fn test_negotiate_algorithms() {
        let client = parse_server_kexinit(&generate_client_kexinit()).unwrap();
        let server = parse_server_kexinit(&generate_client_kexinit()).unwrap();

        let negotiated = negotiate_algorithms(&client, &server).unwrap();

        // According to RFC 4253 Section 7.1: "The first algorithm in each list
        // that is also in the other's list is chosen."
        // The default proposal omits the discouraged 1024-bit group.
        assert_eq!(negotiated.kex, "diffie-hellman-group14-sha1");
        assert_eq!(negotiated.compression, "none");
    }

    // --- parse_version_string edge cases ---

    #[test]
    fn test_parse_version_not_ssh_prefix() {
        assert!(parse_version_string(b"NOTSH-2.0-foo").is_err());
    }

    #[test]
    fn test_parse_version_minimal_two_parts() {
        // "SSH-2.0" has only 2 parts after split on '-', software_version is empty
        let (proto, sw) = parse_version_string(b"SSH-2.0").unwrap();
        assert_eq!(proto, 2);
        assert_eq!(sw, ""); // no software version component
    }

    #[test]
    fn test_parse_version_single_part() {
        // "SSH" has only 1 part — too few
        assert!(parse_version_string(b"SSH").is_err());
    }

    #[test]
    fn test_parse_version_non_numeric_protocol() {
        assert!(parse_version_string(b"SSH-abc-foo").is_err());
    }

    #[test]
    fn test_parse_version_ssh15_rejected() {
        assert!(parse_version_string(b"SSH-1.5-OldServer").is_err());
    }

    #[test]
    fn test_parse_version_multiple_dashes_in_software() {
        let (proto, sw) = parse_version_string(b"SSH-2.0-My-Cool-Server-1.0").unwrap();
        assert_eq!(proto, 2);
        assert_eq!(sw, "My-Cool-Server-1.0");
    }

    // --- generate_client_kexinit_with_prefs ---

    #[test]
    fn test_kexinit_with_preferred_cipher() {
        let kexinit = generate_client_kexinit_with_prefs(None, Some("aes256-ctr"), None);
        let proposal = parse_server_kexinit(&kexinit).unwrap();
        assert_eq!(proposal.encryption_algorithms_c2s[0], "aes256-ctr");
    }

    #[test]
    fn test_kexinit_with_preferred_mac() {
        let kexinit = generate_client_kexinit_with_prefs(None, None, Some("hmac-sha2-512"));
        let proposal = parse_server_kexinit(&kexinit).unwrap();
        assert_eq!(proposal.mac_algorithms_c2s[0], "hmac-sha2-512");
    }

    #[test]
    fn test_kexinit_with_preferred_kex() {
        let kexinit = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), None, None);
        let proposal = parse_server_kexinit(&kexinit).unwrap();
        assert_eq!(proposal.kex_algorithms[0], "curve25519-sha256");
    }

    #[test]
    fn test_kexinit_with_all_prefs() {
        let kexinit = generate_client_kexinit_with_prefs(
            Some("ecdh-sha2-nistp256"),
            Some("aes128-gcm@openssh.com"),
            Some("hmac-sha1-etm@openssh.com"),
        );
        let proposal = parse_server_kexinit(&kexinit).unwrap();
        assert_eq!(proposal.kex_algorithms[0], "ecdh-sha2-nistp256");
        assert_eq!(proposal.encryption_algorithms_c2s[0], "aes128-gcm@openssh.com");
        assert_eq!(proposal.mac_algorithms_c2s[0], "hmac-sha1-etm@openssh.com");
    }

    #[test]
    fn test_kexinit_preferred_not_duplicated() {
        let kexinit = generate_client_kexinit_with_prefs(None, Some("aes128-ctr"), None);
        let proposal = parse_server_kexinit(&kexinit).unwrap();
        let count = proposal.encryption_algorithms_c2s.iter()
            .filter(|a| *a == "aes128-ctr").count();
        assert_eq!(count, 1, "Preferred cipher should appear exactly once");
    }

    // --- parse_server_kexinit error cases ---

    #[test]
    fn test_kexinit_parse_empty() {
        assert!(parse_server_kexinit(&[]).is_err());
    }

    #[test]
    fn test_kexinit_parse_wrong_msg_type() {
        let mut data = vec![21]; // NEWKEYS instead of KEXINIT
        data.extend_from_slice(&[0; 100]);
        assert!(parse_server_kexinit(&data).is_err());
    }

    #[test]
    fn test_kexinit_parse_too_short_for_cookie() {
        let data = vec![20, 0, 0, 0]; // msg type + 3 bytes (need 16 for cookie)
        assert!(parse_server_kexinit(&data).is_err());
    }

    // --- select_algorithm edge cases ---

    #[test]
    fn test_select_algorithm_empty_preferred() {
        let result = select_algorithm(&[], &["aes128-ctr".to_string()]);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_algorithm_empty_server() {
        let result = select_algorithm(&["aes128-ctr".to_string()], &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_algorithm_first_match_wins() {
        let preferred = vec!["first".to_string(), "second".to_string()];
        let server = vec!["second".to_string(), "first".to_string()];
        assert_eq!(select_algorithm(&preferred, &server), Some("first".to_string()));
    }

    // --- negotiate_algorithms with restricted lists ---

    #[test]
    fn test_negotiate_respects_client_preference() {
        let mut client = parse_server_kexinit(&generate_client_kexinit()).unwrap();
        let server = parse_server_kexinit(&generate_client_kexinit()).unwrap();
        // Reverse client KEX order
        client.kex_algorithms.reverse();
        let negotiated = negotiate_algorithms(&client, &server).unwrap();
        // Should pick client's first that's also in server
        assert!(server.kex_algorithms.contains(&negotiated.kex));
        assert_eq!(negotiated.kex, "ecdh-sha2-nistp521");
    }

    // --- HandshakeState ---

    #[test]
    fn test_handshake_state_all_fields() {
        let mut state = HandshakeState::default();
        state.enc_c2s = Some("aes128-ctr".to_string());
        state.enc_s2c = Some("aes256-ctr".to_string());
        state.mac_c2s = Some("hmac-sha1".to_string());
        state.mac_s2c = Some("hmac-sha2-256".to_string());
        assert_eq!(state.enc_c2s, Some("aes128-ctr".to_string()));
        assert_eq!(state.mac_s2c, Some("hmac-sha2-256".to_string()));
    }

    #[test]
    fn test_handshake_state_clone() {
        let mut state = HandshakeState::default();
        state.enc_c2s = Some("aes128-ctr".to_string());
        let cloned = state.clone();
        assert_eq!(state.enc_c2s, cloned.enc_c2s);
    }

    #[test]
    fn test_handshake_state_debug() {
        let state = HandshakeState::default();
        let debug = format!("{:?}", state);
        assert!(debug.contains("HandshakeState"));
    }

    // --- async version exchange ---

    #[tokio::test]
    async fn test_send_version_writes_correct_bytes() {
        let mut buf = Vec::new();
        send_version(&mut buf).await.unwrap();
        assert_eq!(buf, SSH_VERSION_STRING.as_bytes());
    }

    #[tokio::test]
    async fn test_send_version_custom() {
        let mut buf = Vec::new();
        send_version_custom(&mut buf, "SSH-2.0-test\r\n").await.unwrap();
        assert_eq!(buf, b"SSH-2.0-test\r\n");
    }

    #[tokio::test]
    async fn test_recv_version_valid() {
        let data = b"SSH-2.0-TestServer\r\n";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let version = recv_version(&mut cursor).await.unwrap();
        assert_eq!(version, "SSH-2.0-TestServer");
    }

    #[tokio::test]
    async fn test_server_banner_preserves_packet_boundary() {
        let mut data = b"\r\nNotice\r\nSSH-2.0-TestServer\r\n".to_vec();
        data.extend_from_slice(&[0, 0, 0, 12, 10, 21]);
        let mut cursor = std::io::Cursor::new(data);
        assert_eq!(recv_server_version(&mut cursor).await.unwrap(), "SSH-2.0-TestServer");
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, [0, 0, 0, 12, 10, 21]);
    }

    #[tokio::test]
    async fn test_server_banner_does_not_relax_identification_limit() {
        let mut data = b"Notice\r\nSSH-2.0-".to_vec();
        data.extend_from_slice(&[b'a'; 300]);
        data.extend_from_slice(b"\r\n");
        let mut cursor = std::io::Cursor::new(data);
        assert!(recv_server_version(&mut cursor).await.unwrap_err().to_string()
            .contains("Version string too long"));
    }

    #[tokio::test]
    async fn test_recv_version_lf_only() {
        let data = b"SSH-2.0-NoCarriageReturn\n";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let version = recv_version(&mut cursor).await.unwrap();
        assert_eq!(version, "SSH-2.0-NoCarriageReturn");
    }

    #[tokio::test]
    async fn test_recv_version_too_long() {
        let mut data = b"SSH-2.0-".to_vec();
        data.extend_from_slice(&[b'a'; 300]); // way over 255
        data.push(b'\n');
        let mut cursor = std::io::Cursor::new(data);
        let result = recv_version(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_recv_version_rejects_non_ssh_string() {
        // Simulates a telnet client pressing Enter — just "\r\n"
        let data = b"\r\n";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let result = recv_version(&mut cursor).await;
        assert!(result.is_err(), "Empty line should be rejected");
        assert!(result.unwrap_err().to_string().contains("Invalid SSH identification string"));
    }

    #[tokio::test]
    async fn test_recv_version_rejects_http_request() {
        let data = b"GET / HTTP/1.1\r\n";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let result = recv_version(&mut cursor).await;
        assert!(result.is_err(), "HTTP request should be rejected");
    }

    // --- constants ---

    #[test]
    fn test_version_string_constants() {
        assert!(SSH_VERSION_STRING.starts_with("SSH-2.0-"));
        assert!(SSH_VERSION_STRING.ends_with("\r\n"));
        assert!(SSH_SERVER_VERSION_STRING.starts_with("SSH-2.0-"));
        assert!(SSH_SERVER_VERSION_STRING.ends_with("\r\n"));
    }
}
