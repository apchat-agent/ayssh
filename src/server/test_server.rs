//! Test SSH Server - minimal server for crypto algorithm testing
//!
//! Implements just enough of the SSH server protocol to exercise all
//! crypto paths: version exchange, KEXINIT, key exchange, NEWKEYS,
//! service request, authentication, channel open, and data exchange.

use crate::error::SshError;
use crate::protocol::KexAlgorithm;
use crate::transport::handshake::{
    generate_server_kexinit_with_prefs, negotiate_algorithms, parse_server_kexinit,
    recv_version, send_version_custom, SSH_SERVER_VERSION_STRING,
};
use crate::transport::kex::KexContext;
use crate::transport::{EncryptionState, DecryptionState};

use super::encrypted_io::{build_unencrypted_packet, ServerEncryptedIO};
use super::host_key::HostKeyPair;

use bytes::{BufMut, BytesMut};
use std::str::FromStr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

/// Algorithm filter for controlling which algorithms the server offers
#[derive(Debug, Clone, Default)]
pub struct AlgorithmFilter {
    pub kex: Option<String>,
    pub cipher: Option<String>,
    pub mac: Option<String>,
}

/// Minimal SSH test server
pub struct TestSshServer {
    listener: TcpListener,
    host_key: HostKeyPair,
    filter: AlgorithmFilter,
}

impl TestSshServer {
    /// Create a new test server on the specified port (0 = OS-assigned)
    pub async fn new(port: u16) -> Result<Self, SshError> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| SshError::ConnectionError(format!("Failed to bind {}: {}", addr, e)))?;
        let host_key = HostKeyPair::generate_ed25519();
        info!("Test SSH server listening on {}", listener.local_addr().unwrap());

        Ok(Self {
            listener,
            host_key,
            filter: AlgorithmFilter::default(),
        })
    }

    /// Set the host key
    pub fn with_host_key(mut self, key: HostKeyPair) -> Self {
        self.host_key = key;
        self
    }

    /// Set algorithm filter
    pub fn with_filter(mut self, filter: AlgorithmFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Get the local address this server is listening on
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Accept one TCP connection and return the raw stream
    pub async fn accept_stream(&self) -> Result<TcpStream, SshError> {
        let (stream, addr) = self.listener.accept().await
            .map_err(|e| SshError::ConnectionError(format!("Accept failed: {}", e)))?;
        info!("Accepted connection from {}", addr);
        Ok(stream)
    }

    /// Perform SSH handshake + auth on a stream, returning an authenticated
    /// ServerEncryptedIO with an open channel ready for data exchange.
    /// Returns (io, client_channel_id) on success.
    pub async fn handshake_and_auth(&self, stream: TcpStream) -> Result<(ServerEncryptedIO, u32), SshError> {
        server_handshake(stream, &self.host_key, &self.filter).await
    }

    /// Accept one connection, do full SSH protocol with test data, then close
    pub async fn accept_one(&self) -> Result<(), SshError> {
        let stream = self.accept_stream().await?;
        let (mut io, client_channel) = self.handshake_and_auth(stream).await?;

        // Send test data
        let test_data = b"AYSSH_TEST_OK\n";
        let mut data_msg = BytesMut::new();
        data_msg.put_u8(94); // SSH_MSG_CHANNEL_DATA
        data_msg.put_u32(client_channel);
        data_msg.put_u32(test_data.len() as u32);
        data_msg.put_slice(test_data);
        io.send_message(&data_msg).await?;

        // Send EOF + CLOSE
        let mut eof = BytesMut::new();
        eof.put_u8(96);
        eof.put_u32(client_channel);
        io.send_message(&eof).await?;
        let mut close = BytesMut::new();
        close.put_u8(97);
        close.put_u32(client_channel);
        io.send_message(&close).await?;

        info!("Test connection handled successfully");
        Ok(())
    }
}

/// Auth behavior for the test server
#[derive(Debug, Clone)]
pub enum AuthBehavior {
    /// Permit credential-free access via none/password/keyboard-interactive.
    /// Public keys are rejected because this fixture has no authorized keys.
    AcceptAll,
    /// Reject auth with USERAUTH_FAILURE
    RejectPassword { available_methods: String },
    /// Handle keyboard-interactive auth (RFC 4256)
    KeyboardInteractive { expected_password: String },
    /// Reject first attempt with USERAUTH_FAILURE listing available_methods,
    /// then accept the second attempt. Used to test auth method fallback.
    RejectFirstThenAccept { available_methods: String },
    /// Accept public key authentication (send PK_OK then SUCCESS)
    AcceptPublicKey,
    /// Send UserauthBanner before accepting (RFC 4252 §5.4)
    SendBannerThenAccept { banner: String },
}

/// Read authentication requests until the client selects a recognized method.
/// RFC 4252 section 5 requires unknown methods to be rejected, even by a
/// credential-free test server. A rejection leaves authentication in progress.
async fn recv_auth_request(io: &mut ServerEncryptedIO, behavior: &AuthBehavior) -> Result<Vec<u8>, SshError> {
    // The default fixture does not configure or authorize any public keys.
    // In particular, an unsigned query must never produce USERAUTH_SUCCESS
    // (RFC 4252 section 7). Dedicated scripted modes retain their test policy.
    let allow_publickey = !matches!(behavior, AuthBehavior::AcceptAll);
    let available_methods: &[u8] = if allow_publickey {
        b"password,publickey,keyboard-interactive"
    } else {
        b"password,keyboard-interactive"
    };
    loop {
        let request = io.recv_message().await?;
        if request.first() != Some(&50) {
            return Err(SshError::ProtocolError(format!(
                "Expected USERAUTH_REQUEST (50), got {}", request.first().unwrap_or(&0)
            )));
        }
        let mut fields = &request[1..];
        let decode_error = |error: crate::protocol::types::SshError| SshError::ProtocolError(error.to_string());
        let _user = crate::protocol::SshString::decode(&mut fields).map_err(decode_error)?;
        let _service = crate::protocol::SshString::decode(&mut fields).map_err(decode_error)?;
        let method = crate::protocol::SshString::decode(&mut fields).map_err(decode_error)?;
        if matches!(method.as_bytes(), b"none" | b"password" | b"keyboard-interactive")
            || (method.as_bytes() == b"publickey" && allow_publickey)
        {
            return Ok(request);
        }
        send_auth_failure(io, available_methods).await?;
    }
}

async fn send_auth_failure(io: &mut ServerEncryptedIO, methods: &[u8]) -> Result<(), SshError> {
    let mut failure = BytesMut::new();
    failure.put_u8(51); // SSH_MSG_USERAUTH_FAILURE
    failure.put_u32(methods.len() as u32);
    failure.put_slice(methods);
    failure.put_u8(0); // partial_success = false
    io.send_message(&failure).await
}

/// Perform SSH handshake + auth on a connection.
/// Returns (ServerEncryptedIO, client_channel_id) ready for data exchange.
pub async fn server_handshake(
    stream: TcpStream,
    host_key: &HostKeyPair,
    filter: &AlgorithmFilter,
) -> Result<(ServerEncryptedIO, u32), SshError> {
    server_handshake_with_auth(stream, host_key, filter, &AuthBehavior::AcceptAll).await
}

/// Perform SSH handshake with configurable auth behavior.
/// With AcceptAll, returns (ServerEncryptedIO, client_channel_id) ready for data exchange.
/// With RejectPassword, sends USERAUTH_FAILURE and returns (io, 0).
pub async fn server_handshake_with_auth(
    stream: TcpStream,
    host_key: &HostKeyPair,
    filter: &AlgorithmFilter,
    auth_behavior: &AuthBehavior,
) -> Result<(ServerEncryptedIO, u32), SshError> {
    let mut io = ServerEncryptedIO::new(stream);
    let mut send_seq: u32 = 0;
    let mut recv_seq: u32 = 0;

    // Step 1: Version exchange (server sends first)
    send_version_custom(&mut io.stream, SSH_SERVER_VERSION_STRING).await?;
    let client_version = recv_version(&mut io.stream).await?;
    debug!("Client version: {}", client_version);

    // Step 2: Send server KEXINIT
    let server_kexinit = generate_server_kexinit_with_prefs(
        filter.kex.as_deref(),
        filter.cipher.as_deref(),
        filter.mac.as_deref(),
        host_key.supported_algorithms(),
    );
    let server_kexinit_packet = build_unencrypted_packet(&server_kexinit);
    io.stream.write_all(&server_kexinit_packet).await?;
    send_seq += 1;
    debug!("Sent server KEXINIT ({} bytes)", server_kexinit.len());

    // Step 3: Receive client KEXINIT
    let client_kexinit_packet = io.read_unencrypted_packet(30).await?;
    recv_seq += 1;
    let pkt_len = u32::from_be_bytes([
        client_kexinit_packet[0], client_kexinit_packet[1],
        client_kexinit_packet[2], client_kexinit_packet[3],
    ]) as usize;
    let pad_len = client_kexinit_packet[4] as usize;
    let client_kexinit_payload = &client_kexinit_packet[5..4 + pkt_len - pad_len];
    debug!("Received client KEXINIT ({} bytes payload)", client_kexinit_payload.len());

    // Step 4: Negotiate algorithms
    let server_proposal = parse_server_kexinit(&server_kexinit)
        .map_err(|e| SshError::ProtocolError(e.to_string()))?;
    let client_proposal = parse_server_kexinit(client_kexinit_payload)
        .map_err(|e| SshError::ProtocolError(e.to_string()))?;
    let strict_kex = client_proposal.kex_algorithms.iter().any(|a| a == "kex-strict-c-v00@openssh.com")
        && server_proposal.kex_algorithms.iter().any(|a| a == "kex-strict-s-v00@openssh.com");
    if strict_kex && (recv_seq != 1 || client_kexinit_payload.first() != Some(&20)) {
        return Err(SshError::ProtocolError("Strict KEX requires KEXINIT as the first packet".into()));
    }
    // For negotiation, the CLIENT's proposal takes priority (first match wins)
    let negotiated = match negotiate_algorithms(&client_proposal, &server_proposal) {
        Ok(algorithms) => algorithms,
        Err(error) => {
            crate::transport::handshake::disconnect_kex_failed(&mut io.stream).await;
            return Err(error);
        }
    };
    info!("Negotiated: kex={}, enc={}, mac={}", negotiated.kex, negotiated.enc_c2s, negotiated.mac_c2s);

    // Step 5: Key exchange (receive KEXDH_INIT, send KEXDH_REPLY)
    let kex_algorithm = KexAlgorithm::from_str(&negotiated.kex)
        .unwrap_or(KexAlgorithm::DiffieHellmanGroup14Sha256);

    let mut kex_context = KexContext::new(kex_algorithm);

    // Set version strings and KEXINIT payloads for exchange hash
    let client_ver_clean = client_version
        .strip_suffix("\r\n")
        .unwrap_or(client_version.strip_suffix('\n').unwrap_or(&client_version));
    let server_ver_clean = SSH_SERVER_VERSION_STRING
        .strip_suffix("\r\n")
        .unwrap_or(SSH_SERVER_VERSION_STRING);

    kex_context.set_exchange_info(
        client_ver_clean.as_bytes(),
        server_ver_clean.as_bytes(),
        client_kexinit_payload,
        &server_kexinit,
    );
    kex_context.set_server_host_key(&host_key.public_key_blob());

    if crate::transport::handshake::wrong_kex_guess(&client_proposal, &negotiated) {
        io.read_unencrypted_packet(30).await?;
        recv_seq += 1;
    }

    // Receive KEXDH_INIT (message type 30)
    let kexdh_init_packet = io.read_unencrypted_packet(30).await?;
    recv_seq += 1;
    let ki_pkt_len = u32::from_be_bytes([
        kexdh_init_packet[0], kexdh_init_packet[1],
        kexdh_init_packet[2], kexdh_init_packet[3],
    ]) as usize;
    let ki_pad_len = kexdh_init_packet[4] as usize;
    let kexdh_init_payload = &kexdh_init_packet[5..4 + ki_pkt_len - ki_pad_len];

    if kexdh_init_payload[0] != 30 {
        return Err(SshError::ProtocolError(format!("Expected KEXDH_INIT (30), got {}", kexdh_init_payload[0])));
    }

    // Extract client's ephemeral public key (e)
    let client_e_data = &kexdh_init_payload[1..]; // skip msg type
    // e is encoded as SSH string (length-prefixed)
    if client_e_data.len() < 4 {
        return Err(SshError::ProtocolError("KEXDH_INIT too short".to_string()));
    }
    let e_len = u32::from_be_bytes([client_e_data[0], client_e_data[1], client_e_data[2], client_e_data[3]]) as usize;
    let client_e = &client_e_data[4..4 + e_len];
    debug!("Client ephemeral key: {} bytes", client_e.len());

    // Generate server's ephemeral key and compute shared secret
    use rand::rngs::OsRng;
    kex_context.generate_client_key(&mut OsRng)?;
    let server_ephemeral = kex_context.client_ephemeral.clone().unwrap();

    // Process client's ephemeral key
    // process_server_kex_init expects the data AFTER the host key string
    // in KEXDH_REPLY format: [string Q_S][string sig]
    // For the server receiving KEXDH_INIT, the data is just [string e]
    // which is already length-prefixed in client_e_data
    debug!("Client e: {} bytes, first 4: {:?}", client_e.len(),
           &client_e[..std::cmp::min(4, client_e.len())]);
    // Wrap as length-prefixed for process_server_kex_init
    let mut client_e_for_kex = Vec::with_capacity(4 + client_e.len());
    client_e_for_kex.extend_from_slice(&(client_e.len() as u32).to_be_bytes());
    client_e_for_kex.extend_from_slice(client_e);
    if let Err(error) = kex_context.process_server_kex_init(&client_e_for_kex) {
        crate::transport::handshake::disconnect_kex_failed(&mut io.stream).await;
        return Err(error.into());
    }

    // For the exchange hash, swap client/server ephemeral keys:
    // client_ephemeral in KexContext = server's key (f), but for hash we need it as client's (e)
    // Let's set them correctly:
    // The hash needs: e = client's key, f = server's key
    // KexContext stores: client_ephemeral = what generate_client_key produced = server's f
    // server_ephemeral = what process_server_kex_init stored = client's e (length-prefixed)
    // But build_hash_input uses client_ephemeral as e and server_ephemeral as f
    // So we need to SWAP them for the server side:
    let _server_f = kex_context.client_ephemeral.take();
    let _client_e_lp = kex_context.server_ephemeral.take();
    kex_context.client_ephemeral = Some(client_e.to_vec()); // e = client's raw key
    kex_context.server_ephemeral = Some({
        // f needs to be length-prefixed for the hash
        let mut f_lp = Vec::with_capacity(4 + server_ephemeral.len());
        f_lp.extend_from_slice(&(server_ephemeral.len() as u32).to_be_bytes());
        f_lp.extend_from_slice(&server_ephemeral);
        f_lp
    });

    // Compute shared secret and session ID
    if let Err(error) = kex_context.compute_shared_secret() {
        // RFC 8731 section 3 defines an invalid peer key abort as a disconnect.
        crate::transport::handshake::disconnect_kex_failed(&mut io.stream).await;
        return Err(error.into());
    }
    let session_id = kex_context.session_id.clone().unwrap();
    debug!("Session ID computed ({} bytes)", session_id.len());

    // Sign the exchange hash with the host key
    let signature = host_key.sign_with_algorithm(&session_id, &negotiated.host_key)?;
    debug!("Exchange hash signed ({} bytes)", signature.len());

    // Build KEXDH_REPLY: msg_type(31) || string(K_S) || mpint(f) || string(sig)
    let host_key_blob = host_key.public_key_blob();
    let mut reply_payload = BytesMut::new();
    reply_payload.put_u8(31); // SSH_MSG_KEXDH_REPLY
    // K_S (host key blob as SSH string)
    reply_payload.put_u32(host_key_blob.len() as u32);
    reply_payload.put_slice(&host_key_blob);
    // f (server's ephemeral public key as SSH string/mpint)
    reply_payload.put_u32(server_ephemeral.len() as u32);
    reply_payload.put_slice(&server_ephemeral);
    // signature
    reply_payload.put_u32(signature.len() as u32);
    reply_payload.put_slice(&signature);

    let reply_packet = build_unencrypted_packet(&reply_payload);
    io.stream.write_all(&reply_packet).await?;
    send_seq += 1;
    debug!("Sent KEXDH_REPLY");

    // Step 6: NEWKEYS exchange
    let newkeys_msg = crate::transport::kex::encode_newkeys();
    io.stream.write_all(&newkeys_msg).await?;
    send_seq += 1;
    debug!("Sent NEWKEYS");

    // Receive client NEWKEYS
    let newkeys_packet = io.read_unencrypted_packet(30).await?;
    recv_seq += 1;
    if newkeys_packet.len() >= 6 && newkeys_packet[5] == 21 {
        debug!("Received client NEWKEYS");
    } else {
        return Err(SshError::ProtocolError("Expected NEWKEYS".to_string()));
    }

    // Derive session keys
    let session_keys = kex_context.derive_session_keys_directional(&session_id, &negotiated)?;

    if strict_kex {
        send_seq = 0;
        recv_seq = 0;
    }

    // Set up encryption: server encrypts with S2C keys, decrypts with C2S keys
    io.encrypt_state = Some(EncryptionState {
        enc_key: session_keys.enc_key_s2c.clone(),
        iv: session_keys.server_iv.clone(),
        mac_key: session_keys.mac_key_s2c.clone(),
        sequence_number: send_seq,
        aead_counter: 0,
        enc_algorithm: negotiated.enc_s2c.clone(),
        mac_algorithm: negotiated.mac_s2c.clone(),
        bytes_encrypted: 0,
    });
    io.decrypt_state = Some(DecryptionState {
        dec_key: session_keys.enc_key_c2s.clone(),
        iv: session_keys.client_iv.clone(),
        mac_key: session_keys.mac_key_c2s.clone(),
        sequence_number: recv_seq,
        aead_counter: 0,
        dec_algorithm: negotiated.enc_c2s.clone(),
        mac_algorithm: negotiated.mac_c2s.clone(),
    });
    info!("Encryption established: enc={}, mac={}", negotiated.enc_c2s, negotiated.mac_c2s);

    // RFC 8308 sections 2.3 and 3.1: the client marker permits a server extension message.
    if client_proposal.kex_algorithms.iter().any(|a| a == "ext-info-c") {
        let algorithms = b"ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521";
        let mut extensions = BytesMut::new();
        extensions.put_u8(7); // SSH_MSG_EXT_INFO
        extensions.put_u32(1);
        extensions.put_u32(15);
        extensions.put_slice(b"server-sig-algs");
        extensions.put_u32(algorithms.len() as u32);
        extensions.put_slice(algorithms);
        io.send_message(&extensions).await?;
    }

    // Step 7: Handle SERVICE_REQUEST
    let service_req = io.recv_message().await?;
    if service_req.is_empty() || service_req[0] != 5 {
        return Err(SshError::ProtocolError(format!("Expected SERVICE_REQUEST (5), got {}", service_req.get(0).unwrap_or(&0))));
    }
    debug!("Received SERVICE_REQUEST");

    // Send SERVICE_ACCEPT
    let mut accept = BytesMut::new();
    accept.put_u8(6); // SSH_MSG_SERVICE_ACCEPT
    accept.put_u32(12);
    accept.put_slice(b"ssh-userauth");
    io.send_message(&accept).await?;
    debug!("Sent SERVICE_ACCEPT");

    // Step 8: Handle USERAUTH_REQUEST
    let auth_req = recv_auth_request(&mut io, auth_behavior).await?;
    debug!("Received USERAUTH_REQUEST");

    match auth_behavior {
        AuthBehavior::AcceptAll => {
            // Send USERAUTH_SUCCESS
            io.send_message(&[52]).await?; // SSH_MSG_USERAUTH_SUCCESS
            debug!("Sent USERAUTH_SUCCESS");
        }
        AuthBehavior::RejectPassword { available_methods } => {
            // Send USERAUTH_FAILURE
            let mut fail_msg = BytesMut::new();
            fail_msg.put_u8(51); // SSH_MSG_USERAUTH_FAILURE
            let methods = available_methods.as_bytes();
            fail_msg.put_u32(methods.len() as u32);
            fail_msg.put_slice(methods);
            fail_msg.put_u8(0); // partial_success = false
            io.send_message(&fail_msg).await?;
            debug!("Sent USERAUTH_FAILURE");
            return Ok((io, 0));
        }
        AuthBehavior::KeyboardInteractive { expected_password } => {
            // Send SSH_MSG_USERAUTH_INFO_REQUEST (60) with one prompt
            let mut info_req = BytesMut::new();
            info_req.put_u8(60); // SSH_MSG_USERAUTH_INFO_REQUEST
            info_req.put_u32(0); // name (empty string)
            info_req.put_u32(0); // instruction (empty string)
            info_req.put_u32(0); // language tag (empty string)
            info_req.put_u32(1); // num-prompts = 1
            let prompt = b"Password: ";
            info_req.put_u32(prompt.len() as u32);
            info_req.put_slice(prompt);
            info_req.put_u8(0); // echo = false
            io.send_message(&info_req).await?;
            debug!("Sent USERAUTH_INFO_REQUEST");

            // Receive SSH_MSG_USERAUTH_INFO_RESPONSE (61)
            let info_resp = io.recv_message().await?;
            if info_resp.is_empty() || info_resp[0] != 61 {
                return Err(SshError::ProtocolError(format!(
                    "Expected USERAUTH_INFO_RESPONSE (61), got {}",
                    info_resp.get(0).unwrap_or(&0)
                )));
            }
            debug!("Received USERAUTH_INFO_RESPONSE");

            // Parse: num-responses (u32) + response[0] (string)
            let num_responses = u32::from_be_bytes([
                info_resp[1], info_resp[2], info_resp[3], info_resp[4],
            ]);
            if num_responses < 1 {
                return Err(SshError::ProtocolError("No responses in INFO_RESPONSE".to_string()));
            }
            let resp_len = u32::from_be_bytes([
                info_resp[5], info_resp[6], info_resp[7], info_resp[8],
            ]) as usize;
            let response_password = std::str::from_utf8(&info_resp[9..9 + resp_len])
                .unwrap_or("");

            if response_password == expected_password {
                // Send USERAUTH_SUCCESS
                io.send_message(&[52]).await?;
                debug!("Sent USERAUTH_SUCCESS (keyboard-interactive)");
                // Fall through to channel open handling
            } else {
                // Send USERAUTH_FAILURE
                let mut fail_msg = BytesMut::new();
                fail_msg.put_u8(51);
                let methods = b"keyboard-interactive";
                fail_msg.put_u32(methods.len() as u32);
                fail_msg.put_slice(methods);
                fail_msg.put_u8(0);
                io.send_message(&fail_msg).await?;
                debug!("Sent USERAUTH_FAILURE (wrong password)");
                return Ok((io, 0));
            }
        }
        AuthBehavior::RejectFirstThenAccept { available_methods } => {
            // First attempt: send USERAUTH_FAILURE with available methods
            let mut fail_msg = BytesMut::new();
            fail_msg.put_u8(51); // SSH_MSG_USERAUTH_FAILURE
            let methods = available_methods.as_bytes();
            fail_msg.put_u32(methods.len() as u32);
            fail_msg.put_slice(methods);
            fail_msg.put_u8(0); // partial_success = false
            io.send_message(&fail_msg).await?;
            debug!("Sent USERAUTH_FAILURE (reject first attempt), available: {}", available_methods);

            // Wait for second auth attempt
            let _auth_req2 = recv_auth_request(&mut io, auth_behavior).await?;
            debug!("Received second USERAUTH_REQUEST, accepting");

            // Accept second attempt
            io.send_message(&[52]).await?; // USERAUTH_SUCCESS
            debug!("Sent USERAUTH_SUCCESS on second attempt");
        }
        AuthBehavior::AcceptPublicKey => {
            // Parse the auth request to extract algorithm and public key blob
            // Format: byte(50) | string(username) | string(service) | string(method)
            //       | boolean(has_signature) | string(algorithm) | string(pubkey_blob)
            let mut offset = 1; // skip msg type (50)
            // username (string)
            let user_len = u32::from_be_bytes([auth_req[offset], auth_req[offset+1], auth_req[offset+2], auth_req[offset+3]]) as usize;
            offset += 4 + user_len;
            // service (string)
            let svc_len = u32::from_be_bytes([auth_req[offset], auth_req[offset+1], auth_req[offset+2], auth_req[offset+3]]) as usize;
            offset += 4 + svc_len;
            // method (string)
            let method_len = u32::from_be_bytes([auth_req[offset], auth_req[offset+1], auth_req[offset+2], auth_req[offset+3]]) as usize;
            offset += 4 + method_len;
            // has_signature (boolean)
            offset += 1; // skip boolean
            // algorithm name (string)
            let algo_len = u32::from_be_bytes([auth_req[offset], auth_req[offset+1], auth_req[offset+2], auth_req[offset+3]]) as usize;
            let algo = auth_req[offset+4..offset+4+algo_len].to_vec();
            offset += 4 + algo_len;
            // public key blob (string)
            let blob_len = u32::from_be_bytes([auth_req[offset], auth_req[offset+1], auth_req[offset+2], auth_req[offset+3]]) as usize;
            let blob = auth_req[offset+4..offset+4+blob_len].to_vec();

            // Send SSH_MSG_USERAUTH_PK_OK (60)
            let mut pk_ok = BytesMut::new();
            pk_ok.put_u8(60); // SSH_MSG_USERAUTH_PK_OK
            pk_ok.put_u32(algo_len as u32);
            pk_ok.put_slice(&algo);
            pk_ok.put_u32(blob_len as u32);
            pk_ok.put_slice(&blob);
            io.send_message(&pk_ok).await?;
            debug!("Sent SSH_MSG_USERAUTH_PK_OK for algorithm {:?}", std::str::from_utf8(&algo).unwrap_or("?"));

            // Receive second USERAUTH_REQUEST with signature
            let _auth_req2 = recv_auth_request(&mut io, auth_behavior).await?;

            // Accept unconditionally (don't verify signature)
            io.send_message(&[52]).await?; // USERAUTH_SUCCESS
            debug!("Sent USERAUTH_SUCCESS for public key auth");
        }
        AuthBehavior::SendBannerThenAccept { banner } => {
            // Send SSH_MSG_USERAUTH_BANNER (53) before accepting
            let mut banner_msg = BytesMut::new();
            banner_msg.put_u8(53); // SSH_MSG_USERAUTH_BANNER
            banner_msg.put_u32(banner.len() as u32);
            banner_msg.put_slice(banner.as_bytes());
            banner_msg.put_u32(0); // language tag (empty)
            io.send_message(&banner_msg).await?;
            debug!("Sent USERAUTH_BANNER: {}", banner);

            // Then accept
            io.send_message(&[52]).await?; // USERAUTH_SUCCESS
            debug!("Sent USERAUTH_SUCCESS after banner");
        }
    }

    // Step 9: Handle CHANNEL_OPEN
    let chan_open = io.recv_message().await?;
    if chan_open.is_empty() || chan_open[0] != 90 {
        return Err(SshError::ProtocolError(format!("Expected CHANNEL_OPEN (90), got {}", chan_open.get(0).unwrap_or(&0))));
    }
    debug!("Received CHANNEL_OPEN");

    // Parse sender channel from CHANNEL_OPEN
    // Format: type(1) || string(channel_type) || uint32(sender_channel) || uint32(window) || uint32(max_packet)
    let mut offset = 1;
    let ct_len = u32::from_be_bytes([chan_open[offset], chan_open[offset+1], chan_open[offset+2], chan_open[offset+3]]) as usize;
    offset += 4 + ct_len;
    let client_channel = u32::from_be_bytes([chan_open[offset], chan_open[offset+1], chan_open[offset+2], chan_open[offset+3]]);
    let server_channel: u32 = 0;

    // Send CHANNEL_OPEN_CONFIRMATION
    let mut conf = BytesMut::new();
    conf.put_u8(91); // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    conf.put_u32(client_channel); // recipient channel
    conf.put_u32(server_channel); // sender channel
    conf.put_u32(1048576); // window size
    conf.put_u32(32768); // max packet size
    io.send_message(&conf).await?;
    debug!("Sent CHANNEL_OPEN_CONFIRMATION");

    // Handle channel requests (pty-req, shell) - accept them all
    for _ in 0..10 {
        let msg = io.recv_message().await?;
        if msg.is_empty() { continue; }
        match msg[0] {
            98 => {
                // SSH_MSG_CHANNEL_REQUEST
                // Check if want_reply is set
                let want_reply = if msg.len() > 9 {
                    let req_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                    if msg.len() > 9 + req_len { msg[9 + req_len] != 0 } else { false }
                } else { false };

                if want_reply {
                    let mut success = BytesMut::new();
                    success.put_u8(99); // SSH_MSG_CHANNEL_SUCCESS
                    success.put_u32(client_channel);
                    io.send_message(&success).await?;
                }

                // Check if this is shell or exec request
                if msg.len() > 9 {
                    let req_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                    if msg.len() >= 9 + req_len {
                        let req_type = std::str::from_utf8(&msg[9..9+req_len]).unwrap_or("");
                        debug!("CHANNEL_REQUEST type={}", req_type);
                        if req_type == "shell" || req_type == "exec" || req_type == "subsystem" {
                            break; // Shell/exec/subsystem received, ready for data
                        }
                    }
                }
            }
            93 => {
                // SSH_MSG_CHANNEL_WINDOW_ADJUST
                debug!("Received CHANNEL_WINDOW_ADJUST");
                continue;
            }
            _ => {
                debug!("Received message type {} during channel setup", msg[0]);
                break;
            }
        }
    }

    info!("SSH handshake + auth + channel complete");
    Ok((io, client_channel))
}

use tokio::io::AsyncWriteExt;

/// Run an SFTP server on an already-established SSH channel.
/// Call this after server_handshake when the channel request type is "subsystem"
/// with name "sftp".
pub async fn run_sftp_server(
    io: &mut super::encrypted_io::ServerEncryptedIO,
    client_channel: u32,
    handler: std::sync::Arc<super::sftp_server::MemoryFs>,
) -> Result<(), SshError> {
    let server = super::sftp_server::SftpServerSession::new(handler);
    server.run(io, client_channel).await
}

/// Read the next CHANNEL_DATA message, skipping WINDOW_ADJUST and other protocol messages.
async fn recv_channel_data(
    io: &mut super::encrypted_io::ServerEncryptedIO,
) -> Result<Vec<u8>, SshError> {
    loop {
        let msg = io.recv_message().await?;
        if msg.is_empty() { continue; }
        match msg[0] {
            94 => return Ok(msg), // CHANNEL_DATA
            93 => continue,       // WINDOW_ADJUST — skip
            _ => continue,        // skip other protocol messages
        }
    }
}

/// Handle SCP upload (scp -t) on the server side.
/// Reads the file data sent by the client and returns it.
pub async fn handle_scp_upload(
    io: &mut super::encrypted_io::ServerEncryptedIO,
    client_channel: u32,
) -> Result<(String, Vec<u8>), SshError> {
    // Send initial OK (\0) to signal ready
    let mut ok_msg = BytesMut::new();
    ok_msg.put_u8(94); // CHANNEL_DATA
    ok_msg.put_u32(client_channel);
    ok_msg.put_u32(1);
    ok_msg.put_u8(0); // \0 = OK
    io.send_message(&ok_msg).await?;

    // Read file header: "C<mode> <size> <filename>\n"
    let header_msg = recv_channel_data(io).await?;
    let data_len = u32::from_be_bytes([header_msg[5], header_msg[6], header_msg[7], header_msg[8]]) as usize;
    let header_bytes = &header_msg[9..9 + data_len];
    let header = String::from_utf8_lossy(header_bytes).to_string();

    if !header.starts_with('C') {
        return Err(SshError::ProtocolError(format!("SCP: expected C header, got: {}", header)));
    }

    // Parse "C<mode> <size> <filename>\n"
    let parts: Vec<&str> = header.trim().splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(SshError::ProtocolError(format!("SCP: malformed header: {}", header)));
    }
    let file_size: usize = parts[1].parse()
        .map_err(|_| SshError::ProtocolError(format!("SCP: bad size: {}", parts[1])))?;
    let filename = parts[2].to_string();

    // Send OK for header
    let mut ok2 = BytesMut::new();
    ok2.put_u8(94); ok2.put_u32(client_channel);
    ok2.put_u32(1); ok2.put_u8(0);
    io.send_message(&ok2).await?;

    // Read file data (may come in multiple CHANNEL_DATA messages).
    // Skip WINDOW_ADJUST (93) and other protocol messages.
    let mut file_data = Vec::with_capacity(file_size);
    while file_data.len() < file_size + 1 { // +1 for trailing \0
        let msg = recv_channel_data(io).await?;
        let len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
        file_data.extend_from_slice(&msg[9..9 + len]);
    }
    // Trim to file_size (remove trailing \0)
    file_data.truncate(file_size);

    // Send final OK
    let mut ok3 = BytesMut::new();
    ok3.put_u8(94); ok3.put_u32(client_channel);
    ok3.put_u32(1); ok3.put_u8(0);
    io.send_message(&ok3).await?;

    Ok((filename, file_data))
}

/// Handle SCP download (scp -f) on the server side.
/// Sends the given file data to the client.
pub async fn handle_scp_download(
    io: &mut super::encrypted_io::ServerEncryptedIO,
    client_channel: u32,
    filename: &str,
    data: &[u8],
    mode: u32,
) -> Result<(), SshError> {
    // Wait for initial ready signal (\0) from client
    let _ready_msg = recv_channel_data(io).await?;

    // Send file header: "C<mode> <size> <filename>\n"
    let header = format!("C{:04o} {} {}\n", mode, data.len(), filename);
    let mut header_msg = BytesMut::new();
    header_msg.put_u8(94); // CHANNEL_DATA
    header_msg.put_u32(client_channel);
    header_msg.put_u32(header.len() as u32);
    header_msg.put_slice(header.as_bytes());
    io.send_message(&header_msg).await?;

    // Wait for OK (skip WINDOW_ADJUST)
    let _ok_msg = recv_channel_data(io).await?;

    // Send file data
    let mut data_msg = BytesMut::new();
    data_msg.put_u8(94);
    data_msg.put_u32(client_channel);
    data_msg.put_u32(data.len() as u32);
    data_msg.put_slice(data);
    io.send_message(&data_msg).await?;

    // Send completion \0
    let mut done_msg = BytesMut::new();
    done_msg.put_u8(94);
    done_msg.put_u32(client_channel);
    done_msg.put_u32(1);
    done_msg.put_u8(0);
    io.send_message(&done_msg).await?;

    // Wait for client's final OK
    let _ = io.recv_message().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drain remaining channel messages (EOF, CLOSE) so the server
    /// doesn't hit broken pipe when the client drops the connection.
    async fn drain_channel_close(transport: &mut crate::transport::Transport) {
        for _ in 0..5 {
            match transport.recv_message().await {
                Ok(msg) if !msg.is_empty() && msg[0] == 97 => break, // CHANNEL_CLOSE
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    #[tokio::test]
    async fn test_server_binds_to_random_port() {
        let server = TestSshServer::new(0).await.unwrap();
        let addr = server.local_addr();
        assert_ne!(addr.port(), 0);
    }

    /// Basic server-client end-to-end test with default algorithms.
    /// Basic server-client smoke test with default algorithms.
    /// Uses run_crypto_test to avoid spawning extra threads that could
    /// interfere with test_crypto_matrix when run in parallel.
    #[test]
    fn test_server_accepts_client_connection() {
        run_crypto_test(None, None, None);
    }

    // Old inline test removed - replaced by run_crypto_test() above

    #[test]
    #[ignore = "dead code placeholder"]
    fn _removed() {
        use std::sync::mpsc;
        let t0 = std::time::Instant::now();
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake(stream, &host_key, &filter).await
                    .expect("Server handshake failed");

                let mut msg = BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"AYSSH_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();

                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                io.send_message(&eof).await.unwrap();
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                io.send_message(&close).await.unwrap();
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.expect("Client handshake failed");
                transport.send_service_request("ssh-userauth").await.unwrap();
                let svc = transport.recv_service_accept().await.unwrap();
                assert_eq!(svc, "ssh-userauth");

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("test".to_string());
                auth.available_methods.insert("password".to_string());
                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Success));

                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap();

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+len]).unwrap_or("");
                assert!(text.contains("AYSSH_TEST_OK"), "Got {:?}", text);

                // Drain EOF + CLOSE so server doesn't hit broken pipe
                drain_channel_close(&mut transport).await;
            });
        });

        server.join().expect("Server thread panicked");
        client.join().expect("Client thread panicked");
        eprintln!("[TEST] server-client e2e: {:?}", t0.elapsed());
    }

    /// Helper: run a full server-client handshake with specific algorithm preferences and host key
    fn run_crypto_test_with_host_key(
        host_key: HostKeyPair,
        kex: Option<&str>,
        cipher: Option<&str>,
        mac: Option<&str>,
    ) {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let kex_s = kex.map(|s| s.to_string());
        let cipher_s = cipher.map(|s| s.to_string());
        let mac_s = mac.map(|s| s.to_string());

        let kex_c = kex_s.clone();
        let cipher_c = cipher_s.clone();
        let mac_c = mac_s.clone();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let filter = AlgorithmFilter {
                    kex: kex_s, cipher: cipher_s, mac: mac_s,
                };
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake(stream, &host_key, &filter).await
                    .expect("Server handshake failed");

                // Send test data + EOF + CLOSE
                let mut msg = BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"AYSSH_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();
                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                io.send_message(&eof).await.unwrap();
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                io.send_message(&close).await.unwrap();
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                if let Some(ref k) = kex_c { transport.set_preferred_kex(k); }
                if let Some(ref c) = cipher_c { transport.set_preferred_cipher(c); }
                if let Some(ref m) = mac_c { transport.set_preferred_mac(m); }

                transport.handshake().await.expect("Handshake failed");
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("test".to_string());
                auth.available_methods.insert("password".to_string());
                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Success));

                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap();

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+len]).unwrap_or("");
                assert!(text.contains("AYSSH_TEST_OK"), "Got {:?}", text);

                // Drain EOF + CLOSE so server doesn't hit broken pipe
                drain_channel_close(&mut transport).await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Helper: run a full server-client handshake with specific algorithm preferences
    fn run_crypto_test(kex: Option<&str>, cipher: Option<&str>, mac: Option<&str>) {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let kex_s = kex.map(|s| s.to_string());
        let cipher_s = cipher.map(|s| s.to_string());
        let mac_s = mac.map(|s| s.to_string());

        let kex_c = kex_s.clone();
        let cipher_c = cipher_s.clone();
        let mac_c = mac_s.clone();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter {
                    kex: kex_s, cipher: cipher_s, mac: mac_s,
                };
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake(stream, &host_key, &filter).await
                    .expect("Server handshake failed");

                // Send test data + EOF + CLOSE
                let mut msg = BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"AYSSH_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();
                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                io.send_message(&eof).await.unwrap();
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                io.send_message(&close).await.unwrap();
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                if let Some(ref k) = kex_c { transport.set_preferred_kex(k); }
                if let Some(ref c) = cipher_c { transport.set_preferred_cipher(c); }
                if let Some(ref m) = mac_c { transport.set_preferred_mac(m); }

                transport.handshake().await.expect("Handshake failed");
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("test".to_string());
                auth.available_methods.insert("password".to_string());
                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Success));

                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap();

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+len]).unwrap_or("");
                assert!(text.contains("AYSSH_TEST_OK"), "Got {:?}", text);

                // Drain EOF + CLOSE so server doesn't hit broken pipe
                drain_channel_close(&mut transport).await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test keyboard-interactive authentication (RFC 4256).
    #[test]
    fn test_keyboard_interactive_auth() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth_behavior = AuthBehavior::KeyboardInteractive {
                    expected_password: "test_password".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake_with_auth(stream, &host_key, &filter, &auth_behavior).await
                    .expect("Server handshake failed");

                // Send test data
                let mut msg = BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"AYSSH_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();
                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                io.send_message(&eof).await.unwrap();
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                io.send_message(&close).await.unwrap();
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.expect("Handshake failed");
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_keyboard_interactive_handler(|_challenge| {
                        // Return the password for any prompt
                        Ok(vec!["test_password".to_string()])
                    });
                auth.available_methods.insert("keyboard-interactive".to_string());
                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Success),
                    "Expected Success, got {:?}", r);

                // Verify we can receive data through the channel
                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap();

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+len]).unwrap_or("");
                assert!(text.contains("AYSSH_TEST_OK"), "Got {:?}", text);

                // Drain EOF + CLOSE so server doesn't hit broken pipe
                drain_channel_close(&mut transport).await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test with RSA host key instead of Ed25519
    #[test]
    fn test_rsa_host_key() {
        let path = std::path::Path::new("tests/keys/test_rsa_2048");
        let host_key = HostKeyPair::load_openssh_rsa(path)
            .expect("Failed to load RSA test key");
        run_crypto_test_with_host_key(
            host_key,
            Some("diffie-hellman-group14-sha256"),
            Some("aes128-ctr"),
            Some("hmac-sha1"),
        );
    }

    /// Test RSA host key with curve25519 KEX
    #[test]
    fn test_rsa_host_key_curve25519() {
        let path = std::path::Path::new("tests/keys/test_rsa_2048");
        let host_key = HostKeyPair::load_openssh_rsa(path)
            .expect("Failed to load RSA test key");
        run_crypto_test_with_host_key(
            host_key,
            Some("curve25519-sha256"),
            Some("aes256-ctr"),
            Some("hmac-sha2-256"),
        );
    }

    /// Exhaustive crypto combination test.
    /// Runs all KEX × cipher × MAC combinations sequentially in a single test
    /// to avoid thread starvation from 28+ parallel server-client pairs.
    #[test]
    fn test_crypto_matrix() {
        let kex_algorithms = [
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group14-sha256",
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
        ];

        let ciphers = [
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
        ];

        let aead_ciphers = [
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ];

        let macs = [
            "hmac-sha1",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
        ];

        let mut passed = 0;
        let mut failed = Vec::new();
        let t0 = std::time::Instant::now();

        // Test each KEX with a representative cipher+MAC
        for kex in &kex_algorithms {
            let label = format!("kex={}", kex);
            eprint!("  {} ... ", label);
            match std::panic::catch_unwind(|| {
                run_crypto_test(Some(kex), Some("aes128-ctr"), Some("hmac-sha1"));
            }) {
                Ok(()) => { passed += 1; eprintln!("ok"); }
                Err(_) => { failed.push(label); eprintln!("FAILED"); }
            }
        }

        // Test each non-AEAD cipher with a fixed KEX+MAC
        for cipher in &ciphers {
            let label = format!("cipher={}", cipher);
            eprint!("  {} ... ", label);
            match std::panic::catch_unwind(|| {
                run_crypto_test(Some("curve25519-sha256"), Some(cipher), Some("hmac-sha1"));
            }) {
                Ok(()) => { passed += 1; eprintln!("ok"); }
                Err(_) => { failed.push(label); eprintln!("FAILED"); }
            }
        }

        // Test each AEAD cipher (MAC is implicit)
        for cipher in &aead_ciphers {
            let label = format!("aead={}", cipher);
            eprint!("  {} ... ", label);
            match std::panic::catch_unwind(|| {
                run_crypto_test(Some("curve25519-sha256"), Some(cipher), None);
            }) {
                Ok(()) => { passed += 1; eprintln!("ok"); }
                Err(_) => { failed.push(label); eprintln!("FAILED"); }
            }
        }

        // Test each MAC with a fixed KEX+cipher
        for mac in &macs {
            let label = format!("mac={}", mac);
            eprint!("  {} ... ", label);
            match std::panic::catch_unwind(|| {
                run_crypto_test(Some("curve25519-sha256"), Some("aes256-ctr"), Some(mac));
            }) {
                Ok(()) => { passed += 1; eprintln!("ok"); }
                Err(_) => { failed.push(label); eprintln!("FAILED"); }
            }
        }

        // Cross-combination spot checks
        let combos: Vec<(&str, &str, Option<&str>)> = vec![
            ("curve25519-sha256", "aes256-ctr", Some("hmac-sha2-256")),
            ("ecdh-sha2-nistp256", "aes256-cbc", Some("hmac-sha2-512")),
            ("ecdh-sha2-nistp384", "aes192-ctr", Some("hmac-sha1-etm@openssh.com")),
            ("diffie-hellman-group1-sha1", "aes128-cbc", Some("hmac-sha2-256-etm@openssh.com")),
            ("curve25519-sha256", "aes128-gcm@openssh.com", None),
            ("ecdh-sha2-nistp521", "aes256-gcm@openssh.com", None),
            ("diffie-hellman-group14-sha1", "aes256-ctr", Some("hmac-sha2-512-etm@openssh.com")),
        ];

        for (kex, cipher, mac) in &combos {
            let label = format!("combo: {} + {} + {}", kex, cipher, mac.unwrap_or("implicit"));
            eprint!("  {} ... ", label);
            match std::panic::catch_unwind(|| {
                run_crypto_test(Some(kex), Some(cipher), *mac);
            }) {
                Ok(()) => { passed += 1; eprintln!("ok"); }
                Err(_) => { failed.push(label); eprintln!("FAILED"); }
            }
        }

        let total = passed + failed.len();
        eprintln!("\n  Crypto matrix: {}/{} passed in {:?}", passed, total, t0.elapsed());

        if !failed.is_empty() {
            panic!("Crypto matrix: {} failures:\n  {}", failed.len(), failed.join("\n  "));
        }
    }

    /// Test that wrong password is properly rejected by the server.
    #[test]
    fn test_wrong_password_rejected() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth_behavior = AuthBehavior::RejectPassword {
                    available_methods: "password".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                server_handshake_with_auth(stream, &host_key, &filter, &auth_behavior).await
                    .expect("Server handshake failed");
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.expect("Handshake failed");
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("wrong_password".to_string());
                auth.available_methods.insert("password".to_string());
                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Failure { .. }),
                    "Expected Failure, got {:?}", r);
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test RSA public key authentication (Priority 2.1).
    /// Client sends publickey probe, server responds with PK_OK,
    /// client sends signed request, server accepts.
    #[test]
    fn test_rsa_publickey_auth() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth_behavior = AuthBehavior::AcceptPublicKey;
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake_with_auth(stream, &host_key, &filter, &auth_behavior).await
                    .expect("Server handshake failed");
                // Send test data + EOF + CLOSE
                let mut msg = BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"AYSSH_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();
                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                io.send_message(&eof).await.unwrap();
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                io.send_message(&close).await.unwrap();
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let key_data = std::fs::read("tests/keys/test_rsa_2048").unwrap();
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.expect("Handshake failed");
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_private_key(key_data);
                auth.available_methods.insert("publickey".to_string());
                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Success),
                    "Expected Success, got {:?}", r);

                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap();

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+len]).unwrap_or("");
                assert!(text.contains("AYSSH_TEST_OK"), "Got {:?}", text);

                // Drain EOF + CLOSE so server doesn't hit broken pipe
                drain_channel_close(&mut transport).await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test large data transfer (>32KB) across multiple CHANNEL_DATA messages.
    /// Exercises the multi-packet data path and verifies data integrity.
    #[test]
    fn test_large_data_transfer() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        // Generate 100KB of patterned data
        let total_size: usize = 100 * 1024;
        let test_data: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();
        let test_data_clone = test_data.clone();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake(stream, &host_key, &filter).await
                    .expect("Server handshake failed");

                // Send data in chunks of 16KB (under max_packet=32KB)
                let chunk_size = 16 * 1024;
                for chunk in test_data_clone.chunks(chunk_size) {
                    let mut msg = BytesMut::new();
                    msg.put_u8(94); // CHANNEL_DATA
                    msg.put_u32(ch);
                    msg.put_u32(chunk.len() as u32);
                    msg.put_slice(chunk);
                    io.send_message(&msg).await.unwrap();
                }

                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                let _ = io.send_message(&eof).await;
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                let _ = io.send_message(&close).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.unwrap();
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("test".to_string());
                auth.available_methods.insert("password".to_string());
                auth.authenticate().await.unwrap();

                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap(); // channel success

                // Read all CHANNEL_DATA messages and reassemble
                let mut received = Vec::new();
                loop {
                    let msg = transport.recv_message().await.unwrap();
                    if msg.is_empty() { continue; }
                    match msg[0] {
                        94 => { // CHANNEL_DATA
                            let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                            received.extend_from_slice(&msg[9..9+data_len]);
                        }
                        96 | 97 => break, // EOF or CLOSE
                        _ => {}
                    }
                }

                // Drain remaining
                for _ in 0..5 {
                    match transport.recv_message().await {
                        Ok(msg) if !msg.is_empty() && msg[0] == 97 => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }

                assert_eq!(received.len(), test_data.len(),
                    "Expected {} bytes, got {}", test_data.len(), received.len());
                assert_eq!(received, test_data,
                    "Data mismatch at byte {}", received.iter().zip(test_data.iter())
                        .position(|(a, b)| a != b).unwrap_or(received.len()));
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test that the client handles connection timeout (server accepts TCP but never speaks).
    #[test]
    fn test_connection_timeout() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        // Server: accept TCP connection but never send anything
        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                // Hold the stream open but never send version string
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                drop(stream);
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
                let mut transport = crate::transport::Transport::new(stream);

                // Handshake should timeout or fail (server never sends version)
                let start = std::time::Instant::now();
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    transport.handshake(),
                ).await;

                let elapsed = start.elapsed();
                assert!(elapsed < std::time::Duration::from_secs(5),
                    "Should timeout within 5s, took {:?}", elapsed);

                match result {
                    Err(_) => {
                        // Timeout — expected
                        eprintln!("[timeout_test] Correctly timed out after {:?}", elapsed);
                    }
                    Ok(Err(_)) => {
                        // Connection error — also acceptable
                        eprintln!("[timeout_test] Got connection error after {:?}", elapsed);
                    }
                    Ok(Ok(())) => {
                        panic!("Handshake should not succeed against silent server");
                    }
                }
            });
        });

        client.join().expect("Client panicked");
        // Don't wait for server — it's sleeping
        drop(server);
    }

    /// Test that the client handles server dropping connection mid-handshake.
    #[test]
    fn test_server_drops_mid_handshake() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let (mut stream, _) = listener.accept().await.unwrap();
                // Send version string then immediately close
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"SSH-2.0-evil_server\r\n").await;
                stream.shutdown().await.unwrap();
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
                let mut transport = crate::transport::Transport::new(stream);
                let result = transport.handshake().await;
                assert!(result.is_err(), "Handshake should fail when server drops mid-handshake");
                eprintln!("[drop_test] Got expected error: {}", result.unwrap_err());
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test that the server handles malformed data without crashing.
    /// Sends garbage bytes after TCP connect — the server should error gracefully.
    #[test]
    fn test_server_handles_malformed_data() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let (stream, _) = listener.accept().await.unwrap();

                // server_handshake should fail gracefully, not panic
                let result = server_handshake(stream, &host_key, &filter).await;
                assert!(result.is_err(), "Server should reject malformed data");
                eprintln!("[malformed_test] Server correctly rejected: {}", result.err().unwrap());
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
                // Send garbage instead of SSH version string
                use tokio::io::AsyncWriteExt;
                stream.write_all(b"\x00\x00\x00\xFF GARBAGE DATA NOT SSH\n").await.unwrap();
                // Give server time to process
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            });
        });

        // Client thread finishes first
        client.join().expect("Client panicked");
        server.join().expect("Server thread panicked (should have handled error gracefully)");
    }

    /// Test that the server handles premature disconnect without crashing.
    #[test]
    fn test_server_handles_premature_disconnect() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let (stream, _) = listener.accept().await.unwrap();

                let result = server_handshake(stream, &host_key, &filter).await;
                assert!(result.is_err(), "Server should handle disconnect gracefully");
                eprintln!("[premature_disconnect] Server correctly handled: {}", result.err().unwrap());
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
                // Send valid version string, then disconnect immediately
                use tokio::io::AsyncWriteExt;
                stream.write_all(b"SSH-2.0-test_client\r\n").await.unwrap();
                stream.shutdown().await.unwrap();
            });
        });

        client.join().expect("Client panicked");
        server.join().expect("Server thread panicked (should have handled disconnect gracefully)");
    }

    /// Test auth method fallback: server rejects publickey, client falls back to password.
    #[test]
    fn test_auth_method_fallback() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth_behavior = AuthBehavior::RejectFirstThenAccept {
                    available_methods: "password".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake_with_auth(stream, &host_key, &filter, &auth_behavior).await
                    .expect("Server handshake failed");

                // Send test data
                let mut msg = BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"FALLBACK_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();
                let mut eof = BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                let _ = io.send_message(&eof).await;
                let mut close = BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                let _ = io.send_message(&close).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.unwrap();
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                // Configure auth with publickey (will be rejected) and password (will succeed)
                let key_data = std::fs::read("tests/keys/test_ed25519").unwrap();
                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_private_key(key_data)
                    .with_password("test".to_string())
                    .with_method_order(vec!["publickey".to_string(), "password".to_string()]);

                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Success),
                    "Expected Success after fallback, got {:?}", r);

                // Verify we can use the connection
                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let ch = session.remote_channel_id();
                transport.send_channel_request(ch, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap();

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+len]).unwrap_or("");
                assert!(text.contains("FALLBACK_OK"), "Got {:?}", text);

                drain_channel_close(&mut transport).await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test auth fallback with handler that aborts.
    #[test]
    fn test_auth_fallback_handler_abort() {
        use std::sync::mpsc;
        let (port_tx, port_rx) = mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth_behavior = AuthBehavior::RejectPassword {
                    available_methods: "password".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                // This will return early since client aborts
                let _ = server_handshake_with_auth(stream, &host_key, &filter, &auth_behavior).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap()
                );
                transport.handshake().await.unwrap();
                transport.send_service_request("ssh-userauth").await.unwrap();
                transport.recv_service_accept().await.unwrap();

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("test".to_string())
                    .with_method_order(vec!["password".to_string()])
                    .with_fallback_handler(|_ctx| {
                        // Always abort — don't try anything else
                        crate::auth::AuthFallbackVerdict::Abort
                    });
                auth.available_methods.insert("password".to_string());

                let r = auth.authenticate().await.unwrap();
                assert!(matches!(r, crate::auth::AuthenticationResult::Failure { .. }),
                    "Expected Failure after abort, got {:?}", r);
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }
}
