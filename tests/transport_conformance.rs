use ayssh::server::{encrypted_io::{build_unencrypted_packet, ServerEncryptedIO}, host_key::HostKeyPair, test_server::{server_handshake, AlgorithmFilter}};
use ayssh::transport::{handshake::{generate_client_kexinit_with_prefs, recv_version}, kex::KexContext};
use ayssh::protocol::KexAlgorithm;
use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpStream}};

fn replace_list(payload: &mut Vec<u8>, field: usize, list: &str) {
    let mut offset = 17;
    for _ in 0..field {
        let len = u32::from_be_bytes(payload[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4 + len;
    }
    let len = u32::from_be_bytes(payload[offset..offset+4].try_into().unwrap()) as usize;
    let mut replacement = (list.len() as u32).to_be_bytes().to_vec();
    replacement.extend_from_slice(list.as_bytes());
    payload.splice(offset..offset+4+len, replacement);
}

async fn start(key: HostKeyPair) -> (ServerEncryptedIO, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(async move { let _ = server_handshake(server, &key, &AlgorithmFilter::default()).await; });
    let mut io = ServerEncryptedIO::new(stream);
    io.stream.write_all(b"SSH-2.0-regression\r\n").await.unwrap();
    recv_version(&mut io.stream).await.unwrap();
    (io, task)
}

#[tokio::test]
async fn client_processes_server_pre_version_lines() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(async move {
        let mut transport = ayssh::transport::Transport::new(stream);
        let _ = transport.handshake().await;
    });
    let mut io = ServerEncryptedIO::new(server);
    // Banner lines may be longer than the identification's 255-byte limit.
    let mut introduction = b"Welcome to the test server\r\n".to_vec();
    introduction.extend_from_slice(&[b'x'; 512]);
    introduction.extend_from_slice(b"\r\nSSH-2.0-regression\r\n");
    io.stream.write_all(&introduction).await.unwrap();
    recv_version(&mut io.stream).await.unwrap();
    let packet = io.read_unencrypted_packet(3).await;
    task.abort();
    assert_eq!(packet.expect("client must continue to KEXINIT after banner lines")[5], 20);
}

#[tokio::test]
async fn wrong_kex_guess_discarded() {
    for wrong_host in [false, true] {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    io.read_unencrypted_packet(3).await.unwrap();
    let mut offer = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), None, None);
    replace_list(&mut offer, 0, if wrong_host { "curve25519-sha256" } else { "unknown-kex,curve25519-sha256" });
    replace_list(&mut offer, 1, if wrong_host { "unknown-host,ssh-ed25519" } else { "ssh-ed25519" });
    let follows = offer.len() - 5;
    offer[follows] = 1;
    io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
    io.stream.write_all(&build_unencrypted_packet(&[200])).await.unwrap();
    let mut ctx = KexContext::new(KexAlgorithm::Curve25519Sha256);
    ctx.generate_client_key(&mut rand::rngs::OsRng).unwrap();
    let public = ctx.client_ephemeral.unwrap();
    let mut init = vec![30];
    init.extend_from_slice(&(public.len() as u32).to_be_bytes());
    init.extend_from_slice(&public);
    io.stream.write_all(&build_unencrypted_packet(&init)).await.unwrap();
    let reply = io.read_unencrypted_packet(3).await.unwrap();
    assert_eq!(reply[5], 31);
    task.abort();
    }
}

fn read_string<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    let value = &data[4..4+len];
    *data = &data[4+len..];
    value
}

#[tokio::test]
async fn rsa_sha2_signature_negotiated() {
    for algorithm in ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"] {
        let key = HostKeyPair::generate_rsa(1024).unwrap();
        let (mut io, task) = start(key).await;
        io.read_unencrypted_packet(3).await.unwrap();
        let mut offer = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), None, None);
        replace_list(&mut offer, 1, algorithm);
        io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
        let mut ctx = KexContext::new(KexAlgorithm::Curve25519Sha256);
        ctx.generate_client_key(&mut rand::rngs::OsRng).unwrap();
        let public = ctx.client_ephemeral.unwrap();
        let mut init = vec![30];
        init.extend_from_slice(&(public.len() as u32).to_be_bytes());
        init.extend_from_slice(&public);
        io.stream.write_all(&build_unencrypted_packet(&init)).await.unwrap();
        let reply = io.read_unencrypted_packet(3).await.unwrap();
        let end = reply.len() - reply[4] as usize;
        let mut payload = &reply[6..end];
        let _host_key = read_string(&mut payload);
        let _ephemeral = read_string(&mut payload);
        let mut signature = read_string(&mut payload);
        assert_eq!(read_string(&mut signature), algorithm.as_bytes());
        task.abort();
    }
}

#[test]
fn rsa_signature_hash_and_label() {
    use sha2::Digest;
    let key = HostKeyPair::generate_rsa(1024).unwrap();
    let private = match &key { HostKeyPair::Rsa(key) => key, _ => unreachable!() };
    let public = rsa::RsaPublicKey::from(private.as_ref());
    for algorithm in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
        let encoded = key.sign_with_algorithm(b"exchange hash", algorithm).unwrap();
        let mut signature = encoded.as_slice();
        assert_eq!(read_string(&mut signature), algorithm.as_bytes());
        let bytes = read_string(&mut signature);
        let (scheme, hash) = match algorithm {
            "rsa-sha2-256" => (rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), sha2::Sha256::digest(b"exchange hash").to_vec()),
            "rsa-sha2-512" => (rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), sha2::Sha512::digest(b"exchange hash").to_vec()),
            _ => (rsa::Pkcs1v15Sign::new::<sha1::Sha1>(), sha1::Sha1::digest(b"exchange hash").to_vec()),
        };
        public.verify(scheme, &hash, bytes).unwrap();
    }
}

#[tokio::test]
async fn server_advertises_kex_strict() {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    let packet = io.read_unencrypted_packet(3).await.unwrap();
    let end = packet.len() - packet[4] as usize;
    let proposal = ayssh::transport::handshake::parse_server_kexinit(&packet[5..end]).unwrap();
    assert!(proposal.kex_algorithms.iter().any(|a| a == "kex-strict-s-v00@openssh.com"));
    assert!(!proposal.kex_algorithms.iter().any(|a| a == "kex-strict-c-v00@openssh.com"));
    task.abort();
}

async fn exchange(kex_list: &str, mac_c2s: &str, mac_s2c: &str) -> (ServerEncryptedIO, tokio::task::JoinHandle<()>, ayssh::transport::kex::SessionKeys) {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    let server_offer_packet = io.read_unencrypted_packet(3).await.unwrap();
    let end = server_offer_packet.len() - server_offer_packet[4] as usize;
    let server_offer = &server_offer_packet[5..end];
    let mut offer = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), Some("aes128-cbc"), Some(mac_c2s));
    replace_list(&mut offer, 0, kex_list);
    replace_list(&mut offer, 1, "ssh-ed25519");
    replace_list(&mut offer, 4, mac_c2s);
    replace_list(&mut offer, 5, mac_s2c);
    io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
    let kex = kex_list.split(',').next().unwrap().parse().unwrap();
    let mut ctx = KexContext::new(kex);
    ctx.generate_client_key(&mut rand::rngs::OsRng).unwrap();
    let public = ctx.client_ephemeral.clone().unwrap();
    let mut init = vec![30];
    init.extend_from_slice(&(public.len() as u32).to_be_bytes());
    init.extend_from_slice(&public);
    io.stream.write_all(&build_unencrypted_packet(&init)).await.unwrap();
    let reply = io.read_unencrypted_packet(3).await.unwrap();
    let end = reply.len() - reply[4] as usize;
    let mut payload = &reply[6..end];
    let host_key = read_string(&mut payload);
    ctx.set_exchange_info(b"SSH-2.0-regression", b"SSH-2.0-ayssh_test_server", &offer, server_offer);
    ctx.set_server_host_key(host_key);
    ctx.process_server_kex_init(payload).unwrap();
    ctx.compute_shared_secret().unwrap();
    let hash = ctx.session_id.clone().unwrap();
    let mut keys = ctx.derive_session_keys_for(&hash, Some("aes128-cbc"), Some(mac_c2s)).unwrap();
    let outgoing = ctx.derive_session_keys_for(&hash, Some("aes128-cbc"), Some(mac_s2c)).unwrap();
    keys.mac_key_s2c = outgoing.mac_key_s2c;
    assert_eq!(io.read_unencrypted_packet(3).await.unwrap()[5], 21);
    io.stream.write_all(&build_unencrypted_packet(&[21])).await.unwrap();
    (io, task, keys)
}

async fn read_protected(io: &mut ServerEncryptedIO, keys: &ayssh::transport::kex::SessionKeys, mac: &str, sequence: u32) -> Vec<u8> {
    let first = io.read_exact_buffered(16).await.unwrap();
    let header = ayssh::crypto::cipher::aes_cbc_decrypt_raw(&keys.enc_key_s2c, &keys.server_iv, &first).unwrap();
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    let mut encrypted = first;
    encrypted.extend_from_slice(&io.read_exact_buffered(length + 4 - 16).await.unwrap());
    let plaintext = ayssh::crypto::cipher::aes_cbc_decrypt_raw(&keys.enc_key_s2c, &keys.server_iv, &encrypted).unwrap();
    let (algorithm, size) = match mac {
        "hmac-sha2-256" => (ring::hmac::HMAC_SHA256, 32),
        "hmac-sha2-512" => (ring::hmac::HMAC_SHA512, 64),
        _ => (ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, 20),
    };
    let tag = io.read_exact_buffered(size).await.unwrap();
    let mut authenticated = sequence.to_be_bytes().to_vec();
    authenticated.extend_from_slice(&plaintext);
    ring::hmac::verify(&ring::hmac::Key::new(algorithm, &keys.mac_key_s2c), &authenticated, &tag).unwrap();
    plaintext[5..plaintext.len()-plaintext[4] as usize].to_vec()
}

#[tokio::test]
async fn ext_info_after_newkeys() {
    let (mut io, task, keys) = exchange("curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com", "hmac-sha1", "hmac-sha1").await;
    let payload = tokio::time::timeout(std::time::Duration::from_millis(200), read_protected(&mut io, &keys, "hmac-sha1", 0)).await.unwrap();
    assert_eq!(payload[0], 7);
    assert_eq!(u32::from_be_bytes(payload[1..5].try_into().unwrap()), 1);
    let mut fields = &payload[5..];
    assert_eq!(read_string(&mut fields), b"server-sig-algs");
    let algorithms = std::str::from_utf8(read_string(&mut fields)).unwrap();
    assert!(algorithms.split(',').any(|a| a == "rsa-sha2-256"));
    assert!(algorithms.split(',').any(|a| a == "ssh-ed25519"));
    assert!(fields.is_empty());
    task.abort();
}

#[tokio::test]
async fn directional_mac_lengths() {
    for (incoming, outgoing) in [("hmac-sha2-256", "hmac-sha2-512"), ("hmac-sha2-512", "hmac-sha2-256")] {
        let (mut io, task, keys) = exchange("curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com", incoming, outgoing).await;
        let payload = read_protected(&mut io, &keys, outgoing, 0).await;
        assert_eq!(payload[0], 7);
        task.abort();
    }
}

#[test]
fn nist_kdf_digest() {
    for (algorithm, digest, hash_size) in [
        (KexAlgorithm::EcdhSha2Nistp384, &ring::digest::SHA384, 48),
        (KexAlgorithm::EcdhSha2Nistp521, &ring::digest::SHA512, 64),
    ] {
        let mut ctx = KexContext::new(algorithm);
        ctx.shared_secret = Some(vec![1; 32]);
        let hash = vec![2; hash_size];
        let keys = ctx.derive_session_keys_for(&hash, Some("aes128-cbc"), Some("hmac-sha2-512")).unwrap();
        let mut input = 32u32.to_be_bytes().to_vec();
        input.extend_from_slice(&[1; 32]);
        input.extend_from_slice(&hash);
        let mut first = input.clone();
        first.push(b'F');
        first.extend_from_slice(&hash);
        let mut expected = ring::digest::digest(digest, &first).as_ref().to_vec();
        if expected.len() < 64 {
            input.extend_from_slice(&expected);
            expected.extend_from_slice(ring::digest::digest(digest, &input).as_ref());
        }
        expected.truncate(64);
        assert_eq!(keys.mac_key_s2c, expected);
    }
}

#[tokio::test]
async fn nist_protected_packets() {
    for curve in ["ecdh-sha2-nistp384", "ecdh-sha2-nistp521"] {
        let list = format!("{curve},ext-info-c,kex-strict-c-v00@openssh.com");
        let (mut io, task, keys) = exchange(&list, "hmac-sha2-512", "hmac-sha2-512").await;
        assert_eq!(read_protected(&mut io, &keys, "hmac-sha2-512", 0).await[0], 7);
        task.abort();
    }
}

#[tokio::test]
async fn server_offers_loaded_host_key_only() {
    for (key, expected) in [
        (HostKeyPair::generate_ed25519(), vec!["ssh-ed25519"]),
        (HostKeyPair::generate_rsa(1024).unwrap(), vec!["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]),
        (HostKeyPair::generate_ecdsa_p256(), vec!["ecdsa-sha2-nistp256"]),
        (HostKeyPair::generate_ecdsa_p384(), vec!["ecdsa-sha2-nistp384"]),
        (HostKeyPair::generate_ecdsa_p521(), vec!["ecdsa-sha2-nistp521"]),
    ] {
        let (mut io, task) = start(key).await;
        let packet = io.read_unencrypted_packet(3).await.unwrap();
        let end = packet.len() - packet[4] as usize;
        let proposal = ayssh::transport::handshake::parse_server_kexinit(&packet[5..end]).unwrap();
        assert_eq!(proposal.server_host_key_algorithms, expected);
        task.abort();
    }
}

#[test]
fn mac_compare_receivers_use_constant_time_comparison() {
    // Guard the security-sensitive receive sites against early-exit comparisons.
    for source in [include_str!("../src/transport/mod.rs"), include_str!("../src/server/encrypted_io.rs")] {
        assert!(!source.contains("expected_mac.iter().zip"));
        assert!(!source.contains("expected_mac != received_mac"));
        assert!(source.matches("verify_packet_mac(&expected_mac,").count() >= 2);
    }
}

fn assert_kex_disconnect(packet: &[u8]) {
    assert_eq!(packet[5], 1, "expected SSH_MSG_DISCONNECT before any KEX reply or NEWKEYS");
    assert_eq!(u32::from_be_bytes(packet[6..10].try_into().unwrap()), 3);
}

async fn invalid_client_key_disconnect(public: &[u8]) {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    io.read_unencrypted_packet(3).await.unwrap();
    let mut offer = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), None, None);
    replace_list(&mut offer, 1, "ssh-ed25519");
    io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
    let mut init = vec![30];
    init.extend_from_slice(&(public.len() as u32).to_be_bytes());
    init.extend_from_slice(public);
    io.stream.write_all(&build_unencrypted_packet(&init)).await.unwrap();
    assert_kex_disconnect(&io.read_unencrypted_packet(3).await.unwrap());
    task.await.unwrap();
}

async fn invalid_server_key_disconnect(public: &[u8]) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(async move {
        let mut transport = ayssh::transport::Transport::new(stream);
        assert!(transport.handshake().await.is_err());
    });
    let mut io = ServerEncryptedIO::new(server);
    io.stream.write_all(b"SSH-2.0-regression\r\n").await.unwrap();
    recv_version(&mut io.stream).await.unwrap();
    io.read_unencrypted_packet(3).await.unwrap();
    let mut offer = ayssh::transport::handshake::generate_server_kexinit_with_prefs(
        Some("curve25519-sha256"), None, None, &["ssh-ed25519"]);
    replace_list(&mut offer, 0, "curve25519-sha256");
    io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
    assert_eq!(io.read_unencrypted_packet(3).await.unwrap()[5], 30);
    let host_key = HostKeyPair::generate_ed25519().public_key_blob();
    let mut reply = vec![31];
    for field in [host_key.as_slice(), public, &[]] {
        reply.extend_from_slice(&(field.len() as u32).to_be_bytes());
        reply.extend_from_slice(field);
    }
    io.stream.write_all(&build_unencrypted_packet(&reply)).await.unwrap();
    assert_kex_disconnect(&io.read_unencrypted_packet(3).await.unwrap());
    task.await.unwrap();
}

#[tokio::test]
async fn x25519_server_disconnects_zero_peer() {
    invalid_client_key_disconnect(&[0; 32]).await;
}

#[tokio::test]
async fn x25519_server_disconnects_wrong_length_peer() {
    for length in [0, 31, 33] {
        invalid_client_key_disconnect(&vec![1; length]).await;
    }
}

#[tokio::test]
async fn x25519_client_disconnects_zero_peer() {
    invalid_server_key_disconnect(&[0; 32]).await;
}

#[tokio::test]
async fn x25519_client_disconnects_wrong_length_peer() {
    for length in [0, 31, 33] {
        invalid_server_key_disconnect(&vec![1; length]).await;
    }
}

#[tokio::test]
async fn no_common_algorithm_disconnect_reason() {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    io.read_unencrypted_packet(3).await.unwrap();
    let mut offer = generate_client_kexinit_with_prefs(None, None, None);
    replace_list(&mut offer, 0, "unknown-kex");
    io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
    let response = io.read_unencrypted_packet(3).await.unwrap();
    assert_eq!(response[5], 1);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 3);
    task.await.unwrap();
}

#[tokio::test]
async fn initial_parser_requires_kexinit() {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    io.read_unencrypted_packet(3).await.unwrap();
    let offer = generate_client_kexinit_with_prefs(None, None, None);
    io.stream.write_all(&build_unencrypted_packet(&[2])).await.unwrap();
    io.stream.write_all(&build_unencrypted_packet(&offer)).await.unwrap();
    assert!(io.read_unencrypted_packet(3).await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn plaintext_supported_size_and_buffering() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut sender = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (receiver, _) = listener.accept().await.unwrap();
    let packet = build_unencrypted_packet(&vec![2; 34986]);
    assert_eq!(packet.len(), 35000);
    let next = build_unencrypted_packet(&[21]);
    let mut combined = packet.clone();
    combined.extend_from_slice(&next);
    let write = tokio::spawn(async move { sender.write_all(&combined).await.unwrap(); });
    let mut io = ServerEncryptedIO::new(receiver);
    assert_eq!(io.read_unencrypted_packet(3).await.unwrap(), packet);
    assert_eq!(io.read_unencrypted_packet(3).await.unwrap(), next);
    write.await.unwrap();
}

#[test]
fn directional_cipher_key_sizes() {
    let mut ctx = KexContext::new(KexAlgorithm::Curve25519Sha256);
    ctx.shared_secret = Some(vec![1; 32]);
    let hash = vec![2; 32];
    let mut offer = generate_client_kexinit_with_prefs(None, None, None);
    replace_list(&mut offer, 2, "aes128-cbc");
    replace_list(&mut offer, 3, "aes256-gcm@openssh.com");
    replace_list(&mut offer, 4, "hmac-sha2-256");
    replace_list(&mut offer, 5, "hmac-sha2-512");
    let proposal = ayssh::transport::handshake::parse_server_kexinit(&offer).unwrap();
    let selected = ayssh::transport::handshake::negotiate_algorithms(&proposal, &proposal).unwrap();
    let keys = ctx.derive_session_keys_directional(&hash, &selected).unwrap();
    assert_eq!(keys.enc_key_c2s.len(), 16);
    assert_eq!(keys.enc_key_s2c.len(), 32);
    assert_eq!(keys.client_iv.len(), 16);
    assert_eq!(keys.server_iv.len(), 12);
    assert_eq!(keys.mac_key_c2s.len(), 32);
    assert_eq!(keys.mac_key_s2c.len(), 64);
}
