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
async fn wrong_kex_guess_discarded() {
    let (mut io, task) = start(HostKeyPair::generate_ed25519()).await;
    io.read_unencrypted_packet(3).await.unwrap();
    let mut offer = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), None, None);
    replace_list(&mut offer, 0, "unknown-kex,curve25519-sha256");
    replace_list(&mut offer, 1, "ssh-ed25519");
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
    let mut offer = generate_client_kexinit_with_prefs(Some("curve25519-sha256"), None, None);
    replace_list(&mut offer, 0, "curve25519-sha256");
    replace_list(&mut offer, 1, "ssh-ed25519");
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

