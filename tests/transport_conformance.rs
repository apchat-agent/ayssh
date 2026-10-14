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

