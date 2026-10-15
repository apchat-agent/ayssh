//! Authentication regressions exercised over an encrypted localhost connection.
use ayssh::protocol::message::Message;
use ayssh::server::TestSshServer;
use ayssh::transport::Transport;
use std::time::Duration;
use tokio::net::TcpStream;

struct ServerTask(tokio::task::JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect() -> (Transport, ServerTask) {
    let server = TestSshServer::new(0).await.unwrap();
    let address = server.local_addr();
    let task = ServerTask(tokio::spawn(async move {
        let _ = server.accept_one().await;
    }));
    let mut transport = Transport::new(TcpStream::connect(address).await.unwrap());
    transport.set_preferred_kex("curve25519-sha256");
    transport.set_preferred_cipher("aes128-ctr");
    transport.set_preferred_mac("hmac-sha2-256");
    tokio::time::timeout(Duration::from_secs(5), transport.handshake())
        .await.unwrap().unwrap();
    transport.send_service_request("ssh-userauth").await.unwrap();
    let service = tokio::time::timeout(Duration::from_secs(3), transport.recv_service_accept())
        .await.unwrap().unwrap();
    assert_eq!(service, "ssh-userauth");
    (transport, task)
}

fn request(method: &[u8]) -> Message {
    let mut message = Message::new();
    message.write_byte(50);
    message.write_string(b"testuser");
    message.write_string(b"ssh-connection");
    message.write_string(method);
    message
}

async fn reply(transport: &mut Transport) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), transport.recv_message())
        .await.unwrap().unwrap()
}

fn assert_failure(payload: &[u8]) {
    assert_eq!(payload[0], 51, "expected SSH_MSG_USERAUTH_FAILURE");
    assert!(payload.len() >= 6);
    let length = u32::from_be_bytes(payload[1..5].try_into().unwrap()) as usize;
    assert_eq!(payload.len(), 6 + length);
    assert_eq!(payload[5 + length], 0, "partial success must be false");
    let methods = std::str::from_utf8(&payload[5..5 + length]).unwrap();
    assert!(!methods.split(',').any(|method| method == "none"));
}

#[tokio::test]
async fn unknown_auth_method_is_rejected_and_can_retry() {
    let (mut transport, _server) = connect().await;
    // Two failures must leave the connection in authentication, even when
    // requests arrive back-to-back (RFC 4252 sections 5 and 5.1).
    for method in [b"frobnicate-method".as_slice(), b"another-unknown"] {
        transport.send_message(request(method).as_bytes()).await.unwrap();
    }
    assert_failure(&reply(&mut transport).await);
    assert_failure(&reply(&mut transport).await);
    // This test fixture deliberately permits access without credentials.
    transport.send_message(request(b"none").as_bytes()).await.unwrap();
    assert_eq!(reply(&mut transport).await, [52]);
}

#[tokio::test]
async fn unsigned_publickey_query_is_rejected_and_can_retry() {
    let (mut transport, _server) = connect().await;
    let key = ayssh::server::HostKeyPair::generate_ed25519().public_key_blob();
    for algorithm in [b"ssh-ed25519".as_slice(), b"unknown-key-algorithm"] {
        let mut query = request(b"publickey");
        query.write_bool(false);
        query.write_string(algorithm);
        query.write_string(&key);
        transport.send_message(query.as_bytes()).await.unwrap();
        let response = reply(&mut transport).await;
        assert_failure(&response);
        let methods = std::str::from_utf8(&response[5..response.len() - 1]).unwrap();
        assert!(!methods.split(',').any(|method| method == "publickey"));
    }
    // A query never authenticates the client; it may still try another method.
    transport.send_message(request(b"none").as_bytes()).await.unwrap();
    assert_eq!(reply(&mut transport).await, [52]);
}
