use ayssh::server::{test_server::{server_handshake, AlgorithmFilter}, HostKeyPair};
use ayssh::RawSshSession;
use std::time::Duration;
use tokio::net::TcpListener;

async fn close_exchange(client_initiates: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut io, client_channel) = server_handshake(
            stream, &HostKeyPair::generate_ed25519(), &AlgorithmFilter::default(),
        ).await.unwrap();
        if client_initiates {
            assert_eq!(io.recv_message().await.unwrap(), [97, 0, 0, 0, 0]);
        }
        let mut close = vec![97];
        close.extend_from_slice(&client_channel.to_be_bytes());
        io.send_message(&close).await.unwrap();
        if !client_initiates {
            let ack = tokio::time::timeout(Duration::from_secs(1), io.recv_message()).await;
            assert_eq!(ack.expect("CHANNEL_CLOSE must be acknowledged").unwrap(), [97, 0, 0, 0, 0]);
        }
        closed_tx.send(()).unwrap();
        // Keep the connection open to distinguish silence from a TCP teardown.
        assert!(tokio::time::timeout(Duration::from_millis(100), io.recv_message()).await.is_err(),
            "a channel must send CLOSE only once");
    });
    let mut session = tokio::time::timeout(Duration::from_secs(5),
        RawSshSession::connect_with_password("127.0.0.1", port, "test", "test"))
        .await.unwrap().unwrap();
    if client_initiates {
        session.disconnect().await.unwrap();
    }
    assert!(session.receive(Duration::from_secs(2)).await.is_err());
    closed_rx.await.expect("peer must receive CLOSE before application cleanup");
    // Applications may clean up after receive reports closure. Do not send
    // another CLOSE after acknowledging the peer or initiating closure.
    session.disconnect().await.unwrap();
    session.disconnect().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn received_channel_close_is_acknowledged_once() {
    close_exchange(false).await;
}

#[tokio::test]
async fn channel_close_already_sent_is_not_repeated() {
    close_exchange(true).await;
}
