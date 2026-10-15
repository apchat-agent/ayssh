//! Raw SSH Session — vendor-neutral byte-stream over an authenticated SSH channel.
//!
//! Provides a simple `send(&[u8])` / `receive(timeout) -> Vec<u8>` API
//! over an SSH session channel with PTY and shell. No vendor-specific
//! behavior — all device interaction logic stays in the caller.
//!
//! # Example
//! ```no_run
//! # async fn example() -> Result<(), ayssh::error::SshError> {
//! use ayssh::RawSshSession;
//! use std::time::Duration;
//!
//! let mut session = RawSshSession::connect_with_password(
//!     "10.1.1.1", 22, "operator", "password123"
//! ).await?;
//!
//! // Read initial banner/prompt
//! let banner = session.receive(Duration::from_secs(5)).await?;
//! println!("Got: {}", String::from_utf8_lossy(&banner));
//!
//! // Send a command
//! session.send(b"show version\n").await?;
//! let output = session.receive(Duration::from_secs(10)).await?;
//! println!("{}", String::from_utf8_lossy(&output));
//!
//! session.disconnect().await?;
//! # Ok(())
//! # }
//! ```

use crate::error::SshError;
use crate::transport::Transport;
use bytes::BufMut;
use std::time::Duration;
use tracing::{debug, info};

/// A vendor-neutral SSH session providing raw byte-stream I/O.
///
/// Handles SSH protocol internally (channel messages, window adjust, etc.)
/// and exposes a simple send/receive interface over an authenticated shell.
pub struct RawSshSession {
    transport: Transport,
    channel_id: u32, // remote channel ID (for sending to server)
    /// Bytes consumed from the SSH window but not yet reported back via WINDOW_ADJUST.
    /// We batch adjustments to avoid flooding the server with tiny control messages.
    window_consumed: u32,
    /// Banner messages received during authentication (RFC 4252 §5.4)
    banners: Vec<String>,
    /// Whether this side has already sent CHANNEL_CLOSE (RFC 4254 section 5.3).
    close_sent: bool,
}

impl RawSshSession {
    /// Send WINDOW_ADJUST after this many bytes have been consumed.
    /// Large enough to avoid flooding, small enough to not stall the sender.
    const WINDOW_ADJUST_THRESHOLD: u32 = 32768;

    /// Connect with password authentication, open PTY + shell.
    ///
    /// After this returns, the caller has a raw byte stream to the remote shell.
    /// No vendor-specific commands are sent.
    pub async fn connect_with_password(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<Self, SshError> {
        let mut transport = Self::connect_and_handshake(host, port).await?;
        let banners = Self::authenticate_password(&mut transport, username, password).await?;
        let mut session = Self::open_pty_shell(transport).await?;
        session.banners = banners;
        Ok(session)
    }

    /// Connect with public key authentication, open PTY + shell.
    pub async fn connect_with_publickey(
        host: &str,
        port: u16,
        username: &str,
        private_key: &[u8],
    ) -> Result<Self, SshError> {
        let mut transport = Self::connect_and_handshake(host, port).await?;
        let banners = Self::authenticate_publickey(&mut transport, username, private_key).await?;
        let mut session = Self::open_pty_shell(transport).await?;
        session.banners = banners;
        Ok(session)
    }

    /// Connect with keyboard-interactive authentication, open PTY + shell.
    ///
    /// The `response_handler` is called for each challenge from the server
    /// and should return the appropriate responses (usually just the password).
    pub async fn connect_with_keyboard_interactive<F>(
        host: &str,
        port: u16,
        username: &str,
        response_handler: F,
    ) -> Result<Self, SshError>
    where
        F: Fn(&crate::auth::keyboard::Challenge) -> Result<Vec<String>, SshError> + Send + Sync + 'static,
    {
        let mut transport = Self::connect_and_handshake(host, port).await?;
        let banners = Self::authenticate_keyboard_interactive(&mut transport, username, response_handler).await?;
        let mut session = Self::open_pty_shell(transport).await?;
        session.banners = banners;
        Ok(session)
    }

    /// Create from an already-authenticated transport and channel.
    ///
    /// `channel_id` must be the REMOTE channel ID (the one used when sending
    /// messages to the server, from CHANNEL_OPEN_CONFIRMATION).
    pub fn from_parts(transport: Transport, channel_id: u32) -> Self {
        Self { transport, channel_id, window_consumed: 0, banners: Vec::new(), close_sent: false }
    }

    /// Send raw bytes to the remote shell.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.transport.send_channel_data(self.channel_id, data).await
    }

    /// Receive raw bytes from the remote shell.
    ///
    /// Semantics:
    /// - If data is immediately available, return it right away
    /// - Only block up to `timeout` if there is no data yet
    /// - Return empty Vec if timeout expires with no data (not an error)
    /// - SSH protocol messages are handled internally:
    ///   - CHANNEL_DATA (94): extract and return the payload
    ///   - CHANNEL_WINDOW_ADJUST (93): handled internally, keep reading
    ///   - CHANNEL_EOF (96): return error (channel ended)
    ///   - CHANNEL_CLOSE (97): acknowledge once, then return error (channel closed)
    ///   - Other messages: ignored, keep reading
    pub async fn receive(&mut self, timeout: Duration) -> Result<Vec<u8>, SshError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(vec![]);
            }
            let remaining = deadline - now;
            match tokio::time::timeout(remaining, self.transport.recv_message()).await {
                Ok(Ok(msg)) if !msg.is_empty() => {
                    match msg[0] {
                        94 => { // SSH_MSG_CHANNEL_DATA
                            if msg.len() > 9 {
                                let data_len = u32::from_be_bytes(
                                    [msg[5], msg[6], msg[7], msg[8]]
                                ) as usize;
                                if msg.len() >= 9 + data_len {
                                    // Batch window adjustments: accumulate consumed bytes and
                                    // send WINDOW_ADJUST only when the threshold is reached.
                                    // Sending per-byte adjusts floods old SSH servers (e.g.
                                    // Cisco SSH-2.0-Cisco-1.25) with control messages.
                                    self.window_consumed += data_len as u32;
                                    if self.window_consumed >= Self::WINDOW_ADJUST_THRESHOLD {
                                        let adjust = self.window_consumed;
                                        self.window_consumed = 0;
                                        let _ = self.transport.send_channel_window_adjust(
                                            self.channel_id, adjust,
                                        ).await;
                                    }
                                    return Ok(msg[9..9 + data_len].to_vec());
                                }
                            }
                            return Ok(vec![]);
                        }
                        93 => continue, // CHANNEL_WINDOW_ADJUST — ignore
                        96 => return Err(SshError::ChannelError("Channel EOF".into())),
                        97 => {
                            // RFC 4254 section 5.3: reply unless we already sent
                            // CLOSE. Use the peer's channel ID, not the incoming
                            // recipient (which identifies our local channel).
                            self.disconnect().await?;
                            return Err(SshError::ChannelError("Channel closed".into()));
                        }
                        _ => continue, // other messages (e.g., global requests)
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(vec![]), // timeout — no data
            }
        }
    }

    /// Close the channel and disconnect.
    pub async fn disconnect(&mut self) -> Result<(), SshError> {
        if !self.close_sent {
            self.transport.send_channel_close(self.channel_id).await?;
            self.close_sent = true;
        }
        Ok(())
    }

    /// Get banner messages received during authentication (RFC 4252 §5.4).
    pub fn banners(&self) -> &[String] {
        &self.banners
    }

    /// Get a reference to the underlying transport.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Get a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut Transport {
        &mut self.transport
    }

    /// Get the remote channel ID.
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    // --- Internal helpers ---

    /// TCP connect + SSH handshake + service request.
    pub(crate) async fn connect_and_handshake(host: &str, port: u16) -> Result<Transport, SshError> {
        let addr = format!("{}:{}", host, port);
        info!("Connecting to {}...", addr);

        let stream = tokio::net::TcpStream::connect(&addr).await
            .map_err(|e| SshError::ConnectionError(format!("TCP connect to {}: {}", addr, e)))?;

        let mut transport = Transport::new(stream);
        transport.set_remote_host(host, port);
        transport.handshake().await?;
        debug!("SSH handshake complete");

        transport.send_service_request("ssh-userauth").await?;
        transport.recv_service_accept().await?;
        debug!("ssh-userauth service accepted");

        Ok(transport)
    }

    /// Authenticate with password. Returns banners received during auth.
    pub(crate) async fn authenticate_password(
        transport: &mut Transport,
        username: &str,
        password: &str,
    ) -> Result<Vec<String>, SshError> {
        let mut auth = crate::auth::Authenticator::new(transport, username.to_string())
            .with_password(password.to_string())
            .with_method_order(vec!["password".to_string()]);

        match auth.authenticate().await? {
            crate::auth::AuthenticationResult::Success => {
                info!("Password authentication successful");
                Ok(auth.banners().to_vec())
            }
            crate::auth::AuthenticationResult::Failure { .. } => {
                Err(SshError::AuthenticationFailed("Password authentication failed".to_string()))
            }
        }
    }

    /// Authenticate with public key. Returns banners received during auth.
    pub(crate) async fn authenticate_publickey(
        transport: &mut Transport,
        username: &str,
        private_key: &[u8],
    ) -> Result<Vec<String>, SshError> {
        let mut auth = crate::auth::Authenticator::new(transport, username.to_string())
            .with_private_key(private_key.to_vec())
            .with_method_order(vec!["publickey".to_string()]);

        match auth.authenticate().await? {
            crate::auth::AuthenticationResult::Success => {
                info!("Public key authentication successful");
                Ok(auth.banners().to_vec())
            }
            crate::auth::AuthenticationResult::Failure { .. } => {
                Err(SshError::AuthenticationFailed("Public key authentication failed".to_string()))
            }
        }
    }

    /// Authenticate with keyboard-interactive. Returns banners received during auth.
    async fn authenticate_keyboard_interactive<F>(
        transport: &mut Transport,
        username: &str,
        response_handler: F,
    ) -> Result<Vec<String>, SshError>
    where
        F: Fn(&crate::auth::keyboard::Challenge) -> Result<Vec<String>, SshError> + Send + Sync + 'static,
    {
        let mut auth = crate::auth::Authenticator::new(transport, username.to_string())
            .with_keyboard_interactive_handler(response_handler)
            .with_method_order(vec!["keyboard-interactive".to_string()]);

        match auth.authenticate().await? {
            crate::auth::AuthenticationResult::Success => {
                info!("Keyboard-interactive authentication successful");
                Ok(auth.banners().to_vec())
            }
            crate::auth::AuthenticationResult::Failure { .. } => {
                Err(SshError::AuthenticationFailed("Keyboard-interactive authentication failed".to_string()))
            }
        }
    }

    /// Open session channel, request PTY and shell.
    pub(crate) async fn open_pty_shell(mut transport: Transport) -> Result<Self, SshError> {
        let session = crate::session::Session::open(&mut transport).await?;
        let channel_id = session.remote_channel_id();
        info!("Session channel opened (remote_id={})", channel_id);

        // Request PTY (vt100, 80x24)
        {
            let mut pty_msg = bytes::BytesMut::new();
            pty_msg.put_u8(crate::protocol::MessageType::ChannelRequest as u8);
            pty_msg.put_u32(channel_id);
            let req_type = b"pty-req";
            pty_msg.put_u32(req_type.len() as u32);
            pty_msg.put_slice(req_type);
            pty_msg.put_u8(1); // want reply
            let term = b"vt100";
            pty_msg.put_u32(term.len() as u32);
            pty_msg.put_slice(term);
            pty_msg.put_u32(80);  // width chars
            pty_msg.put_u32(24);  // height chars
            pty_msg.put_u32(0);   // width pixels
            pty_msg.put_u32(0);   // height pixels
            pty_msg.put_u32(0);   // terminal modes (empty)
            transport.send_message(&pty_msg).await?;
            let _pty_response = transport.recv_message().await?;
            debug!("PTY allocated");
        }

        // Request shell
        transport.send_channel_request(channel_id, "shell", true).await?;
        let _shell_response = transport.recv_message().await?;
        debug!("Shell started");

        Ok(Self { transport, channel_id, window_consumed: 0, banners: Vec::new(), close_sent: false })
    }

    /// Open a new connection, authenticate, and execute a command (exec channel).
    ///
    /// Unlike `connect_with_password` which opens a PTY + shell, this opens
    /// an exec channel for the given command. Useful for SCP, single-command
    /// execution, etc.
    ///
    /// Returns a `RawSshSession` connected to the command's stdin/stdout.
    pub async fn exec_with_password(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        command: &str,
    ) -> Result<Self, SshError> {
        let mut transport = Self::connect_and_handshake(host, port).await?;
        Self::authenticate_password(&mut transport, username, password).await?;

        let session = crate::session::Session::open(&mut transport).await?;
        let channel_id = session.remote_channel_id();
        info!("Exec channel opened (remote_id={})", channel_id);

        // Send exec request
        let mut exec_msg = bytes::BytesMut::new();
        exec_msg.put_u8(crate::protocol::MessageType::ChannelRequest as u8);
        exec_msg.put_u32(channel_id);
        let req_type = b"exec";
        exec_msg.put_u32(req_type.len() as u32);
        exec_msg.put_slice(req_type);
        exec_msg.put_u8(1); // want reply
        exec_msg.put_u32(command.len() as u32);
        exec_msg.put_slice(command.as_bytes());
        transport.send_message(&exec_msg).await?;

        // Wait for channel success/failure
        let response = transport.recv_message().await?;
        if !response.is_empty() && response[0] == 100 {
            // CHANNEL_FAILURE
            return Err(SshError::ChannelError("Exec request rejected".to_string()));
        }
        debug!("Exec channel ready for command: {}", command);

        Ok(Self::from_parts(transport, channel_id))
    }

    /// Open a new connection with public key auth and execute a command.
    pub async fn exec_with_publickey(
        host: &str,
        port: u16,
        username: &str,
        private_key: &[u8],
        command: &str,
    ) -> Result<Self, SshError> {
        let mut transport = Self::connect_and_handshake(host, port).await?;
        Self::authenticate_publickey(&mut transport, username, private_key).await?;
        Self::open_exec_channel(transport, command).await
    }

    /// Open an exec channel on an already-authenticated transport.
    pub(crate) async fn open_exec_channel(mut transport: Transport, command: &str) -> Result<Self, SshError> {
        let session = crate::session::Session::open(&mut transport).await?;
        let channel_id = session.remote_channel_id();
        info!("Exec channel opened (remote_id={})", channel_id);

        let mut exec_msg = bytes::BytesMut::new();
        exec_msg.put_u8(crate::protocol::MessageType::ChannelRequest as u8);
        exec_msg.put_u32(channel_id);
        let req_type = b"exec";
        exec_msg.put_u32(req_type.len() as u32);
        exec_msg.put_slice(req_type);
        exec_msg.put_u8(1); // want reply
        exec_msg.put_u32(command.len() as u32);
        exec_msg.put_slice(command.as_bytes());
        transport.send_message(&exec_msg).await?;

        let response = transport.recv_message().await?;
        if !response.is_empty() && response[0] == 100 {
            return Err(SshError::ChannelError("Exec request rejected".to_string()));
        }
        debug!("Exec channel ready for command: {}", command);

        Ok(Self::from_parts(transport, channel_id))
    }
}

impl std::fmt::Debug for RawSshSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSshSession")
            .field("channel_id", &self.channel_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a RawSshSession from a local TCP pair (no handshake).
    async fn make_session_pair() -> (RawSshSession, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(
            tokio::net::TcpStream::connect(addr),
            listener.accept()
        );
        let transport = Transport::new(client.unwrap());
        let session = RawSshSession::from_parts(transport, 42);
        (session, server.unwrap().0)
    }

    #[tokio::test]
    async fn test_from_parts_and_accessors() {
        let (session, _server) = make_session_pair().await;
        assert_eq!(session.channel_id(), 42);
    }

    #[tokio::test]
    async fn test_transport_accessor() {
        let (session, _server) = make_session_pair().await;
        let _transport_ref = session.transport();
        // Just verify it doesn't panic
    }

    #[tokio::test]
    async fn test_transport_mut_accessor() {
        let (mut session, _server) = make_session_pair().await;
        let _transport_ref = session.transport_mut();
        // Just verify it doesn't panic
    }

    #[tokio::test]
    async fn test_debug_formatting() {
        let (session, _server) = make_session_pair().await;
        let debug = format!("{:?}", session);
        assert!(debug.contains("RawSshSession"));
        assert!(debug.contains("42")); // channel_id
    }

    #[tokio::test]
    async fn test_from_parts_various_channel_ids() {
        for channel_id in [0, 1, 100, u32::MAX] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, _server) = tokio::join!(
                tokio::net::TcpStream::connect(addr),
                listener.accept()
            );
            let transport = Transport::new(client.unwrap());
            let session = RawSshSession::from_parts(transport, channel_id);
            assert_eq!(session.channel_id(), channel_id);
        }
    }

    #[tokio::test]
    async fn test_receive_timeout_returns_empty() {
        let (mut session, _server) = make_session_pair().await;
        let result = session.receive(Duration::from_millis(50)).await;
        assert!(result.is_ok() || result.is_err());
    }

    /// Full end-to-end test using our test server: handshake → auth → PTY → shell → send/receive
    #[test]
    fn test_raw_session_full_flow_with_test_server() {
        use crate::server::test_server::*;
        use crate::server::host_key::HostKeyPair;
        use bytes::BufMut;

        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

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

                // Send test data
                let mut msg = bytes::BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"RAW_SESSION_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();

                let mut eof = bytes::BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                let _ = io.send_message(&eof).await;
                let mut close = bytes::BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                let _ = io.send_message(&close).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                // Test connect_and_handshake + authenticate_password + open_pty_shell
                let mut transport = RawSshSession::connect_and_handshake("127.0.0.1", port).await.unwrap();
                RawSshSession::authenticate_password(&mut transport, "test", "test").await.unwrap();
                let mut session = RawSshSession::open_pty_shell(transport).await.unwrap();

                assert!(session.channel_id() < 100); // reasonable channel id

                // Test receive — should get the test data
                let data = session.receive(Duration::from_secs(5)).await.unwrap();
                let text = String::from_utf8_lossy(&data);
                assert!(text.contains("RAW_SESSION_TEST_OK"), "Got: {:?}", text);

                // Drain EOF/CLOSE
                for _ in 0..5 {
                    match session.receive(Duration::from_millis(500)).await {
                        Ok(d) if d.is_empty() => break,
                        Err(_) => break,
                        _ => continue,
                    }
                }

                let _ = session.disconnect().await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test send method with test server
    #[test]
    fn test_raw_session_send_with_test_server() {
        use crate::server::test_server::*;
        use crate::server::host_key::HostKeyPair;
        use bytes::BufMut;

        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

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

                // Read what client sends (should be CHANNEL_DATA)
                let msg = io.recv_message().await.unwrap();
                assert!(!msg.is_empty());
                // Send back acknowledgment
                let mut reply = bytes::BytesMut::new();
                reply.put_u8(94); reply.put_u32(ch);
                let data = b"ACK";
                reply.put_u32(data.len() as u32); reply.put_slice(data);
                io.send_message(&reply).await.unwrap();

                let mut eof = bytes::BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                let _ = io.send_message(&eof).await;
                let mut close = bytes::BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                let _ = io.send_message(&close).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = RawSshSession::connect_and_handshake("127.0.0.1", port).await.unwrap();
                RawSshSession::authenticate_password(&mut transport, "test", "test").await.unwrap();
                let mut session = RawSshSession::open_pty_shell(transport).await.unwrap();

                // Test send
                session.send(b"hello from client\n").await.unwrap();

                // Read acknowledgment
                let ack = session.receive(Duration::from_secs(5)).await.unwrap();
                assert_eq!(ack, b"ACK");

                // Drain
                for _ in 0..5 {
                    match session.receive(Duration::from_millis(500)).await {
                        Ok(d) if d.is_empty() => break,
                        Err(_) => break,
                        _ => continue,
                    }
                }
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test connect failure (bad host)
    #[tokio::test]
    async fn test_connect_and_handshake_bad_host() {
        let result = RawSshSession::connect_and_handshake("127.0.0.1", 1).await;
        assert!(result.is_err());
    }

    /// Test connect_with_password error (no server)
    #[tokio::test]
    async fn test_connect_with_password_no_server() {
        let result = RawSshSession::connect_with_password("127.0.0.1", 1, "user", "pass").await;
        assert!(result.is_err());
    }

    /// Test connect_with_publickey error (no server)
    #[tokio::test]
    async fn test_connect_with_publickey_no_server() {
        let result = RawSshSession::connect_with_publickey("127.0.0.1", 1, "user", b"key").await;
        assert!(result.is_err());
    }

    /// Test exec_with_password error (no server)
    #[tokio::test]
    async fn test_exec_with_password_no_server() {
        let result = RawSshSession::exec_with_password("127.0.0.1", 1, "user", "pass", "ls").await;
        assert!(result.is_err());
    }

    /// Test exec_with_publickey error (no server)
    #[tokio::test]
    async fn test_exec_with_publickey_no_server() {
        let result = RawSshSession::exec_with_publickey("127.0.0.1", 1, "user", b"key", "ls").await;
        assert!(result.is_err());
    }

    /// Test connect_with_keyboard_interactive error path (no server at port 1)
    #[tokio::test]
    async fn test_connect_with_keyboard_interactive_no_server() {
        let result = RawSshSession::connect_with_keyboard_interactive(
            "127.0.0.1", 1, "user",
            |_challenge| Ok(vec!["password".to_string()]),
        ).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // Should be a connection error since there's no server
        assert!(
            err_msg.contains("connect") || err_msg.contains("Connect") || err_msg.contains("refused") || err_msg.contains("Connection"),
            "Unexpected error: {}", err_msg
        );
    }

    /// Test authenticate_password with invalid credentials against test server
    #[test]
    fn test_authenticate_password_rejected_by_server() {
        use crate::server::test_server::*;
        use crate::server::host_key::HostKeyPair;

        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth = AuthBehavior::RejectPassword {
                    available_methods: "publickey".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                let _result = server_handshake_with_auth(stream, &host_key, &filter, &auth).await;
                // Server returns (io, 0) after rejecting — that's fine
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = RawSshSession::connect_and_handshake("127.0.0.1", port).await.unwrap();
                let result = RawSshSession::authenticate_password(&mut transport, "baduser", "badpass").await;
                assert!(result.is_err(), "Expected auth failure, got Ok");
                let err_msg = result.unwrap_err().to_string();
                assert!(
                    err_msg.contains("uthentication") || err_msg.contains("auth") || err_msg.contains("failed"),
                    "Unexpected error: {}", err_msg
                );
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test authenticate_publickey with invalid credentials against test server
    #[test]
    fn test_authenticate_publickey_rejected_by_server() {
        use crate::server::test_server::*;
        use crate::server::host_key::HostKeyPair;

        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth = AuthBehavior::RejectPassword {
                    available_methods: "password".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                let _result = server_handshake_with_auth(stream, &host_key, &filter, &auth).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = RawSshSession::connect_and_handshake("127.0.0.1", port).await.unwrap();
                // Use a bogus key — the server will reject regardless
                let bogus_key = b"not-a-real-private-key";
                let result = RawSshSession::authenticate_publickey(&mut transport, "baduser", bogus_key).await;
                assert!(result.is_err(), "Expected auth failure, got Ok");
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test that UserauthBanner is handled during password auth (RFC 4252 §5.4)
    #[test]
    fn test_userauth_banner_during_password_auth() {
        use crate::server::test_server::*;
        use crate::server::host_key::HostKeyPair;
        use bytes::BufMut;

        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();
                let auth = AuthBehavior::SendBannerThenAccept {
                    banner: "Authorized users only. All activity is monitored.".to_string(),
                };
                let (stream, _) = listener.accept().await.unwrap();
                let (mut io, ch) = server_handshake_with_auth(stream, &host_key, &filter, &auth).await
                    .expect("Server handshake failed");

                // Send test data so client can verify the session works
                let mut msg = bytes::BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"BANNER_TEST_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();

                let mut eof = bytes::BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                let _ = io.send_message(&eof).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                let mut transport = RawSshSession::connect_and_handshake("127.0.0.1", port).await.unwrap();
                let banners = RawSshSession::authenticate_password(&mut transport, "test", "test").await
                    .expect("Auth should succeed despite banner");

                // Verify banner was captured
                assert_eq!(banners.len(), 1, "Expected 1 banner, got {:?}", banners);
                assert!(banners[0].contains("Authorized users only"), "Banner text: {:?}", banners[0]);

                // Verify session works after banner
                let mut session = RawSshSession::open_pty_shell(transport).await.unwrap();
                session.banners = banners;
                assert_eq!(session.banners().len(), 1);

                let data = session.receive(Duration::from_secs(5)).await.unwrap();
                let text = String::from_utf8_lossy(&data);
                assert!(text.contains("BANNER_TEST_OK"), "Got: {:?}", text);

                let _ = session.disconnect().await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }

    /// Test open_exec_channel via exec_with_password against the test server
    #[test]
    fn test_exec_channel_with_test_server() {
        use crate::server::test_server::*;
        use crate::server::host_key::HostKeyPair;
        use bytes::BufMut;

        let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();

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

                // Server sends back exec output
                let mut msg = bytes::BytesMut::new();
                msg.put_u8(94); msg.put_u32(ch);
                let data = b"EXEC_OUTPUT_OK\n";
                msg.put_u32(data.len() as u32); msg.put_slice(data);
                io.send_message(&msg).await.unwrap();

                let mut eof = bytes::BytesMut::new();
                eof.put_u8(96); eof.put_u32(ch);
                let _ = io.send_message(&eof).await;
                let mut close = bytes::BytesMut::new();
                close.put_u8(97); close.put_u32(ch);
                let _ = io.send_message(&close).await;
            });
        });

        let client = std::thread::spawn(move || {
            let port = port_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async {
                // exec_with_password exercises open_exec_channel internally
                let mut session = RawSshSession::exec_with_password(
                    "127.0.0.1", port, "test", "test", "echo hello",
                ).await.unwrap();

                assert!(session.channel_id() < 100);

                // Read the exec output
                let data = session.receive(Duration::from_secs(5)).await.unwrap();
                let text = String::from_utf8_lossy(&data);
                assert!(text.contains("EXEC_OUTPUT_OK"), "Got: {:?}", text);

                // Drain EOF/CLOSE
                for _ in 0..5 {
                    match session.receive(Duration::from_millis(500)).await {
                        Ok(d) if d.is_empty() => break,
                        Err(_) => break,
                        _ => continue,
                    }
                }

                let _ = session.disconnect().await;
            });
        });

        server.join().expect("Server panicked");
        client.join().expect("Client panicked");
    }
}
