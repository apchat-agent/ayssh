//! Exercise RFC 4252 section 7 at the production TCP entry point. Unlike an
//! ordinary SSH client, this client can send invalid proofs for a registered key.
//! Transport encryption is real; only the USERAUTH_REQUEST payload is hand-built.

use async_trait::async_trait;
use ayssh::error::SshError;
use ayssh::host_key_verify::AcceptAll;
use ayssh::server::{serve_connection, AuthRejectionReason, HostKeyPair, ServerHandler};
use ayssh::transport::Transport;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);
const USER: &[u8] = b"account";
const ALGORITHM: &[u8] = b"ssh-ed25519";

fn string(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u32).to_be_bytes());
    message.extend_from_slice(value);
}

fn public_key(key: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    string(&mut blob, ALGORITHM);
    string(&mut blob, key.verifying_key().as_bytes());
    blob
}

fn auth_prefix(username: &[u8], key: &[u8], signed: bool) -> Vec<u8> {
    let mut request = vec![50]; // SSH_MSG_USERAUTH_REQUEST
    string(&mut request, username);
    string(&mut request, b"ssh-connection");
    string(&mut request, b"publickey");
    request.push(u8::from(signed));
    string(&mut request, ALGORITHM);
    string(&mut request, key);
    request
}

fn signed_data(session_id: &[u8], prefix: &[u8]) -> Vec<u8> {
    // RFC 4252 section 7 includes the length-prefixed *initial* session ID.
    let mut data = Vec::new();
    string(&mut data, session_id);
    data.extend_from_slice(prefix);
    data
}

fn channel_open() -> Vec<u8> {
    let mut request = vec![90]; // SSH_MSG_CHANNEL_OPEN, RFC 4254 section 5.1
    string(&mut request, b"session");
    request.extend_from_slice(&0u32.to_be_bytes());
    request.extend_from_slice(&(1024 * 1024u32).to_be_bytes());
    request.extend_from_slice(&32768u32.to_be_bytes());
    request
}

fn exec_request(channel: u32) -> Vec<u8> {
    let mut request = vec![98]; // SSH_MSG_CHANNEL_REQUEST, RFC 4254 section 6.5
    request.extend_from_slice(&channel.to_be_bytes());
    string(&mut request, b"exec");
    request.push(1); // want-reply
    string(&mut request, b"succeed");
    request
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Observation {
    Refused(Option<String>, Option<Vec<u8>>, AuthRejectionReason),
    Verified(String, Vec<u8>),
}

struct Handler {
    key: Vec<u8>,
    executions: Arc<AtomicUsize>,
    observations: Arc<Mutex<Vec<Observation>>>,
}

#[async_trait]
impl ServerHandler for Handler {
    async fn authorize_public_key(&self, username: &str, public_key: &[u8]) -> bool {
        username.as_bytes() == USER && public_key == self.key
    }

    async fn auth_refused(
        &self,
        username: Option<&str>,
        key: Option<&[u8]>,
        reason: AuthRejectionReason,
    ) {
        self.observations.lock().unwrap().push(Observation::Refused(
            username.map(str::to_owned),
            key.map(<[u8]>::to_vec),
            reason,
        ));
    }

    async fn authentication_succeeded(&self, username: &str, key: &[u8]) {
        self.observations
            .lock()
            .unwrap()
            .push(Observation::Verified(username.to_owned(), key.to_vec()));
    }

    async fn exec(&self, username: &str, command: &[u8]) -> Result<Option<Command>, SshError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        assert_eq!(username.as_bytes(), USER);
        assert_eq!(command, b"succeed");
        let mut child = Command::new("/bin/sh");
        child.args(["-c", "exit 0"]);
        Ok(Some(child))
    }
}

struct Client {
    transport: Transport,
    key: Vec<u8>,
    executions: Arc<AtomicUsize>,
    observations: Arc<Mutex<Vec<Observation>>>,
    server: JoinHandle<Result<(), SshError>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Client {
    async fn connect(key: &SigningKey) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = public_key(key);
        let executions = Arc::new(AtomicUsize::new(0));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let handler = Handler {
            key: key.clone(),
            executions: executions.clone(),
            observations: observations.clone(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            serve_connection(stream, &HostKeyPair::generate_ed25519(), &handler).await
        });
        let transport = Transport::new(TcpStream::connect(address).await.unwrap());
        let mut client = Self {
            transport,
            key,
            executions,
            observations,
            server,
        };
        timeout(DEADLINE, async {
            // This fixture owns the loopback listener and its ephemeral host key.
            client
                .transport
                .handshake_with_verifier(&AcceptAll)
                .await
                .unwrap();
            assert!(!client.transport.session_id().unwrap().is_empty());
            client
                .transport
                .send_service_request("ssh-userauth")
                .await
                .unwrap();
            assert_eq!(
                client.transport.recv_service_accept().await.unwrap(),
                "ssh-userauth"
            );
        })
        .await
        .expect("transport handshake/service request timed out");

        // Prove the exact transmitted username/key is registered before testing
        // the signature. An ACL rejection must not make a negative test pass.
        let query = auth_prefix(USER, &client.key, false);
        client.send(&query).await;
        let mut expected = vec![60]; // SSH_MSG_USERAUTH_PK_OK
        string(&mut expected, ALGORITHM);
        string(&mut expected, &client.key);
        assert_eq!(client.receive().await, expected);
        assert_eq!(client.executions.load(Ordering::SeqCst), 0);
        client
    }

    async fn send(&mut self, message: &[u8]) {
        timeout(DEADLINE, self.transport.send_message(message))
            .await
            .expect("client send timed out")
            .unwrap();
    }

    async fn receive(&mut self) -> Vec<u8> {
        timeout(DEADLINE, self.transport.recv_message())
            .await
            .expect("server response timed out")
            .unwrap()
    }

    fn data_to_sign(&self, username: &[u8], session_id: &[u8]) -> Vec<u8> {
        signed_data(session_id, &auth_prefix(username, &self.key, true))
    }

    async fn authenticate(&mut self, signature: &[u8; 64]) -> Vec<u8> {
        let mut blob = Vec::new();
        string(&mut blob, ALGORITHM);
        string(&mut blob, signature);
        let mut request = auth_prefix(USER, &self.key, true);
        string(&mut request, &blob);
        self.send(&request).await;
        self.receive().await
    }

    async fn assert_rejected(mut self, signature: &[u8; 64]) {
        let mut failure = vec![51]; // SSH_MSG_USERAUTH_FAILURE
        string(&mut failure, b"publickey");
        failure.push(0); // no partial success
        assert_eq!(
            self.authenticate(signature).await,
            failure,
            "invalid proof for a registered key must receive USERAUTH_FAILURE"
        );

        // Try to proceed anyway. Wait for the server to finish before asserting
        // the callback count, so a delayed execution cannot escape the assertion.
        self.send(&channel_open()).await;
        // A closed transport is expected if the server already rejected OPEN;
        // a stalled write is a test failure, not evidence of denial.
        let _ = timeout(DEADLINE, self.transport.send_message(&exec_request(0)))
            .await
            .expect("post-rejection exec write timed out");
        let result = timeout(DEADLINE, &mut self.server)
            .await
            .expect("server accepted post-rejection session traffic")
            .expect("production server panicked");
        assert!(
            matches!(result, Err(SshError::ProtocolError(_))),
            "{result:?}"
        );
        assert_eq!(
            self.executions.load(Ordering::SeqCst),
            0,
            "rejected authentication reached the exec handler"
        );
    }
}

fn signing_key() -> SigningKey {
    let mut secret = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

#[tokio::test]
async fn registered_key_with_random_signature_is_rejected() {
    let key = signing_key();
    let client = Client::connect(&key).await;
    let mut signature = [0; 64];
    rand::rngs::OsRng.fill_bytes(&mut signature);
    client.assert_rejected(&signature).await;
}

#[tokio::test]
async fn registered_key_signature_from_another_session_is_rejected() {
    let key = signing_key();
    let previous = Client::connect(&key).await;
    let previous_id = previous.transport.session_id().unwrap().to_vec();
    drop(previous);
    let client = Client::connect(&key).await;
    assert_ne!(client.transport.session_id().unwrap(), previous_id);
    let data = client.data_to_sign(USER, &previous_id);
    let signature = key.sign(&data);
    key.verifying_key()
        .verify_strict(&data, &signature)
        .unwrap();
    client.assert_rejected(&signature.to_bytes()).await;
}

#[tokio::test]
async fn registered_key_signature_for_another_username_is_rejected() {
    let key = signing_key();
    let client = Client::connect(&key).await;
    // The wire request still names the registered account; only the signed
    // preimage uses a different name. Otherwise the ACL could mask a bypass.
    let data = client.data_to_sign(b"another-account", client.transport.session_id().unwrap());
    let signature = key.sign(&data);
    key.verifying_key()
        .verify_strict(&data, &signature)
        .unwrap();
    client.assert_rejected(&signature.to_bytes()).await;
}

#[tokio::test]
async fn registered_key_with_matching_signature_authenticates_and_executes() {
    let key = signing_key();
    let mut client = Client::connect(&key).await;
    let data = client.data_to_sign(USER, client.transport.session_id().unwrap());
    assert_eq!(client.authenticate(&key.sign(&data).to_bytes()).await, [52]);
    client.send(&channel_open()).await;
    let confirmation = client.receive().await;
    assert_eq!(confirmation.len(), 17);
    assert_eq!(confirmation[0], 91); // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    let channel = u32::from_be_bytes(confirmation[5..9].try_into().unwrap());
    client.send(&exec_request(channel)).await;
    assert_eq!(client.receive().await, [99, 0, 0, 0, 0]); // CHANNEL_SUCCESS
    let mut exit = vec![98, 0, 0, 0, 0];
    string(&mut exit, b"exit-status");
    exit.extend_from_slice(&[0, 0, 0, 0, 0]); // want-reply=false, status=0
    assert_eq!(client.receive().await, exit);
    assert_eq!(client.receive().await, [96, 0, 0, 0, 0]); // CHANNEL_EOF
    assert_eq!(client.receive().await, [97, 0, 0, 0, 0]); // CHANNEL_CLOSE
    timeout(DEADLINE, client.transport.send_channel_close(channel))
        .await
        .expect("channel close write timed out")
        .unwrap();
    timeout(DEADLINE, &mut client.server)
        .await
        .expect("server did not finish")
        .expect("server panicked")
        .unwrap();
    assert_eq!(client.executions.load(Ordering::SeqCst), 1);
}

fn auth_failure() -> Vec<u8> {
    let mut failure = vec![51];
    string(&mut failure, b"publickey");
    failure.push(0);
    failure
}

#[tokio::test]
async fn authentication_observer_reports_refusals_before_later_verified_success() {
    let key = signing_key();
    let mut client = Client::connect(&key).await;
    // connect completed an accepted unsigned key query, not authentication.
    assert!(client.observations.lock().unwrap().is_empty());
    for method in [b"none".as_slice(), b"password".as_slice()] {
        let mut request = vec![50];
        string(&mut request, USER);
        string(&mut request, b"ssh-connection");
        string(&mut request, method);
        if method == b"password" {
            request.push(0);
            string(&mut request, b"synthetic-password-not-observed");
        }
        client.send(&request).await;
        assert_eq!(client.receive().await, auth_failure());
        if method == b"none" {
            assert!(client.observations.lock().unwrap().is_empty());
        }
    }
    let unknown = public_key(&signing_key());
    client.send(&auth_prefix(USER, &unknown, false)).await;
    assert_eq!(client.receive().await, auth_failure());
    assert_eq!(client.authenticate(&[0; 64]).await, auth_failure());
    let data = client.data_to_sign(USER, client.transport.session_id().unwrap());
    assert_eq!(client.authenticate(&key.sign(&data).to_bytes()).await, [52]);
    assert_eq!(
        *client.observations.lock().unwrap(),
        vec![
            Observation::Refused(
                Some("account".into()),
                None,
                AuthRejectionReason::UnsupportedMethod
            ),
            Observation::Refused(
                Some("account".into()),
                Some(unknown),
                AuthRejectionReason::KeyNotAuthorized
            ),
            Observation::Refused(
                Some("account".into()),
                Some(client.key.clone()),
                AuthRejectionReason::InvalidSignature
            ),
            Observation::Verified("account".into(), client.key.clone()),
        ]
    );
    // Verification is observable even when the client never opens a channel.
    assert_eq!(client.executions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authentication_observer_reports_unsupported_and_malformed_public_keys() {
    let key = signing_key();
    let mut client = Client::connect(&key).await;
    for (algorithm, blob) in [
        (b"unsupported-key".as_slice(), b"unused".as_slice()),
        (ALGORITHM, b"truncated".as_slice()),
    ] {
        let mut request = vec![50];
        string(&mut request, USER);
        string(&mut request, b"ssh-connection");
        string(&mut request, b"publickey");
        request.push(0);
        string(&mut request, algorithm);
        string(&mut request, blob);
        client.send(&request).await;
        assert_eq!(client.receive().await, auth_failure());
    }
    assert_eq!(
        *client.observations.lock().unwrap(),
        vec![
            Observation::Refused(
                Some("account".into()),
                None,
                AuthRejectionReason::UnsupportedKeyAlgorithm
            ),
            Observation::Refused(
                Some("account".into()),
                None,
                AuthRejectionReason::MalformedPublicKey
            ),
        ]
    );
    assert_eq!(client.executions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authentication_observer_reports_signed_policy_denial_then_verified_success() {
    let registered = signing_key();
    let denied = signing_key();
    let mut client = Client::connect(&registered).await;
    let denied_blob = public_key(&denied);
    let mut request = auth_prefix(USER, &denied_blob, true);
    let data = signed_data(client.transport.session_id().unwrap(), &request);
    let mut signature = Vec::new();
    string(&mut signature, ALGORITHM);
    string(&mut signature, &denied.sign(&data).to_bytes());
    string(&mut request, &signature);
    client.send(&request).await;
    assert_eq!(client.receive().await, auth_failure());
    assert_eq!(
        *client.observations.lock().unwrap(),
        vec![Observation::Refused(
            Some("account".into()),
            Some(denied_blob),
            AuthRejectionReason::KeyNotAuthorized
        ),]
    );
    assert_eq!(client.executions.load(Ordering::SeqCst), 0);
    let data = client.data_to_sign(USER, client.transport.session_id().unwrap());
    assert_eq!(
        client
            .authenticate(&registered.sign(&data).to_bytes())
            .await,
        [52]
    );
    assert_eq!(
        client.observations.lock().unwrap().last(),
        Some(&Observation::Verified("account".into(), client.key.clone()))
    );
    assert_eq!(client.observations.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn authentication_observer_reports_unsupported_service_without_payload() {
    let registered = signing_key();
    let mut client = Client::connect(&registered).await;
    let mut request = vec![50];
    string(&mut request, USER);
    string(&mut request, b"unsupported-service");
    string(&mut request, b"publickey");
    request.push(0);
    string(&mut request, ALGORITHM);
    string(&mut request, &client.key);
    client.send(&request).await;
    assert_eq!(client.receive().await, auth_failure());
    assert_eq!(
        *client.observations.lock().unwrap(),
        vec![Observation::Refused(
            Some("account".into()),
            None,
            AuthRejectionReason::UnsupportedService
        ),]
    );
    assert_eq!(client.executions.load(Ordering::SeqCst), 0);
    let data = client.data_to_sign(USER, client.transport.session_id().unwrap());
    assert_eq!(
        client
            .authenticate(&registered.sign(&data).to_bytes())
            .await,
        [52]
    );
    assert_eq!(client.observations.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn authentication_observer_reports_invalid_username_length_and_utf8() {
    for invalid in [vec![b'x'; 257], vec![0xff]] {
        let registered = signing_key();
        let mut client = Client::connect(&registered).await;
        client
            .send(&auth_prefix(&invalid, &client.key.clone(), false))
            .await;
        let result = timeout(DEADLINE, &mut client.server)
            .await
            .expect("invalid username must terminate promptly")
            .expect("production server panicked");
        assert!(
            matches!(result, Err(SshError::ProtocolError(_))),
            "{result:?}"
        );
        assert_eq!(
            *client.observations.lock().unwrap(),
            vec![Observation::Refused(
                None,
                None,
                AuthRejectionReason::InvalidUsername
            ),]
        );
        assert_eq!(client.executions.load(Ordering::SeqCst), 0);
    }
}
