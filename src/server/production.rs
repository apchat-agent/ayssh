//! Authenticated command server using RFC 4252 public-key authentication and
//! RFC 4254 session channels. Policy and executable selection belong to callers.

use super::encrypted_io::ServerEncryptedIO;
use super::test_server::{server_transport_handshake, AlgorithmFilter};
use super::HostKeyPair;
use crate::error::SshError;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedWriteHalf, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(30);
const WINDOW: u32 = 1024 * 1024;
const PACKET: usize = 32 * 1024;

/// Fixed categories for rejected RFC 4252 authentication attempts.
/// These carry no password, signature, arbitrary error string or method payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRejectionReason {
    InvalidUsername,
    UnsupportedService,
    UnsupportedMethod,
    UnsupportedKeyAlgorithm,
    MalformedPublicKey,
    InvalidSignature,
    KeyNotAuthorized,
}

/// Application policy for authenticated command execution.
///
/// The server verifies the RFC 4252 section 7 signature itself. The key callback
/// receives the exact SSH public-key blob, not its textual/base64 representation.
/// It is also called for unsigned key queries; a `true` result only permits a
/// signature challenge, never authentication without proof of key possession.
#[async_trait]
pub trait ServerHandler: Send + Sync {
    /// Authorize this key for this account. Unsupported key algorithms are
    /// rejected before this callback; currently only `ssh-ed25519` is supported.
    async fn authorize_public_key(&self, username: &str, public_key: &[u8]) -> bool;

    /// Observe one rejected authentication attempt, before its failure response.
    /// The username is claimed, not authenticated. Public-key bytes are supplied
    /// only for a well-formed supported key; observers may hash them for a public
    /// fingerprint. Passwords, signatures and arbitrary method payloads are never
    /// supplied. RFC 4252 section 5.2 `none` discovery is not a credential attempt.
    /// Malformed wire framing and transport failures remain serve_connection errors.
    /// Observers must return promptly; the existing authentication deadline applies.
    async fn auth_refused(
        &self,
        _username: Option<&str>,
        _public_key: Option<&[u8]>,
        _reason: AuthRejectionReason,
    ) {
    }

    /// Observe verified identity after signature and policy checks, before
    /// USERAUTH_SUCCESS and before any channel or exec request. An unsigned key
    /// query never invokes this callback. The callback does not grant authority.
    async fn authentication_succeeded(&self, _username: &str, _public_key: &[u8]) {}

    /// Select an executable for a verified account and untrusted command bytes.
    /// Return `None` to refuse the request. No shell interpretation is performed
    /// by the library. Configure arguments, environment, cwd and isolation here.
    /// The server overrides stdin/stdout/stderr with pipes and enables kill-on-drop.
    async fn exec(&self, username: &str, command: &[u8]) -> Result<Option<Command>, SshError>;
}

/// Serve one TCP connection and one session command (RFC 4254 sections 5–6).
///
/// Only signed Ed25519 public-key authentication is accepted. Shell, PTY,
/// subsystem, environment, forwarding and additional session channels are refused.
/// Initial handshake/authentication and pre-exec requests have 30-second deadlines.
/// Supply a persistent host key; accept-loop limits and process isolation remain
/// the caller's responsibility. See `SERVER-API.md` for operational limitations.
pub async fn serve_connection<H: ServerHandler + ?Sized>(
    stream: TcpStream,
    host_key: &HostKeyPair,
    handler: &H,
) -> Result<(), SshError> {
    let (io, username) = timeout(TIMEOUT, async {
        let (mut io, session_id) = server_transport_handshake(
            stream,
            host_key,
            &AlgorithmFilter::default(),
            Some(b"ssh-ed25519"),
        )
        .await?;
        let username = authenticate(&mut io, &session_id, handler).await?;
        Ok::<_, SshError>((io, username))
    })
    .await
    .map_err(|_| SshError::TimeoutError)??;
    let mut io = Messages::new(io);
    let (channel, mut command) = timeout(TIMEOUT, open_exec(&mut io, handler, &username))
        .await
        .map_err(|_| SshError::TimeoutError)??;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            // RFC 4254 section 5.4: reply only when the request asks for one.
            if channel.exec_reply {
                io.send(&channel_message(100, channel.peer)).await?;
            }
            return Err(error.into());
        }
    };
    // Acceptance is sent only after the application process really starts.
    if channel.exec_reply {
        io.send(&channel_message(99, channel.peer)).await?;
    }
    let result = run_command(&mut io, channel, &mut child).await;
    if result.is_err() || child.try_wait()?.is_none() {
        // kill() also waits, preventing zombies when a client disconnects.
        let _ = child.kill().await;
    }
    result
}

fn protocol(message: &str) -> SshError {
    SshError::ProtocolError(message.into())
}

/// Bounds-checked decoder; all network-controlled lengths are checked before use.
struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], SshError> {
        if length > self.0.len() {
            return Err(protocol("Truncated SSH message"));
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, SshError> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> Result<bool, SshError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(protocol("Invalid SSH boolean")),
        }
    }
    fn number(&mut self) -> Result<u32, SshError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<&'a [u8], SshError> {
        let length = self.number()? as usize;
        self.take(length)
    }
    fn end(&self) -> Result<(), SshError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(protocol("Unexpected trailing SSH fields"))
        }
    }
    fn recipient(&mut self) -> Result<(), SshError> {
        if self.number()? == 0 {
            Ok(())
        } else {
            Err(protocol("Unknown session channel"))
        }
    }
}
fn string(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    message.extend_from_slice(bytes);
}
fn channel_message(kind: u8, recipient: u32) -> Vec<u8> {
    let mut message = vec![kind];
    message.extend_from_slice(&recipient.to_be_bytes());
    message
}

async fn authenticate<H: ServerHandler + ?Sized>(
    io: &mut ServerEncryptedIO,
    session_id: &[u8],
    handler: &H,
) -> Result<String, SshError> {
    let service = io.recv_message().await?;
    let mut fields = Fields(&service);
    if fields.byte()? != 5 || fields.string()? != b"ssh-userauth" {
        return Err(protocol("Expected ssh-userauth service"));
    }
    fields.end()?;
    let mut accept = vec![6];
    string(&mut accept, b"ssh-userauth");
    io.send_message(&accept).await?;
    let mut failure = vec![51];
    string(&mut failure, b"publickey");
    failure.push(0);
    // Bound credential attempts even when a caller supplies an expensive lookup.
    for _ in 0..16 {
        let request = io.recv_message().await?;
        let mut fields = Fields(&request);
        if fields.byte()? != 50 {
            return Err(protocol("Expected authentication request"));
        }
        let username = fields.string()?;
        if username.len() > 256 {
            handler
                .auth_refused(None, None, AuthRejectionReason::InvalidUsername)
                .await;
            return Err(protocol("Account name too long"));
        }
        let username = match std::str::from_utf8(username) {
            Ok(username) => username,
            Err(_) => {
                handler
                    .auth_refused(None, None, AuthRejectionReason::InvalidUsername)
                    .await;
                return Err(protocol("Account name is not UTF-8"));
            }
        };
        let service = fields.string()?;
        let method = fields.string()?;
        if service != b"ssh-connection" {
            handler
                .auth_refused(
                    Some(username),
                    None,
                    AuthRejectionReason::UnsupportedService,
                )
                .await;
            io.send_message(&failure).await?;
            continue;
        }
        if method != b"publickey" {
            // RFC 4252 section 5.2: clients commonly discover available methods
            // with `none`; it supplies no credential and is not an auth attempt.
            if method != b"none" {
                handler
                    .auth_refused(Some(username), None, AuthRejectionReason::UnsupportedMethod)
                    .await;
            }
            io.send_message(&failure).await?;
            continue;
        }
        let signed = fields.boolean()?;
        let algorithm = fields.string()?;
        let blob = fields.string()?;
        let signed_prefix = request.len() - fields.0.len();
        let signature = if signed { Some(fields.string()?) } else { None };
        fields.end()?;
        if algorithm != b"ssh-ed25519" {
            handler
                .auth_refused(
                    Some(username),
                    None,
                    AuthRejectionReason::UnsupportedKeyAlgorithm,
                )
                .await;
            io.send_message(&failure).await?;
            continue;
        }
        if decode_public_key(blob).is_err() {
            handler
                .auth_refused(
                    Some(username),
                    None,
                    AuthRejectionReason::MalformedPublicKey,
                )
                .await;
            io.send_message(&failure).await?;
            continue;
        }
        let reason = if let Some(signature) = signature {
            // Preserve the security boundary: verify before consulting policy.
            if !verify_signature(session_id, &request[..signed_prefix], blob, signature) {
                AuthRejectionReason::InvalidSignature
            } else if !handler.authorize_public_key(username, blob).await {
                AuthRejectionReason::KeyNotAuthorized
            } else {
                handler.authentication_succeeded(username, blob).await;
                io.send_message(&[52]).await?;
                return Ok(username.to_owned());
            }
        } else if handler.authorize_public_key(username, blob).await {
            let mut challenge = vec![60];
            string(&mut challenge, algorithm);
            string(&mut challenge, blob);
            io.send_message(&challenge).await?;
            continue;
        } else {
            AuthRejectionReason::KeyNotAuthorized
        };
        handler
            .auth_refused(Some(username), Some(blob), reason)
            .await;
        io.send_message(&failure).await?;
    }
    Err(SshError::AuthenticationFailed(
        "Authentication attempt limit reached".into(),
    ))
}

fn decode_public_key(blob: &[u8]) -> Result<ed25519_dalek::VerifyingKey, SshError> {
    let mut fields = Fields(blob);
    if fields.string()? != b"ssh-ed25519" {
        return Err(protocol("Unsupported public key algorithm"));
    }
    let bytes: &[u8; 32] = fields
        .string()?
        .try_into()
        .map_err(|_| protocol("Invalid Ed25519 key length"))?;
    fields.end()?;
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|_| protocol("Invalid Ed25519 public key"))
}

/// Verify the RFC 4252 section 7 signature over the original transport session
/// identifier and complete USERAUTH_REQUEST prefix. Strict verification rejects
/// weak/noncanonical Ed25519 signatures. Malformed wire blobs fail closed.
fn verify_signature(
    session_id: &[u8],
    request_prefix: &[u8],
    public_key_blob: &[u8],
    signature_blob: &[u8],
) -> bool {
    let verify = || -> Result<(), SshError> {
        let key = decode_public_key(public_key_blob)?;
        let mut fields = Fields(signature_blob);
        if fields.string()? != b"ssh-ed25519" {
            return Err(protocol("Unsupported signature algorithm"));
        }
        let signature = ed25519_dalek::Signature::from_slice(fields.string()?)
            .map_err(|_| protocol("Invalid Ed25519 signature length"))?;
        fields.end()?;
        let mut signed_data = Vec::new();
        string(&mut signed_data, session_id);
        signed_data.extend_from_slice(request_prefix);
        key.verify_strict(&signed_data, &signature)
            .map_err(|_| protocol("Invalid authentication signature"))
    };
    verify().is_ok()
}

struct Messages {
    input: mpsc::Receiver<Result<Vec<u8>, SshError>>,
    output: ServerEncryptedIO<OwnedWriteHalf>,
    reader: JoinHandle<()>,
}
impl Drop for Messages {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
impl Messages {
    fn new(io: ServerEncryptedIO) -> Self {
        let (mut input, output) = io.into_split();
        let (tx, rx) = mpsc::channel(32);
        let reader = tokio::spawn(async move {
            loop {
                // This future is never selected against another operation.
                // Partial encrypted packets remain owned by this reader until
                // complete; cancellation only happens when the connection ends.
                let message = input.recv_message().await;
                let failed = message.is_err();
                if tx.send(message).await.is_err() || failed {
                    break;
                }
            }
        });
        Self {
            input: rx,
            output,
            reader,
        }
    }
    async fn receive(&mut self) -> Result<Vec<u8>, SshError> {
        self.input
            .recv()
            .await
            .ok_or_else(|| protocol("Connection reader stopped"))?
    }
    async fn send(&mut self, message: &[u8]) -> Result<(), SshError> {
        timeout(TIMEOUT, self.output.send_message(message))
            .await
            .map_err(|_| SshError::TimeoutError)?
    }
}

struct Channel {
    peer: u32,
    send_window: u32,
    max_packet: u32,
    exec_reply: bool,
    input_eof: bool,
}

async fn reject_open(io: &mut Messages, peer: u32) -> Result<(), SshError> {
    let mut failure = channel_message(92, peer);
    failure.extend_from_slice(&1u32.to_be_bytes()); // administratively prohibited
    string(&mut failure, b"Only one session channel is permitted");
    string(&mut failure, b"");
    io.send(&failure).await
}
async fn reject_global(io: &mut Messages, fields: &mut Fields<'_>) -> Result<(), SshError> {
    fields.string()?;
    if fields.boolean()? {
        io.send(&[82]).await?;
    }
    Ok(())
}

async fn open_exec<H: ServerHandler + ?Sized>(
    io: &mut Messages,
    handler: &H,
    username: &str,
) -> Result<(Channel, Command), SshError> {
    let mut channel: Option<Channel> = None;
    loop {
        let message = io.receive().await?;
        let mut fields = Fields(&message);
        match fields.byte()? {
            2 | 4 => {} // transport IGNORE / DEBUG
            80 => reject_global(io, &mut fields).await?,
            90 => {
                let kind = fields.string()?;
                let peer = fields.number()?;
                let send_window = fields.number()?;
                let max_packet = fields.number()?;
                if kind != b"session" || channel.is_some() {
                    reject_open(io, peer).await?;
                    continue;
                }
                fields.end()?;
                if max_packet == 0 {
                    return Err(protocol("Zero channel packet limit"));
                }
                let mut confirmation = channel_message(91, peer);
                confirmation.extend_from_slice(&0u32.to_be_bytes());
                confirmation.extend_from_slice(&WINDOW.to_be_bytes());
                confirmation.extend_from_slice(&(PACKET as u32).to_be_bytes());
                io.send(&confirmation).await?;
                channel = Some(Channel {
                    peer,
                    send_window,
                    max_packet,
                    exec_reply: false,
                    input_eof: false,
                });
            }
            98 => {
                fields.recipient()?;
                let channel = channel
                    .as_mut()
                    .ok_or_else(|| protocol("Request before channel open"))?;
                let kind = fields.string()?;
                let want_reply = fields.boolean()?;
                if kind == b"exec" {
                    let command = fields.string()?;
                    fields.end()?;
                    if let Some(command) = handler.exec(username, command).await? {
                        channel.exec_reply = want_reply;
                        return Ok((Channel { ..*channel }, command));
                    }
                }
                if want_reply {
                    io.send(&channel_message(100, channel.peer)).await?;
                }
            }
            93 => {
                fields.recipient()?;
                let channel = channel
                    .as_mut()
                    .ok_or_else(|| protocol("Window update before channel open"))?;
                channel.send_window = channel
                    .send_window
                    .checked_add(fields.number()?)
                    .ok_or_else(|| protocol("Channel window overflow"))?;
                fields.end()?;
            }
            96 => {
                fields.recipient()?;
                fields.end()?;
                channel
                    .as_mut()
                    .ok_or_else(|| protocol("EOF before channel open"))?
                    .input_eof = true;
            }
            97 => {
                fields.recipient()?;
                fields.end()?;
                if let Some(channel) = channel {
                    io.send(&channel_message(97, channel.peer)).await?;
                }
                return Err(protocol("Session closed before exec"));
            }
            _ => return Err(protocol("Unexpected message before exec")),
        }
    }
}

async fn run_command(
    io: &mut Messages,
    mut channel: Channel,
    child: &mut Child,
) -> Result<(), SshError> {
    let mut stdin = child.stdin.take();
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| protocol("Missing child stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| protocol("Missing child stderr"))?;
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut input_offset = 0;
    let mut receive_window = WINDOW;
    let mut input_eof = channel.input_eof;
    let mut output_eof = false;
    let mut error_eof = false;
    let mut output_buffer = vec![0; PACKET];
    let mut error_buffer = vec![0; PACKET];
    let mut output_pending = Vec::new();
    let mut error_pending = Vec::new();
    let mut status = None;
    loop {
        if input_eof && queue.is_empty() {
            stdin.take();
        }
        // RFC 4254 section 5.2: normal and extended data share one send window.
        for (kind, pending) in [(94, &mut output_pending), (95, &mut error_pending)] {
            if !pending.is_empty() && channel.send_window > 0 {
                let size = pending
                    .len()
                    .min(channel.send_window as usize)
                    .min(channel.max_packet as usize);
                let mut message = channel_message(kind, channel.peer);
                if kind == 95 {
                    message.extend_from_slice(&1u32.to_be_bytes());
                }
                string(&mut message, &pending[..size]);
                io.send(&message).await?;
                pending.drain(..size);
                channel.send_window -= size as u32;
            }
        }
        if channel.send_window > 0 && (!output_pending.is_empty() || !error_pending.is_empty()) {
            continue;
        }
        if status.is_some()
            && output_eof
            && error_eof
            && output_pending.is_empty()
            && error_pending.is_empty()
        {
            break;
        }
        if stdin.is_none() && !queue.is_empty() {
            // A process may exit or close its input while the client still sends.
            // Discard accepted input without retaining memory or stalling output.
            let discarded = queue.iter().map(Vec::len).sum::<usize>() - input_offset;
            queue.clear();
            input_offset = 0;
            receive_window += discarded as u32;
            let mut adjust = channel_message(93, channel.peer);
            adjust.extend_from_slice(&(discarded as u32).to_be_bytes());
            io.send(&adjust).await?;
        }
        tokio::select! {
            message = io.receive() => {
                let message = message?;
                let mut fields = Fields(&message);
                match fields.byte()? {
                    2 | 4 => {},
                    80 => reject_global(io, &mut fields).await?,
                    90 => {
                        fields.string()?;
                        let peer = fields.number()?;
                        reject_open(io, peer).await?;
                    }
                    93 => {
                        fields.recipient()?;
                        channel.send_window = channel.send_window.checked_add(fields.number()?)
                            .ok_or_else(|| protocol("Channel window overflow"))?;
                        fields.end()?;
                    }
                    94 => {
                        fields.recipient()?;
                        let data = fields.string()?;
                        fields.end()?;
                        if input_eof || data.len() > PACKET || data.len() > receive_window as usize {
                            return Err(protocol("Invalid channel input or receive window exceeded"));
                        }
                        receive_window -= data.len() as u32;
                        if !data.is_empty() { queue.push_back(data.to_vec()); }
                    }
                    96 => { fields.recipient()?; fields.end()?; input_eof = true; }
                    97 => {
                        fields.recipient()?; fields.end()?;
                        io.send(&channel_message(97, channel.peer)).await?;
                        return Ok(());
                    }
                    98 => {
                        fields.recipient()?;
                        fields.string()?;
                        if fields.boolean()? { io.send(&channel_message(100, channel.peer)).await?; }
                    }
                    _ => return Err(protocol("Unexpected message during exec")),
                }
            }
            written = async {
                stdin.as_mut().unwrap().write(&queue.front().unwrap()[input_offset..]).await
            }, if stdin.is_some() && !queue.is_empty() => {
                match written {
                    Ok(0) | Err(_) => { stdin.take(); }
                    Ok(size) => {
                        input_offset += size;
                        if input_offset == queue.front().unwrap().len() { queue.pop_front(); input_offset = 0; }
                        receive_window += size as u32;
                        let mut adjust = channel_message(93, channel.peer);
                        adjust.extend_from_slice(&(size as u32).to_be_bytes());
                        io.send(&adjust).await?;
                    }
                }
            }
            read = stdout.read(&mut output_buffer), if !output_eof && output_pending.is_empty() => {
                let size = read?;
                output_eof = size == 0;
                output_pending = output_buffer[..size].to_vec();
            }
            read = stderr.read(&mut error_buffer), if !error_eof && error_pending.is_empty() => {
                let size = read?;
                error_eof = size == 0;
                error_pending = error_buffer[..size].to_vec();
            }
            exit = child.wait(), if status.is_none() => {
                status = Some(exit?);
                stdin.take();
            }
        }
    }
    // Drain both streams before reporting completion; exit status then EOF then
    // CLOSE implements RFC 4254 sections 6.10 and 5.3 without truncating output.
    let mut exit = channel_message(98, channel.peer);
    string(&mut exit, b"exit-status");
    exit.push(0);
    exit.extend_from_slice(&(status.unwrap().code().unwrap_or(255) as u32).to_be_bytes());
    io.send(&exit).await?;
    io.send(&channel_message(96, channel.peer)).await?;
    io.send(&channel_message(97, channel.peer)).await?;
    // Do not reset the TCP connection before OpenSSH consumes buffered output.
    let _ = timeout(Duration::from_secs(5), async {
        while let Ok(message) = io.receive().await {
            if message.first() == Some(&97) {
                break;
            }
        }
    })
    .await;
    Ok(())
}
#[cfg(test)]
mod signature_tests {
    use super::verify_signature;
    use ed25519_dalek::{Signer, SigningKey};

    fn wire_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn public_blob(key: &SigningKey) -> Vec<u8> {
        let mut blob = Vec::new();
        wire_string(&mut blob, b"ssh-ed25519");
        wire_string(&mut blob, &key.verifying_key().to_bytes());
        blob
    }

    // RFC 4252 section 7: the signature covers the initial session identifier
    // followed by USERAUTH_REQUEST through the complete public-key blob.
    fn request(username: &[u8], key_blob: &[u8]) -> Vec<u8> {
        let mut request = vec![50];
        wire_string(&mut request, username);
        wire_string(&mut request, b"ssh-connection");
        wire_string(&mut request, b"publickey");
        request.push(1);
        wire_string(&mut request, b"ssh-ed25519");
        wire_string(&mut request, key_blob);
        request
    }

    fn sign(key: &SigningKey, session_id: &[u8], request: &[u8]) -> Vec<u8> {
        let mut signed_data = Vec::new();
        wire_string(&mut signed_data, session_id);
        signed_data.extend_from_slice(request);
        let mut signature = Vec::new();
        wire_string(&mut signature, b"ssh-ed25519");
        wire_string(&mut signature, &key.sign(&signed_data).to_bytes());
        signature
    }

    #[test]
    fn signed_authentication_request_is_verified() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let blob = public_blob(&key);
        let request = request(b"alice", &blob);
        let session = [11; 32];
        let signature = sign(&key, &session, &request);
        assert!(verify_signature(&session, &request, &blob, &signature));
    }

    #[test]
    fn signed_authentication_rejects_a_changed_username() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let blob = public_blob(&key);
        let original = request(b"alice", &blob);
        let tampered = request(b"carol", &blob);
        let session = [11; 32];
        let signature = sign(&key, &session, &original);
        assert!(!verify_signature(&session, &tampered, &blob, &signature));
    }

    #[test]
    fn signed_authentication_rejects_replay_on_another_session() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let blob = public_blob(&key);
        let request = request(b"alice", &blob);
        let signature = sign(&key, &[11; 32], &request);
        assert!(!verify_signature(&[12; 32], &request, &blob, &signature));
    }

    #[test]
    fn attacker_cannot_sign_for_another_public_key() {
        let registered = SigningKey::from_bytes(&[7; 32]);
        let attacker = SigningKey::from_bytes(&[9; 32]);
        let blob = public_blob(&registered);
        let request = request(b"alice", &blob);
        let session = [11; 32];
        let forged = sign(&attacker, &session, &request);
        assert!(!verify_signature(&session, &request, &blob, &forged));
    }

    #[test]
    fn truncated_key_and_signature_blobs_are_rejected_without_panicking() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let blob = public_blob(&key);
        let request = request(b"alice", &blob);
        let session = [11; 32];
        let signature = sign(&key, &session, &request);
        for length in 0..blob.len() {
            assert!(
                !verify_signature(&session, &request, &blob[..length], &signature),
                "accepted key truncated to {length} bytes"
            );
        }
        for length in 0..signature.len() {
            assert!(
                !verify_signature(&session, &request, &blob, &signature[..length]),
                "accepted signature truncated to {length} bytes"
            );
        }
    }

    #[test]
    fn malformed_key_and_signature_blobs_are_rejected_without_panicking() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let blob = public_blob(&key);
        let request = request(b"alice", &blob);
        let session = [11; 32];
        let signature = sign(&key, &session, &request);

        let mut wrong_key_algorithm = blob.clone();
        wrong_key_algorithm[4] = b'x';
        let mut trailing_key_bytes = blob.clone();
        trailing_key_bytes.push(0);
        let mut wrong_key_size = Vec::new();
        wire_string(&mut wrong_key_size, b"ssh-ed25519");
        wire_string(&mut wrong_key_size, &[7; 31]);
        for malformed in [
            vec![0xff; 4],
            wrong_key_algorithm,
            trailing_key_bytes,
            wrong_key_size,
        ] {
            assert!(!verify_signature(
                &session, &request, &malformed, &signature
            ));
        }

        let mut wrong_signature_algorithm = signature.clone();
        wrong_signature_algorithm[4] = b'x';
        let mut trailing_signature_bytes = signature.clone();
        trailing_signature_bytes.push(0);
        let mut corrupted_signature = signature.clone();
        *corrupted_signature.last_mut().unwrap() ^= 0x80;
        let mut wrong_signature_size = Vec::new();
        wire_string(&mut wrong_signature_size, b"ssh-ed25519");
        wire_string(&mut wrong_signature_size, &[7; 63]);
        for malformed in [
            vec![0xff; 4],
            wrong_signature_algorithm,
            trailing_signature_bytes,
            corrupted_signature,
            wrong_signature_size,
        ] {
            assert!(!verify_signature(&session, &request, &blob, &malformed));
        }
    }
}
