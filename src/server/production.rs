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
            io.send(&channel_message(100, channel.peer)).await?;
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
            return Err(protocol("Account name too long"));
        }
        let username =
            std::str::from_utf8(username).map_err(|_| protocol("Account name is not UTF-8"))?;
        let service = fields.string()?;
        let method = fields.string()?;
        if service != b"ssh-connection" || method != b"publickey" {
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
            io.send_message(&failure).await?;
            continue;
        }
        let mut key_fields = Fields(blob);
        if key_fields.string()? != algorithm {
            return Err(protocol("Public key algorithm mismatch"));
        }
        let key_bytes: &[u8; 32] = key_fields
            .string()?
            .try_into()
            .map_err(|_| protocol("Invalid Ed25519 key length"))?;
        key_fields.end()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
            .map_err(|_| protocol("Invalid Ed25519 public key"))?;
        if let Some(signature) = signature {
            let mut signature_fields = Fields(signature);
            if signature_fields.string()? != algorithm {
                return Err(protocol("Signature algorithm mismatch"));
            }
            let signature = ed25519_dalek::Signature::from_slice(signature_fields.string()?)
                .map_err(|_| protocol("Invalid Ed25519 signature length"))?;
            signature_fields.end()?;
            let mut signed_data = Vec::new();
            string(&mut signed_data, session_id);
            signed_data.extend_from_slice(&request[..signed_prefix]);
            // RFC 4252 section 7 binds username, service, key and signature to
            // this transport's original session ID. Strict verification also
            // rejects weak/noncanonical Ed25519 signatures.
            if key.verify_strict(&signed_data, &signature).is_ok()
                && handler.authorize_public_key(username, blob).await
            {
                io.send_message(&[52]).await?;
                return Ok(username.to_owned());
            }
        } else if handler.authorize_public_key(username, blob).await {
            let mut challenge = vec![60];
            string(&mut challenge, algorithm);
            string(&mut challenge, blob);
            io.send_message(&challenge).await?;
            continue;
        }
        io.send_message(&failure).await?;
    }
    Err(SshError::AuthenticationFailed(
        "Authentication attempt limit reached".into(),
    ))
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
