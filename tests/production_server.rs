//! Production server interoperability with a real OpenSSH client.
//!
//! Authentication follows RFC 4252 section 7; channel execution, extended data,
//! EOF and exit status follow RFC 4254 sections 5 and 6. These tests deliberately
//! use an external client so signed authentication and stream framing are real.

use async_trait::async_trait;
use ayssh::error::SshError;
use ayssh::server::{serve_connection, HostKeyPair, ServerHandler};
use base64::Engine;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(20);

struct Handler {
    key: Vec<u8>,
    executions: Arc<AtomicUsize>,
}

#[async_trait]
impl ServerHandler for Handler {
    async fn authorize_public_key(&self, username: &str, public_key: &[u8]) -> bool {
        username == "account" && public_key == self.key
    }

    async fn exec(&self, username: &str, command: &[u8]) -> Result<Option<Command>, SshError> {
        assert_eq!(username, "account");
        self.executions.fetch_add(1, Ordering::SeqCst);
        let script = match command {
            b"echo-stream" => "printf 'ready\\n'; cat; printf 'diagnostic\\n' >&2; exit 23",
            b"succeed" => "printf 'accepted\\n'",
            _ => return Ok(None),
        };
        let mut child = Command::new("sh");
        child.args(["-c", script]);
        Ok(Some(child))
    }
}

struct Fixture {
    directory: TempDir,
    key: PathBuf,
    port: u16,
    executions: Arc<AtomicUsize>,
    server: JoinHandle<Result<(), SshError>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn generate_key(path: &Path) {
    let output = timeout(
        DEADLINE,
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("ssh-keygen timed out")
    .expect("ssh-keygen must be installed for production server interoperability tests");
    assert!(output.status.success(), "ssh-keygen: {:?}", output);
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("identity");
        generate_key(&key).await;
        let public_key = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let blob = base64::engine::general_purpose::STANDARD
            .decode(public_key.split_whitespace().nth(1).unwrap())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let executions = Arc::new(AtomicUsize::new(0));
        let handler = Handler {
            key: blob,
            executions: executions.clone(),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            serve_connection(stream, &HostKeyPair::generate_ed25519(), &handler).await
        });
        Self {
            directory,
            key,
            port,
            executions,
            server,
        }
    }

    fn ssh(&self, key: &Path) -> Command {
        let mut command = Command::new("ssh");
        command
            .args([
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=5",
            ])
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.directory.path().join("known_hosts").display()
            ))
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-i")
            .arg(key)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    async fn run(&self, options: &[&str], remote_command: Option<&str>) -> Output {
        let mut client = self.ssh(&self.key);
        client.args(options).arg("account@127.0.0.1");
        if let Some(remote_command) = remote_command {
            client.arg(remote_command);
        }
        timeout(DEADLINE, client.output())
            .await
            .expect("ssh timed out")
            .expect("ssh must be installed")
    }

    fn assert_no_exec(&self) {
        assert_eq!(
            self.executions.load(Ordering::SeqCst),
            0,
            "rejected request reached exec handler"
        );
    }
}

#[tokio::test]
async fn registered_key_exec_streams_binary_input_output_stderr_and_exit_status() {
    let mut fixture = Fixture::new().await;
    let mut client = fixture.ssh(&fixture.key);
    let mut child = client
        .args(["-T", "account@127.0.0.1", "echo-stream"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut ready = [0; 6];
    timeout(DEADLINE, stdout.read_exact(&mut ready))
        .await
        .expect("stdout must arrive before stdin closes")
        .unwrap();
    assert_eq!(&ready, b"ready\n");

    // Exceed typical SSH channel windows and include every byte value. Reading
    // and writing concurrently catches deadlocks and accidental text conversion.
    let payload: Vec<u8> = (0..3 * 1024 * 1024).map(|n| (n % 256) as u8).collect();
    let mut stdin = child.stdin.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let result = timeout(DEADLINE, async {
        let writer = async {
            stdin.write_all(&payload).await.unwrap();
            stdin.shutdown().await.unwrap();
            drop(stdin);
        };
        let reader = async {
            let mut data = Vec::new();
            stdout.read_to_end(&mut data).await.unwrap();
            data
        };
        let errors = async {
            let mut data = Vec::new();
            stderr.read_to_end(&mut data).await.unwrap();
            data
        };
        let (_, data, errors, status) = tokio::join!(writer, reader, errors, child.wait());
        (data, errors, status.unwrap())
    })
    .await
    .expect("bidirectional exec streaming timed out");
    assert_eq!(result.0, payload);
    assert_eq!(result.1, b"diagnostic\n");
    assert_eq!(result.2.code(), Some(23));
    assert_eq!(fixture.executions.load(Ordering::SeqCst), 1);
    timeout(DEADLINE, &mut fixture.server)
        .await
        .expect("server did not close")
        .expect("server task panicked")
        .expect("server rejected authenticated exec");
}

#[tokio::test]
async fn unregistered_key_cannot_execute() {
    let fixture = Fixture::new().await;
    let wrong_key = fixture.directory.path().join("unregistered");
    generate_key(&wrong_key).await;
    let output = timeout(
        DEADLINE,
        fixture
            .ssh(&wrong_key)
            .args(["-T", "account@127.0.0.1", "succeed"])
            .output(),
    )
    .await
    .expect("ssh timed out")
    .unwrap();
    assert_eq!(output.status.code(), Some(255), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Permission denied"),
        "{output:?}"
    );
    assert!(output.stdout.is_empty());
    fixture.assert_no_exec();
}

#[tokio::test]
async fn registered_key_cannot_authenticate_as_another_account() {
    let fixture = Fixture::new().await;
    let output = timeout(
        DEADLINE,
        fixture
            .ssh(&fixture.key)
            .args(["-T", "other@127.0.0.1", "succeed"])
            .output(),
    )
    .await
    .expect("ssh timed out")
    .unwrap();
    assert_eq!(output.status.code(), Some(255), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Permission denied"),
        "{output:?}"
    );
    fixture.assert_no_exec();
}

#[tokio::test]
async fn credential_free_authentication_is_rejected() {
    let fixture = Fixture::new().await;
    let mut command = Command::new("ssh");
    let output = timeout(
        DEADLINE,
        command
            .args([
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=none",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ])
            .arg("-p")
            .arg(fixture.port.to_string())
            .args(["account@127.0.0.1", "succeed"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("ssh timed out")
    .unwrap();
    assert_eq!(output.status.code(), Some(255), "{output:?}");
    fixture.assert_no_exec();
}

#[tokio::test]
async fn shell_request_is_rejected() {
    let fixture = Fixture::new().await;
    let output = fixture.run(&["-T"], None).await;
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("shell request failed"),
        "{output:?}"
    );
    fixture.assert_no_exec();
}

#[tokio::test]
async fn pty_request_is_rejected() {
    let fixture = Fixture::new().await;
    let output = fixture.run(&["-tt"], Some("succeed")).await;
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("PTY allocation request failed"),
        "{output:?}"
    );
}

#[tokio::test]
async fn direct_tcp_forwarding_is_rejected() {
    let fixture = Fixture::new().await;
    let output = fixture.run(&["-W", "127.0.0.1:9"], None).await;
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("open failed"),
        "{output:?}"
    );
    fixture.assert_no_exec();
}

#[tokio::test]
async fn remote_tcp_forwarding_is_rejected() {
    let fixture = Fixture::new().await;
    let output = fixture
        .run(
            &[
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-R",
                "0:127.0.0.1:9",
            ],
            None,
        )
        .await;
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("remote port forwarding failed"),
        "{output:?}"
    );
    fixture.assert_no_exec();
}

#[tokio::test]
async fn handler_may_reject_an_exec_command() {
    let fixture = Fixture::new().await;
    let output = fixture.run(&["-T"], Some("unrecognized")).await;
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exec request failed"),
        "{output:?}"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(fixture.executions.load(Ordering::SeqCst), 1);
}
