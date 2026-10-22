# Authenticated SSH command server

`ayssh::server::serve_connection(stream, &host_key, &handler)` serves an accepted
Tokio TCP stream. The caller owns the listener, connection concurrency limits,
persistent host key and application policy. `TestSshServer` and its scripted
authentication modes remain independent test fixtures.

Implement `ServerHandler` with `async_trait`:

```rust,ignore
#[async_trait::async_trait]
impl ayssh::server::ServerHandler for Handler {
    async fn authorize_public_key(&self, user: &str, blob: &[u8]) -> bool {
        // Compare the entire SSH wire-format public key with this user's keys.
        self.registered_key(user, blob).await
    }

    async fn exec(
        &self,
        user: &str,
        command: &[u8],
    ) -> Result<Option<tokio::process::Command>, ayssh::error::SshError> {
        // Parse untrusted bytes, authorize the account and select an executable.
        // None rejects execution; do not pass untrusted text to `sh -c`.
        let Some(arguments) = self.authorize_command(user, command).await else {
            return Ok(None);
        };
        let mut process = tokio::process::Command::new("/usr/local/bin/service");
        process.args(arguments).env_clear().current_dir("/srv/service");
        Ok(Some(process))
    }
}
```

The public key callback receives the decoded SSH wire-format blob, not an
OpenSSH public-key line or base64 text. Authentication supports `ssh-ed25519`
only. Unknown algorithms and every other authentication method are refused.
The callback may run for both an unsigned key query and a signed request.
Accepting a query sends `USERAUTH_PK_OK` only; the server authenticates only after
strict Ed25519 verification of the signature over the initial session ID and
complete authentication request, as specified in RFC 4252 section 7. The callback
must authorize both the username and complete public key, not just the username
or algorithm. The server does not log credentials, keys or commands.

Two optional callbacks let an application audit authentication; both default to
doing nothing. `auth_refused(username, public_key, reason)` runs before each
`USERAUTH_FAILURE` with an `AuthRejectionReason` (invalid username, unsupported
service, method or key algorithm, malformed key, invalid signature, key not
authorized). The username is claimed, not verified; the key blob is supplied only
when it decoded as a supported key. RFC 4252 section 5.2 `none` method discovery
is not reported. `authentication_succeeded(username, public_key)` runs after
signature verification and policy approval, before `USERAUTH_SUCCESS`; an unsigned
key query never calls it. Neither callback receives passwords or signatures, and
neither grants or denies access. Return promptly: both run inside the
authentication deadline.

Each connection permits one session channel and one exec command. The library
pipes binary stdin, stdout and stderr without text conversion. Client EOF closes
child stdin after queued data is consumed. Output streams share the peer's window
and obey its maximum packet size. Incoming input has a 1 MiB window and 32 KiB
maximum data packet; window credits return only when bytes are consumed or the
child has closed its input. Both output streams drain before `exit-status`, EOF
and channel close are sent (RFC 4254 sections 5.2, 5.3, 6.5 and 6.10). A process
terminated by a signal reports exit status 255.

Shell, PTY, subsystem, environment and forwarding requests are refused. Additional
channels are refused. Exec policy is entirely application-defined; the library
never invokes a shell implicitly. Applications should configure process arguments,
environment, working directory and OS isolation. Stdio configuration is overridden
with pipes. The command is spawned only after authenticated policy approval, and
request success is sent only after spawning succeeds.

Handshake and authentication together have a 30-second deadline and at most 16
authentication requests. Opening a session and selecting a command has another
30-second deadline. Socket writes have a 30-second deadline. The encrypted reader
runs separately with a bounded queue, so partial packet reads are never abandoned
when stdout, stderr or child stdin makes progress. A disconnected client or dropped
connection future kills the direct child; normal disconnect handling also reaps it.
Applications that launch descendants should arrange their own process-group or
container lifecycle. Authenticated commands have no execution or idle deadline;
callers can wrap `serve_connection` in their own timeout.

This initial API does not implement rekey, multiple sessions, SSH certificates,
password/keyboard-interactive authentication, signal requests or process-group
management. Rekey requests terminate the connection; long transfers must stay
below client rekey limits. Apply deployment resource limits and transport policy
appropriate to the application. The transport algorithm negotiation currently
shares the existing server transport implementation.

Run the real-client integration tests with:

```sh
cargo test --test production_server
```

They require `ssh`, `ssh-keygen`, `sh` and `cat`, isolate client configuration and
known-host files, and include a three-MiB binary stream and denied request cases.

Run the production authentication regression tests with:

```sh
cargo test --test production_auth
```

[`tests/production_auth.rs`](tests/production_auth.rs) drives `serve_connection`
over TCP using the client transport and hand-built signed authentication requests.
It first confirms the key is registered, then requires `USERAUTH_FAILURE` for a
random signature, a valid signature from another real transport session, and a
valid signature over a different username. None may reach the exec handler. A
matching signature authenticates and executes through the same harness. Replacing
the production authentication branch's signature check with unconditional `true`
makes all three negative tests fail on unexpected `USERAUTH_SUCCESS`; the positive
control still passes. Separate verifier unit tests cover truncated fields,
oversized encoded lengths, algorithm mismatches and trailing fields.
