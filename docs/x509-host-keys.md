# RFC 6187 RSA certificate host keys

Client-side `x509v3-ssh-rsa` support is disabled by default. Enable it with
`SshClient::with_x509_host_keys(true)` or `Transport::set_x509_host_keys(true)`.
The opt-in places the certificate algorithm first in the client proposal.
No server-side certificate algorithm is advertised or implemented.

```rust,no_run
use ayssh::{SshClient, host_key_verify::TofuFileStore};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = SshClient::new("test-host".into(), 22).with_x509_host_keys(true);
let mut transport = client.connect().await?;
let pins = TofuFileStore::new("./certificate_known_hosts")?;
transport.handshake_with_verifier(&pins).await?;
// Key exchange is complete; this example does not authenticate.
drop(transport);
# Ok(()) }
```

The end-entity certificate subject and SHA-256 fingerprint are printed after
successful exchange-hash signature verification. `StrictFileStore`,
`TofuFileStore`, and `TofuStore` compare the SHA-256 digest of the leaf DER.
For certificate entries, the known_hosts-style format is:

```
host x509v3-ssh-rsa BASE64_OF_32_BYTE_SHA256_DIGEST
```

Use `[host]:port` for nonstandard ports. The displayed fingerprint uses
`SHA256:` followed by unpadded base64; the file stores the digest as padded
base64 without that prefix. Chain and OCSP changes do not change the pin.
Existing accept-all / handshake-without-verifier mode is also supported.
A custom `HostKeyVerifier` receives the complete RFC 6187 blob.

The parser uses RustCrypto's pure-Rust [x509-cert 0.2.5](https://docs.rs/x509-cert/0.2.5/),
pinned exactly to retain compatibility with the existing DER/SPKI dependencies.
Limits are 1 MiB per blob, 32 certificates, 32 OCSP responses, and 256 KiB per
certificate/response. Certificates require valid DER and the leaf requires an
RSA SubjectPublicKeyInfo. OCSP receives DER framing checks only.
RFC 6187 section 3.2 requires an `ssh-rsa` PKCS#1 v1.5 / SHA-1 signature over
the exchange hash, verified before accepting or persisting a certificate pin.

TODO: CA chain, validity, key usage, hostname identity, and revocation validation.
Certificate acceptance currently means fingerprint trust, with no CA validation.
Server support and `x509v3-rsa2048-sha256` / ECDSA variants remain future work.
