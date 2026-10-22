//! SSH Test Server
//!
//! A minimal SSH server implementation for testing all crypto algorithm
//! combinations. Reuses the same Transport primitives as the client,
//! validating the symmetric architecture.

pub mod encrypted_io;
pub mod host_key;
pub mod sftp_server;
pub mod test_server;

pub use encrypted_io::ServerEncryptedIO;
pub use host_key::HostKeyPair;
pub use sftp_server::{SftpHandler, SftpServerSession, MemoryFs};
pub use test_server::{TestSshServer, AlgorithmFilter, server_handshake};

pub mod production;
pub use production::{serve_connection, AuthRejectionReason, ServerHandler};
