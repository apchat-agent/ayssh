//! SSH Client Library
//!
//! This library provides a Rust implementation of an SSH client with support for:
//! - Asynchronous connections using Tokio
//! - Secure authentication
//! - Channel management
//!
//! # Example
//!
//! ```no_run
//! use ayssh::Config;
//!
//! // Example configuration
//! let config = Config::new()
//!     .with_host("example.com")
//!     .with_port(22)
//!     .with_username("user");
//! ```

pub mod agent;
pub mod auth;
pub mod channel;
pub mod cisco_conn;
pub mod cisco_ssh;
pub mod client;
pub mod server;
pub mod unix_conn;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod host_key_verify;
pub mod known_hosts;
pub mod multiplex;
pub mod port_forward;
pub mod raw_session;
pub mod keys;
pub mod protocol;
pub mod session;
pub mod sftp;
pub mod transport;
pub mod utils;

// Re-export commonly used items
pub use auth::AuthMethod;
pub use auth::AuthMethodManager;
pub use auth::Authenticator;
pub use auth::AuthenticationResult;
pub use auth::AuthState;
pub use channel::Channel;
pub use channel::ChannelId;
pub use channel::ChannelType;
pub use channel::ChannelManager;
pub use channel::ChannelTransferManager;
pub use cisco_conn::CiscoConn;
pub use cisco_conn::ConnectionType;
pub use client::SshClient;
pub use unix_conn::UnixConn;
pub use config::Config;
pub use connection::{SshConnection, SshConnectionBuilder};
pub use error::SshError;
pub use known_hosts::{KnownHosts, HostKey, HostKeyType};
pub use protocol::{AuthMethod as ProtocolAuthMethod, MessageType};
pub use raw_session::RawSshSession;
pub use session::Session;
pub use session::SessionManager;
pub use session::WindowDimensions;
pub use session::TerminalModes;
pub use session::TerminalMode;
pub use session::SessionState;
pub use transport::Transport;

/// Version information for the SSH client
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initializes the logging system.
///
/// This should be called early in the application lifecycle to enable
/// logging output. Uses `tracing-subscriber` for flexible log configuration
/// via the `RUST_LOG` environment variable (consistent with aytelnet).
pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert!(!NAME.is_empty());
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_logging_initialization() {
        // Test that logging can be initialized
        let result = init_logging();
        assert!(result.is_ok());
    }
}

/// RFC 6187 certificate host keys (client-side, fingerprint trust only).
pub mod x509;
