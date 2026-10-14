//! SSH Client implementation

use crate::auth::{Authenticator, AuthMethodManager, AuthMethod as AuthMethodConfig};
use crate::protocol::AuthMethod as ProtocolAuthMethod;
use crate::session::Session;
use crate::error::SshError;
use crate::transport::Transport;
use tokio::net::TcpStream;

/// SSH Client for connecting to remote servers
pub struct SshClient {
    host: String,
    enable_x509: bool,
    port: u16,
    /// Username for authentication
    username: Option<String>,
    /// Password for authentication
    password: Option<String>,
    /// Private key for authentication
    private_key: Option<Vec<u8>>,
    /// Allowed authentication methods
    allowed_methods: Vec<ProtocolAuthMethod>,
}

impl std::fmt::Debug for SshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("has_password", &self.password.is_some())
            .field("has_private_key", &self.private_key.is_some())
            .finish_non_exhaustive()
    }
}

impl SshClient {
    /// Create a new SSH client
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            enable_x509: false,
            port,
            username: None,
            password: None,
            private_key: None,
            allowed_methods: vec![
                ProtocolAuthMethod::Password,
                ProtocolAuthMethod::PublicKey,
                ProtocolAuthMethod::None,
            ],
        }
    }

    /// Enable RFC 6187 certificate host key negotiation (off by default).
    pub fn with_x509_host_keys(mut self, enabled: bool) -> Self {
        self.enable_x509 = enabled;
        self
    }

    /// Get the host
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Set the username for authentication
    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Set the password for authentication
    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the private key for authentication
    pub fn with_private_key(mut self, private_key: Vec<u8>) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set allowed authentication methods
    pub fn with_allowed_methods(mut self, methods: Vec<ProtocolAuthMethod>) -> Self {
        self.allowed_methods = methods;
        self
    }

    /// Add a password authentication method
    pub fn with_password_auth(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    /// Add a public key authentication method
    pub fn with_publickey_auth(mut self, username: String, private_key: Vec<u8>) -> Self {
        self.username = Some(username);
        self.private_key = Some(private_key);
        self
    }

    /// Connect to the server without authentication
    ///
    /// This establishes a TCP connection and performs the SSH handshake
    /// but does not authenticate. Returns a Transport for further operations.
    pub async fn connect(&self) -> Result<Transport, SshError> {
        // Establish TCP connection
        let addr = format!("{}:{}", self.host, self.port);
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| SshError::ConnectionError(format!("Failed to connect: {}", e)))?;

        let mut transport = Transport::new(stream);
        transport.set_remote_host(&self.host, self.port);
        transport.set_x509_host_keys(self.enable_x509);
        Ok(transport)
    }

    /// Connect with authentication
    ///
    /// This performs the complete SSH connection flow:
    /// 1. Establish TCP connection
    /// 2. Perform version exchange
    /// 3. Perform key exchange
    /// 4. Send SERVICE_REQUEST for "ssh-connection"
    /// 5. Authenticate using the Authenticator
    /// 6. Open session channel
    /// 7. Return Session
    pub async fn connect_with_auth(&self, auth_method: AuthMethodConfig) -> Result<Session, SshError> {
        // Validate credentials
        let username = match &self.username {
            Some(u) => u.clone(),
            None => {
                match &auth_method {
                    AuthMethodConfig::Password { username, .. } |
                    AuthMethodConfig::PublicKey { username, .. } => username.clone(),
                }
            }
        };

        // Connect and perform handshake
        let mut transport = self.connect().await?;

        // Perform SSH handshake (version exchange and key exchange)
        transport.handshake().await?;

        // Request ssh-userauth service (RFC 4252 Section 2)
        transport.send_service_request("ssh-userauth").await?;
        let service = transport.recv_service_accept().await?;
        eprintln!("✓ Service accepted: {}", service);

        // Authenticate
        let mut authenticator = Authenticator::new(&mut transport, username.clone())
            .with_password(self.password.clone().unwrap_or_default())
            .with_private_key(self.private_key.clone().unwrap_or_default());

        // Add allowed methods based on auth_method
        let mut auth_manager = AuthMethodManager::new();
        for method in &self.allowed_methods {
            auth_manager.add_allowed(*method);
        }

        match auth_method {
            AuthMethodConfig::Password { .. } => {
                authenticator.available_methods.insert("password".to_string());
            }
            AuthMethodConfig::PublicKey { .. } => {
                authenticator.available_methods.insert("publickey".to_string());
            }
        }

        let auth_result = authenticator.authenticate().await?;

        match auth_result {
            crate::auth::AuthenticationResult::Success => {
                eprintln!("✓ Authentication successful");
            }
            crate::auth::AuthenticationResult::Failure { .. } => {
                return Err(SshError::AuthenticationFailed(
                    "Authentication failed".to_string()
                ));
            }
        }

        // Open session channel
        let session = Session::open(&mut transport).await?;

        Ok(session)
    }

    /// Connect with password authentication
    pub async fn connect_with_password(&self, username: String, password: String) -> Result<Session, SshError> {
        self.connect_with_auth(AuthMethodConfig::Password { username, password }).await
    }

    /// Connect with public key authentication
    pub async fn connect_with_publickey(&self, username: String, private_key: Vec<u8>) -> Result<Session, SshError> {
        self.connect_with_auth(AuthMethodConfig::PublicKey { username, private_key }).await
    }

    /// Create an authenticator for manual authentication flow
    pub fn create_authenticator(&self) -> Result<Authenticator<'_>, SshError> {
        let _username = match &self.username {
            Some(u) => u.clone(),
            None => return Err(SshError::AuthenticationFailed("No username provided".into())),
        };

        let mut auth_manager = AuthMethodManager::new();
        for method in &self.allowed_methods {
            auth_manager.add_allowed(*method);
        }

        // Note: We can't create a real Authenticator without a Transport
        // This is a placeholder for when Transport is available
        Err(SshError::ProtocolError(
            "Authenticator requires established Transport".into()
        ))
    }

    /// Get the username
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get the password
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Check if password authentication is configured
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Check if public key authentication is configured
    pub fn has_publickey(&self) -> bool {
        self.private_key.is_some()
    }
}

impl Default for SshClient {
    fn default() -> Self {
        Self::new("localhost".to_string(), 22)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client_defaults() {
        let client = SshClient::new("example.com".to_string(), 2222);
        assert_eq!(client.host(), "example.com");
        assert_eq!(client.port(), 2222);
        assert!(client.username().is_none());
        assert!(client.password().is_none());
        assert!(!client.has_password());
        assert!(!client.has_publickey());
    }

    #[test]
    fn test_default_client() {
        let client = SshClient::default();
        assert_eq!(client.host(), "localhost");
        assert_eq!(client.port(), 22);
    }

    #[test]
    fn test_default_allowed_methods() {
        let client = SshClient::new("host".to_string(), 22);
        // Default allowed methods: Password, PublicKey, None
        assert_eq!(client.allowed_methods.len(), 3);
        assert!(client.allowed_methods.contains(&ProtocolAuthMethod::Password));
        assert!(client.allowed_methods.contains(&ProtocolAuthMethod::PublicKey));
        assert!(client.allowed_methods.contains(&ProtocolAuthMethod::None));
    }

    #[test]
    fn test_with_username() {
        let client = SshClient::new("host".to_string(), 22)
            .with_username("alice".to_string());
        assert_eq!(client.username(), Some("alice"));
    }

    #[test]
    fn test_with_password() {
        let client = SshClient::new("host".to_string(), 22)
            .with_password("secret".to_string());
        assert_eq!(client.password(), Some("secret"));
        assert!(client.has_password());
    }

    #[test]
    fn test_with_private_key() {
        let client = SshClient::new("host".to_string(), 22)
            .with_private_key(vec![1, 2, 3]);
        assert!(client.has_publickey());
    }

    #[test]
    fn test_with_allowed_methods() {
        let client = SshClient::new("host".to_string(), 22)
            .with_allowed_methods(vec![ProtocolAuthMethod::Password]);
        assert_eq!(client.allowed_methods.len(), 1);
        assert!(client.allowed_methods.contains(&ProtocolAuthMethod::Password));
    }

    #[test]
    fn test_with_password_auth() {
        let client = SshClient::new("host".to_string(), 22)
            .with_password_auth("bob".to_string(), "pass123".to_string());
        assert_eq!(client.username(), Some("bob"));
        assert_eq!(client.password(), Some("pass123"));
        assert!(client.has_password());
    }

    #[test]
    fn test_with_publickey_auth() {
        let key_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let client = SshClient::new("host".to_string(), 22)
            .with_publickey_auth("carol".to_string(), key_data.clone());
        assert_eq!(client.username(), Some("carol"));
        assert!(client.has_publickey());
        assert_eq!(client.private_key, Some(key_data));
    }

    #[test]
    fn test_builder_chaining() {
        let client = SshClient::new("myserver.com".to_string(), 2222)
            .with_username("user".to_string())
            .with_password("pw".to_string())
            .with_private_key(vec![42])
            .with_allowed_methods(vec![ProtocolAuthMethod::PublicKey]);

        assert_eq!(client.host(), "myserver.com");
        assert_eq!(client.port(), 2222);
        assert_eq!(client.username(), Some("user"));
        assert_eq!(client.password(), Some("pw"));
        assert!(client.has_password());
        assert!(client.has_publickey());
        assert_eq!(client.allowed_methods.len(), 1);
    }

    #[test]
    fn test_create_authenticator_no_username() {
        let client = SshClient::new("host".to_string(), 22);
        let result = client.create_authenticator();
        assert!(result.is_err());
        match result {
            Err(SshError::AuthenticationFailed(msg)) => {
                assert!(msg.contains("No username"));
            }
            _ => panic!("Expected AuthenticationFailed error"),
        }
    }

    #[test]
    fn test_create_authenticator_with_username_returns_protocol_error() {
        let client = SshClient::new("host".to_string(), 22)
            .with_username("user".to_string());
        let result = client.create_authenticator();
        // Should fail because no Transport is available
        assert!(result.is_err());
        match result {
            Err(SshError::ProtocolError(msg)) => {
                assert!(msg.contains("Transport"));
            }
            _ => panic!("Expected ProtocolError about Transport"),
        }
    }

    #[test]
    fn test_no_password_no_publickey() {
        let client = SshClient::new("host".to_string(), 22);
        assert!(!client.has_password());
        assert!(!client.has_publickey());
        assert!(client.username().is_none());
        assert!(client.password().is_none());
    }
}