//! Server-side encrypted packet I/O
//!
//! Wraps the transport layer's encrypt/decrypt functions for server use.
//! Key difference from client: server encrypts with s2c keys and decrypts
//! with c2s keys (opposite of client).

use crate::error::SshError;
use crate::transport::{EncryptionState, DecryptionState, encrypt_packet_cbc,
    is_aead_cipher, is_etm_mac, mac_length, gcm_nonce, decrypt_data,
    compute_mac};
use crate::crypto::cipher::aes_cbc_decrypt_raw;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Server-side encrypted I/O handler
pub struct ServerEncryptedIO<S = TcpStream> {
    pub stream: S,
    /// Encrypt state: server uses s2c keys for sending
    pub(crate) encrypt_state: Option<EncryptionState>,
    /// Decrypt state: server uses c2s keys for receiving
    pub(crate) decrypt_state: Option<DecryptionState>,
    /// Leftover bytes from TCP reads
    read_buffer: Vec<u8>,
}

impl<S> std::fmt::Debug for ServerEncryptedIO<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerEncryptedIO")
            .field("encryption_active", &self.encrypt_state.is_some())
            .field("decryption_active", &self.decrypt_state.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerEncryptedIO {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            encrypt_state: None,
            decrypt_state: None,
            read_buffer: Vec::new(),
        }
    }

    /// Split independent cipher states so a reader can finish each packet without
    /// being cancelled when application output becomes ready.
    pub(crate) fn into_split(self) -> (
        ServerEncryptedIO<tokio::net::tcp::OwnedReadHalf>,
        ServerEncryptedIO<tokio::net::tcp::OwnedWriteHalf>,
    ) {
        let (read, write) = self.stream.into_split();
        (
            ServerEncryptedIO { stream: read, encrypt_state: None,
                decrypt_state: self.decrypt_state, read_buffer: self.read_buffer },
            ServerEncryptedIO { stream: write, encrypt_state: self.encrypt_state,
                decrypt_state: None, read_buffer: Vec::new() },
        )
    }
}

impl<S: AsyncRead + Unpin> ServerEncryptedIO<S> {
    /// Read exactly `n` bytes from the buffer + stream
    pub async fn read_exact_buffered(&mut self, n: usize) -> Result<Vec<u8>, SshError> {
        let mut data = Vec::with_capacity(n);

        let from_buf = std::cmp::min(n, self.read_buffer.len());
        if from_buf > 0 {
            data.extend_from_slice(&self.read_buffer[..from_buf]);
            self.read_buffer = self.read_buffer[from_buf..].to_vec();
        }

        if data.len() < n {
            let remaining = n - data.len();
            let mut buf = vec![0u8; remaining];
            self.stream.read_exact(&mut buf).await?;
            data.extend_from_slice(&buf);
        }

        Ok(data)
    }

    /// Read one unencrypted SSH packet, preserving leftover bytes
    pub async fn read_unencrypted_packet(&mut self, timeout_secs: u64) -> Result<Vec<u8>, SshError> {
        let mut data = std::mem::take(&mut self.read_buffer);

        loop {
            if data.len() >= 4 {
                let packet_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                crate::transport::validate_plaintext_header(packet_len, data.get(4).copied())?;
                let total_needed = 4 + packet_len;
                if data.len() >= total_needed {
                    let remainder = data.split_off(total_needed);
                    self.read_buffer = remainder;
                    return Ok(data);
                }
            }

            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                self.stream.read(&mut buf),
            ).await {
                Ok(Ok(0)) => return Err(SshError::ConnectionError("Connection closed".to_string())),
                Ok(Ok(n)) => data.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => return Err(SshError::IoError(e)),
                Err(_) => return Err(SshError::TimeoutError),
            }
        }
    }

    /// Receive an encrypted message (or unencrypted if decryption not yet set up)
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, SshError> {
        if self.decrypt_state.is_none() {
            let packet = self.read_unencrypted_packet(30).await?;
            // Extract payload from packet
            if packet.len() < 5 {
                return Err(SshError::ProtocolError("Packet too short".to_string()));
            }
            let packet_len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
            let padding_len = packet[4] as usize;
            let payload_end = 4 + packet_len - padding_len;
            return Ok(packet[5..payload_end].to_vec());
        }

        // Encrypted path - mirrors Transport::recv_message()
        let (dec_algo, mac_algo) = {
            let ds = self.decrypt_state.as_ref().unwrap();
            (ds.dec_algorithm.clone(), ds.mac_algorithm.clone())
        };
        let aead = is_aead_cipher(&dec_algo);
        let etm = !aead && is_etm_mac(&mac_algo);
        let mac_len = if aead { 16 } else { mac_length(&mac_algo) };

        let decrypted = if dec_algo == "chacha20-poly1305@openssh.com" {
            // ChaCha20-Poly1305: length IS encrypted (unlike AES-GCM)
            let encrypted_length_bytes = self.read_exact_buffered(4).await?;
            let enc_len_arr: [u8; 4] = encrypted_length_bytes.try_into()
                .map_err(|_| SshError::ProtocolError("Short read for length".to_string()))?;

            // Extract key and seq before the next mutable borrow of self
            let (dec_key, seq_num) = {
                let ds = self.decrypt_state.as_ref().unwrap();
                (ds.dec_key.clone(), ds.sequence_number as u64)
            };

            let packet_length = crate::crypto::ssh_chacha20::decrypt_length(
                &dec_key, seq_num, &enc_len_arr,
            ).map_err(|e| SshError::ProtocolError(format!("ChaCha20 length decrypt: {}", e)))? as usize;

            if packet_length < 1 || packet_length > 35000 {
                return Err(SshError::ProtocolError(format!("Invalid packet length: {}", packet_length)));
            }

            // Read encrypted payload + 16-byte Poly1305 tag
            let ct_with_tag = self.read_exact_buffered(packet_length + 16).await?;
            let encrypted_payload = &ct_with_tag[..packet_length];
            let tag: [u8; 16] = ct_with_tag[packet_length..].try_into()
                .map_err(|_| SshError::ProtocolError("Short read for tag".to_string()))?;

            let plaintext = crate::crypto::ssh_chacha20::decrypt(
                &dec_key, seq_num, &enc_len_arr, encrypted_payload, &tag,
            ).map_err(|e| SshError::ProtocolError(format!("ChaCha20 decrypt: {}", e)))?;

            self.decrypt_state.as_mut().unwrap().sequence_number =
                self.decrypt_state.as_ref().unwrap().sequence_number.wrapping_add(1);

            // Reconstruct full packet: length(4) + decrypted(padlen + payload + padding)
            let mut full = Vec::with_capacity(4 + plaintext.len());
            full.extend_from_slice(&(packet_length as u32).to_be_bytes());
            full.extend_from_slice(&plaintext);
            full
        } else if aead {
            // AES-GCM AEAD path (length is cleartext)
            let length_bytes = self.read_exact_buffered(4).await?;
            let packet_length = u32::from_be_bytes([
                length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3],
            ]) as usize;

            if packet_length < 1 || packet_length > 35000 {
                return Err(SshError::ProtocolError(format!("Invalid packet length: {}", packet_length)));
            }

            let ct_with_tag = self.read_exact_buffered(packet_length + 16).await?;
            let decrypt_state = self.decrypt_state.as_mut().unwrap();
            let nonce = gcm_nonce(&decrypt_state.iv, decrypt_state.aead_counter);

            use crate::crypto::cipher::aes_gcm_decrypt_with_aad;
            let plaintext = aes_gcm_decrypt_with_aad(
                &decrypt_state.dec_key, &nonce, &length_bytes, &ct_with_tag,
            ).map_err(|_| SshError::ProtocolError("AEAD auth failed".to_string()))?;

            decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);
            decrypt_state.aead_counter += 1;

            let mut full = Vec::with_capacity(4 + plaintext.len());
            full.extend_from_slice(&length_bytes);
            full.extend_from_slice(&plaintext);
            full
        } else if etm {
            // ETM path
            let length_bytes = self.read_exact_buffered(4).await?;
            let packet_length = u32::from_be_bytes([
                length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3],
            ]) as usize;

            if packet_length < 1 || packet_length > 35000 {
                return Err(SshError::ProtocolError(format!("Invalid packet length: {}", packet_length)));
            }

            let encrypted = self.read_exact_buffered(packet_length).await?;
            let received_mac = self.read_exact_buffered(mac_len).await?;

            // Verify MAC before decrypting
            let mut mac_data = Vec::with_capacity(4 + 4 + encrypted.len());
            let ds = self.decrypt_state.as_ref().unwrap();
            mac_data.extend_from_slice(&ds.sequence_number.to_be_bytes());
            mac_data.extend_from_slice(&length_bytes);
            mac_data.extend_from_slice(&encrypted);
            let expected_mac = compute_mac(&mac_algo, &ds.mac_key, &mac_data);

            if !crate::transport::verify_packet_mac(&expected_mac, &received_mac) {
                return Err(SshError::ProtocolError("ETM MAC failed".to_string()));
            }

            let decrypt_state = self.decrypt_state.as_mut().unwrap();
            let plaintext = decrypt_data(&decrypt_state.dec_algorithm, &decrypt_state.dec_key, &mut decrypt_state.iv, &encrypted)?;
            decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);

            let mut full = Vec::with_capacity(4 + plaintext.len());
            full.extend_from_slice(&length_bytes);
            full.extend_from_slice(&plaintext);
            full
        } else {
            // Standard mode
            let first_block = self.read_exact_buffered(16).await?;
            let (current_iv, dec_key) = {
                let ds = self.decrypt_state.as_ref().unwrap();
                (ds.iv.clone(), ds.dec_key.clone())
            };

            let decrypted_first = match dec_algo.as_str() {
                "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => aes_cbc_decrypt_raw(&dec_key, &current_iv, &first_block)?,
                "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => {
                    use crate::crypto::cipher::aes_ctr_decrypt;
                    aes_ctr_decrypt(&dec_key, &current_iv, &first_block)?
                }
                other => return Err(SshError::ProtocolError(format!("Unsupported cipher: {}", other))),
            };

            let packet_length = u32::from_be_bytes([
                decrypted_first[0], decrypted_first[1], decrypted_first[2], decrypted_first[3],
            ]) as usize;

            if packet_length < 1 || packet_length > 35000 {
                return Err(SshError::ProtocolError(format!("Invalid packet length: {}", packet_length)));
            }

            let total_encrypted = 4 + packet_length;
            let remaining_encrypted = total_encrypted.checked_sub(16)
                .ok_or_else(|| SshError::ProtocolError("Encrypted packet shorter than block".into()))?;
            let rest = self.read_exact_buffered(remaining_encrypted + mac_len).await?;

            let mut full_ct = Vec::with_capacity(total_encrypted);
            full_ct.extend_from_slice(&first_block);
            full_ct.extend_from_slice(&rest[..remaining_encrypted]);
            let received_mac = &rest[remaining_encrypted..];

            let decrypt_state = self.decrypt_state.as_mut().unwrap();
            let decrypted = decrypt_data(&decrypt_state.dec_algorithm, &decrypt_state.dec_key, &mut decrypt_state.iv, &full_ct)?;

            let mut mac_data = Vec::with_capacity(4 + decrypted.len());
            mac_data.extend_from_slice(&decrypt_state.sequence_number.to_be_bytes());
            mac_data.extend_from_slice(&decrypted);
            let expected_mac = compute_mac(&decrypt_state.mac_algorithm, &decrypt_state.mac_key, &mac_data);

            if !crate::transport::verify_packet_mac(&expected_mac, &received_mac) {
                return Err(SshError::ProtocolError("MAC verification failed".to_string()));
            }

            decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);
            decrypted
        };

        // Extract payload from decrypted packet
        if decrypted.len() < 5 {
            return Err(SshError::ProtocolError("Decrypted packet too short".to_string()));
        }
        let padding_len = decrypted[4] as usize;
        let payload_end = decrypted.len().checked_sub(padding_len).unwrap_or(0);
        if padding_len < 4 || payload_end <= 5 {
            return Err(SshError::ProtocolError("Invalid padding in decrypted packet".to_string()));
        }
        Ok(decrypted[5..payload_end].to_vec())
    }
}

impl<S: AsyncWrite + Unpin> ServerEncryptedIO<S> {
    /// Send an encrypted message (or unencrypted if encryption not yet set up)
    pub async fn send_message(&mut self, payload: &[u8]) -> Result<(), SshError> {
        if let Some(ref mut enc_state) = self.encrypt_state {
            let encrypted = encrypt_packet_cbc(payload, enc_state)?;
            self.stream.write_all(&encrypted).await?;
        } else {
            // Send as unencrypted SSH packet
            let packet = build_unencrypted_packet(payload);
            self.stream.write_all(&packet).await?;
        }
        Ok(())
    }

}

/// Build an unencrypted SSH binary packet from payload
pub fn build_unencrypted_packet(payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let total_without_padding = 4 + 1 + payload_len;
    let remainder = total_without_padding % 8;
    let mut padding_length = if remainder == 0 { 8u8 } else { (8 - remainder) as u8 };
    if padding_length < 4 { padding_length += 8; }

    let packet_length = payload_len as u32 + padding_length as u32 + 1;

    let mut packet = Vec::with_capacity(4 + 1 + payload_len + padding_length as usize);
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(padding_length);
    packet.extend_from_slice(payload);
    packet.resize(packet.len() + padding_length as usize, 0);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_unencrypted_packet() {
        let payload = vec![5, 0, 0, 0, 12]; // SERVICE_REQUEST start
        let packet = build_unencrypted_packet(&payload);

        // Verify packet structure
        let packet_len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        assert_eq!(packet.len(), 4 + packet_len);
        let padding_len = packet[4] as usize;
        assert!(padding_len >= 4);
        assert_eq!((4 + packet_len) % 8, 0);
        assert_eq!(&packet[5..5 + payload.len()], &payload);
    }

    #[test]
    fn test_build_unencrypted_packet_alignment() {
        // Test various payload sizes for 8-byte alignment
        for size in 1..=50 {
            let payload = vec![0u8; size];
            let packet = build_unencrypted_packet(&payload);
            let total = packet.len();
            assert_eq!(total % 8, 0, "packet with {}-byte payload must be 8-byte aligned", size);
        }
    }
}
