//! RFC 6187 RSA certificate host keys. Trust is a SHA-256 pin of the leaf DER.
//! TODO: CA chain, validity, key usage and revocation validation are out of scope.
use crate::error::SshError;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

pub const ALGORITHM: &str = "x509v3-ssh-rsa";
const MAX_BLOB: usize = 1024 * 1024;
const MAX_ITEMS: u32 = 32;
const MAX_ITEM: usize = 256 * 1024;

fn invalid(message: &str) -> SshError {
    SshError::ProtocolError(format!("X509 host key: {}", message))
}

pub(crate) fn read_u32(input: &mut &[u8]) -> Result<u32, SshError> {
    let bytes = input.get(..4).ok_or_else(|| invalid("truncated length"))?;
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    *input = &input[4..];
    Ok(value)
}

pub(crate) fn read_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], SshError> {
    let len = read_u32(input)? as usize;
    let value = input
        .get(..len)
        .ok_or_else(|| invalid("truncated string"))?;
    *input = &input[len..];
    Ok(value)
}

/// Parsed certificate chain and stapled OCSP responses. No CA trust is implied.
#[derive(Debug)]
pub struct CertificateHostKey {
    certificates: Vec<Vec<u8>>,
    ocsp_responses: Vec<Vec<u8>>,
    pub subject: String,
    pub public_key: rsa::RsaPublicKey,
}

impl CertificateHostKey {
    pub fn parse(blob: &[u8]) -> Result<Self, SshError> {
        if blob.len() > MAX_BLOB {
            return Err(invalid("blob too large"));
        }
        let mut input = blob;
        if read_string(&mut input)? != ALGORITHM.as_bytes() {
            return Err(invalid("wrong algorithm"));
        }
        let count = read_u32(&mut input)?;
        if count == 0 || count > MAX_ITEMS {
            return Err(invalid("invalid certificate count"));
        }
        let mut certificates = Vec::new();
        let mut leaf = None;
        for index in 0..count {
            let der = read_string(&mut input)?;
            if der.len() > MAX_ITEM {
                return Err(invalid("certificate too large"));
            }
            let cert = x509_cert::Certificate::from_der(der)
                .map_err(|_| invalid("invalid certificate DER"))?;
            if index == 0 {
                leaf = Some(cert);
            }
            certificates.push(der.to_vec());
        }
        let count = read_u32(&mut input)?;
        if count > MAX_ITEMS {
            return Err(invalid("invalid OCSP count"));
        }
        let mut ocsp_responses = Vec::new();
        for _ in 0..count {
            let der = read_string(&mut input)?;
            if der.len() > MAX_ITEM {
                return Err(invalid("OCSP response too large"));
            }
            // Validate DER framing. OCSP status and signatures need future CA validation.
            x509_cert::der::asn1::AnyRef::from_der(der).map_err(|_| invalid("invalid OCSP DER"))?;
            ocsp_responses.push(der.to_vec());
        }
        if !input.is_empty() {
            return Err(invalid("trailing bytes"));
        }
        let leaf = leaf.ok_or_else(|| invalid("missing certificate"))?;
        let spki = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| invalid("invalid SPKI"))?;
        let public_key = rsa::RsaPublicKey::from_public_key_der(&spki)
            .map_err(|_| invalid("end-entity SPKI is not a valid RSA key"))?;
        Ok(Self {
            certificates,
            ocsp_responses,
            subject: leaf.tbs_certificate.subject.to_string(),
            public_key,
        })
    }

    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }
    pub fn ocsp_responses(&self) -> &[Vec<u8>] {
        &self.ocsp_responses
    }

    /// Re-encode the validated RFC 6187 wire blob.
    pub fn encode(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        fn string(blob: &mut Vec<u8>, value: &[u8]) {
            blob.extend_from_slice(&(value.len() as u32).to_be_bytes());
            blob.extend_from_slice(value);
        }
        string(&mut blob, ALGORITHM.as_bytes());
        blob.extend_from_slice(&(self.certificates.len() as u32).to_be_bytes());
        for cert in &self.certificates {
            string(&mut blob, cert);
        }
        blob.extend_from_slice(&(self.ocsp_responses.len() as u32).to_be_bytes());
        for response in &self.ocsp_responses {
            string(&mut blob, response);
        }
        blob
    }

    pub fn fingerprint_bytes(&self) -> Vec<u8> {
        Sha256::digest(&self.certificates[0]).to_vec()
    }

    pub fn fingerprint(&self) -> String {
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(self.fingerprint_bytes())
        )
    }

    pub fn verify_signature(&self, exchange_hash: &[u8], signature: &[u8]) -> Result<(), SshError> {
        let mut input = signature;
        if read_string(&mut input)? != b"ssh-rsa" {
            return Err(invalid("expected ssh-rsa signature"));
        }
        let signature = read_string(&mut input)?;
        if !input.is_empty() {
            return Err(invalid("trailing signature bytes"));
        }
        crate::auth::signature::RsaSignatureEncoder::verify(
            &self.public_key,
            exchange_hash,
            signature,
        )
    }
}

/// Extract bounded fields from the KEX reply after its message-type byte.
pub(crate) fn parse_kex_reply(data: &[u8]) -> Result<(&[u8], &[u8]), SshError> {
    let mut input = data;
    let key = read_string(&mut input)?;
    let _ephemeral = read_string(&mut input)?;
    let signature = read_string(&mut input)?;
    if !input.is_empty() {
        return Err(invalid("trailing KEX reply bytes"));
    }
    Ok((key, signature))
}

/// Certificate stores compare only the leaf digest, independent of chain/OCSP changes.
pub(crate) fn trust_identity(algorithm: &str, blob: &[u8]) -> Result<Vec<u8>, SshError> {
    if algorithm == ALGORITHM {
        Ok(CertificateHostKey::parse(blob)?.fingerprint_bytes())
    } else {
        Ok(blob.to_vec())
    }
}
