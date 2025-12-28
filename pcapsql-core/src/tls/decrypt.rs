//! TLS record decryption engine.
//!
//! Implements AEAD decryption for TLS 1.2 and TLS 1.3 records using:
//! - AES-128-GCM
//! - AES-256-GCM
//! - ChaCha20-Poly1305

use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use thiserror::Error;

use super::kdf::{AeadAlgorithm, Tls12KeyMaterial, Tls13KeyMaterial};

/// Errors during TLS record decryption.
#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid IV length: expected {expected}, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },

    #[error("Invalid nonce length: expected 12, got {0}")]
    InvalidNonceLength(usize),

    #[error("Decryption failed: authentication tag mismatch")]
    AuthenticationFailed,

    #[error("Unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(AeadAlgorithm),

    #[error("Ciphertext too short: minimum {min_len} bytes, got {actual}")]
    CiphertextTooShort { min_len: usize, actual: usize },
}

/// Direction of TLS traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// TLS record decryption context.
///
/// Holds the AEAD key material and provides methods to decrypt TLS records.
pub struct DecryptionContext {
    /// The AEAD algorithm
    algorithm: AeadAlgorithm,
    /// Decryption key
    key: LessSafeKey,
    /// Implicit IV (TLS 1.2) or base IV (TLS 1.3)
    iv: Vec<u8>,
    /// Current sequence number for nonce construction
    sequence_number: u64,
}

impl DecryptionContext {
    /// Create a new decryption context for TLS 1.2.
    ///
    /// For TLS 1.2 with AEAD:
    /// - The nonce is: implicit_iv (4 bytes) || explicit_nonce (8 bytes from record)
    /// - The explicit_nonce is typically the sequence number
    pub fn new_tls12(
        keys: &Tls12KeyMaterial,
        algorithm: AeadAlgorithm,
        direction: Direction,
    ) -> Result<Self, DecryptionError> {
        let (key_bytes, iv_bytes) = match direction {
            Direction::ClientToServer => (&keys.client_write_key, &keys.client_write_iv),
            Direction::ServerToClient => (&keys.server_write_key, &keys.server_write_iv),
        };

        Self::new(algorithm, key_bytes, iv_bytes)
    }

    /// Create a new decryption context for TLS 1.3.
    ///
    /// For TLS 1.3:
    /// - The nonce is: iv XOR padded_sequence_number
    /// - The IV is derived from the traffic secret via HKDF-Expand-Label
    pub fn new_tls13(
        keys: &Tls13KeyMaterial,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, DecryptionError> {
        Self::new(algorithm, &keys.key, &keys.iv)
    }

    /// Create a new decryption context from raw key material.
    pub fn new(algorithm: AeadAlgorithm, key: &[u8], iv: &[u8]) -> Result<Self, DecryptionError> {
        let ring_algo = match algorithm {
            AeadAlgorithm::Aes128Gcm => &AES_128_GCM,
            AeadAlgorithm::Aes256Gcm => &AES_256_GCM,
            AeadAlgorithm::Chacha20Poly1305 => &CHACHA20_POLY1305,
        };

        let expected_key_len = algorithm.key_len();
        if key.len() != expected_key_len {
            return Err(DecryptionError::InvalidKeyLength {
                expected: expected_key_len,
                actual: key.len(),
            });
        }

        let unbound_key =
            UnboundKey::new(ring_algo, key).map_err(|_| DecryptionError::InvalidKeyLength {
                expected: expected_key_len,
                actual: key.len(),
            })?;

        Ok(Self {
            algorithm,
            key: LessSafeKey::new(unbound_key),
            iv: iv.to_vec(),
            sequence_number: 0,
        })
    }

    /// Get the current sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Set the sequence number (useful for resuming mid-stream).
    pub fn set_sequence_number(&mut self, seq: u64) {
        self.sequence_number = seq;
    }

    /// Decrypt a TLS 1.2 AEAD record in place.
    ///
    /// For TLS 1.2 AEAD ciphers:
    /// - Record format: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)
    /// - Nonce = implicit_iv (4 bytes) || explicit_nonce (8 bytes)
    /// - AAD = seq_num (8 bytes) || type (1) || version (2) || length (2)
    ///
    /// Returns the decrypted plaintext.
    pub fn decrypt_tls12_record(
        &mut self,
        record_type: u8,
        version: u16,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        // TLS 1.2 AEAD record structure:
        // explicit_nonce (8 bytes) || encrypted_data || auth_tag (16 bytes)
        let explicit_nonce_len = 8;
        let tag_len = self.algorithm.tag_len();
        let min_len = explicit_nonce_len + tag_len;

        if ciphertext.len() < min_len {
            return Err(DecryptionError::CiphertextTooShort {
                min_len,
                actual: ciphertext.len(),
            });
        }

        let explicit_nonce = &ciphertext[..explicit_nonce_len];
        let encrypted_with_tag = &ciphertext[explicit_nonce_len..];

        // Construct the 12-byte nonce: implicit_iv (4) || explicit_nonce (8)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.iv[..4.min(self.iv.len())]);
        nonce_bytes[4..].copy_from_slice(explicit_nonce);

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| DecryptionError::InvalidNonceLength(nonce_bytes.len()))?;

        // Construct AAD: seq_num (8) || type (1) || version (2) || length (2)
        let plaintext_len = encrypted_with_tag.len() - tag_len;
        let mut aad_bytes = [0u8; 13];
        aad_bytes[..8].copy_from_slice(&self.sequence_number.to_be_bytes());
        aad_bytes[8] = record_type;
        aad_bytes[9..11].copy_from_slice(&version.to_be_bytes());
        aad_bytes[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());

        let aad = Aad::from(&aad_bytes);

        // Decrypt in place
        let mut buffer = encrypted_with_tag.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, aad, &mut buffer)
            .map_err(|_| DecryptionError::AuthenticationFailed)?;

        self.sequence_number += 1;

        Ok(plaintext.to_vec())
    }

    /// Decrypt a TLS 1.3 AEAD record in place.
    ///
    /// For TLS 1.3:
    /// - Record format: ciphertext || tag (16 bytes)
    /// - Nonce = iv XOR padded_sequence_number
    /// - AAD = record_header (type || legacy_version || length)
    /// - Inner plaintext ends with content_type byte
    ///
    /// Returns the decrypted plaintext (including inner content type).
    pub fn decrypt_tls13_record(
        &mut self,
        ciphertext: &[u8],
        record_header: &[u8; 5],
    ) -> Result<Vec<u8>, DecryptionError> {
        let tag_len = self.algorithm.tag_len();

        if ciphertext.len() < tag_len {
            return Err(DecryptionError::CiphertextTooShort {
                min_len: tag_len,
                actual: ciphertext.len(),
            });
        }

        // Construct the 12-byte nonce: iv XOR padded_seq_num
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&self.iv[..12.min(self.iv.len())]);

        // XOR with padded sequence number (right-aligned)
        let seq_bytes = self.sequence_number.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| DecryptionError::InvalidNonceLength(nonce_bytes.len()))?;

        // AAD is the TLS record header (type || version || length)
        let aad = Aad::from(record_header);

        // Decrypt in place
        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, aad, &mut buffer)
            .map_err(|_| DecryptionError::AuthenticationFailed)?;

        self.sequence_number += 1;

        Ok(plaintext.to_vec())
    }

    /// Decrypt a TLS record, auto-detecting the version from context.
    ///
    /// This is a convenience wrapper that routes to the appropriate decryption
    /// method based on TLS version.
    pub fn decrypt_record(
        &mut self,
        tls_version: TlsVersion,
        record_type: u8,
        protocol_version: u16,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        match tls_version {
            TlsVersion::Tls12 | TlsVersion::Tls11 | TlsVersion::Tls10 => {
                self.decrypt_tls12_record(record_type, protocol_version, ciphertext)
            }
            TlsVersion::Tls13 => {
                // Reconstruct record header for TLS 1.3 AAD
                let mut header = [0u8; 5];
                header[0] = record_type;
                header[1..3].copy_from_slice(&protocol_version.to_be_bytes());
                header[3..5].copy_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                self.decrypt_tls13_record(ciphertext, &header)
            }
        }
    }
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// Create from wire protocol version value.
    pub fn from_wire(version: u16) -> Option<Self> {
        match version {
            0x0301 => Some(TlsVersion::Tls10),
            0x0302 => Some(TlsVersion::Tls11),
            0x0303 => Some(TlsVersion::Tls12), // Note: TLS 1.3 also uses 0x0303 in record layer
            0x0304 => Some(TlsVersion::Tls13), // Supported versions extension
            _ => None,
        }
    }

    /// Get the wire protocol version value.
    pub fn to_wire(&self) -> u16 {
        match self {
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 | TlsVersion::Tls13 => 0x0303, // TLS 1.3 uses 0x0303 in record layer
        }
    }
}

/// Extract the inner content type from a TLS 1.3 decrypted record.
///
/// TLS 1.3 inner plaintext format: content || zeros || content_type
/// The content_type is the last non-zero byte.
pub fn extract_tls13_inner_content_type(plaintext: &[u8]) -> Option<(u8, &[u8])> {
    // Find the last non-zero byte (content type)
    let mut i = plaintext.len();
    while i > 0 && plaintext[i - 1] == 0 {
        i -= 1;
    }

    if i == 0 {
        return None;
    }

    let content_type = plaintext[i - 1];
    let content = &plaintext[..i - 1];

    Some((content_type, content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::kdf::{derive_tls12_keys, derive_tls13_keys};

    #[test]
    fn test_decryption_context_creation() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let ctx = DecryptionContext::new(AeadAlgorithm::Aes128Gcm, &key, &iv);
        assert!(ctx.is_ok());

        let ctx = ctx.unwrap();
        assert_eq!(ctx.sequence_number(), 0);
    }

    #[test]
    fn test_decryption_context_wrong_key_length() {
        let key = [0x42u8; 15]; // Wrong length
        let iv = [0x01u8; 12];

        let result = DecryptionContext::new(AeadAlgorithm::Aes128Gcm, &key, &iv);
        assert!(matches!(
            result,
            Err(DecryptionError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn test_tls12_context_from_keys() {
        let master_secret = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let keys =
            derive_tls12_keys(&master_secret, &client_random, &server_random, 0xC02F).unwrap();

        let ctx = DecryptionContext::new_tls12(
            &keys,
            AeadAlgorithm::Aes128Gcm,
            Direction::ClientToServer,
        );
        assert!(ctx.is_ok());

        let ctx = DecryptionContext::new_tls12(
            &keys,
            AeadAlgorithm::Aes128Gcm,
            Direction::ServerToClient,
        );
        assert!(ctx.is_ok());
    }

    #[test]
    fn test_tls13_context_from_keys() {
        let traffic_secret = [0x42u8; 32];
        let keys = derive_tls13_keys(&traffic_secret, 0x1301).unwrap();

        let ctx = DecryptionContext::new_tls13(&keys, AeadAlgorithm::Aes128Gcm);
        assert!(ctx.is_ok());
    }

    #[test]
    fn test_sequence_number() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let mut ctx = DecryptionContext::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        assert_eq!(ctx.sequence_number(), 0);
        ctx.set_sequence_number(100);
        assert_eq!(ctx.sequence_number(), 100);
    }

    #[test]
    fn test_tls_version_from_wire() {
        assert_eq!(TlsVersion::from_wire(0x0301), Some(TlsVersion::Tls10));
        assert_eq!(TlsVersion::from_wire(0x0302), Some(TlsVersion::Tls11));
        assert_eq!(TlsVersion::from_wire(0x0303), Some(TlsVersion::Tls12));
        assert_eq!(TlsVersion::from_wire(0x0304), Some(TlsVersion::Tls13));
        assert_eq!(TlsVersion::from_wire(0x0300), None);
    }

    #[test]
    fn test_tls_version_to_wire() {
        assert_eq!(TlsVersion::Tls10.to_wire(), 0x0301);
        assert_eq!(TlsVersion::Tls11.to_wire(), 0x0302);
        assert_eq!(TlsVersion::Tls12.to_wire(), 0x0303);
        assert_eq!(TlsVersion::Tls13.to_wire(), 0x0303); // TLS 1.3 uses 0x0303 in record layer
    }

    #[test]
    fn test_extract_tls13_inner_content_type() {
        // Normal case: content + content_type
        let plaintext = [0x48, 0x54, 0x54, 0x50, 0x17]; // "HTTP" + application_data(23)
        let result = extract_tls13_inner_content_type(&plaintext);
        assert!(result.is_some());
        let (content_type, content) = result.unwrap();
        assert_eq!(content_type, 0x17);
        assert_eq!(content, &[0x48, 0x54, 0x54, 0x50]);

        // With padding zeros
        let plaintext = [0x48, 0x54, 0x17, 0x00, 0x00];
        let result = extract_tls13_inner_content_type(&plaintext);
        assert!(result.is_some());
        let (content_type, content) = result.unwrap();
        assert_eq!(content_type, 0x17);
        assert_eq!(content, &[0x48, 0x54]);

        // Empty content
        let plaintext = [0x17];
        let result = extract_tls13_inner_content_type(&plaintext);
        assert!(result.is_some());
        let (content_type, content) = result.unwrap();
        assert_eq!(content_type, 0x17);
        assert!(content.is_empty());

        // All zeros (invalid)
        let plaintext = [0x00, 0x00, 0x00];
        let result = extract_tls13_inner_content_type(&plaintext);
        assert!(result.is_none());

        // Empty (invalid)
        let plaintext: [u8; 0] = [];
        let result = extract_tls13_inner_content_type(&plaintext);
        assert!(result.is_none());
    }

    #[test]
    fn test_decrypt_tls12_record_too_short() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 4]; // TLS 1.2 implicit IV is 4 bytes

        let mut ctx = DecryptionContext::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        // Too short: need at least 8 (explicit nonce) + 16 (tag) = 24 bytes
        let ciphertext = [0u8; 20];
        let result = ctx.decrypt_tls12_record(23, 0x0303, &ciphertext);
        assert!(matches!(
            result,
            Err(DecryptionError::CiphertextTooShort { .. })
        ));
    }

    #[test]
    fn test_decrypt_tls13_record_too_short() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];

        let mut ctx = DecryptionContext::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();

        // Too short: need at least 16 bytes for tag
        let ciphertext = [0u8; 10];
        let header = [0x17, 0x03, 0x03, 0x00, 0x0A];
        let result = ctx.decrypt_tls13_record(&ciphertext, &header);
        assert!(matches!(
            result,
            Err(DecryptionError::CiphertextTooShort { .. })
        ));
    }

    // Note: We can't easily test successful decryption without a known test vector
    // or generating actual encrypted data. Integration tests will cover this.
}
