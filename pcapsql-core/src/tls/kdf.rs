//! TLS key derivation functions.
//!
//! Implements:
//! - TLS 1.2 PRF (Pseudo-Random Function) based on HMAC-SHA256/SHA384
//! - TLS 1.3 HKDF-based key derivation

use ring::hmac::{self, Algorithm as HmacAlgorithm, Key as HmacKey};
use ring::hkdf::{self, KeyType, Prk, HKDF_SHA256, HKDF_SHA384};
use thiserror::Error;

/// Errors during key derivation.
#[derive(Debug, Error)]
pub enum KeyDerivationError {
    #[error("Unsupported cipher suite: 0x{0:04x}")]
    UnsupportedCipherSuite(u16),

    #[error("Invalid key material length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
}

/// Hash algorithm used for key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    /// Get the output length in bytes.
    pub fn output_len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }

    /// Get the corresponding HMAC algorithm.
    fn hmac_algorithm(&self) -> HmacAlgorithm {
        match self {
            HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
            HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
        }
    }

    /// Get the corresponding HKDF algorithm.
    fn hkdf_algorithm(&self) -> hkdf::Algorithm {
        match self {
            HashAlgorithm::Sha256 => HKDF_SHA256,
            HashAlgorithm::Sha384 => HKDF_SHA384,
        }
    }
}

/// AEAD algorithm for TLS record encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl AeadAlgorithm {
    /// Get the key size in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
            AeadAlgorithm::Chacha20Poly1305 => 32,
        }
    }

    /// Get the IV/nonce size in bytes.
    pub fn iv_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 12,
            AeadAlgorithm::Aes256Gcm => 12,
            AeadAlgorithm::Chacha20Poly1305 => 12,
        }
    }

    /// Get the authentication tag size in bytes.
    pub fn tag_len(&self) -> usize {
        16 // All supported AEAD ciphers use 16-byte tags
    }

    /// Determine the AEAD algorithm from a TLS cipher suite ID.
    pub fn from_cipher_suite(suite_id: u16) -> Option<Self> {
        match suite_id {
            // TLS 1.3 cipher suites
            0x1301 => Some(AeadAlgorithm::Aes128Gcm),       // TLS_AES_128_GCM_SHA256
            0x1302 => Some(AeadAlgorithm::Aes256Gcm),       // TLS_AES_256_GCM_SHA384
            0x1303 => Some(AeadAlgorithm::Chacha20Poly1305), // TLS_CHACHA20_POLY1305_SHA256

            // TLS 1.2 ECDHE-RSA cipher suites
            0xC02F => Some(AeadAlgorithm::Aes128Gcm), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030 => Some(AeadAlgorithm::Aes256Gcm), // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xCCA8 => Some(AeadAlgorithm::Chacha20Poly1305), // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

            // TLS 1.2 ECDHE-ECDSA cipher suites
            0xC02B => Some(AeadAlgorithm::Aes128Gcm), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02C => Some(AeadAlgorithm::Aes256Gcm), // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xCCA9 => Some(AeadAlgorithm::Chacha20Poly1305), // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

            // TLS 1.2 DHE-RSA cipher suites
            0x009E => Some(AeadAlgorithm::Aes128Gcm), // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            0x009F => Some(AeadAlgorithm::Aes256Gcm), // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            0xCCAA => Some(AeadAlgorithm::Chacha20Poly1305), // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

            // TLS 1.2 RSA cipher suites (less common, no forward secrecy)
            0x009C => Some(AeadAlgorithm::Aes128Gcm), // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D => Some(AeadAlgorithm::Aes256Gcm), // TLS_RSA_WITH_AES_256_GCM_SHA384

            _ => None,
        }
    }
}

/// Get the hash algorithm for a TLS cipher suite.
pub fn hash_for_cipher_suite(suite_id: u16) -> Option<HashAlgorithm> {
    match suite_id {
        // SHA-384 cipher suites
        0x1302 | // TLS_AES_256_GCM_SHA384
        0xC030 | // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02C | // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0x009F | // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x009D   // TLS_RSA_WITH_AES_256_GCM_SHA384
            => Some(HashAlgorithm::Sha384),

        // SHA-256 cipher suites (most common)
        0x1301 | // TLS_AES_128_GCM_SHA256
        0x1303 | // TLS_CHACHA20_POLY1305_SHA256
        0xC02F | // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xCCA8 | // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xC02B | // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xCCA9 | // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0x009E | // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0xCCAA | // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0x009C   // TLS_RSA_WITH_AES_128_GCM_SHA256
            => Some(HashAlgorithm::Sha256),

        _ => None,
    }
}

/// TLS 1.2 key material derived from master secret.
#[derive(Debug, Clone)]
pub struct Tls12KeyMaterial {
    /// Client write MAC key (for HMAC-based ciphers, empty for AEAD)
    pub client_write_mac_key: Vec<u8>,
    /// Server write MAC key (for HMAC-based ciphers, empty for AEAD)
    pub server_write_mac_key: Vec<u8>,
    /// Client write encryption key
    pub client_write_key: Vec<u8>,
    /// Server write encryption key
    pub server_write_key: Vec<u8>,
    /// Client write IV (implicit for AEAD)
    pub client_write_iv: Vec<u8>,
    /// Server write IV (implicit for AEAD)
    pub server_write_iv: Vec<u8>,
}

/// TLS 1.3 key material derived from traffic secret.
#[derive(Debug, Clone)]
pub struct Tls13KeyMaterial {
    /// Encryption key
    pub key: Vec<u8>,
    /// IV for nonce construction
    pub iv: Vec<u8>,
}

// ============================================================================
// TLS 1.2 PRF Implementation
// ============================================================================

/// TLS 1.2 PRF (Pseudo-Random Function).
///
/// PRF(secret, label, seed) = P_<hash>(secret, label + seed)
///
/// Where P_hash is defined as:
///   P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                          HMAC_hash(secret, A(2) + seed) + ...
///
/// With A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
pub fn tls12_prf(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    output_len: usize,
    hash_algo: HashAlgorithm,
) -> Vec<u8> {
    // Combine label and seed
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    p_hash(secret, &label_seed, output_len, hash_algo)
}

/// P_hash expansion function used by TLS 1.2 PRF.
fn p_hash(secret: &[u8], seed: &[u8], output_len: usize, hash_algo: HashAlgorithm) -> Vec<u8> {
    let hmac_algo = hash_algo.hmac_algorithm();
    let key = HmacKey::new(hmac_algo, secret);
    let hash_len = hash_algo.output_len();

    let mut result = Vec::with_capacity(output_len);
    let mut a = hmac::sign(&key, seed); // A(1) = HMAC(secret, seed)

    while result.len() < output_len {
        // P_hash output = HMAC(secret, A(i) + seed)
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(a.as_ref());
        ctx.update(seed);
        let p_block = ctx.sign();

        // Append to result (may need to truncate final block)
        let remaining = output_len - result.len();
        let take = remaining.min(hash_len);
        result.extend_from_slice(&p_block.as_ref()[..take]);

        // A(i+1) = HMAC(secret, A(i))
        a = hmac::sign(&key, a.as_ref());
    }

    result
}

/// Derive TLS 1.2 key material from master secret.
///
/// Key block = PRF(master_secret, "key expansion",
///                 server_random + client_random)
///
/// Key block is partitioned as:
///   client_write_MAC_key[mac_key_length]
///   server_write_MAC_key[mac_key_length]
///   client_write_key[enc_key_length]
///   server_write_key[enc_key_length]
///   client_write_IV[fixed_iv_length]
///   server_write_IV[fixed_iv_length]
pub fn derive_tls12_keys(
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cipher_suite_id: u16,
) -> Result<Tls12KeyMaterial, KeyDerivationError> {
    let aead = AeadAlgorithm::from_cipher_suite(cipher_suite_id)
        .ok_or(KeyDerivationError::UnsupportedCipherSuite(cipher_suite_id))?;

    let hash_algo = hash_for_cipher_suite(cipher_suite_id)
        .ok_or(KeyDerivationError::UnsupportedCipherSuite(cipher_suite_id))?;

    // For AEAD ciphers, MAC key length is 0
    let mac_key_len = 0;
    let enc_key_len = aead.key_len();
    let iv_len = 4; // Fixed IV length for TLS 1.2 AEAD

    // Total key material needed
    let key_block_len = 2 * mac_key_len + 2 * enc_key_len + 2 * iv_len;

    // Seed = server_random + client_random (note: order differs from master secret derivation)
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let key_block = tls12_prf(
        master_secret,
        b"key expansion",
        &seed,
        key_block_len,
        hash_algo,
    );

    // Partition key block
    let mut offset = 0;

    let client_write_mac_key = if mac_key_len > 0 {
        let k = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        k
    } else {
        Vec::new()
    };

    let server_write_mac_key = if mac_key_len > 0 {
        let k = key_block[offset..offset + mac_key_len].to_vec();
        offset += mac_key_len;
        k
    } else {
        Vec::new()
    };

    let client_write_key = key_block[offset..offset + enc_key_len].to_vec();
    offset += enc_key_len;

    let server_write_key = key_block[offset..offset + enc_key_len].to_vec();
    offset += enc_key_len;

    let client_write_iv = key_block[offset..offset + iv_len].to_vec();
    offset += iv_len;

    let server_write_iv = key_block[offset..offset + iv_len].to_vec();

    Ok(Tls12KeyMaterial {
        client_write_mac_key,
        server_write_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

// ============================================================================
// TLS 1.3 HKDF Implementation
// ============================================================================

/// Helper for HKDF-Expand-Label as defined in RFC 8446.
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// Where HkdfLabel = struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// };
fn hkdf_expand_label(
    prk: &Prk,
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, KeyDerivationError> {
    // Build HkdfLabel
    let tls13_label = {
        let mut l = Vec::with_capacity(6 + label.len());
        l.extend_from_slice(b"tls13 ");
        l.extend_from_slice(label);
        l
    };

    // HkdfLabel encoding
    let mut hkdf_label = Vec::with_capacity(2 + 1 + tls13_label.len() + 1 + context.len());
    hkdf_label.push((output_len >> 8) as u8);
    hkdf_label.push(output_len as u8);
    hkdf_label.push(tls13_label.len() as u8);
    hkdf_label.extend_from_slice(&tls13_label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // Expand using the label as info
    struct ExpandLen(usize);
    impl KeyType for ExpandLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let info = [hkdf_label.as_slice()];
    let okm = prk
        .expand(&info, ExpandLen(output_len))
        .map_err(|_| KeyDerivationError::DerivationFailed("HKDF expand failed".to_string()))?;

    let mut output = vec![0u8; output_len];
    okm.fill(&mut output)
        .map_err(|_| KeyDerivationError::DerivationFailed("HKDF fill failed".to_string()))?;

    Ok(output)
}

/// Derive TLS 1.3 key material from a traffic secret.
///
/// For TLS 1.3, the traffic secret is directly provided by SSLKEYLOGFILE
/// (e.g., CLIENT_TRAFFIC_SECRET_0 or SERVER_TRAFFIC_SECRET_0).
///
/// Key derivation:
///   [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
///   [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
pub fn derive_tls13_keys(
    traffic_secret: &[u8],
    cipher_suite_id: u16,
) -> Result<Tls13KeyMaterial, KeyDerivationError> {
    let aead = AeadAlgorithm::from_cipher_suite(cipher_suite_id)
        .ok_or(KeyDerivationError::UnsupportedCipherSuite(cipher_suite_id))?;

    let hash_algo = hash_for_cipher_suite(cipher_suite_id)
        .ok_or(KeyDerivationError::UnsupportedCipherSuite(cipher_suite_id))?;

    let hkdf_algo = hash_algo.hkdf_algorithm();

    // For TLS 1.3, the traffic_secret from SSLKEYLOGFILE IS the PRK
    // (already the output of HKDF-Extract), so we use it directly
    let prk = Prk::new_less_safe(hkdf_algo, traffic_secret);

    let key_len = aead.key_len();
    let iv_len = aead.iv_len();

    let key = hkdf_expand_label(&prk, b"key", &[], key_len)?;
    let iv = hkdf_expand_label(&prk, b"iv", &[], iv_len)?;

    Ok(Tls13KeyMaterial { key, iv })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_from_cipher_suite() {
        // TLS 1.3
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0x1301),
            Some(AeadAlgorithm::Aes128Gcm)
        );
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0x1302),
            Some(AeadAlgorithm::Aes256Gcm)
        );
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0x1303),
            Some(AeadAlgorithm::Chacha20Poly1305)
        );

        // TLS 1.2
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0xC02F),
            Some(AeadAlgorithm::Aes128Gcm)
        );
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0xC030),
            Some(AeadAlgorithm::Aes256Gcm)
        );
        assert_eq!(
            AeadAlgorithm::from_cipher_suite(0xCCA8),
            Some(AeadAlgorithm::Chacha20Poly1305)
        );

        // Unknown
        assert_eq!(AeadAlgorithm::from_cipher_suite(0x0000), None);
    }

    #[test]
    fn test_hash_for_cipher_suite() {
        // SHA-256 suites
        assert_eq!(
            hash_for_cipher_suite(0x1301),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            hash_for_cipher_suite(0xC02F),
            Some(HashAlgorithm::Sha256)
        );

        // SHA-384 suites
        assert_eq!(
            hash_for_cipher_suite(0x1302),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            hash_for_cipher_suite(0xC030),
            Some(HashAlgorithm::Sha384)
        );

        // Unknown
        assert_eq!(hash_for_cipher_suite(0x0000), None);
    }

    #[test]
    fn test_tls12_prf_basic() {
        // Test that PRF produces consistent output
        let secret = [0x42u8; 48];
        let label = b"test label";
        let seed = [0x01u8; 32];

        let result1 = tls12_prf(&secret, label, &seed, 32, HashAlgorithm::Sha256);
        let result2 = tls12_prf(&secret, label, &seed, 32, HashAlgorithm::Sha256);

        assert_eq!(result1.len(), 32);
        assert_eq!(result1, result2);

        // Different inputs should produce different outputs
        let result3 = tls12_prf(&secret, b"other label", &seed, 32, HashAlgorithm::Sha256);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_tls12_prf_sha384() {
        let secret = [0x42u8; 48];
        let label = b"test label";
        let seed = [0x01u8; 32];

        let result_256 = tls12_prf(&secret, label, &seed, 48, HashAlgorithm::Sha256);
        let result_384 = tls12_prf(&secret, label, &seed, 48, HashAlgorithm::Sha384);

        // Different hash algorithms should produce different outputs
        assert_ne!(result_256, result_384);
    }

    #[test]
    fn test_derive_tls12_keys() {
        let master_secret = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let keys = derive_tls12_keys(&master_secret, &client_random, &server_random, 0xC02F)
            .expect("key derivation should succeed");

        // AES-128-GCM: 16-byte key, 4-byte IV, no MAC key
        assert_eq!(keys.client_write_key.len(), 16);
        assert_eq!(keys.server_write_key.len(), 16);
        assert_eq!(keys.client_write_iv.len(), 4);
        assert_eq!(keys.server_write_iv.len(), 4);
        assert!(keys.client_write_mac_key.is_empty());
        assert!(keys.server_write_mac_key.is_empty());

        // Keys should be different
        assert_ne!(keys.client_write_key, keys.server_write_key);
        assert_ne!(keys.client_write_iv, keys.server_write_iv);
    }

    #[test]
    fn test_derive_tls12_keys_aes256() {
        let master_secret = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        let keys = derive_tls12_keys(&master_secret, &client_random, &server_random, 0xC030)
            .expect("key derivation should succeed");

        // AES-256-GCM: 32-byte key
        assert_eq!(keys.client_write_key.len(), 32);
        assert_eq!(keys.server_write_key.len(), 32);
    }

    #[test]
    fn test_derive_tls12_keys_unsupported() {
        let master_secret = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        // Unknown cipher suite
        let result = derive_tls12_keys(&master_secret, &client_random, &server_random, 0x0000);
        assert!(matches!(
            result,
            Err(KeyDerivationError::UnsupportedCipherSuite(0x0000))
        ));
    }

    #[test]
    fn test_derive_tls13_keys() {
        // Sample traffic secret (32 bytes for SHA-256 based suites)
        let traffic_secret = [0x42u8; 32];

        // TLS_AES_128_GCM_SHA256
        let keys = derive_tls13_keys(&traffic_secret, 0x1301)
            .expect("key derivation should succeed");

        // AES-128-GCM: 16-byte key, 12-byte IV
        assert_eq!(keys.key.len(), 16);
        assert_eq!(keys.iv.len(), 12);
    }

    #[test]
    fn test_derive_tls13_keys_aes256() {
        // Sample traffic secret (48 bytes for SHA-384 based suites)
        let traffic_secret = [0x42u8; 48];

        // TLS_AES_256_GCM_SHA384
        let keys = derive_tls13_keys(&traffic_secret, 0x1302)
            .expect("key derivation should succeed");

        // AES-256-GCM: 32-byte key, 12-byte IV
        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.iv.len(), 12);
    }

    #[test]
    fn test_derive_tls13_keys_chacha20() {
        let traffic_secret = [0x42u8; 32];

        // TLS_CHACHA20_POLY1305_SHA256
        let keys = derive_tls13_keys(&traffic_secret, 0x1303)
            .expect("key derivation should succeed");

        // ChaCha20-Poly1305: 32-byte key, 12-byte IV
        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.iv.len(), 12);
    }

    #[test]
    fn test_derive_tls13_keys_consistency() {
        let traffic_secret = [0x42u8; 32];

        // Same input should produce same output
        let keys1 = derive_tls13_keys(&traffic_secret, 0x1301).unwrap();
        let keys2 = derive_tls13_keys(&traffic_secret, 0x1301).unwrap();

        assert_eq!(keys1.key, keys2.key);
        assert_eq!(keys1.iv, keys2.iv);

        // Different secret should produce different output
        let other_secret = [0x43u8; 32];
        let keys3 = derive_tls13_keys(&other_secret, 0x1301).unwrap();

        assert_ne!(keys1.key, keys3.key);
        assert_ne!(keys1.iv, keys3.iv);
    }

    #[test]
    fn test_aead_key_lengths() {
        assert_eq!(AeadAlgorithm::Aes128Gcm.key_len(), 16);
        assert_eq!(AeadAlgorithm::Aes256Gcm.key_len(), 32);
        assert_eq!(AeadAlgorithm::Chacha20Poly1305.key_len(), 32);

        assert_eq!(AeadAlgorithm::Aes128Gcm.iv_len(), 12);
        assert_eq!(AeadAlgorithm::Aes256Gcm.iv_len(), 12);
        assert_eq!(AeadAlgorithm::Chacha20Poly1305.iv_len(), 12);

        assert_eq!(AeadAlgorithm::Aes128Gcm.tag_len(), 16);
        assert_eq!(AeadAlgorithm::Aes256Gcm.tag_len(), 16);
        assert_eq!(AeadAlgorithm::Chacha20Poly1305.tag_len(), 16);
    }
}
