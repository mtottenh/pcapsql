//! SSLKEYLOGFILE parser for TLS decryption.
//!
//! Parses the NSS Key Log format used by browsers (Chrome, Firefox), curl,
//! and other TLS implementations for exporting session keys.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur when parsing SSLKEYLOGFILE.
#[derive(Debug, Error)]
pub enum KeyLogError {
    /// I/O error reading the file
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid hex string in key log
    #[error("Invalid hex at line {line}: {message}")]
    InvalidHex { line: usize, message: String },

    /// Invalid line format
    #[error("Invalid format at line {line}: {message}")]
    InvalidFormat { line: usize, message: String },

    /// Unknown key type
    #[error("Unknown key type at line {line}: {key_type}")]
    UnknownKeyType { line: usize, key_type: String },
}

/// A single entry from an SSLKEYLOGFILE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLogEntry {
    /// TLS 1.2 and earlier: CLIENT_RANDOM <client_random> <master_secret>
    /// The master_secret is always 48 bytes.
    ClientRandom {
        client_random: [u8; 32],
        master_secret: [u8; 48],
    },

    /// TLS 1.3: CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
    /// Secret length depends on cipher suite hash (32 for SHA-256, 48 for SHA-384).
    ClientHandshakeTrafficSecret {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },

    /// TLS 1.3: SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
    ServerHandshakeTrafficSecret {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },

    /// TLS 1.3: CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
    /// This is the initial application data secret.
    ClientTrafficSecret0 {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },

    /// TLS 1.3: SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
    ServerTrafficSecret0 {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },

    /// TLS 1.3: EXPORTER_SECRET <client_random> <secret>
    ExporterSecret {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },

    /// TLS 1.3: EARLY_EXPORTER_SECRET <client_random> <secret>
    /// Used for 0-RTT early data.
    EarlyExporterSecret {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },

    /// CLIENT_EARLY_TRAFFIC_SECRET <client_random> <secret>
    /// Used for 0-RTT early data.
    ClientEarlyTrafficSecret {
        client_random: [u8; 32],
        secret: Vec<u8>,
    },
}

impl KeyLogEntry {
    /// Get the client_random for this entry.
    pub fn client_random(&self) -> &[u8; 32] {
        match self {
            KeyLogEntry::ClientRandom { client_random, .. } => client_random,
            KeyLogEntry::ClientHandshakeTrafficSecret { client_random, .. } => client_random,
            KeyLogEntry::ServerHandshakeTrafficSecret { client_random, .. } => client_random,
            KeyLogEntry::ClientTrafficSecret0 { client_random, .. } => client_random,
            KeyLogEntry::ServerTrafficSecret0 { client_random, .. } => client_random,
            KeyLogEntry::ExporterSecret { client_random, .. } => client_random,
            KeyLogEntry::EarlyExporterSecret { client_random, .. } => client_random,
            KeyLogEntry::ClientEarlyTrafficSecret { client_random, .. } => client_random,
        }
    }
}

/// Collection of key log entries for a single TLS session.
///
/// A TLS 1.3 session may have multiple entries (handshake secrets, traffic secrets).
/// A TLS 1.2 session typically has just one CLIENT_RANDOM entry.
#[derive(Debug, Clone, Default)]
pub struct KeyLogEntries {
    /// TLS 1.2 master secret (from CLIENT_RANDOM entry)
    pub master_secret: Option<[u8; 48]>,

    /// TLS 1.3 client handshake traffic secret
    pub client_handshake_traffic_secret: Option<Vec<u8>>,

    /// TLS 1.3 server handshake traffic secret
    pub server_handshake_traffic_secret: Option<Vec<u8>>,

    /// TLS 1.3 client application traffic secret (initial)
    pub client_traffic_secret_0: Option<Vec<u8>>,

    /// TLS 1.3 server application traffic secret (initial)
    pub server_traffic_secret_0: Option<Vec<u8>>,

    /// TLS 1.3 exporter secret
    pub exporter_secret: Option<Vec<u8>>,

    /// TLS 1.3 early exporter secret (0-RTT)
    pub early_exporter_secret: Option<Vec<u8>>,

    /// TLS 1.3 client early traffic secret (0-RTT)
    pub client_early_traffic_secret: Option<Vec<u8>>,
}

impl KeyLogEntries {
    /// Check if this has TLS 1.2 keys.
    pub fn has_tls12_keys(&self) -> bool {
        self.master_secret.is_some()
    }

    /// Check if this has TLS 1.3 application keys.
    pub fn has_tls13_app_keys(&self) -> bool {
        self.client_traffic_secret_0.is_some() && self.server_traffic_secret_0.is_some()
    }

    /// Check if this has TLS 1.3 handshake keys.
    pub fn has_tls13_handshake_keys(&self) -> bool {
        self.client_handshake_traffic_secret.is_some()
            && self.server_handshake_traffic_secret.is_some()
    }

    /// Add an entry to this collection.
    fn add_entry(&mut self, entry: KeyLogEntry) {
        match entry {
            KeyLogEntry::ClientRandom { master_secret, .. } => {
                self.master_secret = Some(master_secret);
            }
            KeyLogEntry::ClientHandshakeTrafficSecret { secret, .. } => {
                self.client_handshake_traffic_secret = Some(secret);
            }
            KeyLogEntry::ServerHandshakeTrafficSecret { secret, .. } => {
                self.server_handshake_traffic_secret = Some(secret);
            }
            KeyLogEntry::ClientTrafficSecret0 { secret, .. } => {
                self.client_traffic_secret_0 = Some(secret);
            }
            KeyLogEntry::ServerTrafficSecret0 { secret, .. } => {
                self.server_traffic_secret_0 = Some(secret);
            }
            KeyLogEntry::ExporterSecret { secret, .. } => {
                self.exporter_secret = Some(secret);
            }
            KeyLogEntry::EarlyExporterSecret { secret, .. } => {
                self.early_exporter_secret = Some(secret);
            }
            KeyLogEntry::ClientEarlyTrafficSecret { secret, .. } => {
                self.client_early_traffic_secret = Some(secret);
            }
        }
    }
}

/// Parsed SSLKEYLOGFILE indexed by client_random for fast lookup.
#[derive(Debug, Clone)]
pub struct KeyLog {
    /// Entries indexed by client_random (32 bytes).
    entries: HashMap<[u8; 32], KeyLogEntries>,

    /// Total number of entries parsed.
    entry_count: usize,
}

impl KeyLog {
    /// Create an empty KeyLog.
    pub fn new() -> Self {
        KeyLog {
            entries: HashMap::new(),
            entry_count: 0,
        }
    }

    /// Parse a KeyLog from file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyLogError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::from_reader(reader)
    }

    /// Parse a KeyLog from a string.
    pub fn parse(content: &str) -> Result<Self, KeyLogError> {
        Self::from_reader(content.as_bytes())
    }

    /// Parse a KeyLog from any reader.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, KeyLogError> {
        let reader = BufReader::new(reader);
        let mut keylog = KeyLog::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result?;
            let line_num = line_num + 1; // 1-indexed for error messages

            // Skip empty lines and comments
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let entry = parse_line(line, line_num)?;
            keylog.add_entry(entry);
        }

        Ok(keylog)
    }

    /// Add an entry to the keylog.
    fn add_entry(&mut self, entry: KeyLogEntry) {
        let client_random = *entry.client_random();
        self.entries
            .entry(client_random)
            .or_default()
            .add_entry(entry);
        self.entry_count += 1;
    }

    /// Look up entries by client_random.
    pub fn lookup(&self, client_random: &[u8; 32]) -> Option<&KeyLogEntries> {
        self.entries.get(client_random)
    }

    /// Look up entries by client_random slice (converts to array).
    pub fn lookup_slice(&self, client_random: &[u8]) -> Option<&KeyLogEntries> {
        if client_random.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(client_random);
        self.lookup(&arr)
    }

    /// Get the number of unique sessions (client_randoms) in the keylog.
    pub fn session_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the total number of entries parsed.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Check if the keylog is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all client_randoms.
    pub fn client_randoms(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.entries.keys()
    }
}

impl Default for KeyLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a single line from SSLKEYLOGFILE.
fn parse_line(line: &str, line_num: usize) -> Result<KeyLogEntry, KeyLogError> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() != 3 {
        return Err(KeyLogError::InvalidFormat {
            line: line_num,
            message: format!("expected 3 space-separated fields, got {}", parts.len()),
        });
    }

    let key_type = parts[0];
    let client_random_hex = parts[1];
    let secret_hex = parts[2];

    // Parse client_random (always 32 bytes = 64 hex chars)
    let client_random = parse_hex_32(client_random_hex, line_num)?;

    match key_type {
        "CLIENT_RANDOM" => {
            // TLS 1.2 master secret is always 48 bytes
            let master_secret = parse_hex_48(secret_hex, line_num)?;
            Ok(KeyLogEntry::ClientRandom {
                client_random,
                master_secret,
            })
        }
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::ClientHandshakeTrafficSecret {
                client_random,
                secret,
            })
        }
        "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::ServerHandshakeTrafficSecret {
                client_random,
                secret,
            })
        }
        "CLIENT_TRAFFIC_SECRET_0" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::ClientTrafficSecret0 {
                client_random,
                secret,
            })
        }
        "SERVER_TRAFFIC_SECRET_0" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::ServerTrafficSecret0 {
                client_random,
                secret,
            })
        }
        "EXPORTER_SECRET" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::ExporterSecret {
                client_random,
                secret,
            })
        }
        "EARLY_EXPORTER_SECRET" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::EarlyExporterSecret {
                client_random,
                secret,
            })
        }
        "CLIENT_EARLY_TRAFFIC_SECRET" => {
            let secret = parse_hex_vec(secret_hex, line_num)?;
            Ok(KeyLogEntry::ClientEarlyTrafficSecret {
                client_random,
                secret,
            })
        }
        _ => Err(KeyLogError::UnknownKeyType {
            line: line_num,
            key_type: key_type.to_string(),
        }),
    }
}

/// Parse a hex string into a 32-byte array.
fn parse_hex_32(hex: &str, line: usize) -> Result<[u8; 32], KeyLogError> {
    if hex.len() != 64 {
        return Err(KeyLogError::InvalidHex {
            line,
            message: format!("expected 64 hex chars for client_random, got {}", hex.len()),
        });
    }

    let bytes = parse_hex_vec(hex, line)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a hex string into a 48-byte array.
fn parse_hex_48(hex: &str, line: usize) -> Result<[u8; 48], KeyLogError> {
    if hex.len() != 96 {
        return Err(KeyLogError::InvalidHex {
            line,
            message: format!("expected 96 hex chars for master_secret, got {}", hex.len()),
        });
    }

    let bytes = parse_hex_vec(hex, line)?;
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a hex string into a Vec<u8>.
fn parse_hex_vec(hex: &str, line: usize) -> Result<Vec<u8>, KeyLogError> {
    if !hex.len().is_multiple_of(2) {
        return Err(KeyLogError::InvalidHex {
            line,
            message: "hex string has odd length".to_string(),
        });
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();

    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let high = hex_digit(h).ok_or_else(|| KeyLogError::InvalidHex {
            line,
            message: format!("invalid hex character: {h}"),
        })?;
        let low = hex_digit(l).ok_or_else(|| KeyLogError::InvalidHex {
            line,
            message: format!("invalid hex character: {l}"),
        })?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

/// Convert a hex character to its value.
fn hex_digit(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_random() {
        let content = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        let keylog = KeyLog::parse(content).unwrap();

        assert_eq!(keylog.session_count(), 1);
        assert_eq!(keylog.entry_count(), 1);

        let client_random: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let entries = keylog.lookup(&client_random).unwrap();
        assert!(entries.has_tls12_keys());
        assert!(!entries.has_tls13_app_keys());

        let master_secret = entries.master_secret.unwrap();
        assert_eq!(master_secret[0], 0x00);
        assert_eq!(master_secret[47], 0x2f);
    }

    #[test]
    fn test_parse_tls13_secrets() {
        let content = r#"
# TLS 1.3 session
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0000000000000000000000000000000000000000000000000000000000000001 aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb
SERVER_HANDSHAKE_TRAFFIC_SECRET 0000000000000000000000000000000000000000000000000000000000000001 11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff
CLIENT_TRAFFIC_SECRET_0 0000000000000000000000000000000000000000000000000000000000000001 deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718
SERVER_TRAFFIC_SECRET_0 0000000000000000000000000000000000000000000000000000000000000001 cafebabe12345678deadbeef87654321abcdef01234567890abcdef012345678
"#;

        let keylog = KeyLog::parse(content).unwrap();

        assert_eq!(keylog.session_count(), 1);
        assert_eq!(keylog.entry_count(), 4);

        let client_random: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr[31] = 0x01;
            arr
        };

        let entries = keylog.lookup(&client_random).unwrap();
        assert!(!entries.has_tls12_keys());
        assert!(entries.has_tls13_app_keys());
        assert!(entries.has_tls13_handshake_keys());

        assert!(entries.client_handshake_traffic_secret.is_some());
        assert!(entries.server_handshake_traffic_secret.is_some());
        assert!(entries.client_traffic_secret_0.is_some());
        assert!(entries.server_traffic_secret_0.is_some());
    }

    #[test]
    fn test_parse_multiple_sessions() {
        let content = r#"
CLIENT_RANDOM aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
CLIENT_RANDOM bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f
CLIENT_RANDOM cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
"#;

        let keylog = KeyLog::parse(content).unwrap();

        assert_eq!(keylog.session_count(), 3);
        assert_eq!(keylog.entry_count(), 3);

        // Verify each session
        let cr_a = [0xaa; 32];
        let cr_b = [0xbb; 32];
        let cr_c = [0xcc; 32];
        let cr_missing = [0xdd; 32];

        assert!(keylog.lookup(&cr_a).is_some());
        assert!(keylog.lookup(&cr_b).is_some());
        assert!(keylog.lookup(&cr_c).is_some());
        assert!(keylog.lookup(&cr_missing).is_none());
    }

    #[test]
    fn test_skip_comments_and_empty_lines() {
        let content = r#"
# This is a comment
   # Indented comment

CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f

# Another comment
"#;

        let keylog = KeyLog::parse(content).unwrap();
        assert_eq!(keylog.session_count(), 1);
    }

    #[test]
    fn test_lookup_slice() {
        let content = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        let keylog = KeyLog::parse(content).unwrap();

        let client_random: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        // Lookup with slice
        assert!(keylog.lookup_slice(&client_random).is_some());

        // Wrong length returns None
        assert!(keylog.lookup_slice(&[0x01, 0x23]).is_none());
    }

    #[test]
    fn test_invalid_hex_length() {
        // Client random too short
        let content = "CLIENT_RANDOM 0123456789abcdef 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        let result = KeyLog::parse(content);
        assert!(matches!(
            result,
            Err(KeyLogError::InvalidHex { line: 1, .. })
        ));
    }

    #[test]
    fn test_invalid_hex_char() {
        let content = "CLIENT_RANDOM zzzz456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        let result = KeyLog::parse(content);
        assert!(matches!(
            result,
            Err(KeyLogError::InvalidHex { line: 1, .. })
        ));
    }

    #[test]
    fn test_unknown_key_type() {
        let content = "UNKNOWN_TYPE 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef deadbeef";

        let result = KeyLog::parse(content);
        assert!(matches!(
            result,
            Err(KeyLogError::UnknownKeyType {
                line: 1,
                key_type,
            }) if key_type == "UNKNOWN_TYPE"
        ));
    }

    #[test]
    fn test_invalid_format_wrong_fields() {
        let content = "CLIENT_RANDOM only_two_fields";

        let result = KeyLog::parse(content);
        assert!(matches!(
            result,
            Err(KeyLogError::InvalidFormat { line: 1, .. })
        ));
    }

    #[test]
    fn test_case_insensitive_hex() {
        let content = "CLIENT_RANDOM AABBCCDD00112233445566778899aabbccddeeff00112233445566778899AABB 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        let keylog = KeyLog::parse(content).unwrap();
        assert_eq!(keylog.session_count(), 1);
    }

    #[test]
    fn test_client_randoms_iterator() {
        let content = r#"
CLIENT_RANDOM aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
CLIENT_RANDOM bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f
"#;

        let keylog = KeyLog::parse(content).unwrap();

        let randoms: Vec<_> = keylog.client_randoms().collect();
        assert_eq!(randoms.len(), 2);
    }

    #[test]
    fn test_empty_keylog() {
        let content = "# Just comments\n\n";
        let keylog = KeyLog::parse(content).unwrap();
        assert!(keylog.is_empty());
        assert_eq!(keylog.session_count(), 0);
        assert_eq!(keylog.entry_count(), 0);
    }

    #[test]
    fn test_sha384_traffic_secret() {
        // SHA-384 produces 48-byte secrets
        let content = "CLIENT_TRAFFIC_SECRET_0 0000000000000000000000000000000000000000000000000000000000000001 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        let keylog = KeyLog::parse(content).unwrap();

        let client_random: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr[31] = 0x01;
            arr
        };

        let entries = keylog.lookup(&client_random).unwrap();
        let secret = entries.client_traffic_secret_0.as_ref().unwrap();
        assert_eq!(secret.len(), 48);
    }
}
