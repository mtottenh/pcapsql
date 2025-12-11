//! TLS decryption support for pcapsql.
//!
//! This module provides the ability to decrypt TLS traffic using SSLKEYLOGFILE,
//! the standard key logging format used by browsers, curl, and other TLS clients.
//!
//! ## Architecture
//!
//! ```text
//! TCP Stream Reassembly -> TLS Handshake Parser (tls-parser)
//!     |                         |
//!     v                         v
//! Key Lookup (SSLKEYLOGFILE) <- client_random, server_random, cipher_suite
//!     |
//!     v
//! Key Derivation (TLS 1.2 PRF / TLS 1.3 HKDF)
//!     |
//!     v
//! Record Decryption (AES-GCM, ChaCha20-Poly1305)
//!     |
//!     v
//! Application Protocol Parsing (HTTP/2, HTTP/1.1, etc.)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use pcapsql_core::tls::KeyLog;
//!
//! // Load keys from SSLKEYLOGFILE
//! let keylog = KeyLog::from_file("/tmp/keys.log")?;
//!
//! // Look up master secret by client_random
//! if let Some(entries) = keylog.lookup(&client_random) {
//!     // Use entries for key derivation and decryption
//! }
//! ```
//!
//! ## Supported Features
//!
//! - TLS 1.2 master secret (CLIENT_RANDOM)
//! - TLS 1.3 traffic secrets (CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, etc.)
//! - AES-128-GCM, AES-256-GCM cipher suites
//! - ChaCha20-Poly1305 cipher suite
//!
//! ## SSLKEYLOGFILE Format
//!
//! The NSS Key Log format is a text file with lines like:
//!
//! ```text
//! # TLS 1.2
//! CLIENT_RANDOM <64_hex_client_random> <96_hex_master_secret>
//!
//! # TLS 1.3
//! CLIENT_HANDSHAKE_TRAFFIC_SECRET <64_hex_client_random> <traffic_secret>
//! SERVER_HANDSHAKE_TRAFFIC_SECRET <64_hex_client_random> <traffic_secret>
//! CLIENT_TRAFFIC_SECRET_0 <64_hex_client_random> <traffic_secret>
//! SERVER_TRAFFIC_SECRET_0 <64_hex_client_random> <traffic_secret>
//! ```

pub mod decrypt;
pub mod kdf;
pub mod keylog;
pub mod session;

pub use decrypt::{
    extract_tls13_inner_content_type, DecryptionContext, DecryptionError, Direction, TlsVersion,
};
pub use kdf::{
    derive_tls12_keys, derive_tls13_keys, hash_for_cipher_suite, tls12_prf, AeadAlgorithm,
    HashAlgorithm, KeyDerivationError, Tls12KeyMaterial, Tls13KeyMaterial,
};
pub use keylog::{KeyLog, KeyLogEntries, KeyLogEntry, KeyLogError};
pub use session::{HandshakeData, SessionError, SessionState, Tls13HandshakePhase, TlsSession};
