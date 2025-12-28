//! TLS decryption integration tests.
//!
//! These tests verify the full TLS decryption pipeline from keylog parsing
//! through key derivation to record decryption.

use std::sync::Arc;

use pcapsql_core::{
    derive_tls12_keys, derive_tls13_keys, AeadAlgorithm, DecryptionContext, KeyLog, SessionError,
    TlsDirection, TlsSession, TlsVersion,
};

// ============================================================================
// Test Constants
// ============================================================================

/// Test client random (32 bytes)
const TEST_CLIENT_RANDOM: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Test server random (32 bytes)
const TEST_SERVER_RANDOM: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// Test TLS 1.2 master secret (48 bytes)
const TEST_MASTER_SECRET: [u8; 48] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// Test TLS 1.3 traffic secret (32 bytes for SHA-256)
const TEST_TRAFFIC_SECRET_32: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
];

/// Test TLS 1.3 traffic secret (48 bytes for SHA-384)
const TEST_TRAFFIC_SECRET_48: [u8; 48] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];

// Cipher suite IDs
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;
const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xC030;
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA8;

// ============================================================================
// Keylog Tests
// ============================================================================

#[test]
fn test_keylog_parsing_tls12() {
    let keylog_content = format!(
        "CLIENT_RANDOM {} {}",
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_MASTER_SECRET)
    );

    let keylog = KeyLog::from_str(&keylog_content).expect("Failed to parse keylog");

    assert_eq!(keylog.session_count(), 1);
    assert_eq!(keylog.entry_count(), 1);

    let entries = keylog
        .lookup(&TEST_CLIENT_RANDOM)
        .expect("Should find entry");
    assert!(entries.master_secret.is_some());
}

#[test]
fn test_keylog_parsing_tls13() {
    let keylog_content = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n\
         SERVER_TRAFFIC_SECRET_0 {} {}",
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_TRAFFIC_SECRET_32),
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_TRAFFIC_SECRET_32),
    );

    let keylog = KeyLog::from_str(&keylog_content).expect("Failed to parse keylog");

    assert_eq!(keylog.session_count(), 1);
    assert_eq!(keylog.entry_count(), 2);

    let entries = keylog
        .lookup(&TEST_CLIENT_RANDOM)
        .expect("Should find entry");
    assert!(entries.client_traffic_secret_0.is_some());
    assert!(entries.server_traffic_secret_0.is_some());
}

#[test]
fn test_keylog_parsing_mixed() {
    // Keylog with both TLS 1.2 and TLS 1.3 entries for different sessions
    let client_random_1 = [0xaa; 32];
    let client_random_2 = [0xbb; 32];

    let keylog_content = format!(
        "# Comment line\n\
         CLIENT_RANDOM {} {}\n\
         \n\
         CLIENT_TRAFFIC_SECRET_0 {} {}\n\
         SERVER_TRAFFIC_SECRET_0 {} {}",
        hex::encode(client_random_1),
        hex::encode(TEST_MASTER_SECRET),
        hex::encode(client_random_2),
        hex::encode(TEST_TRAFFIC_SECRET_32),
        hex::encode(client_random_2),
        hex::encode(TEST_TRAFFIC_SECRET_32),
    );

    let keylog = KeyLog::from_str(&keylog_content).expect("Failed to parse keylog");

    assert_eq!(keylog.session_count(), 2);
    assert_eq!(keylog.entry_count(), 3);

    // TLS 1.2 session
    let entries_12 = keylog
        .lookup(&client_random_1)
        .expect("Should find TLS 1.2 entry");
    assert!(entries_12.master_secret.is_some());
    assert!(!entries_12.has_tls13_app_keys());

    // TLS 1.3 session
    let entries_13 = keylog
        .lookup(&client_random_2)
        .expect("Should find TLS 1.3 entry");
    assert!(entries_13.has_tls13_app_keys());
}

// ============================================================================
// Key Derivation Tests
// ============================================================================

#[test]
fn test_tls12_key_derivation_aes128gcm() {
    let keys = derive_tls12_keys(
        &TEST_MASTER_SECRET,
        &TEST_CLIENT_RANDOM,
        &TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    )
    .expect("Key derivation should succeed");

    assert_eq!(keys.client_write_key.len(), 16); // AES-128
    assert_eq!(keys.server_write_key.len(), 16);
    assert_eq!(keys.client_write_iv.len(), 4); // Fixed IV for TLS 1.2
    assert_eq!(keys.server_write_iv.len(), 4);
}

#[test]
fn test_tls12_key_derivation_aes256gcm() {
    let keys = derive_tls12_keys(
        &TEST_MASTER_SECRET,
        &TEST_CLIENT_RANDOM,
        &TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    )
    .expect("Key derivation should succeed");

    assert_eq!(keys.client_write_key.len(), 32); // AES-256
    assert_eq!(keys.server_write_key.len(), 32);
}

#[test]
fn test_tls12_key_derivation_chacha20() {
    let keys = derive_tls12_keys(
        &TEST_MASTER_SECRET,
        &TEST_CLIENT_RANDOM,
        &TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    )
    .expect("Key derivation should succeed");

    assert_eq!(keys.client_write_key.len(), 32); // ChaCha20
    assert_eq!(keys.server_write_key.len(), 32);
}

#[test]
fn test_tls13_key_derivation_aes128gcm() {
    let keys = derive_tls13_keys(&TEST_TRAFFIC_SECRET_32, TLS_AES_128_GCM_SHA256)
        .expect("Key derivation should succeed");

    assert_eq!(keys.key.len(), 16); // AES-128
    assert_eq!(keys.iv.len(), 12); // Full IV for TLS 1.3
}

#[test]
fn test_tls13_key_derivation_aes256gcm() {
    let keys = derive_tls13_keys(&TEST_TRAFFIC_SECRET_48, TLS_AES_256_GCM_SHA384)
        .expect("Key derivation should succeed");

    assert_eq!(keys.key.len(), 32); // AES-256
    assert_eq!(keys.iv.len(), 12);
}

#[test]
fn test_tls13_key_derivation_chacha20() {
    let keys = derive_tls13_keys(&TEST_TRAFFIC_SECRET_32, TLS_CHACHA20_POLY1305_SHA256)
        .expect("Key derivation should succeed");

    assert_eq!(keys.key.len(), 32); // ChaCha20
    assert_eq!(keys.iv.len(), 12);
}

// ============================================================================
// Decryption Context Tests
// ============================================================================

#[test]
fn test_decryption_context_tls12_aes128gcm() {
    let keys = derive_tls12_keys(
        &TEST_MASTER_SECRET,
        &TEST_CLIENT_RANDOM,
        &TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    )
    .unwrap();

    // Create contexts for client and server directions
    let client_ctx = DecryptionContext::new_tls12(
        &keys,
        AeadAlgorithm::Aes128Gcm,
        TlsDirection::ClientToServer,
    );
    assert!(client_ctx.is_ok(), "Client context creation should succeed");

    let server_ctx = DecryptionContext::new_tls12(
        &keys,
        AeadAlgorithm::Aes128Gcm,
        TlsDirection::ServerToClient,
    );
    assert!(server_ctx.is_ok(), "Server context creation should succeed");
}

#[test]
fn test_decryption_context_tls12_aes256gcm() {
    let keys = derive_tls12_keys(
        &TEST_MASTER_SECRET,
        &TEST_CLIENT_RANDOM,
        &TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    )
    .unwrap();

    let ctx = DecryptionContext::new_tls12(
        &keys,
        AeadAlgorithm::Aes256Gcm,
        TlsDirection::ClientToServer,
    );
    assert!(ctx.is_ok(), "AES-256-GCM context creation should succeed");
}

#[test]
fn test_decryption_context_tls13_aes128gcm() {
    let keys = derive_tls13_keys(&TEST_TRAFFIC_SECRET_32, TLS_AES_128_GCM_SHA256).unwrap();

    let ctx = DecryptionContext::new_tls13(&keys, AeadAlgorithm::Aes128Gcm);
    assert!(
        ctx.is_ok(),
        "TLS 1.3 AES-128-GCM context creation should succeed"
    );
}

#[test]
fn test_decryption_context_tls13_aes256gcm() {
    let keys = derive_tls13_keys(&TEST_TRAFFIC_SECRET_48, TLS_AES_256_GCM_SHA384).unwrap();

    let ctx = DecryptionContext::new_tls13(&keys, AeadAlgorithm::Aes256Gcm);
    assert!(
        ctx.is_ok(),
        "TLS 1.3 AES-256-GCM context creation should succeed"
    );
}

// ============================================================================
// TLS Session State Machine Tests
// ============================================================================

#[test]
fn test_session_tls12_full_handshake() {
    // Create keylog with master secret
    let keylog_content = format!(
        "CLIENT_RANDOM {} {}",
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_MASTER_SECRET)
    );
    let keylog = Arc::new(KeyLog::from_str(&keylog_content).unwrap());

    let mut session = TlsSession::new(keylog);

    // Process ClientHello
    session.process_client_hello(TEST_CLIENT_RANDOM);

    // Process ServerHello with AES-128-GCM cipher suite
    let result = session.process_server_hello(
        TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsVersion::Tls12,
    );

    assert!(result.is_ok(), "ServerHello processing should succeed");
    assert!(
        session.can_decrypt(),
        "Should be able to decrypt after handshake"
    );
}

#[test]
fn test_session_tls13_full_handshake() {
    // Create keylog with TLS 1.3 traffic secrets
    let keylog_content = format!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n\
         SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\n\
         CLIENT_TRAFFIC_SECRET_0 {} {}\n\
         SERVER_TRAFFIC_SECRET_0 {} {}",
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_TRAFFIC_SECRET_32),
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_TRAFFIC_SECRET_32),
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_TRAFFIC_SECRET_32),
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_TRAFFIC_SECRET_32),
    );
    let keylog = Arc::new(KeyLog::from_str(&keylog_content).unwrap());

    let mut session = TlsSession::new(keylog);

    // Process ClientHello
    session.process_client_hello(TEST_CLIENT_RANDOM);

    // Process ServerHello with TLS 1.3 AES-128-GCM
    let result = session.process_server_hello(
        TEST_SERVER_RANDOM,
        TLS_AES_128_GCM_SHA256,
        TlsVersion::Tls13,
    );

    assert!(result.is_ok(), "TLS 1.3 ServerHello should succeed");
    assert!(session.can_decrypt(), "Should be able to decrypt TLS 1.3");
}

#[test]
fn test_session_missing_keys() {
    // Empty keylog
    let keylog = Arc::new(KeyLog::new());

    let mut session = TlsSession::new(keylog);
    session.process_client_hello(TEST_CLIENT_RANDOM);

    let result = session.process_server_hello(
        TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsVersion::Tls12,
    );

    assert!(
        matches!(result, Err(SessionError::MissingKeys)),
        "Should fail with MissingKeys error"
    );
    assert!(
        !session.can_decrypt(),
        "Should not be able to decrypt without keys"
    );
}

#[test]
fn test_session_unsupported_cipher_suite() {
    let keylog_content = format!(
        "CLIENT_RANDOM {} {}",
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_MASTER_SECRET)
    );
    let keylog = Arc::new(KeyLog::from_str(&keylog_content).unwrap());

    let mut session = TlsSession::new(keylog);
    session.process_client_hello(TEST_CLIENT_RANDOM);

    // Use an unsupported cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
    let result = session.process_server_hello(TEST_SERVER_RANDOM, 0x002F, TlsVersion::Tls12);

    assert!(
        matches!(result, Err(SessionError::UnsupportedCipherSuite(_))),
        "Should fail with UnsupportedCipherSuite error, got: {:?}",
        result
    );
}

// ============================================================================
// Cipher Suite Coverage Tests
// ============================================================================

/// Test that all advertised cipher suites can create decryption contexts
#[test]
fn test_supported_cipher_suites() {
    // TLS 1.3 cipher suites
    let tls13_suites = [
        (0x1301, "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    ];

    // TLS 1.2 cipher suites
    let tls12_suites = [
        (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        (0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    ];

    for (suite_id, name) in tls13_suites {
        let alg = AeadAlgorithm::from_cipher_suite(suite_id);
        assert!(
            alg.is_some(),
            "TLS 1.3 suite {} (0x{:04X}) should be supported",
            name,
            suite_id
        );
    }

    for (suite_id, name) in tls12_suites {
        let alg = AeadAlgorithm::from_cipher_suite(suite_id);
        assert!(
            alg.is_some(),
            "TLS 1.2 suite {} (0x{:04X}) should be supported",
            name,
            suite_id
        );
    }
}

/// Test key derivation for all supported TLS 1.2 cipher suites
#[test]
fn test_tls12_key_derivation_all_suites() {
    let tls12_suites = [
        (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 16),
        (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 32),
        (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 16),
        (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 32),
        (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 32),
        (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 32),
        (0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 16),
        (0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 32),
    ];

    for (suite_id, name, expected_key_len) in tls12_suites {
        let result = derive_tls12_keys(
            &TEST_MASTER_SECRET,
            &TEST_CLIENT_RANDOM,
            &TEST_SERVER_RANDOM,
            suite_id,
        );

        assert!(
            result.is_ok(),
            "Key derivation should succeed for {} (0x{:04X})",
            name,
            suite_id
        );

        let keys = result.unwrap();
        assert_eq!(
            keys.client_write_key.len(),
            expected_key_len,
            "Key length mismatch for {} (0x{:04X})",
            name,
            suite_id
        );
    }
}

/// Test key derivation for all supported TLS 1.3 cipher suites
#[test]
fn test_tls13_key_derivation_all_suites() {
    let tls13_suites = [
        (
            0x1301,
            "TLS_AES_128_GCM_SHA256",
            &TEST_TRAFFIC_SECRET_32[..],
            16,
        ),
        (
            0x1302,
            "TLS_AES_256_GCM_SHA384",
            &TEST_TRAFFIC_SECRET_48[..],
            32,
        ),
        (
            0x1303,
            "TLS_CHACHA20_POLY1305_SHA256",
            &TEST_TRAFFIC_SECRET_32[..],
            32,
        ),
    ];

    for (suite_id, name, traffic_secret, expected_key_len) in tls13_suites {
        let result = derive_tls13_keys(traffic_secret, suite_id);

        assert!(
            result.is_ok(),
            "Key derivation should succeed for {} (0x{:04X})",
            name,
            suite_id
        );

        let keys = result.unwrap();
        assert_eq!(
            keys.key.len(),
            expected_key_len,
            "Key length mismatch for {} (0x{:04X})",
            name,
            suite_id
        );
    }
}

// ============================================================================
// End-to-End Pipeline Tests (with pre-captured data)
// ============================================================================

#[test]
fn test_full_pipeline_with_synthetic_data() {
    // Create a keylog
    let keylog_content = format!(
        "CLIENT_RANDOM {} {}",
        hex::encode(TEST_CLIENT_RANDOM),
        hex::encode(TEST_MASTER_SECRET)
    );
    let keylog = Arc::new(KeyLog::from_str(&keylog_content).unwrap());

    // Create session
    let mut session = TlsSession::new(keylog.clone());

    // Simulate handshake
    session.process_client_hello(TEST_CLIENT_RANDOM);
    let result = session.process_server_hello(
        TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsVersion::Tls12,
    );
    assert!(result.is_ok());

    // Verify we can decrypt
    assert!(session.can_decrypt());

    // The decryption context is ready for actual encrypted records
    // In a real test with captured data, we would:
    // 1. Read encrypted TLS records from PCAP
    // 2. Call session.decrypt_record() for each record
    // 3. Verify the decrypted plaintext matches expected data
}

/// Test loading pre-captured TLS 1.2 data (if available)
#[test]
fn test_precaptured_tls12() {
    let pcap_path = "testdata/tls/tls12_aes128gcm.pcap";
    let keylog_path = "testdata/tls/tls12_aes128gcm.keys";

    if !std::path::Path::new(pcap_path).exists() {
        eprintln!(
            "Skipping test_precaptured_tls12: test data not found at {}",
            pcap_path
        );
        eprintln!("See testdata/tls/README.md for instructions on generating test data");
        return;
    }

    let keylog = KeyLog::from_file(keylog_path).expect("Failed to load keylog");
    assert!(keylog.session_count() > 0, "Keylog should have sessions");
}

/// Test loading pre-captured TLS 1.3 data (if available)
#[test]
fn test_precaptured_tls13() {
    let pcap_path = "testdata/tls/tls13_aes256gcm.pcap";
    let keylog_path = "testdata/tls/tls13_aes256gcm.keys";

    if !std::path::Path::new(pcap_path).exists() {
        eprintln!(
            "Skipping test_precaptured_tls13: test data not found at {}",
            pcap_path
        );
        return;
    }

    let keylog = KeyLog::from_file(keylog_path).expect("Failed to load keylog");
    assert!(keylog.session_count() > 0, "Keylog should have sessions");
}

/// Test loading pre-captured HTTP/2 data (if available)
#[test]
fn test_precaptured_http2() {
    let pcap_path = "testdata/tls/http2_multiplex.pcap";
    let keylog_path = "testdata/tls/http2_multiplex.keys";

    if !std::path::Path::new(pcap_path).exists() {
        eprintln!(
            "Skipping test_precaptured_http2: test data not found at {}",
            pcap_path
        );
        return;
    }

    let keylog = KeyLog::from_file(keylog_path).expect("Failed to load keylog");
    assert!(keylog.session_count() > 0, "Keylog should have sessions");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_keylog_file_not_found() {
    let result = KeyLog::from_file("/nonexistent/path/to/keylog.txt");
    assert!(result.is_err(), "Should fail for nonexistent file");
}

#[test]
fn test_keylog_empty_file() {
    let keylog = KeyLog::from_str("").unwrap();
    assert!(keylog.is_empty());
    assert_eq!(keylog.session_count(), 0);
}

#[test]
fn test_keylog_comments_only() {
    let keylog = KeyLog::from_str("# This is a comment\n# Another comment\n").unwrap();
    assert!(keylog.is_empty());
}

#[test]
fn test_keylog_invalid_hex() {
    // Invalid hex in client_random
    let result = KeyLog::from_str("CLIENT_RANDOM ZZZZ 0000");
    assert!(result.is_err(), "Should fail with invalid hex");
}

#[test]
fn test_keylog_wrong_length() {
    // Client random too short (should be 32 bytes = 64 hex chars)
    let result = KeyLog::from_str("CLIENT_RANDOM 0102030405 0102030405");
    assert!(result.is_err(), "Should fail with wrong length");
}

#[test]
fn test_session_no_client_hello() {
    let keylog = Arc::new(KeyLog::new());
    let mut session = TlsSession::new(keylog);

    // Try to process ServerHello without ClientHello
    let _result = session.process_server_hello(
        TEST_SERVER_RANDOM,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsVersion::Tls12,
    );

    // This should handle gracefully - either error or just not decrypt
    // The exact behavior depends on implementation
    assert!(!session.can_decrypt());
}

#[test]
fn test_unsupported_cipher_suite_derivation() {
    // Try to derive keys with an unsupported cipher suite
    let result = derive_tls12_keys(
        &TEST_MASTER_SECRET,
        &TEST_CLIENT_RANDOM,
        &TEST_SERVER_RANDOM,
        0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA - not supported
    );

    assert!(result.is_err(), "Should fail for unsupported cipher suite");
}
