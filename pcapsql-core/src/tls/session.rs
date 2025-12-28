//! TLS session state management.
//!
//! Manages the lifecycle of a TLS session from handshake through decryption,
//! coordinating key lookup, key derivation, and decryption contexts.

use std::sync::Arc;

use super::decrypt::{DecryptionContext, DecryptionError, Direction, TlsVersion};
use super::kdf::{derive_tls12_keys, derive_tls13_keys, AeadAlgorithm, KeyDerivationError};
use super::keylog::{KeyLog, KeyLogEntries};
use thiserror::Error;

/// Errors that can occur during TLS session management.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(#[from] KeyDerivationError),

    #[error("Decryption error: {0}")]
    Decryption(#[from] DecryptionError),

    #[error("Missing key material for client_random")]
    MissingKeys,

    #[error("Unsupported cipher suite: 0x{0:04x}")]
    UnsupportedCipherSuite(u16),

    #[error("Session not initialized: handshake incomplete")]
    NotInitialized,

    #[error("Missing client_random from ClientHello")]
    MissingClientRandom,

    #[error("Missing server_random from ServerHello")]
    MissingServerRandom,

    #[error("Missing cipher suite selection from ServerHello")]
    MissingCipherSuite,
}

/// State of a TLS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, waiting for ClientHello
    Initial,
    /// Received ClientHello, waiting for ServerHello
    ClientHelloReceived,
    /// Received ServerHello, keys can be derived
    ServerHelloReceived,
    /// TLS 1.3: Handshake keys established, waiting for Finished messages
    Tls13HandshakeEncrypted,
    /// Keys derived, ready for application data decryption
    KeysEstablished,
    /// Session closed or errored
    Closed,
}

/// TLS 1.3 handshake phase tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13HandshakePhase {
    /// Initial state after ServerHello, both sides sending encrypted handshake
    Initial,
    /// Server has sent Finished, waiting for client Finished
    ServerFinished,
    /// Both Finished messages seen, application data mode
    Complete,
}

/// Handshake data collected from TLS handshake messages.
#[derive(Debug, Clone, Default)]
pub struct HandshakeData {
    /// Client random from ClientHello (32 bytes)
    pub client_random: Option<[u8; 32]>,

    /// Server random from ServerHello (32 bytes)
    pub server_random: Option<[u8; 32]>,

    /// Selected cipher suite from ServerHello
    pub cipher_suite: Option<u16>,

    /// TLS version negotiated (from ServerHello or supported_versions extension)
    pub version: Option<TlsVersion>,

    /// Session ID (for resumption tracking)
    pub session_id: Option<Vec<u8>>,
}

impl HandshakeData {
    /// Check if we have enough data to derive keys.
    pub fn can_derive_keys(&self) -> bool {
        self.client_random.is_some() && self.server_random.is_some() && self.cipher_suite.is_some()
    }

    /// Get the effective TLS version.
    pub fn effective_version(&self) -> Option<TlsVersion> {
        self.version
    }
}

/// A TLS session that can decrypt traffic.
///
/// Manages the full lifecycle:
/// 1. Collect handshake data (client_random, server_random, cipher_suite)
/// 2. Look up keys from SSLKEYLOGFILE
/// 3. Derive encryption keys
/// 4. Create decryption contexts for both directions
/// 5. Decrypt application data records
pub struct TlsSession {
    /// Current session state
    state: SessionState,

    /// Collected handshake data
    handshake: HandshakeData,

    /// Reference to the keylog for key lookup
    keylog: Arc<KeyLog>,

    /// Client-to-server decryption context (application traffic)
    client_decrypt: Option<DecryptionContext>,

    /// Server-to-client decryption context (application traffic)
    server_decrypt: Option<DecryptionContext>,

    /// TLS 1.3 only: Client-to-server handshake decryption context
    client_hs_decrypt: Option<DecryptionContext>,

    /// TLS 1.3 only: Server-to-client handshake decryption context
    server_hs_decrypt: Option<DecryptionContext>,

    /// TLS 1.3 handshake phase tracking
    tls13_hs_phase: Tls13HandshakePhase,
}

impl TlsSession {
    /// Create a new TLS session with a keylog reference.
    pub fn new(keylog: Arc<KeyLog>) -> Self {
        Self {
            state: SessionState::Initial,
            handshake: HandshakeData::default(),
            keylog,
            client_decrypt: None,
            server_decrypt: None,
            client_hs_decrypt: None,
            server_hs_decrypt: None,
            tls13_hs_phase: Tls13HandshakePhase::Initial,
        }
    }

    /// Get the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get the handshake data.
    pub fn handshake(&self) -> &HandshakeData {
        &self.handshake
    }

    /// Process a ClientHello message.
    ///
    /// Extracts the client_random from the handshake.
    pub fn process_client_hello(&mut self, client_random: [u8; 32]) {
        self.handshake.client_random = Some(client_random);
        self.state = SessionState::ClientHelloReceived;
    }

    /// Process a ServerHello message.
    ///
    /// Extracts server_random and cipher_suite, then attempts key derivation.
    pub fn process_server_hello(
        &mut self,
        server_random: [u8; 32],
        cipher_suite: u16,
        version: TlsVersion,
    ) -> Result<(), SessionError> {
        self.handshake.server_random = Some(server_random);
        self.handshake.cipher_suite = Some(cipher_suite);
        self.handshake.version = Some(version);
        self.state = SessionState::ServerHelloReceived;

        // Try to establish keys immediately
        self.try_establish_keys()
    }

    /// Attempt to establish decryption keys.
    ///
    /// This requires:
    /// - client_random and server_random from handshake
    /// - Cipher suite selection
    /// - Key material from SSLKEYLOGFILE
    pub fn try_establish_keys(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::KeysEstablished
            || self.state == SessionState::Tls13HandshakeEncrypted
        {
            return Ok(()); // Already done
        }

        let client_random = self
            .handshake
            .client_random
            .ok_or(SessionError::MissingClientRandom)?;

        let server_random = self
            .handshake
            .server_random
            .ok_or(SessionError::MissingServerRandom)?;

        let cipher_suite = self
            .handshake
            .cipher_suite
            .ok_or(SessionError::MissingCipherSuite)?;

        let version = self.handshake.version.unwrap_or(TlsVersion::Tls12);

        // Look up keys from SSLKEYLOGFILE and clone to avoid borrow conflict
        let key_entries = self
            .keylog
            .lookup(&client_random)
            .ok_or(SessionError::MissingKeys)?
            .clone();

        // Get the AEAD algorithm
        let aead = AeadAlgorithm::from_cipher_suite(cipher_suite)
            .ok_or(SessionError::UnsupportedCipherSuite(cipher_suite))?;

        // Derive keys based on TLS version
        match version {
            TlsVersion::Tls13 => {
                self.establish_tls13_keys(&key_entries, cipher_suite, aead)?;
                // For TLS 1.3, we start in handshake encryption mode
                self.state = SessionState::Tls13HandshakeEncrypted;
            }
            _ => {
                self.establish_tls12_keys(
                    &key_entries,
                    &client_random,
                    &server_random,
                    cipher_suite,
                    aead,
                )?;
                self.state = SessionState::KeysEstablished;
            }
        }

        Ok(())
    }

    /// Establish TLS 1.2 keys.
    fn establish_tls12_keys(
        &mut self,
        key_entries: &KeyLogEntries,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        cipher_suite: u16,
        aead: AeadAlgorithm,
    ) -> Result<(), SessionError> {
        let master_secret = key_entries.master_secret.ok_or(SessionError::MissingKeys)?;

        let keys = derive_tls12_keys(&master_secret, client_random, server_random, cipher_suite)?;

        self.client_decrypt = Some(DecryptionContext::new_tls12(
            &keys,
            aead,
            Direction::ClientToServer,
        )?);
        self.server_decrypt = Some(DecryptionContext::new_tls12(
            &keys,
            aead,
            Direction::ServerToClient,
        )?);

        Ok(())
    }

    /// Establish TLS 1.3 keys.
    ///
    /// For TLS 1.3, we set up both handshake and application traffic keys.
    /// After ServerHello, encrypted records use handshake keys until both
    /// sides have sent their Finished messages, then application keys are used.
    fn establish_tls13_keys(
        &mut self,
        key_entries: &KeyLogEntries,
        cipher_suite: u16,
        aead: AeadAlgorithm,
    ) -> Result<(), SessionError> {
        // Set up handshake traffic keys (used for encrypted handshake messages)
        if let (Some(client_hs_secret), Some(server_hs_secret)) = (
            key_entries.client_handshake_traffic_secret.as_ref(),
            key_entries.server_handshake_traffic_secret.as_ref(),
        ) {
            let client_hs_keys = derive_tls13_keys(client_hs_secret, cipher_suite)?;
            let server_hs_keys = derive_tls13_keys(server_hs_secret, cipher_suite)?;

            self.client_hs_decrypt = Some(DecryptionContext::new_tls13(&client_hs_keys, aead)?);
            self.server_hs_decrypt = Some(DecryptionContext::new_tls13(&server_hs_keys, aead)?);
        }

        // Set up application traffic keys (used after handshake completes)
        let client_secret = key_entries
            .client_traffic_secret_0
            .as_ref()
            .ok_or(SessionError::MissingKeys)?;

        let server_secret = key_entries
            .server_traffic_secret_0
            .as_ref()
            .ok_or(SessionError::MissingKeys)?;

        let client_keys = derive_tls13_keys(client_secret, cipher_suite)?;
        let server_keys = derive_tls13_keys(server_secret, cipher_suite)?;

        self.client_decrypt = Some(DecryptionContext::new_tls13(&client_keys, aead)?);
        self.server_decrypt = Some(DecryptionContext::new_tls13(&server_keys, aead)?);

        // Reset handshake phase tracking
        self.tls13_hs_phase = Tls13HandshakePhase::Initial;

        Ok(())
    }

    /// Check if the session can decrypt traffic.
    pub fn can_decrypt(&self) -> bool {
        match self.state {
            SessionState::KeysEstablished => {
                self.client_decrypt.is_some() && self.server_decrypt.is_some()
            }
            SessionState::Tls13HandshakeEncrypted => {
                // Can decrypt if we have handshake keys
                self.client_hs_decrypt.is_some() && self.server_hs_decrypt.is_some()
            }
            _ => false,
        }
    }

    /// Check if we're in TLS 1.3 handshake encryption mode.
    pub fn is_tls13_handshake_phase(&self) -> bool {
        self.state == SessionState::Tls13HandshakeEncrypted
    }

    /// Get the current TLS 1.3 handshake phase.
    pub fn tls13_handshake_phase(&self) -> Tls13HandshakePhase {
        self.tls13_hs_phase
    }

    /// Transition to TLS 1.3 application data phase.
    /// Called when both Finished messages have been processed.
    pub fn transition_to_application_data(&mut self) {
        if self.state == SessionState::Tls13HandshakeEncrypted {
            self.state = SessionState::KeysEstablished;
            self.tls13_hs_phase = Tls13HandshakePhase::Complete;
        }
    }

    /// Mark that the server has sent its Finished message.
    pub fn mark_server_finished(&mut self) {
        if self.tls13_hs_phase == Tls13HandshakePhase::Initial {
            self.tls13_hs_phase = Tls13HandshakePhase::ServerFinished;
        }
    }

    /// Mark that the client has sent its Finished message.
    /// This also transitions to application data mode.
    pub fn mark_client_finished(&mut self) {
        self.transition_to_application_data();
    }

    /// Decrypt a TLS record.
    ///
    /// Returns the decrypted plaintext. For TLS 1.3, this automatically uses
    /// the correct keys based on the handshake phase.
    pub fn decrypt_record(
        &mut self,
        direction: Direction,
        record_type: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        if !self.can_decrypt() {
            return Err(SessionError::NotInitialized);
        }

        let version = self.handshake.version.unwrap_or(TlsVersion::Tls12);
        let protocol_version = version.to_wire();

        // For TLS 1.3, select the correct decryption context based on handshake phase
        let ctx = if self.state == SessionState::Tls13HandshakeEncrypted {
            // During handshake phase, use handshake keys
            match direction {
                Direction::ClientToServer => self.client_hs_decrypt.as_mut(),
                Direction::ServerToClient => self.server_hs_decrypt.as_mut(),
            }
        } else {
            // Application data phase, use traffic keys
            match direction {
                Direction::ClientToServer => self.client_decrypt.as_mut(),
                Direction::ServerToClient => self.server_decrypt.as_mut(),
            }
        };

        let ctx = ctx.ok_or(SessionError::NotInitialized)?;
        let plaintext = ctx.decrypt_record(version, record_type, protocol_version, ciphertext)?;
        Ok(plaintext)
    }

    /// Decrypt a TLS 1.3 handshake record specifically.
    /// Use this when you know you're decrypting handshake messages.
    pub fn decrypt_handshake_record(
        &mut self,
        direction: Direction,
        record_type: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let ctx = match direction {
            Direction::ClientToServer => self.client_hs_decrypt.as_mut(),
            Direction::ServerToClient => self.server_hs_decrypt.as_mut(),
        };

        let ctx = ctx.ok_or(SessionError::NotInitialized)?;
        let version = TlsVersion::Tls13;
        let protocol_version = version.to_wire();

        let plaintext = ctx.decrypt_record(version, record_type, protocol_version, ciphertext)?;
        Ok(plaintext)
    }

    /// Decrypt a TLS 1.3 application data record specifically.
    /// Use this when you know you're decrypting application data.
    pub fn decrypt_application_record(
        &mut self,
        direction: Direction,
        record_type: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let ctx = match direction {
            Direction::ClientToServer => self.client_decrypt.as_mut(),
            Direction::ServerToClient => self.server_decrypt.as_mut(),
        };

        let ctx = ctx.ok_or(SessionError::NotInitialized)?;
        let version = TlsVersion::Tls13;
        let protocol_version = version.to_wire();

        let plaintext = ctx.decrypt_record(version, record_type, protocol_version, ciphertext)?;
        Ok(plaintext)
    }

    /// Get the cipher suite name if available.
    pub fn cipher_suite_name(&self) -> Option<&'static str> {
        self.handshake.cipher_suite.and_then(cipher_suite_name)
    }

    /// Get the client's sequence number (for debugging).
    pub fn client_sequence(&self) -> Option<u64> {
        self.client_decrypt.as_ref().map(|c| c.sequence_number())
    }

    /// Get the server's sequence number (for debugging).
    pub fn server_sequence(&self) -> Option<u64> {
        self.server_decrypt.as_ref().map(|c| c.sequence_number())
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }
}

/// Get the cipher suite name for a given ID.
fn cipher_suite_name(id: u16) -> Option<&'static str> {
    match id {
        // TLS 1.3
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),

        // TLS 1.2 ECDHE-RSA
        0xC02F => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        0xC030 => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        0xCCA8 => Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),

        // TLS 1.2 ECDHE-ECDSA
        0xC02B => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        0xC02C => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        0xCCA9 => Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),

        // TLS 1.2 DHE-RSA
        0x009E => Some("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        0x009F => Some("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        0xCCAA => Some("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),

        // TLS 1.2 RSA
        0x009C => Some("TLS_RSA_WITH_AES_128_GCM_SHA256"),
        0x009D => Some("TLS_RSA_WITH_AES_256_GCM_SHA384"),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keylog() -> Arc<KeyLog> {
        // Create a keylog with test data
        let content = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        Arc::new(KeyLog::from_str(content).unwrap())
    }

    fn create_test_keylog_tls13() -> Arc<KeyLog> {
        let content = r#"
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb
SERVER_HANDSHAKE_TRAFFIC_SECRET 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef cafebabe556677889900aabbccddeeff00112233445566778899aabbccddeeff
CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb
SERVER_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff
"#;
        Arc::new(KeyLog::from_str(content).unwrap())
    }

    #[test]
    fn test_session_initial_state() {
        let keylog = create_test_keylog();
        let session = TlsSession::new(keylog);

        assert_eq!(session.state(), SessionState::Initial);
        assert!(!session.can_decrypt());
    }

    #[test]
    fn test_session_client_hello() {
        let keylog = create_test_keylog();
        let mut session = TlsSession::new(keylog);

        let client_random = [0x42u8; 32];
        session.process_client_hello(client_random);

        assert_eq!(session.state(), SessionState::ClientHelloReceived);
        assert_eq!(session.handshake().client_random, Some(client_random));
    }

    #[test]
    fn test_session_server_hello_missing_keys() {
        let keylog = create_test_keylog();
        let mut session = TlsSession::new(keylog);

        // Use a different client_random that's not in the keylog
        let client_random = [0x42u8; 32];
        session.process_client_hello(client_random);

        let server_random = [0x43u8; 32];
        let result = session.process_server_hello(server_random, 0xC02F, TlsVersion::Tls12);

        // Should fail because the client_random isn't in the keylog
        assert!(matches!(result, Err(SessionError::MissingKeys)));
    }

    #[test]
    fn test_session_tls12_key_establishment() {
        let keylog = create_test_keylog();
        let mut session = TlsSession::new(keylog);

        // Use the client_random that's in the keylog
        let client_random: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        session.process_client_hello(client_random);

        let server_random = [0x43u8; 32];
        let result = session.process_server_hello(server_random, 0xC02F, TlsVersion::Tls12);

        assert!(result.is_ok());
        assert_eq!(session.state(), SessionState::KeysEstablished);
        assert!(session.can_decrypt());
        assert_eq!(
            session.cipher_suite_name(),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
    }

    #[test]
    fn test_session_tls13_key_establishment() {
        let keylog = create_test_keylog_tls13();
        let mut session = TlsSession::new(keylog);

        // Use the client_random that's in the keylog
        let client_random: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        session.process_client_hello(client_random);

        let server_random = [0x43u8; 32];
        let result = session.process_server_hello(server_random, 0x1301, TlsVersion::Tls13);

        assert!(result.is_ok());
        // For TLS 1.3, we start in handshake encryption mode
        assert_eq!(session.state(), SessionState::Tls13HandshakeEncrypted);
        assert!(session.can_decrypt());
        assert_eq!(session.cipher_suite_name(), Some("TLS_AES_128_GCM_SHA256"));

        // Test transition to application data mode after handshake completes
        assert!(session.is_tls13_handshake_phase());
        session.mark_server_finished();
        assert_eq!(
            session.tls13_handshake_phase(),
            Tls13HandshakePhase::ServerFinished
        );
        session.mark_client_finished();
        assert_eq!(session.state(), SessionState::KeysEstablished);
        assert!(!session.is_tls13_handshake_phase());
    }

    #[test]
    fn test_session_unsupported_cipher_suite() {
        let keylog = create_test_keylog();
        let mut session = TlsSession::new(keylog);

        let client_random: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        session.process_client_hello(client_random);

        let server_random = [0x43u8; 32];
        // Use an unsupported cipher suite
        let result = session.process_server_hello(server_random, 0x0000, TlsVersion::Tls12);

        assert!(matches!(
            result,
            Err(SessionError::UnsupportedCipherSuite(0x0000))
        ));
    }

    #[test]
    fn test_session_close() {
        let keylog = create_test_keylog();
        let mut session = TlsSession::new(keylog);

        session.close();
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_decrypt_not_initialized() {
        let keylog = create_test_keylog();
        let mut session = TlsSession::new(keylog);

        let result = session.decrypt_record(Direction::ClientToServer, 23, &[0u8; 32]);
        assert!(matches!(result, Err(SessionError::NotInitialized)));
    }

    #[test]
    fn test_handshake_data_can_derive_keys() {
        let mut data = HandshakeData::default();
        assert!(!data.can_derive_keys());

        data.client_random = Some([0u8; 32]);
        assert!(!data.can_derive_keys());

        data.server_random = Some([0u8; 32]);
        assert!(!data.can_derive_keys());

        data.cipher_suite = Some(0xC02F);
        assert!(data.can_derive_keys());
    }

    #[test]
    fn test_cipher_suite_name() {
        assert_eq!(cipher_suite_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(cipher_suite_name(0x1302), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(
            cipher_suite_name(0xC02F),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(cipher_suite_name(0x0000), None);
    }
}
