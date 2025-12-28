//! TLS table schema definition.
//!
//! The `tls` table contains TLS/SSL handshake and record fields.
//!
//! ## Decryption Foundation
//!
//! The `client_random` and `server_random` fields are essential for TLS decryption
//! when used with SSLKEYLOGFILE. The `session_id` field tracks session resumption.
//!
//! ## JA3 Fingerprinting
//!
//! JA3 and JA3S fingerprints enable TLS client/server fingerprinting for
//! threat hunting and security analysis.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `tls` table.
///
/// Fields are organized into categories:
///
/// ### Record Layer
/// - `frame_number`: Reference to frames table
/// - `record_type`: TLS record type (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application)
/// - `record_version`: Record layer version (e.g., 0x0303 for TLS 1.2)
/// - `version`: TLS version string (e.g., "TLS 1.2", "TLS 1.3")
///
/// ### Handshake
/// - `handshake_type`: Handshake message type (1=ClientHello, 2=ServerHello, etc.)
/// - `handshake_version`: Handshake protocol version
///
/// ### Decryption Foundation (for future SSLKEYLOGFILE support)
/// - `client_random`: 32-byte random from ClientHello (key lookup)
/// - `server_random`: 32-byte random from ServerHello (key derivation)
/// - `session_id`: Session identifier for resumption tracking
/// - `session_id_length`: Length of session ID
///
/// ### Cipher Suites
/// - `cipher_suites`: Offered cipher suites (semicolon-separated, from ClientHello)
/// - `cipher_suite_count`: Number of offered cipher suites
/// - `selected_cipher`: Selected cipher suite name (from ServerHello)
/// - `selected_cipher_id`: Selected cipher suite ID (for decryption)
///
/// ### Compression
/// - `compression_methods`: Offered compression methods
/// - `selected_compression`: Selected compression method
///
/// ### Extensions
/// - `sni`: Server Name Indication hostname
/// - `alpn`: Application-Layer Protocol Negotiation (e.g., "h2;http/1.1")
/// - `supported_versions`: TLS 1.3 supported_versions extension
/// - `signature_algorithms`: Offered signature algorithms
/// - `supported_groups`: Elliptic curves / named groups
/// - `ec_point_formats`: EC point format extension
/// - `extensions_length`: Total extensions length
/// - `extension_types`: List of extension type IDs
///
/// ### Alerts
/// - `alert_level`: Alert severity (1=Warning, 2=Fatal)
/// - `alert_description`: Alert description code
/// - `alert_description_str`: Alert description name
///
/// ### Heartbeat
/// - `is_heartbeat`: True if this is a heartbeat record
/// - `heartbeat_type`: Heartbeat message type
///
/// ### Other
/// - `is_change_cipher_spec`: True if ChangeCipherSpec record
/// - `has_app_data`: True if Application Data record
/// - `app_data_length`: Length of encrypted application data
///
/// ### JA3 Fingerprinting
/// - `ja3`: JA3 fingerprint string (ClientHello)
/// - `ja3_hash`: MD5 hash of JA3 string
/// - `ja3s`: JA3S fingerprint string (ServerHello)
/// - `ja3s_hash`: MD5 hash of JA3S string
///
/// ### Certificates
/// - `certificate_count`: Number of certificates in chain
pub fn tls_table_schema() -> Schema {
    Schema::new(vec![
        // Core identification
        Field::new("frame_number", DataType::UInt64, false),
        // Record layer
        Field::new("record_type", DataType::UInt8, true),
        Field::new("record_version", DataType::UInt16, true),
        Field::new("version", DataType::Utf8, true),
        // Handshake
        Field::new("handshake_type", DataType::UInt8, true),
        Field::new("handshake_version", DataType::UInt16, true),
        // Decryption foundation fields
        Field::new("client_random", DataType::FixedSizeBinary(32), true),
        Field::new("server_random", DataType::FixedSizeBinary(32), true),
        Field::new("session_id", DataType::Binary, true),
        Field::new("session_id_length", DataType::UInt8, true),
        // Cipher suites
        Field::new("cipher_suites", DataType::Utf8, true),
        Field::new("cipher_suite_count", DataType::UInt16, true),
        Field::new("selected_cipher", DataType::Utf8, true),
        Field::new("selected_cipher_id", DataType::UInt16, true),
        // Compression
        Field::new("compression_methods", DataType::Utf8, true),
        Field::new("selected_compression", DataType::UInt8, true),
        // Extensions
        Field::new("sni", DataType::Utf8, true),
        Field::new("alpn", DataType::Utf8, true),
        Field::new("supported_versions", DataType::Utf8, true),
        Field::new("signature_algorithms", DataType::Utf8, true),
        Field::new("supported_groups", DataType::Utf8, true),
        Field::new("ec_point_formats", DataType::Utf8, true),
        Field::new("extensions_length", DataType::UInt16, true),
        Field::new("extension_types", DataType::Utf8, true),
        // Alerts
        Field::new("alert_level", DataType::UInt8, true),
        Field::new("alert_description", DataType::UInt8, true),
        Field::new("alert_description_str", DataType::Utf8, true),
        // Heartbeat
        Field::new("is_heartbeat", DataType::Boolean, true),
        Field::new("heartbeat_type", DataType::UInt8, true),
        // Other record types
        Field::new("is_change_cipher_spec", DataType::Boolean, true),
        Field::new("has_app_data", DataType::Boolean, true),
        Field::new("app_data_length", DataType::UInt32, true),
        // JA3 fingerprinting
        Field::new("ja3", DataType::Utf8, true),
        Field::new("ja3_hash", DataType::Utf8, true),
        Field::new("ja3s", DataType::Utf8, true),
        Field::new("ja3s_hash", DataType::Utf8, true),
        // Certificate info
        Field::new("certificate_count", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_schema() {
        let schema = tls_table_schema();

        // Check key fields exist
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("record_type").is_ok());
        assert!(schema.field_with_name("sni").is_ok());
        assert!(schema.field_with_name("selected_cipher").is_ok());

        // Check new decryption foundation fields
        assert!(schema.field_with_name("client_random").is_ok());
        assert!(schema.field_with_name("server_random").is_ok());
        assert!(schema.field_with_name("session_id").is_ok());

        // Check JA3 fields
        assert!(schema.field_with_name("ja3").is_ok());
        assert!(schema.field_with_name("ja3_hash").is_ok());
        assert!(schema.field_with_name("ja3s").is_ok());
        assert!(schema.field_with_name("ja3s_hash").is_ok());

        // Check extension fields
        assert!(schema.field_with_name("alpn").is_ok());
        assert!(schema.field_with_name("supported_versions").is_ok());
        assert!(schema.field_with_name("signature_algorithms").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = tls_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("tls."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }

    #[test]
    fn test_decryption_field_types() {
        let schema = tls_table_schema();

        // client_random and server_random should be FixedSizeBinary(32)
        let client_random = schema.field_with_name("client_random").unwrap();
        assert_eq!(client_random.data_type(), &DataType::FixedSizeBinary(32));

        let server_random = schema.field_with_name("server_random").unwrap();
        assert_eq!(server_random.data_type(), &DataType::FixedSizeBinary(32));

        // session_id should be Binary (variable length)
        let session_id = schema.field_with_name("session_id").unwrap();
        assert_eq!(session_id.data_type(), &DataType::Binary);

        // selected_cipher_id should be UInt16
        let cipher_id = schema.field_with_name("selected_cipher_id").unwrap();
        assert_eq!(cipher_id.data_type(), &DataType::UInt16);
    }
}
