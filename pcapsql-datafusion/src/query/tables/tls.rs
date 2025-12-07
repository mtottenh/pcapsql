//! TLS table schema definition.
//!
//! The `tls` table contains TLS/SSL handshake and record fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `tls` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `record_type`: TLS record type (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application)
/// - `version`: TLS version (e.g., "TLS 1.2", "TLS 1.3")
/// - `handshake_type`: Handshake message type (1=ClientHello, 2=ServerHello, etc.)
/// - `sni`: Server Name Indication (from ClientHello)
/// - `cipher_suites`: Offered cipher suites (comma-separated, from ClientHello)
/// - `selected_cipher`: Selected cipher suite (from ServerHello)
pub fn tls_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("record_type", DataType::UInt8, true),
        Field::new("version", DataType::Utf8, true),
        Field::new("handshake_type", DataType::UInt8, true),
        Field::new("sni", DataType::Utf8, true),
        Field::new("cipher_suites", DataType::Utf8, true),
        Field::new("selected_cipher", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_schema() {
        let schema = tls_table_schema();

        assert_eq!(schema.fields().len(), 7);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("record_type").is_ok());
        assert!(schema.field_with_name("sni").is_ok());
        assert!(schema.field_with_name("selected_cipher").is_ok());
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
}
