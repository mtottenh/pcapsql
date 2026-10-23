//! TLS sessions table schema definition.
//!
//! One row per TCP connection that carried a TLS handshake (a stream-analysis
//! table: built from reassembled streams, not per packet).
//!
//! ## Usage
//!
//! ```sql
//! SELECT sni, alpn, version, cipher_suite, is_decrypted FROM tls_sessions;
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `tls_sessions` table.
///
/// - `frame_number`: frame carrying the ClientHello (join key / capture order)
/// - `connection_id`: stream-manager connection id (shared with `tcp_connections`)
/// - `version`: negotiated version from the ServerHello (`TLS 1.2`, …), else the client's
/// - `cipher_suite`, `cipher_suite_id`: selected suite from the ServerHello
/// - `sni`, `alpn`: ClientHello extensions
/// - `is_decrypted`: a keylog decrypted this session (the Finished message was read)
/// - `server_hello_frame`: frame carrying the ServerHello, if seen
pub fn tls_sessions_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("connection_id", DataType::UInt64, false),
        Field::new("version", DataType::Utf8, true),
        Field::new("cipher_suite", DataType::Utf8, true),
        Field::new("cipher_suite_id", DataType::UInt16, true),
        Field::new("sni", DataType::Utf8, true),
        Field::new("alpn", DataType::Utf8, true),
        Field::new("is_decrypted", DataType::Boolean, false),
        Field::new("server_hello_frame", DataType::UInt64, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_sessions_schema() {
        let schema = tls_sessions_table_schema();
        assert_eq!(schema.fields().len(), 9);
        assert_eq!(schema.field(0).name(), "frame_number");
        assert!(schema.field_with_name("sni").is_ok());
        assert!(schema.field_with_name("is_decrypted").is_ok());
    }
}
