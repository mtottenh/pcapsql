//! QUIC table schema definition.
//!
//! The `quic` table contains QUIC transport protocol fields including
//! header type, version, connection IDs, and packet metadata.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `quic` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `header_form`: "long" or "short"
/// - `long_packet_type`: For long headers: "Initial", "0-RTT", "Handshake", "Retry"
/// - `version`: QUIC version number
/// - `version_name`: Human-readable version name (e.g., "QUIC v1")
/// - `dcid_length`: Destination Connection ID length
/// - `dcid`: Destination Connection ID (hex encoded)
/// - `scid_length`: Source Connection ID length (long header only)
/// - `scid`: Source Connection ID (hex encoded, long header only)
/// - `token_length`: Token length (Initial packets only)
/// - `packet_length`: Packet length (from header)
/// - `spin_bit`: Latency spin bit (short header only)
/// - `key_phase`: Key phase bit (short header only)
/// - `sni`: Server Name Indication (if extractable from Initial packet)
pub fn quic_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("header_form", DataType::Utf8, true),
        Field::new("long_packet_type", DataType::Utf8, true),
        Field::new("version", DataType::UInt32, true),
        Field::new("version_name", DataType::Utf8, true),
        Field::new("dcid_length", DataType::UInt8, true),
        Field::new("dcid", DataType::Utf8, true),
        Field::new("scid_length", DataType::UInt8, true),
        Field::new("scid", DataType::Utf8, true),
        Field::new("token_length", DataType::UInt32, true),
        Field::new("packet_length", DataType::UInt32, true),
        Field::new("spin_bit", DataType::Boolean, true),
        Field::new("key_phase", DataType::Boolean, true),
        Field::new("sni", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_schema() {
        let schema = quic_table_schema();

        assert_eq!(schema.fields().len(), 14);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("header_form").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("dcid").is_ok());
        assert!(schema.field_with_name("scid").is_ok());
        assert!(schema.field_with_name("sni").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = quic_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("quic."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
