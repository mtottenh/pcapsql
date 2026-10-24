//! GTP table schema definition.
//!
//! The `gtp` table contains GTP (GPRS Tunneling Protocol) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `gtp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `version`: GTP version (1 for GTPv1)
/// - `protocol_type`: 1 = GTP, 0 = GTP'
/// - `message_type`: Message type code
/// - `length`: Payload length
/// - `teid`: Tunnel Endpoint Identifier
/// - `sequence`: Optional sequence number
/// - `npdu`: N-PDU number (GTPv1, PN flag)
/// - `extension_headers`: GTPv1 extension header chain, comma-separated
///   `Name(0xNN)` entries in header order
/// - `extension_header_count`: Extension headers in the chain
/// - `piggyback`: GTPv2-C P flag (another message follows this one)
/// - `teid_present`: GTPv2-C T flag (the header carries a TEID)
pub fn gtp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("version", DataType::UInt8, true),
        Field::new("protocol_type", DataType::UInt8, true),
        Field::new("message_type", DataType::UInt8, true),
        Field::new("length", DataType::UInt16, true),
        Field::new("teid", DataType::UInt32, true),
        Field::new("sequence", DataType::UInt32, true),
        // GTPv1 optional header fields
        Field::new("npdu", DataType::UInt8, true),
        Field::new("extension_headers", DataType::Utf8, true),
        Field::new("extension_header_count", DataType::UInt8, true),
        // GTPv2-C flags
        Field::new("piggyback", DataType::Boolean, true),
        Field::new("teid_present", DataType::Boolean, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_schema() {
        let schema = gtp_table_schema();

        assert_eq!(schema.fields().len(), 12);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("protocol_type").is_ok());
        assert!(schema.field_with_name("message_type").is_ok());
        assert!(schema.field_with_name("length").is_ok());
        assert!(schema.field_with_name("teid").is_ok());
        assert!(schema.field_with_name("sequence").is_ok());
        for (name, ty) in [
            ("npdu", DataType::UInt8),
            ("extension_headers", DataType::Utf8),
            ("extension_header_count", DataType::UInt8),
            ("piggyback", DataType::Boolean),
            ("teid_present", DataType::Boolean),
        ] {
            assert_eq!(
                schema.field_with_name(name).unwrap().data_type(),
                &ty,
                "{name}"
            );
        }
    }
}
