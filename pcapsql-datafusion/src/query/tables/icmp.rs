//! ICMP table schema definition.
//!
//! The `icmp` table contains ICMP (Internet Control Message Protocol) fields.
//!
//! ## Address Storage
//!
//! - IPv4 gateway address: `UInt32` (32 bits, network byte order)
//!
//! Use the `ip4()` UDF for queries:
//! ```sql
//! SELECT * FROM icmp WHERE gateway = ip4('192.168.1.1');
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `icmp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `type`: ICMP type (e.g., 8 = Echo Request)
/// - `code`: ICMP code (subtype)
/// - `checksum`: ICMP checksum
/// - `type_name`: Human-readable type name
/// - `identifier`: Echo request/reply identifier
/// - `sequence`: Echo request/reply sequence number
/// - `next_hop_mtu`: MTU for "fragmentation needed" errors
/// - `gateway`: Gateway address for redirects (UInt32)
pub fn icmp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("type", DataType::UInt8, true),
        Field::new("code", DataType::UInt8, true),
        Field::new("checksum", DataType::UInt16, true),
        Field::new("type_name", DataType::Utf8, true),
        Field::new("identifier", DataType::UInt16, true),
        Field::new("sequence", DataType::UInt16, true),
        Field::new("next_hop_mtu", DataType::UInt16, true),
        // Gateway address stored as UInt32 (network byte order)
        Field::new("gateway", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_schema() {
        let schema = icmp_table_schema();

        assert_eq!(schema.fields().len(), 9);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("type").is_ok());
        assert!(schema.field_with_name("code").is_ok());
        assert!(schema.field_with_name("type_name").is_ok());
    }
}
