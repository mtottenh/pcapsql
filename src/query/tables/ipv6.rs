//! IPv6 table schema definition.
//!
//! The `ipv6` table contains IPv6 header fields.
//!
//! ## Address Storage
//!
//! IPv6 addresses are stored as `FixedSizeBinary(16)` (128 bits).
//! This enables:
//! - Efficient prefix/CIDR matching via bitwise operations
//! - Correct binary ordering
//! - Compact storage (16 bytes vs 39+ bytes for string)
//!
//! Use the `ip6()` UDF to convert string literals in queries:
//! ```sql
//! SELECT * FROM ipv6 WHERE src_ip = ip6('fe80::1');
//! SELECT * FROM ipv6 WHERE ip6_in_cidr(src_ip, '2001:db8::/32');
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ipv6` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `version`: IP version (always 6)
/// - `traffic_class`: Traffic class
/// - `flow_label`: Flow label
/// - `payload_length`: Payload length
/// - `next_header`: Next header protocol number
/// - `hop_limit`: Hop limit (similar to TTL)
/// - `src_ip`: Source IPv6 address (FixedSizeBinary(16))
/// - `dst_ip`: Destination IPv6 address (FixedSizeBinary(16))
pub fn ipv6_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("version", DataType::UInt8, true),
        Field::new("traffic_class", DataType::UInt8, true),
        Field::new("flow_label", DataType::UInt32, true),
        Field::new("payload_length", DataType::UInt16, true),
        Field::new("next_header", DataType::UInt8, true),
        Field::new("hop_limit", DataType::UInt8, true),
        // IPv6 addresses stored as FixedSizeBinary(16) (128 bits)
        Field::new("src_ip", DataType::FixedSizeBinary(16), true),
        Field::new("dst_ip", DataType::FixedSizeBinary(16), true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_schema() {
        let schema = ipv6_table_schema();

        assert_eq!(schema.fields().len(), 9);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("src_ip").is_ok());
        assert!(schema.field_with_name("dst_ip").is_ok());
        assert!(schema.field_with_name("hop_limit").is_ok());
        assert!(schema.field_with_name("next_header").is_ok());
    }
}
