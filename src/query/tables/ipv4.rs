//! IPv4 table schema definition.
//!
//! The `ipv4` table contains IPv4 header fields.
//!
//! ## Address Storage
//!
//! IPv4 addresses are stored as `UInt32` in network byte order (big-endian).
//! This enables:
//! - Efficient CIDR range queries via bitwise operations
//! - Correct numerical ordering (not lexicographic)
//! - 4x storage reduction vs UTF-8 strings
//!
//! Use the `ip4()` UDF to convert string literals in queries:
//! ```sql
//! SELECT * FROM ipv4 WHERE src_ip = ip4('192.168.1.1');
//! SELECT * FROM ipv4 WHERE ip_in_cidr(src_ip, '10.0.0.0/8');
//! SELECT * FROM ipv4 WHERE src_ip BETWEEN ip4('10.0.0.0') AND ip4('10.0.0.255');
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ipv4` table.
///
/// Fields match the IPv4 protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
/// - `version`: IP version (always 4)
/// - `ihl`: Internet Header Length
/// - `dscp`: Differentiated Services Code Point
/// - `ecn`: Explicit Congestion Notification
/// - `total_length`: Total packet length
/// - `identification`: Identification field
/// - `dont_fragment`: Don't Fragment flag
/// - `more_fragments`: More Fragments flag
/// - `fragment_offset`: Fragment offset
/// - `ttl`: Time To Live
/// - `protocol`: Protocol number (6=TCP, 17=UDP, 1=ICMP)
/// - `checksum`: Header checksum
/// - `src_ip`: Source IP address (UInt32, network byte order)
/// - `dst_ip`: Destination IP address (UInt32, network byte order)
pub fn ipv4_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("version", DataType::UInt8, true),
        Field::new("ihl", DataType::UInt8, true),
        Field::new("dscp", DataType::UInt8, true),
        Field::new("ecn", DataType::UInt8, true),
        Field::new("total_length", DataType::UInt16, true),
        Field::new("identification", DataType::UInt16, true),
        Field::new("dont_fragment", DataType::Boolean, true),
        Field::new("more_fragments", DataType::Boolean, true),
        Field::new("fragment_offset", DataType::UInt16, true),
        Field::new("ttl", DataType::UInt8, true),
        Field::new("protocol", DataType::UInt8, true),
        Field::new("checksum", DataType::UInt16, true),
        // IPv4 addresses stored as UInt32 (4 bytes, network byte order)
        Field::new("src_ip", DataType::UInt32, true),
        Field::new("dst_ip", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_schema() {
        let schema = ipv4_table_schema();

        assert_eq!(schema.fields().len(), 15);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("src_ip").is_ok());
        assert!(schema.field_with_name("dst_ip").is_ok());
        assert!(schema.field_with_name("ttl").is_ok());
        assert!(schema.field_with_name("protocol").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = ipv4_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("ipv4."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
