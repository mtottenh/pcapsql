//! ARP table schema definition.
//!
//! The `arp` table contains Address Resolution Protocol fields.
//!
//! ## Address Storage
//!
//! - MAC addresses: `FixedSizeBinary(6)` (48 bits)
//! - IPv4 addresses: `UInt32` (32 bits, network byte order)
//!
//! Use the `mac()` and `ip4()` UDFs for queries:
//! ```sql
//! SELECT * FROM arp WHERE sender_ip = ip4('192.168.1.1');
//! SELECT * FROM arp WHERE sender_mac = mac('aa:bb:cc:dd:ee:ff');
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `arp` table.
///
/// Fields match the ARP protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
/// - `hardware_type`: Hardware type (1 = Ethernet)
/// - `protocol_type`: Protocol type (0x0800 = IPv4)
/// - `hardware_size`: Hardware address size (6 for Ethernet)
/// - `protocol_size`: Protocol address size (4 for IPv4)
/// - `operation`: Operation code (1 = Request, 2 = Reply)
/// - `operation_name`: Human-readable operation name
/// - `sender_mac`: Sender MAC address (FixedSizeBinary(6))
/// - `sender_ip`: Sender IP address (UInt32)
/// - `target_mac`: Target MAC address (FixedSizeBinary(6))
/// - `target_ip`: Target IP address (UInt32)
pub fn arp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("hardware_type", DataType::UInt16, true),
        Field::new("protocol_type", DataType::UInt16, true),
        Field::new("hardware_size", DataType::UInt8, true),
        Field::new("protocol_size", DataType::UInt8, true),
        Field::new("operation", DataType::UInt16, true),
        Field::new("operation_name", DataType::Utf8, true),
        // MAC addresses stored as FixedSizeBinary(6)
        Field::new("sender_mac", DataType::FixedSizeBinary(6), true),
        // IPv4 addresses stored as UInt32 (network byte order)
        Field::new("sender_ip", DataType::UInt32, true),
        Field::new("target_mac", DataType::FixedSizeBinary(6), true),
        Field::new("target_ip", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_schema() {
        let schema = arp_table_schema();

        assert_eq!(schema.fields().len(), 11);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("operation").is_ok());
        assert!(schema.field_with_name("sender_ip").is_ok());
        assert!(schema.field_with_name("target_ip").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = arp_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("arp."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
