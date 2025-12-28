//! DHCP table schema definition.
//!
//! The `dhcp` table contains DHCP (Dynamic Host Configuration Protocol) fields.
//!
//! ## Address Storage
//!
//! - IPv4 addresses: `UInt32` (32 bits, network byte order)
//! - MAC addresses: `FixedSizeBinary(6)` (48 bits)
//! - Subnet mask: `UInt32` (32 bits, as bitmask)
//!
//! Use the `ip4()` and `mac()` UDFs for queries:
//! ```sql
//! SELECT * FROM dhcp WHERE yiaddr = ip4('192.168.1.100');
//! SELECT * FROM dhcp WHERE chaddr = mac('aa:bb:cc:dd:ee:ff');
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `dhcp` table.
///
/// Fields include both BOOTP header fields and common DHCP options.
pub fn dhcp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        // BOOTP header fields
        Field::new("op", DataType::UInt8, true),
        Field::new("htype", DataType::UInt8, true),
        Field::new("hlen", DataType::UInt8, true),
        Field::new("hops", DataType::UInt8, true),
        Field::new("xid", DataType::UInt32, true),
        Field::new("secs", DataType::UInt16, true),
        Field::new("flags", DataType::UInt16, true),
        // IPv4 addresses stored as UInt32 (network byte order)
        Field::new("ciaddr", DataType::UInt32, true), // Client IP address
        Field::new("yiaddr", DataType::UInt32, true), // Your (client) IP address
        Field::new("siaddr", DataType::UInt32, true), // Server IP address
        Field::new("giaddr", DataType::UInt32, true), // Gateway IP address
        // MAC address stored as FixedSizeBinary(6)
        Field::new("chaddr", DataType::FixedSizeBinary(6), true),
        // Common DHCP options
        Field::new("message_type", DataType::UInt8, true),
        Field::new("server_id", DataType::UInt32, true), // Server identifier (IPv4)
        Field::new("lease_time", DataType::UInt32, true),
        Field::new("subnet_mask", DataType::UInt32, true), // Subnet mask as bitmask
        Field::new("router", DataType::UInt32, true),      // Default gateway (IPv4)
        // DNS servers as comma-separated string (multiple IPs)
        Field::new("dns_servers", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_schema() {
        let schema = dhcp_table_schema();

        assert_eq!(schema.fields().len(), 19);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("xid").is_ok());
        assert!(schema.field_with_name("message_type").is_ok());
        assert!(schema.field_with_name("yiaddr").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = dhcp_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("dhcp."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
