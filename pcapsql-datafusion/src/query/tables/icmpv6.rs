//! ICMPv6 table schema definition.
//!
//! The `icmpv6` table contains ICMPv6 fields including NDP and MLD messages.
//!
//! ## Address Storage
//!
//! - IPv6 addresses: `FixedSizeBinary(16)` (128 bits)
//! - MAC addresses: `FixedSizeBinary(6)` (48 bits)
//!
//! Use the `ip6()` and `mac()` UDFs for queries:
//! ```sql
//! SELECT * FROM icmpv6 WHERE ndp_target_address = ip6('fe80::1');
//! SELECT * FROM icmpv6 WHERE ndp_source_mac = mac('aa:bb:cc:dd:ee:ff');
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `icmpv6` table.
///
/// Fields include core ICMPv6, NDP (Neighbor Discovery), and MLD (Multicast Listener Discovery).
pub fn icmpv6_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        // Core ICMPv6 fields
        Field::new("type", DataType::UInt8, true),
        Field::new("code", DataType::UInt8, true),
        Field::new("checksum", DataType::UInt16, true),
        Field::new("type_name", DataType::Utf8, true),
        // Echo request/reply
        Field::new("echo_id", DataType::UInt16, true),
        Field::new("echo_seq", DataType::UInt16, true),
        // Packet Too Big
        Field::new("mtu", DataType::UInt32, true),
        // Parameter Problem
        Field::new("pointer", DataType::UInt32, true),
        // NDP common - IPv6 address stored as FixedSizeBinary(16)
        Field::new("ndp_target_address", DataType::FixedSizeBinary(16), true),
        // Router Advertisement
        Field::new("ndp_cur_hop_limit", DataType::UInt8, true),
        Field::new("ndp_managed_flag", DataType::Boolean, true),
        Field::new("ndp_other_flag", DataType::Boolean, true),
        Field::new("ndp_router_lifetime", DataType::UInt16, true),
        Field::new("ndp_reachable_time", DataType::UInt32, true),
        Field::new("ndp_retrans_timer", DataType::UInt32, true),
        // Neighbor Advertisement
        Field::new("ndp_router_flag", DataType::Boolean, true),
        Field::new("ndp_solicited_flag", DataType::Boolean, true),
        Field::new("ndp_override_flag", DataType::Boolean, true),
        // NDP Options - MAC addresses stored as FixedSizeBinary(6)
        Field::new("ndp_source_mac", DataType::FixedSizeBinary(6), true),
        Field::new("ndp_target_mac", DataType::FixedSizeBinary(6), true),
        // IPv6 prefix stored as FixedSizeBinary(16)
        Field::new("ndp_prefix", DataType::FixedSizeBinary(16), true),
        Field::new("ndp_prefix_length", DataType::UInt8, true),
        // MLD - IPv6 multicast address stored as FixedSizeBinary(16)
        Field::new("mld_max_response_delay", DataType::UInt16, true),
        Field::new("mld_multicast_address", DataType::FixedSizeBinary(16), true),
        Field::new("mld_num_group_records", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_schema() {
        let schema = icmpv6_table_schema();

        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("type").is_ok());
        assert!(schema.field_with_name("ndp_target_address").is_ok());
        assert!(schema.field_with_name("mld_multicast_address").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = icmpv6_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("icmpv6."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
