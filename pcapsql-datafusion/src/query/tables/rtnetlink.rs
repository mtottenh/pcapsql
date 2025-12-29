//! RTNetlink table schema definition.
//!
//! The `rtnetlink` table contains Linux routing netlink message fields.
//!
//! ## Usage
//!
//! ```sql
//! SELECT * FROM rtnetlink WHERE msg_type_name = 'RTM_NEWLINK';
//! SELECT if_name, mtu FROM rtnetlink WHERE link_index IS NOT NULL;
//! SELECT address, prefix_len FROM rtnetlink WHERE msg_type_name = 'RTM_NEWADDR';
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `rtnetlink` table.
///
/// Fields match the RTNetlink protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
///
/// Common fields:
/// - `msg_type`: RTNetlink message type
/// - `msg_type_name`: Human-readable message type name
///
/// Link message fields:
/// - `link_index`: Interface index
/// - `link_type`: Link layer type
/// - `link_flags`: Link flags
/// - `if_name`: Interface name
/// - `mtu`: Maximum transmission unit
/// - `hw_addr`: Hardware address (MAC)
///
/// Address message fields:
/// - `addr_family`: Address family number
/// - `addr_family_name`: Human-readable address family name
/// - `prefix_len`: Network prefix length
/// - `addr_index`: Interface index for address
/// - `address`: IP address
/// - `local_addr`: Local IP address
///
/// Route message fields:
/// - `route_family`: Route address family
/// - `dst_prefix_len`: Destination prefix length
/// - `src_prefix_len`: Source prefix length
/// - `route_table`: Routing table ID
/// - `route_protocol`: Route origin protocol
/// - `route_scope`: Route scope
/// - `route_type`: Route type
/// - `destination`: Destination address
/// - `gateway`: Gateway address
/// - `oif_index`: Output interface index
pub fn rtnetlink_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        // Common fields
        Field::new("msg_type", DataType::UInt16, true),
        Field::new("msg_type_name", DataType::Utf8, true),
        // Link message fields
        Field::new("link_index", DataType::UInt32, true),
        Field::new("link_type", DataType::UInt16, true),
        Field::new("link_flags", DataType::UInt32, true),
        Field::new("if_name", DataType::Utf8, true),
        Field::new("mtu", DataType::UInt32, true),
        Field::new("hw_addr", DataType::Binary, true),
        // Address message fields
        Field::new("addr_family", DataType::UInt8, true),
        Field::new("addr_family_name", DataType::Utf8, true),
        Field::new("prefix_len", DataType::UInt8, true),
        Field::new("addr_index", DataType::UInt32, true),
        Field::new("address", DataType::Utf8, true),
        Field::new("local_addr", DataType::Utf8, true),
        // Route message fields
        Field::new("route_family", DataType::UInt8, true),
        Field::new("dst_prefix_len", DataType::UInt8, true),
        Field::new("src_prefix_len", DataType::UInt8, true),
        Field::new("route_table", DataType::UInt8, true),
        Field::new("route_protocol", DataType::UInt8, true),
        Field::new("route_scope", DataType::UInt8, true),
        Field::new("route_type", DataType::UInt8, true),
        Field::new("destination", DataType::Utf8, true),
        Field::new("gateway", DataType::Utf8, true),
        Field::new("oif_index", DataType::UInt32, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtnetlink_schema() {
        let schema = rtnetlink_table_schema();

        assert_eq!(schema.fields().len(), 25);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("msg_type").is_ok());
        assert!(schema.field_with_name("msg_type_name").is_ok());
        assert!(schema.field_with_name("link_index").is_ok());
        assert!(schema.field_with_name("if_name").is_ok());
        assert!(schema.field_with_name("address").is_ok());
        assert!(schema.field_with_name("gateway").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = rtnetlink_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("rtnetlink."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
