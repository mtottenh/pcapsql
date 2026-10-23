//! Linux SLL2 table schema definition.
//!
//! The `sll2` table contains second-generation Linux cooked capture header
//! fields (LINKTYPE_LINUX_SLL2 = 276), the default link type for
//! `tcpdump -i any` with libpcap >= 1.10.
//!
//! ## Usage
//!
//! ```sql
//! SELECT interface_index, count(*) FROM sll2 GROUP BY interface_index;
//! SELECT * FROM sll2 WHERE packet_type_name = 'OUTGOING';
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `sll2` table.
///
/// Fields match the SLL2 protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
/// - `protocol`: Protocol type (ethertype or netlink family)
/// - `interface_index`: Index of the interface the packet was captured on
/// - `arphrd_type`: ARPHRD link layer type
/// - `arphrd_name`: Human-readable ARPHRD type name
/// - `packet_type`: Packet type (0=host, 1=broadcast, 2=multicast, 3=otherhost, 4=outgoing)
/// - `packet_type_name`: Human-readable packet type name
/// - `addr_len`: Link layer address length
/// - `addr`: Link layer address (up to 8 bytes)
pub fn sll2_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("protocol", DataType::UInt16, true),
        Field::new("interface_index", DataType::UInt32, true),
        Field::new("arphrd_type", DataType::UInt16, true),
        Field::new("arphrd_name", DataType::Utf8, true),
        Field::new("packet_type", DataType::UInt8, true),
        Field::new("packet_type_name", DataType::Utf8, true),
        Field::new("addr_len", DataType::UInt8, true),
        Field::new("addr", DataType::Binary, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sll2_schema() {
        let schema = sll2_table_schema();
        assert_eq!(schema.fields().len(), 9);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("interface_index").is_ok());
        assert!(schema.field_with_name("packet_type").is_ok());
        assert!(schema.field_with_name("protocol").is_ok());
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("sll2."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
