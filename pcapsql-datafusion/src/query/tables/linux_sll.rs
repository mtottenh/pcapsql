//! Linux SLL table schema definition.
//!
//! The `linux_sll` table contains Linux cooked capture header fields.
//!
//! ## Usage
//!
//! ```sql
//! SELECT * FROM linux_sll WHERE arphrd_name = 'NETLINK';
//! SELECT * FROM linux_sll WHERE packet_type_name = 'OUTGOING';
//! ```

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `linux_sll` table.
///
/// Fields match the Linux SLL protocol parser output (without prefix):
/// - `frame_number`: Reference to frames table
/// - `packet_type`: Packet type (0=host, 1=broadcast, 2=multicast, 3=otherhost, 4=outgoing)
/// - `packet_type_name`: Human-readable packet type name
/// - `arphrd_type`: ARPHRD link layer type
/// - `arphrd_name`: Human-readable ARPHRD type name
/// - `addr_len`: Link layer address length
/// - `addr`: Link layer address (up to 8 bytes)
/// - `protocol`: Protocol type (ethertype or netlink family)
pub fn linux_sll_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("packet_type", DataType::UInt16, true),
        Field::new("packet_type_name", DataType::Utf8, true),
        Field::new("arphrd_type", DataType::UInt16, true),
        Field::new("arphrd_name", DataType::Utf8, true),
        Field::new("addr_len", DataType::UInt16, true),
        Field::new("addr", DataType::Binary, true),
        Field::new("protocol", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_sll_schema() {
        let schema = linux_sll_table_schema();

        assert_eq!(schema.fields().len(), 8);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("packet_type").is_ok());
        assert!(schema.field_with_name("arphrd_type").is_ok());
        assert!(schema.field_with_name("arphrd_name").is_ok());
        assert!(schema.field_with_name("protocol").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = linux_sll_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("linux_sll."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
