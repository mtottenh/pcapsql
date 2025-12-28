//! DNS table schema definition.
//!
//! The `dns` table contains DNS (Domain Name System) query and response fields.

use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

/// Build the schema for the `dns` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `transaction_id`: DNS transaction identifier
/// - `is_query`: True if this is a query, false if response
/// - `opcode`: Operation code
/// - `is_authoritative`: Authoritative answer flag
/// - `is_truncated`: Truncation flag
/// - `recursion_desired`: Recursion desired flag
/// - `recursion_available`: Recursion available flag
/// - `response_code`: Response code (0 = NOERROR, 3 = NXDOMAIN, etc.)
/// - `query_count`: Number of questions
/// - `answer_count`: Number of answer RRs
/// - `authority_count`: Number of authority RRs
/// - `additional_count`: Number of additional RRs
/// - `query_name`: First query domain name
/// - `query_type`: First query type (1 = A, 28 = AAAA, etc.)
/// - `query_class`: First query class (1 = IN)
/// - `answer_ip4s`: List of A record IP addresses (as u32)
/// - `answer_ip6s`: List of AAAA record IP addresses (as 16-byte binary)
/// - `answer_cnames`: List of CNAME record values
/// - `answer_types`: List of answer record types
/// - `answer_ttls`: List of answer TTL values
/// - `has_edns`: Whether EDNS is present
/// - `edns_udp_size`: EDNS UDP payload size
pub fn dns_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("transaction_id", DataType::UInt16, true),
        Field::new("is_query", DataType::Boolean, true),
        Field::new("opcode", DataType::UInt8, true),
        Field::new("is_authoritative", DataType::Boolean, true),
        Field::new("is_truncated", DataType::Boolean, true),
        Field::new("recursion_desired", DataType::Boolean, true),
        Field::new("recursion_available", DataType::Boolean, true),
        Field::new("response_code", DataType::UInt8, true),
        Field::new("query_count", DataType::UInt16, true),
        Field::new("answer_count", DataType::UInt16, true),
        Field::new("authority_count", DataType::UInt16, true),
        Field::new("additional_count", DataType::UInt16, true),
        Field::new("query_name", DataType::Utf8, true),
        Field::new("query_type", DataType::UInt16, true),
        Field::new("query_class", DataType::UInt16, true),
        // New list fields for DNS answers
        Field::new(
            "answer_ip4s",
            DataType::List(Arc::new(Field::new("item", DataType::UInt32, true))),
            true,
        ),
        Field::new(
            "answer_ip6s",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::FixedSizeBinary(16),
                true,
            ))),
            true,
        ),
        Field::new(
            "answer_cnames",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            true,
        ),
        Field::new(
            "answer_types",
            DataType::List(Arc::new(Field::new("item", DataType::UInt16, true))),
            true,
        ),
        Field::new(
            "answer_ttls",
            DataType::List(Arc::new(Field::new("item", DataType::UInt32, true))),
            true,
        ),
        // EDNS fields
        Field::new("has_edns", DataType::Boolean, true),
        Field::new("edns_udp_size", DataType::UInt16, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_schema() {
        let schema = dns_table_schema();

        // 16 original fields + 5 list fields + 2 EDNS fields = 23
        assert_eq!(schema.fields().len(), 23);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("transaction_id").is_ok());
        assert!(schema.field_with_name("query_name").is_ok());
        assert!(schema.field_with_name("is_query").is_ok());
        // New fields
        assert!(schema.field_with_name("answer_ip4s").is_ok());
        assert!(schema.field_with_name("answer_ip6s").is_ok());
        assert!(schema.field_with_name("answer_cnames").is_ok());
        assert!(schema.field_with_name("answer_types").is_ok());
        assert!(schema.field_with_name("answer_ttls").is_ok());
        assert!(schema.field_with_name("has_edns").is_ok());
        assert!(schema.field_with_name("edns_udp_size").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = dns_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("dns."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }

    #[test]
    fn test_list_field_types() {
        let schema = dns_table_schema();

        // Check answer_ip4s is a List<UInt32>
        let ip4s_field = schema.field_with_name("answer_ip4s").unwrap();
        match ip4s_field.data_type() {
            DataType::List(inner) => {
                assert_eq!(inner.data_type(), &DataType::UInt32);
            }
            _ => panic!("answer_ip4s should be a List type"),
        }

        // Check answer_cnames is a List<Utf8>
        let cnames_field = schema.field_with_name("answer_cnames").unwrap();
        match cnames_field.data_type() {
            DataType::List(inner) => {
                assert_eq!(inner.data_type(), &DataType::Utf8);
            }
            _ => panic!("answer_cnames should be a List type"),
        }
    }
}
