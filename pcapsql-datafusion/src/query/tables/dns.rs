//! DNS table schema definition.
//!
//! The `dns` table contains DNS (Domain Name System) query and response fields.

use arrow::datatypes::{DataType, Field, Schema};

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
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_schema() {
        let schema = dns_table_schema();

        assert_eq!(schema.fields().len(), 16);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("transaction_id").is_ok());
        assert!(schema.field_with_name("query_name").is_ok());
        assert!(schema.field_with_name("is_query").is_ok());
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
}
