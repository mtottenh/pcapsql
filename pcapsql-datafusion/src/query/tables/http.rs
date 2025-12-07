//! HTTP table schema definition.
//!
//! The `http` table contains HTTP request and response fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `http` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `is_request`: True if this is a request, false if response
/// - `method`: HTTP method (GET, POST, etc.)
/// - `uri`: Request URI
/// - `version`: HTTP version (e.g., "HTTP/1.1")
/// - `status_code`: Response status code (200, 404, etc.)
/// - `status_text`: Response status text
/// - `host`: Host header value
/// - `content_type`: Content-Type header value
/// - `content_length`: Content-Length header value
/// - `user_agent`: User-Agent header value
/// - `server`: Server header value
pub fn http_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("is_request", DataType::Boolean, true),
        Field::new("method", DataType::Utf8, true),
        Field::new("uri", DataType::Utf8, true),
        Field::new("version", DataType::Utf8, true),
        Field::new("status_code", DataType::UInt16, true),
        Field::new("status_text", DataType::Utf8, true),
        Field::new("host", DataType::Utf8, true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::UInt64, true),
        Field::new("user_agent", DataType::Utf8, true),
        Field::new("server", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_schema() {
        let schema = http_table_schema();

        assert_eq!(schema.fields().len(), 12);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("method").is_ok());
        assert!(schema.field_with_name("uri").is_ok());
        assert!(schema.field_with_name("status_code").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = http_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("http."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
