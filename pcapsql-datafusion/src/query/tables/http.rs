//! HTTP table schema definition.
//!
//! The `http` table contains HTTP request and response fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `http` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `is_request`: True if this is a request, false if response
/// - `headers_complete`: True if all headers were parsed
/// - `method`: HTTP method (GET, POST, etc.)
/// - `uri`: Request URI
/// - `version`: HTTP version (e.g., "HTTP/1.1")
/// - `status_code`: Response status code (200, 404, etc.)
/// - `status_text`: Response status text
/// - `body_length`: Actual body bytes seen
/// - `host`: Host header value
/// - `content_type`: Content-Type header value
/// - `content_length`: Content-Length header value
/// - `user_agent`: User-Agent header value
/// - `server`: Server header value
/// - `transfer_encoding`: Transfer-Encoding header value
/// - `connection`: Connection header value
/// - `cookie`: Cookie header value
/// - `set_cookie`: Set-Cookie header value
/// - `referer`: Referer header value
/// - `accept`: Accept header value
/// - `accept_encoding`: Accept-Encoding header value
/// - `accept_language`: Accept-Language header value
/// - `cache_control`: Cache-Control header value
/// - `authorization`: Authorization type (e.g., "Bearer", "Basic")
/// - `location`: Location header value (for redirects)
/// - `x_forwarded_for`: X-Forwarded-For header value
/// - `x_real_ip`: X-Real-IP header value
pub fn http_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("is_request", DataType::Boolean, true),
        Field::new("headers_complete", DataType::Boolean, true),
        Field::new("method", DataType::Utf8, true),
        Field::new("uri", DataType::Utf8, true),
        Field::new("version", DataType::Utf8, true),
        Field::new("status_code", DataType::UInt16, true),
        Field::new("status_text", DataType::Utf8, true),
        Field::new("body_length", DataType::UInt64, true),
        Field::new("host", DataType::Utf8, true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("content_length", DataType::UInt64, true),
        Field::new("user_agent", DataType::Utf8, true),
        Field::new("server", DataType::Utf8, true),
        Field::new("transfer_encoding", DataType::Utf8, true),
        Field::new("connection", DataType::Utf8, true),
        Field::new("cookie", DataType::Utf8, true),
        Field::new("set_cookie", DataType::Utf8, true),
        Field::new("referer", DataType::Utf8, true),
        Field::new("accept", DataType::Utf8, true),
        Field::new("accept_encoding", DataType::Utf8, true),
        Field::new("accept_language", DataType::Utf8, true),
        Field::new("cache_control", DataType::Utf8, true),
        Field::new("authorization", DataType::Utf8, true),
        Field::new("location", DataType::Utf8, true),
        Field::new("x_forwarded_for", DataType::Utf8, true),
        Field::new("x_real_ip", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_schema() {
        let schema = http_table_schema();

        assert_eq!(schema.fields().len(), 27);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("method").is_ok());
        assert!(schema.field_with_name("uri").is_ok());
        assert!(schema.field_with_name("status_code").is_ok());
        assert!(schema.field_with_name("headers_complete").is_ok());
        assert!(schema.field_with_name("transfer_encoding").is_ok());
        assert!(schema.field_with_name("cookie").is_ok());
        assert!(schema.field_with_name("authorization").is_ok());
        assert!(schema.field_with_name("location").is_ok());
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
