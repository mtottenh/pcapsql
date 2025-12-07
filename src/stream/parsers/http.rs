use std::collections::HashMap;

use arrow::datatypes::{DataType, Field};

use crate::protocol::FieldValue;
use crate::stream::{ParsedMessage, StreamContext, StreamParseResult, StreamParser};

/// HTTP/1.x stream parser.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpStreamParser;

impl HttpStreamParser {
    pub fn new() -> Self {
        Self
    }

    /// Find the end of HTTP headers (\r\n\r\n).
    fn find_header_end(data: &[u8]) -> Option<usize> {
        data.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
    }

    /// Parse HTTP request line: "METHOD URI VERSION\r\n"
    fn parse_request_line(line: &str) -> Option<(String, String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            Some((
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            ))
        } else {
            None
        }
    }

    /// Parse HTTP status line: "VERSION STATUS TEXT\r\n"
    fn parse_status_line(line: &str) -> Option<(String, u16, String)> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            let version = parts[0].to_string();
            let status = parts[1].parse().ok()?;
            let text = parts.get(2).unwrap_or(&"").to_string();
            Some((version, status, text))
        } else {
            None
        }
    }

    /// Parse headers into a map.
    fn parse_headers(header_section: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for line in header_section.lines().skip(1) {
            // Skip first line (request/status)
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }
        headers
    }

    /// Get Content-Length from headers.
    fn get_content_length(headers: &HashMap<String, String>) -> Option<usize> {
        headers.get("content-length").and_then(|v| v.parse().ok())
    }

    /// Check if transfer encoding is chunked.
    fn is_chunked(headers: &HashMap<String, String>) -> bool {
        headers
            .get("transfer-encoding")
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    /// Parse chunked body and return total length.
    fn parse_chunked_body(data: &[u8]) -> Option<usize> {
        let mut pos = 0;

        loop {
            // Find chunk size line
            let chunk_start = pos;
            let line_end = data[pos..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| pos + p)?;

            let size_str = std::str::from_utf8(&data[chunk_start..line_end]).ok()?;
            let chunk_size = usize::from_str_radix(size_str.trim(), 16).ok()?;

            pos = line_end + 2; // Skip \r\n

            if chunk_size == 0 {
                // Final chunk
                if data.len() >= pos + 2 && &data[pos..pos + 2] == b"\r\n" {
                    return Some(pos + 2);
                }
                return None; // Need trailing \r\n
            }

            // Need chunk data + \r\n
            if data.len() < pos + chunk_size + 2 {
                return None;
            }

            pos += chunk_size + 2;
        }
    }
}

impl StreamParser for HttpStreamParser {
    fn name(&self) -> &'static str {
        "http"
    }

    fn display_name(&self) -> &'static str {
        "HTTP"
    }

    fn can_parse_stream(&self, context: &StreamContext) -> bool {
        // Common HTTP ports
        let http_ports = [80, 8080, 8000, 8888, 3000, 5000];
        http_ports.contains(&context.dst_port) || http_ports.contains(&context.src_port)
    }

    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult {
        // Need at least a few bytes to determine message type
        if data.len() < 16 {
            return StreamParseResult::NeedMore {
                minimum_bytes: Some(16),
            };
        }

        // Find end of headers
        let header_end = match Self::find_header_end(data) {
            Some(pos) => pos,
            None => {
                // Headers not complete yet
                return StreamParseResult::NeedMore {
                    minimum_bytes: None,
                };
            }
        };

        // Parse header section
        let header_section = match std::str::from_utf8(&data[..header_end]) {
            Ok(s) => s,
            Err(_) => {
                return StreamParseResult::Error {
                    message: "Invalid UTF-8 in HTTP headers".to_string(),
                    skip_bytes: Some(1),
                };
            }
        };

        let first_line = header_section.lines().next().unwrap_or("");
        let headers = Self::parse_headers(header_section);

        // Determine if request or response
        let is_request = first_line.starts_with("GET ")
            || first_line.starts_with("POST ")
            || first_line.starts_with("PUT ")
            || first_line.starts_with("DELETE ")
            || first_line.starts_with("HEAD ")
            || first_line.starts_with("OPTIONS ")
            || first_line.starts_with("PATCH ")
            || first_line.starts_with("CONNECT ");

        let mut fields = HashMap::new();
        fields.insert("is_request".to_string(), FieldValue::Bool(is_request));

        if is_request {
            // Parse request
            if let Some((method, uri, version)) = Self::parse_request_line(first_line) {
                fields.insert("method".to_string(), FieldValue::String(method));
                fields.insert("uri".to_string(), FieldValue::String(uri));
                fields.insert("http_version".to_string(), FieldValue::String(version));
            }
        } else if first_line.starts_with("HTTP/") {
            // Parse response
            if let Some((version, status, text)) = Self::parse_status_line(first_line) {
                fields.insert("http_version".to_string(), FieldValue::String(version));
                fields.insert("status_code".to_string(), FieldValue::UInt16(status));
                fields.insert("status_text".to_string(), FieldValue::String(text));
            }
        } else {
            return StreamParseResult::NotThisProtocol;
        }

        // Add common headers
        if let Some(host) = headers.get("host") {
            fields.insert("host".to_string(), FieldValue::String(host.clone()));
        }
        if let Some(ct) = headers.get("content-type") {
            fields.insert("content_type".to_string(), FieldValue::String(ct.clone()));
        }
        if let Some(ua) = headers.get("user-agent") {
            fields.insert("user_agent".to_string(), FieldValue::String(ua.clone()));
        }
        if let Some(server) = headers.get("server") {
            fields.insert("server".to_string(), FieldValue::String(server.clone()));
        }

        // Calculate total message length
        let body_start = header_end;
        let body_length = if Self::is_chunked(&headers) {
            // Chunked transfer encoding
            match Self::parse_chunked_body(&data[body_start..]) {
                Some(len) => len,
                None => {
                    return StreamParseResult::NeedMore {
                        minimum_bytes: None,
                    }
                }
            }
        } else if let Some(content_length) = Self::get_content_length(&headers) {
            fields.insert(
                "content_length".to_string(),
                FieldValue::UInt64(content_length as u64),
            );
            let needed = body_start + content_length;
            if data.len() < needed {
                return StreamParseResult::NeedMore {
                    minimum_bytes: Some(needed),
                };
            }
            content_length
        } else {
            // No body (or connection-close semantics)
            0
        };

        let total_length = body_start + body_length;

        let message = ParsedMessage {
            protocol: "http",
            connection_id: context.connection_id,
            message_id: context.messages_parsed as u32,
            direction: context.direction,
            frame_number: 0, // Set by caller
            fields,
        };

        StreamParseResult::Complete {
            messages: vec![message],
            bytes_consumed: total_length,
        }
    }

    fn message_schema(&self) -> Vec<Field> {
        vec![
            Field::new("connection_id", DataType::UInt64, false),
            Field::new("message_id", DataType::UInt32, false),
            Field::new("direction", DataType::Utf8, true),
            Field::new("is_request", DataType::Boolean, true),
            Field::new("method", DataType::Utf8, true),
            Field::new("uri", DataType::Utf8, true),
            Field::new("http_version", DataType::Utf8, true),
            Field::new("status_code", DataType::UInt16, true),
            Field::new("status_text", DataType::Utf8, true),
            Field::new("host", DataType::Utf8, true),
            Field::new("content_type", DataType::Utf8, true),
            Field::new("content_length", DataType::UInt64, true),
            Field::new("user_agent", DataType::Utf8, true),
            Field::new("server", DataType::Utf8, true),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::Direction;
    use std::net::Ipv4Addr;

    fn test_context() -> StreamContext {
        StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 54321,
            dst_port: 80,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        }
    }

    // Test 1: Simple GET request
    #[test]
    fn test_simple_get_request() {
        let parser = HttpStreamParser::new();
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = parser.parse_stream(data, &test_context());

        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(bytes_consumed, data.len());
                assert_eq!(messages.len(), 1);
                let msg = &messages[0];
                assert_eq!(
                    msg.fields.get("method"),
                    Some(&FieldValue::String("GET".to_string()))
                );
                assert_eq!(
                    msg.fields.get("uri"),
                    Some(&FieldValue::String("/index.html".to_string()))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 2: POST request with body
    #[test]
    fn test_post_with_body() {
        let parser = HttpStreamParser::new();
        let body = r#"{"key": "value"}"#;
        let request = format!(
            "POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let result = parser.parse_stream(request.as_bytes(), &test_context());

        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(bytes_consumed, request.len());
                assert_eq!(
                    messages[0].fields.get("method"),
                    Some(&FieldValue::String("POST".to_string()))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 3: HTTP response with Content-Length
    #[test]
    fn test_response_with_content_length() {
        let parser = HttpStreamParser::new();
        let body = "<html>Hello</html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
            body.len(),
            body
        );

        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        let result = parser.parse_stream(response.as_bytes(), &ctx);

        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(
                    messages[0].fields.get("status_code"),
                    Some(&FieldValue::UInt16(200))
                );
                assert_eq!(
                    messages[0].fields.get("is_request"),
                    Some(&FieldValue::Bool(false))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 4: Chunked transfer encoding
    #[test]
    fn test_chunked_encoding() {
        let parser = HttpStreamParser::new();
        let response =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";

        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        let result = parser.parse_stream(response.as_bytes(), &ctx);

        match result {
            StreamParseResult::Complete { bytes_consumed, .. } => {
                assert_eq!(bytes_consumed, response.len());
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 5: HTTP keep-alive (multiple messages)
    #[test]
    fn test_keepalive_multiple_requests() {
        let parser = HttpStreamParser::new();
        let requests = "GET /page1 HTTP/1.1\r\nHost: example.com\r\n\r\nGET /page2 HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // First request
        let result = parser.parse_stream(requests.as_bytes(), &test_context());
        match result {
            StreamParseResult::Complete {
                messages,
                bytes_consumed,
            } => {
                assert_eq!(
                    messages[0].fields.get("uri"),
                    Some(&FieldValue::String("/page1".to_string()))
                );

                // Second request (remaining bytes)
                let result2 =
                    parser.parse_stream(&requests.as_bytes()[bytes_consumed..], &test_context());
                match result2 {
                    StreamParseResult::Complete { messages: msgs2, .. } => {
                        assert_eq!(
                            msgs2[0].fields.get("uri"),
                            Some(&FieldValue::String("/page2".to_string()))
                        );
                    }
                    _ => panic!("Expected Complete for second request"),
                }
            }
            _ => panic!("Expected Complete"),
        }
    }

    // Test 6: Incomplete header (NeedMore)
    #[test]
    fn test_incomplete_header() {
        let parser = HttpStreamParser::new();
        let partial = b"GET /index.html HTTP/1.1\r\nHost: exam";

        let result = parser.parse_stream(partial, &test_context());

        match result {
            StreamParseResult::NeedMore { .. } => {}
            _ => panic!("Expected NeedMore"),
        }
    }

    // Test 7: Incomplete body (NeedMore)
    #[test]
    fn test_incomplete_body() {
        let parser = HttpStreamParser::new();
        let partial = "POST /api HTTP/1.1\r\nContent-Length: 100\r\n\r\npartial";

        let result = parser.parse_stream(partial.as_bytes(), &test_context());

        match result {
            StreamParseResult::NeedMore { minimum_bytes } => {
                // Should need headers + 100 bytes
                assert!(minimum_bytes.is_some());
            }
            _ => panic!("Expected NeedMore"),
        }
    }

    // Test 8: Malformed request
    #[test]
    fn test_not_http() {
        let parser = HttpStreamParser::new();
        let garbage = b"\x00\x01\x02\x03not http at all\r\n\r\n";

        let result = parser.parse_stream(garbage, &test_context());

        match result {
            StreamParseResult::NotThisProtocol | StreamParseResult::Error { .. } => {}
            _ => panic!("Expected NotThisProtocol or Error"),
        }
    }
}
