//! HTTP/1.x stream parser using httparse for zero-copy parsing.
//!
//! This parser handles HTTP messages that span multiple TCP packets through
//! stream reassembly. It supports:
//! - HTTP/1.0 and HTTP/1.1 requests and responses
//! - Chunked transfer encoding
//! - Content-Length based body parsing
//! - Keep-alive connections with multiple messages per stream

use std::collections::HashMap;

use compact_str::CompactString;
use httparse::{Request, Response, Status, EMPTY_HEADER};

use crate::protocol::FieldValue;
use crate::schema::{DataKind, FieldDescriptor};
use crate::stream::{ParsedMessage, StreamContext, StreamParseResult, StreamParser};

/// Maximum number of headers to parse per message.
const MAX_HEADERS: usize = 100;

/// HTTP/1.x stream parser.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpStreamParser;

impl HttpStreamParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract headers from httparse header array into fields map.
    fn extract_headers(headers: &[httparse::Header], fields: &mut HashMap<String, FieldValue>) {
        for header in headers.iter().filter(|h| !h.name.is_empty()) {
            let name_lower = header.name.to_ascii_lowercase();
            let value = String::from_utf8_lossy(header.value).to_string();

            match name_lower.as_str() {
                "host" => {
                    fields.insert("host".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "content-type" => {
                    fields.insert("content_type".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "content-length" => {
                    if let Ok(len) = value.parse::<u64>() {
                        fields.insert("content_length".to_string(), FieldValue::UInt64(len));
                    }
                }
                "user-agent" => {
                    fields.insert("user_agent".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "server" => {
                    fields.insert("server".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "transfer-encoding" => {
                    fields.insert("transfer_encoding".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "connection" => {
                    fields.insert("connection".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "cookie" => {
                    fields.insert("cookie".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "set-cookie" => {
                    fields
                        .entry("set_cookie".to_string())
                        .or_insert(FieldValue::OwnedString(CompactString::new(value)));
                }
                "referer" | "referrer" => {
                    fields.insert("referer".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "accept" => {
                    fields.insert("accept".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "accept-encoding" => {
                    fields.insert("accept_encoding".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "accept-language" => {
                    fields.insert("accept_language".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "cache-control" => {
                    fields.insert("cache_control".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "authorization" => {
                    // Store auth type only for security
                    let auth_type = value.split_whitespace().next().unwrap_or(&value);
                    fields.insert("authorization".to_string(), FieldValue::OwnedString(CompactString::new(auth_type)));
                }
                "location" => {
                    fields.insert("location".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "x-forwarded-for" => {
                    fields.insert("x_forwarded_for".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                "x-real-ip" => {
                    fields.insert("x_real_ip".to_string(), FieldValue::OwnedString(CompactString::new(value)));
                }
                _ => {}
            }
        }
    }

    /// Check if transfer encoding is chunked.
    fn is_chunked(fields: &HashMap<String, FieldValue>) -> bool {
        fields
            .get("transfer_encoding")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    /// Get Content-Length from fields.
    fn get_content_length(fields: &HashMap<String, FieldValue>) -> Option<usize> {
        fields.get("content_length").and_then(|v| {
            if let FieldValue::UInt64(len) = v {
                Some(*len as usize)
            } else {
                None
            }
        })
    }

    /// Parse chunked body and return total length consumed.
    fn parse_chunked_body(data: &[u8]) -> Option<usize> {
        let mut pos = 0;

        loop {
            // Find chunk size line ending
            let line_end = data[pos..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| pos + p)?;

            let size_str = std::str::from_utf8(&data[pos..line_end]).ok()?;
            // Handle chunk extensions (anything after semicolon)
            let size_part = size_str.split(';').next().unwrap_or(size_str);
            let chunk_size = usize::from_str_radix(size_part.trim(), 16).ok()?;

            pos = line_end + 2; // Skip \r\n

            if chunk_size == 0 {
                // Final chunk - need trailing \r\n (and optional trailers)
                if data.len() >= pos + 2 && &data[pos..pos + 2] == b"\r\n" {
                    return Some(pos + 2);
                }
                // Might have trailers, look for \r\n\r\n
                if let Some(end) = data[pos..].windows(4).position(|w| w == b"\r\n\r\n") {
                    return Some(pos + end + 4);
                }
                return None; // Need more data
            }

            // Need chunk data + trailing \r\n
            if data.len() < pos + chunk_size + 2 {
                return None;
            }

            // Verify trailing \r\n after chunk data
            if &data[pos + chunk_size..pos + chunk_size + 2] != b"\r\n" {
                return None; // Malformed
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
        const HTTP_PORTS: [u16; 6] = [80, 8080, 8000, 8888, 3000, 5000];
        HTTP_PORTS.contains(&context.dst_port) || HTTP_PORTS.contains(&context.src_port)
    }

    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult {
        // Need at least a few bytes to determine message type
        if data.len() < 16 {
            return StreamParseResult::NeedMore {
                minimum_bytes: Some(16),
            };
        }

        let mut fields = HashMap::new();

        // Try to parse as HTTP request first
        let mut headers = [EMPTY_HEADER; MAX_HEADERS];
        let mut req = Request::new(&mut headers);

        match req.parse(data) {
            Ok(Status::Complete(header_len)) => {
                fields.insert("is_request".to_string(), FieldValue::Bool(true));

                if let Some(method) = req.method {
                    fields.insert("method".to_string(), FieldValue::OwnedString(CompactString::new(method)));
                }

                if let Some(path) = req.path {
                    fields.insert("uri".to_string(), FieldValue::OwnedString(CompactString::new(path)));
                }

                if let Some(version) = req.version {
                    let version_str = format!("HTTP/1.{}", version);
                    fields.insert("http_version".to_string(), FieldValue::OwnedString(CompactString::new(version_str)));
                }

                Self::extract_headers(&headers, &mut fields);

                // Calculate body length
                let body_start = header_len;
                let body_length = if Self::is_chunked(&fields) {
                    match Self::parse_chunked_body(&data[body_start..]) {
                        Some(len) => len,
                        None => {
                            return StreamParseResult::NeedMore {
                                minimum_bytes: None,
                            }
                        }
                    }
                } else if let Some(content_length) = Self::get_content_length(&fields) {
                    let needed = body_start + content_length;
                    if data.len() < needed {
                        return StreamParseResult::NeedMore {
                            minimum_bytes: Some(needed),
                        };
                    }
                    content_length
                } else {
                    // No body for requests without Content-Length or chunked encoding
                    0
                };

                let total_length = body_start + body_length;

                let message = ParsedMessage {
                    protocol: "http",
                    connection_id: context.connection_id,
                    message_id: context.messages_parsed as u32,
                    direction: context.direction,
                    frame_number: 0,
                    fields,
                };

                return StreamParseResult::Complete {
                    messages: vec![message],
                    bytes_consumed: total_length,
                };
            }
            Ok(Status::Partial) => {
                // Headers not complete yet
                return StreamParseResult::NeedMore {
                    minimum_bytes: None,
                };
            }
            Err(_) => {
                // Not a request, try response
            }
        }

        // Try to parse as HTTP response
        let mut headers = [EMPTY_HEADER; MAX_HEADERS];
        let mut resp = Response::new(&mut headers);

        match resp.parse(data) {
            Ok(Status::Complete(header_len)) => {
                fields.insert("is_request".to_string(), FieldValue::Bool(false));

                if let Some(version) = resp.version {
                    let version_str = format!("HTTP/1.{}", version);
                    fields.insert("http_version".to_string(), FieldValue::OwnedString(CompactString::new(version_str)));
                }

                if let Some(code) = resp.code {
                    fields.insert("status_code".to_string(), FieldValue::UInt16(code));
                }

                if let Some(reason) = resp.reason {
                    fields.insert("status_text".to_string(), FieldValue::OwnedString(CompactString::new(reason)));
                }

                Self::extract_headers(&headers, &mut fields);

                // Calculate body length
                let body_start = header_len;
                let body_length = if Self::is_chunked(&fields) {
                    match Self::parse_chunked_body(&data[body_start..]) {
                        Some(len) => len,
                        None => {
                            return StreamParseResult::NeedMore {
                                minimum_bytes: None,
                            }
                        }
                    }
                } else if let Some(content_length) = Self::get_content_length(&fields) {
                    let needed = body_start + content_length;
                    if data.len() < needed {
                        return StreamParseResult::NeedMore {
                            minimum_bytes: Some(needed),
                        };
                    }
                    content_length
                } else {
                    // For responses without Content-Length, this is tricky
                    // In HTTP/1.0, connection close signals end of response
                    // For now, assume no body if neither is present
                    0
                };

                let total_length = body_start + body_length;

                let message = ParsedMessage {
                    protocol: "http",
                    connection_id: context.connection_id,
                    message_id: context.messages_parsed as u32,
                    direction: context.direction,
                    frame_number: 0,
                    fields,
                };

                return StreamParseResult::Complete {
                    messages: vec![message],
                    bytes_consumed: total_length,
                };
            }
            Ok(Status::Partial) => {
                return StreamParseResult::NeedMore {
                    minimum_bytes: None,
                };
            }
            Err(_) => {
                // Check if it looks like HTTP at all
                if data.starts_with(b"GET ")
                    || data.starts_with(b"POST ")
                    || data.starts_with(b"PUT ")
                    || data.starts_with(b"DELETE ")
                    || data.starts_with(b"HEAD ")
                    || data.starts_with(b"OPTIONS ")
                    || data.starts_with(b"PATCH ")
                    || data.starts_with(b"CONNECT ")
                    || data.starts_with(b"HTTP/")
                {
                    // Looks like HTTP but parsing failed - need more data?
                    return StreamParseResult::NeedMore {
                        minimum_bytes: None,
                    };
                }
            }
        }

        // Not HTTP
        StreamParseResult::NotThisProtocol
    }

    fn message_schema(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("connection_id", DataKind::UInt64),
            FieldDescriptor::new("message_id", DataKind::UInt32),
            FieldDescriptor::new("direction", DataKind::String).set_nullable(true),
            FieldDescriptor::new("is_request", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("method", DataKind::String).set_nullable(true),
            FieldDescriptor::new("uri", DataKind::String).set_nullable(true),
            FieldDescriptor::new("http_version", DataKind::String).set_nullable(true),
            FieldDescriptor::new("status_code", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("status_text", DataKind::String).set_nullable(true),
            FieldDescriptor::new("host", DataKind::String).set_nullable(true),
            FieldDescriptor::new("content_type", DataKind::String).set_nullable(true),
            FieldDescriptor::new("content_length", DataKind::UInt64).set_nullable(true),
            FieldDescriptor::new("user_agent", DataKind::String).set_nullable(true),
            FieldDescriptor::new("server", DataKind::String).set_nullable(true),
            FieldDescriptor::new("transfer_encoding", DataKind::String).set_nullable(true),
            FieldDescriptor::new("connection", DataKind::String).set_nullable(true),
            FieldDescriptor::new("cookie", DataKind::String).set_nullable(true),
            FieldDescriptor::new("set_cookie", DataKind::String).set_nullable(true),
            FieldDescriptor::new("referer", DataKind::String).set_nullable(true),
            FieldDescriptor::new("accept", DataKind::String).set_nullable(true),
            FieldDescriptor::new("accept_encoding", DataKind::String).set_nullable(true),
            FieldDescriptor::new("accept_language", DataKind::String).set_nullable(true),
            FieldDescriptor::new("cache_control", DataKind::String).set_nullable(true),
            FieldDescriptor::new("authorization", DataKind::String).set_nullable(true),
            FieldDescriptor::new("location", DataKind::String).set_nullable(true),
            FieldDescriptor::new("x_forwarded_for", DataKind::String).set_nullable(true),
            FieldDescriptor::new("x_real_ip", DataKind::String).set_nullable(true),
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
                    Some(&FieldValue::OwnedString(CompactString::new("GET")))
                );
                assert_eq!(
                    msg.fields.get("uri"),
                    Some(&FieldValue::OwnedString(CompactString::new("/index.html")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

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
                    Some(&FieldValue::OwnedString(CompactString::new("POST")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

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

    #[test]
    fn test_chunked_with_extensions() {
        let parser = HttpStreamParser::new();
        // Chunked encoding with chunk extension (name=value after size)
        let response =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nHello\r\n0\r\n\r\n";

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
                    Some(&FieldValue::OwnedString(CompactString::new("/page1")))
                );

                // Second request (remaining bytes)
                let result2 =
                    parser.parse_stream(&requests.as_bytes()[bytes_consumed..], &test_context());
                match result2 {
                    StreamParseResult::Complete { messages: msgs2, .. } => {
                        assert_eq!(
                            msgs2[0].fields.get("uri"),
                            Some(&FieldValue::OwnedString(CompactString::new("/page2")))
                        );
                    }
                    _ => panic!("Expected Complete for second request"),
                }
            }
            _ => panic!("Expected Complete"),
        }
    }

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

    #[test]
    fn test_not_http() {
        let parser = HttpStreamParser::new();
        let garbage = b"NOTHTTP random garbage data\x00\x01\x02";

        let result = parser.parse_stream(garbage, &test_context());

        match result {
            StreamParseResult::NotThisProtocol => {}
            _ => panic!("Expected NotThisProtocol"),
        }
    }

    #[test]
    fn test_response_with_all_headers() {
        let parser = HttpStreamParser::new();
        let response = "HTTP/1.1 302 Found\r\n\
            Server: nginx/1.18.0\r\n\
            Content-Type: text/html\r\n\
            Content-Length: 0\r\n\
            Location: https://example.com/new\r\n\
            Set-Cookie: session=abc123; HttpOnly\r\n\
            Cache-Control: no-cache\r\n\
            \r\n";

        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        let result = parser.parse_stream(response.as_bytes(), &ctx);

        match result {
            StreamParseResult::Complete { messages, .. } => {
                let msg = &messages[0];
                assert_eq!(
                    msg.fields.get("status_code"),
                    Some(&FieldValue::UInt16(302))
                );
                assert_eq!(
                    msg.fields.get("location"),
                    Some(&FieldValue::OwnedString(CompactString::new("https://example.com/new")))
                );
                assert!(msg.fields.get("set_cookie").is_some());
                assert_eq!(
                    msg.fields.get("cache_control"),
                    Some(&FieldValue::OwnedString(CompactString::new("no-cache")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_request_with_cookie() {
        let parser = HttpStreamParser::new();
        let request = "GET /api HTTP/1.1\r\n\
            Host: api.example.com\r\n\
            Cookie: session=xyz789; user=john\r\n\
            Authorization: Bearer token123\r\n\
            X-Forwarded-For: 10.0.0.1\r\n\
            \r\n";

        let result = parser.parse_stream(request.as_bytes(), &test_context());

        match result {
            StreamParseResult::Complete { messages, .. } => {
                let msg = &messages[0];
                assert_eq!(
                    msg.fields.get("cookie"),
                    Some(&FieldValue::OwnedString(CompactString::new("session=xyz789; user=john")))
                );
                // Auth should only contain the type
                assert_eq!(
                    msg.fields.get("authorization"),
                    Some(&FieldValue::OwnedString(CompactString::new("Bearer")))
                );
                assert_eq!(
                    msg.fields.get("x_forwarded_for"),
                    Some(&FieldValue::OwnedString(CompactString::new("10.0.0.1")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_http10_request() {
        let parser = HttpStreamParser::new();
        let request = "GET / HTTP/1.0\r\n\r\n";

        let result = parser.parse_stream(request.as_bytes(), &test_context());

        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(
                    messages[0].fields.get("http_version"),
                    Some(&FieldValue::OwnedString(CompactString::new("HTTP/1.0")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_head_request() {
        let parser = HttpStreamParser::new();
        let request = "HEAD /status HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = parser.parse_stream(request.as_bytes(), &test_context());

        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(
                    messages[0].fields.get("method"),
                    Some(&FieldValue::OwnedString(CompactString::new("HEAD")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_options_request() {
        let parser = HttpStreamParser::new();
        let request = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = parser.parse_stream(request.as_bytes(), &test_context());

        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(
                    messages[0].fields.get("method"),
                    Some(&FieldValue::OwnedString(CompactString::new("OPTIONS")))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_100_continue_response() {
        let parser = HttpStreamParser::new();
        let response = "HTTP/1.1 100 Continue\r\n\r\n";

        let mut ctx = test_context();
        ctx.direction = Direction::ToClient;

        let result = parser.parse_stream(response.as_bytes(), &ctx);

        match result {
            StreamParseResult::Complete { messages, .. } => {
                assert_eq!(
                    messages[0].fields.get("status_code"),
                    Some(&FieldValue::UInt16(100))
                );
            }
            _ => panic!("Expected Complete"),
        }
    }
}
