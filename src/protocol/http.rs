//! HTTP protocol parser.
//!
//! Parses HTTP requests and responses. Matches on common HTTP ports or
//! by detecting HTTP method/response signatures in the data.
//!
//! Note: Without TCP reassembly, this parser can only handle single-packet
//! HTTP requests/responses.

use std::collections::HashMap;

use arrow::datatypes::{DataType, Field};

use super::{FieldValue, ParseContext, ParseResult, Protocol};

/// Common HTTP ports.
const HTTP_PORTS: [u16; 4] = [80, 8080, 8000, 8888];

/// HTTP methods.
const HTTP_METHODS: [&str; 8] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
];

/// HTTP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct HttpProtocol;

impl Protocol for HttpProtocol {
    fn name(&self) -> &'static str {
        "http"
    }

    fn display_name(&self) -> &'static str {
        "HTTP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        let src_port = context.hint("src_port").map(|p| p as u16);
        let dst_port = context.hint("dst_port").map(|p| p as u16);

        // Check for HTTP ports
        let port_match = src_port.map_or(false, |p| HTTP_PORTS.contains(&p))
            || dst_port.map_or(false, |p| HTTP_PORTS.contains(&p));

        if port_match {
            return Some(50); // Lower priority than signature-based detection
        }

        None
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        if data.is_empty() {
            return ParseResult::error("Empty HTTP data".to_string(), data);
        }

        let mut fields = HashMap::new();

        // Try to parse as text
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                return ParseResult::error("HTTP data is not valid UTF-8".to_string(), data);
            }
        };

        // Try to parse the first line
        let first_line = text.lines().next().unwrap_or("");

        // Determine if this is a request or response
        if is_http_request(first_line) {
            fields.insert("is_request", FieldValue::Bool(true));
            parse_http_request(first_line, text, &mut fields);
        } else if is_http_response(first_line) {
            fields.insert("is_request", FieldValue::Bool(false));
            parse_http_response(first_line, text, &mut fields);
        } else {
            return ParseResult::error(
                "Not a valid HTTP request or response".to_string(),
                data,
            );
        }

        // Parse common headers
        parse_http_headers(text, &mut fields);

        ParseResult::success(fields, &[], HashMap::new())
    }

    fn schema_fields(&self) -> Vec<Field> {
        vec![
            // Request/Response indicator
            Field::new("http.is_request", DataType::Boolean, true),
            // Request fields
            Field::new("http.method", DataType::Utf8, true),
            Field::new("http.uri", DataType::Utf8, true),
            Field::new("http.version", DataType::Utf8, true),
            // Response fields
            Field::new("http.status_code", DataType::UInt16, true),
            Field::new("http.status_text", DataType::Utf8, true),
            // Common headers
            Field::new("http.host", DataType::Utf8, true),
            Field::new("http.content_type", DataType::Utf8, true),
            Field::new("http.content_length", DataType::UInt64, true),
            Field::new("http.user_agent", DataType::Utf8, true),
            Field::new("http.server", DataType::Utf8, true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }
}

/// Check if the first line is an HTTP request.
fn is_http_request(line: &str) -> bool {
    for method in HTTP_METHODS {
        if line.starts_with(method) && line.contains("HTTP/") {
            return true;
        }
    }
    false
}

/// Check if the first line is an HTTP response.
fn is_http_response(line: &str) -> bool {
    line.starts_with("HTTP/1.0") || line.starts_with("HTTP/1.1") || line.starts_with("HTTP/2")
}

/// Parse an HTTP request line.
fn parse_http_request(first_line: &str, _text: &str, fields: &mut HashMap<&'static str, FieldValue>) {
    // Format: METHOD URI HTTP/VERSION
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();

    if parts.len() >= 1 {
        fields.insert("method", FieldValue::String(parts[0].to_string()));
    }

    if parts.len() >= 2 {
        fields.insert("uri", FieldValue::String(parts[1].to_string()));
    }

    if parts.len() >= 3 {
        // Extract version (remove trailing \r if present)
        let version = parts[2].trim_end();
        fields.insert("version", FieldValue::String(version.to_string()));
    }
}

/// Parse an HTTP response line.
fn parse_http_response(first_line: &str, _text: &str, fields: &mut HashMap<&'static str, FieldValue>) {
    // Format: HTTP/VERSION STATUS_CODE STATUS_TEXT
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();

    if parts.len() >= 1 {
        fields.insert("version", FieldValue::String(parts[0].to_string()));
    }

    if parts.len() >= 2 {
        if let Ok(code) = parts[1].parse::<u16>() {
            fields.insert("status_code", FieldValue::UInt16(code));
        }
    }

    if parts.len() >= 3 {
        let status_text = parts[2].trim_end();
        fields.insert("status_text", FieldValue::String(status_text.to_string()));
    }
}

/// Parse HTTP headers and extract common ones.
fn parse_http_headers(text: &str, fields: &mut HashMap<&'static str, FieldValue>) {
    for line in text.lines().skip(1) {
        // Empty line indicates end of headers
        if line.trim().is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name_lower = name.trim().to_lowercase();
            let value = value.trim();

            match name_lower.as_str() {
                "host" => {
                    fields.insert("host", FieldValue::String(value.to_string()));
                }
                "content-type" => {
                    fields.insert("content_type", FieldValue::String(value.to_string()));
                }
                "content-length" => {
                    if let Ok(len) = value.parse::<u64>() {
                        fields.insert("content_length", FieldValue::UInt64(len));
                    }
                }
                "user-agent" => {
                    fields.insert("user_agent", FieldValue::String(value.to_string()));
                }
                "server" => {
                    fields.insert("server", FieldValue::String(value.to_string()));
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_http_get_request() -> Vec<u8> {
        let request = "GET /index.html HTTP/1.1\r\n\
            Host: www.example.com\r\n\
            User-Agent: Mozilla/5.0\r\n\
            Accept: text/html\r\n\
            \r\n";
        request.as_bytes().to_vec()
    }

    fn create_http_post_request() -> Vec<u8> {
        let request = "POST /api/submit HTTP/1.1\r\n\
            Host: api.example.com\r\n\
            Content-Type: application/json\r\n\
            Content-Length: 27\r\n\
            \r\n\
            {\"name\": \"test\", \"value\": 1}";
        request.as_bytes().to_vec()
    }

    fn create_http_response_200() -> Vec<u8> {
        let response = "HTTP/1.1 200 OK\r\n\
            Server: nginx/1.18.0\r\n\
            Content-Type: text/html\r\n\
            Content-Length: 1234\r\n\
            \r\n\
            <html>...</html>";
        response.as_bytes().to_vec()
    }

    fn create_http_response_404() -> Vec<u8> {
        let response = "HTTP/1.1 404 Not Found\r\n\
            Server: Apache/2.4\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <html>Not Found</html>";
        response.as_bytes().to_vec()
    }

    #[test]
    fn test_can_parse_http_by_port() {
        let parser = HttpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With dst_port 80
        let mut ctx2 = ParseContext::new(1);
        ctx2.hints.insert("dst_port", 80);
        assert!(parser.can_parse(&ctx2).is_some());

        // With dst_port 8080
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("dst_port", 8080);
        assert!(parser.can_parse(&ctx3).is_some());

        // With src_port 80 (response)
        let mut ctx4 = ParseContext::new(1);
        ctx4.hints.insert("src_port", 80);
        assert!(parser.can_parse(&ctx4).is_some());
    }

    #[test]
    fn test_parse_http_get_request() {
        let packet = create_http_get_request();

        let parser = HttpProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 80);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("method"),
            Some(&FieldValue::String("GET".to_string()))
        );
        assert_eq!(
            result.get("uri"),
            Some(&FieldValue::String("/index.html".to_string()))
        );
        assert_eq!(
            result.get("version"),
            Some(&FieldValue::String("HTTP/1.1".to_string()))
        );
        assert_eq!(
            result.get("host"),
            Some(&FieldValue::String("www.example.com".to_string()))
        );
        assert_eq!(
            result.get("user_agent"),
            Some(&FieldValue::String("Mozilla/5.0".to_string()))
        );
    }

    #[test]
    fn test_parse_http_post_request() {
        let packet = create_http_post_request();

        let parser = HttpProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("dst_port", 80);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("method"),
            Some(&FieldValue::String("POST".to_string()))
        );
        assert_eq!(
            result.get("uri"),
            Some(&FieldValue::String("/api/submit".to_string()))
        );
        assert_eq!(
            result.get("content_type"),
            Some(&FieldValue::String("application/json".to_string()))
        );
        assert_eq!(result.get("content_length"), Some(&FieldValue::UInt64(27)));
    }

    #[test]
    fn test_parse_http_response_200() {
        let packet = create_http_response_200();

        let parser = HttpProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("src_port", 80);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(false)));
        assert_eq!(result.get("status_code"), Some(&FieldValue::UInt16(200)));
        assert_eq!(
            result.get("status_text"),
            Some(&FieldValue::String("OK".to_string()))
        );
        assert_eq!(
            result.get("server"),
            Some(&FieldValue::String("nginx/1.18.0".to_string()))
        );
        assert_eq!(
            result.get("content_length"),
            Some(&FieldValue::UInt64(1234))
        );
    }

    #[test]
    fn test_parse_http_response_404() {
        let packet = create_http_response_404();

        let parser = HttpProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("src_port", 80);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("status_code"), Some(&FieldValue::UInt16(404)));
        assert_eq!(
            result.get("status_text"),
            Some(&FieldValue::String("Not Found".to_string()))
        );
    }

    #[test]
    fn test_parse_http_headers() {
        let packet = create_http_get_request();

        let parser = HttpProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert!(result.get("host").is_some());
        assert!(result.get("user_agent").is_some());
    }

    #[test]
    fn test_http_schema_fields() {
        let parser = HttpProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name().as_str()).collect();
        assert!(field_names.contains(&"http.is_request"));
        assert!(field_names.contains(&"http.method"));
        assert!(field_names.contains(&"http.uri"));
        assert!(field_names.contains(&"http.status_code"));
        assert!(field_names.contains(&"http.host"));
    }

    #[test]
    fn test_http_empty_data() {
        let parser = HttpProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&[], &context);

        assert!(!result.is_ok());
    }

    #[test]
    fn test_http_non_http_data() {
        let parser = HttpProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(b"This is not HTTP", &context);

        assert!(!result.is_ok());
    }

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request("GET / HTTP/1.1"));
        assert!(is_http_request("POST /api HTTP/1.0"));
        assert!(is_http_request("PUT /resource HTTP/1.1"));
        assert!(is_http_request("DELETE /item/1 HTTP/1.1"));
        assert!(!is_http_request("HTTP/1.1 200 OK"));
        assert!(!is_http_request("Hello World"));
    }

    #[test]
    fn test_is_http_response() {
        assert!(is_http_response("HTTP/1.1 200 OK"));
        assert!(is_http_response("HTTP/1.0 404 Not Found"));
        assert!(is_http_response("HTTP/2 200 OK"));
        assert!(!is_http_response("GET / HTTP/1.1"));
        assert!(!is_http_response("Hello World"));
    }
}
