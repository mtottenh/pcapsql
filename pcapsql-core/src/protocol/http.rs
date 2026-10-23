//! HTTP/1.x packet parser.
//!
//! Feeds the per-packet `http` table: one row for the TCP segment that
//! *starts* an HTTP/1.x message, carrying the request line or status line
//! and the common headers found in that segment. The parser runs only on a
//! segment whose payload begins with a request method or `HTTP/1.`
//! (the TCP layer sniffs the payload and sets the [`PAYLOAD_HINT`] child
//! hint), so body continuation segments and non-HTTP traffic on HTTP ports
//! produce no `http` rows.
//!
//! Headers that do not fit in the first segment are not seen here:
//! `headers_complete` is `false` for such a message. Reassembly across
//! segments, bodies and keep-alive streams are the stream layer's job
//! (`http_messages`, see `stream::parsers::http`), which shares the header
//! mapping in this module.

use compact_str::CompactString;
use httparse::{Request, Response, Status, EMPTY_HEADER};
use smallvec::SmallVec;

use super::{FieldEntry, FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// Ports on which an HTTP/1.x message start is matched with raised priority.
/// Shared with the stream parser's port check.
pub const HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8888, 3000, 5000];

/// Child hint the TCP layer sets to 1 when its payload starts an HTTP/1.x
/// message (see [`starts_http_message`]). Absent otherwise.
pub const PAYLOAD_HINT: &str = "http_payload";

/// Maximum number of headers extracted from one segment.
const MAX_HEADERS: usize = 100;

/// Request methods recognized at the start of a segment (RFC 9110 §9 plus
/// PATCH), each followed by the space that ends the method token.
const METHOD_TOKENS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// True when `payload` begins with an HTTP/1.x request line or status line.
///
/// A prefix test only: a few byte comparisons per TCP segment.
#[inline]
pub fn starts_http_message(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/1.") || METHOD_TOKENS.iter().any(|m| payload.starts_with(m))
}

/// Header names mapped to `http` columns, as (header, column) pairs.
const HEADER_COLUMNS: &[(&str, &str)] = &[
    ("host", "host"),
    ("content-type", "content_type"),
    ("content-length", "content_length"),
    ("user-agent", "user_agent"),
    ("server", "server"),
    ("transfer-encoding", "transfer_encoding"),
    ("connection", "connection"),
    ("cookie", "cookie"),
    ("set-cookie", "set_cookie"),
    ("referer", "referer"),
    ("referrer", "referer"),
    ("accept", "accept"),
    ("accept-encoding", "accept_encoding"),
    ("accept-language", "accept_language"),
    ("cache-control", "cache_control"),
    ("authorization", "authorization"),
    ("location", "location"),
    ("x-forwarded-for", "x_forwarded_for"),
    ("x-real-ip", "x_real_ip"),
];

/// Map one header to its `http` column and value, or `None` for a header
/// that has no column.
///
/// Values are zero-copy when valid UTF-8. `Content-Length` becomes a
/// `UInt64` (an unparsable value yields no field). `Authorization` keeps
/// only the scheme (`Bearer`, `Basic`), never the credentials.
pub(crate) fn header_field<'a>(name: &str, value: &'a [u8]) -> Option<FieldEntry<'a>> {
    let column = HEADER_COLUMNS
        .iter()
        .find(|(header, _)| name.eq_ignore_ascii_case(header))
        .map(|(_, column)| *column)?;

    let value = match column {
        "content_length" => {
            let text = std::str::from_utf8(value).ok()?;
            return text
                .trim()
                .parse::<u64>()
                .ok()
                .map(|len| (column, FieldValue::UInt64(len)));
        }
        "authorization" => match std::str::from_utf8(value) {
            Ok(text) => FieldValue::Str(text.split_whitespace().next().unwrap_or(text)),
            Err(_) => {
                let lossy = String::from_utf8_lossy(value);
                let scheme = lossy.split_whitespace().next().unwrap_or(&lossy);
                FieldValue::OwnedString(CompactString::new(scheme))
            }
        },
        _ => text_value(value),
    };
    Some((column, value))
}

/// A header value as a string field: borrowed when valid UTF-8.
fn text_value(value: &[u8]) -> FieldValue<'_> {
    match std::str::from_utf8(value) {
        Ok(text) => FieldValue::Str(text),
        Err(_) => FieldValue::OwnedString(CompactString::from(String::from_utf8_lossy(value))),
    }
}

/// HTTP/1.x packet parser (see the module documentation).
#[derive(Debug, Clone, Copy)]
pub struct HttpProtocol;

type Fields<'a> = SmallVec<[FieldEntry<'a>; 16]>;

/// Push a field unless the column is already set: the first occurrence of
/// a repeated header wins (a row has one value per column).
fn push_unique<'a>(fields: &mut Fields<'a>, entry: FieldEntry<'a>) {
    if !fields.iter().any(|(name, _)| *name == entry.0) {
        fields.push(entry);
    }
}

/// Add the headers found so far (`EMPTY_HEADER` entries are unparsed).
fn push_headers<'a>(fields: &mut Fields<'a>, headers: &[httparse::Header<'a>]) {
    for header in headers.iter().filter(|h| !h.name.is_empty()) {
        if let Some(entry) = header_field(header.name, header.value) {
            push_unique(fields, entry);
        }
    }
}

/// The `version` column for an httparse minor version.
fn version_str(minor: u8) -> &'static str {
    if minor == 0 {
        "HTTP/1.0"
    } else {
        "HTTP/1.1"
    }
}

/// Finish a message start: `headers_complete`, the headers seen, and the
/// payload bytes after the header block when it is complete.
///
/// On a parse error after part of the start line was read (a malformed
/// header, too many headers, a bad status line) the fields in hand are
/// kept with `headers_complete = false` alongside the error; only a start
/// line that yielded nothing is a fields-less error row.
fn finish<'a>(
    mut fields: Fields<'a>,
    status: Result<Status<usize>, httparse::Error>,
    headers: &[httparse::Header<'a>],
    data: &'a [u8],
    kind: &str,
) -> ParseResult<'a> {
    let status = match status {
        Ok(status) => status,
        Err(e) => {
            let error = format!("HTTP {kind} parse error: {e}");
            // `is_request` alone means nothing of the start line was read.
            if fields.len() <= 1 {
                return ParseResult::error(error, data);
            }
            fields.push(("headers_complete", FieldValue::Bool(false)));
            push_headers(&mut fields, headers);
            return ParseResult::partial(fields, &data[data.len()..], error);
        }
    };
    let complete = matches!(status, Status::Complete(_));
    fields.push(("headers_complete", FieldValue::Bool(complete)));
    push_headers(&mut fields, headers);
    if let Status::Complete(header_len) = status {
        fields.push((
            "body_length",
            FieldValue::UInt64(data.len().saturating_sub(header_len) as u64),
        ));
    }
    // Terminal layer: the body is not parsed further.
    ParseResult::success(fields, &data[data.len()..], SmallVec::new())
}

fn parse_request(data: &[u8]) -> ParseResult<'_> {
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut req = Request::new(&mut headers);
    let status = req.parse(data);
    // The request line is filled in as far as it was parsed, even when the
    // header block is incomplete or malformed.
    let (method, path, version) = (req.method, req.path, req.version);

    let mut fields = Fields::new();
    fields.push(("is_request", FieldValue::Bool(true)));
    if let Some(method) = method {
        fields.push(("method", FieldValue::Str(method)));
    }
    if let Some(path) = path {
        fields.push(("uri", FieldValue::Str(path)));
    }
    if let Some(version) = version {
        fields.push(("version", FieldValue::Str(version_str(version))));
    }
    finish(fields, status, &headers, data, "request")
}

fn parse_response(data: &[u8]) -> ParseResult<'_> {
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut resp = Response::new(&mut headers);
    let status = resp.parse(data);
    let (version, code, reason) = (resp.version, resp.code, resp.reason);

    let mut fields = Fields::new();
    fields.push(("is_request", FieldValue::Bool(false)));
    if let Some(version) = version {
        fields.push(("version", FieldValue::Str(version_str(version))));
    }
    if let Some(code) = code {
        fields.push(("status_code", FieldValue::UInt16(code)));
    }
    if let Some(reason) = reason {
        fields.push(("status_text", FieldValue::Str(reason)));
    }
    finish(fields, status, &headers, data, "response")
}

impl Protocol for HttpProtocol {
    fn name(&self) -> &'static str {
        "http"
    }

    fn display_name(&self) -> &'static str {
        "HTTP"
    }

    /// Matches a TCP segment whose payload starts an HTTP/1.x message (the
    /// TCP layer's [`PAYLOAD_HINT`]). On an HTTP port the match outranks the
    /// other port-based TCP parsers; elsewhere it ranks below them, so a
    /// well-known port's own protocol (TLS, SSH, DNS, BGP) keeps the
    /// segment and only unclaimed ports fall through to HTTP.
    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        if context.hint("transport") != Some(6) || context.hint(PAYLOAD_HINT) != Some(1) {
            return None;
        }
        let on_http_port = [context.hint("src_port"), context.hint("dst_port")]
            .iter()
            .flatten()
            .any(|port| HTTP_PORTS.iter().any(|p| *p as u64 == *port));
        Some(if on_http_port { 60 } else { 40 })
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        if data.starts_with(b"HTTP/") {
            parse_response(data)
        } else {
            parse_request(data)
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        let text = |name: &'static str, description: &'static str| {
            FieldDescriptor::new(name, DataKind::String)
                .set_nullable(true)
                .with_description(description)
        };
        vec![
            FieldDescriptor::new("http.is_request", DataKind::Bool)
                .set_nullable(true)
                .with_description("True for a request, false for a response"),
            FieldDescriptor::new("http.headers_complete", DataKind::Bool)
                .set_nullable(true)
                .with_description("True when the whole header block is in this segment"),
            text("http.method", "Request method (GET, POST, ...)"),
            text("http.uri", "Request target"),
            text("http.version", "HTTP/1.0 or HTTP/1.1"),
            FieldDescriptor::new("http.status_code", DataKind::UInt16)
                .set_nullable(true)
                .with_description("Response status code"),
            text("http.status_text", "Response reason phrase"),
            FieldDescriptor::new("http.body_length", DataKind::UInt64)
                .set_nullable(true)
                .with_description(
                    "Payload bytes after the header block in this segment (headers complete \
                     only; may include pipelined requests or chunk framing)",
                ),
            text("http.host", "Host header"),
            text("http.content_type", "Content-Type header"),
            FieldDescriptor::new("http.content_length", DataKind::UInt64)
                .set_nullable(true)
                .with_description("Content-Length header"),
            text("http.user_agent", "User-Agent header"),
            text("http.server", "Server header"),
            text("http.transfer_encoding", "Transfer-Encoding header"),
            text("http.connection", "Connection header"),
            text("http.cookie", "Cookie header"),
            text("http.set_cookie", "First Set-Cookie header"),
            text("http.referer", "Referer header"),
            text("http.accept", "Accept header"),
            text("http.accept_encoding", "Accept-Encoding header"),
            text("http.accept_language", "Accept-Language header"),
            text("http.cache_control", "Cache-Control header"),
            text(
                "http.authorization",
                "Authorization scheme only (Bearer, Basic, ...)",
            ),
            text("http.location", "Location header"),
            text("http.x_forwarded_for", "X-Forwarded-For header"),
            text("http.x_real_ip", "X-Real-IP header"),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["tcp"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{default_registry, parse_packet, ParseScope};

    fn ctx(src_port: u64, dst_port: u64, sniffed: bool) -> ParseContext {
        let mut ctx = ParseContext::new(1);
        ctx.insert_hint("src_port", src_port);
        ctx.insert_hint("dst_port", dst_port);
        ctx.insert_hint("transport", 6);
        if sniffed {
            ctx.insert_hint(PAYLOAD_HINT, 1);
        }
        ctx
    }

    fn parse(data: &[u8]) -> ParseResult<'_> {
        HttpProtocol.parse(data, &ctx(40000, 80, true))
    }

    fn text<'a>(result: &'a ParseResult<'_>, name: &str) -> Option<&'a str> {
        result.get(name).and_then(|v| v.as_str())
    }

    #[test]
    fn sniff_recognizes_message_starts_only() {
        assert!(starts_http_message(b"GET / HTTP/1.1\r\n"));
        assert!(starts_http_message(b"POST /api HTTP/1.0\r\n"));
        assert!(starts_http_message(b"TRACE * HTTP/1.1\r\n"));
        assert!(starts_http_message(b"HTTP/1.1 200 OK\r\n"));
        assert!(starts_http_message(b"HTTP/1.0 404 Not Found\r\n"));
        assert!(!starts_http_message(b"hello pcapsql"));
        assert!(!starts_http_message(b"GETTING started"));
        assert!(!starts_http_message(b"HTTP/2.0"));
        assert!(!starts_http_message(b"\x16\x03\x01\x00\x05"));
        assert!(!starts_http_message(b""));
        assert!(!starts_http_message(b"GET"));
    }

    #[test]
    fn can_parse_needs_tcp_and_sniffed_payload() {
        let parser = HttpProtocol;
        assert_eq!(parser.can_parse(&ctx(40000, 80, true)), Some(60));
        assert_eq!(parser.can_parse(&ctx(8080, 40000, true)), Some(60));
        // An HTTP message start on an unclaimed port still matches, below
        // the port-based parsers' priority.
        assert_eq!(parser.can_parse(&ctx(40000, 9999, true)), Some(40));
        // Port 80 traffic that does not start a message is not HTTP.
        assert_eq!(parser.can_parse(&ctx(40000, 80, false)), None);
        // UDP never carries HTTP/1.x.
        let mut udp = ctx(40000, 80, true);
        udp.set_hint("transport", 17);
        assert_eq!(parser.can_parse(&udp), None);
        assert_eq!(parser.can_parse(&ParseContext::new(1)), None);
    }

    #[test]
    fn parses_complete_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\
            User-Agent: pcapsql/1.0\r\nAccept: text/plain\r\n\
            Cookie: a=1\r\nAuthorization: Bearer secret-token\r\n\r\n";
        let result = parse(data);
        assert!(result.is_ok(), "{:?}", result.error);
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(text(&result, "method"), Some("GET"));
        assert_eq!(text(&result, "uri"), Some("/index.html"));
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert_eq!(text(&result, "host"), Some("example.test"));
        assert_eq!(text(&result, "user_agent"), Some("pcapsql/1.0"));
        assert_eq!(text(&result, "accept"), Some("text/plain"));
        assert_eq!(text(&result, "cookie"), Some("a=1"));
        // Credentials never reach the table.
        assert_eq!(text(&result, "authorization"), Some("Bearer"));
        assert_eq!(result.get("body_length"), Some(&FieldValue::UInt64(0)));
        assert!(result.get("status_code").is_none());
        assert!(result.remaining.is_empty());
    }

    #[test]
    fn parses_complete_response_with_body() {
        let data = b"HTTP/1.1 200 OK\r\nServer: corpus\r\nContent-Type: text/plain\r\n\
            Content-Length: 5\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nhello";
        let result = parse(data);
        assert!(result.is_ok(), "{:?}", result.error);
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(false)));
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert_eq!(result.get("status_code"), Some(&FieldValue::UInt16(200)));
        assert_eq!(text(&result, "status_text"), Some("OK"));
        assert_eq!(text(&result, "server"), Some("corpus"));
        assert_eq!(text(&result, "content_type"), Some("text/plain"));
        assert_eq!(result.get("content_length"), Some(&FieldValue::UInt64(5)));
        assert_eq!(result.get("body_length"), Some(&FieldValue::UInt64(5)));
        // Repeated header: the first value wins, and there is one entry.
        assert_eq!(text(&result, "set_cookie"), Some("a=1"));
        assert_eq!(
            result
                .fields
                .iter()
                .filter(|(k, _)| *k == "set_cookie")
                .count(),
            1
        );
        assert!(result.get("method").is_none());
    }

    #[test]
    fn http10_version() {
        let result = parse(b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(text(&result, "version"), Some("HTTP/1.0"));
        let result = parse(b"HTTP/1.0 302 Found\r\nLocation: /x\r\n\r\n");
        assert_eq!(text(&result, "version"), Some("HTTP/1.0"));
        assert_eq!(result.get("status_code"), Some(&FieldValue::UInt16(302)));
        assert_eq!(text(&result, "location"), Some("/x"));
    }

    #[test]
    fn partial_header_block_keeps_start_line_and_seen_headers() {
        // Header block cut mid-header: the request line and the complete
        // headers are reported; the cut one and the body are not.
        let result = parse(b"POST /api HTTP/1.1\r\nHost: api.test\r\nContent-Len");
        assert!(result.is_ok(), "{:?}", result.error);
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(text(&result, "method"), Some("POST"));
        assert_eq!(text(&result, "uri"), Some("/api"));
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert_eq!(text(&result, "host"), Some("api.test"));
        assert!(result.get("content_length").is_none());
        assert!(result.get("body_length").is_none());

        // Cut inside the status line.
        let result = parse(b"HTTP/1.1 50");
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(false)));
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert!(result.get("status_code").is_none());
    }

    #[test]
    fn malformed_start_is_an_error() {
        // A TLS record: bytes that are not request-line tokens, so nothing
        // of a start line is in hand and the row carries no fields.
        let result = parse(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01");
        assert!(result.error.is_some());
        assert!(result.fields.is_empty());

        // A sniffed start whose request target is not valid: the error is
        // reported, and what was read (the method) is kept.
        let result = parse(b"GET \xff\xfe\x00");
        assert!(result.error.is_some());
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(true)));
        assert_eq!(text(&result, "method"), Some("GET"));
        assert!(result.get("uri").is_none());
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );
        assert!(result.get("body_length").is_none());
    }

    #[test]
    fn malformed_header_block_keeps_start_line() {
        // A header name with a space: httparse rejects the block, but the
        // request line and the headers before it stay on the row.
        let result = parse(b"GET /path HTTP/1.1\r\nHost: h\r\nBad Header: x\r\n\r\n");
        assert!(result.error.is_some(), "expected a parse error");
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(true)));
        assert_eq!(text(&result, "method"), Some("GET"));
        assert_eq!(text(&result, "uri"), Some("/path"));
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert_eq!(text(&result, "host"), Some("h"));
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );
        assert!(result.get("body_length").is_none());
        assert!(result.remaining.is_empty());

        // A leading-space header line.
        let result = parse(b"GET / HTTP/1.1\r\n Host: x\r\n\r\n");
        assert!(result.error.is_some());
        assert_eq!(text(&result, "method"), Some("GET"));
        assert_eq!(text(&result, "uri"), Some("/"));
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );

        // More headers than the parser keeps.
        let mut data = b"GET /many HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 1) {
            data.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
        }
        data.extend_from_slice(b"\r\n");
        let result = parse(&data);
        assert!(result.error.is_some());
        assert_eq!(text(&result, "method"), Some("GET"));
        assert_eq!(text(&result, "uri"), Some("/many"));
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );

        // A status line with two spaces: the version is in hand.
        let result = parse(b"HTTP/1.1  200 OK\r\n\r\n");
        assert!(result.error.is_some());
        assert_eq!(result.get("is_request"), Some(&FieldValue::Bool(false)));
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert!(result.get("status_code").is_none());
        assert_eq!(
            result.get("headers_complete"),
            Some(&FieldValue::Bool(false))
        );

        // A bad status code after a good version.
        let result = parse(b"HTTP/1.1 ok\r\n\r\n");
        assert!(result.error.is_some());
        assert_eq!(text(&result, "version"), Some("HTTP/1.1"));
        assert!(result.get("status_code").is_none());
    }

    #[test]
    fn header_mapping_is_case_insensitive_and_scoped() {
        assert_eq!(
            header_field("HOST", b"a.test"),
            Some(("host", FieldValue::Str("a.test")))
        );
        assert_eq!(
            header_field("Referrer", b"/r"),
            Some(("referer", FieldValue::Str("/r")))
        );
        assert_eq!(
            header_field("content-length", b" 42 "),
            Some(("content_length", FieldValue::UInt64(42)))
        );
        assert_eq!(header_field("Content-Length", b"many"), None);
        assert_eq!(
            header_field("Authorization", b"Basic dXNlcjpwYXNz"),
            Some(("authorization", FieldValue::Str("Basic")))
        );
        assert_eq!(header_field("X-Unknown", b"v"), None);
        // Invalid UTF-8 is kept lossily instead of dropped.
        assert_eq!(
            header_field("Server", b"nginx\xff"),
            Some((
                "server",
                FieldValue::OwnedString(CompactString::new("nginx\u{FFFD}"))
            ))
        );
    }

    #[test]
    fn schema_matches_emitted_fields() {
        let parser = HttpProtocol;
        let schema: Vec<String> = parser
            .schema_fields()
            .iter()
            .map(|f| f.name.trim_start_matches("http.").to_string())
            .collect();
        let data = b"HTTP/1.1 200 OK\r\nServer: s\r\nContent-Type: t\r\nContent-Length: 0\r\n\
            Transfer-Encoding: identity\r\nConnection: close\r\nSet-Cookie: c\r\n\
            Cache-Control: no-cache\r\nLocation: /l\r\nX-Forwarded-For: 1.1.1.1\r\n\
            X-Real-IP: 2.2.2.2\r\n\r\n";
        for (name, _) in &parse(data).fields {
            assert!(schema.contains(&name.to_string()), "unlisted field {name}");
        }
        let data = b"GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: u\r\nCookie: c\r\nReferer: r\r\n\
            Accept: a\r\nAccept-Encoding: e\r\nAccept-Language: l\r\nAuthorization: Bearer x\r\n\r\n";
        for (name, _) in &parse(data).fields {
            assert!(schema.contains(&name.to_string()), "unlisted field {name}");
        }
        for (_, column) in HEADER_COLUMNS {
            assert!(
                schema.contains(&column.to_string()),
                "unlisted column {column}"
            );
        }
    }

    /// Ethernet/IPv4/TCP frame carrying `payload` between the given ports.
    fn tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        use crate::protocol::test_utils::{EthernetBuilder, Ipv4Builder, TcpBuilder};
        let tcp = TcpBuilder::new()
            .src_port(src_port)
            .dst_port(dst_port)
            .psh_ack()
            .payload(payload.to_vec())
            .build();
        let ip = Ipv4Builder::new().tcp().payload(tcp).build();
        EthernetBuilder::new().ipv4().payload(ip).build()
    }

    fn layer_names(frame: &[u8]) -> Vec<&'static str> {
        let registry = default_registry();
        parse_packet(&registry, 1, frame, &ParseScope::full())
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn chain_reaches_http_only_for_message_starts() {
        let registry = default_registry();

        // A request on port 80.
        let frame = tcp_frame(40000, 80, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        let parsed = parse_packet(&registry, 1, &frame, &ParseScope::full());
        let names: Vec<_> = parsed.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["ethernet", "ipv4", "tcp", "http"]);
        let http = &parsed.iter().find(|(n, _)| *n == "http").unwrap().1;
        assert_eq!(text(http, "host"), Some("h"));
        assert_eq!(http.encap_depth, 0);

        // A response from port 8080.
        assert_eq!(
            layer_names(&tcp_frame(8080, 40000, b"HTTP/1.1 204 No Content\r\n\r\n")),
            ["ethernet", "ipv4", "tcp", "http"]
        );

        // Port 80, but not a message start (a body or mid-stream segment).
        assert_eq!(
            layer_names(&tcp_frame(40000, 80, b"hello pcapsql")),
            ["ethernet", "ipv4", "tcp"]
        );

        // A message start on an unclaimed port is HTTP too.
        assert_eq!(
            layer_names(&tcp_frame(40000, 9000, b"POST /x HTTP/1.1\r\n\r\n")),
            ["ethernet", "ipv4", "tcp", "http"]
        );

        // TLS keeps its port even when the payload looks like HTTP.
        assert_eq!(
            layer_names(&tcp_frame(40000, 443, b"GET / HTTP/1.1\r\n\r\n")),
            ["ethernet", "ipv4", "tcp", "tls"]
        );
    }

    #[test]
    fn scoped_parse_for_http_table_runs_the_chain() {
        let registry = default_registry();
        let frame = tcp_frame(40000, 80, b"GET / HTTP/1.1\r\n\r\n");
        let scope = ParseScope::for_tables(&["http"], &registry);
        let names: Vec<_> = parse_packet(&registry, 1, &frame, &scope)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["ethernet", "ipv4", "tcp", "http"]);

        // A query on tcp alone does not pay for HTTP parsing.
        let scope = ParseScope::for_tables(&["tcp"], &registry);
        let names: Vec<_> = parse_packet(&registry, 1, &frame, &scope)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["ethernet", "ipv4", "tcp"]);
    }

    #[test]
    fn header_block_split_across_segments() {
        let registry = default_registry();

        // First segment: the request line and one header, cut mid-header.
        let first = tcp_frame(40000, 80, b"GET /split HTTP/1.1\r\nHost: h\r\nUser-Ag");
        let parsed = parse_packet(&registry, 1, &first, &ParseScope::full());
        let names: Vec<_> = parsed.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["ethernet", "ipv4", "tcp", "http"]);
        let http = &parsed.iter().find(|(n, _)| *n == "http").unwrap().1;
        assert!(http.is_ok(), "{:?}", http.error);
        assert_eq!(text(http, "method"), Some("GET"));
        assert_eq!(text(http, "uri"), Some("/split"));
        assert_eq!(text(http, "host"), Some("h"));
        assert!(http.get("user_agent").is_none());
        assert_eq!(http.get("headers_complete"), Some(&FieldValue::Bool(false)));
        assert!(http.get("body_length").is_none());

        // Continuation segment: the rest of the headers. Not a message
        // start, so it adds no row.
        let second = tcp_frame(40000, 80, b"ent: x\r\nAccept: */*\r\n\r\n");
        assert_eq!(layer_names(&second), ["ethernet", "ipv4", "tcp"]);
    }
}
