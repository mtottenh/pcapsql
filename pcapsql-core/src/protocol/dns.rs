//! DNS protocol parser.

use std::collections::HashSet;

use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// DNS well-known port.
pub const DNS_PORT: u16 = 53;

/// DNS protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct DnsProtocol;

impl Protocol for DnsProtocol {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn display_name(&self) -> &'static str {
        "DNS"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Check for DNS port (53) in either src_port or dst_port
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        match (src_port, dst_port) {
            (Some(53), _) | (_, Some(53)) => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // DNS header is 12 bytes minimum
        if data.len() < 12 {
            return ParseResult::error("DNS header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        // Transaction ID (2 bytes)
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        fields.push(("transaction_id", FieldValue::UInt16(transaction_id)));

        // Flags (2 bytes)
        let flags = u16::from_be_bytes([data[2], data[3]]);

        // QR bit (bit 15) - 0 = query, 1 = response
        let is_query = (flags & 0x8000) == 0;
        fields.push(("is_query", FieldValue::Bool(is_query)));

        // Opcode (bits 11-14)
        let opcode = ((flags >> 11) & 0x0F) as u8;
        fields.push(("opcode", FieldValue::UInt8(opcode)));

        // AA bit (bit 10) - Authoritative Answer
        let is_authoritative = (flags & 0x0400) != 0;
        fields.push(("is_authoritative", FieldValue::Bool(is_authoritative)));

        // TC bit (bit 9) - Truncated
        let is_truncated = (flags & 0x0200) != 0;
        fields.push(("is_truncated", FieldValue::Bool(is_truncated)));

        // RD bit (bit 8) - Recursion Desired
        let recursion_desired = (flags & 0x0100) != 0;
        fields.push(("recursion_desired", FieldValue::Bool(recursion_desired)));

        // RA bit (bit 7) - Recursion Available
        let recursion_available = (flags & 0x0080) != 0;
        fields.push(("recursion_available", FieldValue::Bool(recursion_available)));

        // RCODE (bits 0-3) - Response Code
        let response_code = (flags & 0x000F) as u8;
        fields.push(("response_code", FieldValue::UInt8(response_code)));

        // Question count (2 bytes)
        let query_count = u16::from_be_bytes([data[4], data[5]]);
        fields.push(("query_count", FieldValue::UInt16(query_count)));

        // Answer count (2 bytes)
        let answer_count = u16::from_be_bytes([data[6], data[7]]);
        fields.push(("answer_count", FieldValue::UInt16(answer_count)));

        // Authority count (2 bytes)
        let authority_count = u16::from_be_bytes([data[8], data[9]]);
        fields.push(("authority_count", FieldValue::UInt16(authority_count)));

        // Additional count (2 bytes)
        let additional_count = u16::from_be_bytes([data[10], data[11]]);
        fields.push(("additional_count", FieldValue::UInt16(additional_count)));

        // Parse the first question section if present
        if query_count > 0 {
            match parse_question(&data[12..]) {
                Ok((name, qtype, qclass, consumed)) => {
                    fields.push(("query_name", FieldValue::String(name)));
                    fields.push(("query_type", FieldValue::UInt16(qtype)));
                    fields.push(("query_class", FieldValue::UInt16(qclass)));

                    // Return remaining bytes after the question section
                    let remaining_offset = 12 + consumed;
                    if remaining_offset <= data.len() {
                        return ParseResult::success(
                            fields,
                            &data[remaining_offset..],
                            SmallVec::new(),
                        );
                    }
                }
                Err(e) => {
                    // Partial parse - we have header but couldn't fully parse question
                    return ParseResult::partial(fields, &data[12..], e);
                }
            }
        }

        // No questions or couldn't parse them
        ParseResult::success(fields, &data[12..], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("dns.transaction_id", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.is_query", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("dns.opcode", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dns.is_authoritative", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("dns.is_truncated", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("dns.recursion_desired", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("dns.recursion_available", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("dns.response_code", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dns.query_count", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.answer_count", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.authority_count", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.additional_count", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.query_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dns.query_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.query_class", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["udp", "tcp"] // DNS runs over UDP (primarily) and TCP
    }

    fn parse_projected<'a>(
        &self,
        data: &'a [u8],
        _context: &ParseContext,
        fields: Option<&HashSet<String>>,
    ) -> ParseResult<'a> {
        // If no projection, use full parse
        let fields = match fields {
            None => return self.parse(data, _context),
            Some(f) if f.is_empty() => return self.parse(data, _context),
            Some(f) => f,
        };

        // DNS header is 12 bytes minimum
        if data.len() < 12 {
            return ParseResult::error("DNS header too short".to_string(), data);
        }

        let mut result_fields = SmallVec::new();

        // Parse header fields (all cheap)
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_query = (flags & 0x8000) == 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let is_authoritative = (flags & 0x0400) != 0;
        let is_truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let response_code = (flags & 0x000F) as u8;
        let query_count = u16::from_be_bytes([data[4], data[5]]);
        let answer_count = u16::from_be_bytes([data[6], data[7]]);
        let authority_count = u16::from_be_bytes([data[8], data[9]]);
        let additional_count = u16::from_be_bytes([data[10], data[11]]);

        // Insert only requested header fields
        if fields.contains("transaction_id") {
            result_fields.push(("transaction_id", FieldValue::UInt16(transaction_id)));
        }
        if fields.contains("is_query") {
            result_fields.push(("is_query", FieldValue::Bool(is_query)));
        }
        if fields.contains("opcode") {
            result_fields.push(("opcode", FieldValue::UInt8(opcode)));
        }
        if fields.contains("is_authoritative") {
            result_fields.push(("is_authoritative", FieldValue::Bool(is_authoritative)));
        }
        if fields.contains("is_truncated") {
            result_fields.push(("is_truncated", FieldValue::Bool(is_truncated)));
        }
        if fields.contains("recursion_desired") {
            result_fields.push(("recursion_desired", FieldValue::Bool(recursion_desired)));
        }
        if fields.contains("recursion_available") {
            result_fields.push(("recursion_available", FieldValue::Bool(recursion_available)));
        }
        if fields.contains("response_code") {
            result_fields.push(("response_code", FieldValue::UInt8(response_code)));
        }
        if fields.contains("query_count") {
            result_fields.push(("query_count", FieldValue::UInt16(query_count)));
        }
        if fields.contains("answer_count") {
            result_fields.push(("answer_count", FieldValue::UInt16(answer_count)));
        }
        if fields.contains("authority_count") {
            result_fields.push(("authority_count", FieldValue::UInt16(authority_count)));
        }
        if fields.contains("additional_count") {
            result_fields.push(("additional_count", FieldValue::UInt16(additional_count)));
        }

        // Only parse question section if any of the expensive fields are requested
        let need_question = fields.contains("query_name")
            || fields.contains("query_type")
            || fields.contains("query_class");

        if need_question && query_count > 0 {
            match parse_question(&data[12..]) {
                Ok((name, qtype, qclass, consumed)) => {
                    if fields.contains("query_name") {
                        result_fields.push(("query_name", FieldValue::String(name)));
                    }
                    if fields.contains("query_type") {
                        result_fields.push(("query_type", FieldValue::UInt16(qtype)));
                    }
                    if fields.contains("query_class") {
                        result_fields.push(("query_class", FieldValue::UInt16(qclass)));
                    }

                    let remaining_offset = 12 + consumed;
                    if remaining_offset <= data.len() {
                        return ParseResult::success(
                            result_fields,
                            &data[remaining_offset..],
                            SmallVec::new(),
                        );
                    }
                }
                Err(e) => {
                    return ParseResult::partial(result_fields, &data[12..], e);
                }
            }
        }

        ParseResult::success(result_fields, &data[12..], SmallVec::new())
    }

    fn cheap_fields(&self) -> &'static [&'static str] {
        // Header fields are all cheap - they come from the fixed 12-byte header
        &[
            "transaction_id",
            "is_query",
            "opcode",
            "is_authoritative",
            "is_truncated",
            "recursion_desired",
            "recursion_available",
            "response_code",
            "query_count",
            "answer_count",
            "authority_count",
            "additional_count",
        ]
    }

    fn expensive_fields(&self) -> &'static [&'static str] {
        // Question fields require parsing variable-length domain name
        &["query_name", "query_type", "query_class"]
    }
}

/// Parse a DNS question section and return (name, qtype, qclass, bytes_consumed).
fn parse_question(data: &[u8]) -> Result<(String, u16, u16, usize), String> {
    let (name, name_len) = parse_domain_name(data)?;

    // After the name, we need 4 more bytes for QTYPE (2) and QCLASS (2)
    let qtype_start = name_len;
    if data.len() < qtype_start + 4 {
        return Err("Question section too short for QTYPE/QCLASS".to_string());
    }

    let qtype = u16::from_be_bytes([data[qtype_start], data[qtype_start + 1]]);
    let qclass = u16::from_be_bytes([data[qtype_start + 2], data[qtype_start + 3]]);

    Ok((name, qtype, qclass, qtype_start + 4))
}

/// Parse a DNS domain name from the data.
/// Returns (decoded_name, bytes_consumed).
fn parse_domain_name(data: &[u8]) -> Result<(String, usize), String> {
    // Typical domain has 2-4 labels (e.g., www.example.com)
    let mut name_parts = Vec::with_capacity(4);
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return Err("Unexpected end of data while parsing domain name".to_string());
        }

        let len = data[pos] as usize;

        if len == 0 {
            // Null terminator
            pos += 1;
            break;
        }

        // Check for compression pointer (top 2 bits set)
        if (len & 0xC0) == 0xC0 {
            // DNS compression not fully supported in this simple parser
            // Just skip the pointer and stop
            pos += 2;
            break;
        }

        // Check for invalid length
        if len > 63 {
            return Err(format!("Invalid label length: {len}"));
        }

        if pos + 1 + len > data.len() {
            return Err("Label extends beyond data".to_string());
        }

        // Extract the label
        let label = &data[pos + 1..pos + 1 + len];
        match std::str::from_utf8(label) {
            Ok(s) => name_parts.push(s.to_string()),
            Err(_) => {
                // Non-UTF8 label - represent as hex
                name_parts.push(format!("[{len:02x}]"));
            }
        }

        pos += 1 + len;

        // Limit iterations to prevent infinite loops
        if name_parts.len() > 128 {
            return Err("Too many labels in domain name".to_string());
        }
    }

    let name = if name_parts.is_empty() {
        ".".to_string()
    } else {
        name_parts.join(".")
    };

    Ok((name, pos))
}

/// DNS record types.
#[allow(dead_code)]
pub mod record_type {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const ANY: u16 = 255;
}

/// DNS response codes.
#[allow(dead_code)]
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal DNS query header.
    fn create_dns_query(transaction_id: u16, query_name: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&transaction_id.to_be_bytes());

        // Flags: Standard query (0x0100 = RD set)
        packet.extend_from_slice(&[0x01, 0x00]);

        // Question count: 1
        packet.extend_from_slice(&[0x00, 0x01]);

        // Answer, Authority, Additional counts: 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Query name
        packet.extend_from_slice(query_name);

        // QTYPE: A (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        // QCLASS: IN (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    /// Create a DNS response header.
    fn create_dns_response(transaction_id: u16, rcode: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&transaction_id.to_be_bytes());

        // Flags: Response (0x8180 = QR set, RD set, RA set)
        let flags = 0x8180u16 | (rcode as u16);
        packet.extend_from_slice(&flags.to_be_bytes());

        // Question count: 1
        packet.extend_from_slice(&[0x00, 0x01]);

        // Answer count: 1
        packet.extend_from_slice(&[0x00, 0x01]);

        // Authority, Additional counts: 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question section (example.com)
        packet.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
        ]);

        // QTYPE: A, QCLASS: IN
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        packet
    }

    /// Encode a domain name in DNS format.
    fn encode_domain_name(name: &str) -> Vec<u8> {
        let mut result = Vec::new();
        for part in name.split('.') {
            if !part.is_empty() {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
        }
        result.push(0); // Null terminator
        result
    }

    #[test]
    fn test_parse_dns_query() {
        let query_name = encode_domain_name("example.com");
        let packet = create_dns_query(0x1234, &query_name);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 53);
        context.parent_protocol = Some("udp");

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("transaction_id"),
            Some(&FieldValue::UInt16(0x1234))
        );
        assert_eq!(result.get("is_query"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("query_count"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("answer_count"), Some(&FieldValue::UInt16(0)));
        assert_eq!(result.get("recursion_desired"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("query_name"),
            Some(&FieldValue::String("example.com".to_string()))
        );
        assert_eq!(result.get("query_type"), Some(&FieldValue::UInt16(1))); // A record
        assert_eq!(result.get("query_class"), Some(&FieldValue::UInt16(1))); // IN class
    }

    #[test]
    fn test_parse_dns_response() {
        let packet = create_dns_response(0xABCD, 0);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 53);
        context.parent_protocol = Some("udp");

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("transaction_id"),
            Some(&FieldValue::UInt16(0xABCD))
        );
        assert_eq!(result.get("is_query"), Some(&FieldValue::Bool(false)));
        assert_eq!(result.get("answer_count"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("recursion_available"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("response_code"), Some(&FieldValue::UInt8(0)));
    }

    #[test]
    fn test_parse_dns_nxdomain() {
        let packet = create_dns_response(0x5678, rcode::NXDOMAIN);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 53);
        context.parent_protocol = Some("udp");

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("response_code"),
            Some(&FieldValue::UInt8(rcode::NXDOMAIN))
        );
    }

    #[test]
    fn test_can_parse_dns() {
        let parser = DnsProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With dst_port 53
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("dst_port", 53);
        assert!(parser.can_parse(&ctx2).is_some());

        // With src_port 53
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("src_port", 53);
        assert!(parser.can_parse(&ctx3).is_some());

        // With different port
        let mut ctx4 = ParseContext::new(1);
        ctx4.insert_hint("dst_port", 80);
        assert!(parser.can_parse(&ctx4).is_none());
    }

    #[test]
    fn test_parse_dns_too_short() {
        let short_packet = [0x12, 0x34, 0x00, 0x00]; // Only 4 bytes

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 53);

        let result = parser.parse(&short_packet, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_parse_domain_name_simple() {
        // "www.example.com" encoded
        let data = [
            0x03, b'w', b'w', b'w', // "www"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
        ];

        let (name, len) = parse_domain_name(&data).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(len, 17);
    }

    #[test]
    fn test_parse_domain_name_root() {
        // Root domain
        let data = [0x00];

        let (name, len) = parse_domain_name(&data).unwrap();
        assert_eq!(name, ".");
        assert_eq!(len, 1);
    }

    #[test]
    fn test_dns_aaaa_query() {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&[0x12, 0x34]);

        // Flags: Standard query with RD
        packet.extend_from_slice(&[0x01, 0x00]);

        // Counts: 1 question
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Query name: ipv6.google.com
        packet.extend_from_slice(&[
            0x04, b'i', b'p', b'v', b'6', // "ipv6"
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', // "google"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
        ]);

        // QTYPE: AAAA (28)
        packet.extend_from_slice(&[0x00, 0x1C]);

        // QCLASS: IN (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 53);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("query_name"),
            Some(&FieldValue::String("ipv6.google.com".to_string()))
        );
        assert_eq!(
            result.get("query_type"),
            Some(&FieldValue::UInt16(record_type::AAAA))
        );
    }

    #[test]
    fn test_dns_schema_fields() {
        let parser = DnsProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"dns.transaction_id"));
        assert!(field_names.contains(&"dns.is_query"));
        assert!(field_names.contains(&"dns.query_name"));
        assert!(field_names.contains(&"dns.query_type"));
    }

    #[test]
    fn test_dns_projected_header_only() {
        // Test that we can skip expensive query_name parsing
        let query_name = encode_domain_name("example.com");
        let packet = create_dns_query(0x1234, &query_name);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 53);

        // Only request header fields - skip expensive query_name parsing
        let fields: HashSet<String> = ["transaction_id", "is_query", "response_code"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parser.parse_projected(&packet, &context, Some(&fields));

        assert!(result.is_ok());
        // Requested fields are present
        assert_eq!(
            result.get("transaction_id"),
            Some(&FieldValue::UInt16(0x1234))
        );
        assert_eq!(result.get("is_query"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("response_code"), Some(&FieldValue::UInt8(0)));
        // Expensive fields are NOT present (query_name was skipped)
        assert!(result.get("query_name").is_none());
        assert!(result.get("query_type").is_none());
        assert!(result.get("query_class").is_none());
    }

    #[test]
    fn test_dns_projected_with_query_name() {
        let query_name = encode_domain_name("example.com");
        let packet = create_dns_query(0x5678, &query_name);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 53);

        // Request query_name - this requires domain name parsing
        let fields: HashSet<String> = ["transaction_id", "query_name"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parser.parse_projected(&packet, &context, Some(&fields));

        assert!(result.is_ok());
        assert_eq!(
            result.get("transaction_id"),
            Some(&FieldValue::UInt16(0x5678))
        );
        assert_eq!(
            result.get("query_name"),
            Some(&FieldValue::String("example.com".to_string()))
        );
        // Other fields not requested
        assert!(result.get("is_query").is_none());
        assert!(result.get("query_type").is_none());
    }
}
