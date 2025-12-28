//! DNS protocol parser using simple-dns library.

use std::collections::HashSet;

use compact_str::CompactString;
use simple_dns::{rdata::RData, Packet, PacketFlag, OPCODE, RCODE};
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
        // Check for DNS port in either src_port or dst_port
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        match (src_port, dst_port) {
            (Some(p), _) | (_, Some(p)) if p == DNS_PORT as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // Parse using simple-dns
        let packet = match Packet::parse(data) {
            Ok(p) => p,
            Err(e) => return ParseResult::error(format!("DNS parse error: {e}"), data),
        };

        let mut fields = SmallVec::new();

        // Extract header fields
        extract_header_fields(&packet, &mut fields);

        // Extract question fields (first question only)
        extract_question_fields(&packet, &mut fields);

        // Extract answer fields (as lists)
        extract_answer_fields(&packet, &mut fields);

        // Extract EDNS fields
        extract_edns_fields(&packet, &mut fields);

        ParseResult::success(fields, &[], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Header fields (cheap)
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
            // Question fields (expensive)
            FieldDescriptor::new("dns.query_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dns.query_type", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dns.query_class", DataKind::UInt16).set_nullable(true),
            // Answer fields (lists) - NEW
            FieldDescriptor::new(
                "dns.answer_ip4s",
                DataKind::List(Box::new(DataKind::UInt32)),
            )
            .set_nullable(true),
            FieldDescriptor::new(
                "dns.answer_ip6s",
                DataKind::List(Box::new(DataKind::FixedBinary(16))),
            )
            .set_nullable(true),
            FieldDescriptor::new(
                "dns.answer_cnames",
                DataKind::List(Box::new(DataKind::String)),
            )
            .set_nullable(true),
            FieldDescriptor::new(
                "dns.answer_types",
                DataKind::List(Box::new(DataKind::UInt16)),
            )
            .set_nullable(true),
            FieldDescriptor::new(
                "dns.answer_ttls",
                DataKind::List(Box::new(DataKind::UInt32)),
            )
            .set_nullable(true),
            // EDNS fields - NEW
            FieldDescriptor::new("dns.has_edns", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("dns.edns_udp_size", DataKind::UInt16).set_nullable(true),
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
        requested_fields: Option<&HashSet<String>>,
    ) -> ParseResult<'a> {
        // If no projection, use full parse
        let requested = match requested_fields {
            None => return self.parse(data, _context),
            Some(f) if f.is_empty() => return self.parse(data, _context),
            Some(f) => f,
        };

        // Parse using simple-dns
        let packet = match Packet::parse(data) {
            Ok(p) => p,
            Err(e) => return ParseResult::error(format!("DNS parse error: {e}"), data),
        };

        let mut fields = SmallVec::new();

        // Check which field categories are needed
        let need_header = requested.iter().any(|f| is_header_field(f));
        let need_question = requested.iter().any(|f| is_question_field(f));
        let need_answers = requested.iter().any(|f| is_answer_field(f));
        let need_edns = requested.iter().any(|f| is_edns_field(f));

        if need_header {
            extract_header_fields_projected(&packet, &mut fields, requested);
        }

        if need_question {
            extract_question_fields_projected(&packet, &mut fields, requested);
        }

        if need_answers {
            extract_answer_fields_projected(&packet, &mut fields, requested);
        }

        if need_edns {
            extract_edns_fields_projected(&packet, &mut fields, requested);
        }

        ParseResult::success(fields, &[], SmallVec::new())
    }

    fn cheap_fields(&self) -> &'static [&'static str] {
        // Header fields are all cheap
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
            "has_edns",
            "edns_udp_size",
        ]
    }

    fn expensive_fields(&self) -> &'static [&'static str] {
        // Fields requiring parsing variable-length sections
        &[
            "query_name",
            "query_type",
            "query_class",
            "answer_ip4s",
            "answer_ip6s",
            "answer_cnames",
            "answer_types",
            "answer_ttls",
        ]
    }
}

/// Check if field is a header field.
fn is_header_field(field: &str) -> bool {
    matches!(
        field,
        "transaction_id"
            | "is_query"
            | "opcode"
            | "is_authoritative"
            | "is_truncated"
            | "recursion_desired"
            | "recursion_available"
            | "response_code"
            | "query_count"
            | "answer_count"
            | "authority_count"
            | "additional_count"
    )
}

/// Check if field is a question field.
fn is_question_field(field: &str) -> bool {
    matches!(field, "query_name" | "query_type" | "query_class")
}

/// Check if field is an answer field.
fn is_answer_field(field: &str) -> bool {
    matches!(
        field,
        "answer_ip4s" | "answer_ip6s" | "answer_cnames" | "answer_types" | "answer_ttls"
    )
}

/// Check if field is an EDNS field.
fn is_edns_field(field: &str) -> bool {
    matches!(field, "has_edns" | "edns_udp_size")
}

/// Convert OPCODE to u8.
fn opcode_to_u8(opcode: OPCODE) -> u8 {
    match opcode {
        OPCODE::StandardQuery => 0,
        OPCODE::InverseQuery => 1,
        OPCODE::ServerStatusRequest => 2,
        OPCODE::Notify => 4,
        OPCODE::Update => 5,
        OPCODE::Reserved => 15, // Reserved
    }
}

/// Convert RCODE to u8.
fn rcode_to_u8(rcode: RCODE) -> u8 {
    match rcode {
        RCODE::NoError => 0,
        RCODE::FormatError => 1,
        RCODE::ServerFailure => 2,
        RCODE::NameError => 3,
        RCODE::NotImplemented => 4,
        RCODE::Refused => 5,
        RCODE::YXDOMAIN => 6,
        RCODE::YXRRSET => 7,
        RCODE::NXRRSET => 8,
        RCODE::NOTAUTH => 9,
        RCODE::NOTZONE => 10,
        RCODE::BADVERS => 16,
        RCODE::Reserved => 15,
    }
}

/// Extract header fields from a DNS packet.
fn extract_header_fields(packet: &Packet, fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    fields.push(("transaction_id", FieldValue::UInt16(packet.id())));
    fields.push((
        "is_query",
        FieldValue::Bool(!packet.has_flags(PacketFlag::RESPONSE)),
    ));
    fields.push(("opcode", FieldValue::UInt8(opcode_to_u8(packet.opcode()))));
    fields.push((
        "is_authoritative",
        FieldValue::Bool(packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER)),
    ));
    fields.push((
        "is_truncated",
        FieldValue::Bool(packet.has_flags(PacketFlag::TRUNCATION)),
    ));
    fields.push((
        "recursion_desired",
        FieldValue::Bool(packet.has_flags(PacketFlag::RECURSION_DESIRED)),
    ));
    fields.push((
        "recursion_available",
        FieldValue::Bool(packet.has_flags(PacketFlag::RECURSION_AVAILABLE)),
    ));
    fields.push((
        "response_code",
        FieldValue::UInt8(rcode_to_u8(packet.rcode())),
    ));
    fields.push((
        "query_count",
        FieldValue::UInt16(packet.questions.len() as u16),
    ));
    fields.push((
        "answer_count",
        FieldValue::UInt16(packet.answers.len() as u16),
    ));
    fields.push((
        "authority_count",
        FieldValue::UInt16(packet.name_servers.len() as u16),
    ));
    fields.push((
        "additional_count",
        FieldValue::UInt16(packet.additional_records.len() as u16),
    ));
}

/// Extract header fields from a DNS packet (projected).
fn extract_header_fields_projected(
    packet: &Packet,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    requested: &HashSet<String>,
) {
    if requested.contains("transaction_id") {
        fields.push(("transaction_id", FieldValue::UInt16(packet.id())));
    }
    if requested.contains("is_query") {
        fields.push((
            "is_query",
            FieldValue::Bool(!packet.has_flags(PacketFlag::RESPONSE)),
        ));
    }
    if requested.contains("opcode") {
        fields.push(("opcode", FieldValue::UInt8(opcode_to_u8(packet.opcode()))));
    }
    if requested.contains("is_authoritative") {
        fields.push((
            "is_authoritative",
            FieldValue::Bool(packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER)),
        ));
    }
    if requested.contains("is_truncated") {
        fields.push((
            "is_truncated",
            FieldValue::Bool(packet.has_flags(PacketFlag::TRUNCATION)),
        ));
    }
    if requested.contains("recursion_desired") {
        fields.push((
            "recursion_desired",
            FieldValue::Bool(packet.has_flags(PacketFlag::RECURSION_DESIRED)),
        ));
    }
    if requested.contains("recursion_available") {
        fields.push((
            "recursion_available",
            FieldValue::Bool(packet.has_flags(PacketFlag::RECURSION_AVAILABLE)),
        ));
    }
    if requested.contains("response_code") {
        fields.push((
            "response_code",
            FieldValue::UInt8(rcode_to_u8(packet.rcode())),
        ));
    }
    if requested.contains("query_count") {
        fields.push((
            "query_count",
            FieldValue::UInt16(packet.questions.len() as u16),
        ));
    }
    if requested.contains("answer_count") {
        fields.push((
            "answer_count",
            FieldValue::UInt16(packet.answers.len() as u16),
        ));
    }
    if requested.contains("authority_count") {
        fields.push((
            "authority_count",
            FieldValue::UInt16(packet.name_servers.len() as u16),
        ));
    }
    if requested.contains("additional_count") {
        fields.push((
            "additional_count",
            FieldValue::UInt16(packet.additional_records.len() as u16),
        ));
    }
}

/// Extract question fields from a DNS packet.
fn extract_question_fields(
    packet: &Packet,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
) {
    if let Some(question) = packet.questions.first() {
        fields.push((
            "query_name",
            FieldValue::OwnedString(CompactString::new(question.qname.to_string())),
        ));
        fields.push(("query_type", FieldValue::UInt16(question.qtype.into())));
        fields.push(("query_class", FieldValue::UInt16(question.qclass.into())));
    } else {
        fields.push(("query_name", FieldValue::Null));
        fields.push(("query_type", FieldValue::Null));
        fields.push(("query_class", FieldValue::Null));
    }
}

/// Extract question fields from a DNS packet (projected).
fn extract_question_fields_projected(
    packet: &Packet,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    requested: &HashSet<String>,
) {
    if let Some(question) = packet.questions.first() {
        if requested.contains("query_name") {
            fields.push((
                "query_name",
                FieldValue::OwnedString(CompactString::new(question.qname.to_string())),
            ));
        }
        if requested.contains("query_type") {
            fields.push(("query_type", FieldValue::UInt16(question.qtype.into())));
        }
        if requested.contains("query_class") {
            fields.push(("query_class", FieldValue::UInt16(question.qclass.into())));
        }
    } else {
        if requested.contains("query_name") {
            fields.push(("query_name", FieldValue::Null));
        }
        if requested.contains("query_type") {
            fields.push(("query_type", FieldValue::Null));
        }
        if requested.contains("query_class") {
            fields.push(("query_class", FieldValue::Null));
        }
    }
}

/// Extract answer fields from a DNS packet as lists.
fn extract_answer_fields(packet: &Packet, fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    let mut ip4s: Vec<FieldValue> = Vec::new();
    let mut ip6s: Vec<FieldValue> = Vec::new();
    let mut cnames: Vec<FieldValue> = Vec::new();
    let mut types: Vec<FieldValue> = Vec::new();
    let mut ttls: Vec<FieldValue> = Vec::new();

    for answer in &packet.answers {
        // Record type
        let rtype: u16 = answer.rdata.type_code().into();
        types.push(FieldValue::UInt16(rtype));

        // TTL
        ttls.push(FieldValue::UInt32(answer.ttl));

        // Extract type-specific data
        match &answer.rdata {
            RData::A(a) => {
                ip4s.push(FieldValue::UInt32(a.address));
            }
            RData::AAAA(aaaa) => {
                // Use IpAddr to avoid heap allocation for IPv6 address
                ip6s.push(FieldValue::IpAddr(std::net::IpAddr::V6(
                    std::net::Ipv6Addr::from(aaaa.address),
                )));
            }
            RData::CNAME(cname) => {
                cnames.push(FieldValue::OwnedString(CompactString::new(
                    cname.0.to_string(),
                )));
            }
            _ => {}
        }
    }

    // Push list fields
    fields.push(("answer_ip4s", FieldValue::List(ip4s)));
    fields.push(("answer_ip6s", FieldValue::List(ip6s)));
    fields.push(("answer_cnames", FieldValue::List(cnames)));
    fields.push(("answer_types", FieldValue::List(types)));
    fields.push(("answer_ttls", FieldValue::List(ttls)));
}

/// Extract answer fields from a DNS packet (projected).
fn extract_answer_fields_projected(
    packet: &Packet,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    requested: &HashSet<String>,
) {
    let need_ip4s = requested.contains("answer_ip4s");
    let need_ip6s = requested.contains("answer_ip6s");
    let need_cnames = requested.contains("answer_cnames");
    let need_types = requested.contains("answer_types");
    let need_ttls = requested.contains("answer_ttls");

    let mut ip4s: Vec<FieldValue> = Vec::new();
    let mut ip6s: Vec<FieldValue> = Vec::new();
    let mut cnames: Vec<FieldValue> = Vec::new();
    let mut types: Vec<FieldValue> = Vec::new();
    let mut ttls: Vec<FieldValue> = Vec::new();

    for answer in &packet.answers {
        if need_types {
            let rtype: u16 = answer.rdata.type_code().into();
            types.push(FieldValue::UInt16(rtype));
        }

        if need_ttls {
            ttls.push(FieldValue::UInt32(answer.ttl));
        }

        match &answer.rdata {
            RData::A(a) if need_ip4s => {
                ip4s.push(FieldValue::UInt32(a.address));
            }
            RData::AAAA(aaaa) if need_ip6s => {
                // Use IpAddr to avoid heap allocation for IPv6 address
                ip6s.push(FieldValue::IpAddr(std::net::IpAddr::V6(
                    std::net::Ipv6Addr::from(aaaa.address),
                )));
            }
            RData::CNAME(cname) if need_cnames => {
                cnames.push(FieldValue::OwnedString(CompactString::new(
                    cname.0.to_string(),
                )));
            }
            _ => {}
        }
    }

    if need_ip4s {
        fields.push(("answer_ip4s", FieldValue::List(ip4s)));
    }
    if need_ip6s {
        fields.push(("answer_ip6s", FieldValue::List(ip6s)));
    }
    if need_cnames {
        fields.push(("answer_cnames", FieldValue::List(cnames)));
    }
    if need_types {
        fields.push(("answer_types", FieldValue::List(types)));
    }
    if need_ttls {
        fields.push(("answer_ttls", FieldValue::List(ttls)));
    }
}

/// Extract EDNS fields from a DNS packet.
fn extract_edns_fields(packet: &Packet, fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    if let Some(opt) = packet.opt() {
        fields.push(("has_edns", FieldValue::Bool(true)));
        fields.push(("edns_udp_size", FieldValue::UInt16(opt.udp_packet_size)));
    } else {
        fields.push(("has_edns", FieldValue::Bool(false)));
        fields.push(("edns_udp_size", FieldValue::Null));
    }
}

/// Extract EDNS fields from a DNS packet (projected).
fn extract_edns_fields_projected(
    packet: &Packet,
    fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    requested: &HashSet<String>,
) {
    let has_edns = packet.opt().is_some();

    if requested.contains("has_edns") {
        fields.push(("has_edns", FieldValue::Bool(has_edns)));
    }

    if requested.contains("edns_udp_size") {
        if let Some(opt) = packet.opt() {
            fields.push(("edns_udp_size", FieldValue::UInt16(opt.udp_packet_size)));
        } else {
            fields.push(("edns_udp_size", FieldValue::Null));
        }
    }
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
    pub const OPT: u16 = 41;
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
    use std::net::Ipv4Addr;

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

    /// Create a DNS response header with an A record answer.
    fn create_dns_response_with_answer(transaction_id: u16, ip: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&transaction_id.to_be_bytes());

        // Flags: Response (0x8180 = QR set, RD set, RA set)
        packet.extend_from_slice(&[0x81, 0x80]);

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

        // Answer section
        // Name: compression pointer to question name
        packet.extend_from_slice(&[0xC0, 0x0C]);

        // TYPE: A (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        // CLASS: IN (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        // TTL: 300 seconds
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);

        // RDLENGTH: 4
        packet.extend_from_slice(&[0x00, 0x04]);

        // RDATA: IP address
        packet.extend_from_slice(&ip);

        packet
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
        assert_eq!(
            result.get("recursion_desired"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(
            result.get("query_name"),
            Some(&FieldValue::OwnedString(CompactString::new("example.com")))
        );
        assert_eq!(result.get("query_type"), Some(&FieldValue::UInt16(1))); // A record
        assert_eq!(result.get("query_class"), Some(&FieldValue::UInt16(1))); // IN class
    }

    #[test]
    fn test_parse_dns_response_with_answer() {
        let packet = create_dns_response_with_answer(0xABCD, [93, 184, 216, 34]);

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
        assert_eq!(result.get("response_code"), Some(&FieldValue::UInt8(0)));

        // Check answer_ip4s list
        if let Some(FieldValue::List(ip4s)) = result.get("answer_ip4s") {
            assert_eq!(ip4s.len(), 1);
            // 93.184.216.34 as u32: (93 << 24) | (184 << 16) | (216 << 8) | 34
            let expected_ip = u32::from(Ipv4Addr::new(93, 184, 216, 34));
            assert_eq!(ip4s[0], FieldValue::UInt32(expected_ip));
        } else {
            panic!("Expected answer_ip4s to be a list");
        }

        // Check answer_types list
        if let Some(FieldValue::List(types)) = result.get("answer_types") {
            assert_eq!(types.len(), 1);
            assert_eq!(types[0], FieldValue::UInt16(1)); // A record
        } else {
            panic!("Expected answer_types to be a list");
        }

        // Check answer_ttls list
        if let Some(FieldValue::List(ttls)) = result.get("answer_ttls") {
            assert_eq!(ttls.len(), 1);
            assert_eq!(ttls[0], FieldValue::UInt32(300)); // 300 seconds TTL
        } else {
            panic!("Expected answer_ttls to be a list");
        }
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
    fn test_dns_schema_fields() {
        let parser = DnsProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"dns.transaction_id"));
        assert!(field_names.contains(&"dns.is_query"));
        assert!(field_names.contains(&"dns.query_name"));
        assert!(field_names.contains(&"dns.query_type"));
        // New fields
        assert!(field_names.contains(&"dns.answer_ip4s"));
        assert!(field_names.contains(&"dns.answer_ip6s"));
        assert!(field_names.contains(&"dns.answer_cnames"));
        assert!(field_names.contains(&"dns.has_edns"));
    }

    #[test]
    fn test_dns_projected_header_only() {
        let query_name = encode_domain_name("example.com");
        let packet = create_dns_query(0x1234, &query_name);

        let parser = DnsProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 53);

        // Only request header fields - skip expensive parsing
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
        // Expensive fields are NOT present
        assert!(result.get("query_name").is_none());
        assert!(result.get("answer_ip4s").is_none());
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
            Some(&FieldValue::OwnedString(CompactString::new(
                "ipv6.google.com"
            )))
        );
        assert_eq!(
            result.get("query_type"),
            Some(&FieldValue::UInt16(record_type::AAAA))
        );
    }
}
