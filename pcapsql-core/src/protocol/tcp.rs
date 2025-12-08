//! TCP protocol parser.

use std::collections::HashSet;

use smallvec::SmallVec;

use etherparse::TcpHeaderSlice;

use super::{FieldValue, ParseContext, ParseResult, PayloadMode, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for TCP.
pub const IP_PROTO_TCP: u8 = 6;

/// TCP flags bit positions.
pub mod flags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const NS: u16 = 0x100;
}

/// TCP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct TcpProtocol;

impl Protocol for TcpProtocol {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn display_name(&self) -> &'static str {
        "TCP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint("ip_protocol") {
            Some(proto) if proto == IP_PROTO_TCP as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        match TcpHeaderSlice::from_slice(data) {
            Ok(tcp) => {
                let mut fields = SmallVec::new();

                fields.push(("src_port", FieldValue::UInt16(tcp.source_port())));
                fields.push(("dst_port", FieldValue::UInt16(tcp.destination_port())));
                fields.push(("seq", FieldValue::UInt32(tcp.sequence_number())));
                fields.push(("ack", FieldValue::UInt32(tcp.acknowledgment_number())));
                fields.push(("data_offset", FieldValue::UInt8(tcp.data_offset())));

                // Compute flags as a combined value
                let mut tcp_flags: u16 = 0;
                if tcp.fin() {
                    tcp_flags |= flags::FIN;
                }
                if tcp.syn() {
                    tcp_flags |= flags::SYN;
                }
                if tcp.rst() {
                    tcp_flags |= flags::RST;
                }
                if tcp.psh() {
                    tcp_flags |= flags::PSH;
                }
                if tcp.ack() {
                    tcp_flags |= flags::ACK;
                }
                if tcp.urg() {
                    tcp_flags |= flags::URG;
                }
                if tcp.ece() {
                    tcp_flags |= flags::ECE;
                }
                if tcp.cwr() {
                    tcp_flags |= flags::CWR;
                }
                if tcp.ns() {
                    tcp_flags |= flags::NS;
                }
                fields.push(("flags", FieldValue::UInt16(tcp_flags)));

                // Individual flag fields for convenience
                fields.push(("flag_fin", FieldValue::Bool(tcp.fin())));
                fields.push(("flag_syn", FieldValue::Bool(tcp.syn())));
                fields.push(("flag_rst", FieldValue::Bool(tcp.rst())));
                fields.push(("flag_psh", FieldValue::Bool(tcp.psh())));
                fields.push(("flag_ack", FieldValue::Bool(tcp.ack())));
                fields.push(("flag_urg", FieldValue::Bool(tcp.urg())));

                fields.push(("window", FieldValue::UInt16(tcp.window_size())));
                fields.push(("checksum", FieldValue::UInt16(tcp.checksum())));
                fields.push(("urgent_ptr", FieldValue::UInt16(tcp.urgent_pointer())));

                // Options length
                let header_len = tcp.slice().len();
                let options_len = header_len.saturating_sub(20);
                fields.push(("options_length", FieldValue::UInt8(options_len as u8)));

                let mut child_hints = SmallVec::new();
                child_hints.push(("src_port", tcp.source_port() as u64));
                child_hints.push(("dst_port", tcp.destination_port() as u64));
                child_hints.push(("transport", 6)); // TCP

                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("TCP parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("tcp.src_port", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tcp.dst_port", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tcp.seq", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("tcp.ack", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("tcp.data_offset", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("tcp.flags", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tcp.flag_fin", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tcp.flag_syn", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tcp.flag_rst", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tcp.flag_psh", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tcp.flag_ack", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tcp.flag_urg", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("tcp.window", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tcp.checksum", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tcp.urgent_ptr", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("tcp.options_length", DataKind::UInt8).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[] // Application protocols handled by StreamManager
    }

    fn payload_mode(&self) -> PayloadMode {
        PayloadMode::Stream
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv4", "ipv6"]
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

        match TcpHeaderSlice::from_slice(data) {
            Ok(tcp) => {
                let mut result_fields = SmallVec::new();
                let header_len = tcp.slice().len();

                // Always extract ports for child hints (needed for protocol detection)
                let src_port = tcp.source_port();
                let dst_port = tcp.destination_port();

                // Only insert requested fields
                if fields.contains("src_port") {
                    result_fields.push(("src_port", FieldValue::UInt16(src_port)));
                }
                if fields.contains("dst_port") {
                    result_fields.push(("dst_port", FieldValue::UInt16(dst_port)));
                }
                if fields.contains("seq") {
                    result_fields.push(("seq", FieldValue::UInt32(tcp.sequence_number())));
                }
                if fields.contains("ack") {
                    result_fields.push(("ack", FieldValue::UInt32(tcp.acknowledgment_number())));
                }
                if fields.contains("data_offset") {
                    result_fields.push(("data_offset", FieldValue::UInt8(tcp.data_offset())));
                }

                // Compute flags only if any flag field is requested
                let need_flags = fields.contains("flags")
                    || fields.contains("flag_fin")
                    || fields.contains("flag_syn")
                    || fields.contains("flag_rst")
                    || fields.contains("flag_psh")
                    || fields.contains("flag_ack")
                    || fields.contains("flag_urg");

                if need_flags {
                    let mut tcp_flags: u16 = 0;
                    if tcp.fin() {
                        tcp_flags |= flags::FIN;
                    }
                    if tcp.syn() {
                        tcp_flags |= flags::SYN;
                    }
                    if tcp.rst() {
                        tcp_flags |= flags::RST;
                    }
                    if tcp.psh() {
                        tcp_flags |= flags::PSH;
                    }
                    if tcp.ack() {
                        tcp_flags |= flags::ACK;
                    }
                    if tcp.urg() {
                        tcp_flags |= flags::URG;
                    }
                    if tcp.ece() {
                        tcp_flags |= flags::ECE;
                    }
                    if tcp.cwr() {
                        tcp_flags |= flags::CWR;
                    }
                    if tcp.ns() {
                        tcp_flags |= flags::NS;
                    }

                    if fields.contains("flags") {
                        result_fields.push(("flags", FieldValue::UInt16(tcp_flags)));
                    }
                    if fields.contains("flag_fin") {
                        result_fields.push(("flag_fin", FieldValue::Bool(tcp.fin())));
                    }
                    if fields.contains("flag_syn") {
                        result_fields.push(("flag_syn", FieldValue::Bool(tcp.syn())));
                    }
                    if fields.contains("flag_rst") {
                        result_fields.push(("flag_rst", FieldValue::Bool(tcp.rst())));
                    }
                    if fields.contains("flag_psh") {
                        result_fields.push(("flag_psh", FieldValue::Bool(tcp.psh())));
                    }
                    if fields.contains("flag_ack") {
                        result_fields.push(("flag_ack", FieldValue::Bool(tcp.ack())));
                    }
                    if fields.contains("flag_urg") {
                        result_fields.push(("flag_urg", FieldValue::Bool(tcp.urg())));
                    }
                }

                if fields.contains("window") {
                    result_fields.push(("window", FieldValue::UInt16(tcp.window_size())));
                }
                if fields.contains("checksum") {
                    result_fields.push(("checksum", FieldValue::UInt16(tcp.checksum())));
                }
                if fields.contains("urgent_ptr") {
                    result_fields.push(("urgent_ptr", FieldValue::UInt16(tcp.urgent_pointer())));
                }
                if fields.contains("options_length") {
                    let options_len = header_len.saturating_sub(20);
                    result_fields.push(("options_length", FieldValue::UInt8(options_len as u8)));
                }

                // Child hints always needed for protocol chaining
                let mut child_hints = SmallVec::new();
                child_hints.push(("src_port", src_port as u64));
                child_hints.push(("dst_port", dst_port as u64));
                child_hints.push(("transport", 6)); // TCP

                ParseResult::success(result_fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("TCP parse error: {e}"), data),
        }
    }

    fn cheap_fields(&self) -> &'static [&'static str] {
        // These fields are extracted from the fixed header with minimal computation
        &[
            "src_port",
            "dst_port",
            "seq",
            "ack",
            "data_offset",
            "flags",
            "flag_fin",
            "flag_syn",
            "flag_rst",
            "flag_psh",
            "flag_ack",
            "flag_urg",
            "window",
            "checksum",
            "urgent_ptr",
        ]
    }

    fn expensive_fields(&self) -> &'static [&'static str] {
        // Options require computing data_offset and variable-length parsing
        &["options_length"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_syn() {
        // TCP SYN packet (20 byte header, no options)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(80)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(8080)));
        assert_eq!(result.get("flag_syn"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flag_ack"), Some(&FieldValue::Bool(false)));
        assert_eq!(result.get("flags"), Some(&FieldValue::UInt16(flags::SYN)));
    }

    #[test]
    fn test_parse_tcp_syn_ack() {
        let header = [
            0x1f, 0x90, // Src port: 8080
            0x00, 0x50, // Dst port: 80
            0x00, 0x00, 0x10, 0x00, // Seq: 4096
            0x00, 0x00, 0x00, 0x02, // Ack: 2
            0x50, // Data offset: 5 (20 bytes)
            0x12, // Flags: SYN + ACK
            0xff, 0xff, // Window: 65535
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("flag_syn"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flag_ack"), Some(&FieldValue::Bool(true)));
        assert_eq!(
            result.get("flags"),
            Some(&FieldValue::UInt16(flags::SYN | flags::ACK))
        );
        assert_eq!(result.get("seq"), Some(&FieldValue::UInt32(4096)));
        assert_eq!(result.get("ack"), Some(&FieldValue::UInt32(2)));
    }

    #[test]
    fn test_parse_tcp_fin_ack() {
        let header = [
            0x00, 0x50, // Src port: 80
            0xc0, 0x00, // Dst port: 49152
            0x00, 0x01, 0x00, 0x00, // Seq
            0x00, 0x02, 0x00, 0x00, // Ack
            0x50, // Data offset: 5
            0x11, // Flags: FIN + ACK
            0x00, 0x01, // Window: 1
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("flag_fin"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flag_ack"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flag_syn"), Some(&FieldValue::Bool(false)));
    }

    #[test]
    fn test_parse_tcp_rst() {
        let header = [
            0x00, 0x50, // Src port: 80
            0xc0, 0x00, // Dst port: 49152
            0x00, 0x00, 0x00, 0x00, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, // Data offset: 5
            0x04, // Flags: RST
            0x00, 0x00, // Window: 0
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("flag_rst"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flags"), Some(&FieldValue::UInt16(flags::RST)));
    }

    #[test]
    fn test_parse_tcp_psh_ack() {
        let header = [
            0x01, 0xbb, // Src port: 443
            0xd4, 0x31, // Dst port: 54321
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x01, // Ack
            0x50, // Data offset: 5
            0x18, // Flags: PSH + ACK
            0x10, 0x00, // Window: 4096
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // Payload
            0x48, 0x54, 0x54, 0x50, // "HTTP"
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(443)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(54321)));
        assert_eq!(result.get("flag_psh"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flag_ack"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.remaining.len(), 4); // Payload
    }

    #[test]
    fn test_can_parse_tcp() {
        let parser = TcpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ip_protocol", 17); // UDP
        assert!(parser.can_parse(&ctx2).is_none());

        // With TCP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ip_protocol", 6);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_tcp_too_short() {
        let short_header = [0x00, 0x50, 0x1f, 0x90]; // Only 4 bytes

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_tcp_child_hints() {
        let header = [
            0x01, 0xbb, // Src port: 443
            0x00, 0x50, // Dst port: 80
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, // Data offset: 5
            0x02, // Flags: SYN
            0xff, 0xff, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.hint("src_port"), Some(443u64));
        assert_eq!(result.hint("dst_port"), Some(80u64));
        assert_eq!(result.hint("transport"), Some(6u64));
    }

    #[test]
    fn test_tcp_projected_parsing_ports_only() {
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        // Project to only ports
        let fields: HashSet<String> = ["src_port", "dst_port"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parser.parse_projected(&header, &context, Some(&fields));

        assert!(result.is_ok());
        // Requested fields are present
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(80)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(8080)));
        // Unrequested fields are NOT present
        assert!(result.get("seq").is_none());
        assert!(result.get("ack").is_none());
        assert!(result.get("flags").is_none());
        assert!(result.get("flag_syn").is_none());
        // Child hints are still populated
        assert_eq!(result.hint("src_port"), Some(80u64));
        assert_eq!(result.hint("dst_port"), Some(8080u64));
    }

    #[test]
    fn test_tcp_projected_parsing_with_flags() {
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes)
            0x12, // Flags: SYN + ACK
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        // Project to ports and specific flags
        let fields: HashSet<String> = ["src_port", "flag_syn", "flag_ack"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parser.parse_projected(&header, &context, Some(&fields));

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(80)));
        assert_eq!(result.get("flag_syn"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("flag_ack"), Some(&FieldValue::Bool(true)));
        // Combined flags field not requested
        assert!(result.get("flags").is_none());
        // Other fields not requested
        assert!(result.get("dst_port").is_none());
        assert!(result.get("seq").is_none());
    }

    #[test]
    fn test_tcp_projected_parsing_none_uses_full() {
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        // No projection - should return all fields
        let result = parser.parse_projected(&header, &context, None);

        assert!(result.is_ok());
        // All fields present
        assert!(result.get("src_port").is_some());
        assert!(result.get("dst_port").is_some());
        assert!(result.get("seq").is_some());
        assert!(result.get("ack").is_some());
        assert!(result.get("flags").is_some());
        assert!(result.get("flag_syn").is_some());
        assert!(result.get("window").is_some());
    }
}
