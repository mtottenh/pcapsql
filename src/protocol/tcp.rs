//! TCP protocol parser.

use std::collections::HashMap;

use arrow::datatypes::{DataType, Field};
use etherparse::TcpHeaderSlice;

use super::{FieldValue, ParseContext, ParseResult, PayloadMode, Protocol};

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
                let mut fields = HashMap::new();

                fields.insert("src_port", FieldValue::UInt16(tcp.source_port()));
                fields.insert("dst_port", FieldValue::UInt16(tcp.destination_port()));
                fields.insert("seq", FieldValue::UInt32(tcp.sequence_number()));
                fields.insert("ack", FieldValue::UInt32(tcp.acknowledgment_number()));
                fields.insert("data_offset", FieldValue::UInt8(tcp.data_offset()));

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
                fields.insert("flags", FieldValue::UInt16(tcp_flags));

                // Individual flag fields for convenience
                fields.insert("flag_fin", FieldValue::Bool(tcp.fin()));
                fields.insert("flag_syn", FieldValue::Bool(tcp.syn()));
                fields.insert("flag_rst", FieldValue::Bool(tcp.rst()));
                fields.insert("flag_psh", FieldValue::Bool(tcp.psh()));
                fields.insert("flag_ack", FieldValue::Bool(tcp.ack()));
                fields.insert("flag_urg", FieldValue::Bool(tcp.urg()));

                fields.insert("window", FieldValue::UInt16(tcp.window_size()));
                fields.insert("checksum", FieldValue::UInt16(tcp.checksum()));
                fields.insert("urgent_ptr", FieldValue::UInt16(tcp.urgent_pointer()));

                // Options length
                let header_len = tcp.slice().len();
                let options_len = header_len.saturating_sub(20);
                fields.insert("options_length", FieldValue::UInt8(options_len as u8));

                let mut child_hints = HashMap::new();
                child_hints.insert("src_port", tcp.source_port() as u64);
                child_hints.insert("dst_port", tcp.destination_port() as u64);
                child_hints.insert("transport", 6); // TCP

                ParseResult::success(fields, &data[header_len..], child_hints)
            }
            Err(e) => ParseResult::error(format!("TCP parse error: {e}"), data),
        }
    }

    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("tcp.src_port", DataType::UInt16, true),
            Field::new("tcp.dst_port", DataType::UInt16, true),
            Field::new("tcp.seq", DataType::UInt32, true),
            Field::new("tcp.ack", DataType::UInt32, true),
            Field::new("tcp.data_offset", DataType::UInt8, true),
            Field::new("tcp.flags", DataType::UInt16, true),
            Field::new("tcp.flag_fin", DataType::Boolean, true),
            Field::new("tcp.flag_syn", DataType::Boolean, true),
            Field::new("tcp.flag_rst", DataType::Boolean, true),
            Field::new("tcp.flag_psh", DataType::Boolean, true),
            Field::new("tcp.flag_ack", DataType::Boolean, true),
            Field::new("tcp.flag_urg", DataType::Boolean, true),
            Field::new("tcp.window", DataType::UInt16, true),
            Field::new("tcp.checksum", DataType::UInt16, true),
            Field::new("tcp.urgent_ptr", DataType::UInt16, true),
            Field::new("tcp.options_length", DataType::UInt8, true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[] // Application protocols handled by StreamManager
    }

    fn payload_mode(&self) -> PayloadMode {
        PayloadMode::Stream
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
        context.hints.insert("ip_protocol", 6);

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
        context.hints.insert("ip_protocol", 6);

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
        context.hints.insert("ip_protocol", 6);

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
        context.hints.insert("ip_protocol", 6);

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
        context.hints.insert("ip_protocol", 6);

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
        ctx2.hints.insert("ip_protocol", 17); // UDP
        assert!(parser.can_parse(&ctx2).is_none());

        // With TCP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("ip_protocol", 6);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_tcp_too_short() {
        let short_header = [0x00, 0x50, 0x1f, 0x90]; // Only 4 bytes

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 6);

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
        context.hints.insert("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.child_hints.get("src_port"), Some(&443u64));
        assert_eq!(result.child_hints.get("dst_port"), Some(&80u64));
        assert_eq!(result.child_hints.get("transport"), Some(&6u64));
    }
}
