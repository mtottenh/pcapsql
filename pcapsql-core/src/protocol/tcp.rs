//! TCP protocol parser.

use std::collections::HashSet;

use smallvec::SmallVec;

use etherparse::{TcpHeaderSlice, TcpOptionElement};

use super::{FieldValue, ParseContext, ParseResult, PayloadMode, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for TCP.
pub const IP_PROTO_TCP: u8 = 6;

/// TCP flags bit positions.
#[allow(dead_code)]
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

/// TCP option kinds.
#[allow(dead_code)]
pub mod options {
    pub const END_OF_LIST: u8 = 0;
    pub const NOP: u8 = 1;
    pub const MSS: u8 = 2;
    pub const WINDOW_SCALE: u8 = 3;
    pub const SACK_PERMITTED: u8 = 4;
    pub const SACK: u8 = 5;
    pub const TIMESTAMP: u8 = 8;
}

/// Parsed TCP options container.
/// Uses zero-copy parsing via etherparse.
#[derive(Debug, Clone, Default)]
pub struct ParsedTcpOptions {
    /// List of option names present (e.g., "MSS,WS,TS")
    pub option_names: SmallVec<[&'static str; 4]>,
    /// Maximum Segment Size (option 2)
    pub mss: Option<u16>,
    /// Window Scale factor (option 3)
    pub window_scale: Option<u8>,
    /// SACK Permitted (option 4)
    pub sack_permitted: bool,
    /// SACK block left edges (option 5) - parallel to sack_right_edges
    pub sack_left_edges: SmallVec<[u32; 4]>,
    /// SACK block right edges (option 5) - parallel to sack_left_edges
    pub sack_right_edges: SmallVec<[u32; 4]>,
    /// Timestamp value (TSval) - sender's timestamp (option 8)
    pub ts_val: Option<u32>,
    /// Timestamp echo reply (TSecr) - echoed timestamp from peer (option 8)
    pub ts_ecr: Option<u32>,
}

/// Get a static string for common TCP option combinations.
/// Returns None for uncommon combinations, which fall back to dynamic allocation.
fn get_options_static(opts: &ParsedTcpOptions) -> Option<&'static str> {
    // Build bitmask: MSS=1, WS=2, SACK_PERM=4, SACK=8, TS=16
    let mut mask: u8 = 0;
    for name in &opts.option_names {
        match *name {
            "MSS" => mask |= 1,
            "WS" => mask |= 2,
            "SACK_PERM" => mask |= 4,
            "SACK" => mask |= 8,
            "TS" => mask |= 16,
            _ => return None, // Unknown option, fall back to dynamic
        }
    }

    // Lookup common combinations (in order options appear in parse_tcp_options)
    match mask {
        0b00001 => Some("MSS"),
        0b00010 => Some("WS"),
        0b00011 => Some("MSS,WS"),
        0b00100 => Some("SACK_PERM"),
        0b00101 => Some("MSS,SACK_PERM"),
        0b00111 => Some("MSS,WS,SACK_PERM"),
        0b01000 => Some("SACK"),
        0b10000 => Some("TS"),
        0b10001 => Some("MSS,TS"),
        0b10010 => Some("WS,TS"),
        0b10011 => Some("MSS,WS,TS"),
        0b10100 => Some("SACK_PERM,TS"),
        0b10101 => Some("MSS,SACK_PERM,TS"),
        0b10111 => Some("MSS,WS,SACK_PERM,TS"),
        0b11000 => Some("SACK,TS"),
        0b11111 => Some("MSS,WS,SACK_PERM,SACK,TS"),
        _ => None, // Uncommon combination
    }
}

/// Parse TCP options using etherparse's iterator.
/// This is zero-copy for all options.
fn parse_tcp_options(tcp: &TcpHeaderSlice<'_>) -> ParsedTcpOptions {
    let mut result = ParsedTcpOptions::default();

    for opt_result in tcp.options_iterator() {
        let opt = match opt_result {
            Ok(o) => o,
            Err(_) => continue, // Skip malformed options
        };

        match opt {
            TcpOptionElement::Noop => {
                // NOP - skip, don't add to option names
            }
            TcpOptionElement::MaximumSegmentSize(mss) => {
                result.mss = Some(mss);
                result.option_names.push("MSS");
            }
            TcpOptionElement::WindowScale(scale) => {
                result.window_scale = Some(scale);
                result.option_names.push("WS");
            }
            TcpOptionElement::SelectiveAcknowledgementPermitted => {
                result.sack_permitted = true;
                result.option_names.push("SACK_PERM");
            }
            TcpOptionElement::SelectiveAcknowledgement(first, rest) => {
                // Store SACK blocks as parallel lists of left/right edges
                result.sack_left_edges.push(first.0);
                result.sack_right_edges.push(first.1);
                for block in rest.into_iter().flatten() {
                    result.sack_left_edges.push(block.0);
                    result.sack_right_edges.push(block.1);
                }
                result.option_names.push("SACK");
            }
            TcpOptionElement::Timestamp(ts_val, ts_ecr) => {
                result.ts_val = Some(ts_val);
                result.ts_ecr = Some(ts_ecr);
                result.option_names.push("TS");
            }
        }
    }

    result
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

                // Parse all TCP options
                if options_len > 0 {
                    let opts = parse_tcp_options(&tcp);

                    // Options list string - use static lookup for common combinations
                    if !opts.option_names.is_empty() {
                        let options_str = if let Some(static_str) = get_options_static(&opts) {
                            FieldValue::Str(static_str) // Zero-copy static string
                        } else {
                            FieldValue::OwnedString(opts.option_names.join(",").into())
                        };
                        fields.push(("options", options_str));
                    } else {
                        fields.push(("options", FieldValue::Null));
                    }

                    // MSS
                    if let Some(mss) = opts.mss {
                        fields.push(("mss", FieldValue::UInt16(mss)));
                    } else {
                        fields.push(("mss", FieldValue::Null));
                    }

                    // Window Scale
                    if let Some(ws) = opts.window_scale {
                        fields.push(("window_scale", FieldValue::UInt8(ws)));
                    } else {
                        fields.push(("window_scale", FieldValue::Null));
                    }

                    // SACK Permitted
                    if opts.sack_permitted {
                        fields.push(("sack_permitted", FieldValue::Bool(true)));
                    } else {
                        fields.push(("sack_permitted", FieldValue::Null));
                    }

                    // SACK Blocks as parallel lists
                    if !opts.sack_left_edges.is_empty() {
                        let left_edges: Vec<FieldValue> = opts
                            .sack_left_edges
                            .iter()
                            .map(|&v| FieldValue::UInt32(v))
                            .collect();
                        let right_edges: Vec<FieldValue> = opts
                            .sack_right_edges
                            .iter()
                            .map(|&v| FieldValue::UInt32(v))
                            .collect();
                        fields.push(("sack_left_edges", FieldValue::List(left_edges)));
                        fields.push(("sack_right_edges", FieldValue::List(right_edges)));
                    } else {
                        fields.push(("sack_left_edges", FieldValue::Null));
                        fields.push(("sack_right_edges", FieldValue::Null));
                    }

                    // Timestamps
                    if let Some(ts_val) = opts.ts_val {
                        fields.push(("ts_val", FieldValue::UInt32(ts_val)));
                    } else {
                        fields.push(("ts_val", FieldValue::Null));
                    }
                    if let Some(ts_ecr) = opts.ts_ecr {
                        fields.push(("ts_ecr", FieldValue::UInt32(ts_ecr)));
                    } else {
                        fields.push(("ts_ecr", FieldValue::Null));
                    }
                } else {
                    // No options - all null
                    fields.push(("options", FieldValue::Null));
                    fields.push(("mss", FieldValue::Null));
                    fields.push(("window_scale", FieldValue::Null));
                    fields.push(("sack_permitted", FieldValue::Null));
                    fields.push(("sack_left_edges", FieldValue::Null));
                    fields.push(("sack_right_edges", FieldValue::Null));
                    fields.push(("ts_val", FieldValue::Null));
                    fields.push(("ts_ecr", FieldValue::Null));
                }

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
            // TCP options fields
            FieldDescriptor::new("tcp.options", DataKind::String)
                .set_nullable(true)
                .with_description("Comma-separated list of TCP options present (e.g., MSS,WS,TS)"),
            FieldDescriptor::new("tcp.mss", DataKind::UInt16)
                .set_nullable(true)
                .with_description("Maximum Segment Size (option 2)"),
            FieldDescriptor::new("tcp.window_scale", DataKind::UInt8)
                .set_nullable(true)
                .with_description("Window scale factor (option 3)"),
            FieldDescriptor::new("tcp.sack_permitted", DataKind::Bool)
                .set_nullable(true)
                .with_description("Selective ACK permitted (option 4)"),
            FieldDescriptor::new(
                "tcp.sack_left_edges",
                DataKind::List(Box::new(DataKind::UInt32)),
            )
            .set_nullable(true)
            .with_description("SACK block left edges (option 5)"),
            FieldDescriptor::new(
                "tcp.sack_right_edges",
                DataKind::List(Box::new(DataKind::UInt32)),
            )
            .set_nullable(true)
            .with_description("SACK block right edges (option 5)"),
            FieldDescriptor::new("tcp.ts_val", DataKind::UInt32)
                .set_nullable(true)
                .with_description("TCP timestamp value (TSval) - sender's timestamp (option 8)"),
            FieldDescriptor::new("tcp.ts_ecr", DataKind::UInt32)
                .set_nullable(true)
                .with_description("TCP timestamp echo reply (TSecr) - echoed timestamp (option 8)"),
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

                // Parse TCP options if any option field is requested
                let need_options = fields.contains("options")
                    || fields.contains("mss")
                    || fields.contains("window_scale")
                    || fields.contains("sack_permitted")
                    || fields.contains("sack_left_edges")
                    || fields.contains("sack_right_edges")
                    || fields.contains("ts_val")
                    || fields.contains("ts_ecr");

                if need_options {
                    let options_len = header_len.saturating_sub(20);
                    if options_len > 0 {
                        let opts = parse_tcp_options(&tcp);

                        if fields.contains("options") {
                            if !opts.option_names.is_empty() {
                                let options_str =
                                    if let Some(static_str) = get_options_static(&opts) {
                                        FieldValue::Str(static_str)
                                    } else {
                                        FieldValue::OwnedString(opts.option_names.join(",").into())
                                    };
                                result_fields.push(("options", options_str));
                            } else {
                                result_fields.push(("options", FieldValue::Null));
                            }
                        }
                        if fields.contains("mss") {
                            if let Some(mss) = opts.mss {
                                result_fields.push(("mss", FieldValue::UInt16(mss)));
                            } else {
                                result_fields.push(("mss", FieldValue::Null));
                            }
                        }
                        if fields.contains("window_scale") {
                            if let Some(ws) = opts.window_scale {
                                result_fields.push(("window_scale", FieldValue::UInt8(ws)));
                            } else {
                                result_fields.push(("window_scale", FieldValue::Null));
                            }
                        }
                        if fields.contains("sack_permitted") {
                            if opts.sack_permitted {
                                result_fields.push(("sack_permitted", FieldValue::Bool(true)));
                            } else {
                                result_fields.push(("sack_permitted", FieldValue::Null));
                            }
                        }
                        let need_sack_edges = fields.contains("sack_left_edges")
                            || fields.contains("sack_right_edges");
                        if need_sack_edges {
                            if !opts.sack_left_edges.is_empty() {
                                if fields.contains("sack_left_edges") {
                                    let left_edges: Vec<FieldValue> = opts
                                        .sack_left_edges
                                        .iter()
                                        .map(|&v| FieldValue::UInt32(v))
                                        .collect();
                                    result_fields
                                        .push(("sack_left_edges", FieldValue::List(left_edges)));
                                }
                                if fields.contains("sack_right_edges") {
                                    let right_edges: Vec<FieldValue> = opts
                                        .sack_right_edges
                                        .iter()
                                        .map(|&v| FieldValue::UInt32(v))
                                        .collect();
                                    result_fields
                                        .push(("sack_right_edges", FieldValue::List(right_edges)));
                                }
                            } else {
                                if fields.contains("sack_left_edges") {
                                    result_fields.push(("sack_left_edges", FieldValue::Null));
                                }
                                if fields.contains("sack_right_edges") {
                                    result_fields.push(("sack_right_edges", FieldValue::Null));
                                }
                            }
                        }
                        if fields.contains("ts_val") {
                            if let Some(ts_val) = opts.ts_val {
                                result_fields.push(("ts_val", FieldValue::UInt32(ts_val)));
                            } else {
                                result_fields.push(("ts_val", FieldValue::Null));
                            }
                        }
                        if fields.contains("ts_ecr") {
                            if let Some(ts_ecr) = opts.ts_ecr {
                                result_fields.push(("ts_ecr", FieldValue::UInt32(ts_ecr)));
                            } else {
                                result_fields.push(("ts_ecr", FieldValue::Null));
                            }
                        }
                    } else {
                        // No options - all null
                        if fields.contains("options") {
                            result_fields.push(("options", FieldValue::Null));
                        }
                        if fields.contains("mss") {
                            result_fields.push(("mss", FieldValue::Null));
                        }
                        if fields.contains("window_scale") {
                            result_fields.push(("window_scale", FieldValue::Null));
                        }
                        if fields.contains("sack_permitted") {
                            result_fields.push(("sack_permitted", FieldValue::Null));
                        }
                        if fields.contains("sack_left_edges") {
                            result_fields.push(("sack_left_edges", FieldValue::Null));
                        }
                        if fields.contains("sack_right_edges") {
                            result_fields.push(("sack_right_edges", FieldValue::Null));
                        }
                        if fields.contains("ts_val") {
                            result_fields.push(("ts_val", FieldValue::Null));
                        }
                        if fields.contains("ts_ecr") {
                            result_fields.push(("ts_ecr", FieldValue::Null));
                        }
                    }
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
        &[
            "options_length",
            "options",
            "mss",
            "window_scale",
            "sack_permitted",
            "sack_left_edges",
            "sack_right_edges",
            "ts_val",
            "ts_ecr",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_static_lookup() {
        // Test that common option combinations return static strings
        let mut opts = ParsedTcpOptions::default();
        opts.option_names.push("MSS");
        opts.option_names.push("WS");
        opts.option_names.push("SACK_PERM");
        opts.option_names.push("TS");

        let result = get_options_static(&opts);
        assert_eq!(result, Some("MSS,WS,SACK_PERM,TS"));

        // Test single options
        let mut opts_mss = ParsedTcpOptions::default();
        opts_mss.option_names.push("MSS");
        assert_eq!(get_options_static(&opts_mss), Some("MSS"));

        // Test uncommon combination returns None
        let mut opts_unknown = ParsedTcpOptions::default();
        opts_unknown.option_names.push("UNKNOWN");
        assert_eq!(get_options_static(&opts_unknown), None);
    }

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

    #[test]
    fn test_parse_tcp_timestamp_option() {
        // TCP packet with timestamp option
        // Header: 32 bytes (20 base + 12 options)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x02, // Ack: 2
            0x80, // Data offset: 8 (32 bytes)
            0x10, // Flags: ACK
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options (12 bytes):
            0x01, // NOP
            0x01, // NOP
            0x08, // Timestamp option kind
            0x0a, // Timestamp option length (10)
            0x12, 0x34, 0x56, 0x78, // TSval: 0x12345678 = 305419896
            0x9a, 0xbc, 0xde, 0xf0, // TSecr: 0x9abcdef0 = 2596069104
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("options_length"), Some(&FieldValue::UInt8(12)));
        assert_eq!(result.get("ts_val"), Some(&FieldValue::UInt32(0x12345678)));
        assert_eq!(result.get("ts_ecr"), Some(&FieldValue::UInt32(0x9abcdef0)));
    }

    #[test]
    fn test_parse_tcp_no_timestamp() {
        // TCP packet without timestamp option (20 byte header)
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
        assert_eq!(result.get("options_length"), Some(&FieldValue::UInt8(0)));
        assert_eq!(result.get("ts_val"), Some(&FieldValue::Null));
        assert_eq!(result.get("ts_ecr"), Some(&FieldValue::Null));
    }

    #[test]
    fn test_parse_tcp_mss_option() {
        // TCP SYN packet with MSS option
        // Header: 24 bytes (20 base + 4 options)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x60, // Data offset: 6 (24 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options (4 bytes):
            0x02, 0x04, 0x05, 0xb4, // MSS = 1460
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("options_length"), Some(&FieldValue::UInt8(4)));
        assert_eq!(result.get("mss"), Some(&FieldValue::UInt16(1460)));
        // Check options string contains MSS (may be static or owned)
        match result.get("options") {
            Some(FieldValue::Str(s)) => assert!(s.contains("MSS")),
            Some(FieldValue::OwnedString(s)) => assert!(s.contains("MSS")),
            _ => panic!("Expected string for options"),
        }
    }

    #[test]
    fn test_parse_tcp_window_scale_option() {
        // TCP SYN packet with Window Scale option
        // Header: 24 bytes (20 base + 4 options, padded)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x60, // Data offset: 6 (24 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options (4 bytes):
            0x03, 0x03, 0x07, // Window Scale = 7
            0x00, // Padding (End of options)
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("window_scale"), Some(&FieldValue::UInt8(7)));
    }

    #[test]
    fn test_parse_tcp_sack_permitted_option() {
        // TCP SYN packet with SACK Permitted option
        // Header: 24 bytes (20 base + 4 options, padded)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x60, // Data offset: 6 (24 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options (4 bytes):
            0x04, 0x02, // SACK Permitted
            0x01, 0x00, // NOP + padding
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("sack_permitted"), Some(&FieldValue::Bool(true)));
    }

    #[test]
    fn test_parse_tcp_sack_blocks() {
        // TCP packet with SACK blocks (during retransmission)
        // Header: 32 bytes (20 base + 12 options)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x02, // Ack: 2
            0x80, // Data offset: 8 (32 bytes)
            0x10, // Flags: ACK
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options (12 bytes):
            0x01, // NOP
            0x01, // NOP
            // SACK option with 1 block
            0x05, 0x0a, // SACK, length 10 (2 + 8 bytes)
            0x00, 0x00, 0x10, 0x00, // Left edge: 4096
            0x00, 0x00, 0x20, 0x00, // Right edge: 8192
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());

        // Check SACK left edges
        if let Some(FieldValue::List(edges)) = result.get("sack_left_edges") {
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0], FieldValue::UInt32(4096));
        } else {
            panic!("Expected List for sack_left_edges");
        }

        // Check SACK right edges
        if let Some(FieldValue::List(edges)) = result.get("sack_right_edges") {
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0], FieldValue::UInt32(8192));
        } else {
            panic!("Expected List for sack_right_edges");
        }
    }

    #[test]
    fn test_parse_tcp_multiple_options() {
        // TCP SYN packet with MSS, SACK Permitted, Timestamps, Window Scale
        // This is a typical SYN packet with all common options
        // Header: 40 bytes (20 base + 20 options)
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0xa0, // Data offset: 10 (40 bytes)
            0x02, // Flags: SYN
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options (20 bytes):
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
            0x04, 0x02, // SACK Permitted
            0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // Timestamps
            0x01, // NOP
            0x03, 0x03, 0x07, // Window Scale 7
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("mss"), Some(&FieldValue::UInt16(1460)));
        assert_eq!(result.get("sack_permitted"), Some(&FieldValue::Bool(true)));
        assert_eq!(result.get("window_scale"), Some(&FieldValue::UInt8(7)));
        assert_eq!(result.get("ts_val"), Some(&FieldValue::UInt32(1)));
        assert_eq!(result.get("ts_ecr"), Some(&FieldValue::UInt32(0)));

        // Check options string contains all options (may be static or owned)
        let opts_str = match result.get("options") {
            Some(FieldValue::Str(s)) => *s,
            Some(FieldValue::OwnedString(s)) => s.as_str(),
            _ => panic!("Expected string for options"),
        };
        assert!(
            opts_str.contains("MSS"),
            "options should contain MSS: {}",
            opts_str
        );
        assert!(
            opts_str.contains("SACK_PERM"),
            "options should contain SACK_PERM: {}",
            opts_str
        );
        assert!(
            opts_str.contains("TS"),
            "options should contain TS: {}",
            opts_str
        );
        assert!(
            opts_str.contains("WS"),
            "options should contain WS: {}",
            opts_str
        );
    }

    #[test]
    fn test_parse_tcp_timestamp_projected() {
        // TCP packet with timestamp option
        let header = [
            0x00, 0x50, // Src port: 80
            0x1f, 0x90, // Dst port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x02, // Ack: 2
            0x80, // Data offset: 8 (32 bytes)
            0x10, // Flags: ACK
            0x72, 0x10, // Window: 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            // TCP Options:
            0x01, // NOP
            0x01, // NOP
            0x08, // Timestamp option kind
            0x0a, // Timestamp option length
            0xaa, 0xbb, 0xcc, 0xdd, // TSval
            0x11, 0x22, 0x33, 0x44, // TSecr
        ];

        let parser = TcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 6);

        // Project to only timestamp fields
        let fields: HashSet<String> = ["ts_val", "ts_ecr"].iter().map(|s| s.to_string()).collect();
        let result = parser.parse_projected(&header, &context, Some(&fields));

        assert!(result.is_ok());
        assert_eq!(result.get("ts_val"), Some(&FieldValue::UInt32(0xaabbccdd)));
        assert_eq!(result.get("ts_ecr"), Some(&FieldValue::UInt32(0x11223344)));
        // Other fields not present
        assert!(result.get("src_port").is_none());
        assert!(result.get("seq").is_none());
    }
}
