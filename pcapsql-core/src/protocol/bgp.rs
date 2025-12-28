//! BGP (Border Gateway Protocol) parser.
//!
//! BGP is the protocol backing the core routing decisions on the Internet.
//! It maintains a table of IP networks or 'prefixes' which designate
//! network reachability among autonomous systems (AS).
//!
//! RFC 4271: A Border Gateway Protocol 4 (BGP-4)
//! RFC 6793: BGP Support for Four-Octet Autonomous System (AS) Number Space
//! RFC 2918: Route Refresh Capability for BGP-4

use compact_str::CompactString;
use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// BGP TCP port.
pub const BGP_PORT: u16 = 179;

/// BGP message types.
pub mod message_type {
    pub const OPEN: u8 = 1;
    pub const UPDATE: u8 = 2;
    pub const NOTIFICATION: u8 = 3;
    pub const KEEPALIVE: u8 = 4;
    pub const ROUTE_REFRESH: u8 = 5;
}

/// BGP path attribute type codes.
pub mod path_attr_type {
    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXT_HOP: u8 = 3;
    pub const MULTI_EXIT_DISC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITIES: u8 = 8;
    pub const MP_REACH_NLRI: u8 = 14;
    pub const MP_UNREACH_NLRI: u8 = 15;
}

/// BGP ORIGIN attribute values.
pub mod origin_type {
    pub const IGP: u8 = 0;
    pub const EGP: u8 = 1;
    pub const INCOMPLETE: u8 = 2;
}

/// BGP AS_PATH segment types.
pub mod as_path_segment_type {
    pub const AS_SET: u8 = 1;
    pub const AS_SEQUENCE: u8 = 2;
}

/// BGP error codes for NOTIFICATION messages.
pub mod error_code {
    pub const MESSAGE_HEADER_ERROR: u8 = 1;
    pub const OPEN_MESSAGE_ERROR: u8 = 2;
    pub const UPDATE_MESSAGE_ERROR: u8 = 3;
    pub const HOLD_TIMER_EXPIRED: u8 = 4;
    pub const FSM_ERROR: u8 = 5;
    pub const CEASE: u8 = 6;
    pub const ROUTE_REFRESH_ERROR: u8 = 7;
}

/// BGP capability codes in OPEN optional parameters.
pub mod capability_code {
    pub const MULTIPROTOCOL: u8 = 1;
    pub const ROUTE_REFRESH: u8 = 2;
    pub const FOUR_OCTET_AS: u8 = 65;
    pub const ADD_PATH: u8 = 69;
    pub const ENHANCED_ROUTE_REFRESH: u8 = 70;
}

/// AS_TRANS value used when 4-byte ASN is negotiated (RFC 6793).
pub const AS_TRANS: u16 = 23456;

/// BGP Marker: 16 bytes of 0xFF.
const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// Get the name of a BGP message type.
fn message_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        message_type::OPEN => "OPEN",
        message_type::UPDATE => "UPDATE",
        message_type::NOTIFICATION => "NOTIFICATION",
        message_type::KEEPALIVE => "KEEPALIVE",
        message_type::ROUTE_REFRESH => "ROUTE-REFRESH",
        _ => "UNKNOWN",
    }
}

/// Get the name of a BGP ORIGIN value.
fn origin_name(origin: u8) -> &'static str {
    match origin {
        origin_type::IGP => "IGP",
        origin_type::EGP => "EGP",
        origin_type::INCOMPLETE => "INCOMPLETE",
        _ => "UNKNOWN",
    }
}

/// Get the name of a BGP error code.
fn error_code_name(code: u8) -> &'static str {
    match code {
        error_code::MESSAGE_HEADER_ERROR => "Message Header Error",
        error_code::OPEN_MESSAGE_ERROR => "OPEN Message Error",
        error_code::UPDATE_MESSAGE_ERROR => "UPDATE Message Error",
        error_code::HOLD_TIMER_EXPIRED => "Hold Timer Expired",
        error_code::FSM_ERROR => "Finite State Machine Error",
        error_code::CEASE => "Cease",
        error_code::ROUTE_REFRESH_ERROR => "ROUTE-REFRESH Message Error",
        _ => "Unknown",
    }
}

/// Get the name of a path attribute type.
#[allow(dead_code)]
fn path_attr_type_name(type_code: u8) -> &'static str {
    match type_code {
        path_attr_type::ORIGIN => "ORIGIN",
        path_attr_type::AS_PATH => "AS_PATH",
        path_attr_type::NEXT_HOP => "NEXT_HOP",
        path_attr_type::MULTI_EXIT_DISC => "MULTI_EXIT_DISC",
        path_attr_type::LOCAL_PREF => "LOCAL_PREF",
        path_attr_type::ATOMIC_AGGREGATE => "ATOMIC_AGGREGATE",
        path_attr_type::AGGREGATOR => "AGGREGATOR",
        path_attr_type::COMMUNITIES => "COMMUNITIES",
        path_attr_type::MP_REACH_NLRI => "MP_REACH_NLRI",
        path_attr_type::MP_UNREACH_NLRI => "MP_UNREACH_NLRI",
        _ => "UNKNOWN",
    }
}

/// BGP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct BgpProtocol;

impl Protocol for BgpProtocol {
    fn name(&self) -> &'static str {
        "bgp"
    }

    fn display_name(&self) -> &'static str {
        "BGP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when TCP dst_port or src_port hint equals 179
        if let Some(dst_port) = context.hint("dst_port") {
            if dst_port == BGP_PORT as u64 {
                return Some(100);
            }
        }
        if let Some(src_port) = context.hint("src_port") {
            if src_port == BGP_PORT as u64 {
                return Some(100);
            }
        }
        None
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // BGP header minimum is 19 bytes (16 marker + 2 length + 1 type)
        if data.len() < 19 {
            return ParseResult::error("BGP header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        // Bytes 0-15: Marker (should be all 0xFF)
        if data[0..16] != BGP_MARKER {
            return ParseResult::error("BGP: invalid marker".to_string(), data);
        }

        // Bytes 16-17: Length (total message length including header)
        let length = u16::from_be_bytes([data[16], data[17]]);
        fields.push(("length", FieldValue::UInt16(length)));

        if !(19..=4096).contains(&length) {
            return ParseResult::error(format!("BGP: invalid length {length}"), data);
        }

        // Byte 18: Type
        let msg_type = data[18];
        fields.push(("message_type", FieldValue::UInt8(msg_type)));
        fields.push((
            "message_type_name",
            FieldValue::Str(message_type_name(msg_type)),
        ));

        // Parse message-specific fields
        let message_data = if data.len() >= length as usize {
            &data[19..length as usize]
        } else {
            &data[19..]
        };

        match msg_type {
            message_type::OPEN => {
                self.parse_open_message(message_data, &mut fields);
            }
            message_type::UPDATE => {
                self.parse_update_message(message_data, &mut fields);
            }
            message_type::NOTIFICATION => {
                self.parse_notification_message(message_data, &mut fields);
            }
            message_type::KEEPALIVE => {
                // KEEPALIVE has no additional data (header only)
            }
            message_type::ROUTE_REFRESH => {
                self.parse_route_refresh_message(message_data, &mut fields);
            }
            _ => {
                // Unknown message type
            }
        }

        // Calculate remaining data
        let consumed = std::cmp::min(length as usize, data.len());
        ParseResult::success(fields, &data[consumed..], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Common header fields
            FieldDescriptor::new("bgp.message_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("bgp.message_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.length", DataKind::UInt16).set_nullable(true),
            // OPEN message fields
            FieldDescriptor::new("bgp.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("bgp.my_as", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.my_as_4byte", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("bgp.hold_time", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.bgp_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.capabilities", DataKind::String).set_nullable(true),
            // UPDATE message fields
            FieldDescriptor::new("bgp.withdrawn_routes_len", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.withdrawn_routes", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.withdrawn_count", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.path_attr_len", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.origin", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("bgp.origin_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.as_path", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.as_path_length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.next_hop", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.med", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("bgp.local_pref", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("bgp.atomic_aggregate", DataKind::Bool).set_nullable(true),
            FieldDescriptor::new("bgp.aggregator_as", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("bgp.aggregator_ip", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.nlri", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.nlri_count", DataKind::UInt16).set_nullable(true),
            // NOTIFICATION message fields
            FieldDescriptor::new("bgp.error_code", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("bgp.error_code_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("bgp.error_subcode", DataKind::UInt8).set_nullable(true),
            // ROUTE-REFRESH message fields
            FieldDescriptor::new("bgp.afi", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("bgp.safi", DataKind::UInt8).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["tcp"]
    }
}

impl BgpProtocol {
    /// Parse BGP OPEN message.
    ///
    /// OPEN Message Format:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+
    /// |    Version    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     My Autonomous System      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |           Hold Time           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         BGP Identifier                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Opt Parm Len  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |             Optional Parameters (variable)                    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_open_message(
        &self,
        data: &[u8],
        fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    ) {
        if data.len() < 10 {
            return;
        }

        // Byte 0: Version
        let version = data[0];
        fields.push(("version", FieldValue::UInt8(version)));

        // Bytes 1-2: My AS (may be AS_TRANS=23456 if 4-byte ASN is used)
        let my_as = u16::from_be_bytes([data[1], data[2]]);
        fields.push(("my_as", FieldValue::UInt16(my_as)));

        // Bytes 3-4: Hold Time
        let hold_time = u16::from_be_bytes([data[3], data[4]]);
        fields.push(("hold_time", FieldValue::UInt16(hold_time)));

        // Bytes 5-8: BGP Identifier (IPv4 address)
        let bgp_id = format!("{}.{}.{}.{}", data[5], data[6], data[7], data[8]);
        fields.push((
            "bgp_id",
            FieldValue::OwnedString(CompactString::new(bgp_id)),
        ));

        // Byte 9: Optional Parameters Length
        let opt_params_len = data[9] as usize;
        if data.len() < 10 + opt_params_len {
            return;
        }

        // Parse optional parameters to extract capabilities
        let opt_params = &data[10..10 + opt_params_len];
        self.parse_open_optional_params(opt_params, fields, my_as);
    }

    /// Parse OPEN message optional parameters to extract capabilities.
    fn parse_open_optional_params(
        &self,
        data: &[u8],
        fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
        my_as_2byte: u16,
    ) {
        let mut offset = 0;
        // Typical OPEN has 2-5 capabilities
        let mut capabilities = Vec::with_capacity(4);
        let mut four_byte_asn: Option<u32> = None;

        while offset + 2 <= data.len() {
            let param_type = data[offset];
            let param_len = data[offset + 1] as usize;
            offset += 2;

            if offset + param_len > data.len() {
                break;
            }

            // Parameter type 2 = Capabilities
            if param_type == 2 {
                // Parse capabilities within this parameter
                let cap_data = &data[offset..offset + param_len];
                let mut cap_offset = 0;

                while cap_offset + 2 <= cap_data.len() {
                    let cap_code = cap_data[cap_offset];
                    let cap_len = cap_data[cap_offset + 1] as usize;
                    cap_offset += 2;

                    if cap_offset + cap_len > cap_data.len() {
                        break;
                    }

                    // Extract capability name
                    let cap_name = match cap_code {
                        capability_code::MULTIPROTOCOL => "MULTIPROTOCOL",
                        capability_code::ROUTE_REFRESH => "ROUTE_REFRESH",
                        capability_code::FOUR_OCTET_AS => "4-BYTE-AS",
                        capability_code::ADD_PATH => "ADD_PATH",
                        capability_code::ENHANCED_ROUTE_REFRESH => "ENHANCED_ROUTE_REFRESH",
                        _ => "UNKNOWN",
                    };
                    capabilities.push(cap_name);

                    // Extract 4-byte ASN if present (capability 65)
                    if cap_code == capability_code::FOUR_OCTET_AS && cap_len == 4 {
                        let asn = u32::from_be_bytes([
                            cap_data[cap_offset],
                            cap_data[cap_offset + 1],
                            cap_data[cap_offset + 2],
                            cap_data[cap_offset + 3],
                        ]);
                        four_byte_asn = Some(asn);
                    }

                    cap_offset += cap_len;
                }
            }

            offset += param_len;
        }

        if !capabilities.is_empty() {
            fields.push((
                "capabilities",
                FieldValue::OwnedString(CompactString::new(capabilities.join(","))),
            ));
        }

        // If 4-byte ASN capability was found, store it
        // Also check if my_as is AS_TRANS (23456), indicating 4-byte ASN is in use
        if let Some(asn) = four_byte_asn {
            fields.push(("my_as_4byte", FieldValue::UInt32(asn)));
        } else if my_as_2byte != AS_TRANS {
            // No 4-byte capability, so the 2-byte AS is the real AS
            fields.push(("my_as_4byte", FieldValue::UInt32(my_as_2byte as u32)));
        }
    }

    /// Parse BGP UPDATE message with full path attribute decoding.
    ///
    /// UPDATE Message Format:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Withdrawn Routes Length     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       Withdrawn Routes (variable)                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      Total Path Attribute Length                              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       Path Attributes (variable)                             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       Network Layer Reachability Information (variable)      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_update_message(
        &self,
        data: &[u8],
        fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    ) {
        if data.len() < 4 {
            return;
        }

        let mut offset = 0;

        // Bytes 0-1: Withdrawn Routes Length
        let withdrawn_routes_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        fields.push((
            "withdrawn_routes_len",
            FieldValue::UInt16(withdrawn_routes_len as u16),
        ));
        offset += 2;

        // Parse withdrawn routes (NLRI prefixes)
        if data.len() < offset + withdrawn_routes_len {
            return;
        }
        let withdrawn_data = &data[offset..offset + withdrawn_routes_len];
        let withdrawn_prefixes = self.parse_nlri_prefixes(withdrawn_data);
        if !withdrawn_prefixes.is_empty() {
            fields.push((
                "withdrawn_routes",
                FieldValue::OwnedString(CompactString::new(withdrawn_prefixes.join(","))),
            ));
            fields.push((
                "withdrawn_count",
                FieldValue::UInt16(withdrawn_prefixes.len() as u16),
            ));
        }
        offset += withdrawn_routes_len;

        // Check for path attributes length field
        if data.len() < offset + 2 {
            return;
        }

        // Total Path Attribute Length
        let path_attr_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        fields.push(("path_attr_len", FieldValue::UInt16(path_attr_len as u16)));
        offset += 2;

        // Parse path attributes
        if data.len() < offset + path_attr_len {
            return;
        }
        let path_attr_data = &data[offset..offset + path_attr_len];
        self.parse_path_attributes(path_attr_data, fields);
        offset += path_attr_len;

        // Parse NLRI (remaining bytes are advertised prefixes)
        if offset < data.len() {
            let nlri_data = &data[offset..];
            let nlri_prefixes = self.parse_nlri_prefixes(nlri_data);
            if !nlri_prefixes.is_empty() {
                fields.push((
                    "nlri",
                    FieldValue::OwnedString(CompactString::new(nlri_prefixes.join(","))),
                ));
                fields.push(("nlri_count", FieldValue::UInt16(nlri_prefixes.len() as u16)));
            }
        }
    }

    /// Parse NLRI prefixes (used for both withdrawn routes and announced routes).
    /// Each prefix is: length (1 byte) + prefix bytes (ceil(length/8) bytes)
    fn parse_nlri_prefixes(&self, data: &[u8]) -> Vec<String> {
        // UPDATE messages typically have 1-8 prefixes
        let mut prefixes = Vec::with_capacity(8);
        let mut offset = 0;

        while offset < data.len() {
            let prefix_len_bits = data[offset] as usize;
            offset += 1;

            // Calculate how many bytes the prefix occupies
            let prefix_bytes = prefix_len_bits.div_ceil(8);
            if offset + prefix_bytes > data.len() {
                break;
            }

            // Build the prefix (pad with zeros to make 4 bytes for IPv4)
            let mut prefix = [0u8; 4];
            let copy_len = prefix_bytes.min(4);
            prefix[..copy_len].copy_from_slice(&data[offset..offset + copy_len]);

            let prefix_str = format!(
                "{}.{}.{}.{}/{}",
                prefix[0], prefix[1], prefix[2], prefix[3], prefix_len_bits
            );
            prefixes.push(prefix_str);

            offset += prefix_bytes;
        }

        prefixes
    }

    /// Parse path attributes from UPDATE message.
    fn parse_path_attributes(
        &self,
        data: &[u8],
        fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    ) {
        let mut offset = 0;

        while offset + 3 <= data.len() {
            // Attribute flags (1 byte)
            let flags = data[offset];
            let optional = (flags & 0x80) != 0;
            let transitive = (flags & 0x40) != 0;
            let partial = (flags & 0x20) != 0;
            let extended_length = (flags & 0x10) != 0;
            let _ = (optional, transitive, partial); // Silence unused warnings

            // Attribute type code (1 byte)
            let type_code = data[offset + 1];
            offset += 2;

            // Attribute length (1 or 2 bytes depending on extended_length flag)
            let attr_len = if extended_length {
                if offset + 2 > data.len() {
                    break;
                }
                let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                len
            } else {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                len
            };

            if offset + attr_len > data.len() {
                break;
            }

            let attr_data = &data[offset..offset + attr_len];

            // Parse specific attributes
            match type_code {
                path_attr_type::ORIGIN => {
                    if !attr_data.is_empty() {
                        let origin = attr_data[0];
                        fields.push(("origin", FieldValue::UInt8(origin)));
                        fields.push(("origin_name", FieldValue::Str(origin_name(origin))));
                    }
                }
                path_attr_type::AS_PATH => {
                    let (as_path_str, path_length) = self.parse_as_path(attr_data);
                    fields.push((
                        "as_path",
                        FieldValue::OwnedString(CompactString::new(as_path_str)),
                    ));
                    fields.push(("as_path_length", FieldValue::UInt16(path_length)));
                }
                path_attr_type::NEXT_HOP => {
                    if attr_data.len() >= 4 {
                        let next_hop = format!(
                            "{}.{}.{}.{}",
                            attr_data[0], attr_data[1], attr_data[2], attr_data[3]
                        );
                        fields.push((
                            "next_hop",
                            FieldValue::OwnedString(CompactString::new(next_hop)),
                        ));
                    }
                }
                path_attr_type::MULTI_EXIT_DISC => {
                    if attr_data.len() >= 4 {
                        let med = u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]);
                        fields.push(("med", FieldValue::UInt32(med)));
                    }
                }
                path_attr_type::LOCAL_PREF => {
                    if attr_data.len() >= 4 {
                        let local_pref = u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]);
                        fields.push(("local_pref", FieldValue::UInt32(local_pref)));
                    }
                }
                path_attr_type::ATOMIC_AGGREGATE => {
                    // Presence indicates atomic aggregate (no value)
                    fields.push(("atomic_aggregate", FieldValue::Bool(true)));
                }
                path_attr_type::AGGREGATOR => {
                    // Can be 6 bytes (2-byte AS + 4-byte IP) or 8 bytes (4-byte AS + 4-byte IP)
                    if attr_data.len() >= 6 {
                        let (asn, ip_offset) = if attr_data.len() >= 8 {
                            // 4-byte AS
                            (
                                u32::from_be_bytes([
                                    attr_data[0],
                                    attr_data[1],
                                    attr_data[2],
                                    attr_data[3],
                                ]),
                                4,
                            )
                        } else {
                            // 2-byte AS
                            (u16::from_be_bytes([attr_data[0], attr_data[1]]) as u32, 2)
                        };
                        fields.push(("aggregator_as", FieldValue::UInt32(asn)));

                        if attr_data.len() >= ip_offset + 4 {
                            let ip = format!(
                                "{}.{}.{}.{}",
                                attr_data[ip_offset],
                                attr_data[ip_offset + 1],
                                attr_data[ip_offset + 2],
                                attr_data[ip_offset + 3]
                            );
                            fields.push((
                                "aggregator_ip",
                                FieldValue::OwnedString(CompactString::new(ip)),
                            ));
                        }
                    }
                }
                _ => {
                    // Unknown or unhandled attribute type
                }
            }

            offset += attr_len;
        }
    }

    /// Parse AS_PATH attribute and return (path_string, path_length).
    /// Supports both 2-byte and 4-byte AS numbers (auto-detected based on segment length).
    fn parse_as_path(&self, data: &[u8]) -> (String, u16) {
        // Typical AS path has 2-6 segments
        let mut segments = Vec::with_capacity(4);
        let mut total_length = 0u16;
        let mut offset = 0;

        while offset + 2 <= data.len() {
            let segment_type = data[offset];
            let segment_len = data[offset + 1] as usize;
            offset += 2;

            // Determine if this is 2-byte or 4-byte AS based on remaining data
            // Heuristic: if remaining bytes / segment_len == 4, use 4-byte ASNs
            let remaining = data.len() - offset;
            let as_size = if segment_len > 0 && remaining >= segment_len * 4 {
                4 // 4-byte ASNs
            } else {
                2 // 2-byte ASNs
            };

            let needed_bytes = segment_len * as_size;
            if offset + needed_bytes > data.len() {
                break;
            }

            // Pre-allocate based on segment_len
            let mut asns = Vec::with_capacity(segment_len);
            for i in 0..segment_len {
                let asn = if as_size == 4 {
                    u32::from_be_bytes([
                        data[offset + i * 4],
                        data[offset + i * 4 + 1],
                        data[offset + i * 4 + 2],
                        data[offset + i * 4 + 3],
                    ])
                } else {
                    u16::from_be_bytes([data[offset + i * 2], data[offset + i * 2 + 1]]) as u32
                };
                asns.push(asn.to_string());
            }

            let segment_str = match segment_type {
                as_path_segment_type::AS_SET => format!("{{{}}}", asns.join(",")),
                as_path_segment_type::AS_SEQUENCE => asns.join(" "),
                _ => asns.join(" "),
            };
            segments.push(segment_str);

            // AS_SEQUENCE contributes to path length, AS_SET counts as 1
            if segment_type == as_path_segment_type::AS_SEQUENCE {
                total_length += segment_len as u16;
            } else if segment_type == as_path_segment_type::AS_SET {
                total_length += 1;
            }

            offset += needed_bytes;
        }

        (segments.join(" "), total_length)
    }

    /// Parse NOTIFICATION message.
    fn parse_notification_message(
        &self,
        data: &[u8],
        fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    ) {
        if data.len() < 2 {
            return;
        }

        // Byte 0: Error Code
        let error_code = data[0];
        fields.push(("error_code", FieldValue::UInt8(error_code)));
        fields.push((
            "error_code_name",
            FieldValue::Str(error_code_name(error_code)),
        ));

        // Byte 1: Error Subcode
        let error_subcode = data[1];
        fields.push(("error_subcode", FieldValue::UInt8(error_subcode)));

        // Remaining bytes are error-specific data (not parsed)
    }

    /// Parse ROUTE-REFRESH message (RFC 2918).
    fn parse_route_refresh_message(
        &self,
        data: &[u8],
        fields: &mut SmallVec<[(&'static str, FieldValue); 16]>,
    ) {
        if data.len() < 4 {
            return;
        }

        // Bytes 0-1: AFI (Address Family Identifier)
        let afi = u16::from_be_bytes([data[0], data[1]]);
        fields.push(("afi", FieldValue::UInt16(afi)));

        // Byte 2: Reserved (must be 0)
        // Byte 3: SAFI (Subsequent Address Family Identifier)
        let safi = data[3];
        fields.push(("safi", FieldValue::UInt8(safi)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a BGP message header.
    fn create_bgp_header(msg_type: u8, length: u16) -> Vec<u8> {
        let mut header = Vec::new();

        // Marker (16 bytes of 0xFF)
        header.extend_from_slice(&BGP_MARKER);

        // Length
        header.extend_from_slice(&length.to_be_bytes());

        // Type
        header.push(msg_type);

        header
    }

    /// Create a BGP OPEN message.
    fn create_bgp_open(version: u8, my_as: u16, hold_time: u16, bgp_id: [u8; 4]) -> Vec<u8> {
        let mut msg = create_bgp_header(message_type::OPEN, 29); // 19 + 10

        // Version
        msg.push(version);

        // My AS
        msg.extend_from_slice(&my_as.to_be_bytes());

        // Hold Time
        msg.extend_from_slice(&hold_time.to_be_bytes());

        // BGP Identifier
        msg.extend_from_slice(&bgp_id);

        // Optional Parameters Length
        msg.push(0);

        msg
    }

    /// Create a BGP UPDATE message (minimal).
    fn create_bgp_update(withdrawn_len: u16, path_attr_len: u16) -> Vec<u8> {
        let total_len = 19 + 2 + withdrawn_len + 2 + path_attr_len;
        let mut msg = create_bgp_header(message_type::UPDATE, total_len);

        // Withdrawn Routes Length
        msg.extend_from_slice(&withdrawn_len.to_be_bytes());

        // Withdrawn Routes (empty)
        msg.extend(vec![0u8; withdrawn_len as usize]);

        // Path Attribute Length
        msg.extend_from_slice(&path_attr_len.to_be_bytes());

        // Path Attributes (empty)
        msg.extend(vec![0u8; path_attr_len as usize]);

        msg
    }

    // Test 1: can_parse with TCP port 179
    #[test]
    fn test_can_parse_with_tcp_port_179() {
        let parser = BgpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong port
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("dst_port", 80);
        assert!(parser.can_parse(&ctx2).is_none());

        // With BGP dst_port
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("dst_port", 179);
        assert!(parser.can_parse(&ctx3).is_some());

        // With BGP src_port
        let mut ctx4 = ParseContext::new(1);
        ctx4.insert_hint("src_port", 179);
        assert!(parser.can_parse(&ctx4).is_some());
    }

    // Test 2: Marker validation (16 bytes of 0xFF)
    #[test]
    fn test_marker_validation() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Valid marker
        let valid_msg = create_bgp_header(message_type::KEEPALIVE, 19);
        let result = parser.parse(&valid_msg, &context);
        assert!(result.is_ok());

        // Invalid marker
        let mut invalid_msg = create_bgp_header(message_type::KEEPALIVE, 19);
        invalid_msg[0] = 0xFE; // Corrupt marker
        let result = parser.parse(&invalid_msg, &context);
        assert!(!result.is_ok());
        assert!(result.error.unwrap().contains("invalid marker"));
    }

    // Test 3: Message type parsing
    #[test]
    fn test_message_type_parsing() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let test_types = [
            (message_type::OPEN, "OPEN"),
            (message_type::UPDATE, "UPDATE"),
            (message_type::NOTIFICATION, "NOTIFICATION"),
            (message_type::KEEPALIVE, "KEEPALIVE"),
            (message_type::ROUTE_REFRESH, "ROUTE-REFRESH"),
        ];

        for (msg_type, name) in test_types {
            // Use appropriate length for message type
            let length = if msg_type == message_type::OPEN {
                29
            } else {
                19
            };
            let mut msg = create_bgp_header(msg_type, length);
            // Add padding for OPEN message
            if msg_type == message_type::OPEN {
                msg.extend(vec![0u8; 10]);
            }

            let result = parser.parse(&msg, &context);
            assert!(result.is_ok());
            assert_eq!(
                result.get("message_type"),
                Some(&FieldValue::UInt8(msg_type))
            );
            assert_eq!(
                result.get("message_type_name"),
                Some(&FieldValue::Str(name))
            );
        }
    }

    // Test 4: OPEN message parsing
    #[test]
    fn test_open_message_parsing() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let msg = create_bgp_open(4, 65001, 180, [192, 168, 1, 1]);
        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(4)));
        assert_eq!(result.get("my_as"), Some(&FieldValue::UInt16(65001)));
        assert_eq!(result.get("hold_time"), Some(&FieldValue::UInt16(180)));
        assert_eq!(
            result.get("bgp_id"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.1")))
        );
    }

    // Test 5: KEEPALIVE message (no payload)
    #[test]
    fn test_keepalive_message() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let msg = create_bgp_header(message_type::KEEPALIVE, 19);
        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("message_type"),
            Some(&FieldValue::UInt8(message_type::KEEPALIVE))
        );
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(19)));
    }

    // Test 6: UPDATE message basic parsing
    #[test]
    fn test_update_message_basic_parsing() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let msg = create_bgp_update(5, 10);
        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("message_type"),
            Some(&FieldValue::UInt8(message_type::UPDATE))
        );
        assert_eq!(
            result.get("withdrawn_routes_len"),
            Some(&FieldValue::UInt16(5))
        );
        assert_eq!(result.get("path_attr_len"), Some(&FieldValue::UInt16(10)));
    }

    // Test 7: NOTIFICATION message
    #[test]
    fn test_notification_message() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let mut msg = create_bgp_header(message_type::NOTIFICATION, 21);
        msg.push(6); // Error code: Cease
        msg.push(4); // Error subcode: Administrative Reset

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("message_type"),
            Some(&FieldValue::UInt8(message_type::NOTIFICATION))
        );
        assert_eq!(
            result.get("message_type_name"),
            Some(&FieldValue::Str("NOTIFICATION"))
        );
    }

    // Test 8: Invalid marker rejection
    #[test]
    fn test_invalid_marker_rejection() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // All zeros marker (invalid)
        let mut msg = vec![0u8; 16];
        msg.extend_from_slice(&19u16.to_be_bytes());
        msg.push(message_type::KEEPALIVE);

        let result = parser.parse(&msg, &context);
        assert!(!result.is_ok());
        assert!(result.error.unwrap().contains("invalid marker"));
    }

    // Test 9: Too short message
    #[test]
    fn test_bgp_too_short() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let short_msg = [0xFF; 18]; // Only 18 bytes
        let result = parser.parse(&short_msg, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 10: Schema fields
    #[test]
    fn test_bgp_schema_fields() {
        let parser = BgpProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"bgp.message_type"));
        assert!(field_names.contains(&"bgp.message_type_name"));
        assert!(field_names.contains(&"bgp.length"));
        assert!(field_names.contains(&"bgp.version"));
        assert!(field_names.contains(&"bgp.my_as"));
        assert!(field_names.contains(&"bgp.hold_time"));
        assert!(field_names.contains(&"bgp.bgp_id"));
        assert!(field_names.contains(&"bgp.withdrawn_routes_len"));
        assert!(field_names.contains(&"bgp.path_attr_len"));
    }

    // Test 11: Multiple BGP messages in stream
    #[test]
    fn test_multiple_messages() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Two KEEPALIVE messages back-to-back
        let mut data = create_bgp_header(message_type::KEEPALIVE, 19);
        data.extend(create_bgp_header(message_type::KEEPALIVE, 19));

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 19); // Second message remains
    }

    // Test 12: OPEN message with 4-byte ASN capability (RFC 6793)
    #[test]
    fn test_open_with_4byte_asn_capability() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Build OPEN with optional parameters containing 4-byte AS capability
        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        // Build optional parameters: capability 65 (4-byte AS) with value 4200000001
        let four_byte_asn: u32 = 4200000001;
        let cap_data = [
            2,
            6, // Parameter type 2 (Capabilities), length 6
            capability_code::FOUR_OCTET_AS,
            4, // Capability 65, length 4
            ((four_byte_asn >> 24) & 0xFF) as u8,
            ((four_byte_asn >> 16) & 0xFF) as u8,
            ((four_byte_asn >> 8) & 0xFF) as u8,
            (four_byte_asn & 0xFF) as u8,
        ];

        let total_len = 19 + 10 + cap_data.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::OPEN);

        // OPEN fields
        msg.push(4); // Version
        msg.extend_from_slice(&AS_TRANS.to_be_bytes()); // my_as = AS_TRANS (23456)
        msg.extend_from_slice(&180u16.to_be_bytes()); // Hold time
        msg.extend_from_slice(&[10, 0, 0, 1]); // BGP ID
        msg.push(cap_data.len() as u8); // Opt params length
        msg.extend_from_slice(&cap_data);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("my_as"), Some(&FieldValue::UInt16(AS_TRANS)));
        assert_eq!(
            result.get("my_as_4byte"),
            Some(&FieldValue::UInt32(four_byte_asn))
        );

        // Check capabilities string contains 4-BYTE-AS
        if let Some(FieldValue::OwnedString(caps)) = result.get("capabilities") {
            assert!(caps.contains("4-BYTE-AS"));
        } else {
            panic!("Expected capabilities field");
        }
    }

    // Test 13: UPDATE message with withdrawn routes
    #[test]
    fn test_update_with_withdrawn_routes() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Build UPDATE with withdrawn routes: 10.0.0.0/8, 192.168.0.0/16
        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        // Withdrawn routes: 10.0.0.0/8 (2 bytes: len=8, prefix=10)
        //                   192.168.0.0/16 (3 bytes: len=16, prefix=192,168)
        let withdrawn = [
            8, 10, // 10.0.0.0/8
            16, 192, 168, // 192.168.0.0/16
        ];

        let total_len = 19 + 2 + withdrawn.len() + 2; // header + withdrawn_len + withdrawn + path_attr_len
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        // Withdrawn routes length
        msg.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        msg.extend_from_slice(&withdrawn);

        // Path attribute length (0 - no attributes)
        msg.extend_from_slice(&0u16.to_be_bytes());

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("withdrawn_routes_len"),
            Some(&FieldValue::UInt16(5))
        );
        assert_eq!(result.get("withdrawn_count"), Some(&FieldValue::UInt16(2)));

        if let Some(FieldValue::OwnedString(routes)) = result.get("withdrawn_routes") {
            assert!(routes.contains("10.0.0.0/8"));
            assert!(routes.contains("192.168.0.0/16"));
        } else {
            panic!("Expected withdrawn_routes field");
        }
    }

    // Test 14: UPDATE message with path attributes
    #[test]
    fn test_update_with_path_attributes() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Build path attributes
        let mut path_attrs = Vec::new();

        // ORIGIN (type 1): IGP (0) - flags: well-known, transitive
        path_attrs.extend_from_slice(&[0x40, path_attr_type::ORIGIN, 1, origin_type::IGP]);

        // AS_PATH (type 2): AS_SEQUENCE with 2-byte ASNs [65001, 65002]
        path_attrs.extend_from_slice(&[
            0x40,
            path_attr_type::AS_PATH,
            6,
            as_path_segment_type::AS_SEQUENCE,
            2, // AS_SEQUENCE with 2 ASNs
            0xFD,
            0xE9, // 65001
            0xFD,
            0xEA, // 65002
        ]);

        // NEXT_HOP (type 3): 192.168.1.1
        path_attrs.extend_from_slice(&[0x40, path_attr_type::NEXT_HOP, 4, 192, 168, 1, 1]);

        // MED (type 4): 100
        path_attrs.extend_from_slice(&[0x80, path_attr_type::MULTI_EXIT_DISC, 4, 0, 0, 0, 100]);

        // LOCAL_PREF (type 5): 200
        path_attrs.extend_from_slice(&[0x40, path_attr_type::LOCAL_PREF, 4, 0, 0, 0, 200]);

        // Build message
        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        // Withdrawn routes length (0)
        msg.extend_from_slice(&0u16.to_be_bytes());

        // Path attribute length
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("origin"),
            Some(&FieldValue::UInt8(origin_type::IGP))
        );
        assert_eq!(result.get("origin_name"), Some(&FieldValue::Str("IGP")));
        assert_eq!(
            result.get("next_hop"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.1")))
        );
        assert_eq!(result.get("med"), Some(&FieldValue::UInt32(100)));
        assert_eq!(result.get("local_pref"), Some(&FieldValue::UInt32(200)));
        assert_eq!(result.get("as_path_length"), Some(&FieldValue::UInt16(2)));

        if let Some(FieldValue::OwnedString(as_path)) = result.get("as_path") {
            assert!(as_path.contains("65001"));
            assert!(as_path.contains("65002"));
        } else {
            panic!("Expected as_path field");
        }
    }

    // Test 15: UPDATE message with NLRI (advertised prefixes)
    #[test]
    fn test_update_with_nlri() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Minimal path attributes (ORIGIN + AS_PATH + NEXT_HOP required)
        let path_attrs = [
            0x40,
            path_attr_type::ORIGIN,
            1,
            origin_type::IGP,
            0x40,
            path_attr_type::AS_PATH,
            0, // Empty AS_PATH
            0x40,
            path_attr_type::NEXT_HOP,
            4,
            10,
            0,
            0,
            1,
        ];

        // NLRI: 172.16.0.0/12
        let nlri = [12, 172, 16]; // /12 prefix needs 2 bytes

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len() + nlri.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        msg.extend_from_slice(&0u16.to_be_bytes()); // No withdrawn
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);
        msg.extend_from_slice(&nlri);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("nlri_count"), Some(&FieldValue::UInt16(1)));

        if let Some(FieldValue::OwnedString(nlri_str)) = result.get("nlri") {
            assert!(nlri_str.contains("172.16.0.0/12"));
        } else {
            panic!("Expected nlri field");
        }
    }

    // Test 16: ROUTE-REFRESH message (RFC 2918)
    #[test]
    fn test_route_refresh_message() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let mut msg = create_bgp_header(message_type::ROUTE_REFRESH, 23); // 19 + 4

        // AFI = 1 (IPv4), Reserved = 0, SAFI = 1 (Unicast)
        msg.extend_from_slice(&1u16.to_be_bytes()); // AFI
        msg.push(0); // Reserved
        msg.push(1); // SAFI

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("message_type"),
            Some(&FieldValue::UInt8(message_type::ROUTE_REFRESH))
        );
        assert_eq!(
            result.get("message_type_name"),
            Some(&FieldValue::Str("ROUTE-REFRESH"))
        );
        assert_eq!(result.get("afi"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("safi"), Some(&FieldValue::UInt8(1)));
    }

    // Test 17: ROUTE-REFRESH for IPv6 multicast
    #[test]
    fn test_route_refresh_ipv6_multicast() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let mut msg = create_bgp_header(message_type::ROUTE_REFRESH, 23);

        // AFI = 2 (IPv6), SAFI = 2 (Multicast)
        msg.extend_from_slice(&2u16.to_be_bytes()); // AFI
        msg.push(0); // Reserved
        msg.push(2); // SAFI

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("afi"), Some(&FieldValue::UInt16(2)));
        assert_eq!(result.get("safi"), Some(&FieldValue::UInt8(2)));
    }

    // Test 18: AS_PATH with AS_SET segment
    #[test]
    fn test_as_path_with_as_set() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // AS_PATH with AS_SET {65001, 65002, 65003}
        let path_attrs = [
            0x40,
            path_attr_type::ORIGIN,
            1,
            origin_type::IGP,
            0x40,
            path_attr_type::AS_PATH,
            8,
            as_path_segment_type::AS_SET,
            3, // AS_SET with 3 ASNs
            0xFD,
            0xE9, // 65001
            0xFD,
            0xEA, // 65002
            0xFD,
            0xEB, // 65003
            0x40,
            path_attr_type::NEXT_HOP,
            4,
            10,
            0,
            0,
            1,
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        // AS_SET counts as 1 for path length
        assert_eq!(result.get("as_path_length"), Some(&FieldValue::UInt16(1)));

        if let Some(FieldValue::OwnedString(as_path)) = result.get("as_path") {
            // AS_SET should be formatted with braces
            assert!(as_path.contains("{"));
            assert!(as_path.contains("}"));
        } else {
            panic!("Expected as_path field");
        }
    }

    // Test 19: NOTIFICATION with error code and subcode
    #[test]
    fn test_notification_error_codes() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let test_cases = [
            (error_code::MESSAGE_HEADER_ERROR, 1, "Message Header Error"),
            (error_code::OPEN_MESSAGE_ERROR, 2, "OPEN Message Error"),
            (error_code::UPDATE_MESSAGE_ERROR, 1, "UPDATE Message Error"),
            (error_code::HOLD_TIMER_EXPIRED, 0, "Hold Timer Expired"),
            (error_code::FSM_ERROR, 0, "Finite State Machine Error"),
            (error_code::CEASE, 4, "Cease"), // Subcode 4 = Administrative Reset
        ];

        for (err_code, err_subcode, expected_name) in test_cases {
            let mut msg = create_bgp_header(message_type::NOTIFICATION, 21);
            msg.push(err_code);
            msg.push(err_subcode);

            let result = parser.parse(&msg, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("error_code"), Some(&FieldValue::UInt8(err_code)));
            assert_eq!(
                result.get("error_subcode"),
                Some(&FieldValue::UInt8(err_subcode))
            );
            assert_eq!(
                result.get("error_code_name"),
                Some(&FieldValue::Str(expected_name))
            );
        }
    }

    // Test 20: ATOMIC_AGGREGATE attribute
    #[test]
    fn test_atomic_aggregate_attribute() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let path_attrs = [
            0x40,
            path_attr_type::ORIGIN,
            1,
            origin_type::IGP,
            0x40,
            path_attr_type::AS_PATH,
            0,
            0x40,
            path_attr_type::NEXT_HOP,
            4,
            10,
            0,
            0,
            1,
            0x40,
            path_attr_type::ATOMIC_AGGREGATE,
            0, // Zero length
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("atomic_aggregate"),
            Some(&FieldValue::Bool(true))
        );
    }

    // Test 21: AGGREGATOR attribute
    #[test]
    fn test_aggregator_attribute() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // AGGREGATOR with 2-byte AS
        let path_attrs = [
            0x40,
            path_attr_type::ORIGIN,
            1,
            origin_type::IGP,
            0x40,
            path_attr_type::AS_PATH,
            0,
            0x40,
            path_attr_type::NEXT_HOP,
            4,
            10,
            0,
            0,
            1,
            0xC0,
            path_attr_type::AGGREGATOR,
            6, // Optional, Transitive
            0xFD,
            0xE9, // AS 65001
            192,
            168,
            1,
            1, // Aggregator IP
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("aggregator_as"),
            Some(&FieldValue::UInt32(65001))
        );
        assert_eq!(
            result.get("aggregator_ip"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.1")))
        );
    }

    // Test 22: Extended length path attribute
    #[test]
    fn test_extended_length_attribute() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        // Build a path with extended length flag
        let mut path_attrs = Vec::new();

        // ORIGIN with standard length
        path_attrs.extend_from_slice(&[0x40, path_attr_type::ORIGIN, 1, origin_type::EGP]);

        // AS_PATH with extended length flag (0x10)
        // Long AS_PATH with multiple ASNs
        path_attrs.push(0x50); // Transitive + Extended length
        path_attrs.push(path_attr_type::AS_PATH);
        path_attrs.extend_from_slice(&14u16.to_be_bytes()); // Length as 2 bytes
        path_attrs.push(as_path_segment_type::AS_SEQUENCE);
        path_attrs.push(6); // 6 ASNs
        for asn in [65001u16, 65002, 65003, 65004, 65005, 65006] {
            path_attrs.extend_from_slice(&asn.to_be_bytes());
        }

        // NEXT_HOP
        path_attrs.extend_from_slice(&[0x40, path_attr_type::NEXT_HOP, 4, 10, 0, 0, 1]);

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(
            result.get("origin"),
            Some(&FieldValue::UInt8(origin_type::EGP))
        );
        assert_eq!(result.get("origin_name"), Some(&FieldValue::Str("EGP")));
        assert_eq!(result.get("as_path_length"), Some(&FieldValue::UInt16(6)));
    }

    // Test 23: Multiple NLRI prefixes
    #[test]
    fn test_multiple_nlri_prefixes() {
        let parser = BgpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 179);

        let path_attrs = [
            0x40,
            path_attr_type::ORIGIN,
            1,
            origin_type::IGP,
            0x40,
            path_attr_type::AS_PATH,
            0,
            0x40,
            path_attr_type::NEXT_HOP,
            4,
            10,
            0,
            0,
            1,
        ];

        // Multiple NLRI: 10.0.0.0/8, 172.16.0.0/16, 192.168.1.0/24
        let nlri = [
            8, 10, // 10.0.0.0/8
            16, 172, 16, // 172.16.0.0/16
            24, 192, 168, 1, // 192.168.1.0/24
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(&BGP_MARKER);

        let total_len = 19 + 2 + 2 + path_attrs.len() + nlri.len();
        msg.extend_from_slice(&(total_len as u16).to_be_bytes());
        msg.push(message_type::UPDATE);

        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&path_attrs);
        msg.extend_from_slice(&nlri);

        let result = parser.parse(&msg, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("nlri_count"), Some(&FieldValue::UInt16(3)));

        if let Some(FieldValue::OwnedString(nlri_str)) = result.get("nlri") {
            assert!(nlri_str.contains("10.0.0.0/8"));
            assert!(nlri_str.contains("172.16.0.0/16"));
            assert!(nlri_str.contains("192.168.1.0/24"));
        } else {
            panic!("Expected nlri field");
        }
    }
}
