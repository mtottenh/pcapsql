//! OSPF (Open Shortest Path First) protocol parser.
//!
//! OSPF is a link-state routing protocol for IP networks that uses
//! a shortest path first (SPF) algorithm for finding the best path.
//!
//! RFC 2328: OSPF Version 2
//! RFC 5340: OSPF for IPv6

use std::collections::HashMap;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for OSPF.
pub const IP_PROTOCOL_OSPF: u8 = 89;

/// OSPF packet types.
pub mod packet_type {
    pub const HELLO: u8 = 1;
    pub const DATABASE_DESCRIPTION: u8 = 2;
    pub const LINK_STATE_REQUEST: u8 = 3;
    pub const LINK_STATE_UPDATE: u8 = 4;
    pub const LINK_STATE_ACK: u8 = 5;
}

/// OSPF LSA types (RFC 2328).
pub mod lsa_type {
    /// Router-LSA: Describes router's links within an area.
    pub const ROUTER: u8 = 1;
    /// Network-LSA: Describes transit network.
    pub const NETWORK: u8 = 2;
    /// Summary-LSA (IP network): Describes route to network.
    pub const SUMMARY_NETWORK: u8 = 3;
    /// Summary-LSA (ASBR): Describes route to ASBR.
    pub const SUMMARY_ASBR: u8 = 4;
    /// AS-External-LSA: Describes route to external network.
    pub const AS_EXTERNAL: u8 = 5;
}

/// Get the name of an LSA type.
fn lsa_type_name(ls_type: u8) -> &'static str {
    match ls_type {
        lsa_type::ROUTER => "Router-LSA",
        lsa_type::NETWORK => "Network-LSA",
        lsa_type::SUMMARY_NETWORK => "Summary-LSA-Network",
        lsa_type::SUMMARY_ASBR => "Summary-LSA-ASBR",
        lsa_type::AS_EXTERNAL => "AS-External-LSA",
        _ => "Unknown",
    }
}

/// Get the name of an OSPF packet type.
fn packet_type_name(pkt_type: u8) -> &'static str {
    match pkt_type {
        packet_type::HELLO => "Hello",
        packet_type::DATABASE_DESCRIPTION => "Database Description",
        packet_type::LINK_STATE_REQUEST => "Link State Request",
        packet_type::LINK_STATE_UPDATE => "Link State Update",
        packet_type::LINK_STATE_ACK => "Link State Acknowledgment",
        _ => "Unknown",
    }
}

/// OSPF protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct OspfProtocol;

impl Protocol for OspfProtocol {
    fn name(&self) -> &'static str {
        "ospf"
    }

    fn display_name(&self) -> &'static str {
        "OSPF"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when IP protocol hint equals 89
        match context.hint("ip_protocol") {
            Some(proto) if proto == IP_PROTOCOL_OSPF as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // OSPF header is 24 bytes minimum
        if data.len() < 24 {
            return ParseResult::error("OSPF header too short".to_string(), data);
        }

        let mut fields = HashMap::new();

        // Byte 0: Version
        let version = data[0];
        fields.insert("version", FieldValue::UInt8(version));

        // Byte 1: Type
        let msg_type = data[1];
        fields.insert("message_type", FieldValue::UInt8(msg_type));
        fields.insert(
            "message_type_name",
            FieldValue::String(packet_type_name(msg_type).to_string()),
        );

        // Bytes 2-3: Packet Length
        let length = u16::from_be_bytes([data[2], data[3]]);
        fields.insert("length", FieldValue::UInt16(length));

        // Bytes 4-7: Router ID
        let router_id = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
        fields.insert("router_id", FieldValue::String(router_id));

        // Bytes 8-11: Area ID
        let area_id = format!("{}.{}.{}.{}", data[8], data[9], data[10], data[11]);
        fields.insert("area_id", FieldValue::String(area_id));

        // Bytes 12-13: Checksum
        let checksum = u16::from_be_bytes([data[12], data[13]]);
        fields.insert("checksum", FieldValue::UInt16(checksum));

        // Bytes 14-15: AuType (Authentication Type)
        let auth_type = u16::from_be_bytes([data[14], data[15]]);
        fields.insert("auth_type", FieldValue::UInt16(auth_type));

        // Bytes 16-23: Authentication (8 bytes)
        // We skip detailed authentication parsing

        // Parse packet-specific fields
        let packet_data = if data.len() >= length as usize {
            &data[24..length as usize]
        } else {
            &data[24..]
        };

        match (msg_type, version) {
            (packet_type::HELLO, 2) => {
                self.parse_hello_v2(packet_data, &mut fields);
            }
            (packet_type::DATABASE_DESCRIPTION, 2) => {
                self.parse_db_description_v2(packet_data, &mut fields);
            }
            (packet_type::LINK_STATE_UPDATE, 2) => {
                self.parse_ls_update_v2(packet_data, &mut fields);
            }
            (packet_type::LINK_STATE_ACK, 2) => {
                self.parse_ls_ack_v2(packet_data, &mut fields);
            }
            _ => {
                // Unknown packet type or version
            }
        }

        // Calculate remaining data
        let consumed = std::cmp::min(length as usize, data.len());
        ParseResult::success(fields, &data[consumed..], HashMap::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            // Common header fields
            FieldDescriptor::new("ospf.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ospf.message_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ospf.message_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ospf.router_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.area_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.auth_type", DataKind::UInt16).set_nullable(true),
            // Hello packet fields
            FieldDescriptor::new("ospf.hello_interval", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ospf.dead_interval", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ospf.designated_router", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.backup_dr", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.neighbor_count", DataKind::UInt16).set_nullable(true),
            // Database Description fields
            FieldDescriptor::new("ospf.dd_interface_mtu", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ospf.dd_options", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ospf.dd_flags", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ospf.dd_sequence", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ospf.dd_lsa_count", DataKind::UInt16).set_nullable(true),
            // LS Update fields
            FieldDescriptor::new("ospf.lsu_lsa_count", DataKind::UInt32).set_nullable(true),
            // LSA header fields (from first LSA in LS Update/Ack)
            FieldDescriptor::new("ospf.lsa_age", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("ospf.lsa_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ospf.lsa_type_name", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.lsa_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.lsa_advertising_router", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ospf.lsa_sequence", DataKind::UInt32).set_nullable(true),
            // LS Ack fields
            FieldDescriptor::new("ospf.lsa_ack_count", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }
}

impl OspfProtocol {
    /// Parse OSPF v2 Hello packet.
    fn parse_hello_v2(&self, data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
        if data.len() < 20 {
            return;
        }

        // Bytes 0-3: Network Mask (skip)

        // Bytes 4-5: Hello Interval
        let hello_interval = u16::from_be_bytes([data[4], data[5]]);
        fields.insert("hello_interval", FieldValue::UInt16(hello_interval));

        // Bytes 6-7: Options and Router Priority (skip)

        // Bytes 8-11: Router Dead Interval
        let dead_interval = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        fields.insert("dead_interval", FieldValue::UInt32(dead_interval));

        // Bytes 12-15: Designated Router
        let dr = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
        fields.insert("designated_router", FieldValue::String(dr));

        // Bytes 16-19: Backup Designated Router
        let bdr = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
        fields.insert("backup_dr", FieldValue::String(bdr));

        // Count neighbors (remaining data is list of neighbor router IDs)
        let neighbor_data = &data[20..];
        let neighbor_count = (neighbor_data.len() / 4) as u16;
        if neighbor_count > 0 {
            fields.insert("neighbor_count", FieldValue::UInt16(neighbor_count));
        }
    }

    /// Parse OSPF v2 Database Description packet.
    fn parse_db_description_v2(&self, data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
        if data.len() < 8 {
            return;
        }

        // Bytes 0-1: Interface MTU
        let interface_mtu = u16::from_be_bytes([data[0], data[1]]);
        fields.insert("dd_interface_mtu", FieldValue::UInt16(interface_mtu));

        // Byte 2: Options
        let options = data[2];
        fields.insert("dd_options", FieldValue::UInt8(options));

        // Byte 3: DD Flags (I/M/MS bits)
        let dd_flags = data[3];
        fields.insert("dd_flags", FieldValue::UInt8(dd_flags));

        // Bytes 4-7: DD Sequence Number
        let dd_sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        fields.insert("dd_sequence", FieldValue::UInt32(dd_sequence));

        // LSA headers follow (each 20 bytes)
        let lsa_data = &data[8..];
        let lsa_count = (lsa_data.len() / 20) as u16;
        if lsa_count > 0 {
            fields.insert("dd_lsa_count", FieldValue::UInt16(lsa_count));
            // Parse the first LSA header
            self.parse_lsa_header(&lsa_data[..20.min(lsa_data.len())], fields);
        }
    }

    /// Parse OSPF v2 LS Update packet.
    fn parse_ls_update_v2(&self, data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
        if data.len() < 4 {
            return;
        }

        // Bytes 0-3: Number of LSAs
        let lsa_count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        fields.insert("lsu_lsa_count", FieldValue::UInt32(lsa_count));

        // LSAs follow (each with 20-byte header + variable body)
        if lsa_count > 0 && data.len() >= 24 {
            // Parse the first LSA header
            self.parse_lsa_header(&data[4..24], fields);
        }
    }

    /// Parse OSPF v2 LS Acknowledgment packet.
    fn parse_ls_ack_v2(&self, data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
        // LS Ack contains a list of LSA headers (each 20 bytes)
        let lsa_count = (data.len() / 20) as u16;
        if lsa_count > 0 {
            fields.insert("lsa_ack_count", FieldValue::UInt16(lsa_count));
            // Parse the first LSA header
            self.parse_lsa_header(&data[..20.min(data.len())], fields);
        }
    }

    /// Parse a single LSA header (20 bytes).
    ///
    /// LSA Header Format:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |            LS Age             |    Options    |    LS Type    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Link State ID                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                     Advertising Router                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                     LS Sequence Number                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         LS Checksum           |             Length            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_lsa_header(&self, data: &[u8], fields: &mut HashMap<&'static str, FieldValue>) {
        if data.len() < 20 {
            return;
        }

        // Bytes 0-1: LS Age
        let ls_age = u16::from_be_bytes([data[0], data[1]]);
        fields.insert("lsa_age", FieldValue::UInt16(ls_age));

        // Byte 2: Options (skip)
        // Byte 3: LS Type
        let ls_type = data[3];
        fields.insert("lsa_type", FieldValue::UInt8(ls_type));
        fields.insert("lsa_type_name", FieldValue::String(lsa_type_name(ls_type).to_string()));

        // Bytes 4-7: Link State ID
        let ls_id = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
        fields.insert("lsa_id", FieldValue::String(ls_id));

        // Bytes 8-11: Advertising Router
        let adv_router = format!("{}.{}.{}.{}", data[8], data[9], data[10], data[11]);
        fields.insert("lsa_advertising_router", FieldValue::String(adv_router));

        // Bytes 12-15: LS Sequence Number
        let ls_sequence = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        fields.insert("lsa_sequence", FieldValue::UInt32(ls_sequence));

        // Bytes 16-17: LS Checksum (skip)
        // Bytes 18-19: Length (skip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an OSPF v2 header.
    fn create_ospf_header(
        version: u8,
        msg_type: u8,
        length: u16,
        router_id: [u8; 4],
        area_id: [u8; 4],
    ) -> Vec<u8> {
        let mut header = Vec::new();

        // Version
        header.push(version);

        // Type
        header.push(msg_type);

        // Length
        header.extend_from_slice(&length.to_be_bytes());

        // Router ID
        header.extend_from_slice(&router_id);

        // Area ID
        header.extend_from_slice(&area_id);

        // Checksum
        header.extend_from_slice(&[0x00, 0x00]);

        // AuType
        header.extend_from_slice(&[0x00, 0x00]);

        // Authentication (8 bytes)
        header.extend_from_slice(&[0x00; 8]);

        header
    }

    /// Create an OSPF v2 Hello packet.
    fn create_ospf_hello(
        router_id: [u8; 4],
        area_id: [u8; 4],
        hello_interval: u16,
        dead_interval: u32,
        dr: [u8; 4],
        bdr: [u8; 4],
    ) -> Vec<u8> {
        let mut pkt = create_ospf_header(2, packet_type::HELLO, 44, router_id, area_id);

        // Network Mask
        pkt.extend_from_slice(&[255, 255, 255, 0]);

        // Hello Interval
        pkt.extend_from_slice(&hello_interval.to_be_bytes());

        // Options
        pkt.push(0x02);

        // Router Priority
        pkt.push(1);

        // Router Dead Interval
        pkt.extend_from_slice(&dead_interval.to_be_bytes());

        // Designated Router
        pkt.extend_from_slice(&dr);

        // Backup Designated Router
        pkt.extend_from_slice(&bdr);

        pkt
    }

    // Test 1: can_parse with IP protocol 89
    #[test]
    fn test_can_parse_with_ip_protocol_89() {
        let parser = OspfProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.hints.insert("ip_protocol", 6); // TCP
        assert!(parser.can_parse(&ctx2).is_none());

        // With OSPF protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.hints.insert("ip_protocol", 89);
        assert!(parser.can_parse(&ctx3).is_some());
        assert_eq!(parser.can_parse(&ctx3), Some(100));
    }

    // Test 2: OSPF header parsing
    #[test]
    fn test_ospf_header_parsing() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let pkt = create_ospf_header(
            2,
            packet_type::HELLO,
            24,
            [192, 168, 1, 1],
            [0, 0, 0, 0],
        );

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(packet_type::HELLO)));
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(24)));
    }

    // Test 3: Version detection (v2 vs v3)
    #[test]
    fn test_version_detection() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // OSPFv2
        let pkt_v2 = create_ospf_header(2, packet_type::HELLO, 24, [1, 1, 1, 1], [0, 0, 0, 0]);
        let result_v2 = parser.parse(&pkt_v2, &context);
        assert!(result_v2.is_ok());
        assert_eq!(result_v2.get("version"), Some(&FieldValue::UInt8(2)));

        // OSPFv3
        let pkt_v3 = create_ospf_header(3, packet_type::HELLO, 24, [1, 1, 1, 1], [0, 0, 0, 0]);
        let result_v3 = parser.parse(&pkt_v3, &context);
        assert!(result_v3.is_ok());
        assert_eq!(result_v3.get("version"), Some(&FieldValue::UInt8(3)));
    }

    // Test 4: Hello packet parsing
    #[test]
    fn test_hello_packet_parsing() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let pkt = create_ospf_hello(
            [192, 168, 1, 1],
            [0, 0, 0, 0],
            10,  // Hello interval
            40,  // Dead interval
            [192, 168, 1, 1],  // DR
            [192, 168, 1, 2],  // BDR
        );

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("hello_interval"), Some(&FieldValue::UInt16(10)));
        assert_eq!(result.get("dead_interval"), Some(&FieldValue::UInt32(40)));
        assert_eq!(result.get("designated_router"), Some(&FieldValue::String("192.168.1.1".to_string())));
        assert_eq!(result.get("backup_dr"), Some(&FieldValue::String("192.168.1.2".to_string())));
    }

    // Test 5: Router ID extraction
    #[test]
    fn test_router_id_extraction() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let pkt = create_ospf_header(
            2,
            packet_type::HELLO,
            24,
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("router_id"), Some(&FieldValue::String("10.0.0.1".to_string())));
    }

    // Test 6: Area ID extraction
    #[test]
    fn test_area_id_extraction() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Backbone area (0.0.0.0)
        let pkt1 = create_ospf_header(2, packet_type::HELLO, 24, [1, 1, 1, 1], [0, 0, 0, 0]);
        let result1 = parser.parse(&pkt1, &context);
        assert!(result1.is_ok());
        assert_eq!(result1.get("area_id"), Some(&FieldValue::String("0.0.0.0".to_string())));

        // Non-backbone area
        let pkt2 = create_ospf_header(2, packet_type::HELLO, 24, [1, 1, 1, 1], [0, 0, 0, 1]);
        let result2 = parser.parse(&pkt2, &context);
        assert!(result2.is_ok());
        assert_eq!(result2.get("area_id"), Some(&FieldValue::String("0.0.0.1".to_string())));
    }

    // Test 7: Message type name mapping
    #[test]
    fn test_message_type_name_mapping() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let test_types = [
            (packet_type::HELLO, "Hello"),
            (packet_type::DATABASE_DESCRIPTION, "Database Description"),
            (packet_type::LINK_STATE_REQUEST, "Link State Request"),
            (packet_type::LINK_STATE_UPDATE, "Link State Update"),
            (packet_type::LINK_STATE_ACK, "Link State Acknowledgment"),
        ];

        for (pkt_type, name) in test_types {
            let pkt = create_ospf_header(2, pkt_type, 24, [1, 1, 1, 1], [0, 0, 0, 0]);
            let result = parser.parse(&pkt, &context);

            assert!(result.is_ok());
            assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(pkt_type)));
            assert_eq!(result.get("message_type_name"), Some(&FieldValue::String(name.to_string())));
        }
    }

    // Test 8: Too short packet
    #[test]
    fn test_ospf_too_short() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let short_pkt = [2u8, 1, 0, 24]; // Only 4 bytes
        let result = parser.parse(&short_pkt, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 9: Authentication type
    #[test]
    fn test_auth_type() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let mut pkt = create_ospf_header(2, packet_type::HELLO, 24, [1, 1, 1, 1], [0, 0, 0, 0]);
        // Set auth type to MD5 (2)
        pkt[14] = 0;
        pkt[15] = 2;

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("auth_type"), Some(&FieldValue::UInt16(2)));
    }

    // Test 10: Schema fields
    #[test]
    fn test_ospf_schema_fields() {
        let parser = OspfProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"ospf.version"));
        assert!(field_names.contains(&"ospf.message_type"));
        assert!(field_names.contains(&"ospf.message_type_name"));
        assert!(field_names.contains(&"ospf.length"));
        assert!(field_names.contains(&"ospf.router_id"));
        assert!(field_names.contains(&"ospf.area_id"));
        assert!(field_names.contains(&"ospf.auth_type"));
        assert!(field_names.contains(&"ospf.hello_interval"));
        assert!(field_names.contains(&"ospf.dead_interval"));
        assert!(field_names.contains(&"ospf.designated_router"));
        assert!(field_names.contains(&"ospf.backup_dr"));
    }

    // Test 11: Database Description parsing
    #[test]
    fn test_database_description_parsing() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build DD packet
        let mut pkt = create_ospf_header(
            2,
            packet_type::DATABASE_DESCRIPTION,
            32,
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        // DD specific fields
        pkt.extend_from_slice(&1500u16.to_be_bytes()); // Interface MTU
        pkt.push(0x02); // Options
        pkt.push(0x07); // DD Flags (I/M/MS all set)
        pkt.extend_from_slice(&0x12345678u32.to_be_bytes()); // DD Sequence

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("dd_interface_mtu"), Some(&FieldValue::UInt16(1500)));
        assert_eq!(result.get("dd_options"), Some(&FieldValue::UInt8(0x02)));
        assert_eq!(result.get("dd_flags"), Some(&FieldValue::UInt8(0x07)));
        assert_eq!(result.get("dd_sequence"), Some(&FieldValue::UInt32(0x12345678)));
    }

    // Test 12: Database Description with LSA headers
    #[test]
    fn test_database_description_with_lsa() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build DD packet
        let mut pkt = create_ospf_header(
            2,
            packet_type::DATABASE_DESCRIPTION,
            52, // 24 header + 8 DD + 20 LSA header
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        // DD specific fields
        pkt.extend_from_slice(&1500u16.to_be_bytes()); // Interface MTU
        pkt.push(0x02); // Options
        pkt.push(0x01); // DD Flags (MS only)
        pkt.extend_from_slice(&1u32.to_be_bytes()); // DD Sequence

        // LSA Header (20 bytes)
        pkt.extend_from_slice(&100u16.to_be_bytes()); // LS Age = 100
        pkt.push(0x00); // Options
        pkt.push(lsa_type::ROUTER); // LS Type = Router-LSA
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Link State ID
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Advertising Router
        pkt.extend_from_slice(&0x80000001u32.to_be_bytes()); // LS Sequence
        pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
        pkt.extend_from_slice(&36u16.to_be_bytes()); // Length

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("dd_lsa_count"), Some(&FieldValue::UInt16(1)));
        assert_eq!(result.get("lsa_age"), Some(&FieldValue::UInt16(100)));
        assert_eq!(result.get("lsa_type"), Some(&FieldValue::UInt8(lsa_type::ROUTER)));
        assert_eq!(result.get("lsa_type_name"), Some(&FieldValue::String("Router-LSA".to_string())));
    }

    // Test 13: LS Update parsing
    #[test]
    fn test_ls_update_parsing() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build LS Update packet
        let mut pkt = create_ospf_header(
            2,
            packet_type::LINK_STATE_UPDATE,
            48, // 24 header + 4 count + 20 LSA header
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        // Number of LSAs
        pkt.extend_from_slice(&2u32.to_be_bytes()); // 2 LSAs

        // First LSA Header (20 bytes)
        pkt.extend_from_slice(&500u16.to_be_bytes()); // LS Age
        pkt.push(0x00); // Options
        pkt.push(lsa_type::NETWORK); // LS Type = Network-LSA
        pkt.extend_from_slice(&[192, 168, 1, 0]); // Link State ID
        pkt.extend_from_slice(&[192, 168, 1, 1]); // Advertising Router
        pkt.extend_from_slice(&0x80000002u32.to_be_bytes()); // LS Sequence
        pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
        pkt.extend_from_slice(&32u16.to_be_bytes()); // Length

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("lsu_lsa_count"), Some(&FieldValue::UInt32(2)));
        assert_eq!(result.get("lsa_age"), Some(&FieldValue::UInt16(500)));
        assert_eq!(result.get("lsa_type"), Some(&FieldValue::UInt8(lsa_type::NETWORK)));
        assert_eq!(result.get("lsa_type_name"), Some(&FieldValue::String("Network-LSA".to_string())));
        assert_eq!(result.get("lsa_id"), Some(&FieldValue::String("192.168.1.0".to_string())));
        assert_eq!(result.get("lsa_advertising_router"), Some(&FieldValue::String("192.168.1.1".to_string())));
    }

    // Test 14: LS Acknowledgment parsing
    #[test]
    fn test_ls_ack_parsing() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build LS Ack packet
        let mut pkt = create_ospf_header(
            2,
            packet_type::LINK_STATE_ACK,
            64, // 24 header + 40 (2 LSA headers)
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        // First LSA Header (20 bytes)
        pkt.extend_from_slice(&200u16.to_be_bytes()); // LS Age
        pkt.push(0x00); // Options
        pkt.push(lsa_type::AS_EXTERNAL); // LS Type = AS-External-LSA
        pkt.extend_from_slice(&[0, 0, 0, 0]); // Link State ID
        pkt.extend_from_slice(&[172, 16, 0, 1]); // Advertising Router
        pkt.extend_from_slice(&0x80000010u32.to_be_bytes()); // LS Sequence
        pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
        pkt.extend_from_slice(&36u16.to_be_bytes()); // Length

        // Second LSA Header (20 bytes)
        pkt.extend_from_slice(&300u16.to_be_bytes()); // LS Age
        pkt.push(0x00); // Options
        pkt.push(lsa_type::SUMMARY_NETWORK); // LS Type
        pkt.extend_from_slice(&[10, 1, 0, 0]); // Link State ID
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Advertising Router
        pkt.extend_from_slice(&0x80000005u32.to_be_bytes()); // LS Sequence
        pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
        pkt.extend_from_slice(&28u16.to_be_bytes()); // Length

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("lsa_ack_count"), Some(&FieldValue::UInt16(2)));
        // First LSA header fields
        assert_eq!(result.get("lsa_age"), Some(&FieldValue::UInt16(200)));
        assert_eq!(result.get("lsa_type"), Some(&FieldValue::UInt8(lsa_type::AS_EXTERNAL)));
        assert_eq!(result.get("lsa_type_name"), Some(&FieldValue::String("AS-External-LSA".to_string())));
    }

    // Test 15: LSA type names
    #[test]
    fn test_lsa_type_names() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        let test_cases = [
            (lsa_type::ROUTER, "Router-LSA"),
            (lsa_type::NETWORK, "Network-LSA"),
            (lsa_type::SUMMARY_NETWORK, "Summary-LSA-Network"),
            (lsa_type::SUMMARY_ASBR, "Summary-LSA-ASBR"),
            (lsa_type::AS_EXTERNAL, "AS-External-LSA"),
        ];

        for (ls_type, expected_name) in test_cases {
            let mut pkt = create_ospf_header(
                2,
                packet_type::LINK_STATE_UPDATE,
                48,
                [10, 0, 0, 1],
                [0, 0, 0, 0],
            );

            pkt.extend_from_slice(&1u32.to_be_bytes()); // 1 LSA

            // LSA Header
            pkt.extend_from_slice(&100u16.to_be_bytes()); // LS Age
            pkt.push(0x00); // Options
            pkt.push(ls_type); // LS Type
            pkt.extend_from_slice(&[10, 0, 0, 0]); // Link State ID
            pkt.extend_from_slice(&[10, 0, 0, 1]); // Advertising Router
            pkt.extend_from_slice(&0x80000001u32.to_be_bytes()); // LS Sequence
            pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
            pkt.extend_from_slice(&20u16.to_be_bytes()); // Length

            let result = parser.parse(&pkt, &context);
            assert!(result.is_ok());
            assert_eq!(result.get("lsa_type"), Some(&FieldValue::UInt8(ls_type)));
            assert_eq!(result.get("lsa_type_name"), Some(&FieldValue::String(expected_name.to_string())));
        }
    }

    // Test 16: LSA sequence number
    #[test]
    fn test_lsa_sequence_number() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build LS Update with specific sequence number
        let mut pkt = create_ospf_header(
            2,
            packet_type::LINK_STATE_UPDATE,
            48,
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        pkt.extend_from_slice(&1u32.to_be_bytes()); // 1 LSA

        // LSA Header with specific sequence 0x80001234
        pkt.extend_from_slice(&100u16.to_be_bytes()); // LS Age
        pkt.push(0x00); // Options
        pkt.push(lsa_type::ROUTER); // LS Type
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Link State ID
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Advertising Router
        pkt.extend_from_slice(&0x80001234u32.to_be_bytes()); // LS Sequence
        pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
        pkt.extend_from_slice(&20u16.to_be_bytes()); // Length

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("lsa_sequence"), Some(&FieldValue::UInt32(0x80001234)));
    }

    // Test 17: Hello with neighbors
    #[test]
    fn test_hello_with_neighbors() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build Hello packet with 3 neighbors
        // Need to manually create header with correct length (44 base + 12 neighbors = 56)
        let mut pkt = create_ospf_header(
            2,
            packet_type::HELLO,
            56, // 24 header + 20 hello + 12 neighbors
            [192, 168, 1, 1],
            [0, 0, 0, 0],
        );

        // Network Mask
        pkt.extend_from_slice(&[255, 255, 255, 0]);
        // Hello Interval
        pkt.extend_from_slice(&10u16.to_be_bytes());
        // Options
        pkt.push(0x02);
        // Router Priority
        pkt.push(1);
        // Router Dead Interval
        pkt.extend_from_slice(&40u32.to_be_bytes());
        // Designated Router
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        // Backup Designated Router
        pkt.extend_from_slice(&[192, 168, 1, 2]);

        // Add neighbor router IDs
        pkt.extend_from_slice(&[192, 168, 1, 2]); // Neighbor 1
        pkt.extend_from_slice(&[192, 168, 1, 3]); // Neighbor 2
        pkt.extend_from_slice(&[192, 168, 1, 4]); // Neighbor 3

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("neighbor_count"), Some(&FieldValue::UInt16(3)));
    }

    // Test 18: LS Age field in LSA
    #[test]
    fn test_lsa_age_field() {
        let parser = OspfProtocol;
        let mut context = ParseContext::new(1);
        context.hints.insert("ip_protocol", 89);

        // Build LS Update with specific LS Age
        let mut pkt = create_ospf_header(
            2,
            packet_type::LINK_STATE_UPDATE,
            48,
            [10, 0, 0, 1],
            [0, 0, 0, 0],
        );

        pkt.extend_from_slice(&1u32.to_be_bytes()); // 1 LSA

        // LSA Header with LS Age = 1800 (halfway to MaxAge)
        pkt.extend_from_slice(&1800u16.to_be_bytes()); // LS Age
        pkt.push(0x00); // Options
        pkt.push(lsa_type::ROUTER); // LS Type
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Link State ID
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Advertising Router
        pkt.extend_from_slice(&0x80000001u32.to_be_bytes()); // LS Sequence
        pkt.extend_from_slice(&[0x00, 0x00]); // LS Checksum
        pkt.extend_from_slice(&20u16.to_be_bytes()); // Length

        let result = parser.parse(&pkt, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("lsa_age"), Some(&FieldValue::UInt16(1800)));
    }
}
