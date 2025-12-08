//! DHCP protocol parser.
//!
//! Parses DHCP (Dynamic Host Configuration Protocol) messages used for
//! network configuration. Matches on UDP ports 67/68 and the DHCP magic cookie.

use compact_str::CompactString;
use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// DHCP server port.
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP magic cookie (0x63825363).
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// DHCP minimum header size (without options).
const DHCP_MIN_HEADER_SIZE: usize = 236;

/// DHCP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct DhcpProtocol;

impl Protocol for DhcpProtocol {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn display_name(&self) -> &'static str {
        "DHCP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Check for DHCP ports (67 or 68) in either direction
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        match (src_port, dst_port) {
            (Some(67), _) | (_, Some(67)) | (Some(68), _) | (_, Some(68)) => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // DHCP header is at least 236 bytes
        if data.len() < DHCP_MIN_HEADER_SIZE {
            return ParseResult::error("DHCP header too short".to_string(), data);
        }

        // Check for DHCP magic cookie at offset 236
        if data.len() >= 240 && data[236..240] != DHCP_MAGIC_COOKIE {
            return ParseResult::error(
                "DHCP magic cookie not found (might be BOOTP)".to_string(),
                data,
            );
        }

        let mut fields = SmallVec::new();

        // Parse fixed header fields
        // Op (1 byte): 1 = BOOTREQUEST, 2 = BOOTREPLY
        let op = data[0];
        fields.push(("op", FieldValue::UInt8(op)));

        // Hardware type (1 byte): 1 = Ethernet
        let htype = data[1];
        fields.push(("htype", FieldValue::UInt8(htype)));

        // Hardware address length (1 byte)
        let hlen = data[2];
        fields.push(("hlen", FieldValue::UInt8(hlen)));

        // Hops (1 byte)
        let hops = data[3];
        fields.push(("hops", FieldValue::UInt8(hops)));

        // Transaction ID (4 bytes)
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        fields.push(("xid", FieldValue::UInt32(xid)));

        // Seconds elapsed (2 bytes)
        let secs = u16::from_be_bytes([data[8], data[9]]);
        fields.push(("secs", FieldValue::UInt16(secs)));

        // Flags (2 bytes)
        let flags = u16::from_be_bytes([data[10], data[11]]);
        fields.push(("flags", FieldValue::UInt16(flags)));

        // Client IP address (4 bytes)
        let ciaddr = format_ip(&data[12..16]);
        fields.push(("ciaddr", FieldValue::OwnedString(CompactString::new(ciaddr))));

        // Your (client) IP address (4 bytes)
        let yiaddr = format_ip(&data[16..20]);
        fields.push(("yiaddr", FieldValue::OwnedString(CompactString::new(yiaddr))));

        // Server IP address (4 bytes)
        let siaddr = format_ip(&data[20..24]);
        fields.push(("siaddr", FieldValue::OwnedString(CompactString::new(siaddr))));

        // Gateway/relay IP address (4 bytes)
        let giaddr = format_ip(&data[24..28]);
        fields.push(("giaddr", FieldValue::OwnedString(CompactString::new(giaddr))));

        // Client hardware address (16 bytes, but only first hlen are valid)
        let chaddr_len = (hlen as usize).min(16);
        let chaddr = format_mac(&data[28..28 + chaddr_len]);
        fields.push(("chaddr", FieldValue::OwnedString(CompactString::new(chaddr))));

        // Skip server host name (64 bytes) and boot file name (128 bytes)
        // These are at offsets 44 and 108 respectively

        // Parse options (starting at offset 240, after magic cookie)
        if data.len() > 240 {
            parse_dhcp_options(&data[240..], &mut fields);
        }

        // No child protocols after DHCP
        ParseResult::success(fields, &[], SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("dhcp.op", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dhcp.htype", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dhcp.hlen", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dhcp.hops", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dhcp.xid", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("dhcp.secs", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dhcp.flags", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("dhcp.ciaddr", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.yiaddr", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.siaddr", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.giaddr", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.chaddr", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.message_type", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("dhcp.server_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.lease_time", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("dhcp.subnet_mask", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.router", DataKind::String).set_nullable(true),
            FieldDescriptor::new("dhcp.dns_servers", DataKind::String).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["udp"]
    }
}

/// Format an IP address from 4 bytes.
fn format_ip(bytes: &[u8]) -> String {
    if bytes.len() >= 4 {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        "0.0.0.0".to_string()
    }
}

/// Format a MAC address from bytes.
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse DHCP options and add relevant fields.
fn parse_dhcp_options(data: &[u8], fields: &mut SmallVec<[(&'static str, FieldValue); 16]>) {
    let mut offset = 0;

    while offset < data.len() {
        let option_code = data[offset];

        // Option 0: Pad
        if option_code == 0 {
            offset += 1;
            continue;
        }

        // Option 255: End
        if option_code == 255 {
            break;
        }

        // Other options have length byte
        if offset + 1 >= data.len() {
            break;
        }
        let option_len = data[offset + 1] as usize;

        if offset + 2 + option_len > data.len() {
            break;
        }

        let option_data = &data[offset + 2..offset + 2 + option_len];

        match option_code {
            // Option 1: Subnet Mask
            1 if option_len == 4 => {
                fields.push(("subnet_mask", FieldValue::OwnedString(CompactString::new(format_ip(option_data)))));
            }
            // Option 3: Router
            3 if option_len >= 4 => {
                // Can have multiple routers, just use first one
                fields.push(("router", FieldValue::OwnedString(CompactString::new(format_ip(&option_data[..4])))));
            }
            // Option 6: DNS Servers
            6 if option_len >= 4 => {
                let dns_servers: Vec<String> = option_data
                    .chunks(4)
                    .filter(|chunk| chunk.len() == 4)
                    .map(format_ip)
                    .collect();
                fields.push(("dns_servers", FieldValue::OwnedString(CompactString::new(dns_servers.join(",")))));
            }
            // Option 51: IP Address Lease Time
            51 if option_len == 4 => {
                let lease_time = u32::from_be_bytes([
                    option_data[0],
                    option_data[1],
                    option_data[2],
                    option_data[3],
                ]);
                fields.push(("lease_time", FieldValue::UInt32(lease_time)));
            }
            // Option 53: DHCP Message Type
            53 if option_len == 1 => {
                fields.push(("message_type", FieldValue::UInt8(option_data[0])));
            }
            // Option 54: Server Identifier
            54 if option_len == 4 => {
                fields.push(("server_id", FieldValue::OwnedString(CompactString::new(format_ip(option_data)))));
            }
            _ => {}
        }

        offset += 2 + option_len;
    }
}

/// DHCP message types.
#[allow(dead_code)]
pub mod message_type {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal DHCP Discover packet.
    fn create_dhcp_discover() -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        // Op: BOOTREQUEST (1)
        packet[0] = 1;
        // Hardware type: Ethernet (1)
        packet[1] = 1;
        // Hardware address length: 6
        packet[2] = 6;
        // Hops: 0
        packet[3] = 0;
        // Transaction ID
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        // Seconds: 0
        packet[8..10].copy_from_slice(&0u16.to_be_bytes());
        // Flags: Broadcast (0x8000)
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        // Client IP: 0.0.0.0
        // Your IP: 0.0.0.0
        // Server IP: 0.0.0.0
        // Gateway IP: 0.0.0.0
        // Client MAC: 00:11:22:33:44:55
        packet[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Magic cookie at offset 236
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        // Options start at 240
        // Option 53: DHCP Message Type = Discover (1)
        packet[240] = 53;
        packet[241] = 1;
        packet[242] = message_type::DISCOVER;

        // Option 255: End
        packet[243] = 255;

        packet
    }

    /// Create a DHCP Offer packet with common options.
    fn create_dhcp_offer() -> Vec<u8> {
        let mut packet = vec![0u8; 350];

        // Op: BOOTREPLY (2)
        packet[0] = 2;
        // Hardware type: Ethernet (1)
        packet[1] = 1;
        // Hardware address length: 6
        packet[2] = 6;
        // Hops: 0
        packet[3] = 0;
        // Transaction ID
        packet[4..8].copy_from_slice(&0xABCDEF01u32.to_be_bytes());
        // Seconds: 0
        packet[8..10].copy_from_slice(&0u16.to_be_bytes());
        // Flags: 0
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());
        // Client IP: 0.0.0.0
        // Your IP: 192.168.1.100
        packet[16..20].copy_from_slice(&[192, 168, 1, 100]);
        // Server IP: 192.168.1.1
        packet[20..24].copy_from_slice(&[192, 168, 1, 1]);
        // Gateway IP: 0.0.0.0
        // Client MAC: 00:11:22:33:44:55
        packet[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Magic cookie at offset 236
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        let mut opt_offset = 240;

        // Option 53: DHCP Message Type = Offer (2)
        packet[opt_offset] = 53;
        packet[opt_offset + 1] = 1;
        packet[opt_offset + 2] = message_type::OFFER;
        opt_offset += 3;

        // Option 54: Server Identifier = 192.168.1.1
        packet[opt_offset] = 54;
        packet[opt_offset + 1] = 4;
        packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&[192, 168, 1, 1]);
        opt_offset += 6;

        // Option 51: Lease Time = 86400 seconds (1 day)
        packet[opt_offset] = 51;
        packet[opt_offset + 1] = 4;
        packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&86400u32.to_be_bytes());
        opt_offset += 6;

        // Option 1: Subnet Mask = 255.255.255.0
        packet[opt_offset] = 1;
        packet[opt_offset + 1] = 4;
        packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&[255, 255, 255, 0]);
        opt_offset += 6;

        // Option 3: Router = 192.168.1.1
        packet[opt_offset] = 3;
        packet[opt_offset + 1] = 4;
        packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&[192, 168, 1, 1]);
        opt_offset += 6;

        // Option 6: DNS Servers = 8.8.8.8, 8.8.4.4
        packet[opt_offset] = 6;
        packet[opt_offset + 1] = 8;
        packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&[8, 8, 8, 8]);
        packet[opt_offset + 6..opt_offset + 10].copy_from_slice(&[8, 8, 4, 4]);
        opt_offset += 10;

        // Option 255: End
        packet[opt_offset] = 255;

        packet
    }

    /// Create a DHCP ACK packet.
    fn create_dhcp_ack() -> Vec<u8> {
        let mut packet = create_dhcp_offer();
        // Change message type to ACK
        packet[242] = message_type::ACK;
        packet
    }

    #[test]
    fn test_can_parse_dhcp() {
        let parser = DhcpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With dst_port 67 (server)
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("dst_port", 67);
        assert!(parser.can_parse(&ctx2).is_some());

        // With src_port 68 (client)
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("src_port", 68);
        assert!(parser.can_parse(&ctx3).is_some());

        // With different port
        let mut ctx4 = ParseContext::new(1);
        ctx4.insert_hint("dst_port", 80);
        assert!(parser.can_parse(&ctx4).is_none());
    }

    #[test]
    fn test_parse_dhcp_discover() {
        let packet = create_dhcp_discover();

        let parser = DhcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 67);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("op"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.get("htype"), Some(&FieldValue::UInt8(1)));
        assert_eq!(result.get("hlen"), Some(&FieldValue::UInt8(6)));
        assert_eq!(result.get("xid"), Some(&FieldValue::UInt32(0x12345678)));
        assert_eq!(result.get("flags"), Some(&FieldValue::UInt16(0x8000)));
        assert_eq!(
            result.get("chaddr"),
            Some(&FieldValue::OwnedString(CompactString::new("00:11:22:33:44:55")))
        );
        assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(1)));
    }

    #[test]
    fn test_parse_dhcp_offer() {
        let packet = create_dhcp_offer();

        let parser = DhcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 67);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("op"), Some(&FieldValue::UInt8(2)));
        assert_eq!(result.get("xid"), Some(&FieldValue::UInt32(0xABCDEF01)));
        assert_eq!(
            result.get("yiaddr"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.100")))
        );
        assert_eq!(
            result.get("siaddr"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.1")))
        );
        assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(2)));
        assert_eq!(
            result.get("server_id"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.1")))
        );
    }

    #[test]
    fn test_parse_dhcp_ack() {
        let packet = create_dhcp_ack();

        let parser = DhcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 67);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("message_type"), Some(&FieldValue::UInt8(5)));
    }

    #[test]
    fn test_parse_dhcp_options() {
        let packet = create_dhcp_offer();

        let parser = DhcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 67);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("lease_time"), Some(&FieldValue::UInt32(86400)));
        assert_eq!(
            result.get("subnet_mask"),
            Some(&FieldValue::OwnedString(CompactString::new("255.255.255.0")))
        );
        assert_eq!(
            result.get("router"),
            Some(&FieldValue::OwnedString(CompactString::new("192.168.1.1")))
        );
        assert_eq!(
            result.get("dns_servers"),
            Some(&FieldValue::OwnedString(CompactString::new("8.8.8.8,8.8.4.4")))
        );
    }

    #[test]
    fn test_dhcp_schema_fields() {
        let parser = DhcpProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"dhcp.op"));
        assert!(field_names.contains(&"dhcp.xid"));
        assert!(field_names.contains(&"dhcp.message_type"));
        assert!(field_names.contains(&"dhcp.lease_time"));
    }

    #[test]
    fn test_dhcp_too_short() {
        let short_packet = vec![0u8; 100]; // Too short for DHCP

        let parser = DhcpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 67);

        let result = parser.parse(&short_packet, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }
}
