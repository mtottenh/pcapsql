//! NTP protocol parser.
//!
//! Parses NTP (Network Time Protocol) messages used for time synchronization.
//! Matches on UDP port 123.

use compact_str::CompactString;
use smallvec::SmallVec;

use super::{FieldValue, ParseContext, ParseResult, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// NTP port.
pub const NTP_PORT: u16 = 123;

/// NTP header size.
const NTP_HEADER_SIZE: usize = 48;

/// NTP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct NtpProtocol;

impl Protocol for NtpProtocol {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn display_name(&self) -> &'static str {
        "NTP"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Check for NTP port
        let src_port = context.hint("src_port");
        let dst_port = context.hint("dst_port");

        match (src_port, dst_port) {
            (Some(p), _) | (_, Some(p)) if p == NTP_PORT as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], _context: &ParseContext) -> ParseResult<'a> {
        // NTP header is 48 bytes
        if data.len() < NTP_HEADER_SIZE {
            return ParseResult::error("NTP header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        // First byte: LI (2 bits), VN (3 bits), Mode (3 bits)
        let first_byte = data[0];
        let li = (first_byte >> 6) & 0x03; // Leap Indicator
        let version = (first_byte >> 3) & 0x07; // Version Number
        let mode = first_byte & 0x07; // Mode

        fields.push(("version", FieldValue::UInt8(version)));
        fields.push(("mode", FieldValue::UInt8(mode)));
        fields.push(("leap_indicator", FieldValue::UInt8(li)));

        // Second byte: Stratum
        let stratum = data[1];
        fields.push(("stratum", FieldValue::UInt8(stratum)));

        // Third byte: Poll (signed, log2 seconds)
        let poll = data[2] as i8;
        fields.push(("poll", FieldValue::UInt8(poll as u8)));

        // Fourth byte: Precision (signed, log2 seconds)
        let precision = data[3] as i8;
        fields.push(("precision", FieldValue::UInt8(precision as u8)));

        // Root Delay (4 bytes, signed fixed-point)
        let root_delay = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        fields.push(("root_delay", FieldValue::UInt32(root_delay)));

        // Root Dispersion (4 bytes, unsigned fixed-point)
        let root_dispersion = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        fields.push(("root_dispersion", FieldValue::UInt32(root_dispersion)));

        // Reference ID (4 bytes) - meaning depends on stratum
        let ref_id_bytes = &data[12..16];
        let reference_id = if stratum == 0 || stratum == 1 {
            // For stratum 0-1, it's ASCII (e.g., "GPS", "PPS")
            CompactString::new(String::from_utf8_lossy(ref_id_bytes).trim_end_matches('\0'))
        } else {
            // For stratum 2+, it's an IP address
            CompactString::new(format!(
                "{}.{}.{}.{}",
                ref_id_bytes[0], ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3]
            ))
        };
        fields.push(("reference_id", FieldValue::OwnedString(reference_id)));

        // Reference Timestamp (8 bytes) - NTP format
        let reference_ts = read_ntp_timestamp(&data[16..24]);
        fields.push(("reference_ts", FieldValue::Int64(reference_ts)));

        // Origin Timestamp (8 bytes)
        let origin_ts = read_ntp_timestamp(&data[24..32]);
        fields.push(("origin_ts", FieldValue::Int64(origin_ts)));

        // Receive Timestamp (8 bytes)
        let receive_ts = read_ntp_timestamp(&data[32..40]);
        fields.push(("receive_ts", FieldValue::Int64(receive_ts)));

        // Transmit Timestamp (8 bytes)
        let transmit_ts = read_ntp_timestamp(&data[40..48]);
        fields.push(("transmit_ts", FieldValue::Int64(transmit_ts)));

        // Any remaining data would be extension fields or authentication
        let remaining = &data[NTP_HEADER_SIZE..];

        ParseResult::success(fields, remaining, SmallVec::new())
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("ntp.version", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ntp.mode", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ntp.leap_indicator", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ntp.stratum", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ntp.poll", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ntp.precision", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ntp.root_delay", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ntp.root_dispersion", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ntp.reference_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ntp.reference_ts", DataKind::Int64).set_nullable(true),
            FieldDescriptor::new("ntp.origin_ts", DataKind::Int64).set_nullable(true),
            FieldDescriptor::new("ntp.receive_ts", DataKind::Int64).set_nullable(true),
            FieldDescriptor::new("ntp.transmit_ts", DataKind::Int64).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &[]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["udp"]
    }
}

/// Read an NTP timestamp (8 bytes) and return as i64 (seconds since 1900).
/// NTP timestamp: 32-bit seconds + 32-bit fraction.
fn read_ntp_timestamp(data: &[u8]) -> i64 {
    if data.len() < 8 {
        return 0;
    }
    let seconds = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    // We're ignoring the fractional part for simplicity
    seconds as i64
}

/// NTP modes.
#[allow(dead_code)]
pub mod mode {
    pub const RESERVED: u8 = 0;
    pub const SYMMETRIC_ACTIVE: u8 = 1;
    pub const SYMMETRIC_PASSIVE: u8 = 2;
    pub const CLIENT: u8 = 3;
    pub const SERVER: u8 = 4;
    pub const BROADCAST: u8 = 5;
    pub const CONTROL: u8 = 6;
    pub const PRIVATE: u8 = 7;
}

/// NTP stratum levels.
#[allow(dead_code)]
pub mod stratum {
    pub const UNSPECIFIED: u8 = 0;
    pub const PRIMARY: u8 = 1;
    // 2-15: Secondary reference (via NTP)
    pub const UNSYNCHRONIZED: u8 = 16;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an NTP client request packet.
    fn create_ntp_client_request() -> Vec<u8> {
        let mut packet = vec![0u8; 48];

        // LI=0, VN=4, Mode=3 (client)
        packet[0] = 0x23; // 0b00100011

        // Stratum: 0 (unspecified)
        packet[1] = 0;

        // Poll: 6 (64 seconds)
        packet[2] = 6;

        // Precision: -20
        packet[3] = 0xEC; // -20 as signed byte

        // Root Delay: 0
        // Root Dispersion: 0
        // Reference ID: 0
        // All timestamps: 0 for client request

        packet
    }

    /// Create an NTP server response packet.
    fn create_ntp_server_response() -> Vec<u8> {
        let mut packet = vec![0u8; 48];

        // LI=0, VN=4, Mode=4 (server)
        packet[0] = 0x24; // 0b00100100

        // Stratum: 1 (primary)
        packet[1] = 1;

        // Poll: 6
        packet[2] = 6;

        // Precision: -20
        packet[3] = 0xEC;

        // Root Delay: some small value
        packet[4..8].copy_from_slice(&0x00000100u32.to_be_bytes());

        // Root Dispersion: some small value
        packet[8..12].copy_from_slice(&0x00000200u32.to_be_bytes());

        // Reference ID: "GPS\0" for stratum 1
        packet[12..16].copy_from_slice(b"GPS\0");

        // Reference timestamp: some NTP time
        packet[16..20].copy_from_slice(&0xE1B23456u32.to_be_bytes());

        // Origin timestamp
        packet[24..28].copy_from_slice(&0xE1B23460u32.to_be_bytes());

        // Receive timestamp
        packet[32..36].copy_from_slice(&0xE1B23461u32.to_be_bytes());

        // Transmit timestamp
        packet[40..44].copy_from_slice(&0xE1B23462u32.to_be_bytes());

        packet
    }

    #[test]
    fn test_can_parse_ntp() {
        let parser = NtpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With dst_port 123
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("dst_port", 123);
        assert!(parser.can_parse(&ctx2).is_some());

        // With src_port 123
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("src_port", 123);
        assert!(parser.can_parse(&ctx3).is_some());

        // With different port
        let mut ctx4 = ParseContext::new(1);
        ctx4.insert_hint("dst_port", 80);
        assert!(parser.can_parse(&ctx4).is_none());
    }

    #[test]
    fn test_parse_ntp_client_request() {
        let packet = create_ntp_client_request();

        let parser = NtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("dst_port", 123);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(4)));
        assert_eq!(result.get("mode"), Some(&FieldValue::UInt8(3))); // Client
        assert_eq!(result.get("stratum"), Some(&FieldValue::UInt8(0)));
    }

    #[test]
    fn test_parse_ntp_server_response() {
        let packet = create_ntp_server_response();

        let parser = NtpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("src_port", 123);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(4)));
        assert_eq!(result.get("mode"), Some(&FieldValue::UInt8(4))); // Server
        assert_eq!(result.get("stratum"), Some(&FieldValue::UInt8(1))); // Primary
        assert_eq!(
            result.get("reference_id"),
            Some(&FieldValue::OwnedString(CompactString::new("GPS")))
        );
    }

    #[test]
    fn test_ntp_version_modes() {
        // Test NTPv3 client
        let mut packet = vec![0u8; 48];
        packet[0] = 0x1B; // LI=0, VN=3, Mode=3

        let parser = NtpProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&packet, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("version"), Some(&FieldValue::UInt8(3)));
        assert_eq!(result.get("mode"), Some(&FieldValue::UInt8(3)));
    }

    #[test]
    fn test_ntp_schema_fields() {
        let parser = NtpProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());

        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"ntp.version"));
        assert!(field_names.contains(&"ntp.mode"));
        assert!(field_names.contains(&"ntp.stratum"));
        assert!(field_names.contains(&"ntp.reference_ts"));
    }

    #[test]
    fn test_ntp_too_short() {
        let short_packet = vec![0u8; 20]; // Too short for NTP

        let parser = NtpProtocol;
        let context = ParseContext::new(1);

        let result = parser.parse(&short_packet, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }
}
