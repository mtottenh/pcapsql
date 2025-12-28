//! IPsec (ESP and AH) protocol parser.
//!
//! IPsec provides security services at the IP layer including:
//! - ESP (Encapsulating Security Payload): Encryption and authentication
//! - AH (Authentication Header): Authentication only
//!
//! RFC 4303: IP Encapsulating Security Payload (ESP)
//! RFC 4302: IP Authentication Header (AH)
//!
//! # Encrypted Payload Limitations
//!
//! **Important:** ESP payloads are encrypted and cannot be parsed without the
//! corresponding Security Association (SA) and decryption keys. This parser
//! extracts only the unencrypted header fields:
//!
//! ## ESP Limitations
//!
//! The ESP header format (RFC 4303) places the Next Header field in the
//! encrypted trailer, making it inaccessible without decryption:
//!
//! ```text
//! +---------------+---------------+---------------+---------------+
//! |                Security Parameters Index (SPI)                | <- Cleartext
//! +---------------+---------------+---------------+---------------+
//! |                      Sequence Number                          | <- Cleartext
//! +---------------+---------------+---------------+---------------+
//! |                    Payload Data (variable)                    | <- ENCRYPTED
//! +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               |     Padding (0-255 bytes)                     | <- ENCRYPTED
//! +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |  Pad Length   |  Next Header  | <- ENCRYPTED
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Integrity Check Value (ICV) (variable)                | <- Authentication
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! As a result, for ESP packets this parser:
//! - Extracts SPI and Sequence Number (cleartext header)
//! - Cannot determine the encapsulated protocol (Next Header is encrypted)
//! - Cannot parse inner payloads (data is encrypted)
//! - Cannot verify the ICV without the SA keys
//!
//! ## AH Differences
//!
//! Unlike ESP, the AH header (RFC 4302) does NOT encrypt the payload:
//!
//! ```text
//! +---------------+---------------+---------------+---------------+
//! |  Next Header  |  Payload Len  |          RESERVED             | <- Cleartext
//! +---------------+---------------+---------------+---------------+
//! |                Security Parameters Index (SPI)                | <- Cleartext
//! +---------------+---------------+---------------+---------------+
//! |                    Sequence Number Field                      | <- Cleartext
//! +---------------+---------------+---------------+---------------+
//! |                 Integrity Check Value (ICV)                   | <- Authentication
//! |                         (variable)                            |
//! +---------------+---------------+---------------+---------------+
//! |                    IP Payload (NOT encrypted)                 | <- Cleartext
//! +---------------+---------------+---------------+---------------+
//! ```
//!
//! For AH packets this parser:
//! - Extracts all header fields including Next Header
//! - Can determine the encapsulated protocol
//! - Payload is accessible for further parsing
//! - Cannot verify the ICV without the SA keys
//!
//! ## Decryption Requirements
//!
//! To decrypt ESP payloads, you would need:
//! 1. The Security Association (SA) for this SPI
//! 2. The encryption algorithm (AES-CBC, AES-GCM, etc.)
//! 3. The encryption key
//! 4. The IV (typically prepended to the encrypted payload)
//!
//! This information is typically exchanged via IKE (Internet Key Exchange)
//! and is not available from packet capture alone.
//!
//! ## Practical Implications
//!
//! When querying IPsec traffic:
//! - `ipsec.spi` - Available for both ESP and AH
//! - `ipsec.sequence` - Available for both ESP and AH
//! - `ipsec.protocol` - Returns "ESP" or "AH"
//! - `ipsec.ah_next_header` - Only available for AH packets
//! - Inner protocol fields - Only parseable for AH packets
//!
//! For ESP traffic analysis without decryption, focus on:
//! - Traffic flow analysis (source/destination IPs)
//! - SPI values (can identify security associations)
//! - Sequence numbers (can detect replay attacks or packet loss)
//! - Packet timing and sizes

use smallvec::SmallVec;

use super::ipv6::next_header;
use super::{FieldValue, ParseContext, ParseResult, PayloadMode, Protocol};
use crate::schema::{DataKind, FieldDescriptor};

/// IPsec protocol parser (handles both ESP and AH).
#[derive(Debug, Clone, Copy)]
pub struct IpsecProtocol;

impl Protocol for IpsecProtocol {
    fn name(&self) -> &'static str {
        "ipsec"
    }

    fn display_name(&self) -> &'static str {
        "IPsec"
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        // Match when IP protocol hint equals ESP (50) or AH (51)
        match context.hint("ip_protocol") {
            Some(proto) if proto == next_header::ESP as u64 => Some(100),
            Some(proto) if proto == next_header::AH as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(&self, data: &'a [u8], context: &ParseContext) -> ParseResult<'a> {
        // Determine if this is ESP or AH based on the context hint
        let is_esp = match context.hint("ip_protocol") {
            Some(proto) => proto == next_header::ESP as u64,
            None => return ParseResult::error("IPsec: missing ip_protocol hint".to_string(), data),
        };

        if is_esp {
            self.parse_esp(data)
        } else {
            self.parse_ah(data)
        }
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("ipsec.protocol", DataKind::String).set_nullable(true),
            FieldDescriptor::new("ipsec.spi", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ipsec.sequence", DataKind::UInt32).set_nullable(true),
            FieldDescriptor::new("ipsec.ah_next_header", DataKind::UInt8).set_nullable(true),
            FieldDescriptor::new("ipsec.ah_icv_length", DataKind::UInt8).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        // ESP payload is encrypted, AH can have any IP protocol
        &[]
    }

    fn payload_mode(&self) -> PayloadMode {
        // ESP payload is encrypted, so we can't parse further
        // AH payload could be parsed, but we treat IPsec as terminal for simplicity
        PayloadMode::None
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv4", "ipv6"] // IPsec (ESP/AH) runs over IPv4/IPv6
    }
}

impl IpsecProtocol {
    /// Parse ESP (Encapsulating Security Payload) header.
    ///
    /// ESP Header:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |               Security Parameters Index (SPI)                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                      Sequence Number                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                    Payload Data (encrypted)                   |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_esp<'a>(&self, data: &'a [u8]) -> ParseResult<'a> {
        // ESP header minimum is 8 bytes (SPI + Sequence Number)
        if data.len() < 8 {
            return ParseResult::error("ESP header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        fields.push(("protocol", FieldValue::Str("ESP")));

        // Bytes 0-3: Security Parameters Index (SPI)
        let spi = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        fields.push(("spi", FieldValue::UInt32(spi)));

        // Bytes 4-7: Sequence Number
        let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        fields.push(("sequence", FieldValue::UInt32(sequence)));

        // The rest is encrypted payload, we can't parse further
        // Note: The actual payload starts at byte 8, but it's encrypted
        // The trailer (padding, pad length, next header) and ICV are at the end
        // but we can't determine their location without decryption

        // Return with no child hints since ESP payload is encrypted
        ParseResult::success(fields, &data[8..], SmallVec::new())
    }

    /// Parse AH (Authentication Header).
    ///
    /// AH Header:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Next Header  |  Payload Len  |          RESERVED             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                 Security Parameters Index (SPI)               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                    Sequence Number Field                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                    ICV (variable length)                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_ah<'a>(&self, data: &'a [u8]) -> ParseResult<'a> {
        // AH header minimum is 12 bytes (without ICV)
        if data.len() < 12 {
            return ParseResult::error("AH header too short".to_string(), data);
        }

        let mut fields = SmallVec::new();

        fields.push(("protocol", FieldValue::Str("AH")));

        // Byte 0: Next Header
        let next_header = data[0];
        fields.push(("ah_next_header", FieldValue::UInt8(next_header)));

        // Byte 1: Payload Length (in 32-bit words, minus 2)
        // Total AH length = (payload_len + 2) * 4 bytes
        let payload_len = data[1];
        let ah_length = ((payload_len as usize) + 2) * 4;

        // Calculate ICV length: AH length - 12 bytes (fixed header)
        let icv_length = if ah_length > 12 {
            (ah_length - 12) as u8
        } else {
            0
        };
        fields.push(("ah_icv_length", FieldValue::UInt8(icv_length)));

        // Bytes 2-3: Reserved

        // Bytes 4-7: SPI
        let spi = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        fields.push(("spi", FieldValue::UInt32(spi)));

        // Bytes 8-11: Sequence Number
        let sequence = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        fields.push(("sequence", FieldValue::UInt32(sequence)));

        // ICV follows (variable length based on payload_len)
        // Payload starts after AH header

        if data.len() < ah_length {
            return ParseResult::error("AH: data too short for declared length".to_string(), data);
        }

        // Set up child hints for the next protocol (based on next_header)
        let mut child_hints = SmallVec::new();
        child_hints.push(("ip_protocol", next_header as u64));

        ParseResult::success(fields, &data[ah_length..], child_hints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an ESP header.
    fn create_esp_header(spi: u32, sequence: u32) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&spi.to_be_bytes());
        header.extend_from_slice(&sequence.to_be_bytes());
        header
    }

    /// Create an AH header.
    fn create_ah_header(next_header: u8, spi: u32, sequence: u32, icv_len: usize) -> Vec<u8> {
        let mut header = Vec::new();

        // Next Header
        header.push(next_header);

        // Payload Length (in 32-bit words minus 2)
        // AH length = (payload_len + 2) * 4
        // ICV is after 12-byte fixed header
        // So: payload_len = (12 + icv_len) / 4 - 2
        let ah_length = 12 + icv_len;
        let payload_len = (ah_length / 4) - 2;
        header.push(payload_len as u8);

        // Reserved
        header.extend_from_slice(&[0x00, 0x00]);

        // SPI
        header.extend_from_slice(&spi.to_be_bytes());

        // Sequence Number
        header.extend_from_slice(&sequence.to_be_bytes());

        // ICV (variable length)
        header.extend(vec![0u8; icv_len]);

        header
    }

    // Test 1: can_parse with ESP (protocol 50)
    #[test]
    fn test_can_parse_with_esp_protocol() {
        let parser = IpsecProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With wrong protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint("ip_protocol", 6); // TCP
        assert!(parser.can_parse(&ctx2).is_none());

        // With ESP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint("ip_protocol", 50);
        assert!(parser.can_parse(&ctx3).is_some());
        assert_eq!(parser.can_parse(&ctx3), Some(100));
    }

    // Test 2: can_parse with AH (protocol 51)
    #[test]
    fn test_can_parse_with_ah_protocol() {
        let parser = IpsecProtocol;

        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 51);

        assert!(parser.can_parse(&context).is_some());
        assert_eq!(parser.can_parse(&context), Some(100));
    }

    // Test 3: ESP SPI and sequence extraction
    #[test]
    fn test_esp_spi_and_sequence_extraction() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 50); // ESP

        let header = create_esp_header(0x12345678, 0xABCDEF01);
        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("protocol"), Some(&FieldValue::Str("ESP")));
        assert_eq!(result.get("spi"), Some(&FieldValue::UInt32(0x12345678)));
        assert_eq!(
            result.get("sequence"),
            Some(&FieldValue::UInt32(0xABCDEF01))
        );
    }

    // Test 4: AH header parsing
    #[test]
    fn test_ah_header_parsing() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 51); // AH

        // AH with 12-byte ICV (HMAC-SHA-256-128)
        let header = create_ah_header(6, 0x87654321, 0x00000001, 12);
        let result = parser.parse(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("protocol"), Some(&FieldValue::Str("AH")));
        assert_eq!(result.get("spi"), Some(&FieldValue::UInt32(0x87654321)));
        assert_eq!(result.get("sequence"), Some(&FieldValue::UInt32(1)));
    }

    // Test 5: AH next header field
    #[test]
    fn test_ah_next_header_field() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 51); // AH

        // Test different next headers
        let test_cases = [
            (6u8, "TCP"),
            (17u8, "UDP"),
            (1u8, "ICMP"),
            (50u8, "ESP"), // AH can encapsulate ESP
        ];

        for (next_header, _name) in test_cases {
            let header = create_ah_header(next_header, 0x1234, 0x5678, 12);
            let result = parser.parse(&header, &context);

            assert!(result.is_ok());
            assert_eq!(
                result.get("ah_next_header"),
                Some(&FieldValue::UInt8(next_header))
            );
            assert_eq!(result.hint("ip_protocol"), Some(next_header as u64));
        }
    }

    // Test 6: Protocol field ("ESP" vs "AH")
    #[test]
    fn test_protocol_field() {
        let parser = IpsecProtocol;

        // ESP
        let mut ctx_esp = ParseContext::new(1);
        ctx_esp.insert_hint("ip_protocol", 50);
        let esp_header = create_esp_header(0x1234, 0x5678);
        let result_esp = parser.parse(&esp_header, &ctx_esp);
        assert!(result_esp.is_ok());
        assert_eq!(result_esp.get("protocol"), Some(&FieldValue::Str("ESP")));

        // AH
        let mut ctx_ah = ParseContext::new(1);
        ctx_ah.insert_hint("ip_protocol", 51);
        let ah_header = create_ah_header(6, 0x1234, 0x5678, 12);
        let result_ah = parser.parse(&ah_header, &ctx_ah);
        assert!(result_ah.is_ok());
        assert_eq!(result_ah.get("protocol"), Some(&FieldValue::Str("AH")));
    }

    // Test 7: ESP too short
    #[test]
    fn test_esp_too_short() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 50);

        let short_header = [0x00, 0x00, 0x00, 0x01]; // Only 4 bytes
        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 8: AH too short
    #[test]
    fn test_ah_too_short() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 51);

        let short_header = [0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]; // Only 8 bytes
        let result = parser.parse(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    // Test 9: AH ICV length derivation
    #[test]
    fn test_ah_icv_length_derivation() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 51);

        // Test different ICV lengths
        let test_icv_lengths = [12usize, 16, 20, 32];

        for icv_len in test_icv_lengths {
            let header = create_ah_header(6, 0x1234, 0x5678, icv_len);
            let result = parser.parse(&header, &context);

            assert!(result.is_ok());
            assert_eq!(
                result.get("ah_icv_length"),
                Some(&FieldValue::UInt8(icv_len as u8))
            );
        }
    }

    // Test 10: Schema fields
    #[test]
    fn test_ipsec_schema_fields() {
        let parser = IpsecProtocol;
        let fields = parser.schema_fields();

        assert!(!fields.is_empty());
        let field_names: Vec<&str> = fields.iter().map(|f| f.name).collect();
        assert!(field_names.contains(&"ipsec.protocol"));
        assert!(field_names.contains(&"ipsec.spi"));
        assert!(field_names.contains(&"ipsec.sequence"));
        assert!(field_names.contains(&"ipsec.ah_next_header"));
        assert!(field_names.contains(&"ipsec.ah_icv_length"));
    }

    // Test 11: ESP with payload
    #[test]
    fn test_esp_with_payload() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 50);

        let mut data = create_esp_header(0x1234, 0x5678);
        // Add encrypted payload
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 4); // Encrypted payload
    }

    // Test 12: AH with following payload
    #[test]
    fn test_ah_with_following_payload() {
        let parser = IpsecProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint("ip_protocol", 51);

        let mut data = create_ah_header(6, 0x1234, 0x5678, 12);
        // Add payload (e.g., TCP header start)
        data.extend_from_slice(&[0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00]);

        let result = parser.parse(&data, &context);

        assert!(result.is_ok());
        assert_eq!(result.remaining.len(), 8); // TCP header
        assert_eq!(result.hint("ip_protocol"), Some(6u64)); // TCP
    }
}
