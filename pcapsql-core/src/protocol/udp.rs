//! UDP protocol parser.

use etherparse::UdpHeaderSlice;

use super::{
    field_list, Cond, Dispatch, DispatchRule, FieldSet, FieldSink, FieldValue, HintKey, Hints,
    ParseContext, Parsed, Protocol,
};
use crate::schema::{DataKind, FieldDescriptor};

/// IP protocol number for UDP.
pub const IP_PROTO_UDP: u8 = 17;

field_list! {
    /// The fields of a `udp` layer, in the order the parser writes them.
    enum Field {
        SrcPort = "src_port",
        DstPort = "dst_port",
        Length = "length",
        Checksum = "checksum",
    }
}

/// The UDP header at the start of `data`: the fields of `want` (all of
/// them for [`FieldSet::ALL`]) to `fields`, the payload and the hints for
/// the layer above.
#[inline(always)]
fn parse_udp<'a>(data: &'a [u8], want: FieldSet, fields: &mut FieldSink<'_, 'a>) -> Parsed<'a> {
    let udp = match UdpHeaderSlice::from_slice(data) {
        Ok(udp) => udp,
        Err(e) => {
            return Parsed::error(fields.text_fmt(format_args!("UDP parse error: {e}")), data)
        }
    };
    let src_port = udp.source_port();
    let dst_port = udp.destination_port();
    if want.has(Field::SrcPort) {
        fields.push(("src_port", FieldValue::UInt16(src_port)));
    }
    if want.has(Field::DstPort) {
        fields.push(("dst_port", FieldValue::UInt16(dst_port)));
    }
    if want.has(Field::Length) {
        fields.push(("length", FieldValue::UInt16(udp.length())));
    }
    if want.has(Field::Checksum) {
        fields.push(("checksum", FieldValue::UInt16(udp.checksum())));
    }

    let mut child_hints = Hints::new();
    child_hints.insert(HintKey::SrcPort, src_port as u64);
    child_hints.insert(HintKey::DstPort, dst_port as u64);
    child_hints.insert(HintKey::Transport, IP_PROTO_UDP as u64);

    // UDP header is always 8 bytes
    Parsed::ok(&data[8..], child_hints)
}

/// UDP protocol parser.
#[derive(Debug, Clone, Copy)]
pub struct UdpProtocol;

impl Protocol for UdpProtocol {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn display_name(&self) -> &'static str {
        "UDP"
    }

    fn dispatch(&self) -> Dispatch {
        const RULES: &[DispatchRule] = &[DispatchRule::hints(
            &[Cond::Hint(HintKey::IpProtocol, &[IP_PROTO_UDP as u64])],
            100,
        )];
        Dispatch::Exact(RULES)
    }

    fn child_hint_keys(&self) -> Option<&'static [HintKey]> {
        Some(&[HintKey::SrcPort, HintKey::DstPort, HintKey::Transport])
    }

    fn can_parse(&self, context: &ParseContext) -> Option<u32> {
        match context.hint(HintKey::IpProtocol) {
            Some(proto) if proto == IP_PROTO_UDP as u64 => Some(100),
            _ => None,
        }
    }

    fn parse<'a>(
        &self,
        data: &'a [u8],
        _context: &ParseContext,
        fields: &mut FieldSink<'_, 'a>,
    ) -> Parsed<'a> {
        parse_udp(data, FieldSet::ALL, fields)
    }

    fn schema_fields(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("udp.src_port", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("udp.dst_port", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("udp.length", DataKind::UInt16).set_nullable(true),
            FieldDescriptor::new("udp.checksum", DataKind::UInt16).set_nullable(true),
        ]
    }

    fn child_protocols(&self) -> &[&'static str] {
        &["dns", "dhcp", "ntp"]
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["ipv4", "ipv6"]
    }

    fn field_names(&self) -> &'static [&'static str] {
        Field::NAMES
    }

    fn parse_projected<'a>(
        &self,
        data: &'a [u8],
        _context: &ParseContext,
        projection: FieldSet,
        fields: &mut FieldSink<'_, 'a>,
    ) -> Parsed<'a> {
        parse_udp(data, projection, fields)
    }

    fn cheap_fields(&self) -> &'static [&'static str] {
        // All UDP fields come from the fixed 8-byte header
        &["src_port", "dst_port", "length", "checksum"]
    }

    fn expensive_fields(&self) -> &'static [&'static str] {
        // UDP has no expensive fields
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_utils::ParseLayer as _;

    #[test]
    fn test_parse_udp() {
        // UDP header (8 bytes)
        let header = [
            0x00, 0x35, // Src port: 53 (DNS)
            0xc0, 0x00, // Dst port: 49152
            0x00, 0x20, // Length: 32
            0x00, 0x00, // Checksum
            // Payload would follow
            0xde, 0xad, 0xbe, 0xef,
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        let result = parser.parse_layer(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(53)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(49152)));
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(32)));
        assert_eq!(result.remaining.len(), 4); // Payload bytes
    }

    #[test]
    fn test_parse_udp_dns_query() {
        let header = [
            0xc3, 0x50, // Src port: 50000
            0x00, 0x35, // Dst port: 53 (DNS)
            0x00, 0x1c, // Length: 28
            0xab, 0xcd, // Checksum
            // DNS query payload (simplified)
            0x12, 0x34, 0x01, 0x00,
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        let result = parser.parse_layer(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(50000)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(53)));
        assert_eq!(result.hint(HintKey::DstPort), Some(53u64));
    }

    #[test]
    fn test_parse_udp_dhcp() {
        let header = [
            0x00, 0x44, // Src port: 68 (DHCP client)
            0x00, 0x43, // Dst port: 67 (DHCP server)
            0x01, 0x00, // Length: 256
            0x00, 0x00, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        let result = parser.parse_layer(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(68)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(67)));
    }

    #[test]
    fn test_can_parse_udp() {
        let parser = UdpProtocol;

        // Without hint
        let ctx1 = ParseContext::new(1);
        assert!(parser.can_parse(&ctx1).is_none());

        // With TCP protocol
        let mut ctx2 = ParseContext::new(1);
        ctx2.insert_hint(HintKey::IpProtocol, 6);
        assert!(parser.can_parse(&ctx2).is_none());

        // With UDP protocol
        let mut ctx3 = ParseContext::new(1);
        ctx3.insert_hint(HintKey::IpProtocol, 17);
        assert!(parser.can_parse(&ctx3).is_some());
    }

    #[test]
    fn test_parse_udp_too_short() {
        let short_header = [0x00, 0x35, 0xc0, 0x00]; // Only 4 bytes

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        let result = parser.parse_layer(&short_header, &context);

        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_udp_child_hints() {
        let header = [
            0x12, 0x34, // Src port: 4660
            0x56, 0x78, // Dst port: 22136
            0x00, 0x10, // Length: 16
            0x00, 0x00, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        let result = parser.parse_layer(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.hint(HintKey::SrcPort), Some(4660u64));
        assert_eq!(result.hint(HintKey::DstPort), Some(22136u64));
        assert_eq!(result.hint(HintKey::Transport), Some(17u64));
    }

    #[test]
    fn test_udp_minimal_header() {
        // Exactly 8 bytes (minimum valid UDP)
        let header = [
            0x00, 0x50, // Src port: 80
            0x00, 0x51, // Dst port: 81
            0x00, 0x08, // Length: 8 (header only)
            0x00, 0x00, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        let result = parser.parse_layer(&header, &context);

        assert!(result.is_ok());
        assert_eq!(result.get("length"), Some(&FieldValue::UInt16(8)));
        assert!(result.remaining.is_empty());
    }

    #[test]
    fn test_udp_projected_parsing_ports_only() {
        let header = [
            0x00, 0x35, // Src port: 53 (DNS)
            0xc0, 0x00, // Dst port: 49152
            0x00, 0x20, // Length: 32
            0xab, 0xcd, // Checksum
        ];

        let parser = UdpProtocol;
        let mut context = ParseContext::new(1);
        context.insert_hint(HintKey::IpProtocol, 17);

        // Project to only ports
        let result = parser.parse_layer_fields(&header, &context, &["src_port", "dst_port"]);

        assert!(result.is_ok());
        // Requested fields are present
        assert_eq!(result.get("src_port"), Some(&FieldValue::UInt16(53)));
        assert_eq!(result.get("dst_port"), Some(&FieldValue::UInt16(49152)));
        // Unrequested fields are NOT present
        assert!(result.get("length").is_none());
        assert!(result.get("checksum").is_none());
        // Child hints are still populated
        assert_eq!(result.hint(HintKey::SrcPort), Some(53u64));
        assert_eq!(result.hint(HintKey::DstPort), Some(49152u64));

        // A projection of no field (a row count) extracts none, and is
        // otherwise the same parse.
        let none = parser.parse_layer_projected(&header, &context, Some(FieldSet::NONE));
        assert!(none.is_ok());
        assert!(none.fields.is_empty());
        assert_eq!(none.remaining, result.remaining);
        assert_eq!(none.child_hints, result.child_hints);
    }
}
