//! MAC address parsing and address-class tests.
//!
//! Formatting is [`format_mac`](super::format_mac) and
//! [`write_mac`](super::write_mac).

/// Parse a MAC address string into 6 bytes.
///
/// Surrounding whitespace is ignored. Supports formats:
/// - Colon-separated: `aa:bb:cc:dd:ee:ff`
/// - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
/// - No separator: `aabbccddeeff`
///
/// Hex digits are case-insensitive. In the separated forms a group is any
/// hex number up to `ff`, so `a:b:c:d:e:f` is accepted. A string containing
/// a colon is only tried as colon-separated, and likewise for a hyphen.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();

    if s.contains(':') {
        return parse_separated(s, ':');
    }
    if s.contains('-') {
        return parse_separated(s, '-');
    }

    // No separator: exactly 12 hex digits.
    if s.len() == 12 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(mac);
    }

    None
}

/// Exactly six `sep`-separated hex groups.
fn parse_separated(s: &str, sep: char) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(sep);
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(mac)
}

/// Check if MAC address is broadcast (ff:ff:ff:ff:ff:ff). False unless the
/// slice is 6 bytes.
pub fn is_broadcast_mac(bytes: &[u8]) -> bool {
    bytes.len() == 6 && bytes.iter().all(|&b| b == 0xff)
}

/// Check if MAC address is multicast (bit 0 of first octet = 1). Looks at
/// the first byte only; false for an empty slice.
pub fn is_multicast_mac(bytes: &[u8]) -> bool {
    !bytes.is_empty() && (bytes[0] & 0x01) == 0x01
}

/// Check if MAC address is locally administered (bit 1 of first octet = 1).
/// Looks at the first byte only; false for an empty slice.
pub fn is_local_mac(bytes: &[u8]) -> bool {
    !bytes.is_empty() && (bytes[0] & 0x02) == 0x02
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::format_mac;

    #[test]
    fn test_parse_mac_colon() {
        let result = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_hyphen() {
        let result = parse_mac("aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_no_separator() {
        let result = parse_mac("aabbccddeeff").unwrap();
        assert_eq!(result, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_lenient_forms() {
        // Upper case, surrounding whitespace
        assert_eq!(
            parse_mac("  AA:BB:CC:DD:EE:FF\n"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("AABBCCDDEEFF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        // Short groups
        assert_eq!(
            parse_mac("a:b:c:d:e:f"),
            Some([0xa, 0xb, 0xc, 0xd, 0xe, 0xf])
        );
        assert_eq!(parse_mac("0-1-2-3-4-5"), Some([0, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert_eq!(parse_mac(""), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None); // five groups
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None); // seven groups
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:gg"), None); // not hex
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:100"), None); // group above ff
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:"), None); // empty group
        assert_eq!(parse_mac("aa:bb:cc-dd:ee:ff"), None); // mixed separators
        assert_eq!(parse_mac("aa-bb-cc-dd-ee"), None);
        assert_eq!(parse_mac("aabbccddeef"), None); // 11 digits
        assert_eq!(parse_mac("aabbccddeeff0"), None); // 13 digits
        assert_eq!(parse_mac("aabbccddeefg"), None);
        assert_eq!(parse_mac("aabb.ccdd.eeff"), None); // dotted form not supported
    }

    #[test]
    fn test_format_mac() {
        let bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&bytes).unwrap(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_roundtrip() {
        let original = "12:34:56:78:9a:bc";
        let bytes = parse_mac(original).unwrap();
        let formatted = format_mac(&bytes).unwrap();
        assert_eq!(original, formatted);
    }

    #[test]
    fn test_is_broadcast_mac() {
        // Broadcast
        assert!(is_broadcast_mac(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));

        // Not broadcast
        assert!(!is_broadcast_mac(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]));
        assert!(!is_broadcast_mac(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        assert!(!is_broadcast_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        // Wrong length
        assert!(!is_broadcast_mac(&[0xff; 5]));
        assert!(!is_broadcast_mac(&[]));
    }

    #[test]
    fn test_is_multicast_mac() {
        // Multicast (bit 0 of first octet = 1)
        assert!(is_multicast_mac(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01])); // IPv4 multicast
        assert!(is_multicast_mac(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01])); // IPv6 multicast
        assert!(is_multicast_mac(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff])); // Broadcast is also multicast

        // Unicast (bit 0 of first octet = 0)
        assert!(!is_multicast_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(!is_multicast_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01])); // Local, but not multicast
        assert!(!is_multicast_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xfe])); // Even first octet
        assert!(!is_multicast_mac(&[]));
    }

    #[test]
    fn test_is_local_mac() {
        // Locally administered (bit 1 of first octet = 1)
        assert!(is_local_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01])); // Local unicast
        assert!(is_local_mac(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x01])); // Local multicast
        assert!(is_local_mac(&[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff])); // Local + multicast

        // Globally unique (bit 1 of first octet = 0)
        assert!(!is_local_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55])); // OUI-based
        assert!(!is_local_mac(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01])); // IPv4 multicast (global)
        assert!(!is_local_mac(&[0xfc, 0xff, 0xff, 0xff, 0xff, 0xff])); // Not local (bit 1 = 0)
        assert!(!is_local_mac(&[]));
    }
}
