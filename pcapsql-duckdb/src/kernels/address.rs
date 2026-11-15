//! Address parsing. Formatting is already in `pcapsql_core::format`.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse a dotted-quad IPv4 address into its numeric value.
pub fn parse_ip4(text: &str) -> Option<u32> {
    text.parse::<Ipv4Addr>().ok().map(u32::from)
}

/// Parse an IPv6 address into its 16 bytes.
pub fn parse_ip6(text: &str) -> Option<[u8; 16]> {
    text.parse::<Ipv6Addr>().ok().map(|addr| addr.octets())
}

/// Parse a MAC address written with `:` or `-` separators, such as `aa:bb:cc:dd:ee:ff`.
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let text = text.trim();
    let separator = if text.contains(':') { ':' } else { '-' };
    let mut parts = text.split(separator);

    let mut bytes = [0u8; 6];
    for byte in &mut bytes {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip4() {
        assert_eq!(parse_ip4("192.168.1.1"), Some(0xC0A8_0101));
        assert_eq!(parse_ip4("0.0.0.0"), Some(0));
        assert_eq!(parse_ip4("255.255.255.255"), Some(u32::MAX));
        assert_eq!(parse_ip4("192.168.1"), None);
        assert_eq!(parse_ip4("::1"), None);
        assert_eq!(parse_ip4(""), None);
    }

    #[test]
    fn test_parse_ip6() {
        let mut expected = [0u8; 16];
        expected[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        expected[15] = 1;
        assert_eq!(parse_ip6("2001:db8::1"), Some(expected));
        assert_eq!(parse_ip6("192.168.1.1"), None);
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let mac = parse_mac("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert!(parse_mac("invalid").is_none());
        assert!(parse_mac("aa:bb:cc:dd:ee").is_none());
        assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_none());
    }
}
