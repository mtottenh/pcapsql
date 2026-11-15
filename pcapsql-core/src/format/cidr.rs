//! IP address parsing, CIDR membership and address-class tests.
//!
//! IPv4 addresses are `u32` in host order with the first octet in the high
//! byte (`192.168.1.1` is `0xC0A80101`), as stored in the address columns.
//! IPv6 addresses are 16 bytes in network order.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Parse a dotted-decimal IPv4 address. `None` for anything `Ipv4Addr`
/// rejects (surrounding whitespace, missing octets, leading zeros).
pub fn parse_ipv4(s: &str) -> Option<u32> {
    Ipv4Addr::from_str(s).ok().map(u32::from)
}

/// Parse an IPv6 address in any RFC 4291 text form. `None` if invalid.
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    Ipv6Addr::from_str(s).ok().map(|addr| addr.octets())
}

/// The netmask for a prefix length: `/16` is `0xFFFF0000`, `/0` is 0.
/// `None` above 32.
pub fn ipv4_prefix_mask(prefix_len: u32) -> Option<u32> {
    match prefix_len {
        0 => Some(0),
        1..=32 => Some(!0u32 << (32 - prefix_len)),
        _ => None,
    }
}

/// Parse IPv4 CIDR notation (`192.168.0.0/16`) into `(network, mask)`.
///
/// The address is returned as written: host bits are not cleared
/// ([`ipv4_in_cidr`] masks both sides). `None` unless the text is exactly
/// `address/prefix` with a valid address and a prefix of 0 to 32; a bare
/// address without `/prefix` is not accepted.
pub fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let (addr, prefix_len) = cidr.split_once('/')?;
    // `split_once` leaves any further '/' in the prefix, which then fails
    // to parse as a number, so "a/b/c" is rejected as before.
    let network = parse_ipv4(addr)?;
    let mask = ipv4_prefix_mask(prefix_len.parse().ok()?)?;
    Some((network, mask))
}

/// Whether `ip` is in the network, given the pair [`parse_cidr_v4`] returns.
#[inline]
pub fn ipv4_in_cidr(ip: u32, network: u32, mask: u32) -> bool {
    (ip & mask) == (network & mask)
}

/// Parse IPv6 CIDR notation (`2001:db8::/32`) into `(network, prefix_len)`.
///
/// `None` unless the text is exactly `address/prefix` with a valid address
/// and a prefix of 0 to 128.
pub fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u32)> {
    let (addr, prefix_len) = cidr.split_once('/')?;
    let network = parse_ipv6(addr)?;
    let prefix_len: u32 = prefix_len.parse().ok()?;
    if prefix_len > 128 {
        return None;
    }
    Some((network, prefix_len))
}

/// Whether `ip` is in `network/prefix_len`. False when `ip` is not 16 bytes.
/// A prefix length above 128 compares the whole address.
pub fn ipv6_in_prefix(ip: &[u8], network: &[u8; 16], prefix_len: u32) -> bool {
    if ip.len() != 16 {
        return false;
    }

    let full_bytes = ((prefix_len / 8) as usize).min(16);
    let remaining_bits = (prefix_len % 8) as u8;

    if ip[..full_bytes] != network[..full_bytes] {
        return false;
    }

    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !0u8 << (8 - remaining_bits);
        if (ip[full_bytes] & mask) != (network[full_bytes] & mask) {
            return false;
        }
    }

    true
}

/// Check if IPv4 address is in RFC1918 private ranges.
/// - 10.0.0.0/8
/// - 172.16.0.0/12
/// - 192.168.0.0/16
pub fn is_private_ipv4(ip: u32) -> bool {
    let first_octet = (ip >> 24) as u8;
    let second_octet = ((ip >> 16) & 0xFF) as u8;

    // 10.0.0.0/8
    first_octet == 10
        // 172.16.0.0/12 (172.16-31.x.x)
        || (first_octet == 172 && (16..=31).contains(&second_octet))
        // 192.168.0.0/16
        || (first_octet == 192 && second_octet == 168)
}

/// Check if IPv4 address is multicast (224.0.0.0/4).
pub fn is_multicast_ipv4(ip: u32) -> bool {
    (ip >> 28) == 0xE // First 4 bits = 1110
}

/// Check if IPv4 address is loopback (127.0.0.0/8).
pub fn is_loopback_ipv4(ip: u32) -> bool {
    (ip >> 24) == 127
}

/// Check if IPv6 address is link-local (fe80::/10). Looks at the first two
/// bytes only; false for a slice shorter than that.
pub fn is_link_local_ipv6(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
}

/// Check if IPv6 address is multicast (ff00::/8). Looks at the first byte
/// only; false for an empty slice.
pub fn is_multicast_ipv6(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes[0] == 0xff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some(0xC0A80101)); // 192.168.1.1 in hex
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(u32::MAX));
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("192.168.1"), None);
        assert_eq!(parse_ipv4("192.168.1.256"), None);
        assert_eq!(parse_ipv4(" 192.168.1.1"), None);
        assert_eq!(parse_ipv4("192.168.1.1/24"), None);
        assert_eq!(parse_ipv4("::1"), None);
    }

    #[test]
    fn test_unpack_ipv4() {
        assert_eq!(crate::format::format_ipv4(0xC0A80101), "192.168.1.1");
    }

    #[test]
    fn test_parse_cidr_v4() {
        let (network, mask) = parse_cidr_v4("192.168.0.0/16").unwrap();
        assert_eq!(mask, 0xFFFF0000);
        assert_eq!(network, 0xC0A80000);
    }

    #[test]
    fn test_parse_cidr_v4_edges() {
        assert_eq!(parse_cidr_v4("0.0.0.0/0"), Some((0, 0)));
        assert_eq!(parse_cidr_v4("10.1.2.3/32"), Some((0x0A010203, u32::MAX)));
        // Host bits are kept; membership masks both sides.
        assert_eq!(parse_cidr_v4("10.1.2.3/8"), Some((0x0A010203, 0xFF000000)));
    }

    #[test]
    fn test_parse_cidr_v4_invalid() {
        assert_eq!(parse_cidr_v4("192.168.0.0"), None); // no prefix
        assert_eq!(parse_cidr_v4("192.168.0.0/33"), None);
        assert_eq!(parse_cidr_v4("192.168.0.0/"), None);
        assert_eq!(parse_cidr_v4("192.168.0.0/-1"), None);
        assert_eq!(parse_cidr_v4("192.168.0.0/16/8"), None);
        assert_eq!(parse_cidr_v4("/16"), None);
        assert_eq!(parse_cidr_v4("192.168.0/16"), None);
        assert_eq!(parse_cidr_v4("192.168.0.0/ 16"), None);
        assert_eq!(parse_cidr_v4(""), None);
        assert_eq!(parse_cidr_v4("2001:db8::/32"), None);
    }

    #[test]
    fn test_cidr_matching() {
        let (network, mask) = parse_cidr_v4("192.168.0.0/16").unwrap();

        // Should match
        assert!(ipv4_in_cidr(ip4("192.168.1.1"), network, mask));

        // Should not match
        assert!(!ipv4_in_cidr(ip4("10.0.0.1"), network, mask));
    }

    #[test]
    fn test_cidr_matching_edges() {
        // /0 matches everything
        let (network, mask) = parse_cidr_v4("1.2.3.4/0").unwrap();
        assert!(ipv4_in_cidr(ip4("255.255.255.255"), network, mask));
        assert!(ipv4_in_cidr(0, network, mask));

        // /32 matches exactly one address
        let (network, mask) = parse_cidr_v4("10.0.0.1/32").unwrap();
        assert!(ipv4_in_cidr(ip4("10.0.0.1"), network, mask));
        assert!(!ipv4_in_cidr(ip4("10.0.0.2"), network, mask));

        // Host bits in the network text do not matter
        let (network, mask) = parse_cidr_v4("192.168.77.9/16").unwrap();
        assert!(ipv4_in_cidr(ip4("192.168.1.1"), network, mask));
    }

    #[test]
    fn test_ipv4_prefix_mask() {
        assert_eq!(ipv4_prefix_mask(0), Some(0));
        assert_eq!(ipv4_prefix_mask(1), Some(0x8000_0000));
        assert_eq!(ipv4_prefix_mask(24), Some(0xFFFF_FF00));
        assert_eq!(ipv4_prefix_mask(32), Some(u32::MAX));
        assert_eq!(ipv4_prefix_mask(33), None);
    }

    // Helper to convert IP string to u32
    fn ip4(s: &str) -> u32 {
        parse_ipv4(s).unwrap()
    }

    #[test]
    fn test_is_private_ipv4() {
        // 10.0.0.0/8
        assert!(is_private_ipv4(ip4("10.0.0.1")));
        assert!(is_private_ipv4(ip4("10.255.255.255")));

        // 172.16.0.0/12 (172.16-31.x.x)
        assert!(is_private_ipv4(ip4("172.16.0.1")));
        assert!(is_private_ipv4(ip4("172.31.255.255")));
        assert!(!is_private_ipv4(ip4("172.15.255.255"))); // Below range
        assert!(!is_private_ipv4(ip4("172.32.0.1"))); // Above range

        // 192.168.0.0/16
        assert!(is_private_ipv4(ip4("192.168.0.1")));
        assert!(is_private_ipv4(ip4("192.168.255.255")));

        // Public IPs
        assert!(!is_private_ipv4(ip4("8.8.8.8")));
        assert!(!is_private_ipv4(ip4("1.1.1.1")));
        assert!(!is_private_ipv4(ip4("192.169.0.1")));
    }

    #[test]
    fn test_is_multicast_ipv4() {
        // Multicast range: 224.0.0.0 - 239.255.255.255
        assert!(is_multicast_ipv4(ip4("224.0.0.1")));
        assert!(is_multicast_ipv4(ip4("239.255.255.255")));
        assert!(is_multicast_ipv4(ip4("230.1.2.3")));

        // Not multicast
        assert!(!is_multicast_ipv4(ip4("223.255.255.255")));
        assert!(!is_multicast_ipv4(ip4("240.0.0.1"))); // Reserved
        assert!(!is_multicast_ipv4(ip4("192.168.1.1")));
    }

    #[test]
    fn test_is_loopback_ipv4() {
        // Loopback range: 127.0.0.0/8
        assert!(is_loopback_ipv4(ip4("127.0.0.1")));
        assert!(is_loopback_ipv4(ip4("127.255.255.255")));
        assert!(is_loopback_ipv4(ip4("127.0.0.0")));

        // Not loopback
        assert!(!is_loopback_ipv4(ip4("126.255.255.255")));
        assert!(!is_loopback_ipv4(ip4("128.0.0.1")));
        assert!(!is_loopback_ipv4(ip4("192.168.1.1")));
    }

    #[test]
    fn test_parse_ipv6() {
        let bytes = parse_ipv6("2001:db8::1").unwrap();
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[15], 0x01);

        assert_eq!(parse_ipv6("not an address"), None);
        assert_eq!(parse_ipv6("192.168.1.1"), None);
        assert_eq!(parse_ipv6(""), None);
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (network, prefix) = parse_cidr_v6("2001:db8::/32").unwrap();
        assert_eq!(prefix, 32);
        assert_eq!(network[0], 0x20);
        assert_eq!(network[1], 0x01);
    }

    #[test]
    fn test_parse_cidr_v6_invalid() {
        assert_eq!(parse_cidr_v6("2001:db8::"), None); // no prefix
        assert_eq!(parse_cidr_v6("2001:db8::/129"), None);
        assert_eq!(parse_cidr_v6("2001:db8::/"), None);
        assert_eq!(parse_cidr_v6("2001:db8::/32/1"), None);
        assert_eq!(parse_cidr_v6("10.0.0.0/8"), None);
        assert!(parse_cidr_v6("::/0").is_some());
        assert!(parse_cidr_v6("::1/128").is_some());
    }

    #[test]
    fn test_ipv6_in_prefix() {
        let (network, prefix_len) = parse_cidr_v6("2001:db8::/32").unwrap();

        // Should match
        let ip1 = ip6("2001:db8::1");
        assert!(ipv6_in_prefix(&ip1, &network, prefix_len));

        // Should not match
        let ip2 = ip6("fe80::1");
        assert!(!ipv6_in_prefix(&ip2, &network, prefix_len));
    }

    #[test]
    fn test_ipv6_in_prefix_edges() {
        let any = ip6("2001:db8::1");

        // /0 matches everything
        assert!(ipv6_in_prefix(&any, &ip6("::"), 0));
        // /128 is an exact match
        assert!(ipv6_in_prefix(&any, &any, 128));
        assert!(!ipv6_in_prefix(&ip6("2001:db8::2"), &any, 128));
        // A prefix that ends inside a byte: fe80::/10
        let ll = ip6("fe80::");
        assert!(ipv6_in_prefix(&ip6("febf::1"), &ll, 10));
        assert!(!ipv6_in_prefix(&ip6("fec0::1"), &ll, 10));
        // Wrong length is never a member
        assert!(!ipv6_in_prefix(&any[..4], &any, 0));
        assert!(!ipv6_in_prefix(&[], &any, 0));
        // Out-of-range prefix length does not panic
        assert!(ipv6_in_prefix(&any, &any, 200));
    }

    // Helper to convert IPv6 string to bytes
    fn ip6(s: &str) -> [u8; 16] {
        parse_ipv6(s).unwrap()
    }

    #[test]
    fn test_is_link_local_ipv6() {
        // Link-local range: fe80::/10
        assert!(is_link_local_ipv6(&ip6("fe80::1")));
        assert!(is_link_local_ipv6(&ip6("fe80:1234::5678")));
        assert!(is_link_local_ipv6(&ip6(
            "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        )));
        // fe80::/10 means first 10 bits = 1111111010, so fe8x and fe9x are valid
        assert!(is_link_local_ipv6(&ip6("fe90::1")));
        assert!(is_link_local_ipv6(&ip6("febf::1"))); // fe10111111 -> still within /10

        // Not link-local
        assert!(!is_link_local_ipv6(&ip6("fe00::1"))); // fec0 would be site-local
        assert!(!is_link_local_ipv6(&ip6("fec0::1"))); // Site-local (deprecated)
        assert!(!is_link_local_ipv6(&ip6("2001:db8::1"))); // Global unicast
        assert!(!is_link_local_ipv6(&ip6("ff02::1"))); // Multicast
    }

    #[test]
    fn test_is_multicast_ipv6() {
        // Multicast range: ff00::/8
        assert!(is_multicast_ipv6(&ip6("ff02::1"))); // All nodes (link-local)
        assert!(is_multicast_ipv6(&ip6("ff05::2"))); // Site-local routers
        assert!(is_multicast_ipv6(&ip6("ff0e::1"))); // Global multicast
        assert!(is_multicast_ipv6(&ip6(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        )));

        // Not multicast
        assert!(!is_multicast_ipv6(&ip6("fe80::1"))); // Link-local unicast
        assert!(!is_multicast_ipv6(&ip6("2001:db8::1"))); // Global unicast
        assert!(!is_multicast_ipv6(&ip6("::1"))); // Loopback
    }
}
