//! CIDR matching.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Whether `addr` is inside `cidr` (for example `192.168.0.0/16`); `None` if `cidr` is malformed.
pub fn ip4_in_cidr(addr: u32, cidr: &str) -> Option<bool> {
    let (network, prefix_len) = parse_cidr_v4(cidr)?;
    Some(ipv4_in_cidr(addr, network, prefix_len))
}

/// Whether the 16-byte address `addr` is inside `cidr` (for example `fe80::/10`); `None` if
/// `addr` is not 16 bytes or `cidr` is malformed.
pub fn ip6_in_cidr(addr: &[u8], cidr: &str) -> Option<bool> {
    if addr.len() != 16 {
        return None;
    }
    let (network, prefix_len) = parse_cidr_v6(cidr)?;
    Some(ipv6_in_prefix(addr, &network, prefix_len))
}

/// Parse IPv4 CIDR notation into the network address and prefix length.
pub fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let (addr, prefix) = split_cidr(cidr)?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= 32).then_some((u32::from(addr), prefix))
}

/// Whether `addr` and `network` agree on their first `prefix_len` bits.
pub fn ipv4_in_cidr(addr: u32, network: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return addr == network;
    }

    let mask = !0u32 << (32 - prefix_len);
    (addr & mask) == (network & mask)
}

/// Parse IPv6 CIDR notation into the network address and prefix length.
pub fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u8)> {
    let (addr, prefix) = split_cidr(cidr)?;
    let addr: Ipv6Addr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= 128).then_some((addr.octets(), prefix))
}

/// Whether the 16-byte `addr` and `network` agree on their first `prefix_len` bits.
pub fn ipv6_in_prefix(addr: &[u8], network: &[u8; 16], prefix_len: u8) -> bool {
    if addr.len() != 16 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }

    let full_bytes = usize::from(prefix_len / 8).min(16);
    let remaining_bits = prefix_len % 8;

    if addr[..full_bytes] != network[..full_bytes] {
        return false;
    }
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !0u8 << (8 - remaining_bits);
        return (addr[full_bytes] & mask) == (network[full_bytes] & mask);
    }
    true
}

/// Split `address/prefix`; exactly one `/` is required.
fn split_cidr(cidr: &str) -> Option<(&str, &str)> {
    let (addr, prefix) = cidr.split_once('/')?;
    (!prefix.contains('/')).then_some((addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_v4() {
        let (network, prefix) = parse_cidr_v4("192.168.0.0/16").unwrap();
        assert_eq!(network, 0xC0A80000);
        assert_eq!(prefix, 16);

        assert!(parse_cidr_v4("invalid").is_none());
        assert!(parse_cidr_v4("192.168.0.0/33").is_none());
        assert!(parse_cidr_v4("192.168.0.0/16/8").is_none());
    }

    #[test]
    fn test_ipv4_in_cidr() {
        let network = 0xC0A80000; // 192.168.0.0

        // 192.168.1.100 is in 192.168.0.0/16
        assert!(ipv4_in_cidr(0xC0A80164, network, 16));

        // 10.0.0.1 is not
        assert!(!ipv4_in_cidr(0x0A000001, network, 16));

        // Edge cases
        assert!(ipv4_in_cidr(0xC0A80000, 0xC0A80000, 32));
        assert!(ipv4_in_cidr(0x12345678, 0, 0));
    }

    #[test]
    fn test_ip4_in_cidr() {
        assert_eq!(ip4_in_cidr(0xC0A80164, "192.168.0.0/16"), Some(true));
        assert_eq!(ip4_in_cidr(0x0A000001, "192.168.0.0/16"), Some(false));
        assert_eq!(ip4_in_cidr(0x0A000001, "192.168.0.0"), None);
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (network, prefix) = parse_cidr_v6("fe80::/10").unwrap();
        assert_eq!(prefix, 10);
        assert_eq!(network[0], 0xfe);
        assert_eq!(network[1], 0x80);

        assert!(parse_cidr_v6("invalid").is_none());
        assert!(parse_cidr_v6("fe80::/129").is_none());
    }

    #[test]
    fn test_ipv6_in_prefix() {
        let (network, prefix) = parse_cidr_v6("fe80::/10").unwrap();

        // fe80::1 is in fe80::/10
        let addr1 = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
        assert!(ipv6_in_prefix(&addr1, &network, prefix));

        // 2001::1 is not
        let addr2 = "2001::1".parse::<Ipv6Addr>().unwrap().octets();
        assert!(!ipv6_in_prefix(&addr2, &network, prefix));

        // A full-length prefix compares every byte.
        assert!(ipv6_in_prefix(&addr1, &addr1, 128));
        assert!(!ipv6_in_prefix(&addr1, &addr2, 128));
    }

    #[test]
    fn test_ip6_in_cidr() {
        let addr = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(ip6_in_cidr(&addr, "fe80::/10"), Some(true));
        assert_eq!(ip6_in_cidr(&addr, "2001::/16"), Some(false));
        assert_eq!(ip6_in_cidr(&addr[..4], "fe80::/10"), None);
        assert_eq!(ip6_in_cidr(&addr, "fe80::"), None);
    }
}
