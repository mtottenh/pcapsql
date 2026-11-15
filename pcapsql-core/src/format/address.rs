//! Network address formatting and detection.
//!
//! Provides functions to:
//! - Format binary address values as human-readable strings
//! - Detect which columns represent network addresses based on type and name

use std::fmt;

use super::hex::HEX_DIGITS;
use crate::schema::{DataKind, FieldDescriptor};

/// The kind of network address a column represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// IPv4 address stored as UInt32 (network byte order)
    Ipv4,
    /// IPv6 address stored as FixedSizeBinary(16)
    Ipv6,
    /// MAC address stored as FixedSizeBinary(6)
    Mac,
}

/// Format a UInt32 as an IPv4 address string in dotted-decimal notation.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::format_ipv4;
///
/// assert_eq!(format_ipv4(0xC0A80101), "192.168.1.1");
/// assert_eq!(format_ipv4(0x0A000001), "10.0.0.1");
/// ```
pub fn format_ipv4(value: u32) -> String {
    ipv4_text(value, &mut [0; IPV4_TEXT_LEN]).to_owned()
}

/// The length of the longest dotted-decimal IPv4 address.
pub const IPV4_TEXT_LEN: usize = 15;

/// The length of a colon-separated MAC address.
pub const MAC_TEXT_LEN: usize = 17;

/// The length of the longest text form an IPv6 address has: eight groups of
/// four hex digits with the last two written as a dotted IPv4 address. What
/// [`ipv6_text`] writes is at most 39 bytes long, eight groups in hex.
pub const IPV6_TEXT_LEN: usize = 45;

/// `value` in dotted-decimal notation, written to `buf`: what
/// `Ipv4Addr`'s `Display` gives, without going through `fmt`.
///
/// For a caller that stores the text itself, such as a column of strings:
/// the buffer is on its stack and nothing is copied on the way.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::{ipv4_text, IPV4_TEXT_LEN};
///
/// let mut buf = [0; IPV4_TEXT_LEN];
/// assert_eq!(ipv4_text(0xC0A80101, &mut buf), "192.168.1.1");
/// ```
#[inline]
pub fn ipv4_text(value: u32, buf: &mut [u8; IPV4_TEXT_LEN]) -> &str {
    let mut len = 0;
    for (i, octet) in value.to_be_bytes().into_iter().enumerate() {
        if i > 0 {
            buf[len] = b'.';
            len += 1;
        }
        if octet >= 100 {
            buf[len] = b'0' + octet / 100;
            len += 1;
        }
        if octet >= 10 {
            buf[len] = b'0' + octet / 10 % 10;
            len += 1;
        }
        buf[len] = b'0' + octet % 10;
        len += 1;
    }
    ascii(&buf[..len])
}

/// `bytes` as six colon-separated pairs of lowercase hex digits, written to
/// `buf`. Every place that formats a MAC address goes through here.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::{mac_text, MAC_TEXT_LEN};
///
/// let mut buf = [0; MAC_TEXT_LEN];
/// assert_eq!(mac_text(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], &mut buf), "aa:bb:cc:dd:ee:ff");
/// ```
#[inline]
pub fn mac_text<'b>(bytes: &[u8; 6], buf: &'b mut [u8; MAC_TEXT_LEN]) -> &'b str {
    *buf = *b"00:00:00:00:00:00";
    for (pair, &byte) in buf.chunks_mut(3).zip(bytes) {
        pair[0] = HEX_DIGITS[usize::from(byte >> 4)];
        pair[1] = HEX_DIGITS[usize::from(byte & 0x0f)];
    }
    ascii(buf)
}

/// `bytes` as an IPv6 address in RFC 5952 form, written to `buf`: what
/// `Ipv6Addr`'s `Display` gives, without going through `fmt`.
///
/// The groups are in lowercase hex without leading zeros, and the longest
/// run of two or more zero groups, the first of them when several are as
/// long, is written as `::`. An IPv4-mapped address (`::ffff:0:0/96`) has
/// its last 32 bits in dotted-decimal notation: `::ffff:192.0.2.1`. No other
/// address has a dotted part, so an IPv4-compatible one is `::c000:201`.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::{ipv6_text, IPV6_TEXT_LEN};
///
/// let mut buf = [0; IPV6_TEXT_LEN];
/// let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// assert_eq!(ipv6_text(&bytes, &mut buf), "2001:db8::1");
/// ```
#[inline]
pub fn ipv6_text<'b>(bytes: &[u8; 16], buf: &'b mut [u8; IPV6_TEXT_LEN]) -> &'b str {
    let value = u128::from_be_bytes(*bytes);
    if value >> 32 == 0xffff {
        const PREFIX: &[u8; 7] = b"::ffff:";
        let mut dotted = [0; IPV4_TEXT_LEN];
        let v4 = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let dotted = ipv4_text(v4, &mut dotted).as_bytes();
        let len = PREFIX.len() + dotted.len();
        buf[..PREFIX.len()].copy_from_slice(PREFIX);
        buf[PREFIX.len()..len].copy_from_slice(dotted);
        return ascii(&buf[..len]);
    }

    let groups: [u16; 8] =
        std::array::from_fn(|i| u16::from_be_bytes([bytes[2 * i], bytes[2 * i + 1]]));

    // The longest run of zero groups, the first one of that length.
    let (mut zeros_start, mut zeros_len) = (0, 0);
    let mut i = 0;
    while i < 8 {
        if groups[i] != 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < 8 && groups[i] == 0 {
            i += 1;
        }
        if i - start > zeros_len {
            (zeros_start, zeros_len) = (start, i - start);
        }
    }
    // One zero group alone is written out.
    if zeros_len < 2 {
        (zeros_start, zeros_len) = (8, 0);
    }

    let mut len = 0;
    for (i, &group) in groups[..zeros_start].iter().enumerate() {
        if i > 0 {
            buf[len] = b':';
            len += 1;
        }
        len = hex_group(group, buf, len);
    }
    if zeros_len > 0 {
        buf[len] = b':';
        buf[len + 1] = b':';
        len += 2;
        for (i, &group) in groups[zeros_start + zeros_len..].iter().enumerate() {
            if i > 0 {
                buf[len] = b':';
                len += 1;
            }
            len = hex_group(group, buf, len);
        }
    }
    ascii(&buf[..len])
}

/// Write `group` in lowercase hex without leading zeros at `buf[len..]`;
/// returns the length after it.
#[inline]
fn hex_group(group: u16, buf: &mut [u8; IPV6_TEXT_LEN], mut len: usize) -> usize {
    if group >= 0x1000 {
        buf[len] = HEX_DIGITS[usize::from(group >> 12)];
        len += 1;
    }
    if group >= 0x100 {
        buf[len] = HEX_DIGITS[usize::from(group >> 8 & 0xf)];
        len += 1;
    }
    if group >= 0x10 {
        buf[len] = HEX_DIGITS[usize::from(group >> 4 & 0xf)];
        len += 1;
    }
    buf[len] = HEX_DIGITS[usize::from(group & 0xf)];
    len + 1
}

/// Text made of ASCII digits and punctuation only, as a `&str`.
#[inline]
fn ascii(text: &[u8]) -> &str {
    debug_assert!(text.is_ascii());
    // The callers write nothing but ASCII, so the check cannot fail; it is
    // what there is instead of `unsafe`.
    std::str::from_utf8(text).unwrap_or_default()
}

/// Format 16 bytes as an IPv6 address string.
///
/// Returns `None` if the slice is not exactly 16 bytes.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::format_ipv6;
///
/// let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// assert_eq!(format_ipv6(&bytes), Some("2001:db8::1".to_string()));
/// ```
pub fn format_ipv6(bytes: &[u8]) -> Option<String> {
    let bytes: &[u8; 16] = bytes.try_into().ok()?;
    Some(ipv6_text(bytes, &mut [0; IPV6_TEXT_LEN]).to_owned())
}

/// Format 6 bytes as a MAC address string in colon-separated hex format.
///
/// Returns `None` if the slice is not exactly 6 bytes.
///
/// # Example
///
/// ```
/// use pcapsql_core::format::format_mac;
///
/// let bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// assert_eq!(format_mac(&bytes), Some("aa:bb:cc:dd:ee:ff".to_string()));
/// ```
pub fn format_mac(bytes: &[u8]) -> Option<String> {
    let bytes: &[u8; 6] = bytes.try_into().ok()?;
    Some(mac_text(bytes, &mut [0; MAC_TEXT_LEN]).to_owned())
}

/// Write a `u32` as a dotted-decimal IPv4 address: [`format_ipv4`] without
/// the `String`. The sink gets the address in one `write_str`.
pub fn write_ipv4(value: u32, out: &mut impl fmt::Write) -> fmt::Result {
    out.write_str(ipv4_text(value, &mut [0; IPV4_TEXT_LEN]))
}

/// Write 16 bytes as an IPv6 address in RFC 5952 form: [`format_ipv6`]
/// without the `String`. The sink gets the address in one `write_str`.
pub fn write_ipv6(bytes: &[u8; 16], out: &mut impl fmt::Write) -> fmt::Result {
    out.write_str(ipv6_text(bytes, &mut [0; IPV6_TEXT_LEN]))
}

/// Write 6 bytes as a colon-separated lowercase MAC address: [`format_mac`]
/// without the `String`. The sink gets the address in one `write_str`.
pub fn write_mac(bytes: &[u8; 6], out: &mut impl fmt::Write) -> fmt::Result {
    out.write_str(mac_text(bytes, &mut [0; MAC_TEXT_LEN]))
}

/// Detect if a column represents a network address based on its type and name.
///
/// This uses a hybrid approach: both the data type AND the column name
/// must match expected patterns. This prevents false positives (e.g., a UInt32
/// column named "count" won't be treated as an IPv4 address).
///
/// # Detection Rules
///
/// | AddressKind | DataKind | Name Patterns |
/// |-------------|----------|---------------|
/// | Ipv4 | UInt32 | `*_ip`, `*_ip_*`, `*addr`, `router`, `server_id`, `subnet_mask`, `ciaddr`, `yiaddr`, `siaddr`, `giaddr` |
/// | Ipv6 | FixedBinary(16) | `*_ip`, `*_ip_*`, `*_address`, `*_prefix` |
/// | Mac | FixedBinary(6) | `*_mac`, `chaddr`, `*_mac_*` |
pub fn detect_address_column(field: &FieldDescriptor) -> Option<AddressKind> {
    let name = field.name.to_lowercase();

    match field.kind {
        DataKind::UInt32 => {
            // IPv4: must have IP-related name
            if is_ipv4_column_name(&name) {
                Some(AddressKind::Ipv4)
            } else {
                None
            }
        }
        DataKind::FixedBinary(16) => {
            // IPv6: must have IP/address-related name
            if is_ipv6_column_name(&name) {
                Some(AddressKind::Ipv6)
            } else {
                None
            }
        }
        DataKind::FixedBinary(6) => {
            // MAC: must have MAC-related name
            if is_mac_column_name(&name) {
                Some(AddressKind::Mac)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if a column name indicates an IPv4 address.
fn is_ipv4_column_name(name: &str) -> bool {
    // Exact matches for known IPv4 columns
    let exact_matches = [
        "router",
        "server_id",
        "subnet_mask",
        // DHCP-specific
        "ciaddr",
        "yiaddr",
        "siaddr",
        "giaddr",
    ];

    if exact_matches.contains(&name) {
        return true;
    }

    // Pattern matches
    // Ends with _ip (e.g., src_ip, dst_ip, sender_ip, target_ip)
    if name.ends_with("_ip") {
        return true;
    }

    // Contains _ip_ (e.g., src_ip_v4)
    if name.contains("_ip_") {
        return true;
    }

    // Ends with addr (e.g., srcaddr, dstaddr) but not _mac related
    if name.ends_with("addr") && !name.contains("mac") {
        return true;
    }

    false
}

/// Check if a column name indicates an IPv6 address.
fn is_ipv6_column_name(name: &str) -> bool {
    // Ends with _ip (same pattern as IPv4, distinguished by data type)
    if name.ends_with("_ip") {
        return true;
    }

    // Contains _ip_ (e.g., src_ip_v6)
    if name.contains("_ip_") {
        return true;
    }

    // Ends with _address (e.g., ndp_target_address, mld_multicast_address)
    if name.ends_with("_address") {
        return true;
    }

    // Ends with _prefix (e.g., ndp_prefix)
    if name.ends_with("_prefix") {
        return true;
    }

    false
}

/// Check if a column name indicates a MAC address.
fn is_mac_column_name(name: &str) -> bool {
    // Exact match for DHCP client hardware address
    if name == "chaddr" {
        return true;
    }

    // Ends with _mac (e.g., src_mac, dst_mac, sender_mac, target_mac)
    if name.ends_with("_mac") {
        return true;
    }

    // Contains _mac_ (e.g., ndp_source_mac_address)
    if name.contains("_mac_") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== format_ipv4 tests ==========

    #[test]
    fn test_format_ipv4_common() {
        assert_eq!(format_ipv4(0xC0A80101), "192.168.1.1");
        assert_eq!(format_ipv4(0x0A000001), "10.0.0.1");
        assert_eq!(format_ipv4(0x08080808), "8.8.8.8");
    }

    #[test]
    fn test_format_ipv4_edge_cases() {
        assert_eq!(format_ipv4(0x00000000), "0.0.0.0");
        assert_eq!(format_ipv4(0xFFFFFFFF), "255.255.255.255");
        assert_eq!(format_ipv4(0x7F000001), "127.0.0.1");
    }

    #[test]
    fn test_format_ipv4_private_ranges() {
        // 10.0.0.0/8
        assert_eq!(format_ipv4(0x0A123456), "10.18.52.86");
        // 172.16.0.0/12
        assert_eq!(format_ipv4(0xAC100001), "172.16.0.1");
        // 192.168.0.0/16
        assert_eq!(format_ipv4(0xC0A80001), "192.168.0.1");
    }

    // ========== format_ipv6 tests ==========

    #[test]
    fn test_format_ipv6_common() {
        let loopback = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ipv6(&loopback), Some("::1".to_string()));

        let doc = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ipv6(&doc), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_format_ipv6_link_local() {
        let link_local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ipv6(&link_local), Some("fe80::1".to_string()));
    }

    #[test]
    fn test_format_ipv6_invalid_length() {
        assert_eq!(format_ipv6(&[0; 15]), None);
        assert_eq!(format_ipv6(&[0; 17]), None);
        assert_eq!(format_ipv6(&[]), None);
    }

    // ========== format_mac tests ==========

    #[test]
    fn test_format_mac_common() {
        let bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&bytes), Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn test_format_mac_broadcast() {
        let broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            format_mac(&broadcast),
            Some("ff:ff:ff:ff:ff:ff".to_string())
        );
    }

    #[test]
    fn test_format_mac_zeros() {
        let zeros = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(format_mac(&zeros), Some("00:00:00:00:00:00".to_string()));
    }

    #[test]
    fn test_format_mac_invalid_length() {
        assert_eq!(format_mac(&[0; 5]), None);
        assert_eq!(format_mac(&[0; 7]), None);
        assert_eq!(format_mac(&[]), None);
    }

    // ========== detect_address_column tests ==========

    #[test]
    fn test_detect_ipv4_columns() {
        // Standard IP columns
        let field = FieldDescriptor::new("src_ip", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = FieldDescriptor::new("dst_ip", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        // View-style columns (src_ip_v4)
        let field = FieldDescriptor::new("src_ip_v4", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        // ARP columns
        let field = FieldDescriptor::new("sender_ip", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = FieldDescriptor::new("target_ip", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        // DHCP columns
        let field = FieldDescriptor::new("ciaddr", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = FieldDescriptor::new("yiaddr", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = FieldDescriptor::new("router", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));
    }

    #[test]
    fn test_detect_non_ip_uint32() {
        // These UInt32 columns should NOT be detected as IPs
        let field = FieldDescriptor::new("count", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), None);

        let field = FieldDescriptor::new("xid", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), None);

        let field = FieldDescriptor::new("seq", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), None);

        let field = FieldDescriptor::new("flow_label", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), None);
    }

    #[test]
    fn test_detect_ipv6_columns() {
        let field = FieldDescriptor::new("src_ip", DataKind::FixedBinary(16));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));

        let field = FieldDescriptor::new("dst_ip", DataKind::FixedBinary(16));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));

        let field = FieldDescriptor::new("src_ip_v6", DataKind::FixedBinary(16));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));

        let field = FieldDescriptor::new("ndp_target_address", DataKind::FixedBinary(16));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));
    }

    #[test]
    fn test_detect_mac_columns() {
        let field = FieldDescriptor::new("src_mac", DataKind::FixedBinary(6));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));

        let field = FieldDescriptor::new("dst_mac", DataKind::FixedBinary(6));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));

        let field = FieldDescriptor::new("chaddr", DataKind::FixedBinary(6));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));

        let field = FieldDescriptor::new("sender_mac", DataKind::FixedBinary(6));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));
    }

    #[test]
    fn test_detect_non_mac_binary6() {
        // A FixedBinary(6) with non-MAC name should not be detected
        let field = FieldDescriptor::new("some_data", DataKind::FixedBinary(6));
        assert_eq!(detect_address_column(&field), None);
    }

    #[test]
    fn test_detect_wrong_type() {
        // Right name but wrong type should not match
        let field = FieldDescriptor::new("src_ip", DataKind::String);
        assert_eq!(detect_address_column(&field), None);

        let field = FieldDescriptor::new("src_mac", DataKind::String);
        assert_eq!(detect_address_column(&field), None);
    }

    #[test]
    fn test_detect_case_insensitive() {
        let field = FieldDescriptor::new("SRC_IP", DataKind::UInt32);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = FieldDescriptor::new("Dst_Mac", DataKind::FixedBinary(6));
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));
    }

    #[test]
    fn writers_match_formatters() {
        for value in [0u32, 0x0A000001, 0xC0A80101, u32::MAX] {
            let mut s = String::new();
            write_ipv4(value, &mut s).unwrap();
            assert_eq!(s, format_ipv4(value));
        }

        let v6: [[u8; 16]; 3] = [
            [0; 16],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xff; 16],
        ];
        for bytes in v6 {
            let mut s = String::new();
            write_ipv6(&bytes, &mut s).unwrap();
            assert_eq!(Some(s), format_ipv6(&bytes));
        }

        for bytes in [[0u8; 6], [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], [0x0a; 6]] {
            let mut s = String::new();
            write_mac(&bytes, &mut s).unwrap();
            assert_eq!(Some(s), format_mac(&bytes));
        }
    }

    // ========== the hand-written kernels against std's formatting ==========

    /// A sink that records each `write_str` it gets.
    #[derive(Default)]
    struct Pieces(Vec<String>);

    impl fmt::Write for Pieces {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.0.push(s.to_owned());
            Ok(())
        }
    }

    /// What `write_ipv4` and `format_ipv4` did before they were written by
    /// hand: std's `Display` of the address.
    fn std_ipv4(value: u32) -> String {
        std::net::Ipv4Addr::from(value).to_string()
    }

    /// What `write_mac`, `format_mac` and the row writer's string form did
    /// before: `{:02x}` pairs joined by colons.
    fn std_mac(b: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }

    fn check_ipv4(value: u32) {
        let expected = std_ipv4(value);
        let mut buf = [0xffu8; IPV4_TEXT_LEN];
        assert_eq!(ipv4_text(value, &mut buf), expected, "{value:#010x}");
    }

    fn check_mac(bytes: [u8; 6]) {
        let expected = std_mac(&bytes);
        let mut buf = [0xffu8; MAC_TEXT_LEN];
        assert_eq!(mac_text(&bytes, &mut buf), expected, "{bytes:02x?}");
    }

    /// Every value of every pair of adjacent octets (the pairs overlap, so
    /// each octet is seen in each position with every neighbour), the other
    /// two octets taking a short, a medium and a long value.
    #[test]
    fn ipv4_text_is_std_display_for_every_octet_pair() {
        for shift in [0, 8, 16] {
            for fill in [0u32, 0x0909_0909, 0x6363_6363, 0xffff_ffff] {
                for pair in 0..=u32::from(u16::MAX) {
                    let mask = 0xffffu32 << shift;
                    check_ipv4((fill & !mask) | (pair << shift));
                }
            }
        }
    }

    #[test]
    fn mac_text_is_the_02x_form_for_every_octet_pair() {
        for position in 0..5 {
            for fill in [0x00u8, 0x0a, 0xa0, 0xff] {
                for pair in 0..=u16::MAX {
                    let mut bytes = [fill; 6];
                    bytes[position..position + 2].copy_from_slice(&pair.to_be_bytes());
                    check_mac(bytes);
                }
            }
        }
    }

    #[test]
    fn public_forms_agree_with_std_and_write_once() {
        let v4 = [
            0u32,
            1,
            9,
            10,
            99,
            100,
            255,
            0x0A00_0001,
            0xC0A8_0101,
            u32::MAX,
        ];
        for value in v4 {
            let expected = std_ipv4(value);
            assert_eq!(format_ipv4(value), expected);
            let mut pieces = Pieces::default();
            write_ipv4(value, &mut pieces).unwrap();
            assert_eq!(pieces.0, [expected]);
        }
        for bytes in [[0u8; 6], [0xff; 6], [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]] {
            let expected = std_mac(&bytes);
            assert_eq!(format_mac(&bytes), Some(expected.clone()));
            let mut pieces = Pieces::default();
            write_mac(&bytes, &mut pieces).unwrap();
            assert_eq!(pieces.0, [expected]);
        }
    }

    // ========== ipv6_text against std's `Display for Ipv6Addr` ==========
    //
    // `ipv6_text` is what std printed when it was written (Rust 1.97): RFC
    // 5952, and the dotted form for IPv4-mapped addresses only. These tests
    // compare with the std the tests are built with, so they fail if a later
    // std prints an address differently; the text stays as it is until
    // `ipv6_text` is changed.

    fn std_ipv6(bytes: &[u8; 16]) -> String {
        std::net::Ipv6Addr::from(*bytes).to_string()
    }

    fn v6(groups: [u16; 8]) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (pair, group) in bytes.chunks_mut(2).zip(groups) {
            pair.copy_from_slice(&group.to_be_bytes());
        }
        bytes
    }

    /// The kernel alone: the comparison the exhaustive loops make.
    fn check_ipv6(bytes: [u8; 16]) {
        let expected = std_ipv6(&bytes);
        let mut buf = [0xffu8; IPV6_TEXT_LEN];
        assert_eq!(ipv6_text(&bytes, &mut buf), expected, "{bytes:02x?}");
    }

    /// The kernel, the `String` form and the writer, which hands its sink
    /// one piece.
    fn check_ipv6_forms(bytes: [u8; 16]) {
        let expected = std_ipv6(&bytes);
        check_ipv6(bytes);
        assert_eq!(format_ipv6(&bytes), Some(expected.clone()));
        let mut pieces = Pieces::default();
        write_ipv6(&bytes, &mut pieces).unwrap();
        assert_eq!(pieces.0, [expected]);
    }

    /// SplitMix64: a fixed sequence of well-mixed values.
    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn address(&mut self) -> [u8; 16] {
            ((u128::from(self.next()) << 64) | u128::from(self.next())).to_be_bytes()
        }
    }

    /// Non-zero groups of each width in hex digits, among them ones whose
    /// leading nibbles are zero.
    const FILLS: [u16; 6] = [0x1, 0xf, 0x10, 0x0a0, 0x0fff, 0xffff];

    /// Each group takes every value: alone among zeros, and among groups of
    /// one to four hex digits.
    #[test]
    fn ipv6_text_is_std_display_for_every_value_of_each_group() {
        for position in 0..8 {
            for fill in [0, 0x1, 0x0a0, 0x0fff, 0xffff] {
                for group in 0..=u16::MAX {
                    let mut groups = [fill; 8];
                    groups[position] = group;
                    check_ipv6(v6(groups));
                }
            }
        }
    }

    /// Every arrangement of zero and non-zero groups: each position and
    /// length of a run of zeros, and each set of runs to choose among.
    #[test]
    fn ipv6_text_is_std_display_for_every_zero_run_pattern() {
        for mask in 0..=u8::MAX {
            for fill in FILLS {
                let uniform = std::array::from_fn(|i| if mask >> i & 1 == 0 { 0 } else { fill });
                check_ipv6_forms(v6(uniform));
                // The same pattern with a different width in each group.
                let mixed = std::array::from_fn(|i| {
                    if mask >> i & 1 == 0 {
                        0
                    } else {
                        FILLS[(i + usize::from(fill)) % FILLS.len()]
                    }
                });
                check_ipv6_forms(v6(mixed));
            }
        }
    }

    /// The prefixes std has or had a form of its own for: `::` and `::1`,
    /// IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d` in an
    /// earlier std, `::xxxx:xxxx` in this one), and their neighbours, which
    /// never had one.
    const SPECIAL_PREFIXES: [[u16; 6]; 8] = [
        [0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0xffff],
        [0, 0, 0, 0, 0xffff, 0],
        [0, 0, 0, 0, 0, 0xfffe],
        [0, 0, 0, 0, 0, 0x0fff],
        [0, 0, 0, 0, 1, 0xffff],
        [0x64, 0xff9b, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0xffff],
    ];

    fn with_low_bits(prefix: [u16; 6], low: u32) -> [u8; 16] {
        let mut bytes = v6([
            prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], 0, 0,
        ]);
        bytes[12..].copy_from_slice(&low.to_be_bytes());
        bytes
    }

    #[test]
    fn ipv6_text_is_std_display_for_the_special_prefixes() {
        let mut random = Random(0x5eed_0006);
        for prefix in SPECIAL_PREFIXES {
            for low in 0..=u32::from(u16::MAX) {
                // The last group, the one before it, the two octets in the
                // middle of the dotted form, and the first group again with
                // the last one not zero.
                check_ipv6(with_low_bits(prefix, low));
                check_ipv6(with_low_bits(prefix, low << 16));
                check_ipv6(with_low_bits(prefix, low << 8));
                check_ipv6(with_low_bits(prefix, low << 16 | 0x0101));
            }
            for _ in 0..50_000 {
                let low = u32::try_from(random.next() >> 32).unwrap();
                check_ipv6_forms(with_low_bits(prefix, low));
            }
        }
    }

    /// What the text is, said without std: these hold whatever std does.
    #[test]
    fn ipv6_text_special_cases() {
        let text = |groups| format_ipv6(&v6(groups)).unwrap();
        assert_eq!(text([0; 8]), "::");
        assert_eq!(text([0, 0, 0, 0, 0, 0, 0, 1]), "::1");
        assert_eq!(
            text([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201]),
            "::ffff:192.0.2.1"
        );
        assert_eq!(text([0, 0, 0, 0, 0, 0xffff, 0, 0]), "::ffff:0.0.0.0");
        assert_eq!(
            text([0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff]),
            "::ffff:255.255.255.255"
        );
        // IPv4-compatible and the NAT64 prefix are in hex.
        assert_eq!(text([0, 0, 0, 0, 0, 0, 0xc000, 0x0201]), "::c000:201");
        assert_eq!(
            text([0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201]),
            "64:ff9b::c000:201"
        );
        // The first of two runs as long; a longer second run; one zero alone.
        assert_eq!(text([1, 0, 0, 2, 0, 0, 3, 4]), "1::2:0:0:3:4");
        assert_eq!(text([1, 0, 0, 2, 0, 0, 0, 4]), "1:0:0:2::4");
        assert_eq!(text([1, 0, 2, 0, 3, 0, 4, 0]), "1:0:2:0:3:0:4:0");
        assert_eq!(text([1, 2, 3, 4, 5, 6, 0, 0]), "1:2:3:4:5:6::");
        assert_eq!(text([0, 0, 1, 2, 3, 4, 5, 6]), "::1:2:3:4:5:6");
        assert_eq!(text([0xffff; 8]), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        assert_eq!(
            text([0x0abc, 0x00de, 0x000f, 0x1000, 0x0100, 0x0010, 1, 0xa]),
            "abc:de:f:1000:100:10:1:a"
        );
    }

    #[test]
    fn ipv6_text_is_std_display_for_random_addresses() {
        let mut random = Random(0x5eed_0006_0000_0001);
        for _ in 0..200_000 {
            check_ipv6_forms(random.address());
        }
        // Random bits seldom make a zero group: the same with groups zeroed.
        for _ in 0..200_000 {
            let mut bytes = random.address();
            let mask = random.next();
            for (group, pair) in bytes.chunks_mut(2).enumerate() {
                if mask >> group & 1 == 0 {
                    pair.fill(0);
                }
            }
            check_ipv6_forms(bytes);
        }
    }

    mod sampled {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20_000))]

            #[test]
            fn ipv4_text_is_std_display(value in any::<u32>()) {
                check_ipv4(value);
                prop_assert_eq!(format_ipv4(value), std_ipv4(value));
                let mut written = String::new();
                write_ipv4(value, &mut written).unwrap();
                prop_assert_eq!(written, std_ipv4(value));
            }

            #[test]
            fn mac_text_is_the_02x_form(bytes in any::<[u8; 6]>()) {
                check_mac(bytes);
                prop_assert_eq!(format_mac(&bytes), Some(std_mac(&bytes)));
                let mut written = String::new();
                write_mac(&bytes, &mut written).unwrap();
                prop_assert_eq!(written, std_mac(&bytes));
            }
        }
    }
}
