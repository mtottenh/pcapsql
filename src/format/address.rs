//! Network address formatting and detection.
//!
//! Provides functions to:
//! - Format binary address values as human-readable strings
//! - Detect which columns represent network addresses based on type and name

use std::net::{Ipv4Addr, Ipv6Addr};

use arrow::datatypes::{DataType, Field};

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
/// use pcapsql::format::format_ipv4;
///
/// assert_eq!(format_ipv4(0xC0A80101), "192.168.1.1");
/// assert_eq!(format_ipv4(0x0A000001), "10.0.0.1");
/// ```
pub fn format_ipv4(value: u32) -> String {
    let bytes = value.to_be_bytes();
    Ipv4Addr::from(bytes).to_string()
}

/// Format 16 bytes as an IPv6 address string.
///
/// Returns `None` if the slice is not exactly 16 bytes.
///
/// # Example
///
/// ```
/// use pcapsql::format::format_ipv6;
///
/// let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// assert_eq!(format_ipv6(&bytes), Some("2001:db8::1".to_string()));
/// ```
pub fn format_ipv6(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 16 {
        return None;
    }
    let octets: [u8; 16] = bytes.try_into().ok()?;
    Some(Ipv6Addr::from(octets).to_string())
}

/// Format 6 bytes as a MAC address string in colon-separated hex format.
///
/// Returns `None` if the slice is not exactly 6 bytes.
///
/// # Example
///
/// ```
/// use pcapsql::format::format_mac;
///
/// let bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// assert_eq!(format_mac(&bytes), Some("aa:bb:cc:dd:ee:ff".to_string()));
/// ```
pub fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

/// Detect if a column represents a network address based on its type and name.
///
/// This uses a hybrid approach: both the Arrow data type AND the column name
/// must match expected patterns. This prevents false positives (e.g., a UInt32
/// column named "count" won't be treated as an IPv4 address).
///
/// # Detection Rules
///
/// | AddressKind | Arrow Type | Name Patterns |
/// |-------------|------------|---------------|
/// | Ipv4 | UInt32 | `*_ip`, `*_ip_*`, `*addr`, `router`, `server_id`, `subnet_mask`, `ciaddr`, `yiaddr`, `siaddr`, `giaddr` |
/// | Ipv6 | FixedSizeBinary(16) | `*_ip`, `*_ip_*`, `*_address`, `*_prefix` |
/// | Mac | FixedSizeBinary(6) | `*_mac`, `chaddr`, `*_mac_*` |
pub fn detect_address_column(field: &Field) -> Option<AddressKind> {
    let name = field.name().to_lowercase();

    match field.data_type() {
        DataType::UInt32 => {
            // IPv4: must have IP-related name
            if is_ipv4_column_name(&name) {
                Some(AddressKind::Ipv4)
            } else {
                None
            }
        }
        DataType::FixedSizeBinary(16) => {
            // IPv6: must have IP/address-related name
            if is_ipv6_column_name(&name) {
                Some(AddressKind::Ipv6)
            } else {
                None
            }
        }
        DataType::FixedSizeBinary(6) => {
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
        assert_eq!(format_mac(&broadcast), Some("ff:ff:ff:ff:ff:ff".to_string()));
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
        let field = Field::new("src_ip", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = Field::new("dst_ip", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        // View-style columns (src_ip_v4)
        let field = Field::new("src_ip_v4", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        // ARP columns
        let field = Field::new("sender_ip", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = Field::new("target_ip", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        // DHCP columns
        let field = Field::new("ciaddr", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = Field::new("yiaddr", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = Field::new("router", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));
    }

    #[test]
    fn test_detect_non_ip_uint32() {
        // These UInt32 columns should NOT be detected as IPs
        let field = Field::new("count", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), None);

        let field = Field::new("xid", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), None);

        let field = Field::new("seq", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), None);

        let field = Field::new("flow_label", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), None);
    }

    #[test]
    fn test_detect_ipv6_columns() {
        let field = Field::new("src_ip", DataType::FixedSizeBinary(16), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));

        let field = Field::new("dst_ip", DataType::FixedSizeBinary(16), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));

        let field = Field::new("src_ip_v6", DataType::FixedSizeBinary(16), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));

        let field = Field::new("ndp_target_address", DataType::FixedSizeBinary(16), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv6));
    }

    #[test]
    fn test_detect_mac_columns() {
        let field = Field::new("src_mac", DataType::FixedSizeBinary(6), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));

        let field = Field::new("dst_mac", DataType::FixedSizeBinary(6), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));

        let field = Field::new("chaddr", DataType::FixedSizeBinary(6), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));

        let field = Field::new("sender_mac", DataType::FixedSizeBinary(6), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));
    }

    #[test]
    fn test_detect_non_mac_binary6() {
        // A FixedSizeBinary(6) with non-MAC name should not be detected
        let field = Field::new("some_data", DataType::FixedSizeBinary(6), true);
        assert_eq!(detect_address_column(&field), None);
    }

    #[test]
    fn test_detect_wrong_type() {
        // Right name but wrong type should not match
        let field = Field::new("src_ip", DataType::Utf8, true);
        assert_eq!(detect_address_column(&field), None);

        let field = Field::new("src_mac", DataType::Utf8, true);
        assert_eq!(detect_address_column(&field), None);
    }

    #[test]
    fn test_detect_case_insensitive() {
        let field = Field::new("SRC_IP", DataType::UInt32, true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Ipv4));

        let field = Field::new("Dst_Mac", DataType::FixedSizeBinary(6), true);
        assert_eq!(detect_address_column(&field), Some(AddressKind::Mac));
    }
}
