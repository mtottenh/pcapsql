//! Field value types for protocol parsing.
//!
//! This module provides zero-copy field values where possible. FieldValue
//! can reference packet data directly (Str, Bytes variants) or own data
//! when construction is necessary (OwnedString, OwnedBytes).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use compact_str::CompactString;

/// Possible field value types (maps to Arrow types).
///
/// FieldValue supports zero-copy parsing where possible:
/// - `Str` and `Bytes` reference packet data directly
/// - `OwnedString` and `OwnedBytes` are used when values must be constructed
///
/// The lifetime parameter `'data` ties the value to the packet/buffer data.
#[derive(Debug, Clone)]
pub enum FieldValue<'data> {
    // === Primitives (trivial copies) ===
    /// Unsigned 8-bit integer
    UInt8(u8),
    /// Unsigned 16-bit integer
    UInt16(u16),
    /// Unsigned 32-bit integer
    UInt32(u32),
    /// Unsigned 64-bit integer
    UInt64(u64),
    /// Signed 64-bit integer
    Int64(i64),
    /// Boolean value
    Bool(bool),

    // === Network types (small fixed arrays) ===
    /// IP address (v4 or v6)
    IpAddr(IpAddr),
    /// MAC address (6 bytes)
    MacAddr([u8; 6]),

    // === Zero-copy references into packet/buffer ===
    /// Zero-copy string reference into packet data.
    /// Use for strings that exist verbatim in the packet (e.g., TLS SNI, SSH version).
    Str(&'data str),
    /// Zero-copy byte slice reference into packet data.
    /// Use for payload or binary data that exists verbatim in the packet.
    Bytes(&'data [u8]),

    // === Constructed/owned values ===
    /// Owned string for constructed values (DNS names, joined lists, enum names).
    /// Uses CompactString for small-string optimization (inline up to 24 bytes).
    OwnedString(CompactString),
    /// Owned bytes for constructed/decoded data.
    OwnedBytes(Vec<u8>),

    /// List of values (for multi-valued fields like DNS answers).
    /// All elements should be of the same type.
    /// Note: Uses Vec because FieldValue is recursive (SmallVec inline storage causes infinite size).
    List(Vec<FieldValue<'data>>),

    /// Null/missing value
    Null,
}

/// Type alias for FieldValue that owns all its data.
/// Useful for caching where lifetime of packet data is not available.
pub type OwnedFieldValue = FieldValue<'static>;

impl<'data> FieldValue<'data> {
    /// Create a MAC address from bytes.
    pub fn mac(bytes: &[u8]) -> Self {
        if bytes.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&bytes[..6]);
            FieldValue::MacAddr(mac)
        } else {
            FieldValue::Null
        }
    }

    /// Create an IPv4 address from bytes.
    pub fn ipv4(bytes: &[u8]) -> Self {
        if bytes.len() >= 4 {
            FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        } else {
            FieldValue::Null
        }
    }

    /// Create an IPv6 address from bytes.
    pub fn ipv6(bytes: &[u8]) -> Self {
        if bytes.len() >= 16 {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes[..16]);
            FieldValue::IpAddr(IpAddr::V6(Ipv6Addr::from(arr)))
        } else {
            FieldValue::Null
        }
    }

    /// Format a MAC address as a string.
    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    /// Check if this is a null value.
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }

    /// Try to get as u64.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            FieldValue::UInt8(v) => Some(*v as u64),
            FieldValue::UInt16(v) => Some(*v as u64),
            FieldValue::UInt32(v) => Some(*v as u64),
            FieldValue::UInt64(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Int64(v) => Some(*v),
            FieldValue::UInt8(v) => Some(*v as i64),
            FieldValue::UInt16(v) => Some(*v as i64),
            FieldValue::UInt32(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Try to get as u16.
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            FieldValue::UInt16(v) => Some(*v),
            FieldValue::UInt8(v) => Some(*v as u16),
            _ => None,
        }
    }

    /// Try to get as str reference.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(s) => Some(s),
            FieldValue::OwnedString(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Try to get as bytes reference.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Bytes(b) => Some(b),
            FieldValue::OwnedBytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    /// Try to get as string (owned, allocates).
    pub fn as_string(&self) -> Option<String> {
        match self {
            FieldValue::Str(s) => Some(s.to_string()),
            FieldValue::OwnedString(s) => Some(s.to_string()),
            FieldValue::IpAddr(addr) => Some(addr.to_string()),
            FieldValue::MacAddr(mac) => Some(Self::format_mac(mac)),
            FieldValue::UInt8(v) => Some(v.to_string()),
            FieldValue::UInt16(v) => Some(v.to_string()),
            FieldValue::UInt32(v) => Some(v.to_string()),
            FieldValue::UInt64(v) => Some(v.to_string()),
            FieldValue::Int64(v) => Some(v.to_string()),
            FieldValue::Bool(v) => Some(v.to_string()),
            _ => None,
        }
    }

    /// Try to get as list reference.
    pub fn as_list(&self) -> Option<&[FieldValue<'data>]> {
        match self {
            FieldValue::List(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// Get the number of elements if this is a list, or None otherwise.
    pub fn list_len(&self) -> Option<usize> {
        match self {
            FieldValue::List(items) => Some(items.len()),
            _ => None,
        }
    }

    /// Convert to an owned version (for caching).
    /// Copies borrowed data into owned variants.
    pub fn to_owned(&self) -> FieldValue<'static> {
        match self {
            FieldValue::UInt8(v) => FieldValue::UInt8(*v),
            FieldValue::UInt16(v) => FieldValue::UInt16(*v),
            FieldValue::UInt32(v) => FieldValue::UInt32(*v),
            FieldValue::UInt64(v) => FieldValue::UInt64(*v),
            FieldValue::Int64(v) => FieldValue::Int64(*v),
            FieldValue::Bool(v) => FieldValue::Bool(*v),
            FieldValue::IpAddr(v) => FieldValue::IpAddr(*v),
            FieldValue::MacAddr(v) => FieldValue::MacAddr(*v),
            FieldValue::Str(s) => FieldValue::OwnedString(CompactString::new(s)),
            FieldValue::Bytes(b) => FieldValue::OwnedBytes(b.to_vec()),
            FieldValue::OwnedString(s) => FieldValue::OwnedString(s.clone()),
            FieldValue::OwnedBytes(b) => FieldValue::OwnedBytes(b.clone()),
            FieldValue::List(items) => {
                FieldValue::List(items.iter().map(|v| v.to_owned()).collect())
            }
            FieldValue::Null => FieldValue::Null,
        }
    }
}

impl<'data> std::fmt::Display for FieldValue<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValue::UInt8(v) => write!(f, "{v}"),
            FieldValue::UInt16(v) => write!(f, "{v}"),
            FieldValue::UInt32(v) => write!(f, "{v}"),
            FieldValue::UInt64(v) => write!(f, "{v}"),
            FieldValue::Int64(v) => write!(f, "{v}"),
            FieldValue::Bool(v) => write!(f, "{v}"),
            FieldValue::Str(s) => write!(f, "{s}"),
            FieldValue::OwnedString(s) => write!(f, "{s}"),
            FieldValue::Bytes(b) => write!(f, "[{} bytes]", b.len()),
            FieldValue::OwnedBytes(b) => write!(f, "[{} bytes]", b.len()),
            FieldValue::IpAddr(addr) => write!(f, "{addr}"),
            FieldValue::MacAddr(mac) => write!(f, "{}", Self::format_mac(mac)),
            FieldValue::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            FieldValue::Null => write!(f, "NULL"),
        }
    }
}

// Implement PartialEq manually to handle borrowed vs owned comparison
impl<'a, 'b> PartialEq<FieldValue<'b>> for FieldValue<'a> {
    fn eq(&self, other: &FieldValue<'b>) -> bool {
        match (self, other) {
            (FieldValue::UInt8(a), FieldValue::UInt8(b)) => a == b,
            (FieldValue::UInt16(a), FieldValue::UInt16(b)) => a == b,
            (FieldValue::UInt32(a), FieldValue::UInt32(b)) => a == b,
            (FieldValue::UInt64(a), FieldValue::UInt64(b)) => a == b,
            (FieldValue::Int64(a), FieldValue::Int64(b)) => a == b,
            (FieldValue::Bool(a), FieldValue::Bool(b)) => a == b,
            (FieldValue::IpAddr(a), FieldValue::IpAddr(b)) => a == b,
            (FieldValue::MacAddr(a), FieldValue::MacAddr(b)) => a == b,
            // String comparisons: allow cross-comparison between Str and OwnedString
            (FieldValue::Str(a), FieldValue::Str(b)) => a == b,
            (FieldValue::Str(a), FieldValue::OwnedString(b)) => *a == b.as_str(),
            (FieldValue::OwnedString(a), FieldValue::Str(b)) => a.as_str() == *b,
            (FieldValue::OwnedString(a), FieldValue::OwnedString(b)) => a == b,
            // Bytes comparisons: allow cross-comparison between Bytes and OwnedBytes
            (FieldValue::Bytes(a), FieldValue::Bytes(b)) => a == b,
            (FieldValue::Bytes(a), FieldValue::OwnedBytes(b)) => *a == b.as_slice(),
            (FieldValue::OwnedBytes(a), FieldValue::Bytes(b)) => a.as_slice() == *b,
            (FieldValue::OwnedBytes(a), FieldValue::OwnedBytes(b)) => a == b,
            // List comparison: element-wise
            (FieldValue::List(a), FieldValue::List(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
            }
            (FieldValue::Null, FieldValue::Null) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_str() {
        let packet = b"GET /index.html HTTP/1.1\r\n";
        let value = FieldValue::Str(std::str::from_utf8(&packet[4..15]).unwrap());

        match value {
            FieldValue::Str(s) => {
                assert_eq!(s, "/index.html");
                // Verify it's a reference, not owned
                assert!(std::ptr::eq(s.as_ptr(), packet[4..].as_ptr()));
            }
            _ => panic!("Expected Str variant"),
        }
    }

    #[test]
    fn test_zero_copy_bytes() {
        let packet = vec![0x45, 0x00, 0x00, 0x28, 0xde, 0xad, 0xbe, 0xef];
        let payload = &packet[4..];
        let value = FieldValue::Bytes(payload);

        match value {
            FieldValue::Bytes(b) => {
                assert_eq!(b, &[0xde, 0xad, 0xbe, 0xef]);
                assert!(std::ptr::eq(b.as_ptr(), packet[4..].as_ptr()));
            }
            _ => panic!("Expected Bytes variant"),
        }
    }

    #[test]
    fn test_owned_string() {
        // DNS domain name must be constructed (labels + dots)
        let domain = CompactString::new("www.example.com");
        let value = FieldValue::OwnedString(domain);

        match value {
            FieldValue::OwnedString(s) => assert_eq!(s.as_str(), "www.example.com"),
            _ => panic!("Expected OwnedString variant"),
        }
    }

    #[test]
    fn test_compact_string_inline() {
        // CompactString stores small strings inline (no heap alloc)
        let small = CompactString::new("example.com"); // 11 bytes - inline
        assert!(!small.is_heap_allocated());

        let large = CompactString::new("this-is-a-very-long-domain-name.example.com");
        assert!(large.is_heap_allocated());
    }

    #[test]
    fn test_str_owned_string_equality() {
        let borrowed = FieldValue::Str("hello");
        let owned = FieldValue::OwnedString(CompactString::new("hello"));

        assert_eq!(borrowed, owned);
        assert_eq!(owned, borrowed);
    }

    #[test]
    fn test_bytes_owned_bytes_equality() {
        let data = &[1u8, 2, 3, 4][..];
        let borrowed = FieldValue::Bytes(data);
        let owned = FieldValue::OwnedBytes(vec![1, 2, 3, 4]);

        assert_eq!(borrowed, owned);
        assert_eq!(owned, borrowed);
    }

    #[test]
    fn test_to_owned() {
        let packet = b"example.com";
        let borrowed = FieldValue::Str(std::str::from_utf8(packet).unwrap());
        let owned = borrowed.to_owned();

        // Should be equal
        assert_eq!(borrowed, owned);

        // But owned should be OwnedString
        match owned {
            FieldValue::OwnedString(s) => assert_eq!(s.as_str(), "example.com"),
            _ => panic!("Expected OwnedString variant"),
        }
    }

    #[test]
    fn test_as_str() {
        let str_val = FieldValue::Str("hello");
        let owned_val = FieldValue::OwnedString(CompactString::new("world"));
        let int_val = FieldValue::UInt32(42);

        assert_eq!(str_val.as_str(), Some("hello"));
        assert_eq!(owned_val.as_str(), Some("world"));
        assert_eq!(int_val.as_str(), None);
    }

    #[test]
    fn test_as_bytes() {
        let bytes_val = FieldValue::Bytes(&[1, 2, 3]);
        let owned_val = FieldValue::OwnedBytes(vec![4, 5, 6]);
        let int_val = FieldValue::UInt32(42);

        assert_eq!(bytes_val.as_bytes(), Some(&[1u8, 2, 3][..]));
        assert_eq!(owned_val.as_bytes(), Some(&[4u8, 5, 6][..]));
        assert_eq!(int_val.as_bytes(), None);
    }

    #[test]
    fn test_list_basic() {
        let list = FieldValue::List(vec![
            FieldValue::UInt32(1),
            FieldValue::UInt32(2),
            FieldValue::UInt32(3),
        ]);

        assert_eq!(list.list_len(), Some(3));
        assert!(list.as_list().is_some());

        let items = list.as_list().unwrap();
        assert_eq!(items[0], FieldValue::UInt32(1));
        assert_eq!(items[1], FieldValue::UInt32(2));
        assert_eq!(items[2], FieldValue::UInt32(3));
    }

    #[test]
    fn test_list_display() {
        let list = FieldValue::List(vec![
            FieldValue::UInt32(10),
            FieldValue::UInt32(20),
        ]);
        assert_eq!(format!("{}", list), "[10, 20]");

        let empty: FieldValue = FieldValue::List(vec![]);
        assert_eq!(format!("{}", empty), "[]");

        let string_list = FieldValue::List(vec![
            FieldValue::OwnedString(CompactString::new("hello")),
            FieldValue::OwnedString(CompactString::new("world")),
        ]);
        assert_eq!(format!("{}", string_list), "[hello, world]");
    }

    #[test]
    fn test_list_equality() {
        let list1 = FieldValue::List(vec![
            FieldValue::UInt32(1),
            FieldValue::UInt32(2),
        ]);
        let list2 = FieldValue::List(vec![
            FieldValue::UInt32(1),
            FieldValue::UInt32(2),
        ]);
        let list3 = FieldValue::List(vec![
            FieldValue::UInt32(1),
            FieldValue::UInt32(3),
        ]);

        assert_eq!(list1, list2);
        assert_ne!(list1, list3);
    }

    #[test]
    fn test_list_to_owned() {
        let packet = b"test";
        let list_with_borrowed: FieldValue = FieldValue::List(vec![
            FieldValue::Str(std::str::from_utf8(packet).unwrap()),
            FieldValue::UInt32(42),
        ]);

        let owned = list_with_borrowed.to_owned();

        // Should still be equal
        assert_eq!(list_with_borrowed, owned);

        // Verify it's owned
        match &owned {
            FieldValue::List(items) => {
                assert!(matches!(&items[0], FieldValue::OwnedString(_)));
                assert!(matches!(&items[1], FieldValue::UInt32(42)));
            }
            _ => panic!("Expected List variant"),
        }
    }
}
