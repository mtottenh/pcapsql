//! Field value types for protocol parsing.
//!
//! A [`FieldValue`] owns nothing. A string, a byte string or a list is a
//! slice, either of the packet it was parsed from or of the arena of the
//! packet's [`ParseBuf`](super::ParseBuf), where a parser puts the values it
//! has to construct ([`FieldSink`](super::FieldSink)). The value is therefore
//! `Copy`, and forgetting a packet's fields runs no destructor.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::format::{mac_text, MAC_TEXT_LEN};

/// Possible field value types (maps to Arrow types).
///
/// The lifetime parameter `'data` is that of the packet and of the arena
/// the value may point into: the value lives as long as the packet's layers
/// do.
#[derive(Debug, Clone, Copy)]
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
    /// Signed 8-bit integer
    Int8(i8),
    /// Signed 64-bit integer
    Int64(i64),
    /// 64-bit float (fixed-point protocol fields converted to real units)
    Float64(f64),
    /// Boolean value
    Bool(bool),

    // === Network types (small fixed arrays) ===
    /// IP address (v4 or v6)
    IpAddr(IpAddr),
    /// MAC address (6 bytes)
    MacAddr([u8; 6]),

    // === Slices of the packet, of the arena, or static ===
    /// A string: one that exists verbatim in the packet (a TLS SNI, an SSH
    /// version), a static one (an enum's name), or one a parser constructed
    /// in the arena (a DNS name, a joined list).
    Str(&'data str),
    /// A byte string, in the packet or constructed in the arena.
    Bytes(&'data [u8]),
    /// A list of values (a multi-valued field such as the DNS answers), in
    /// the arena. All elements should be of the same type.
    List(&'data [FieldValue<'data>]),

    /// Null/missing value
    Null,
}

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
        mac_text(mac, &mut [0; MAC_TEXT_LEN]).to_owned()
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
            FieldValue::Int8(v) => Some(*v as i64),
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
            _ => None,
        }
    }

    /// Try to get as bytes reference.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Try to get as string (owned, allocates).
    pub fn as_string(&self) -> Option<String> {
        match self {
            FieldValue::Str(s) => Some(s.to_string()),
            FieldValue::IpAddr(addr) => Some(addr.to_string()),
            FieldValue::MacAddr(mac) => Some(Self::format_mac(mac)),
            FieldValue::UInt8(v) => Some(v.to_string()),
            FieldValue::UInt16(v) => Some(v.to_string()),
            FieldValue::UInt32(v) => Some(v.to_string()),
            FieldValue::UInt64(v) => Some(v.to_string()),
            FieldValue::Int8(v) => Some(v.to_string()),
            FieldValue::Int64(v) => Some(v.to_string()),
            FieldValue::Float64(v) => Some(v.to_string()),
            FieldValue::Bool(v) => Some(v.to_string()),
            _ => None,
        }
    }

    /// Try to get as list reference.
    pub fn as_list(&self) -> Option<&[FieldValue<'data>]> {
        match self {
            FieldValue::List(items) => Some(items),
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
}

impl<'data> std::fmt::Display for FieldValue<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValue::UInt8(v) => write!(f, "{v}"),
            FieldValue::UInt16(v) => write!(f, "{v}"),
            FieldValue::UInt32(v) => write!(f, "{v}"),
            FieldValue::UInt64(v) => write!(f, "{v}"),
            FieldValue::Int8(v) => write!(f, "{v}"),
            FieldValue::Int64(v) => write!(f, "{v}"),
            FieldValue::Float64(v) => write!(f, "{v}"),
            FieldValue::Bool(v) => write!(f, "{v}"),
            FieldValue::Str(s) => write!(f, "{s}"),
            FieldValue::Bytes(b) => write!(f, "[{} bytes]", b.len()),
            FieldValue::IpAddr(addr) => write!(f, "{addr}"),
            FieldValue::MacAddr(mac) => f.write_str(mac_text(mac, &mut [0; MAC_TEXT_LEN])),
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

// Not derived: values of different lifetimes compare.
impl<'a, 'b> PartialEq<FieldValue<'b>> for FieldValue<'a> {
    fn eq(&self, other: &FieldValue<'b>) -> bool {
        match (self, other) {
            (FieldValue::UInt8(a), FieldValue::UInt8(b)) => a == b,
            (FieldValue::UInt16(a), FieldValue::UInt16(b)) => a == b,
            (FieldValue::UInt32(a), FieldValue::UInt32(b)) => a == b,
            (FieldValue::UInt64(a), FieldValue::UInt64(b)) => a == b,
            (FieldValue::Int8(a), FieldValue::Int8(b)) => a == b,
            (FieldValue::Int64(a), FieldValue::Int64(b)) => a == b,
            (FieldValue::Float64(a), FieldValue::Float64(b)) => a == b,
            (FieldValue::Bool(a), FieldValue::Bool(b)) => a == b,
            (FieldValue::IpAddr(a), FieldValue::IpAddr(b)) => a == b,
            (FieldValue::MacAddr(a), FieldValue::MacAddr(b)) => a == b,
            (FieldValue::Str(a), FieldValue::Str(b)) => a == b,
            (FieldValue::Bytes(a), FieldValue::Bytes(b)) => a == b,
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
    fn a_value_is_small_and_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<FieldValue<'_>>();
        assert_eq!(std::mem::size_of::<FieldValue<'_>>(), 24);
        assert_eq!(std::mem::size_of::<(&'static str, FieldValue<'_>)>(), 40);
    }

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
        let packet = [0x45, 0x00, 0x00, 0x28, 0xde, 0xad, 0xbe, 0xef];
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
    fn values_of_different_lifetimes_compare() {
        let text = String::from("hello");
        let bytes = vec![1u8, 2, 3, 4];
        assert_eq!(FieldValue::Str(&text), FieldValue::Str("hello"));
        assert_ne!(FieldValue::Str(&text), FieldValue::Str("world"));
        assert_eq!(FieldValue::Bytes(&bytes), FieldValue::Bytes(&[1, 2, 3, 4]));
        assert_ne!(FieldValue::Str("ab"), FieldValue::Bytes(b"ab"));
    }

    #[test]
    fn test_as_str() {
        let str_val = FieldValue::Str("hello");
        let int_val = FieldValue::UInt32(42);

        assert_eq!(str_val.as_str(), Some("hello"));
        assert_eq!(int_val.as_str(), None);
    }

    #[test]
    fn test_as_bytes() {
        let bytes_val = FieldValue::Bytes(&[1, 2, 3]);
        let int_val = FieldValue::UInt32(42);

        assert_eq!(bytes_val.as_bytes(), Some(&[1u8, 2, 3][..]));
        assert_eq!(int_val.as_bytes(), None);
    }

    #[test]
    fn test_list_basic() {
        let list = FieldValue::List(&[
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
        let list = FieldValue::List(&[FieldValue::UInt32(10), FieldValue::UInt32(20)]);
        assert_eq!(format!("{}", list), "[10, 20]");

        let empty: FieldValue = FieldValue::List(&[]);
        assert_eq!(format!("{}", empty), "[]");

        let string_list = FieldValue::List(&[FieldValue::Str("hello"), FieldValue::Str("world")]);
        assert_eq!(format!("{}", string_list), "[hello, world]");
    }

    #[test]
    fn test_list_equality() {
        let list1 = FieldValue::List(&[FieldValue::UInt32(1), FieldValue::UInt32(2)]);
        let list2 = FieldValue::List(&[FieldValue::UInt32(1), FieldValue::UInt32(2)]);
        let list3 = FieldValue::List(&[FieldValue::UInt32(1), FieldValue::UInt32(3)]);

        assert_eq!(list1, list2);
        assert_ne!(list1, list3);
    }
}
