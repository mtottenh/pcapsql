//! Field value types for protocol parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Possible field value types (maps to Arrow types).
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
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
    /// UTF-8 string
    String(String),
    /// Raw bytes
    Bytes(Vec<u8>),
    /// IP address (v4 or v6)
    IpAddr(IpAddr),
    /// MAC address (6 bytes)
    MacAddr([u8; 6]),
    /// Null/missing value
    Null,
}

impl FieldValue {
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

    /// Try to get as string.
    pub fn as_string(&self) -> Option<String> {
        match self {
            FieldValue::String(s) => Some(s.clone()),
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
}

impl std::fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValue::UInt8(v) => write!(f, "{v}"),
            FieldValue::UInt16(v) => write!(f, "{v}"),
            FieldValue::UInt32(v) => write!(f, "{v}"),
            FieldValue::UInt64(v) => write!(f, "{v}"),
            FieldValue::Int64(v) => write!(f, "{v}"),
            FieldValue::Bool(v) => write!(f, "{v}"),
            FieldValue::String(s) => write!(f, "{s}"),
            FieldValue::Bytes(b) => write!(f, "[{} bytes]", b.len()),
            FieldValue::IpAddr(addr) => write!(f, "{addr}"),
            FieldValue::MacAddr(mac) => write!(f, "{}", Self::format_mac(mac)),
            FieldValue::Null => write!(f, "NULL"),
        }
    }
}
