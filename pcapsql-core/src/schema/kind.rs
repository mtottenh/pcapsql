//! Engine-agnostic data type definitions.

/// Data types that can be represented in any columnar format.
///
/// These map to:
/// - Arrow: `DataType::*`
/// - DuckDB: `LogicalType::*`
/// - Parquet: Physical + Logical types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataKind {
    /// Boolean (true/false)
    Bool,

    /// Unsigned 8-bit integer
    UInt8,

    /// Unsigned 16-bit integer
    UInt16,

    /// Unsigned 32-bit integer (also used for IPv4 addresses)
    UInt32,

    /// Unsigned 64-bit integer
    UInt64,

    /// Signed 64-bit integer
    Int64,

    /// 64-bit floating point
    Float64,

    /// UTF-8 string
    String,

    /// Variable-length binary data
    Binary,

    /// Fixed-size binary data (e.g., MAC address = 6, IPv6 = 16)
    FixedBinary(usize),

    /// Timestamp with microsecond precision (UTC)
    TimestampMicros,

    /// Variable-length list of elements of the same type
    List(Box<DataKind>),
}

impl DataKind {
    /// Human-readable type name for display.
    pub fn type_name(&self) -> &'static str {
        match self {
            DataKind::Bool => "bool",
            DataKind::UInt8 => "u8",
            DataKind::UInt16 => "u16",
            DataKind::UInt32 => "u32",
            DataKind::UInt64 => "u64",
            DataKind::Int64 => "i64",
            DataKind::Float64 => "f64",
            DataKind::String => "string",
            DataKind::Binary => "binary",
            DataKind::FixedBinary(n) => match n {
                6 => "mac",
                16 => "ipv6",
                _ => "fixed_binary",
            },
            DataKind::TimestampMicros => "timestamp",
            DataKind::List(_) => "list",
        }
    }

    /// Size in bytes for fixed-width types, None for variable-width.
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            DataKind::Bool => Some(1),
            DataKind::UInt8 => Some(1),
            DataKind::UInt16 => Some(2),
            DataKind::UInt32 => Some(4),
            DataKind::UInt64 => Some(8),
            DataKind::Int64 => Some(8),
            DataKind::Float64 => Some(8),
            DataKind::TimestampMicros => Some(8),
            DataKind::FixedBinary(n) => Some(*n),
            DataKind::String | DataKind::Binary | DataKind::List(_) => None,
        }
    }

    /// Get the inner type for List, or None if not a List.
    pub fn list_inner(&self) -> Option<&DataKind> {
        match self {
            DataKind::List(inner) => Some(inner),
            _ => None,
        }
    }
}

impl std::fmt::Display for DataKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_names() {
        assert_eq!(DataKind::Bool.type_name(), "bool");
        assert_eq!(DataKind::UInt32.type_name(), "u32");
        assert_eq!(DataKind::String.type_name(), "string");
        assert_eq!(DataKind::FixedBinary(6).type_name(), "mac");
        assert_eq!(DataKind::FixedBinary(16).type_name(), "ipv6");
    }

    #[test]
    fn test_fixed_sizes() {
        assert_eq!(DataKind::UInt32.fixed_size(), Some(4));
        assert_eq!(DataKind::String.fixed_size(), None);
        assert_eq!(DataKind::FixedBinary(6).fixed_size(), Some(6));
    }

    #[test]
    fn test_list_type() {
        let list_u32 = DataKind::List(Box::new(DataKind::UInt32));
        assert_eq!(list_u32.type_name(), "list");
        assert_eq!(list_u32.fixed_size(), None);
        assert_eq!(list_u32.list_inner(), Some(&DataKind::UInt32));

        // Nested list
        let list_list = DataKind::List(Box::new(DataKind::List(Box::new(DataKind::String))));
        assert_eq!(list_list.type_name(), "list");
        assert!(matches!(list_list.list_inner(), Some(DataKind::List(_))));
    }
}
