//! Field descriptor for protocol schemas.

use super::DataKind;

/// Engine-agnostic field definition.
///
/// This replaces `arrow::datatypes::Field` in the Protocol trait,
/// allowing protocol parsers to be used with any SQL backend.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescriptor {
    /// Field name (snake_case, e.g., "src_port")
    pub name: &'static str,

    /// Data type
    pub kind: DataKind,

    /// Whether the field can be NULL
    pub nullable: bool,

    /// Optional description for documentation
    pub description: Option<&'static str>,
}

impl FieldDescriptor {
    /// Create a new non-nullable field.
    pub const fn new(name: &'static str, kind: DataKind) -> Self {
        Self {
            name,
            kind,
            nullable: false,
            description: None,
        }
    }

    /// Create a new nullable field.
    pub const fn nullable(name: &'static str, kind: DataKind) -> Self {
        Self {
            name,
            kind,
            nullable: true,
            description: None,
        }
    }

    /// Add a description to the field.
    pub const fn with_description(mut self, desc: &'static str) -> Self {
        self.description = Some(desc);
        self
    }

    /// Builder: set nullability.
    pub const fn set_nullable(mut self, nullable: bool) -> Self {
        self.nullable = nullable;
        self
    }
}

/// Helper macros for common field patterns.
impl FieldDescriptor {
    /// Frame number field (present in all protocol tables).
    pub const fn frame_number() -> Self {
        Self::new("frame_number", DataKind::UInt64).with_description("Unique packet identifier")
    }

    /// Timestamp field.
    pub const fn timestamp() -> Self {
        Self::new("timestamp", DataKind::TimestampMicros)
            .with_description("Packet capture time (UTC)")
    }

    /// Source port field.
    pub const fn src_port() -> Self {
        Self::new("src_port", DataKind::UInt16).with_description("Source port number")
    }

    /// Destination port field.
    pub const fn dst_port() -> Self {
        Self::new("dst_port", DataKind::UInt16).with_description("Destination port number")
    }

    /// IPv4 address field (stored as UInt32).
    pub const fn ipv4_field(name: &'static str) -> Self {
        Self::new(name, DataKind::UInt32)
    }

    /// IPv6 address field (stored as 16-byte binary).
    pub const fn ipv6_field(name: &'static str) -> Self {
        Self::new(name, DataKind::FixedBinary(16))
    }

    /// MAC address field (stored as 6-byte binary).
    pub const fn mac_field(name: &'static str) -> Self {
        Self::new(name, DataKind::FixedBinary(6))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_creation() {
        let field = FieldDescriptor::new("test", DataKind::UInt32);
        assert_eq!(field.name, "test");
        assert_eq!(field.kind, DataKind::UInt32);
        assert!(!field.nullable);
        assert!(field.description.is_none());
    }

    #[test]
    fn test_nullable_field() {
        let field = FieldDescriptor::nullable("optional", DataKind::String);
        assert!(field.nullable);
    }

    #[test]
    fn test_builder_pattern() {
        let field = FieldDescriptor::new("count", DataKind::UInt64)
            .set_nullable(true)
            .with_description("Packet count");

        assert!(field.nullable);
        assert_eq!(field.description, Some("Packet count"));
    }

    #[test]
    fn test_common_fields() {
        let frame = FieldDescriptor::frame_number();
        assert_eq!(frame.name, "frame_number");
        assert_eq!(frame.kind, DataKind::UInt64);

        let mac = FieldDescriptor::mac_field("src_mac");
        assert_eq!(mac.kind, DataKind::FixedBinary(6));
    }
}
