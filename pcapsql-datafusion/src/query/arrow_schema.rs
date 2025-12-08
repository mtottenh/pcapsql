//! Convert pcapsql-core schema types to Arrow types.
//!
//! This module provides the bridge between pcapsql-core's engine-agnostic
//! schema types and Arrow's type system used by DataFusion.

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use pcapsql_core::schema::{DataKind, FieldDescriptor};
use pcapsql_core::Protocol;

/// Convert a FieldDescriptor to an Arrow Field.
pub fn to_arrow_field(fd: &FieldDescriptor) -> Field {
    let data_type = to_arrow_type(&fd.kind);
    Field::new(fd.name.clone(), data_type, fd.nullable)
}

/// Convert a DataKind to an Arrow DataType.
pub fn to_arrow_type(kind: &DataKind) -> DataType {
    match kind {
        DataKind::Bool => DataType::Boolean,
        DataKind::UInt8 => DataType::UInt8,
        DataKind::UInt16 => DataType::UInt16,
        DataKind::UInt32 => DataType::UInt32,
        DataKind::UInt64 => DataType::UInt64,
        DataKind::Int64 => DataType::Int64,
        DataKind::Float64 => DataType::Float64,
        DataKind::String => DataType::Utf8,
        DataKind::Binary => DataType::Binary,
        DataKind::FixedBinary(n) => DataType::FixedSizeBinary(*n as i32),
        DataKind::TimestampMicros => DataType::Timestamp(TimeUnit::Microsecond, None),
    }
}

/// Convert a protocol's schema to Arrow Schema.
pub fn protocol_to_arrow_schema(protocol: &dyn Protocol) -> Schema {
    let fields: Vec<Field> = protocol.schema_fields().iter().map(to_arrow_field).collect();
    Schema::new(fields)
}

/// Convert a slice of FieldDescriptors to Arrow Schema.
pub fn descriptors_to_arrow_schema(descriptors: &[FieldDescriptor]) -> Schema {
    let fields: Vec<Field> = descriptors.iter().map(to_arrow_field).collect();
    Schema::new(fields)
}

/// Detect if an Arrow field represents a network address.
///
/// This is a helper that works directly with Arrow types, avoiding the need
/// to convert between Arrow Field and FieldDescriptor (which uses 'static str).
pub fn detect_arrow_address_column(field: &Field) -> Option<pcapsql_core::AddressKind> {
    use pcapsql_core::AddressKind;

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

fn is_ipv4_column_name(name: &str) -> bool {
    let exact_matches = ["router", "server_id", "subnet_mask", "ciaddr", "yiaddr", "siaddr", "giaddr"];
    if exact_matches.contains(&name) {
        return true;
    }
    if name.ends_with("_ip") || name.contains("_ip_") {
        return true;
    }
    if name.ends_with("addr") && !name.contains("mac") {
        return true;
    }
    false
}

fn is_ipv6_column_name(name: &str) -> bool {
    name.ends_with("_ip") || name.contains("_ip_") || name.ends_with("_address") || name.ends_with("_prefix")
}

fn is_mac_column_name(name: &str) -> bool {
    name == "chaddr" || name.ends_with("_mac") || name.contains("_mac_")
}

/// Convert a FieldValue to a ScalarValue for use in DataFusion expressions.
pub fn field_value_to_scalar(value: &pcapsql_core::FieldValue) -> datafusion::scalar::ScalarValue {
    use datafusion::scalar::ScalarValue;
    use pcapsql_core::FieldValue;

    match value {
        FieldValue::Bool(v) => ScalarValue::Boolean(Some(*v)),
        FieldValue::UInt8(v) => ScalarValue::UInt8(Some(*v)),
        FieldValue::UInt16(v) => ScalarValue::UInt16(Some(*v)),
        FieldValue::UInt32(v) => ScalarValue::UInt32(Some(*v)),
        FieldValue::UInt64(v) => ScalarValue::UInt64(Some(*v)),
        FieldValue::Int64(v) => ScalarValue::Int64(Some(*v)),
        FieldValue::Str(v) => ScalarValue::Utf8(Some(v.to_string())),
        FieldValue::OwnedString(v) => ScalarValue::Utf8(Some(v.to_string())),
        FieldValue::Bytes(v) => ScalarValue::Binary(Some(v.to_vec())),
        FieldValue::OwnedBytes(v) => ScalarValue::Binary(Some(v.clone())),
        FieldValue::MacAddr(v) => ScalarValue::FixedSizeBinary(6, Some(v.to_vec())),
        FieldValue::IpAddr(addr) => {
            // Store as string for now - UDFs handle the conversion
            ScalarValue::Utf8(Some(addr.to_string()))
        }
        FieldValue::Null => ScalarValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        assert_eq!(to_arrow_type(&DataKind::Bool), DataType::Boolean);
        assert_eq!(to_arrow_type(&DataKind::UInt8), DataType::UInt8);
        assert_eq!(to_arrow_type(&DataKind::UInt16), DataType::UInt16);
        assert_eq!(to_arrow_type(&DataKind::UInt32), DataType::UInt32);
        assert_eq!(to_arrow_type(&DataKind::UInt64), DataType::UInt64);
        assert_eq!(to_arrow_type(&DataKind::Int64), DataType::Int64);
        assert_eq!(to_arrow_type(&DataKind::Float64), DataType::Float64);
        assert_eq!(to_arrow_type(&DataKind::String), DataType::Utf8);
        assert_eq!(to_arrow_type(&DataKind::Binary), DataType::Binary);
    }

    #[test]
    fn test_fixed_binary() {
        assert_eq!(
            to_arrow_type(&DataKind::FixedBinary(6)),
            DataType::FixedSizeBinary(6)
        );
        assert_eq!(
            to_arrow_type(&DataKind::FixedBinary(16)),
            DataType::FixedSizeBinary(16)
        );
    }

    #[test]
    fn test_timestamp() {
        assert_eq!(
            to_arrow_type(&DataKind::TimestampMicros),
            DataType::Timestamp(TimeUnit::Microsecond, None)
        );
    }

    #[test]
    fn test_field_conversion() {
        let fd = FieldDescriptor::nullable("test", DataKind::String);
        let arrow_field = to_arrow_field(&fd);

        assert_eq!(arrow_field.name(), "test");
        assert_eq!(arrow_field.data_type(), &DataType::Utf8);
        assert!(arrow_field.is_nullable());
    }

    #[test]
    fn test_field_not_nullable() {
        let fd = FieldDescriptor::new("frame_number", DataKind::UInt64);
        let arrow_field = to_arrow_field(&fd);

        assert_eq!(arrow_field.name(), "frame_number");
        assert_eq!(arrow_field.data_type(), &DataType::UInt64);
        assert!(!arrow_field.is_nullable());
    }

    #[test]
    fn test_descriptors_to_schema() {
        let descriptors = vec![
            FieldDescriptor::new("id", DataKind::UInt64),
            FieldDescriptor::nullable("name", DataKind::String),
            FieldDescriptor::new("active", DataKind::Bool),
        ];

        let schema = descriptors_to_arrow_schema(&descriptors);

        assert_eq!(schema.fields().len(), 3);
        assert_eq!(schema.field(0).name(), "id");
        assert_eq!(schema.field(1).name(), "name");
        assert_eq!(schema.field(2).name(), "active");
    }
}
