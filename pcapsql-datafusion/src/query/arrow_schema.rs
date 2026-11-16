//! Convert pcapsql-core schema types to Arrow types.
//!
//! This module provides the bridge between pcapsql-core's engine-agnostic
//! schema types and Arrow's type system used by DataFusion.

use std::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use pcapsql_core::scan::{ColKind, OutColumn, TableDef, TimestampUnit};

/// The Arrow type that stores a catalogue column kind.
pub fn col_kind_to_arrow_type(kind: ColKind) -> DataType {
    let list = |inner: DataType| DataType::List(Arc::new(Field::new("item", inner, true)));
    match kind {
        ColKind::Bool => DataType::Boolean,
        ColKind::U8 => DataType::UInt8,
        ColKind::U16 => DataType::UInt16,
        ColKind::U32 => DataType::UInt32,
        ColKind::U64 => DataType::UInt64,
        ColKind::I8 => DataType::Int8,
        ColKind::I64 => DataType::Int64,
        ColKind::F64 => DataType::Float64,
        ColKind::Str => DataType::Utf8,
        ColKind::Bin => DataType::Binary,
        ColKind::Fixed(n) => DataType::FixedSizeBinary(i32::from(n)),
        ColKind::TsMicros => DataType::Timestamp(TimeUnit::Microsecond, None),
        ColKind::TsNanos => DataType::Timestamp(TimeUnit::Nanosecond, None),
        ColKind::ListU16 => list(DataType::UInt16),
        ColKind::ListU32 => list(DataType::UInt32),
        ColKind::ListStr => list(DataType::Utf8),
        ColKind::ListFixed(n) => list(DataType::FixedSizeBinary(i32::from(n))),
    }
}

/// The catalogue column kind an Arrow type stores: the inverse of
/// [`col_kind_to_arrow_type`]. `None` for a type no column kind maps to.
pub fn arrow_type_to_col_kind(data_type: &DataType) -> Option<ColKind> {
    let width = |n: &i32| u16::try_from(*n).ok();
    Some(match data_type {
        DataType::Boolean => ColKind::Bool,
        DataType::UInt8 => ColKind::U8,
        DataType::UInt16 => ColKind::U16,
        DataType::UInt32 => ColKind::U32,
        DataType::UInt64 => ColKind::U64,
        DataType::Int8 => ColKind::I8,
        DataType::Int64 => ColKind::I64,
        DataType::Float64 => ColKind::F64,
        DataType::Utf8 => ColKind::Str,
        DataType::Binary => ColKind::Bin,
        DataType::FixedSizeBinary(n) => ColKind::Fixed(width(n)?),
        DataType::Timestamp(TimeUnit::Microsecond, None) => ColKind::TsMicros,
        DataType::Timestamp(TimeUnit::Nanosecond, None) => ColKind::TsNanos,
        DataType::List(field) if field.name() == "item" && field.is_nullable() => {
            match field.data_type() {
                DataType::UInt16 => ColKind::ListU16,
                DataType::UInt32 => ColKind::ListU32,
                DataType::Utf8 => ColKind::ListStr,
                DataType::FixedSizeBinary(n) => ColKind::ListFixed(width(n)?),
                _ => return None,
            }
        }
        _ => return None,
    })
}

/// The Arrow schema of a catalogue table as DataFusion exposes it: the
/// table's default columns in catalogue order (opt-in columns such as the
/// protocol tables' `timestamp` are left out), timestamps in microseconds.
pub fn table_def_to_arrow_schema(table: &TableDef) -> Schema {
    let fields: Vec<Field> = table
        .default_columns()
        .map(|(_, column)| {
            Field::new(
                column.name,
                col_kind_to_arrow_type(column.kind_in(TimestampUnit::Micros)),
                column.nullable,
            )
        })
        .collect();
    Schema::new(fields)
}

/// The Arrow schema of one output of a compiled scan plan: its columns in
/// output order, each in the kind the plan resolved (timestamps in the
/// plan's unit).
pub fn out_columns_to_arrow_schema(columns: &[OutColumn]) -> Schema {
    let fields: Vec<Field> = columns
        .iter()
        .map(|column| {
            Field::new(
                column.name,
                col_kind_to_arrow_type(column.kind),
                column.nullable,
            )
        })
        .collect();
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
    let exact_matches = [
        "router",
        "server_id",
        "subnet_mask",
        "ciaddr",
        "yiaddr",
        "siaddr",
        "giaddr",
    ];
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
    name.ends_with("_ip")
        || name.contains("_ip_")
        || name.ends_with("_address")
        || name.ends_with("_prefix")
}

fn is_mac_column_name(name: &str) -> bool {
    name == "chaddr" || name.ends_with("_mac") || name.contains("_mac_")
}
