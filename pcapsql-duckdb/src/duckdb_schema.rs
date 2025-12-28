//! Convert pcapsql-core schema types to DuckDB types.
//!
//! This is the DuckDB equivalent of `pcapsql-datafusion/src/query/arrow_schema.rs`.

use duckdb::core::{LogicalTypeHandle, LogicalTypeId};
use pcapsql_core::schema::{DataKind, FieldDescriptor};
use pcapsql_core::Protocol;

/// Convert a DataKind to a DuckDB LogicalTypeHandle.
pub fn to_duckdb_type(kind: &DataKind) -> LogicalTypeHandle {
    match kind {
        DataKind::Bool => LogicalTypeHandle::from(LogicalTypeId::Boolean),
        DataKind::UInt8 => LogicalTypeHandle::from(LogicalTypeId::UTinyint),
        DataKind::UInt16 => LogicalTypeHandle::from(LogicalTypeId::USmallint),
        DataKind::UInt32 => LogicalTypeHandle::from(LogicalTypeId::UInteger),
        DataKind::UInt64 => LogicalTypeHandle::from(LogicalTypeId::UBigint),
        DataKind::Int64 => LogicalTypeHandle::from(LogicalTypeId::Bigint),
        DataKind::Float64 => LogicalTypeHandle::from(LogicalTypeId::Double),
        DataKind::String => LogicalTypeHandle::from(LogicalTypeId::Varchar),
        DataKind::Binary => LogicalTypeHandle::from(LogicalTypeId::Blob),
        DataKind::FixedBinary(_) => LogicalTypeHandle::from(LogicalTypeId::Blob),
        // DuckDB uses TimestampS for seconds, we store microseconds as Bigint
        DataKind::TimestampMicros => LogicalTypeHandle::from(LogicalTypeId::Bigint),
        DataKind::List(inner) => {
            let inner_type = to_duckdb_type(inner);
            LogicalTypeHandle::list(&inner_type)
        }
    }
}

/// Convert a FieldDescriptor to a (name, LogicalTypeHandle) pair.
pub fn to_duckdb_column(fd: &FieldDescriptor) -> (&'static str, LogicalTypeHandle) {
    (fd.name, to_duckdb_type(&fd.kind))
}

/// Get all column definitions for a protocol, prefixed with frame_number.
pub fn protocol_columns(protocol: &dyn Protocol) -> Vec<(&'static str, LogicalTypeHandle)> {
    let mut columns = vec![(
        "frame_number",
        LogicalTypeHandle::from(LogicalTypeId::UBigint),
    )];
    columns.extend(protocol.schema_fields().iter().map(to_duckdb_column));
    columns
}

// Note: Unit tests for type conversion are not possible in a loadable extension
// because the DuckDB API is not initialized until the extension is loaded.
// Type conversions are tested via integration tests when loading the extension into DuckDB.
