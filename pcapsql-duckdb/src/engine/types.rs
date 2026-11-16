//! The DuckDB type of every column kind of the catalogue.
//!
//! The shared catalogue (`pcapsql_core::scan::Catalog`) says what a column stores as a
//! [`ColKind`]. This is the one place that turns a kind into a DuckDB logical type, and into the
//! name DuckDB prints for that type (`pcap_schema()` shows it without a connection to ask).
//!
//! | `ColKind` | DuckDB type |
//! |---|---|
//! | `Bool` | `BOOLEAN` |
//! | `U8`, `U16`, `U32`, `U64` | `UTINYINT`, `USMALLINT`, `UINTEGER`, `UBIGINT` |
//! | `I8`, `I64` | `TINYINT`, `BIGINT` |
//! | `F64` | `DOUBLE` |
//! | `Str` | `VARCHAR` |
//! | `Bin`, `Fixed(n)` | `BLOB` |
//! | `TsMicros`, `TsNanos` | `TIMESTAMP`, `TIMESTAMP_NS` |
//! | `ListU16`, `ListU32`, `ListStr`, `ListFixed(n)` | `USMALLINT[]`, `UINTEGER[]`, `VARCHAR[]`, `BLOB[]` |
//!
//! A fixed-size binary value (a MAC address, an IPv6 address) is a `BLOB`: DuckDB has no
//! fixed-size binary type, and the scalar functions (`mac_to_string`, `ip6_to_string`) take
//! `BLOB`. The catalogue declares every timestamp in microseconds and leaves the unit to the
//! engine; this engine stores nanoseconds ([`TIMESTAMPS`]).

use duckdb_neo::{
    connection::FFILink,
    logical_type::LogicalType,
    types::{BlobValue, List, TimestampNsValue, TimestampValue},
    DuckDBType, Result,
};
use pcapsql_core::scan::{ColKind, ColumnDef, TimestampUnit};

/// The unit DuckDB stores packet timestamps in: nanoseconds, which is what a capture records.
pub const TIMESTAMPS: TimestampUnit = TimestampUnit::Nanos;

/// The kind of `column` as this engine stores it: the catalogue's kind, with a timestamp in
/// [`TIMESTAMPS`].
pub const fn column_kind(column: &ColumnDef) -> ColKind {
    column.kind_in(TIMESTAMPS)
}

/// The DuckDB logical type that stores `kind`.
///
/// A timestamp kind already names its unit; apply [`ColKind::with_timestamp_unit`] (or
/// [`column_kind`]) to a catalogue column first.
pub fn logical_type<C: FFILink + ?Sized>(link: &C, kind: ColKind) -> Result<LogicalType> {
    match kind {
        ColKind::Bool => bool::logical_type(link),
        ColKind::U8 => u8::logical_type(link),
        ColKind::U16 => u16::logical_type(link),
        ColKind::U32 => u32::logical_type(link),
        ColKind::U64 => u64::logical_type(link),
        ColKind::I8 => i8::logical_type(link),
        ColKind::I64 => i64::logical_type(link),
        ColKind::F64 => f64::logical_type(link),
        ColKind::Str => String::logical_type(link),
        ColKind::Bin | ColKind::Fixed(_) => BlobValue::logical_type(link),
        ColKind::TsMicros => TimestampValue::logical_type(link),
        ColKind::TsNanos => TimestampNsValue::logical_type(link),
        ColKind::ListU16 => List::<u16>::logical_type(link),
        ColKind::ListU32 => List::<u32>::logical_type(link),
        ColKind::ListStr => List::<String>::logical_type(link),
        ColKind::ListFixed(_) => List::<BlobValue>::logical_type(link),
    }
}

/// The name DuckDB gives the type of [`logical_type`]`(kind)`, as `DESCRIBE` prints it.
pub const fn sql_name(kind: ColKind) -> &'static str {
    match kind {
        ColKind::Bool => "BOOLEAN",
        ColKind::U8 => "UTINYINT",
        ColKind::U16 => "USMALLINT",
        ColKind::U32 => "UINTEGER",
        ColKind::U64 => "UBIGINT",
        ColKind::I8 => "TINYINT",
        ColKind::I64 => "BIGINT",
        ColKind::F64 => "DOUBLE",
        ColKind::Str => "VARCHAR",
        ColKind::Bin | ColKind::Fixed(_) => "BLOB",
        ColKind::TsMicros => "TIMESTAMP",
        ColKind::TsNanos => "TIMESTAMP_NS",
        ColKind::ListU16 => "USMALLINT[]",
        ColKind::ListU32 => "UINTEGER[]",
        ColKind::ListStr => "VARCHAR[]",
        ColKind::ListFixed(_) => "BLOB[]",
    }
}

#[cfg(test)]
mod tests {
    use pcapsql_core::scan::{Catalog, ColumnSource};

    use super::*;

    /// One of every kind. (A new `ColKind` variant does not compile until the two matches above
    /// name it.)
    const ALL_KINDS: [ColKind; 17] = [
        ColKind::Bool,
        ColKind::U8,
        ColKind::U16,
        ColKind::U32,
        ColKind::U64,
        ColKind::I8,
        ColKind::I64,
        ColKind::F64,
        ColKind::Str,
        ColKind::Bin,
        ColKind::Fixed(6),
        ColKind::TsMicros,
        ColKind::TsNanos,
        ColKind::ListU16,
        ColKind::ListU32,
        ColKind::ListStr,
        ColKind::ListFixed(16),
    ];

    #[test]
    fn list_names_are_the_element_name_with_brackets() {
        for (list, element) in [
            (ColKind::ListU16, ColKind::U16),
            (ColKind::ListU32, ColKind::U32),
            (ColKind::ListStr, ColKind::Str),
            (ColKind::ListFixed(16), ColKind::Fixed(16)),
        ] {
            assert_eq!(sql_name(list), format!("{}[]", sql_name(element)));
        }
    }

    #[test]
    fn fixed_size_binary_is_a_blob_whatever_its_width() {
        for width in [1, 6, 16, u16::MAX] {
            assert_eq!(sql_name(ColKind::Fixed(width)), "BLOB");
            assert_eq!(sql_name(ColKind::ListFixed(width)), "BLOB[]");
        }
        assert_eq!(sql_name(ColKind::Bin), "BLOB");
    }

    #[test]
    fn timestamps_are_stored_in_nanoseconds() {
        let column = ColumnDef::new("timestamp", ColKind::TsMicros, ColumnSource::Timestamp);
        assert_eq!(column_kind(&column), ColKind::TsNanos);
        assert_eq!(sql_name(column_kind(&column)), "TIMESTAMP_NS");
        assert_eq!(sql_name(ColKind::TsMicros), "TIMESTAMP");

        // No other kind is touched by the unit.
        for kind in ALL_KINDS {
            if !kind.is_timestamp() {
                let column = ColumnDef::new("c", kind, ColumnSource::Field("c"));
                assert_eq!(column_kind(&column), kind);
            }
        }
    }

    #[test]
    fn every_catalogue_column_has_a_type_name() {
        for (_, table) in Catalog::builtin().tables() {
            for (_, column) in table.columns() {
                let name = sql_name(column_kind(column));
                assert!(!name.is_empty(), "{}.{}", table.name, column.name);
                // The catalogue declares microseconds; nothing may reach DuckDB in that unit.
                assert_ne!(name, "TIMESTAMP", "{}.{}", table.name, column.name);
            }
        }
    }
}
