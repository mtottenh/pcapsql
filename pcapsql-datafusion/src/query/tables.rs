//! Table schemas, as Arrow.
//!
//! Which tables exist and which columns they have is defined by the table
//! catalogue in `pcapsql-core` ([`Catalog::builtin`]); this module renders it
//! as Arrow schemas for DataFusion. Each protocol table holds the fields of
//! one protocol, with `frame_number` as the key for JOINs against `frames`
//! and the encapsulation columns (`encap_depth`, `tunnel_type`, `tunnel_id`)
//! for tunnel-aware queries.
//!
//! Field names are normalized (without protocol prefix) for cleaner SQL:
//! `dns.query_name` is just `query_name` in the `dns` table.
//!
//! Only the catalogue's default columns are exposed: the opt-in `timestamp`
//! of the protocol tables is not a column here (the `*_packets` views and
//! frame-join fusion serve it).

use arrow::datatypes::Schema;
use pcapsql_core::scan::Catalog;

use crate::query::arrow_schema::table_def_to_arrow_schema;

/// Get all table names, in catalogue order.
pub fn all_table_names() -> Vec<&'static str> {
    Catalog::builtin().tables().map(|(_, t)| t.name).collect()
}

/// Names of the tables produced by stream analysis (TCP reassembly → TLS →
/// HTTP) rather than by per-packet parsing. They are built by the scan of
/// the packet pass when the capture ends, which needs the whole capture in
/// order (one partition).
pub fn stream_table_names() -> Vec<&'static str> {
    Catalog::builtin()
        .tables()
        .filter(|(_, t)| t.is_stream())
        .map(|(_, t)| t.name)
        .collect()
}

/// True for a stream-analysis table (see [`stream_table_names`]).
pub fn is_stream_table(name: &str) -> bool {
    Catalog::builtin()
        .table(name)
        .is_some_and(|(_, t)| t.is_stream())
}

/// Get a table schema by table name.
///
/// All tables except `frames` include the encapsulation columns
/// (`encap_depth`, `tunnel_type`, `tunnel_id`).
pub fn get_table_schema(name: &str) -> Option<Schema> {
    let (_, table) = Catalog::builtin().table(name)?;
    Some(table_def_to_arrow_schema(table))
}

/// Get all table schemas as (name, schema) pairs, in catalogue order.
pub fn all_table_schemas() -> Vec<(&'static str, Schema)> {
    Catalog::builtin()
        .tables()
        .map(|(_, t)| (t.name, table_def_to_arrow_schema(t)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::datatypes::{DataType, Field, TimeUnit};

    #[test]
    fn test_all_tables_have_frame_number() {
        let schemas = all_table_schemas();
        assert_eq!(schemas.len(), all_table_names().len());
        for (name, schema) in schemas {
            assert!(
                schema.field_with_name("frame_number").is_ok(),
                "Table '{name}' should have frame_number field"
            );
        }
    }

    #[test]
    fn test_no_protocol_prefix_in_fields() {
        for (name, schema) in all_table_schemas() {
            for field in schema.fields() {
                assert!(
                    !field.name().contains('.'),
                    "Table '{}' has field '{}' with protocol prefix",
                    name,
                    field.name()
                );
            }
        }
    }

    #[test]
    fn test_get_table_schema() {
        assert!(get_table_schema("frames").is_some());
        assert!(get_table_schema("dns").is_some());
        assert!(get_table_schema("tcp").is_some());
        assert!(get_table_schema("nonexistent").is_none());
    }

    #[test]
    fn stream_tables() {
        assert_eq!(
            stream_table_names(),
            ["http2", "tcp_connections", "tls_sessions", "http_messages"]
        );
        assert!(is_stream_table("http2"));
        assert!(!is_stream_table("http"));
        assert!(!is_stream_table("nonexistent"));
    }

    /// The Arrow schema is the catalogue's default columns, one field each
    /// in catalogue order. In particular the opt-in `timestamp` of the
    /// protocol tables is not exposed: only `frames` has a `timestamp`.
    #[test]
    fn schemas_are_the_catalogue_default_columns() {
        for (_, table) in Catalog::builtin().tables() {
            let schema = get_table_schema(table.name).expect("schema");
            let fields: Vec<_> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            let columns: Vec<_> = table.default_columns().map(|(_, c)| c.name).collect();
            assert_eq!(fields, columns, "{}", table.name);
            assert!(schema.metadata().is_empty(), "{}", table.name);
            assert_eq!(
                schema.field_with_name("timestamp").is_ok(),
                table.name == "frames",
                "{}",
                table.name
            );
        }
    }

    /// Spot checks of the kind mapping against the tables as released.
    #[test]
    fn column_types_and_nullability() {
        let micros = DataType::Timestamp(TimeUnit::Microsecond, None);
        let check = |table: &str, column: &str, data_type: &DataType, nullable: bool| {
            let schema = get_table_schema(table).expect("schema");
            let field = schema.field_with_name(column).expect("column");
            assert_eq!(field.data_type(), data_type, "{table}.{column}");
            assert_eq!(field.is_nullable(), nullable, "{table}.{column}");
            assert!(field.metadata().is_empty(), "{table}.{column}");
        };
        check("frames", "timestamp", &micros, false);
        check("frames", "raw_data", &DataType::Binary, false);
        check("tcp_connections", "start_time", &micros, true);
        check("tcp_connections", "duration_us", &DataType::Int64, true);
        check("ipv4", "src_ip", &DataType::UInt32, true);
        check("ipv6", "src_ip", &DataType::FixedSizeBinary(16), true);
        check("ethernet", "src_mac", &DataType::FixedSizeBinary(6), true);
        check("tls", "client_random", &DataType::FixedSizeBinary(32), true);
        check("tcp", "encap_depth", &DataType::UInt8, false);
        check("tcp", "tunnel_type", &DataType::Utf8, true);
        let list =
            |inner: DataType| DataType::List(std::sync::Arc::new(Field::new("item", inner, true)));
        check("tcp", "sack_left_edges", &list(DataType::UInt32), true);
        check(
            "dns",
            "answer_ip6s",
            &list(DataType::FixedSizeBinary(16)),
            true,
        );
        check("dns", "answer_cnames", &list(DataType::Utf8), true);
        check("dns", "answer_types", &list(DataType::UInt16), true);
    }
}
