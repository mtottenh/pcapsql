//! `pcap_protocols()`, `pcap_views()` and `pcap_schema(name)`: what the extension can read, from
//! the same definitions the scans use (`engine::relation`, which takes them from
//! `pcapsql_core::scan`).
//!
//! `pcap_protocols()` lists the tables, `pcap_views()` the views, and `pcap_schema` the columns
//! of either. The three are one table function, [`ListingFunction`], which differ in their
//! columns and in the rows `bind` computes.
//!
//! `pcap_protocols()` lists the tables of the catalogue: `frames`, one table per parser, and
//! the four stream tables, which its `kind` column tells apart. The views are not rows of it.

use std::sync::atomic::{AtomicUsize, Ordering};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    data_chunk::DataChunkRef,
    extension::Extension,
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionCallbacks},
    Error, Result,
};
use pcapsql_core::scan::{
    ColKind, ColumnSource, OutCol, OutColumn, PacketsView, RowSink, TableDef, TableKind,
};

use super::{
    guard,
    relation::{exposed_columns, scan_tables, views, Relation, WHERE_TO_LOOK},
    types,
    writer::ChunkWriter,
};

pub(super) fn register(extension: &Extension) -> Result<()> {
    let protocols = ListingFunction {
        columns: PROTOCOL_COLUMNS,
        rows: |_| Ok(protocol_rows()),
    };
    guard::table_function("pcap_protocols", SignatureBuilder::new(), protocols)
        .register(extension)?;
    let views = ListingFunction {
        columns: VIEW_COLUMNS,
        rows: |_| Ok(view_rows()),
    };
    guard::table_function("pcap_views", SignatureBuilder::new(), views).register(extension)?;
    let schema = ListingFunction {
        columns: SCHEMA_COLUMNS,
        rows: |arguments| Ok(schema_rows(schema_relation(arguments)?)),
    };
    guard::table_function(
        "pcap_schema",
        SignatureBuilder::new().param(FunctionParameter::new::<String>("protocol")),
        schema,
    )
    .register(extension)
}

/// The `kind` column of `pcap_protocols()`.
fn kind_name(kind: TableKind) -> &'static str {
    match kind {
        TableKind::Frames => "frames",
        TableKind::Protocol => "protocol",
        TableKind::Stream => "stream",
    }
}

/// One cell of a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Text(&'static str),
    Count(u32),
    Flag(bool),
}

/// The rows of one call of a listing function, with the columns they have.
#[derive(Debug)]
struct Listing {
    columns: &'static [OutColumn],
    rows: Vec<Vec<Cell>>,
}

/// A column of a listing function. Its kind picks the DuckDB type, as for a scan column.
const fn column(name: &'static str, kind: ColKind) -> OutColumn {
    OutColumn {
        name,
        kind,
        nullable: false,
        source: ColumnSource::Field(name),
    }
}

impl Listing {
    /// Declare the columns and the row count to DuckDB.
    fn bind(self, context: &Context, bind_handle: &BindFunctionHandle<'_>) -> Result<Self> {
        for column in self.columns {
            let logical_type = types::logical_type(context, column.kind)?;
            bind_handle.add_result_column(column.name, &logical_type)?;
        }
        bind_handle.set_cardinality(self.rows.len(), true)?;
        Ok(self)
    }

    /// Write the next chunk of rows. `next_row` is the index of the first row no chunk has
    /// taken yet.
    fn emit(&self, next_row: &AtomicUsize, output: DataChunkRef<'_>) -> Result<()> {
        // Projection pushdown is off, so the chunk holds every declared column in order.
        let mut writer = ChunkWriter::new(output, self.columns)?;
        // Claiming a range atomically keeps the rows unique whatever number of threads DuckDB
        // runs the scan on.
        let start = next_row
            .fetch_add(writer.capacity(), Ordering::Relaxed)
            .min(self.rows.len());
        for row in &self.rows[start..] {
            for (index, cell) in row.iter().enumerate() {
                let col = OutCol(index as u16);
                match *cell {
                    Cell::Text(text) => writer.str(col, text),
                    Cell::Count(count) => writer.u32(col, count),
                    Cell::Flag(flag) => writer.bool(col, flag),
                }
            }
            if writer.end_row().is_break() {
                break;
            }
        }
        // A chunk left at zero rows ends the scan.
        writer.finish()?;
        Ok(())
    }
}

/// A listing function: a table function whose rows are computed at bind. The three differ in
/// their columns and in how `bind` gets the rows from the call's arguments.
struct ListingFunction {
    columns: &'static [OutColumn],
    rows: fn(&[BindArgument]) -> Result<Vec<Vec<Cell>>>,
}

impl TableFunctionCallbacks for ListingFunction {
    type BindData = Listing;
    /// Index of the next row to emit.
    type GlobalState = AtomicUsize;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Self::BindData> {
        Listing {
            columns: self.columns,
            rows: (self.rows)(&arguments)?,
        }
        .bind(context, &bind_handle)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bind_data: &Self::BindData,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Self::GlobalState>> {
        Ok(Some(AtomicUsize::new(0)))
    }

    fn exec(
        &self,
        _context: &Context,
        listing: &Self::BindData,
        _local_state: Option<&mut Self::LocalState>,
        next_row: Option<&Self::GlobalState>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let next_row = next_row.expect("init_global_state always returns a state");
        listing.emit(next_row, output)
    }
}

const PROTOCOL_COLUMNS: &[OutColumn] = &[
    column("name", ColKind::Str),
    column("description", ColKind::Str),
    column("field_count", ColKind::U32),
    column("kind", ColKind::Str),
];

/// The rows of `pcap_protocols()`: one per table of [`scan_tables`], sorted by name.
fn protocol_rows() -> Vec<Vec<Cell>> {
    let mut tables: Vec<&TableDef> = scan_tables().map(|(_, table)| table).collect();
    tables.sort_by_key(|table| table.name);
    tables
        .into_iter()
        .map(|table| {
            vec![
                Cell::Text(table.name),
                Cell::Text(table.description),
                Cell::Count(exposed_columns(table).count() as u32),
                Cell::Text(kind_name(table.kind)),
            ]
        })
        .collect()
}

const VIEW_COLUMNS: &[OutColumn] = &[
    column("name", ColKind::Str),
    column("description", ColKind::Str),
    column("protocol", ColKind::Str),
    column("column_count", ColKind::U32),
];

/// The rows of `pcap_views()`: one per view of [`views`], sorted by name, with the protocol
/// table it has a row per row of.
fn view_rows() -> Vec<Vec<Cell>> {
    let mut views: Vec<&PacketsView> = views().iter().collect();
    views.sort_by_key(|view| view.name);
    views
        .into_iter()
        .map(|view| {
            vec![
                Cell::Text(view.name),
                Cell::Text(view.description),
                Cell::Text(view.anchor),
                Cell::Count(view.columns().len() as u32),
            ]
        })
        .collect()
}

const SCHEMA_COLUMNS: &[OutColumn] = &[
    column("column_name", ColKind::Str),
    column("column_type", ColKind::Str),
    column("nullable", ColKind::Bool),
];

/// The rows of `pcap_schema(name)`: one per column a scan of the table or view returns, in
/// order.
fn schema_rows(relation: Relation) -> Vec<Vec<Cell>> {
    relation
        .columns()
        .into_iter()
        .map(|column| {
            vec![
                Cell::Text(column.name),
                Cell::Text(types::sql_name(column.kind)),
                Cell::Flag(column.nullable),
            ]
        })
        .collect()
}

/// The table or view the one argument of `pcap_schema` names.
fn schema_relation(arguments: &[BindArgument]) -> Result<Relation> {
    let name = arguments
        .first()
        .and_then(|argument| argument.value.as_ref())
        .map(|value| value.get::<String>())
        .transpose()?
        .flatten()
        .ok_or_else(|| Error::invalid_input("pcap_schema: the protocol must not be NULL"))?;
    // The names are lower case; any case is accepted, as the extension always did.
    Relation::find(&name.to_ascii_lowercase()).ok_or_else(|| {
        Error::invalid_input(format!(
            "pcap_schema: there is no protocol table '{name}'; {WHERE_TO_LOOK}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::relation::{relations, scan_table};
    use pcapsql_core::scan::Catalog;

    fn text(cell: &Cell) -> &'static str {
        match cell {
            Cell::Text(text) => text,
            other => panic!("{other:?} is not text"),
        }
    }

    #[test]
    fn protocols_are_the_tables_of_the_catalogue_in_name_order() {
        const STREAMS: [&str; 4] = ["tcp_connections", "tls_sessions", "http_messages", "http2"];
        let rows = protocol_rows();
        let names: Vec<&str> = rows.iter().map(|row| text(&row[0])).collect();
        assert!(names.is_sorted(), "{names:?}");
        assert_eq!(names.len(), scan_tables().count());
        assert_eq!(names.len(), Catalog::builtin().tables().count());
        // `frames`, the 27 parsers of core's default registry, and the stream tables.
        assert_eq!(names.len(), 32);
        assert_eq!(
            names.len(),
            pcapsql_core::default_registry().all_parsers().count() + 1 + STREAMS.len()
        );
        for stream in STREAMS {
            assert!(names.contains(&stream), "{stream}");
            assert!(Relation::find(stream).unwrap().is_stream(), "{stream}");
        }

        for row in &rows {
            assert_eq!(row.len(), PROTOCOL_COLUMNS.len());
            let name = text(&row[0]);
            // The catalogue's description of the table.
            assert_eq!(
                text(&row[1]),
                scan_table(name).unwrap().1.description,
                "{name}"
            );
            assert!(!text(&row[1]).is_empty(), "{name}");
            assert_eq!(
                row[2],
                Cell::Count(schema_rows(Relation::find(name).unwrap()).len() as u32),
                "{name}"
            );
            let kind = if name == "frames" {
                "frames"
            } else if STREAMS.contains(&name) {
                "stream"
            } else {
                "protocol"
            };
            assert_eq!(text(&row[3]), kind, "{name}");
            assert_eq!(Relation::find(name).unwrap().is_stream(), kind == "stream");
        }
    }

    #[test]
    fn frames_schema_follows_the_catalogue() {
        let rows: Vec<(&str, &str, bool)> = schema_rows(Relation::find("frames").unwrap())
            .iter()
            .map(|row| (text(&row[0]), text(&row[1]), row[2] == Cell::Flag(true)))
            .collect();
        assert_eq!(
            rows,
            [
                ("frame_number", "UBIGINT", false),
                ("timestamp", "TIMESTAMP_NS", false),
                ("length", "UINTEGER", false),
                ("original_length", "UINTEGER", false),
                ("link_type", "USMALLINT", false),
                ("raw_data", "BLOB", false),
            ]
        );
    }

    #[test]
    fn protocol_tables_expose_the_opt_in_timestamp_second() {
        for (id, table) in scan_tables().filter(|(_, table)| table.kind == TableKind::Protocol) {
            let rows = schema_rows(Relation::Table(id));
            let names: Vec<&str> = rows.iter().map(|row| text(&row[0])).collect();
            assert_eq!(names[..2], ["frame_number", "timestamp"], "{}", table.name);
            assert_eq!(text(&rows[1][1]), "TIMESTAMP_NS", "{}", table.name);
            assert_eq!(
                names[names.len() - 3..],
                ["encap_depth", "tunnel_type", "tunnel_id"],
                "{}",
                table.name
            );
            // More than `SELECT *` shows in DataFusion, by exactly that column.
            assert_eq!(names.len(), table.default_columns().count() + 1);
        }
    }

    #[test]
    fn address_columns_are_typed_as_the_scalar_functions_expect() {
        let column_type = |table: &str, column: &str| {
            let (_, table) = scan_table(table).unwrap();
            let (_, column) = table.column(column).unwrap();
            (types::sql_name(types::column_kind(column)), column.nullable)
        };
        assert_eq!(column_type("ethernet", "src_mac"), ("BLOB", true));
        assert_eq!(column_type("ipv4", "src_ip"), ("UINTEGER", true));
        assert_eq!(column_type("ipv6", "src_ip"), ("BLOB", true));
        assert_eq!(column_type("tcp", "encap_depth"), ("UTINYINT", false));
    }

    #[test]
    fn views_are_listed_by_name_with_their_protocol() {
        let rows = view_rows();
        let names: Vec<&str> = rows.iter().map(|row| text(&row[0])).collect();
        assert!(names.is_sorted(), "{names:?}");
        assert_eq!(names.len(), 21);
        // None is a row of `pcap_protocols()`, and none has a table's name.
        let tables: Vec<&str> = protocol_rows().iter().map(|row| text(&row[0])).collect();
        for row in &rows {
            assert_eq!(row.len(), VIEW_COLUMNS.len());
            let name = text(&row[0]);
            assert!(!tables.contains(&name), "{name}");
            assert!(!text(&row[1]).is_empty(), "{name}");
            // The protocol is a table the engine reads.
            assert!(tables.contains(&text(&row[2])), "{name}");
            let relation = Relation::find(name).unwrap();
            assert!(matches!(relation, Relation::View(_)), "{name}");
            assert_eq!(relation.name(), name);
            assert_eq!(
                row[3],
                Cell::Count(schema_rows(relation).len() as u32),
                "{name}"
            );
        }
        let tcp = rows
            .iter()
            .find(|row| text(&row[0]) == "tcp_packets")
            .unwrap();
        assert_eq!(text(&tcp[2]), "tcp");
        assert_eq!(tcp[3], Cell::Count(20));
    }

    #[test]
    fn a_view_s_schema_is_its_columns_in_this_engine_s_types() {
        let rows: Vec<(&str, &str, bool)> = schema_rows(Relation::find("arp_packets").unwrap())
            .iter()
            .map(|row| (text(&row[0]), text(&row[1]), row[2] == Cell::Flag(true)))
            .collect();
        assert_eq!(rows[0], ("frame_number", "UBIGINT", false));
        assert_eq!(rows[1], ("timestamp", "TIMESTAMP_NS", false));
        // A left-joined layer's columns can be NULL; the anchor's level cannot.
        assert!(rows.contains(&("src_mac", "BLOB", true)), "{rows:?}");
        assert!(
            rows.contains(&("encap_depth", "UTINYINT", false)),
            "{rows:?}"
        );
        // The names of every relation are distinct, so `find` is unambiguous.
        let mut names = std::collections::HashSet::new();
        for relation in relations() {
            assert!(names.insert(relation.name()), "{}", relation.name());
        }
        assert_eq!(names.len(), 32 + 21);
    }
}
