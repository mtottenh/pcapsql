//! `pcap_protocols()` and `pcap_schema(protocol)`: what the extension can read, from the same
//! catalogue the scans use (`pcapsql_core::scan::Catalog`).
//!
//! [`scan_tables`] and [`exposed_columns`] say which tables and columns of the catalogue this
//! engine offers; the two functions list exactly those.

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
    Catalog, ColId, ColKind, ColumnDef, ColumnSource, OutCol, OutColumn, RowSink, TableDef,
    TableId, TableKind,
};

use super::{guard, types, writer::ChunkWriter};

pub(super) fn register(extension: &Extension) -> Result<()> {
    guard::table_function("pcap_protocols", SignatureBuilder::new(), PcapProtocols)
        .register(extension)?;
    guard::table_function(
        "pcap_schema",
        SignatureBuilder::new().param(FunctionParameter::new::<String>("protocol")),
        PcapSchema,
    )
    .register(extension)
}

/// The tables of the catalogue this engine reads: `frames` and the protocol tables, in
/// catalogue order.
///
/// The stream tables (`tcp_connections`, `tls_sessions`, `http_messages`, `http2`) are in the
/// catalogue but are built by stream analysis, which the extension does not run yet.
pub(super) fn scan_tables() -> impl Iterator<Item = (TableId, &'static TableDef)> {
    Catalog::builtin()
        .tables()
        .filter(|(_, table)| !table.is_stream())
}

/// The table `name`, if the engine reads it (see [`scan_tables`]).
pub(super) fn scan_table(name: &str) -> Option<(TableId, &'static TableDef)> {
    Catalog::builtin()
        .table(name)
        .filter(|(_, table)| !table.is_stream())
}

/// The columns of `table` this engine exposes, in table order: every column of the catalogue,
/// the opt-in ones included. That is the `timestamp` of the protocol tables, which DuckDB needs
/// because it cannot fuse a join against `frames` (decision D5 of the roadmap).
pub(super) fn exposed_columns(table: &TableDef) -> impl Iterator<Item = (ColId, &ColumnDef)> {
    table.columns()
}

/// The `kind` column of `pcap_protocols()`.
fn kind_name(kind: TableKind) -> &'static str {
    match kind {
        TableKind::Frames => "frames",
        TableKind::Protocol => "protocol",
        TableKind::Stream(_) => "stream",
    }
}

fn protocol_description(name: &str) -> &'static str {
    match name {
        "ethernet" => "Ethernet II frames (Layer 2)",
        "linux_sll" => "Linux cooked capture v1 (tcpdump -i any)",
        "sll2" => "Linux cooked capture v2",
        "netlink" => "Linux netlink messages (nlmon captures)",
        "rtnetlink" => "Linux rtnetlink (route/link/address messages)",
        "vlan" => "IEEE 802.1Q VLAN tags",
        "arp" => "Address Resolution Protocol",
        "mpls" => "Multiprotocol Label Switching",
        "ipv4" => "Internet Protocol version 4",
        "ipv6" => "Internet Protocol version 6",
        "tcp" => "Transmission Control Protocol",
        "udp" => "User Datagram Protocol",
        "icmp" => "Internet Control Message Protocol",
        "icmpv6" => "ICMPv6 for IPv6",
        "dns" => "Domain Name System",
        "dhcp" => "Dynamic Host Configuration Protocol",
        "ntp" => "Network Time Protocol",
        "http" => "HTTP/1.x request and status lines with headers (per packet)",
        "tls" => "Transport Layer Security",
        "ssh" => "Secure Shell Protocol",
        "quic" => "QUIC Transport Protocol",
        "vxlan" => "Virtual Extensible LAN",
        "gre" => "Generic Routing Encapsulation",
        "gtp" => "GPRS Tunneling Protocol",
        "ipsec" => "IP Security (ESP/AH)",
        "bgp" => "Border Gateway Protocol",
        "ospf" => "Open Shortest Path First",
        "frames" => "Raw frame metadata (timestamp, length, etc.)",
        _ => "Protocol parser",
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
                Cell::Text(protocol_description(table.name)),
                Cell::Count(exposed_columns(table).count() as u32),
                Cell::Text(kind_name(table.kind)),
            ]
        })
        .collect()
}

struct PcapProtocols;

impl TableFunctionCallbacks for PcapProtocols {
    type BindData = Listing;
    /// Index of the next row to emit.
    type GlobalState = AtomicUsize;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        _arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Self::BindData> {
        Listing {
            columns: PROTOCOL_COLUMNS,
            rows: protocol_rows(),
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

const SCHEMA_COLUMNS: &[OutColumn] = &[
    column("column_name", ColKind::Str),
    column("column_type", ColKind::Str),
    column("nullable", ColKind::Bool),
];

/// The rows of `pcap_schema(table)`: one per column a scan of the table returns, in order.
fn schema_rows(table: &TableDef) -> Vec<Vec<Cell>> {
    exposed_columns(table)
        .map(|(_, column)| {
            vec![
                Cell::Text(column.name),
                Cell::Text(types::sql_name(types::column_kind(column))),
                Cell::Flag(column.nullable),
            ]
        })
        .collect()
}

struct PcapSchema;

impl TableFunctionCallbacks for PcapSchema {
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
        let name = arguments
            .first()
            .and_then(|argument| argument.value.as_ref())
            .map(|value| value.get::<String>())
            .transpose()?
            .flatten()
            .ok_or_else(|| Error::invalid_input("pcap_schema: the protocol must not be NULL"))?;
        // Table names are lower case; any case is accepted, as the extension always did.
        let (_, table) = scan_table(&name.to_ascii_lowercase()).ok_or_else(|| {
            Error::invalid_input(format!(
                "pcap_schema: there is no protocol table '{name}'; \
                 pcap_protocols() lists the tables"
            ))
        })?;
        Listing {
            columns: SCHEMA_COLUMNS,
            rows: schema_rows(table),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn text(cell: &Cell) -> &'static str {
        match cell {
            Cell::Text(text) => text,
            other => panic!("{other:?} is not text"),
        }
    }

    #[test]
    fn protocols_are_frames_and_the_protocol_tables_in_name_order() {
        let rows = protocol_rows();
        let names: Vec<&str> = rows.iter().map(|row| text(&row[0])).collect();
        assert!(names.is_sorted(), "{names:?}");
        assert_eq!(names.len(), scan_tables().count());
        // The 27 parsers of core's default registry, and `frames`.
        assert_eq!(names.len(), 28);
        assert_eq!(
            names.len(),
            pcapsql_core::default_registry().all_parsers().count() + 1
        );
        for stream in ["tcp_connections", "tls_sessions", "http_messages", "http2"] {
            assert!(Catalog::builtin().table(stream).is_some(), "{stream}");
            assert!(!names.contains(&stream), "{stream}");
            assert!(scan_table(stream).is_none(), "{stream}");
        }

        for row in &rows {
            assert_eq!(row.len(), PROTOCOL_COLUMNS.len());
            let name = text(&row[0]);
            // No table is left with the fallback description.
            assert_ne!(text(&row[1]), "Protocol parser", "{name}");
            let (_, table) = scan_table(name).unwrap();
            assert_eq!(
                row[2],
                Cell::Count(schema_rows(table).len() as u32),
                "{name}"
            );
            let kind = if name == "frames" {
                "frames"
            } else {
                "protocol"
            };
            assert_eq!(text(&row[3]), kind, "{name}");
        }
    }

    #[test]
    fn frames_schema_follows_the_catalogue() {
        let (_, frames) = scan_table("frames").unwrap();
        let rows: Vec<(&str, &str, bool)> = schema_rows(frames)
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
        for (_, table) in scan_tables().filter(|(_, table)| table.kind == TableKind::Protocol) {
            let rows = schema_rows(table);
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
    fn test_protocol_descriptions() {
        assert_eq!(protocol_description("tcp"), "Transmission Control Protocol");
        assert_eq!(protocol_description("dns"), "Domain Name System");
        assert_eq!(
            protocol_description("frames"),
            "Raw frame metadata (timestamp, length, etc.)"
        );
        assert_eq!(protocol_description("unknown"), "Protocol parser");
    }
}
