//! The table catalogue: one logical schema for every SQL frontend.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! [`Catalog::builtin`] lists every table pcapsql exposes, with each
//! column's name, [kind](ColKind), nullability and [source](ColumnSource).
//! A frontend maps [`ColKind`] to its own type system (Arrow `DataType`,
//! DuckDB logical type) and takes the table list, the column order and the
//! typing from here, so that the same query sees the same table whichever
//! engine runs it.
//!
//! The column lists are written out per table. They are not derived from
//! [`Protocol::schema_fields`](crate::Protocol::schema_fields): the tables
//! order their columns differently from the parsers' descriptors, leave a few
//! parser fields out, and store addresses typed (IPv4 as [`ColKind::U32`],
//! IPv6 and MAC as [`ColKind::Fixed`]) where the descriptors say `String`.
//! A test pins the agreement between the two.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use crate::schema::DataKind;

/// A table of a [`Catalog`]: its position in [`Catalog::tables`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TableId(pub u16);

/// A column of a [`TableDef`]: its index into [`TableDef::columns`],
/// non-default columns included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ColId(pub u16);

/// The unit an engine stores timestamp columns in.
///
/// The catalogue declares every timestamp column as [`ColKind::TsMicros`];
/// the unit actually stored is the engine's choice, applied with
/// [`ColKind::with_timestamp_unit`] or [`ColumnDef::kind_in`]. Packet
/// timestamps are nanoseconds in core, so both units can be served.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TimestampUnit {
    /// Microseconds since the Unix epoch.
    #[default]
    Micros,
    /// Nanoseconds since the Unix epoch.
    Nanos,
}

/// Flat, `Copy` column kind: what a column stores.
///
/// The variants are exactly the kinds the built-in tables use, plus
/// [`ColKind::TsNanos`] for engines that store nanosecond timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ColKind {
    /// Boolean.
    Bool,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer (also an IPv4 address).
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 8-bit integer.
    I8,
    /// Signed 64-bit integer.
    I64,
    /// 64-bit floating point.
    F64,
    /// UTF-8 string.
    Str,
    /// Variable-length bytes.
    Bin,
    /// Fixed-length bytes (a MAC address is 6, an IPv6 address 16).
    Fixed(u16),
    /// Timestamp (UTC), microseconds since the Unix epoch.
    TsMicros,
    /// Timestamp (UTC), nanoseconds since the Unix epoch.
    TsNanos,
    /// List of [`ColKind::U16`]; elements are nullable in every list kind.
    ListU16,
    /// List of [`ColKind::U32`].
    ListU32,
    /// List of [`ColKind::Str`].
    ListStr,
    /// List of [`ColKind::Fixed`].
    ListFixed(u16),
}

impl ColKind {
    /// The [`DataKind`] of the same meaning. `None` for
    /// [`ColKind::TsNanos`], which [`DataKind`] cannot express.
    pub fn data_kind(self) -> Option<DataKind> {
        let list = |inner: DataKind| DataKind::List(Box::new(inner));
        Some(match self {
            ColKind::Bool => DataKind::Bool,
            ColKind::U8 => DataKind::UInt8,
            ColKind::U16 => DataKind::UInt16,
            ColKind::U32 => DataKind::UInt32,
            ColKind::U64 => DataKind::UInt64,
            ColKind::I8 => DataKind::Int8,
            ColKind::I64 => DataKind::Int64,
            ColKind::F64 => DataKind::Float64,
            ColKind::Str => DataKind::String,
            ColKind::Bin => DataKind::Binary,
            ColKind::Fixed(n) => DataKind::FixedBinary(usize::from(n)),
            ColKind::TsMicros => DataKind::TimestampMicros,
            ColKind::TsNanos => return None,
            ColKind::ListU16 => list(DataKind::UInt16),
            ColKind::ListU32 => list(DataKind::UInt32),
            ColKind::ListStr => list(DataKind::String),
            ColKind::ListFixed(n) => list(DataKind::FixedBinary(usize::from(n))),
        })
    }

    /// True for the two timestamp kinds.
    pub const fn is_timestamp(self) -> bool {
        matches!(self, ColKind::TsMicros | ColKind::TsNanos)
    }

    /// This kind with a timestamp stored in `unit`; every other kind is
    /// returned unchanged.
    pub const fn with_timestamp_unit(self, unit: TimestampUnit) -> ColKind {
        match (self, unit) {
            (ColKind::TsMicros | ColKind::TsNanos, TimestampUnit::Micros) => ColKind::TsMicros,
            (ColKind::TsMicros | ColKind::TsNanos, TimestampUnit::Nanos) => ColKind::TsNanos,
            (other, _) => other,
        }
    }
}

/// A [`DataKind`] no [`ColKind`] stores (a list of anything but `UInt16`,
/// `UInt32`, `String` or `FixedBinary`, or a fixed width above `u16::MAX`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedKind(pub DataKind);

impl fmt::Display for UnsupportedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no column kind stores {:?}", self.0)
    }
}

impl std::error::Error for UnsupportedKind {}

impl TryFrom<&DataKind> for ColKind {
    type Error = UnsupportedKind;

    fn try_from(kind: &DataKind) -> Result<Self, Self::Error> {
        let unsupported = || UnsupportedKind(kind.clone());
        let width = |n: &usize| u16::try_from(*n).map_err(|_| unsupported());
        Ok(match kind {
            DataKind::Bool => ColKind::Bool,
            DataKind::UInt8 => ColKind::U8,
            DataKind::UInt16 => ColKind::U16,
            DataKind::UInt32 => ColKind::U32,
            DataKind::UInt64 => ColKind::U64,
            DataKind::Int8 => ColKind::I8,
            DataKind::Int64 => ColKind::I64,
            DataKind::Float64 => ColKind::F64,
            DataKind::String => ColKind::Str,
            DataKind::Binary => ColKind::Bin,
            DataKind::FixedBinary(n) => ColKind::Fixed(width(n)?),
            DataKind::TimestampMicros => ColKind::TsMicros,
            DataKind::List(inner) => match inner.as_ref() {
                DataKind::UInt16 => ColKind::ListU16,
                DataKind::UInt32 => ColKind::ListU32,
                DataKind::String => ColKind::ListStr,
                DataKind::FixedBinary(n) => ColKind::ListFixed(width(n)?),
                _ => return Err(unsupported()),
            },
        })
    }
}

/// Where a column's value comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ColumnSource {
    /// [`PacketRef::frame_number`](crate::io::PacketRef::frame_number).
    FrameNumber,
    /// [`PacketRef::timestamp_ns`](crate::io::PacketRef::timestamp_ns), in
    /// the engine's [`TimestampUnit`].
    Timestamp,
    /// [`PacketRef::captured_len`](crate::io::PacketRef::captured_len).
    CapturedLen,
    /// [`PacketRef::original_len`](crate::io::PacketRef::original_len).
    OriginalLen,
    /// [`PacketRef::link_type`](crate::io::PacketRef::link_type).
    LinkType,
    /// [`PacketRef::data`](crate::io::PacketRef::data).
    RawData,
    /// [`ParseResult::encap_depth`](crate::ParseResult::encap_depth).
    EncapDepth,
    /// [`ParseResult::tunnel_type`](crate::ParseResult::tunnel_type), as its
    /// name; NULL outside a tunnel.
    TunnelType,
    /// [`ParseResult::tunnel_id`](crate::ParseResult::tunnel_id).
    TunnelId,
    /// A field the table's parser extracted, by its short name (the
    /// descriptor name without the `protocol.` prefix).
    Field(&'static str),
    /// Computed by the stream analysis that builds the column's
    /// [stream table](TableKind::Stream) at the end of the pass. There is no
    /// per-packet source.
    Stream,
}

/// One column of a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnDef {
    /// Column name, unique within the table.
    pub name: &'static str,
    /// What the column stores. A timestamp is declared as
    /// [`ColKind::TsMicros`]; see [`ColumnDef::kind_in`].
    pub kind: ColKind,
    /// Whether the column can hold NULL.
    pub nullable: bool,
    /// Where the value comes from.
    pub source: ColumnSource,
    /// Part of the table as `SELECT *` shows it. `false` marks a column an
    /// engine may opt into; an engine that does not must not expose it at
    /// all. The only such column is the `timestamp` of the protocol tables,
    /// which the DuckDB extension exposes and DataFusion does not.
    pub default: bool,
}

impl ColumnDef {
    /// A nullable default column.
    pub const fn new(name: &'static str, kind: ColKind, source: ColumnSource) -> Self {
        Self {
            name,
            kind,
            nullable: true,
            source,
            default: true,
        }
    }

    /// A nullable default column filled from the parser field `name`.
    pub const fn field(name: &'static str, kind: ColKind) -> Self {
        Self::new(name, kind, ColumnSource::Field(name))
    }

    /// The same column, never NULL.
    pub const fn required(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// The same column, left out of `SELECT *` (see [`ColumnDef::default`]).
    pub const fn opt_in(mut self) -> Self {
        self.default = false;
        self
    }

    /// The column's kind with timestamps stored in `unit`.
    pub const fn kind_in(&self, unit: TimestampUnit) -> ColKind {
        self.kind.with_timestamp_unit(unit)
    }
}

/// The tables built by stream analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamTable {
    /// `tcp_connections`: one row per reassembled TCP connection.
    TcpConnections,
    /// `tls_sessions`: one row per TLS session.
    TlsSessions,
    /// `http_messages`: one row per HTTP/1.x message.
    HttpMessages,
    /// `http2`: one row per HTTP/2 frame of a decrypted TLS stream.
    Http2,
}

/// How a table's rows are produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableKind {
    /// `frames`: one row per packet, from the packet record alone.
    Frames,
    /// One row per parsed layer of the protocol the table is named after.
    Protocol,
    /// Built by stream analysis (TCP reassembly, then TLS and HTTP) from the
    /// whole capture in order, not per packet.
    Stream(StreamTable),
}

/// One table: its name, how it is produced, and its columns in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableDef {
    /// Table name. For a [`TableKind::Protocol`] table this is the parser's
    /// name.
    pub name: &'static str,
    /// How the rows are produced.
    pub kind: TableKind,
    /// Every column, in table order; [`ColId`] indexes this slice.
    pub columns: Box<[ColumnDef]>,
}

impl TableDef {
    /// The column with this id.
    ///
    /// # Panics
    ///
    /// If `id` is not a column of this table.
    pub fn get(&self, id: ColId) -> &ColumnDef {
        &self.columns[usize::from(id.0)]
    }

    /// Look a column up by name.
    pub fn column(&self, name: &str) -> Option<(ColId, &ColumnDef)> {
        self.columns().find(|(_, c)| c.name == name)
    }

    /// Every column with its id, in table order.
    pub fn columns(&self) -> impl Iterator<Item = (ColId, &ColumnDef)> {
        self.columns
            .iter()
            .enumerate()
            .map(|(i, c)| (ColId(i as u16), c))
    }

    /// The columns of `SELECT *` (see [`ColumnDef::default`]) with their
    /// ids, in table order.
    pub fn default_columns(&self) -> impl Iterator<Item = (ColId, &ColumnDef)> {
        self.columns().filter(|(_, c)| c.default)
    }

    /// True for a table built by stream analysis.
    pub const fn is_stream(&self) -> bool {
        matches!(self.kind, TableKind::Stream(_))
    }
}

/// A set of tables.
#[derive(Debug)]
pub struct Catalog {
    tables: Vec<TableDef>,
    by_name: HashMap<&'static str, TableId>,
}

impl Catalog {
    /// Build a catalogue. Table order is kept and defines the [`TableId`]s.
    ///
    /// # Panics
    ///
    /// On a duplicate table name, a duplicate column name within a table, or
    /// more than `u16::MAX` tables or columns.
    pub fn new(tables: Vec<TableDef>) -> Self {
        assert!(tables.len() <= usize::from(u16::MAX), "too many tables");
        let mut by_name = HashMap::with_capacity(tables.len());
        for (i, table) in tables.iter().enumerate() {
            assert!(
                by_name.insert(table.name, TableId(i as u16)).is_none(),
                "duplicate table {}",
                table.name
            );
            assert!(
                table.columns.len() <= usize::from(u16::MAX),
                "{}: too many columns",
                table.name
            );
            for (n, column) in table.columns.iter().enumerate() {
                assert!(
                    !table.columns[..n].iter().any(|c| c.name == column.name),
                    "{}: duplicate column {}",
                    table.name,
                    column.name
                );
            }
        }
        Self { tables, by_name }
    }

    /// The tables pcapsql exposes.
    pub fn builtin() -> &'static Catalog {
        static BUILTIN: OnceLock<Catalog> = OnceLock::new();
        BUILTIN.get_or_init(|| Catalog::new(super::tables::builtin_tables()))
    }

    /// Look a table up by name.
    pub fn table(&self, name: &str) -> Option<(TableId, &TableDef)> {
        let id = *self.by_name.get(name)?;
        Some((id, self.get(id)))
    }

    /// The table with this id.
    ///
    /// # Panics
    ///
    /// If `id` is not a table of this catalogue.
    pub fn get(&self, id: TableId) -> &TableDef {
        &self.tables[usize::from(id.0)]
    }

    /// Every table with its id, in catalogue order.
    pub fn tables(&self) -> impl Iterator<Item = (TableId, &TableDef)> {
        self.tables
            .iter()
            .enumerate()
            .map(|(i, t)| (TableId(i as u16), t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_registry, Protocol};

    /// Parser fields (`proto.field` descriptors) that the protocol's table
    /// does not expose as a column yet. The builders drop these values; the
    /// list pins the gap so that a parser field silently falling out of a
    /// table is caught, and shrinks as columns are added (which changes
    /// `SELECT *` and therefore the golden snapshots).
    const NOT_EXPOSED_AS_COLUMNS: &[&str] = &[
        "mpls.is_reserved_label",
        "mpls.special_label_name",
        "gre.version_valid",
        "gre.version_name",
        "gre.checksum_valid",
        "gre.header_length",
        "vxlan.i_flag_valid",
        "vxlan.flags_valid",
        "vxlan.inner_frame_length",
    ];

    /// `"dns.query_name"` -> `"query_name"`.
    fn short_name(field_name: &str) -> &str {
        field_name
            .split_once('.')
            .map_or(field_name, |(_, short)| short)
    }

    /// Every parser field descriptor (`proto.field`) with a column in its
    /// protocol's table must agree with that column's kind: the builders
    /// convert each `FieldValue` into the column's kind, so a width mismatch
    /// here is where a parser value would be narrowed (or a pushed filter
    /// compared at a different width than the stored column). The one
    /// sanctioned difference is an address: descriptors call it `String`
    /// (engine-agnostic), the tables store it typed (IPv4 `U32`, IPv6
    /// `Fixed(16)`, MAC `Fixed(6)`). Fields with no column must be listed in
    /// `NOT_EXPOSED_AS_COLUMNS`; columns with no descriptor (never
    /// populated) are errors too.
    #[test]
    fn parser_field_descriptors_match_table_schemas() {
        let catalog = Catalog::builtin();
        let registry = default_registry();
        let mut problems = Vec::new();
        for parser in registry.all_parsers() {
            let name = parser.name();
            let Some((_, table)) = catalog.table(name) else {
                problems.push(format!("{name}: parser has no table"));
                continue;
            };
            if table.kind != TableKind::Protocol {
                problems.push(format!("{name}: parser's table is {:?}", table.kind));
            }
            let descriptors = parser.schema_fields();
            for fd in &descriptors {
                let field = short_name(fd.name);
                let column = table
                    .columns
                    .iter()
                    .find(|c| c.source == ColumnSource::Field(field));
                match column {
                    None => {
                        if !NOT_EXPOSED_AS_COLUMNS.contains(&fd.name) {
                            problems.push(format!(
                                "{name}.{field}: no such table column (add it, or list it \
                                 in NOT_EXPOSED_AS_COLUMNS)"
                            ));
                        }
                    }
                    Some(column) => {
                        if NOT_EXPOSED_AS_COLUMNS.contains(&fd.name) {
                            problems.push(format!(
                                "{name}.{field}: listed in NOT_EXPOSED_AS_COLUMNS but exposed"
                            ));
                        }
                        let typed_address = fd.kind == DataKind::String
                            && matches!(
                                column.kind,
                                ColKind::U32 | ColKind::Fixed(16) | ColKind::Fixed(6)
                            );
                        match ColKind::try_from(&fd.kind) {
                            Ok(want) if want == column.kind || typed_address => {}
                            Ok(want) => problems.push(format!(
                                "{name}.{field}: descriptor {want:?} vs table column {:?}",
                                column.kind
                            )),
                            Err(e) => problems.push(format!("{name}.{field}: {e}")),
                        }
                    }
                }
            }
            // Every other column is filled from the frame or the parse
            // context; a `Field` column needs a parser field.
            for column in table.columns.iter() {
                let ColumnSource::Field(field) = column.source else {
                    continue;
                };
                if !descriptors.iter().any(|fd| short_name(fd.name) == field) {
                    problems.push(format!(
                        "{name}.{}: table column has no parser field",
                        column.name
                    ));
                }
            }
        }
        // The other direction: a protocol table without a parser has no rows.
        for (_, table) in catalog.tables() {
            if table.kind == TableKind::Protocol && registry.get_parser(table.name).is_none() {
                problems.push(format!("{}: protocol table has no parser", table.name));
            }
        }
        assert!(
            problems.is_empty(),
            "descriptor / table schema drift:\n  {}",
            problems.join("\n  ")
        );
    }

    /// Table order is `SHOW TABLES` order and defines the `TableId`s.
    #[test]
    fn builtin_tables_and_their_order() {
        let names: Vec<_> = Catalog::builtin().tables().map(|(_, t)| t.name).collect();
        assert_eq!(
            names,
            [
                "frames",
                "ethernet",
                "linux_sll",
                "sll2",
                "arp",
                "vlan",
                "mpls",
                "ipv4",
                "ipv6",
                "tcp",
                "udp",
                "icmp",
                "icmpv6",
                "gre",
                "vxlan",
                "gtp",
                "ipsec",
                "bgp",
                "ospf",
                "dns",
                "dhcp",
                "ntp",
                "http",
                "http2",
                "tls",
                "ssh",
                "quic",
                "netlink",
                "rtnetlink",
                "tcp_connections",
                "tls_sessions",
                "http_messages",
            ]
        );
    }

    #[test]
    fn stream_tables_are_the_four_stream_kinds() {
        let streams: Vec<_> = Catalog::builtin()
            .tables()
            .filter_map(|(_, t)| match t.kind {
                TableKind::Stream(s) => Some((t.name, s)),
                _ => None,
            })
            .collect();
        assert_eq!(
            streams,
            [
                ("http2", StreamTable::Http2),
                ("tcp_connections", StreamTable::TcpConnections),
                ("tls_sessions", StreamTable::TlsSessions),
                ("http_messages", StreamTable::HttpMessages),
            ]
        );
        assert!(Catalog::builtin().table("http2").unwrap().1.is_stream());
        assert!(!Catalog::builtin().table("http").unwrap().1.is_stream());
    }

    /// Ids are positions: lookups by name and by id agree, both for tables
    /// and for columns (non-default columns included).
    #[test]
    fn ids_are_dense_and_lookups_agree() {
        let catalog = Catalog::builtin();
        for (n, (id, table)) in catalog.tables().enumerate() {
            assert_eq!(id, TableId(n as u16));
            assert!(std::ptr::eq(catalog.get(id), table));
            let (by_name, found) = catalog.table(table.name).expect("by name");
            assert_eq!(by_name, id);
            assert!(std::ptr::eq(found, table));

            for (m, (col_id, column)) in table.columns().enumerate() {
                assert_eq!(col_id, ColId(m as u16));
                assert!(std::ptr::eq(table.get(col_id), column));
                let (by_name, found) = table.column(column.name).expect("by name");
                assert_eq!(by_name, col_id, "{}.{}", table.name, column.name);
                assert!(std::ptr::eq(found, column));
            }
            assert!(table.column("no_such_column").is_none());
        }
        assert!(catalog.table("nonexistent").is_none());
    }

    /// Positions other code relies on: `frame_number` leads every table, the
    /// opt-in `timestamp` follows it in a protocol table, and the three
    /// encapsulation columns close every table but `frames`.
    #[test]
    fn column_positions_are_stable() {
        let catalog = Catalog::builtin();
        for (_, table) in catalog.tables() {
            let name = table.name;
            assert_eq!(table.get(ColId(0)).name, "frame_number", "{name}");
            assert_eq!(table.get(ColId(0)).kind, ColKind::U64, "{name}");
            assert!(!table.get(ColId(0)).nullable, "{name}");
            if table.kind == TableKind::Frames {
                continue;
            }
            let tail: Vec<_> = table.columns[table.columns.len() - 3..]
                .iter()
                .map(|c| (c.name, c.kind, c.nullable))
                .collect();
            assert_eq!(
                tail,
                [
                    ("encap_depth", ColKind::U8, false),
                    ("tunnel_type", ColKind::Str, true),
                    ("tunnel_id", ColKind::U64, true),
                ],
                "{name}"
            );
        }
        let (_, tcp) = catalog.table("tcp").unwrap();
        assert_eq!(tcp.column("timestamp").unwrap().0, ColId(1));
        assert_eq!(tcp.column("src_port").unwrap().0, ColId(2));
        assert_eq!(tcp.default_columns().nth(1).unwrap().0, ColId(2));
        let (_, frames) = catalog.table("frames").unwrap();
        let frame_columns: Vec<_> = frames.columns.iter().map(|c| c.name).collect();
        assert_eq!(
            frame_columns,
            [
                "frame_number",
                "timestamp",
                "length",
                "original_length",
                "link_type",
                "raw_data"
            ]
        );
    }

    /// Roadmap decision D5: the one non-default column is the `timestamp`
    /// of a protocol table, directly after `frame_number`. `frames` has its
    /// own (default) timestamp and the stream tables have none.
    #[test]
    fn only_protocol_tables_have_an_opt_in_timestamp() {
        for (_, table) in Catalog::builtin().tables() {
            let opt_in: Vec<_> = table.columns().filter(|(_, c)| !c.default).collect();
            match table.kind {
                TableKind::Protocol => {
                    assert_eq!(opt_in.len(), 1, "{}", table.name);
                    let (id, column) = opt_in[0];
                    assert_eq!(id, ColId(1), "{}", table.name);
                    assert_eq!(
                        *column,
                        ColumnDef {
                            name: "timestamp",
                            kind: ColKind::TsMicros,
                            nullable: false,
                            source: ColumnSource::Timestamp,
                            default: false,
                        },
                        "{}",
                        table.name
                    );
                }
                TableKind::Frames | TableKind::Stream(_) => {
                    assert!(opt_in.is_empty(), "{}", table.name);
                }
            }
            assert_eq!(
                table.default_columns().count(),
                table.columns.len() - opt_in.len()
            );
        }
    }

    /// Each kind of table draws its columns from the sources it can have.
    #[test]
    fn sources_fit_the_table_kind() {
        use ColumnSource::*;
        for (_, table) in Catalog::builtin().tables() {
            for column in table.columns.iter() {
                let ok = match table.kind {
                    TableKind::Frames => matches!(
                        column.source,
                        FrameNumber | Timestamp | CapturedLen | OriginalLen | LinkType | RawData
                    ),
                    TableKind::Protocol => match column.source {
                        FrameNumber | Timestamp | EncapDepth | TunnelType | TunnelId => true,
                        // The short name of a field is the column's name.
                        Field(field) => field == column.name,
                        _ => false,
                    },
                    TableKind::Stream(_) => column.source == Stream,
                };
                assert!(
                    ok,
                    "{}.{}: source {:?}",
                    table.name, column.name, column.source
                );
            }
            // One column per packet or context source.
            for (n, column) in table.columns.iter().enumerate() {
                if matches!(column.source, Field(_) | Stream) {
                    continue;
                }
                assert!(
                    !table.columns[..n].iter().any(|c| c.source == column.source),
                    "{}: two columns from {:?}",
                    table.name,
                    column.source
                );
            }
        }
    }

    /// No table declares nanoseconds: the unit is the engine's choice.
    #[test]
    fn timestamps_are_declared_in_micros_and_convert() {
        let mut timestamps = 0;
        for (_, table) in Catalog::builtin().tables() {
            for column in table.columns.iter() {
                assert_ne!(
                    column.kind,
                    ColKind::TsNanos,
                    "{}.{}",
                    table.name,
                    column.name
                );
                if column.kind.is_timestamp() {
                    timestamps += 1;
                    assert_eq!(column.kind_in(TimestampUnit::Nanos), ColKind::TsNanos);
                    assert_eq!(column.kind_in(TimestampUnit::Micros), ColKind::TsMicros);
                } else {
                    assert_eq!(column.kind_in(TimestampUnit::Nanos), column.kind);
                }
            }
        }
        // frames.timestamp, tcp_connections.start_time / end_time, and one
        // opt-in timestamp per protocol table.
        assert_eq!(timestamps, 3 + 27);
        assert_eq!(
            ColKind::TsNanos.with_timestamp_unit(TimestampUnit::Micros),
            ColKind::TsMicros
        );
    }

    #[test]
    fn col_kind_round_trips_through_data_kind() {
        let kinds = [
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
            ColKind::Fixed(32),
            ColKind::TsMicros,
            ColKind::ListU16,
            ColKind::ListU32,
            ColKind::ListStr,
            ColKind::ListFixed(16),
        ];
        for kind in kinds {
            let data_kind = kind.data_kind().expect("has a DataKind");
            assert_eq!(ColKind::try_from(&data_kind), Ok(kind), "{kind:?}");
        }
        assert_eq!(ColKind::TsNanos.data_kind(), None);

        let list = |inner| DataKind::List(Box::new(inner));
        for unsupported in [
            list(DataKind::Binary),
            list(DataKind::UInt8),
            list(list(DataKind::String)),
            DataKind::FixedBinary(70_000),
            list(DataKind::FixedBinary(70_000)),
        ] {
            assert_eq!(
                ColKind::try_from(&unsupported),
                Err(UnsupportedKind(unsupported.clone()))
            );
        }
    }

    /// Every kind a parser declares can be stored.
    #[test]
    fn every_descriptor_kind_is_a_column_kind() {
        for parser in default_registry().all_parsers() {
            for fd in parser.schema_fields() {
                assert!(
                    ColKind::try_from(&fd.kind).is_ok(),
                    "{}: {:?}",
                    fd.name,
                    fd.kind
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "duplicate column a")]
    fn duplicate_column_names_are_rejected() {
        Catalog::new(vec![TableDef {
            name: "t",
            kind: TableKind::Protocol,
            columns: Box::new([
                ColumnDef::field("a", ColKind::U8),
                ColumnDef::field("a", ColKind::U16),
            ]),
        }]);
    }

    #[test]
    #[should_panic(expected = "duplicate table t")]
    fn duplicate_table_names_are_rejected() {
        let table = || TableDef {
            name: "t",
            kind: TableKind::Protocol,
            columns: Box::new([ColumnDef::field("a", ColKind::U8)]),
        };
        Catalog::new(vec![table(), table()]);
    }
}
