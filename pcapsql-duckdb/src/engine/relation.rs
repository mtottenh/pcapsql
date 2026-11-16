//! What the extension reads, from the same definitions the scans of every frontend use
//! (`pcapsql_core::scan`: its `Catalog` of tables and its `PacketsView`s).
//!
//! [`scan_tables`] and [`exposed_columns`] say which tables and columns of the catalogue this
//! engine offers, and [`views`] which views. A [`Relation`] is one of either: what a scan
//! function reads (`engine::table`) and what the listing functions describe
//! (`engine::listing`).

use pcapsql_core::scan::{
    Catalog, ColId, ColKind, ColumnDef, ColumnSource, FramePredicate, PacketsView, ScanPlan,
    TableDef, TableId, TableScan,
};

use super::types;

/// The tables of the catalogue this engine reads, in catalogue order: all of them. That is
/// `frames`, the protocol tables, and the stream tables (`tcp_connections`, `tls_sessions`,
/// `http_messages`, `http2`), which the scan layer builds from the reassembled TCP streams of
/// a capture rather than frame by frame (see [`Relation::is_stream`]).
pub(super) fn scan_tables() -> impl Iterator<Item = (TableId, &'static TableDef)> {
    Catalog::builtin().tables()
}

/// The table `name` of the catalogue.
pub(super) fn scan_table(name: &str) -> Option<(TableId, &'static TableDef)> {
    Catalog::builtin().table(name)
}

/// The columns of `table` this engine exposes, in table order: every column of the catalogue,
/// the opt-in ones included. That is the `timestamp` of the protocol tables, which DuckDB needs
/// because it cannot fuse a join against `frames` (decision D5 of the roadmap).
pub(super) fn exposed_columns(table: &TableDef) -> impl Iterator<Item = (ColId, &ColumnDef)> {
    table.columns()
}

/// The `*_packets` views this engine reads: all of those the scan layer defines, in its order.
pub(super) fn views() -> &'static [PacketsView] {
    PacketsView::all()
}

/// Where a message about an unknown table or view sends the reader.
pub(super) const WHERE_TO_LOOK: &str =
    "pcap_protocols() lists the tables and pcap_views() the views";

/// What a scan function reads: a table of the catalogue, or a `*_packets` view.
#[derive(Debug, Clone, Copy)]
pub(super) enum Relation {
    /// One of [`scan_tables`].
    Table(TableId),
    /// One of [`views`]: a join of tables on the frame, which the scan layer evaluates frame
    /// by frame as one output of the pass (a fused scan).
    View(&'static PacketsView),
}

/// Which of the frame's own columns a declared column is. A filter on one of these says which
/// frames a scan must read (`engine::pushdown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameColumn {
    Number,
    Timestamp,
}

/// A column a scan function declares to DuckDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Declared {
    pub(super) name: &'static str,
    /// What it stores, a timestamp in this engine's unit.
    pub(super) kind: ColKind,
    pub(super) nullable: bool,
    pub(super) frame: Option<FrameColumn>,
}

impl Relation {
    /// The table or view called `name`, if the engine reads it.
    pub(super) fn find(name: &str) -> Option<Relation> {
        match scan_table(name) {
            Some((table, _)) => Some(Relation::Table(table)),
            None => views()
                .iter()
                .find(|view| view.name == name)
                .map(Relation::View),
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Relation::Table(table) => Catalog::builtin().get(table).name,
            Relation::View(view) => view.name,
        }
    }

    /// Whether the relation is a stream table: its rows are what the reassembled TCP streams
    /// of a whole capture hold when it ends, so a scan of it reads each capture in order as
    /// one partition, takes no frame predicate, and is what a key log is for.
    pub(super) fn is_stream(self) -> bool {
        match self {
            Relation::Table(table) => Catalog::builtin().get(table).is_stream(),
            Relation::View(_) => false,
        }
    }

    /// The columns a scan of the relation returns, in order: a table's exposed columns, a
    /// view's columns.
    pub(super) fn columns(self) -> Vec<Declared> {
        match self {
            Relation::Table(table) => exposed_columns(Catalog::builtin().get(table))
                .map(|(_, column)| Declared {
                    name: column.name,
                    kind: types::column_kind(column),
                    nullable: column.nullable,
                    // None in a stream table: its `frame_number` is worked out by stream
                    // analysis (`ColumnSource::Stream`), a value of the row that says
                    // nothing about which frames to read.
                    frame: match column.source {
                        ColumnSource::FrameNumber => Some(FrameColumn::Number),
                        ColumnSource::Timestamp => Some(FrameColumn::Timestamp),
                        _ => None,
                    },
                })
                .collect(),
            Relation::View(view) => view
                .columns()
                .iter()
                .map(|column| Declared {
                    name: column.name,
                    kind: column.kind_in(types::TIMESTAMPS),
                    nullable: column.nullable,
                    frame: if column.is_frame_number {
                        Some(FrameColumn::Number)
                    } else if column.is_timestamp {
                        Some(FrameColumn::Timestamp)
                    } else {
                        None
                    },
                })
                .collect(),
        }
    }

    /// The plan of a scan of `columns` (indices into [`columns`](Self::columns), in output
    /// order) over the frames `frames` accepts. Either way it has one output: the table's
    /// rows, or the view's joined rows.
    ///
    /// A stream table is built from every frame, so its plan compiles only with the
    /// predicate that accepts them all, which is the only one a scan of it ever has: none
    /// of its columns is a [`FrameColumn`].
    ///
    /// # Panics
    ///
    /// If an index is not a column of the relation.
    pub(super) fn plan(self, columns: &[usize], frames: FramePredicate) -> ScanPlan {
        let mut plan = ScanPlan {
            frames,
            timestamps: types::TIMESTAMPS,
            ..ScanPlan::default()
        };
        match self {
            Relation::Table(table) => {
                let exposed: Vec<ColId> = exposed_columns(Catalog::builtin().get(table))
                    .map(|(id, _)| id)
                    .collect();
                let columns = columns.iter().map(|&index| exposed[index]).collect();
                let scan = TableScan::new(table, columns);
                if self.is_stream() {
                    plan.streams.push(scan);
                } else {
                    plan.tables.push(scan);
                }
            }
            Relation::View(view) => plan.fused.push(view.scan(columns)),
        }
        plan
    }
}

/// Everything a scan function can read: the tables, then the views.
pub(super) fn relations() -> impl Iterator<Item = Relation> {
    scan_tables()
        .map(|(table, _)| Relation::Table(table))
        .chain(views().iter().map(Relation::View))
}
