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

    /// The columns a scan of the relation returns, in order: a table's exposed columns, a
    /// view's columns.
    pub(super) fn columns(self) -> Vec<Declared> {
        match self {
            Relation::Table(table) => exposed_columns(Catalog::builtin().get(table))
                .map(|(_, column)| Declared {
                    name: column.name,
                    kind: types::column_kind(column),
                    nullable: column.nullable,
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
                plan.tables.push(TableScan::new(table, columns));
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
