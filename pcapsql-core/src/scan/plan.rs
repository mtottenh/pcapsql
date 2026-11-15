//! The scan plan: what one pass over a capture must produce.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! A frontend describes a pass as a [`ScanPlan`]: which tables, which of
//! their columns and in what order, which rows can be skipped, how many rows
//! are wanted. [`ScanPlan::compile`] checks the plan against the
//! [`Catalog`] and resolves, once, everything the packet loop would
//! otherwise look up per packet: the [`ParseScope`] (which parsers run and
//! which fields they extract) and, per output, each column's name, kind,
//! nullability and source.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::catalog::{
    Catalog, ColId, ColKind, ColumnSource, TableDef, TableId, TableKind, TimestampUnit,
};
use super::fused::{FusedCell, FusedFilterPlan, FusedMemberPlan, FusedPlan};
use super::predicate::{CompiledPredicate, FramePredicate, RowPredicate};
use super::stream::{StreamPlan, StreamTable};
use crate::{ParseScope, ProtocolRegistry};

/// A column of a scan's output: its position in [`OutputPlan::columns`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutCol(pub u16);

/// An output of a compiled scan: its index into [`CompiledScan::outputs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutputId(pub u16);

/// The scan of one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableScan {
    /// The table.
    pub table: TableId,
    /// The output columns, in output order. Any column of the table can be
    /// named, opt-in columns ([`ColumnDef::default`](super::ColumnDef::default))
    /// included; an empty list produces rows without columns (a row count).
    pub columns: Vec<ColId>,
    /// Rows that can be skipped (conservative: the engine applies its filter
    /// again). Not supported on a stream table.
    pub predicate: Option<RowPredicate>,
    /// At most this many rows are wanted, per partition (a pushed-down
    /// `LIMIT`).
    pub fetch: Option<u64>,
}

impl TableScan {
    /// Scan `columns` of `table`, every row.
    pub fn new(table: TableId, columns: Vec<ColId>) -> Self {
        Self {
            table,
            columns,
            predicate: None,
            fetch: None,
        }
    }
}

/// How a member of a [`FusedScan`] joins in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JoinKind {
    /// Rows without a match are dropped.
    Inner,
    /// A row without a match is kept, with NULL for this member's columns.
    Left,
}

/// The join of one member of a [`FusedScan`] onto an earlier one: equal
/// `frame_number` (always, and trivially true within one frame) and, when
/// `depth` is set, equal `encap_depth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemberJoin {
    /// Inner or left.
    pub kind: JoinKind,
    /// Index of the member whose keys this one is compared with.
    pub with: usize,
    /// Whether `encap_depth` must be equal too.
    pub depth: bool,
}

/// One table of a [`FusedScan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FusedMember {
    /// `frames` or a protocol table.
    pub table: TableId,
    /// `None` for the first member (the root); otherwise the join that
    /// brings this member in.
    pub join: Option<MemberJoin>,
}

/// What one output column of a [`FusedScan`] holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FusedValue {
    /// A column of a member's table: NULL in a row where a left-joined
    /// member has no match.
    Column {
        /// The member.
        member: u16,
        /// A column of that member's table.
        column: ColId,
    },
    /// The first of these member columns that is not NULL, as SQL's
    /// `COALESCE`; NULL when all are. The columns must have the same kind.
    Coalesce(Vec<(u16, ColId)>),
    /// A text chosen by which members have a row: the label of the first
    /// member listed that does, `otherwise` when none does. It is SQL's
    /// `CASE WHEN m.frame_number IS NOT NULL THEN label ... ELSE otherwise
    /// END` over left-joined members.
    Present {
        /// The members to look at, in order, each with its label.
        cases: Vec<(u16, &'static str)>,
        /// The label when none of them has a row.
        otherwise: &'static str,
    },
}

/// One output column of a [`FusedScan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusedColumn {
    /// The column's name in the output. `None`: the name of the table
    /// column, which only a [`FusedValue::Column`] has.
    pub name: Option<&'static str>,
    /// What it holds.
    pub value: FusedValue,
}

impl From<(u16, ColId)> for FusedColumn {
    /// The column `column` of member `member`, under its own name.
    fn from((member, column): (u16, ColId)) -> Self {
        Self {
            name: None,
            value: FusedValue::Column { member, column },
        }
    }
}

/// An exact filter on the joined rows of a [`FusedScan`]: a row is kept if
/// and only if the member has a row in it and the column's value is one of
/// `any_of`, as SQL's `member.column IN (...)` in a `WHERE` (a NULL is not
/// in the list). Unlike a [`RowPredicate`] it is not conservative: no engine
/// applies it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusedFilter {
    /// The member.
    pub member: u16,
    /// An integer column of that member's protocol table, filled from a
    /// parser field.
    pub column: ColId,
    /// The values that keep a row.
    pub any_of: Vec<i64>,
}

/// A join of tables on `frame_number`, produced per frame from the frame's
/// own layers instead of by a join operator.
///
/// The rows are those of the SQL join, every match included: for each frame
/// the members' rows are that frame's layers of each member's table (the
/// frame itself for `frames`), joined in member order, and the frame's
/// joined rows come out in the order of nested loops over the members, the
/// root outermost and each member's rows in layer order. Frames come in
/// capture order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusedScan {
    /// In join order; `members[0]` is the root.
    pub members: Vec<FusedMember>,
    /// The output columns in output order.
    pub columns: Vec<FusedColumn>,
    /// Which joined rows are wanted; `None` for all of them.
    pub filter: Option<FusedFilter>,
    /// At most this many rows are wanted, per partition (counted after the
    /// filter).
    pub fetch: Option<u64>,
}

/// What one pass over a capture must produce.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanPlan {
    /// Scans of `frames` and of protocol tables. At most one per table.
    pub tables: Vec<TableScan>,
    /// Fused joins.
    pub fused: Vec<FusedScan>,
    /// Scans of [stream tables](TableKind::Stream). At most one per table.
    /// Any of these pins the pass to one partition, which is then read to
    /// its end: the rows of a stream table exist when the capture ends.
    pub streams: Vec<TableScan>,
    /// Which frames the pass covers: exactly the packets this accepts give
    /// rows, to every per-packet output. Must be
    /// [all](FramePredicate::all) in a plan with stream tables, whose rows
    /// are derived from the whole capture
    /// ([`PlanError::StreamFramePredicate`]).
    pub frames: FramePredicate,
    /// The unit timestamp columns are produced in.
    pub timestamps: TimestampUnit,
}

/// Why a [`ScanPlan`] does not compile.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The catalogue has no table with this id.
    #[error("the catalogue has no table {}", .0 .0)]
    UnknownTable(TableId),
    /// The table has no column with this id.
    #[error("table {table} has no column {}", column.0)]
    UnknownColumn {
        /// The table's name.
        table: &'static str,
        /// The column asked for.
        column: ColId,
    },
    /// Two scans of the same table in [`ScanPlan::tables`] or in
    /// [`ScanPlan::streams`].
    #[error("table {0} is scanned twice")]
    DuplicateTable(&'static str),
    /// A stream table in [`ScanPlan::tables`] or as a member of a fused
    /// join.
    #[error("{0} is a stream table, not built per packet")]
    NotAPacketTable(&'static str),
    /// A table in [`ScanPlan::streams`] that is not a stream table.
    #[error("{0} is not a stream table")]
    NotAStreamTable(&'static str),
    /// A row predicate on a stream table.
    #[error("stream table {0} cannot take a row predicate")]
    StreamPredicate(&'static str),
    /// A [frame predicate](ScanPlan::frames) other than
    /// [all](FramePredicate::all) in a plan with stream tables. A stream
    /// table is assembled from every packet of the capture in order
    /// (a connection whose first segments are skipped is a different
    /// connection), and its rows belong to no single frame, so there is no
    /// set of frames the predicate could soundly restrict it to.
    #[error("a plan with stream tables cannot restrict the frames it covers")]
    StreamFramePredicate,
    /// A fused join that is not well formed.
    #[error("fused join {fused}: {reason}")]
    InvalidFused {
        /// Its index in [`ScanPlan::fused`].
        fused: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A [stream table](TableKind::Stream) of the catalogue that stream
    /// analysis does not build. No table of the built-in catalogue is one.
    #[error("stream analysis does not build table {0}")]
    StreamNotBuilt(&'static str),
    /// More outputs or output columns than an [`OutputId`] or [`OutCol`]
    /// can number.
    #[error("the plan has too many outputs or columns")]
    TooLarge,
}

/// One column of an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutColumn {
    /// The column's name: in its table or, for a column of a fused join
    /// that was given one ([`FusedColumn::name`]), in the join's output.
    pub name: &'static str,
    /// What it stores, timestamps in the plan's unit.
    pub kind: ColKind,
    /// Whether it can hold NULL. A column of a left-joined member of a
    /// fused join always can.
    pub nullable: bool,
    /// Where the value comes from.
    pub source: ColumnSource,
}

/// One output of a compiled scan: a table's rows, or a fused join's.
#[derive(Clone, Debug)]
pub struct OutputPlan {
    /// The table, or `None` for a fused join.
    pub table: Option<TableId>,
    /// The output columns; [`OutCol`] indexes this slice.
    pub columns: Box<[OutColumn]>,
    predicate: Option<CompiledPredicate>,
    fetch: Option<u64>,
    feed: Feed,
    /// The join, of a fused output.
    fused: Option<Arc<FusedPlan>>,
    /// What each column holds, of a stream table's output.
    stream: Option<StreamPlan>,
}

/// What an output's rows are made from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Feed {
    /// One row per packet, from the packet record (`frames`).
    Frames,
    /// One row per parsed layer with this name (a protocol table).
    Layer(&'static str),
    /// The joined rows of a fused join.
    Fused,
    /// Stream analysis, when the partition ends.
    Stream,
}

impl OutputPlan {
    /// What the output's rows are made from.
    pub(crate) fn feed(&self) -> Feed {
        self.feed
    }

    /// The resolved join of a fused output.
    pub(crate) fn fused(&self) -> Option<&Arc<FusedPlan>> {
        self.fused.as_ref()
    }

    /// The resolved columns of a stream table's output.
    pub(crate) fn stream(&self) -> Option<&StreamPlan> {
        self.stream.as_ref()
    }

    /// The row predicate, if it can drop any row. It keeps per-row lookup
    /// state: clone it for each partition.
    pub fn predicate(&self) -> Option<&CompiledPredicate> {
        self.predicate.as_ref()
    }

    /// At most this many rows are wanted, per partition.
    pub fn fetch(&self) -> Option<u64> {
        self.fetch
    }
}

/// A [`ScanPlan`] checked and resolved against a catalogue and a registry.
#[derive(Clone, Debug)]
pub struct CompiledScan {
    scope: ParseScope,
    outputs: Box<[OutputPlan]>,
    /// How many of `outputs` (the last ones) are stream tables.
    streams: usize,
    frames: FramePredicate,
    timestamps: TimestampUnit,
}

impl CompiledScan {
    /// What to parse: the scanned tables' protocols (the members of fused
    /// joins included) with the protocols they depend on, restricted per
    /// protocol to the fields the output columns read.
    pub fn scope(&self) -> &ParseScope {
        &self.scope
    }

    /// The outputs: [`ScanPlan::tables`], then [`ScanPlan::fused`], then
    /// [`ScanPlan::streams`], each in plan order. [`OutputId`] indexes this
    /// slice. The first two groups get their rows packet by packet; a
    /// stream table gets its rows when the partition ends.
    pub fn outputs(&self) -> &[OutputPlan] {
        &self.outputs
    }

    /// Whether any output is a stream table. Stream analysis needs the
    /// whole capture in order, so such a pass cannot be split into
    /// partitions.
    pub fn requires_single_partition(&self) -> bool {
        self.streams > 0
    }

    /// Which frames the pass covers ([`ScanPlan::frames`]). The scan
    /// driver enforces it; a frontend also plans its partitions with it
    /// ([`plan_ranges`](super::plan_ranges)).
    pub fn frames(&self) -> &FramePredicate {
        &self.frames
    }

    /// The unit timestamp columns are produced in.
    pub fn timestamps(&self) -> TimestampUnit {
        self.timestamps
    }
}

/// The parser fields one protocol table must extract: `None` is all of them.
type Wanted = Option<HashSet<&'static str>>;

/// Per protocol table (in first-use order), the fields the plan reads.
#[derive(Default)]
struct FieldNeeds {
    tables: Vec<(TableId, &'static str)>,
    fields: HashMap<TableId, HashSet<ColId>>,
}

impl FieldNeeds {
    fn want(&mut self, id: TableId, table: &TableDef, columns: impl IntoIterator<Item = ColId>) {
        if table.kind != TableKind::Protocol {
            return; // `frames` comes from the packet record, not from parsing
        }
        if !self.fields.contains_key(&id) {
            self.tables.push((id, table.name));
        }
        self.fields.entry(id).or_default().extend(columns);
    }

    /// The field projection of `table`: the fields its wanted columns read,
    /// or `None` when they read every field the table has a column for (the
    /// parser then runs unprojected).
    fn projection(&self, id: TableId, table: &TableDef) -> Wanted {
        let wanted = &self.fields[&id];
        let mut all = true;
        let mut fields = HashSet::new();
        for (col, def) in table.columns() {
            if let ColumnSource::Field(name) = def.source {
                if wanted.contains(&col) {
                    fields.insert(name);
                } else {
                    all = false;
                }
            }
        }
        (!all).then_some(fields)
    }
}

impl ScanPlan {
    /// Check the plan against `catalog` and resolve everything a packet loop
    /// must not look up: the [`ParseScope`] for `registry` and, per output,
    /// its columns.
    ///
    /// The compiled scan is one a [`PartitionScan`](super::PartitionScan)
    /// runs in full: every output of the plan gets its rows, the
    /// [stream tables](Self::streams) included.
    pub fn compile(
        &self,
        catalog: &Catalog,
        registry: &ProtocolRegistry,
    ) -> Result<CompiledScan, PlanError> {
        let table_of = |id: TableId| catalog.try_get(id).ok_or(PlanError::UnknownTable(id));
        let mut needs = FieldNeeds::default();
        let mut outputs =
            Vec::with_capacity(self.tables.len() + self.fused.len() + self.streams.len());

        let mut seen = HashSet::new();
        for scan in &self.tables {
            let table = table_of(scan.table)?;
            if table.is_stream() {
                return Err(PlanError::NotAPacketTable(table.name));
            }
            if !seen.insert(scan.table) {
                return Err(PlanError::DuplicateTable(table.name));
            }
            let columns = self.scan_columns(table, scan)?;
            let predicate = match &scan.predicate {
                Some(predicate) => {
                    let mut unknown = None;
                    let mut named = Vec::new();
                    predicate.for_each_column(&mut |column| {
                        if table.columns.get(usize::from(column.0)).is_none() {
                            unknown.get_or_insert(column);
                        }
                        named.push(column);
                    });
                    if let Some(column) = unknown {
                        return Err(PlanError::UnknownColumn {
                            table: table.name,
                            column,
                        });
                    }
                    // The fields the predicate compares are extracted even
                    // when they are not output columns; without them it
                    // could never drop a row.
                    needs.want(scan.table, table, named);
                    predicate.compile(table)
                }
                None => None,
            };
            needs.want(scan.table, table, scan.columns.iter().copied());
            outputs.push(OutputPlan {
                table: Some(scan.table),
                columns,
                predicate,
                fetch: scan.fetch,
                feed: match table.kind {
                    TableKind::Frames => Feed::Frames,
                    _ => Feed::Layer(table.name),
                },
                fused: None,
                stream: None,
            });
        }

        for (index, fused) in self.fused.iter().enumerate() {
            let invalid = |reason| PlanError::InvalidFused {
                fused: index,
                reason,
            };
            if fused.members.is_empty() {
                return Err(invalid("no members"));
            }
            let mut members = Vec::with_capacity(fused.members.len());
            for (i, member) in fused.members.iter().enumerate() {
                let table = table_of(member.table)?;
                if table.is_stream() {
                    return Err(PlanError::NotAPacketTable(table.name));
                }
                match (i, &member.join) {
                    (0, None) => {}
                    (0, Some(_)) => return Err(invalid("the first member cannot have a join")),
                    (_, None) => return Err(invalid("a later member needs a join")),
                    (_, Some(join)) if join.with >= i => {
                        return Err(invalid("a member can only join an earlier member"))
                    }
                    (_, Some(_)) => {}
                }
                members.push(table);
            }
            // A column of a member, as an output column and for the parse.
            let member_column =
                |member: u16, column: ColId, needs: &mut FieldNeeds| -> Result<_, PlanError> {
                    let m = usize::from(member);
                    let table = *members
                        .get(m)
                        .ok_or_else(|| invalid("a column names a member the join does not have"))?;
                    let left = matches!(
                        fused.members[m].join,
                        Some(MemberJoin {
                            kind: JoinKind::Left,
                            ..
                        })
                    );
                    let out = self.out_column(table, column, left)?;
                    needs.want(fused.members[m].table, table, [column]);
                    Ok((m, out))
                };
            let mut resolved = Vec::with_capacity(fused.columns.len());
            let mut cells = Vec::with_capacity(fused.columns.len());
            for column in &fused.columns {
                let (out, cell) = match &column.value {
                    FusedValue::Column { member, column: id } => {
                        let (m, out) = member_column(*member, *id, &mut needs)?;
                        (out, FusedCell::column(m, &out))
                    }
                    FusedValue::Coalesce(arguments) => {
                        let mut columns = Vec::with_capacity(arguments.len());
                        for (member, id) in arguments {
                            columns.push(member_column(*member, *id, &mut needs)?);
                        }
                        let (_, first) = *columns
                            .first()
                            .ok_or_else(|| invalid("a COALESCE without arguments"))?;
                        if columns.iter().any(|(_, out)| out.kind != first.kind) {
                            return Err(invalid("the arguments of a COALESCE differ in kind"));
                        }
                        let out = OutColumn {
                            name: first.name,
                            kind: first.kind,
                            nullable: columns.iter().all(|(_, out)| out.nullable),
                            source: ColumnSource::Computed,
                        };
                        (out, FusedCell::coalesce(&columns))
                    }
                    FusedValue::Present { cases, otherwise } => {
                        if cases
                            .iter()
                            .any(|(member, _)| usize::from(*member) >= members.len())
                        {
                            return Err(invalid("a column names a member the join does not have"));
                        }
                        let out = OutColumn {
                            name: "",
                            kind: ColKind::Str,
                            nullable: false,
                            source: ColumnSource::Computed,
                        };
                        let cases = cases.iter().map(|(m, label)| (usize::from(*m), *label));
                        (out, FusedCell::present(cases.collect(), otherwise))
                    }
                };
                let name = match (column.name, &column.value) {
                    (Some(name), _) => name,
                    (None, FusedValue::Column { .. }) => out.name,
                    (None, _) => return Err(invalid("a computed column needs a name")),
                };
                resolved.push(OutColumn { name, ..out });
                cells.push(cell);
            }
            let filter = match &fused.filter {
                None => None,
                Some(filter) => {
                    let (m, out) = member_column(filter.member, filter.column, &mut needs)?;
                    let integer = matches!(
                        out.kind,
                        ColKind::U8
                            | ColKind::U16
                            | ColKind::U32
                            | ColKind::U64
                            | ColKind::I8
                            | ColKind::I64
                    );
                    let ColumnSource::Field(field) = out.source else {
                        return Err(invalid("the filter is not on a parser field"));
                    };
                    if !integer {
                        return Err(invalid("the filter is not on an integer column"));
                    }
                    Some(FusedFilterPlan::new(m, field, out.kind, &filter.any_of))
                }
            };
            // A member with no output column is still parsed: its rows
            // decide which joined rows exist.
            for (member, table) in fused.members.iter().zip(&members) {
                needs.want(member.table, table, []);
            }
            if resolved.len() > usize::from(u16::MAX) {
                return Err(PlanError::TooLarge);
            }
            let plan = FusedPlan {
                members: fused
                    .members
                    .iter()
                    .zip(&members)
                    .map(|(member, table)| FusedMemberPlan {
                        layer: (table.kind != TableKind::Frames).then_some(table.name),
                        join: member.join,
                    })
                    .collect(),
                cells: cells.into(),
                filter,
            };
            outputs.push(OutputPlan {
                table: None,
                columns: resolved.into(),
                predicate: None,
                fetch: fused.fetch,
                feed: Feed::Fused,
                fused: Some(Arc::new(plan)),
                stream: None,
            });
        }

        if !self.streams.is_empty() && !self.frames.is_all() {
            return Err(PlanError::StreamFramePredicate);
        }
        let mut seen = HashSet::new();
        for scan in &self.streams {
            let table = table_of(scan.table)?;
            if !table.is_stream() {
                return Err(PlanError::NotAStreamTable(table.name));
            }
            if !seen.insert(scan.table) {
                return Err(PlanError::DuplicateTable(table.name));
            }
            if scan.predicate.is_some() {
                return Err(PlanError::StreamPredicate(table.name));
            }
            let built =
                StreamTable::named(table.name).ok_or(PlanError::StreamNotBuilt(table.name))?;
            let columns = self.scan_columns(table, scan)?;
            let stream =
                StreamPlan::resolve(built, &columns).map_err(|index| PlanError::UnknownColumn {
                    table: table.name,
                    column: scan.columns[index],
                })?;
            outputs.push(OutputPlan {
                table: Some(scan.table),
                columns,
                predicate: None,
                fetch: scan.fetch,
                feed: Feed::Stream,
                fused: None,
                stream: Some(stream),
            });
        }
        if outputs.len() > usize::from(u16::MAX) {
            return Err(PlanError::TooLarge);
        }

        Ok(CompiledScan {
            scope: parse_scope(catalog, registry, &needs, !self.streams.is_empty()),
            outputs: outputs.into(),
            streams: self.streams.len(),
            frames: self.frames.clone(),
            timestamps: self.timestamps,
        })
    }

    /// The output column for `column` of `table`; `nullable` forces it
    /// nullable.
    fn out_column(
        &self,
        table: &TableDef,
        column: ColId,
        nullable: bool,
    ) -> Result<OutColumn, PlanError> {
        let def = table
            .columns
            .get(usize::from(column.0))
            .ok_or(PlanError::UnknownColumn {
                table: table.name,
                column,
            })?;
        Ok(OutColumn {
            name: def.name,
            kind: def.kind_in(self.timestamps),
            nullable: def.nullable || nullable,
            source: def.source,
        })
    }

    /// The output columns of a table scan.
    fn scan_columns(
        &self,
        table: &TableDef,
        scan: &TableScan,
    ) -> Result<Box<[OutColumn]>, PlanError> {
        if scan.columns.len() > usize::from(u16::MAX) {
            return Err(PlanError::TooLarge);
        }
        scan.columns
            .iter()
            .map(|column| self.out_column(table, *column, false))
            .collect()
    }
}

/// The protocols whose every field stream analysis reads from every packet:
/// the TCP layer (ports, sequence numbers, flags, payload) and the IP
/// addresses.
const STREAM_PROTOCOLS: [&str; 3] = ["tcp", "ipv4", "ipv6"];

/// The scope of a pass: the protocol tables it reads (plus `tcp` for stream
/// analysis) with their dependency closure, and per table the field
/// projection where its columns are a subset.
fn parse_scope(
    catalog: &Catalog,
    registry: &ProtocolRegistry,
    needs: &FieldNeeds,
    streams: bool,
) -> ParseScope {
    let mut names: Vec<&str> = needs.tables.iter().map(|(_, name)| *name).collect();
    if streams {
        names.push("tcp");
    }
    let mut scope = ParseScope::for_tables(&names, registry);
    for (id, name) in &needs.tables {
        if streams && STREAM_PROTOCOLS.contains(name) {
            continue; // stream analysis needs these layers' full fields
        }
        if let Some(fields) = needs.projection(*id, catalog.get(*id)) {
            scope = scope.with_projection(*name, fields.into_iter().map(String::from).collect());
        }
    }
    scope
}

#[cfg(test)]
mod tests;
