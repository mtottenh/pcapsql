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
use std::fmt;
use std::sync::Arc;

use super::catalog::{
    Catalog, ColId, ColKind, ColumnSource, TableDef, TableId, TableKind, TimestampUnit,
};
use super::fused::{FusedCell, FusedFilterPlan, FusedMemberPlan, FusedPlan};
use super::predicate::{CompiledPredicate, FramePredicate, RowPredicate};
use crate::{ParseScope, ProtocolRegistry};

/// A column of a scan's output: its position in [`OutputPlan::columns`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutCol(pub u16);

/// A per-packet output of a compiled scan: its index into
/// [`CompiledScan::outputs`].
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
    /// Any of these pins the pass to one partition.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The catalogue has no table with this id.
    UnknownTable(TableId),
    /// The table has no column with this id.
    UnknownColumn {
        /// The table's name.
        table: &'static str,
        /// The column asked for.
        column: ColId,
    },
    /// Two scans of the same table in [`ScanPlan::tables`] or in
    /// [`ScanPlan::streams`].
    DuplicateTable(&'static str),
    /// A stream table in [`ScanPlan::tables`] or as a member of a fused
    /// join.
    NotAPacketTable(&'static str),
    /// A table in [`ScanPlan::streams`] that is not a stream table.
    NotAStreamTable(&'static str),
    /// A row predicate on a stream table.
    StreamPredicate(&'static str),
    /// A [frame predicate](ScanPlan::frames) other than
    /// [all](FramePredicate::all) in a plan with stream tables. A stream
    /// table is assembled from every packet of the capture in order
    /// (a connection whose first segments are skipped is a different
    /// connection), and its rows belong to no single frame, so there is no
    /// set of frames the predicate could soundly restrict it to.
    StreamFramePredicate,
    /// A fused join that is not well formed.
    InvalidFused {
        /// Its index in [`ScanPlan::fused`].
        fused: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// More outputs or output columns than an [`OutputId`] or [`OutCol`]
    /// can number.
    TooLarge,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::UnknownTable(id) => write!(f, "the catalogue has no table {}", id.0),
            PlanError::UnknownColumn { table, column } => {
                write!(f, "table {table} has no column {}", column.0)
            }
            PlanError::DuplicateTable(table) => write!(f, "table {table} is scanned twice"),
            PlanError::NotAPacketTable(table) => {
                write!(f, "{table} is a stream table, not built per packet")
            }
            PlanError::NotAStreamTable(table) => write!(f, "{table} is not a stream table"),
            PlanError::StreamPredicate(table) => {
                write!(f, "stream table {table} cannot take a row predicate")
            }
            PlanError::StreamFramePredicate => write!(
                f,
                "a plan with stream tables cannot restrict the frames it covers"
            ),
            PlanError::InvalidFused { fused, reason } => {
                write!(f, "fused join {fused}: {reason}")
            }
            PlanError::TooLarge => write!(f, "the plan has too many outputs or columns"),
        }
    }
}

impl std::error::Error for PlanError {}

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
    /// Stream analysis, at the end of the pass.
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
    stream_outputs: Box<[OutputPlan]>,
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

    /// The per-packet outputs: [`ScanPlan::tables`], then
    /// [`ScanPlan::fused`], each in plan order. [`OutputId`] indexes this
    /// slice.
    pub fn outputs(&self) -> &[OutputPlan] {
        &self.outputs
    }

    /// The stream-table outputs, in the order of [`ScanPlan::streams`].
    pub fn stream_outputs(&self) -> &[OutputPlan] {
        &self.stream_outputs
    }

    /// Stream analysis needs the whole capture in order, so a pass with a
    /// stream table cannot be split into partitions.
    pub fn requires_single_partition(&self) -> bool {
        !self.stream_outputs.is_empty()
    }

    /// Which frames the pass covers ([`ScanPlan::frames`]). The scan
    /// driver enforces it; a frontend also plans its partitions with it
    /// ([`plan_ranges`](super::partition::plan_ranges)).
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
    pub fn compile(
        &self,
        catalog: &Catalog,
        registry: &ProtocolRegistry,
    ) -> Result<CompiledScan, PlanError> {
        let table_of = |id: TableId| catalog.try_get(id).ok_or(PlanError::UnknownTable(id));
        let mut needs = FieldNeeds::default();
        let mut outputs = Vec::with_capacity(self.tables.len() + self.fused.len());

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
            });
        }
        if outputs.len() > usize::from(u16::MAX) {
            return Err(PlanError::TooLarge);
        }

        if !self.streams.is_empty() && !self.frames.is_all() {
            return Err(PlanError::StreamFramePredicate);
        }
        let mut stream_outputs = Vec::with_capacity(self.streams.len());
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
            stream_outputs.push(OutputPlan {
                table: Some(scan.table),
                columns: self.scan_columns(table, scan)?,
                predicate: None,
                fetch: scan.fetch,
                feed: Feed::Stream,
                fused: None,
            });
        }

        Ok(CompiledScan {
            scope: parse_scope(catalog, registry, &needs, !self.streams.is_empty()),
            outputs: outputs.into(),
            stream_outputs: stream_outputs.into(),
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
mod tests {
    use super::*;
    use crate::default_registry;
    use crate::scan::{CmpOp, StreamTable};

    fn catalog() -> &'static Catalog {
        Catalog::builtin()
    }

    fn id(table: &str) -> TableId {
        catalog().table(table).expect("table").0
    }

    fn cols(table: &str, names: &[&str]) -> Vec<ColId> {
        let (_, def) = catalog().table(table).expect("table");
        names
            .iter()
            .map(|n| def.column(n).unwrap_or_else(|| panic!("{table}.{n}")).0)
            .collect()
    }

    fn default_cols(table: &str) -> Vec<ColId> {
        let (_, def) = catalog().table(table).expect("table");
        def.default_columns().map(|(c, _)| c).collect()
    }

    fn scan(table: &str, names: &[&str]) -> TableScan {
        TableScan::new(id(table), cols(table, names))
    }

    fn full(table: &str) -> TableScan {
        TableScan::new(id(table), default_cols(table))
    }

    fn compile(plan: &ScanPlan) -> Result<CompiledScan, PlanError> {
        plan.compile(catalog(), &default_registry())
    }

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_empty_plan_parses_nothing() {
        let compiled = compile(&ScanPlan::default()).unwrap();
        assert!(compiled.outputs().is_empty());
        assert!(compiled.stream_outputs().is_empty());
        assert!(!compiled.requires_single_partition());
        assert_eq!(compiled.scope().required(), Some(&set(&["frames"])));
        assert!(compiled.scope().projections().is_empty());
        assert_eq!(compiled.timestamps(), TimestampUnit::Micros);
    }

    #[test]
    fn outputs_follow_the_plan_in_column_order() {
        let plan = ScanPlan {
            tables: vec![
                scan("tcp", &["dst_port", "frame_number", "tunnel_type"]),
                scan("frames", &["timestamp", "length"]),
            ],
            ..ScanPlan::default()
        };
        let compiled = compile(&plan).unwrap();
        let [tcp, frames] = compiled.outputs() else {
            panic!("two outputs");
        };
        assert_eq!(tcp.table, Some(id("tcp")));
        assert_eq!(
            tcp.columns.to_vec(),
            vec![
                OutColumn {
                    name: "dst_port",
                    kind: ColKind::U16,
                    nullable: true,
                    source: ColumnSource::Field("dst_port"),
                },
                OutColumn {
                    name: "frame_number",
                    kind: ColKind::U64,
                    nullable: false,
                    source: ColumnSource::FrameNumber,
                },
                OutColumn {
                    name: "tunnel_type",
                    kind: ColKind::Str,
                    nullable: true,
                    source: ColumnSource::TunnelType,
                },
            ]
        );
        assert_eq!(frames.table, Some(id("frames")));
        assert_eq!(
            frames
                .columns
                .iter()
                .map(|c| (c.name, c.kind, c.source))
                .collect::<Vec<_>>(),
            vec![
                ("timestamp", ColKind::TsMicros, ColumnSource::Timestamp),
                ("length", ColKind::U32, ColumnSource::CapturedLen),
            ]
        );
        assert!(tcp.predicate().is_none());
        assert_eq!(tcp.fetch(), None);
    }

    #[test]
    fn scope_is_the_dependency_closure_with_field_projections() {
        let plan = ScanPlan {
            tables: vec![
                scan("tcp", &["frame_number", "dst_port", "encap_depth"]),
                full("dns"),
                scan("frames", &["length"]),
            ],
            ..ScanPlan::default()
        };
        let registry = default_registry();
        let compiled = plan.compile(catalog(), &registry).unwrap();
        let scope = compiled.scope();
        assert_eq!(
            scope.required(),
            ParseScope::for_tables(&["tcp", "dns", "frames"], &registry).required()
        );
        // Pseudo-columns are not parser fields; a table read in full has no
        // projection; `frames` is not parsed.
        assert_eq!(
            scope.projections(),
            &HashMap::from([("tcp".to_string(), set(&["dst_port"]))])
        );
    }

    #[test]
    fn a_scan_without_field_columns_projects_no_fields() {
        let plan = ScanPlan {
            tables: vec![scan("udp", &[]), scan("tcp", &["frame_number"])],
            ..ScanPlan::default()
        };
        let compiled = compile(&plan).unwrap();
        assert_eq!(
            compiled.scope().projections(),
            &HashMap::from([
                ("udp".to_string(), HashSet::new()),
                ("tcp".to_string(), HashSet::new())
            ])
        );
        assert!(compiled.outputs()[0].columns.is_empty());
    }

    #[test]
    fn timestamp_unit_applies_to_every_timestamp_column() {
        for (unit, kind) in [
            (TimestampUnit::Micros, ColKind::TsMicros),
            (TimestampUnit::Nanos, ColKind::TsNanos),
        ] {
            let plan = ScanPlan {
                tables: vec![scan("frames", &["frame_number", "timestamp"])],
                streams: vec![full("tcp_connections")],
                timestamps: unit,
                ..ScanPlan::default()
            };
            let compiled = compile(&plan).unwrap();
            assert_eq!(compiled.timestamps(), unit);
            let frames = &compiled.outputs()[0];
            assert_eq!(frames.columns[0].kind, ColKind::U64);
            assert_eq!(frames.columns[1].kind, kind);
            let stream = &compiled.stream_outputs()[0];
            let stamps: Vec<ColKind> = stream
                .columns
                .iter()
                .map(|c| c.kind)
                .filter(|k| k.is_timestamp())
                .collect();
            assert!(!stamps.is_empty());
            assert!(stamps.iter().all(|k| *k == kind), "{stamps:?}");
        }
    }

    /// The protocol tables' `timestamp` is not a default column, but a plan
    /// can select it; it is read from the packet, not from a parser field.
    #[test]
    fn the_opt_in_timestamp_column_is_selectable() {
        let (_, tcp) = catalog().table("tcp").unwrap();
        let (timestamp, def) = tcp.column("timestamp").unwrap();
        assert!(!def.default);
        assert!(!default_cols("tcp").contains(&timestamp));

        let plan = ScanPlan {
            tables: vec![scan("tcp", &["timestamp", "dst_port"])],
            timestamps: TimestampUnit::Nanos,
            ..ScanPlan::default()
        };
        let compiled = compile(&plan).unwrap();
        assert_eq!(
            compiled.outputs()[0].columns[0],
            OutColumn {
                name: "timestamp",
                kind: ColKind::TsNanos,
                nullable: false,
                source: ColumnSource::Timestamp,
            }
        );
        assert_eq!(
            compiled.scope().projections(),
            &HashMap::from([("tcp".to_string(), set(&["dst_port"]))])
        );

        // Every column, opt-in included, still reads every field: no
        // projection.
        let all: Vec<ColId> = tcp.columns().map(|(c, _)| c).collect();
        let plan = ScanPlan {
            tables: vec![TableScan::new(id("tcp"), all)],
            ..ScanPlan::default()
        };
        assert!(compile(&plan).unwrap().scope().projections().is_empty());
    }

    #[test]
    fn stream_tables_pin_one_partition_and_parse_tcp_in_full() {
        let plan = ScanPlan {
            tables: vec![
                scan("tcp", &["dst_port"]),
                scan("ipv4", &["ttl"]),
                scan("udp", &["dst_port"]),
            ],
            streams: vec![full("http_messages"), scan("tls_sessions", &[])],
            ..ScanPlan::default()
        };
        let registry = default_registry();
        let compiled = plan.compile(catalog(), &registry).unwrap();
        assert!(compiled.requires_single_partition());
        assert_eq!(compiled.outputs().len(), 3);
        let [http, tls] = compiled.stream_outputs() else {
            panic!("two stream outputs");
        };
        assert_eq!(http.table, Some(id("http_messages")));
        assert_eq!(
            catalog().get(id("http_messages")).kind,
            TableKind::Stream(StreamTable::HttpMessages)
        );
        assert_eq!(http.columns.len(), default_cols("http_messages").len());
        assert!(http
            .columns
            .iter()
            .all(|c| c.source == ColumnSource::Stream));
        assert!(tls.columns.is_empty());
        // The stream analysis reads tcp and the IP layers in full; other
        // tables keep their projection.
        assert_eq!(
            compiled.scope().projections(),
            &HashMap::from([("udp".to_string(), set(&["dst_port"]))])
        );
        assert_eq!(
            compiled.scope().required(),
            ParseScope::for_tables(&["tcp", "ipv4", "udp"], &registry).required()
        );

        // Stream tables alone still parse tcp and what it depends on.
        let plan = ScanPlan {
            streams: vec![full("tcp_connections")],
            ..ScanPlan::default()
        };
        let compiled = plan.compile(catalog(), &registry).unwrap();
        assert!(compiled.requires_single_partition());
        assert!(compiled.outputs().is_empty());
        assert_eq!(
            compiled.scope().required(),
            ParseScope::for_tables(&["tcp"], &registry).required()
        );
        assert!(compiled.scope().projections().is_empty());

        let plan = ScanPlan {
            tables: vec![full("tcp")],
            ..ScanPlan::default()
        };
        assert!(!compile(&plan).unwrap().requires_single_partition());
    }

    #[test]
    fn predicate_and_fetch_reach_the_output() {
        let (_, tcp) = catalog().table("tcp").unwrap();
        let dst_port = tcp.column("dst_port").unwrap().0;
        let frame_number = tcp.column("frame_number").unwrap().0;
        let plan = ScanPlan {
            tables: vec![
                TableScan {
                    predicate: Some(RowPredicate::cmp(dst_port, CmpOp::Eq, 443)),
                    fetch: Some(7),
                    ..scan("tcp", &["frame_number"])
                },
                TableScan {
                    // Cannot drop a row: no compiled predicate.
                    predicate: Some(RowPredicate::cmp(frame_number, CmpOp::Eq, 1)),
                    ..scan("udp", &["frame_number"])
                },
            ],
            ..ScanPlan::default()
        };
        let compiled = compile(&plan).unwrap();
        let [tcp_out, udp_out] = compiled.outputs() else {
            panic!("two outputs");
        };
        assert_eq!(tcp_out.fetch(), Some(7));
        assert!(tcp_out.predicate().is_some());
        assert!(udp_out.predicate().is_none());
        // The predicate's field is extracted although it is not an output
        // column; a predicate that cannot drop a row adds nothing.
        assert_eq!(
            compiled.scope().projections(),
            &HashMap::from([
                ("tcp".to_string(), set(&["dst_port"])),
                ("udp".to_string(), HashSet::new()),
            ])
        );
    }

    #[test]
    fn fused_scans_resolve_members_and_columns() {
        let frames = id("frames");
        let tcp = id("tcp");
        let ipv4 = id("ipv4");
        let col = |table: &str, name: &str| cols(table, &[name])[0];
        let plan = ScanPlan {
            tables: vec![scan("tcp", &["src_port"])],
            fused: vec![FusedScan {
                members: vec![
                    FusedMember {
                        table: frames,
                        join: None,
                    },
                    FusedMember {
                        table: tcp,
                        join: Some(MemberJoin {
                            kind: JoinKind::Inner,
                            with: 0,
                            depth: false,
                        }),
                    },
                    FusedMember {
                        table: ipv4,
                        join: Some(MemberJoin {
                            kind: JoinKind::Left,
                            with: 1,
                            depth: true,
                        }),
                    },
                ],
                columns: vec![
                    (0, col("frames", "timestamp")).into(),
                    (1, col("tcp", "dst_port")).into(),
                    (1, col("tcp", "encap_depth")).into(),
                    (2, col("ipv4", "encap_depth")).into(),
                    (2, col("ipv4", "ttl")).into(),
                ],
                filter: None,
                fetch: Some(3),
            }],
            ..ScanPlan::default()
        };
        let registry = default_registry();
        let compiled = plan.compile(catalog(), &registry).unwrap();
        let [_, fused] = compiled.outputs() else {
            panic!("a table and a fused output");
        };
        assert_eq!(fused.table, None);
        assert_eq!(fused.fetch(), Some(3));
        assert_eq!(
            fused
                .columns
                .iter()
                .map(|c| (c.name, c.nullable, c.source))
                .collect::<Vec<_>>(),
            vec![
                ("timestamp", false, ColumnSource::Timestamp),
                ("dst_port", true, ColumnSource::Field("dst_port")),
                ("encap_depth", false, ColumnSource::EncapDepth),
                // Left-joined: NULL when the frame has no such row.
                ("encap_depth", true, ColumnSource::EncapDepth),
                ("ttl", true, ColumnSource::Field("ttl")),
            ]
        );
        // The table scan's and the fused member's columns are united.
        assert_eq!(
            compiled.scope().projections(),
            &HashMap::from([
                ("tcp".to_string(), set(&["src_port", "dst_port"])),
                ("ipv4".to_string(), set(&["ttl"])),
            ])
        );
        assert_eq!(
            compiled.scope().required(),
            ParseScope::for_tables(&["tcp", "ipv4"], &registry).required()
        );
    }

    #[test]
    fn a_fused_member_without_columns_is_still_parsed() {
        let plan = ScanPlan {
            fused: vec![FusedScan {
                members: vec![
                    FusedMember {
                        table: id("frames"),
                        join: None,
                    },
                    FusedMember {
                        table: id("dns"),
                        join: Some(MemberJoin {
                            kind: JoinKind::Inner,
                            with: 0,
                            depth: false,
                        }),
                    },
                ],
                columns: vec![(0, cols("frames", &["frame_number"])[0]).into()],
                filter: None,
                fetch: None,
            }],
            ..ScanPlan::default()
        };
        let registry = default_registry();
        let compiled = plan.compile(catalog(), &registry).unwrap();
        assert_eq!(
            compiled.scope().required(),
            ParseScope::for_tables(&["dns"], &registry).required()
        );
        assert_eq!(
            compiled.scope().projections(),
            &HashMap::from([("dns".to_string(), HashSet::new())])
        );
    }

    #[test]
    fn unknown_tables_and_columns_are_errors() {
        let nowhere = TableId(u16::MAX);
        let bad_column = ColId(u16::MAX);
        let with = |f: &dyn Fn(&mut ScanPlan)| {
            let mut plan = ScanPlan::default();
            f(&mut plan);
            compile(&plan).unwrap_err()
        };

        assert_eq!(
            with(&|p| p.tables.push(TableScan::new(nowhere, vec![]))),
            PlanError::UnknownTable(nowhere)
        );
        assert_eq!(
            with(&|p| p.streams.push(TableScan::new(nowhere, vec![]))),
            PlanError::UnknownTable(nowhere)
        );
        assert_eq!(
            with(&|p| p.fused.push(FusedScan {
                members: vec![FusedMember {
                    table: nowhere,
                    join: None
                }],
                columns: vec![],
                filter: None,
                fetch: None,
            })),
            PlanError::UnknownTable(nowhere)
        );

        let unknown = |table| PlanError::UnknownColumn {
            table,
            column: bad_column,
        };
        assert_eq!(
            with(&|p| p.tables.push(TableScan::new(id("tcp"), vec![bad_column]))),
            unknown("tcp")
        );
        assert_eq!(
            with(&|p| p
                .streams
                .push(TableScan::new(id("tls_sessions"), vec![bad_column]))),
            unknown("tls_sessions")
        );
        assert_eq!(
            with(&|p| p.fused.push(FusedScan {
                members: vec![FusedMember {
                    table: id("udp"),
                    join: None
                }],
                columns: vec![(0, bad_column).into()],
                filter: None,
                fetch: None,
            })),
            unknown("udp")
        );
        assert_eq!(
            with(&|p| p.tables.push(TableScan {
                predicate: Some(RowPredicate::And(vec![RowPredicate::cmp(
                    bad_column,
                    CmpOp::Eq,
                    1
                )])),
                ..scan("tcp", &["dst_port"])
            })),
            unknown("tcp")
        );
        assert_eq!(
            unknown("tcp").to_string(),
            format!("table tcp has no column {}", u16::MAX)
        );
    }

    #[test]
    fn misplaced_and_repeated_tables_are_errors() {
        let with = |f: &dyn Fn(&mut ScanPlan)| {
            let mut plan = ScanPlan::default();
            f(&mut plan);
            compile(&plan).unwrap_err()
        };
        assert_eq!(
            with(&|p| p.tables.push(full("tcp_connections"))),
            PlanError::NotAPacketTable("tcp_connections")
        );
        assert_eq!(
            with(&|p| p.streams.push(full("tcp"))),
            PlanError::NotAStreamTable("tcp")
        );
        assert_eq!(
            with(&|p| p.streams.push(full("frames"))),
            PlanError::NotAStreamTable("frames")
        );
        assert_eq!(
            with(&|p| p.tables.extend([full("tcp"), scan("tcp", &[])])),
            PlanError::DuplicateTable("tcp")
        );
        assert_eq!(
            with(&|p| p.streams.extend([full("http2"), full("http2")])),
            PlanError::DuplicateTable("http2")
        );
        let (_, sessions) = catalog().table("tls_sessions").unwrap();
        let first = sessions.columns().next().unwrap().0;
        assert_eq!(
            with(&|p| p.streams.push(TableScan {
                predicate: Some(RowPredicate::cmp(first, CmpOp::Eq, 1)),
                ..full("tls_sessions")
            })),
            PlanError::StreamPredicate("tls_sessions")
        );
        // A frame predicate and stream tables do not go together, whatever
        // else the plan holds; either alone is fine.
        let bounded = FramePredicate {
            frames: (std::ops::Bound::Unbounded, std::ops::Bound::Included(10)),
            ..FramePredicate::all()
        };
        let timed = FramePredicate {
            time_ns: (std::ops::Bound::Excluded(0), std::ops::Bound::Unbounded),
            ..FramePredicate::all()
        };
        for frames in [&bounded, &timed] {
            assert_eq!(
                with(&|p| {
                    p.frames = frames.clone();
                    p.streams.push(full("tcp_connections"));
                }),
                PlanError::StreamFramePredicate
            );
            assert_eq!(
                with(&|p| {
                    p.frames = frames.clone();
                    p.tables.push(full("frames"));
                    p.streams.push(scan("tls_sessions", &[]));
                }),
                PlanError::StreamFramePredicate
            );
            let alone = ScanPlan {
                tables: vec![full("frames"), full("tcp")],
                frames: frames.clone(),
                ..Default::default()
            };
            let compiled = compile(&alone).unwrap();
            assert_eq!(compiled.frames(), frames);
            assert!(!compiled.requires_single_partition());
        }
        let streams = ScanPlan {
            tables: vec![full("frames")],
            streams: vec![full("tcp_connections")],
            ..Default::default()
        };
        assert!(compile(&streams).unwrap().frames().is_all());
        // The same table as a scan and as a fused member is fine.
        let plan = ScanPlan {
            tables: vec![full("tcp")],
            fused: vec![FusedScan {
                members: vec![FusedMember {
                    table: id("tcp"),
                    join: None,
                }],
                columns: vec![],
                filter: None,
                fetch: None,
            }],
            ..ScanPlan::default()
        };
        assert!(compile(&plan).is_ok());
    }

    #[test]
    fn malformed_fused_joins_are_errors() {
        let inner = |with| {
            Some(MemberJoin {
                kind: JoinKind::Inner,
                with,
                depth: false,
            })
        };
        let member = |table: &str, join| FusedMember {
            table: id(table),
            join,
        };
        let reason = |members: Vec<FusedMember>, columns: Vec<(u16, ColId)>| {
            let plan = ScanPlan {
                fused: vec![FusedScan {
                    members,
                    columns: columns.into_iter().map(Into::into).collect(),
                    filter: None,
                    fetch: None,
                }],
                ..ScanPlan::default()
            };
            match compile(&plan).unwrap_err() {
                PlanError::InvalidFused { fused: 0, reason } => reason,
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(reason(vec![], vec![]), "no members");
        assert_eq!(
            reason(vec![member("frames", inner(0))], vec![]),
            "the first member cannot have a join"
        );
        assert_eq!(
            reason(vec![member("frames", None), member("tcp", None)], vec![]),
            "a later member needs a join"
        );
        assert_eq!(
            reason(
                vec![member("frames", None), member("tcp", inner(1))],
                vec![]
            ),
            "a member can only join an earlier member"
        );
        assert_eq!(
            reason(vec![member("frames", None)], vec![(1, ColId(0))]),
            "a column names a member the join does not have"
        );

        let plan = ScanPlan {
            fused: vec![FusedScan {
                members: vec![member("frames", None), member("tls_sessions", inner(0))],
                columns: vec![],
                filter: None,
                fetch: None,
            }],
            ..ScanPlan::default()
        };
        assert_eq!(
            compile(&plan).unwrap_err(),
            PlanError::NotAPacketTable("tls_sessions")
        );
    }

    /// `frames`, `tcp` on the frame, `ipv4` and `ipv6` left-joined on the
    /// level of `tcp`.
    fn tcp_join(columns: Vec<FusedColumn>, filter: Option<FusedFilter>) -> ScanPlan {
        let join = |kind, with, depth| Some(MemberJoin { kind, with, depth });
        ScanPlan {
            fused: vec![FusedScan {
                members: vec![
                    FusedMember {
                        table: id("frames"),
                        join: None,
                    },
                    FusedMember {
                        table: id("tcp"),
                        join: join(JoinKind::Inner, 0, false),
                    },
                    FusedMember {
                        table: id("ipv4"),
                        join: join(JoinKind::Left, 1, true),
                    },
                    FusedMember {
                        table: id("ipv6"),
                        join: join(JoinKind::Left, 1, true),
                    },
                ],
                columns,
                filter,
                fetch: None,
            }],
            ..ScanPlan::default()
        }
    }

    #[test]
    fn computed_columns_of_a_fused_join_are_named_typed_and_parsed() {
        let col = |table: &str, name: &str| cols(table, &[name])[0];
        let plan = tcp_join(
            vec![
                FusedColumn {
                    name: Some("src_ip_v4"),
                    value: FusedValue::Column {
                        member: 2,
                        column: col("ipv4", "src_ip"),
                    },
                },
                FusedColumn {
                    name: Some("ttl"),
                    value: FusedValue::Coalesce(vec![
                        (2, col("ipv4", "ttl")),
                        (3, col("ipv6", "hop_limit")),
                    ]),
                },
                FusedColumn {
                    name: Some("family"),
                    value: FusedValue::Present {
                        cases: vec![(2, "v4"), (3, "v6")],
                        otherwise: "none",
                    },
                },
                (1, col("tcp", "encap_depth")).into(),
            ],
            Some(FusedFilter {
                member: 1,
                column: col("tcp", "dst_port"),
                any_of: vec![80, 443],
            }),
        );
        let compiled = compile(&plan).unwrap();
        let columns: Vec<_> = compiled.outputs()[0]
            .columns
            .iter()
            .map(|c| (c.name, c.kind, c.nullable, c.source))
            .collect();
        assert_eq!(
            columns,
            [
                (
                    "src_ip_v4",
                    ColKind::U32,
                    true,
                    ColumnSource::Field("src_ip")
                ),
                ("ttl", ColKind::U8, true, ColumnSource::Computed),
                ("family", ColKind::Str, false, ColumnSource::Computed),
                ("encap_depth", ColKind::U8, false, ColumnSource::EncapDepth),
            ]
        );
        // Every argument of a computed column, and the filter's column, is
        // extracted.
        let projections = compiled.scope().projections();
        let fields = |protocol: &str| {
            let mut fields: Vec<&str> = projections[protocol].iter().map(String::as_str).collect();
            fields.sort_unstable();
            fields
        };
        assert_eq!(fields("ipv4"), ["src_ip", "ttl"]);
        assert_eq!(fields("ipv6"), ["hop_limit"]);
        assert_eq!(fields("tcp"), ["dst_port"]);
    }

    #[test]
    fn malformed_computed_columns_and_filters_are_errors() {
        let col = |table: &str, name: &str| cols(table, &[name])[0];
        let reason = |plan: ScanPlan| match compile(&plan).unwrap_err() {
            PlanError::InvalidFused { fused: 0, reason } => reason,
            other => panic!("{other:?}"),
        };
        let computed = |name, value| tcp_join(vec![FusedColumn { name, value }], None);
        assert_eq!(
            reason(computed(Some("x"), FusedValue::Coalesce(vec![]))),
            "a COALESCE without arguments"
        );
        assert_eq!(
            reason(computed(
                Some("x"),
                FusedValue::Coalesce(vec![(2, col("ipv4", "ttl")), (1, col("tcp", "dst_port"))])
            )),
            "the arguments of a COALESCE differ in kind"
        );
        assert_eq!(
            reason(computed(
                None,
                FusedValue::Coalesce(vec![(2, col("ipv4", "ttl"))])
            )),
            "a computed column needs a name"
        );
        assert_eq!(
            reason(computed(
                Some("x"),
                FusedValue::Present {
                    cases: vec![(4, "no such member")],
                    otherwise: "",
                }
            )),
            "a column names a member the join does not have"
        );
        assert_eq!(
            reason(computed(
                Some("x"),
                FusedValue::Coalesce(vec![(9, col("ipv4", "ttl"))])
            )),
            "a column names a member the join does not have"
        );

        let filtered = |member, column| {
            tcp_join(
                vec![],
                Some(FusedFilter {
                    member,
                    column,
                    any_of: vec![1],
                }),
            )
        };
        assert_eq!(
            reason(filtered(1, col("tcp", "encap_depth"))),
            "the filter is not on a parser field"
        );
        assert_eq!(
            reason(filtered(0, col("frames", "frame_number"))),
            "the filter is not on a parser field"
        );
        assert_eq!(
            reason(filtered(3, col("ipv6", "src_ip"))),
            "the filter is not on an integer column"
        );
        assert_eq!(
            reason(filtered(7, col("tcp", "dst_port"))),
            "a column names a member the join does not have"
        );
        assert!(compile(&filtered(1, col("tcp", "dst_port"))).is_ok());
    }
}
