//! Fused joins: the joined rows of a frame, from the frame's own layers.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! Every table of a pass is produced from the same parsed frame, so a join
//! of those tables on `frame_number` (and `encap_depth`) can be evaluated
//! per frame, over the handful of rows the frame has in each table, instead
//! of by a join operator over the tables. A [`FusedScan`](super::FusedScan)
//! describes such a join; this module evaluates it. The result is exactly
//! the SQL join: inner and left joins, every match, NULLs for a left-joined
//! member without one.
//!
//! [`FusedState::join`] finds the frame's joined rows (not generic: it only
//! compares layer names and depths) and [`FusedState::write_row`] writes one
//! of them to a sink (generic over the sink and inlined into the router,
//! like the writers of `row.rs`, whose cells it uses).

use std::ops::ControlFlow;
use std::sync::Arc;

use super::catalog::ColKind;
use super::plan::{JoinKind, MemberJoin, OutCol, OutColumn};
use super::row::Cell;
use super::sink::{Full, ListSink, RowSink};
use crate::io::PacketRef;
use crate::PacketLayers;

/// A member's row in a joined row: an index into the frame's parsed layers,
/// or one of two markers.
type RowRef = usize;
/// The `frames` table: the packet itself.
const FRAME: RowRef = usize::MAX;
/// A left join that found no row.
const NULL: RowRef = usize::MAX - 1;

/// One member of a compiled fused join.
#[derive(Clone, Debug)]
pub(crate) struct FusedMemberPlan {
    /// The name of the layers that are this member's rows; `None` for
    /// `frames`, whose one row is the packet.
    pub(crate) layer: Option<&'static str>,
    /// `None` for the root.
    pub(crate) join: Option<MemberJoin>,
}

/// How one output column of a fused join is filled.
#[derive(Clone, Debug)]
pub(crate) enum FusedCell {
    /// A column of a member.
    Column { member: usize, cell: Cell },
    /// The first of these that is not NULL.
    Coalesce(Box<[(usize, Cell)]>),
    /// The label of the first member that has a row.
    Present {
        cases: Box<[(usize, &'static str)]>,
        otherwise: &'static str,
    },
}

impl FusedCell {
    pub(crate) fn column(member: usize, column: &OutColumn) -> Self {
        FusedCell::Column {
            member,
            cell: Cell::new(column),
        }
    }

    pub(crate) fn coalesce(columns: &[(usize, OutColumn)]) -> Self {
        FusedCell::Coalesce(
            columns
                .iter()
                .map(|(member, column)| (*member, Cell::new(column)))
                .collect(),
        )
    }

    pub(crate) fn present(cases: Box<[(usize, &'static str)]>, otherwise: &'static str) -> Self {
        FusedCell::Present { cases, otherwise }
    }
}

/// The exact filter of a fused join: the member's field, as the integer its
/// column would hold, is one of `any_of`.
#[derive(Clone, Debug)]
pub(crate) struct FusedFilterPlan {
    member: usize,
    cell: Cell,
    any_of: Box<[i64]>,
}

impl FusedFilterPlan {
    pub(crate) fn new(member: usize, field: &'static str, kind: ColKind, any_of: &[i64]) -> Self {
        Self {
            member,
            cell: Cell::field(field, kind),
            any_of: any_of.into(),
        }
    }
}

/// A fused join resolved for the packet loop.
#[derive(Clone, Debug)]
pub(crate) struct FusedPlan {
    pub(crate) members: Box<[FusedMemberPlan]>,
    pub(crate) cells: Box<[FusedCell]>,
    pub(crate) filter: Option<FusedFilterPlan>,
}

/// The state of one fused output within a partition: the join's plan, the
/// per-column lookup state, and scratch space reused across frames.
#[derive(Debug)]
pub(crate) struct FusedState {
    plan: Arc<FusedPlan>,
    /// The plan's cells, with this partition's field hints.
    cells: Box<[FusedCell]>,
    filter: Option<FusedFilterPlan>,
    /// Each member's rows for the current frame.
    member_rows: Vec<Vec<RowRef>>,
    /// The frame's joined rows: one slot per member, flat.
    tuples: Vec<RowRef>,
    next: Vec<RowRef>,
}

impl FusedState {
    pub(crate) fn new(plan: &Arc<FusedPlan>) -> Self {
        Self {
            plan: Arc::clone(plan),
            cells: plan.cells.clone(),
            filter: plan.filter.clone(),
            member_rows: vec![Vec::new(); plan.members.len()],
            tuples: Vec::new(),
            next: Vec::new(),
        }
    }

    /// Evaluate the join over one frame's `layers`. Returns the number of
    /// joined rows, before the filter; they are numbered from 0 in output
    /// order, and the same frame always gives the same rows.
    pub(crate) fn join(&mut self, layers: &PacketLayers<'_, '_>) -> usize {
        let members = &self.plan.members;
        let depth = |row: RowRef| -> Option<u8> {
            if row == FRAME {
                None
            } else {
                layers.get(row).map(|layer| layer.encap_depth())
            }
        };
        // Each member's rows for this frame.
        for (member, rows) in members.iter().zip(self.member_rows.iter_mut()) {
            rows.clear();
            match member.layer {
                None => rows.push(FRAME),
                Some(table) => rows.extend(
                    layers
                        .names()
                        .enumerate()
                        .filter(|(_, name)| *name == table)
                        .map(|(index, _)| index),
                ),
            }
        }
        // The join, member by member: a tuple per joined row, one slot per
        // member joined so far, flat in `tuples`.
        self.tuples.clear();
        self.tuples.extend_from_slice(&self.member_rows[0]);
        for (width, member) in members.iter().enumerate().skip(1) {
            if self.tuples.is_empty() {
                break;
            }
            let join = member.join.expect("a non-root member has a join");
            self.next.clear();
            for tuple in self.tuples.chunks_exact(width) {
                let anchor = tuple[join.with];
                let mut any = false;
                if anchor != NULL {
                    // A NULL key never equals anything.
                    for &candidate in &self.member_rows[width] {
                        if !join.depth || depth(anchor) == depth(candidate) {
                            any = true;
                            self.next.extend_from_slice(tuple);
                            self.next.push(candidate);
                        }
                    }
                }
                if !any && join.kind == JoinKind::Left {
                    self.next.extend_from_slice(tuple);
                    self.next.push(NULL);
                }
            }
            std::mem::swap(&mut self.tuples, &mut self.next);
        }
        if self.tuples.is_empty() {
            0
        } else {
            self.tuples.len() / members.len()
        }
    }

    /// Whether the filter keeps joined row `row` of the frame last given to
    /// [`join`](Self::join).
    #[inline]
    pub(crate) fn keeps(
        &mut self,
        row: usize,
        packet: &PacketRef<'_>,
        layers: &PacketLayers<'_, '_>,
    ) -> bool {
        let Some(filter) = &mut self.filter else {
            return true;
        };
        let width = self.plan.members.len();
        let slot = self.tuples[row * width + filter.member];
        let mut probe = Probe::default();
        write_slot(
            &mut filter.cell,
            &mut probe,
            OutCol(0),
            slot,
            packet,
            layers,
        );
        match probe.integer {
            Some(value) => filter.any_of.iter().any(|v| i128::from(*v) == value),
            None => false,
        }
    }

    /// Write joined row `row` of the frame last given to
    /// [`join`](Self::join). Returns [`RowSink::end_row`]'s answer.
    #[inline]
    pub(crate) fn write_row<S: RowSink>(
        &mut self,
        sink: &mut S,
        row: usize,
        packet: &PacketRef<'_>,
        layers: &PacketLayers<'_, '_>,
    ) -> ControlFlow<Full> {
        let width = self.plan.members.len();
        let tuple = &self.tuples[row * width..(row + 1) * width];
        for (index, cell) in self.cells.iter_mut().enumerate() {
            let col = OutCol(index as u16);
            match cell {
                FusedCell::Column { member, cell } => {
                    write_slot(cell, sink, col, tuple[*member], packet, layers);
                }
                FusedCell::Coalesce(arguments) => {
                    let mut written = false;
                    for (member, cell) in arguments.iter_mut() {
                        let slot = tuple[*member];
                        // What the argument's column holds is decided by
                        // the one writer every column goes through.
                        let mut probe = Probe::default();
                        write_slot(cell, &mut probe, col, slot, packet, layers);
                        if !probe.null {
                            write_slot(cell, sink, col, slot, packet, layers);
                            written = true;
                            break;
                        }
                    }
                    if !written {
                        sink.null(col);
                    }
                }
                FusedCell::Present { cases, otherwise } => {
                    let label = cases
                        .iter()
                        .find(|(member, _)| tuple[*member] != NULL)
                        .map_or(*otherwise, |(_, label)| *label);
                    sink.str(col, label);
                }
            }
        }
        sink.end_row()
    }
}

/// Write a member column's cell of a joined row in which the member's row
/// is `slot`.
#[inline]
fn write_slot<S: RowSink>(
    cell: &mut Cell,
    sink: &mut S,
    col: OutCol,
    slot: RowRef,
    packet: &PacketRef<'_>,
    layers: &PacketLayers<'_, '_>,
) {
    match slot {
        NULL => sink.null(col),
        FRAME => cell.write_frame(sink, col, packet),
        row => match layers.get(row) {
            Some(layer) => cell.write_layer(sink, col, packet, layer),
            None => sink.null(col),
        },
    }
}

/// A sink that stores nothing and notes what one cell would hold: whether
/// it is NULL and, for an integer, its value.
#[derive(Default)]
struct Probe {
    null: bool,
    integer: Option<i128>,
}

impl RowSink for Probe {
    #[inline(always)]
    fn null(&mut self, _: OutCol) {
        self.null = true;
    }
    #[inline(always)]
    fn bool(&mut self, _: OutCol, _: bool) {}
    #[inline(always)]
    fn u8(&mut self, _: OutCol, v: u8) {
        self.integer = Some(i128::from(v));
    }
    #[inline(always)]
    fn u16(&mut self, _: OutCol, v: u16) {
        self.integer = Some(i128::from(v));
    }
    #[inline(always)]
    fn u32(&mut self, _: OutCol, v: u32) {
        self.integer = Some(i128::from(v));
    }
    #[inline(always)]
    fn u64(&mut self, _: OutCol, v: u64) {
        self.integer = Some(i128::from(v));
    }
    #[inline(always)]
    fn i8(&mut self, _: OutCol, v: i8) {
        self.integer = Some(i128::from(v));
    }
    #[inline(always)]
    fn i64(&mut self, _: OutCol, v: i64) {
        self.integer = Some(i128::from(v));
    }
    #[inline(always)]
    fn f64(&mut self, _: OutCol, _: f64) {}
    #[inline(always)]
    fn str(&mut self, _: OutCol, _: &str) {}
    #[inline(always)]
    fn bytes(&mut self, _: OutCol, _: &[u8]) {}
    #[inline(always)]
    fn timestamp(&mut self, _: OutCol, _: i64) {}

    type List<'s> = Discard;

    #[inline(always)]
    fn list(&mut self, _: OutCol) -> Discard {
        Discard
    }

    #[inline(always)]
    fn end_row(&mut self) -> ControlFlow<Full> {
        ControlFlow::Continue(())
    }
}

/// The list writer of a [`Probe`].
struct Discard;

impl ListSink for Discard {
    #[inline(always)]
    fn null(&mut self) {}
    #[inline(always)]
    fn u16(&mut self, _: u16) {}
    #[inline(always)]
    fn u32(&mut self, _: u32) {}
    #[inline(always)]
    fn str(&mut self, _: &str) {}
    #[inline(always)]
    fn bytes(&mut self, _: &[u8]) {}
    #[inline(always)]
    fn finish(self) {}
}
