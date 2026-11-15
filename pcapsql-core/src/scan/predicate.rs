//! Predicates a scan can apply itself.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! Two kinds, and the type says which one a predicate is:
//!
//! - [`RowPredicate`] is **conservative**. It is evaluated against one parsed
//!   layer before the row is built and may drop the row only when a
//!   comparison is positively false. Anything it cannot decide (an absent
//!   field, a value it cannot compare with the literal, a column that has no
//!   per-layer source) keeps the row, so the engine must apply the original
//!   filter again. Applying it never changes a result; it only saves
//!   building rows.
//! - [`FramePredicate`] is **exact**. It bounds the frame number and the
//!   packet timestamp, both known before a packet is parsed, and a scan that
//!   applies it returns exactly the matching frames.

use std::ops::Bound;

use super::catalog::{ColId, ColumnSource, TableDef};
use crate::io::{PacketRange, PacketRef};
use crate::{FieldHint, FieldValue, LayerRef};

/// A comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CmpOp {
    /// `=`
    Eq,
    /// `<>`
    NotEq,
    /// `<`
    Lt,
    /// `<=`
    LtEq,
    /// `>`
    Gt,
    /// `>=`
    GtEq,
}

impl CmpOp {
    /// The operator with its operands swapped: `a < b` is `b > a`. A
    /// frontend uses it to turn `literal <op> column` into
    /// `column <op> literal`.
    pub const fn swapped(self) -> Self {
        match self {
            CmpOp::Lt => CmpOp::Gt,
            CmpOp::LtEq => CmpOp::GtEq,
            CmpOp::Gt => CmpOp::Lt,
            CmpOp::GtEq => CmpOp::LtEq,
            CmpOp::Eq | CmpOp::NotEq => self,
        }
    }

    #[inline]
    fn holds<T: PartialOrd + ?Sized>(self, left: &T, right: &T) -> bool {
        match self {
            CmpOp::Eq => left == right,
            CmpOp::NotEq => left != right,
            CmpOp::Lt => left < right,
            CmpOp::LtEq => left <= right,
            CmpOp::Gt => left > right,
            CmpOp::GtEq => left >= right,
        }
    }
}

/// The constant side of a comparison.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Literal {
    /// An integer. Compared with integer and boolean values, and with an
    /// IPv4 address as the `u32` its column stores.
    Int(i64),
    /// A string. Compared with string values only.
    Str(Box<str>),
}

impl From<i64> for Literal {
    fn from(value: i64) -> Self {
        Literal::Int(value)
    }
}

impl From<&str> for Literal {
    fn from(value: &str) -> Self {
        Literal::Str(value.into())
    }
}

/// A conservative predicate on the columns of one table (the top of
/// `scan/predicate.rs` says what that means for a frontend).
///
/// A column is compared through the value of its
/// [source](ColumnSource) in the row's own layer:
///
/// | Source | [`Literal::Int`] | [`Literal::Str`] |
/// |---|---|---|
/// | [`Field`](ColumnSource::Field) | an integer or boolean value, or an IPv4 address as `u32`; a `u64` above `i64::MAX` is undecided | a string value |
/// | [`EncapDepth`](ColumnSource::EncapDepth) | the depth | undecided |
/// | [`TunnelType`](ColumnSource::TunnelType) | undecided | the tunnel's name; undecided outside a tunnel |
/// | [`TunnelId`](ColumnSource::TunnelId) | the id, when there is one and it fits `i64` | undecided |
/// | any other | undecided | undecided |
///
/// "Undecided" keeps the row, as does an absent field or a value of any
/// other type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RowPredicate {
    /// `column <op> value`.
    Cmp {
        /// A column of the table the predicate is for.
        column: ColId,
        /// The comparison.
        op: CmpOp,
        /// What the column is compared with.
        value: Literal,
    },
    /// Every one of these holds. An empty list keeps every row.
    And(Vec<RowPredicate>),
}

impl RowPredicate {
    /// `column <op> value`.
    pub fn cmp(column: ColId, op: CmpOp, value: impl Into<Literal>) -> Self {
        RowPredicate::Cmp {
            column,
            op,
            value: value.into(),
        }
    }

    /// Call `f` with every column the predicate names.
    pub fn for_each_column(&self, f: &mut impl FnMut(ColId)) {
        match self {
            RowPredicate::Cmp { column, .. } => f(*column),
            RowPredicate::And(all) => all.iter().for_each(|p| p.for_each_column(f)),
        }
    }

    /// Resolve the predicate against the table it is for.
    ///
    /// Comparisons that can never drop a row are left out: those on a column
    /// with no per-layer source, those whose literal the column's source is
    /// never compared with, and those naming a column `table` does not have.
    /// `None` when nothing is left, i.e. the predicate keeps every row.
    pub fn compile(&self, table: &TableDef) -> Option<CompiledPredicate> {
        let mut terms = Vec::new();
        self.collect_terms(table, &mut terms);
        (!terms.is_empty()).then_some(CompiledPredicate { terms })
    }

    fn collect_terms(&self, table: &TableDef, terms: &mut Vec<Term>) {
        match self {
            RowPredicate::Cmp { column, op, value } => {
                let Some(def) = table.columns.get(usize::from(column.0)) else {
                    return;
                };
                let operand = match (def.source, value) {
                    (ColumnSource::Field(name), _) => Operand::Field(name, FieldHint::default()),
                    (ColumnSource::EncapDepth, Literal::Int(_)) => Operand::EncapDepth,
                    (ColumnSource::TunnelId, Literal::Int(_)) => Operand::TunnelId,
                    (ColumnSource::TunnelType, Literal::Str(_)) => Operand::TunnelType,
                    _ => return,
                };
                terms.push(Term {
                    operand,
                    op: *op,
                    value: value.clone(),
                });
            }
            RowPredicate::And(all) => all.iter().for_each(|p| p.collect_terms(table, terms)),
        }
    }
}

/// What a term reads from the layer.
#[derive(Clone, Debug)]
enum Operand {
    /// A parser field, with where it was found in the previous row.
    Field(&'static str, FieldHint),
    EncapDepth,
    TunnelType,
    TunnelId,
}

/// One comparison of a [`CompiledPredicate`].
#[derive(Clone, Debug)]
struct Term {
    operand: Operand,
    op: CmpOp,
    value: Literal,
}

/// A [`RowPredicate`] resolved against its table: a flat conjunction of
/// comparisons, each knowing where its value comes from.
///
/// It remembers where each field was found in the previous row, so one
/// instance serves one stream of rows of one table; clone it per partition.
#[derive(Clone, Debug)]
pub struct CompiledPredicate {
    terms: Vec<Term>,
}

impl CompiledPredicate {
    /// Whether the row of `layer` is kept: `false` only when a comparison is
    /// positively false.
    #[inline]
    pub fn keeps(&mut self, layer: LayerRef<'_, '_>) -> bool {
        self.terms.iter_mut().all(|term| term.keeps(layer))
    }
}

impl Term {
    #[inline]
    fn keeps(&mut self, layer: LayerRef<'_, '_>) -> bool {
        match &self.value {
            Literal::Int(literal) => {
                let value = match &mut self.operand {
                    Operand::Field(name, hint) => {
                        layer.get_hinted(name, hint).and_then(field_as_i64)
                    }
                    Operand::EncapDepth => Some(i64::from(layer.encap_depth())),
                    Operand::TunnelId => layer.tunnel_id().and_then(|id| i64::try_from(id).ok()),
                    Operand::TunnelType => None,
                };
                value.is_none_or(|v| self.op.holds(&v, literal))
            }
            Literal::Str(literal) => {
                let value = match &mut self.operand {
                    Operand::Field(name, hint) => {
                        layer.get_hinted(name, hint).and_then(field_as_str)
                    }
                    Operand::TunnelType => layer.tunnel_type().as_str(),
                    Operand::EncapDepth | Operand::TunnelId => None,
                };
                value.is_none_or(|v| self.op.holds(v, literal.as_ref()))
            }
        }
    }
}

/// A field value as the integer its column stores. An IPv4 address is its
/// `u32`. `None` for anything not confidently an integer (the row is kept).
fn field_as_i64(value: &FieldValue<'_>) -> Option<i64> {
    match value {
        FieldValue::UInt8(v) => Some(i64::from(*v)),
        FieldValue::UInt16(v) => Some(i64::from(*v)),
        FieldValue::UInt32(v) => Some(i64::from(*v)),
        FieldValue::UInt64(v) => i64::try_from(*v).ok(),
        FieldValue::Int64(v) => Some(*v),
        FieldValue::Int8(v) => Some(i64::from(*v)),
        FieldValue::Bool(v) => Some(i64::from(*v)),
        FieldValue::IpAddr(std::net::IpAddr::V4(v4)) => Some(i64::from(u32::from(*v4))),
        _ => None,
    }
}

/// A field value as a string, only when it is one.
fn field_as_str<'v>(value: &'v FieldValue<'_>) -> Option<&'v str> {
    match value {
        FieldValue::Str(s) => Some(s),
        FieldValue::OwnedString(s) => Some(s.as_str()),
        _ => None,
    }
}

/// An exact predicate on packet metadata: a range of frame numbers and a
/// range of timestamps, both of which must hold.
///
/// Frame numbers ascend through a capture, so the frame bounds also say
/// where a scan can start and stop ([`past_end`](Self::past_end),
/// [`may_overlap`](Self::may_overlap)). Timestamps are not assumed to
/// ascend: the time bounds select packets but never end a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramePredicate {
    /// Bounds on [`PacketRef::frame_number`] (1-based).
    pub frames: (Bound<u64>, Bound<u64>),
    /// Bounds on [`PacketRef::timestamp_ns`], nanoseconds since the Unix
    /// epoch.
    pub time_ns: (Bound<i64>, Bound<i64>),
}

impl Default for FramePredicate {
    fn default() -> Self {
        Self::all()
    }
}

/// `value` satisfies the lower bound.
#[inline]
fn above<T: PartialOrd>(lower: &Bound<T>, value: &T) -> bool {
    match lower {
        Bound::Unbounded => true,
        Bound::Included(b) => value >= b,
        Bound::Excluded(b) => value > b,
    }
}

/// `value` satisfies the upper bound.
#[inline]
fn below<T: PartialOrd>(upper: &Bound<T>, value: &T) -> bool {
    match upper {
        Bound::Unbounded => true,
        Bound::Included(b) => value <= b,
        Bound::Excluded(b) => value < b,
    }
}

/// The range of the values `v` with `v <op> constant`. `None` for `<>`,
/// whose values are not a range.
fn range_of<T: Copy>(op: CmpOp, constant: T) -> Option<(Bound<T>, Bound<T>)> {
    Some(match op {
        CmpOp::Eq => (Bound::Included(constant), Bound::Included(constant)),
        CmpOp::Lt => (Bound::Unbounded, Bound::Excluded(constant)),
        CmpOp::LtEq => (Bound::Unbounded, Bound::Included(constant)),
        CmpOp::Gt => (Bound::Excluded(constant), Bound::Unbounded),
        CmpOp::GtEq => (Bound::Included(constant), Bound::Unbounded),
        CmpOp::NotEq => return None,
    })
}

/// The tighter of two lower bounds.
fn tighter_lower<T: Copy + Ord>(a: Bound<T>, b: Bound<T>) -> Bound<T> {
    match (a, b) {
        (Bound::Unbounded, other) | (other, Bound::Unbounded) => other,
        (Bound::Included(x), Bound::Included(y)) => Bound::Included(x.max(y)),
        (Bound::Excluded(x), Bound::Excluded(y)) => Bound::Excluded(x.max(y)),
        // `> x` is tighter than `>= x`.
        (Bound::Included(i), Bound::Excluded(e)) | (Bound::Excluded(e), Bound::Included(i)) => {
            if i > e {
                Bound::Included(i)
            } else {
                Bound::Excluded(e)
            }
        }
    }
}

/// The tighter of two upper bounds.
fn tighter_upper<T: Copy + Ord>(a: Bound<T>, b: Bound<T>) -> Bound<T> {
    match (a, b) {
        (Bound::Unbounded, other) | (other, Bound::Unbounded) => other,
        (Bound::Included(x), Bound::Included(y)) => Bound::Included(x.min(y)),
        (Bound::Excluded(x), Bound::Excluded(y)) => Bound::Excluded(x.min(y)),
        // `< x` is tighter than `<= x`.
        (Bound::Included(i), Bound::Excluded(e)) | (Bound::Excluded(e), Bound::Included(i)) => {
            if i < e {
                Bound::Included(i)
            } else {
                Bound::Excluded(e)
            }
        }
    }
}

impl FramePredicate {
    /// Every packet.
    pub const fn all() -> Self {
        Self {
            frames: (Bound::Unbounded, Bound::Unbounded),
            time_ns: (Bound::Unbounded, Bound::Unbounded),
        }
    }

    /// No packet: a predicate that [is empty](Self::is_empty).
    pub const fn none() -> Self {
        Self {
            frames: (Bound::Included(1), Bound::Included(0)),
            time_ns: (Bound::Unbounded, Bound::Unbounded),
        }
    }

    /// The packets whose frame number `n` satisfies `n <op> constant`, at
    /// any time. `None` for `<>`, which is not a range.
    pub fn frame_number(op: CmpOp, constant: u64) -> Option<Self> {
        Some(Self {
            frames: range_of(op, constant)?,
            ..Self::all()
        })
    }

    /// The packets whose timestamp `t`, in nanoseconds since the Unix
    /// epoch, satisfies `t <op> constant`, whatever their frame number.
    /// `None` for `<>`, which is not a range.
    pub fn timestamp_ns(op: CmpOp, constant: i64) -> Option<Self> {
        Some(Self {
            time_ns: range_of(op, constant)?,
            ..Self::all()
        })
    }

    /// The predicate that accepts exactly the packets both `self` and
    /// `other` accept: per range, the tighter of each pair of bounds.
    /// Intersecting is commutative and idempotent.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            frames: (
                tighter_lower(self.frames.0, other.frames.0),
                tighter_upper(self.frames.1, other.frames.1),
            ),
            time_ns: (
                tighter_lower(self.time_ns.0, other.time_ns.0),
                tighter_upper(self.time_ns.1, other.time_ns.1),
            ),
        }
    }

    /// True when no bound is set, so every packet is accepted.
    pub const fn is_all(&self) -> bool {
        matches!(
            (&self.frames, &self.time_ns),
            (
                (Bound::Unbounded, Bound::Unbounded),
                (Bound::Unbounded, Bound::Unbounded)
            )
        )
    }

    /// True when no packet at all can match: a range is inverted or holds
    /// no integer (`> 3 AND < 4`), or the frame range ends before frame 1.
    /// A scan with such a predicate reads nothing.
    pub fn is_empty(&self) -> bool {
        fn empty<T: Copy + Ord>(
            (lower, upper): &(Bound<T>, Bound<T>),
            up: impl Fn(T) -> Option<T>,
            down: impl Fn(T) -> Option<T>,
        ) -> bool {
            // The smallest and the largest value inside the bounds.
            let lowest = match *lower {
                Bound::Unbounded => None,
                Bound::Included(b) => Some(b),
                Bound::Excluded(b) => match up(b) {
                    Some(next) => Some(next),
                    None => return true,
                },
            };
            let highest = match *upper {
                Bound::Unbounded => None,
                Bound::Included(b) => Some(b),
                Bound::Excluded(b) => match down(b) {
                    Some(previous) => Some(previous),
                    None => return true,
                },
            };
            matches!((lowest, highest), (Some(lowest), Some(highest)) if lowest > highest)
        }
        self.past_end(1)
            || empty(&self.frames, |b| b.checked_add(1), |b| b.checked_sub(1))
            || empty(&self.time_ns, |b| b.checked_add(1), |b| b.checked_sub(1))
    }

    /// Whether `packet` matches.
    #[inline]
    pub fn accepts(&self, packet: &PacketRef<'_>) -> bool {
        above(&self.frames.0, &packet.frame_number)
            && below(&self.frames.1, &packet.frame_number)
            && above(&self.time_ns.0, &packet.timestamp_ns)
            && below(&self.time_ns.1, &packet.timestamp_ns)
    }

    /// True when neither the frame `frame_number` nor any later one can
    /// match, so a scan in frame order can end here. Decided by the upper
    /// frame bound alone.
    #[inline]
    pub fn past_end(&self, frame_number: u64) -> bool {
        !below(&self.frames.1, &frame_number)
    }

    /// Whether any packet of `range` can match. `time_ns` is the smallest
    /// and largest timestamp of the range's packets when the caller knows
    /// them (from an index), `None` otherwise. `false` is exact: no packet
    /// of the range matches. `true` promises nothing.
    pub fn may_overlap(&self, range: &PacketRange, time_ns: Option<(i64, i64)>) -> bool {
        // The range holds the frames `first ..= last` (`last` unknown when
        // the range runs to the end of the capture).
        let first = range.start.frame_number;
        if !below(&self.frames.1, &first) {
            return false;
        }
        if let Some(end) = &range.end {
            if end.frame_number <= first {
                return false; // an empty range
            }
            if !above(&self.frames.0, &(end.frame_number - 1)) {
                return false;
            }
        }
        if let Some((min, max)) = time_ns {
            if !below(&self.time_ns.1, &min) || !above(&self.time_ns.0, &max) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests;
