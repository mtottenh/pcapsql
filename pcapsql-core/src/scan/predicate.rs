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
use crate::{FieldHint, FieldValue, ParseResult};

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

/// A conservative predicate on the columns of one table (see the
/// [module](self) documentation).
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
    pub fn keeps(&mut self, layer: &ParseResult<'_>) -> bool {
        self.terms.iter_mut().all(|term| term.keeps(layer))
    }
}

impl Term {
    #[inline]
    fn keeps(&mut self, layer: &ParseResult<'_>) -> bool {
        match &self.value {
            Literal::Int(literal) => {
                let value = match &mut self.operand {
                    Operand::Field(name, hint) => {
                        layer.get_hinted(name, hint).and_then(field_as_i64)
                    }
                    Operand::EncapDepth => Some(i64::from(layer.encap_depth)),
                    Operand::TunnelId => layer.tunnel_id.and_then(|id| i64::try_from(id).ok()),
                    Operand::TunnelType => None,
                };
                value.is_none_or(|v| self.op.holds(&v, literal))
            }
            Literal::Str(literal) => {
                let value = match &mut self.operand {
                    Operand::Field(name, hint) => {
                        layer.get_hinted(name, hint).and_then(field_as_str)
                    }
                    Operand::TunnelType => layer.tunnel_type.as_str(),
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
mod tests {
    use super::*;
    use crate::io::PacketPosition;
    use crate::scan::Catalog;
    use crate::TunnelType;
    use smallvec::SmallVec;
    use std::net::{IpAddr, Ipv4Addr};

    fn layer(fields: Vec<(&'static str, FieldValue<'static>)>) -> ParseResult<'static> {
        ParseResult {
            fields: SmallVec::from_vec(fields),
            remaining: &[],
            child_hints: crate::protocol::Hints::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    fn tcp_layer() -> ParseResult<'static> {
        layer(vec![
            ("src_port", FieldValue::UInt16(12345)),
            ("dst_port", FieldValue::UInt16(80)),
            ("flags", FieldValue::UInt16(0x02)),
        ])
    }

    fn ipv4_layer() -> ParseResult<'static> {
        layer(vec![
            (
                "src_ip",
                FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            ),
            ("ttl", FieldValue::UInt8(64)),
        ])
    }

    fn table(name: &str) -> &'static TableDef {
        Catalog::builtin().table(name).expect("table").1
    }

    fn col(table: &TableDef, name: &str) -> ColId {
        table.column(name).expect("column").0
    }

    /// `column <op> value` on `table`, compiled.
    fn compiled(
        table: &TableDef,
        column: &str,
        op: CmpOp,
        value: impl Into<Literal>,
    ) -> Option<CompiledPredicate> {
        RowPredicate::cmp(col(table, column), op, value).compile(table)
    }

    #[test]
    fn int_compare_keeps_and_drops() {
        let tcp = table("tcp");
        let row = tcp_layer();
        let mut keep = compiled(tcp, "dst_port", CmpOp::Eq, 80).unwrap();
        assert!(keep.keeps(&row));
        let mut drop = compiled(tcp, "dst_port", CmpOp::Eq, 443).unwrap();
        assert!(!drop.keeps(&row));
    }

    #[test]
    fn every_operator_compares_integers_and_strings() {
        let tcp = table("tcp");
        let row = tcp_layer(); // dst_port = 80
        for (op, below, equal, above) in [
            (CmpOp::Eq, false, true, false),
            (CmpOp::NotEq, true, false, true),
            (CmpOp::Lt, false, false, true),
            (CmpOp::LtEq, false, true, true),
            (CmpOp::Gt, true, false, false),
            (CmpOp::GtEq, true, true, false),
        ] {
            for (literal, expected) in [(79, below), (80, equal), (81, above)] {
                let mut p = compiled(tcp, "dst_port", op, literal).unwrap();
                assert_eq!(p.keeps(&row), expected, "80 {op:?} {literal}");
            }
        }

        let dns = table("dns");
        let row = layer(vec![("query_name", FieldValue::Str("m.example"))]);
        for (op, below, equal, above) in [
            (CmpOp::Eq, false, true, false),
            (CmpOp::NotEq, true, false, true),
            (CmpOp::Lt, false, false, true),
            (CmpOp::LtEq, false, true, true),
            (CmpOp::Gt, true, false, false),
            (CmpOp::GtEq, true, true, false),
        ] {
            for (literal, expected) in [("a", below), ("m.example", equal), ("z", above)] {
                let mut p = compiled(dns, "query_name", op, literal).unwrap();
                assert_eq!(p.keeps(&row), expected, "m.example {op:?} {literal}");
            }
        }
    }

    #[test]
    fn swapped_operators() {
        assert_eq!(CmpOp::Lt.swapped(), CmpOp::Gt);
        assert_eq!(CmpOp::LtEq.swapped(), CmpOp::GtEq);
        assert_eq!(CmpOp::Gt.swapped(), CmpOp::Lt);
        assert_eq!(CmpOp::GtEq.swapped(), CmpOp::LtEq);
        assert_eq!(CmpOp::Eq.swapped(), CmpOp::Eq);
        assert_eq!(CmpOp::NotEq.swapped(), CmpOp::NotEq);
    }

    /// An absent field is SQL NULL, whose semantics belong to the engine:
    /// the row is kept whatever the operator.
    #[test]
    fn missing_field_keeps_the_row() {
        let tcp = table("tcp");
        let row = tcp_layer();
        for op in [CmpOp::Eq, CmpOp::NotEq, CmpOp::Lt, CmpOp::Gt] {
            let mut p = compiled(tcp, "mss", op, 1460).unwrap();
            assert!(p.keeps(&row), "{op:?}");
        }
    }

    #[test]
    fn ipv4_compares_as_the_u32_its_column_stores() {
        let ipv4 = table("ipv4");
        let row = ipv4_layer();
        let ip = i64::from(u32::from(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(compiled(ipv4, "src_ip", CmpOp::Eq, ip).unwrap().keeps(&row));
        assert!(!compiled(ipv4, "src_ip", CmpOp::Eq, ip + 1)
            .unwrap()
            .keeps(&row));
        // A string against the address is not confidently comparable: keep.
        assert!(compiled(ipv4, "src_ip", CmpOp::Eq, "10.0.0.1")
            .unwrap()
            .keeps(&row));
    }

    #[test]
    fn values_of_another_type_keep_the_row() {
        let tcp = table("tcp");
        // An integer literal against a string value, and the reverse.
        let row = layer(vec![("dst_port", FieldValue::Str("80"))]);
        assert!(compiled(tcp, "dst_port", CmpOp::Eq, 443)
            .unwrap()
            .keeps(&row));
        let row = tcp_layer();
        assert!(compiled(tcp, "dst_port", CmpOp::Eq, "443")
            .unwrap()
            .keeps(&row));
        // A u64 that does not fit i64 is undecided; one that fits compares.
        let row = layer(vec![("dst_port", FieldValue::UInt64(u64::MAX))]);
        assert!(compiled(tcp, "dst_port", CmpOp::Eq, 1).unwrap().keeps(&row));
        let row = layer(vec![("dst_port", FieldValue::UInt64(2))]);
        assert!(!compiled(tcp, "dst_port", CmpOp::Eq, 1).unwrap().keeps(&row));
        // Booleans compare as 0 and 1, owned strings as strings.
        let row = layer(vec![("dst_port", FieldValue::Bool(true))]);
        assert!(!compiled(tcp, "dst_port", CmpOp::Eq, 0).unwrap().keeps(&row));
        let row = layer(vec![(
            "dst_port",
            FieldValue::OwnedString(compact_str::CompactString::new("x")),
        )]);
        assert!(!compiled(tcp, "dst_port", CmpOp::Eq, "y")
            .unwrap()
            .keeps(&row));
        // Null, bytes, MAC and IPv6 values are never compared.
        for value in [
            FieldValue::Null,
            FieldValue::Bytes(&[1, 2]),
            FieldValue::MacAddr([0; 6]),
            FieldValue::IpAddr(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ] {
            let row = layer(vec![("dst_port", value)]);
            assert!(compiled(tcp, "dst_port", CmpOp::Eq, 1).unwrap().keeps(&row));
            assert!(compiled(tcp, "dst_port", CmpOp::Eq, "1")
                .unwrap()
                .keeps(&row));
        }
    }

    #[test]
    fn and_needs_every_comparison() {
        let tcp = table("tcp");
        let row = tcp_layer();
        let both = |src: i64| {
            RowPredicate::And(vec![
                RowPredicate::cmp(col(tcp, "dst_port"), CmpOp::Eq, 80),
                RowPredicate::And(vec![RowPredicate::cmp(
                    col(tcp, "src_port"),
                    CmpOp::Gt,
                    src,
                )]),
            ])
            .compile(tcp)
            .unwrap()
        };
        assert!(both(10_000).keeps(&row));
        assert!(!both(60_000).keeps(&row));
    }

    #[test]
    fn predicates_that_cannot_drop_a_row_compile_to_none() {
        let tcp = table("tcp");
        assert!(RowPredicate::And(vec![]).compile(tcp).is_none());
        // No per-layer source.
        assert!(compiled(tcp, "frame_number", CmpOp::Eq, 1).is_none());
        assert!(compiled(tcp, "timestamp", CmpOp::Gt, 1).is_none());
        // A literal the context column is never compared with.
        assert!(compiled(tcp, "encap_depth", CmpOp::Eq, "0").is_none());
        assert!(compiled(tcp, "tunnel_id", CmpOp::Eq, "7").is_none());
        assert!(compiled(tcp, "tunnel_type", CmpOp::Eq, 1).is_none());
        // A column the table does not have.
        assert!(RowPredicate::cmp(ColId(u16::MAX), CmpOp::Eq, 1)
            .compile(tcp)
            .is_none());
        // `frames` rows and stream-table rows are not built from a layer.
        let frames = table("frames");
        assert!(compiled(frames, "length", CmpOp::Gt, 100).is_none());
        let connections = table("tcp_connections");
        let first = connections.columns().next().unwrap().0;
        assert!(RowPredicate::cmp(first, CmpOp::Eq, 1)
            .compile(connections)
            .is_none());
        // What is left of a mixed conjunction still applies.
        let mut mixed = RowPredicate::And(vec![
            RowPredicate::cmp(col(tcp, "frame_number"), CmpOp::Eq, 1),
            RowPredicate::cmp(col(tcp, "dst_port"), CmpOp::Eq, 443),
        ])
        .compile(tcp)
        .unwrap();
        assert!(!mixed.keeps(&tcp_layer()));
    }

    #[test]
    fn context_columns_compare_with_the_layer_context() {
        let tcp = table("tcp");
        let mut inner = tcp_layer();
        inner.encap_depth = 1;
        inner.tunnel_type = TunnelType::Vxlan;
        inner.tunnel_id = Some(42);
        let outer = tcp_layer();

        let mut depth0 = compiled(tcp, "encap_depth", CmpOp::Eq, 0).unwrap();
        assert!(depth0.keeps(&outer));
        assert!(!depth0.keeps(&inner));

        let mut vxlan = compiled(tcp, "tunnel_type", CmpOp::Eq, "vxlan").unwrap();
        assert!(vxlan.keeps(&inner));
        // Outside a tunnel the column is NULL: undecided.
        assert!(vxlan.keeps(&outer));
        let mut gre = compiled(tcp, "tunnel_type", CmpOp::Eq, "gre").unwrap();
        assert!(!gre.keeps(&inner));
        assert!(gre.keeps(&outer));

        let mut id = compiled(tcp, "tunnel_id", CmpOp::Eq, 42).unwrap();
        assert!(id.keeps(&inner));
        assert!(id.keeps(&outer));
        let mut other = compiled(tcp, "tunnel_id", CmpOp::NotEq, 42).unwrap();
        assert!(!other.keeps(&inner));
        assert!(other.keeps(&outer));
        // An id above i64::MAX is undecided.
        inner.tunnel_id = Some(u64::MAX);
        assert!(id.keeps(&inner));
        assert!(other.keeps(&inner));
    }

    /// The hint follows a field that changes position between rows.
    #[test]
    fn hinted_lookup_follows_a_moving_field() {
        let tcp = table("tcp");
        let mut p = compiled(tcp, "dst_port", CmpOp::Eq, 80).unwrap();
        let first = tcp_layer();
        let moved = layer(vec![
            ("dst_port", FieldValue::UInt16(443)),
            ("src_port", FieldValue::UInt16(80)),
        ]);
        let absent = layer(vec![("src_port", FieldValue::UInt16(80))]);
        assert!(p.keeps(&first));
        assert!(!p.keeps(&moved));
        assert!(p.keeps(&absent));
        assert!(p.keeps(&first));
    }

    #[test]
    fn for_each_column_visits_nested_comparisons() {
        let p = RowPredicate::And(vec![
            RowPredicate::cmp(ColId(3), CmpOp::Eq, 1),
            RowPredicate::And(vec![RowPredicate::cmp(ColId(5), CmpOp::Eq, "x")]),
        ]);
        let mut seen = Vec::new();
        p.for_each_column(&mut |c| seen.push(c));
        assert_eq!(seen, vec![ColId(3), ColId(5)]);
    }

    fn packet(frame_number: u64, timestamp_ns: i64) -> PacketRef<'static> {
        PacketRef {
            frame_number,
            timestamp_ns,
            captured_len: 0,
            original_len: 0,
            link_type: 1,
            data: &[],
        }
    }

    fn range(first: u64, end: Option<u64>) -> PacketRange {
        PacketRange {
            start: PacketPosition {
                byte_offset: 0,
                frame_number: first,
            },
            end: end.map(|frame_number| PacketPosition {
                byte_offset: 0,
                frame_number,
            }),
        }
    }

    #[test]
    fn all_accepts_everything() {
        let all = FramePredicate::all();
        assert!(all.is_all());
        assert_eq!(all, FramePredicate::default());
        assert!(all.accepts(&packet(1, i64::MIN)));
        assert!(all.accepts(&packet(u64::MAX, i64::MAX)));
        assert!(!all.past_end(u64::MAX));
        assert!(all.may_overlap(&PacketRange::whole(), None));
        assert!(all.may_overlap(&range(5, Some(9)), Some((0, 10))));

        for bounded in [
            FramePredicate {
                frames: (Bound::Included(1), Bound::Unbounded),
                ..FramePredicate::all()
            },
            FramePredicate {
                frames: (Bound::Unbounded, Bound::Excluded(9)),
                ..FramePredicate::all()
            },
            FramePredicate {
                time_ns: (Bound::Excluded(0), Bound::Unbounded),
                ..FramePredicate::all()
            },
            FramePredicate {
                time_ns: (Bound::Unbounded, Bound::Included(0)),
                ..FramePredicate::all()
            },
        ] {
            assert!(!bounded.is_all(), "{bounded:?}");
        }
    }

    #[test]
    fn none_accepts_nothing() {
        let none = FramePredicate::none();
        assert!(none.is_empty());
        assert!(!none.is_all());
        assert!(!none.accepts(&packet(1, 0)));
        assert!(!none.accepts(&packet(0, 0)));
        assert!(none.past_end(1));
        assert_eq!(none.intersect(&FramePredicate::all()), none);
    }

    /// A comparison with a constant is the range of the values it holds
    /// for, on the frame number or on the timestamp and nothing else.
    #[test]
    fn a_comparison_is_its_range() {
        const OPS: [CmpOp; 5] = [CmpOp::Eq, CmpOp::Lt, CmpOp::LtEq, CmpOp::Gt, CmpOp::GtEq];
        let frames = [1, 2, 3, 4, 5, 6, 100, u64::MAX - 1, u64::MAX];
        let times = [i64::MIN, -1_000_000_001, -1, 0, 1, 999, 1000, i64::MAX];
        for op in OPS {
            for constant in frames.into_iter().chain([0]) {
                let predicate = FramePredicate::frame_number(op, constant).unwrap();
                assert_eq!(predicate.time_ns, FramePredicate::all().time_ns);
                for frame in frames {
                    assert_eq!(
                        predicate.accepts(&packet(frame, 0)),
                        op.holds(&frame, &constant),
                        "frame {frame} {op:?} {constant}"
                    );
                }
            }
            for constant in times {
                let predicate = FramePredicate::timestamp_ns(op, constant).unwrap();
                assert_eq!(predicate.frames, FramePredicate::all().frames);
                for time in times {
                    assert_eq!(
                        predicate.accepts(&packet(1, time)),
                        op.holds(&time, &constant),
                        "time {time} {op:?} {constant}"
                    );
                }
            }
        }
        // `<>` leaves a hole: not a range.
        assert_eq!(FramePredicate::frame_number(CmpOp::NotEq, 5), None);
        assert_eq!(FramePredicate::timestamp_ns(CmpOp::NotEq, 5), None);
    }

    /// Every pair of bounds on a small domain: the intersection accepts
    /// what both accept, in either order, and intersecting again changes
    /// nothing.
    #[test]
    fn intersection_is_exact_commutative_and_idempotent() {
        let bounds = |values: std::ops::RangeInclusive<u64>| -> Vec<Bound<u64>> {
            let mut bounds = vec![Bound::Unbounded];
            for value in values {
                bounds.push(Bound::Included(value));
                bounds.push(Bound::Excluded(value));
            }
            bounds
        };
        let mut predicates = Vec::new();
        for lower in bounds(1..=4) {
            for upper in bounds(1..=4) {
                predicates.push(FramePredicate {
                    frames: (lower, upper),
                    ..FramePredicate::all()
                });
            }
        }
        for a in &predicates {
            for b in &predicates {
                let both = a.intersect(b);
                for frame in 0..=6 {
                    assert_eq!(
                        both.accepts(&packet(frame, 0)),
                        a.accepts(&packet(frame, 0)) && b.accepts(&packet(frame, 0)),
                        "{a:?} and {b:?}: frame {frame}"
                    );
                }
                assert_eq!(both, b.intersect(a), "{a:?} and {b:?}");
                assert_eq!(both.intersect(b), both, "{a:?} and {b:?}");
                assert_eq!(both.intersect(a), both, "{a:?} and {b:?}");
            }
        }
        // The same on timestamps, across zero, and both ranges at once.
        let early = FramePredicate {
            time_ns: (Bound::Included(-5), Bound::Excluded(7)),
            ..FramePredicate::all()
        };
        let late = FramePredicate {
            frames: (Bound::Unbounded, Bound::Included(9)),
            time_ns: (Bound::Excluded(-5), Bound::Included(9)),
        };
        assert_eq!(
            early.intersect(&late),
            FramePredicate {
                frames: (Bound::Unbounded, Bound::Included(9)),
                time_ns: (Bound::Excluded(-5), Bound::Excluded(7)),
            }
        );
        assert_eq!(early.intersect(&FramePredicate::all()), early);
    }

    #[test]
    fn accepts_applies_both_ranges_with_their_bound_kinds() {
        let p = FramePredicate {
            frames: (Bound::Included(10), Bound::Excluded(20)),
            time_ns: (Bound::Excluded(1_000), Bound::Included(2_000)),
        };
        let accepted: Vec<bool> = [
            (9, 1_500),  // below the frame range
            (10, 1_500), // first frame
            (19, 1_500), // last frame
            (20, 1_500), // excluded upper frame bound
            (15, 1_000), // excluded lower time bound
            (15, 1_001),
            (15, 2_000), // included upper time bound
            (15, 2_001),
        ]
        .iter()
        .map(|&(frame, ts)| p.accepts(&packet(frame, ts)))
        .collect();
        assert_eq!(
            accepted,
            [false, true, true, false, false, true, true, false]
        );

        let p = FramePredicate {
            frames: (Bound::Excluded(10), Bound::Included(20)),
            time_ns: (Bound::Included(-5), Bound::Excluded(5)),
        };
        assert!(!p.accepts(&packet(10, 0)));
        assert!(p.accepts(&packet(11, -5)));
        assert!(p.accepts(&packet(20, 4)));
        assert!(!p.accepts(&packet(20, 5)));
        assert!(!p.accepts(&packet(21, 0)));
    }

    #[test]
    fn past_end_follows_the_upper_frame_bound_only() {
        let included = FramePredicate {
            frames: (Bound::Included(5), Bound::Included(20)),
            time_ns: (Bound::Unbounded, Bound::Included(0)),
        };
        assert!(!included.past_end(1)); // before the range is not past it
        assert!(!included.past_end(20));
        assert!(included.past_end(21));

        let excluded = FramePredicate {
            frames: (Bound::Unbounded, Bound::Excluded(20)),
            ..FramePredicate::all()
        };
        assert!(!excluded.past_end(19));
        assert!(excluded.past_end(20));

        // Time bounds never end a scan: timestamps need not ascend.
        let time_only = FramePredicate {
            time_ns: (Bound::Unbounded, Bound::Included(0)),
            ..FramePredicate::all()
        };
        assert!(!time_only.past_end(u64::MAX));
    }

    /// `past_end(n)` implies that no frame from `n` on is accepted.
    #[test]
    fn is_empty_means_no_packet_matches() {
        use Bound::*;
        let frames = |lower, upper| FramePredicate {
            frames: (lower, upper),
            ..FramePredicate::all()
        };
        let time = |lower, upper| FramePredicate {
            time_ns: (lower, upper),
            ..FramePredicate::all()
        };
        assert!(!FramePredicate::all().is_empty());
        for empty in [
            frames(Included(5), Included(4)),
            frames(Included(5), Excluded(5)),
            frames(Excluded(5), Included(5)),
            frames(Excluded(5), Excluded(6)),
            frames(Excluded(u64::MAX), Unbounded),
            frames(Unbounded, Excluded(1)),
            frames(Unbounded, Included(0)),
            frames(Unbounded, Excluded(0)),
            time(Included(5), Included(4)),
            time(Excluded(-1), Excluded(0)),
            time(Unbounded, Excluded(i64::MIN)),
            time(Excluded(i64::MAX), Unbounded),
        ] {
            assert!(empty.is_empty(), "{empty:?}");
        }
        for some in [
            frames(Included(5), Included(5)),
            frames(Excluded(5), Excluded(7)),
            frames(Unbounded, Included(1)),
            frames(Unbounded, Excluded(2)),
            frames(Included(u64::MAX), Unbounded),
            time(Included(-3), Included(-3)),
            time(Excluded(-2), Excluded(0)),
            time(Unbounded, Included(i64::MIN)),
        ] {
            assert!(!some.is_empty(), "{some:?}");
        }
        // Exhaustively over a small domain: empty exactly when nothing is
        // accepted.
        let bounds = |v: i64| [Unbounded, Included(v), Excluded(v)];
        for low in 0..6i64 {
            for high in 0..6i64 {
                for lower in bounds(low) {
                    for upper in bounds(high) {
                        let p = time(lower, upper);
                        let any = (-2..9).any(|ts| p.accepts(&packet(1, ts)));
                        assert_eq!(p.is_empty(), !any, "{p:?}");
                        let as_u64 = |b: Bound<i64>| match b {
                            Unbounded => Unbounded,
                            Included(v) => Included(v as u64),
                            Excluded(v) => Excluded(v as u64),
                        };
                        let p = frames(as_u64(lower), as_u64(upper));
                        let any = (1..9).any(|frame| p.accepts(&packet(frame, 0)));
                        assert_eq!(p.is_empty(), !any, "{p:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn past_end_agrees_with_accepts() {
        let bounds = |v: u64| [Bound::Unbounded, Bound::Included(v), Bound::Excluded(v)];
        for lower in bounds(3) {
            for upper in bounds(6) {
                let p = FramePredicate {
                    frames: (lower, upper),
                    ..FramePredicate::all()
                };
                for n in 0..10u64 {
                    let later = (n..12).any(|m| p.accepts(&packet(m, 0)));
                    assert_eq!(p.past_end(n), !later, "{p:?} at {n}");
                }
            }
        }
    }

    #[test]
    fn may_overlap_is_exact_about_frame_ranges() {
        let bounds = |v: u64| [Bound::Unbounded, Bound::Included(v), Bound::Excluded(v)];
        for lower in bounds(4) {
            for upper in bounds(8) {
                let p = FramePredicate {
                    frames: (lower, upper),
                    ..FramePredicate::all()
                };
                for first in 1..12u64 {
                    // Ranges with an end (including empty ones) ...
                    for end in first..14 {
                        let any = (first..end).any(|n| p.accepts(&packet(n, 0)));
                        assert_eq!(
                            p.may_overlap(&range(first, Some(end)), None),
                            any,
                            "{p:?} over {first}..{end}"
                        );
                    }
                    // ... and to the end of the capture.
                    let any = (first..40).any(|n| p.accepts(&packet(n, 0)));
                    assert_eq!(
                        p.may_overlap(&range(first, None), None),
                        any,
                        "{p:?} from {first}"
                    );
                }
            }
        }
    }

    #[test]
    fn may_overlap_uses_known_timestamps() {
        let p = FramePredicate {
            frames: (Bound::Unbounded, Bound::Unbounded),
            time_ns: (Bound::Included(100), Bound::Excluded(200)),
        };
        let whole = PacketRange::whole();
        // Unknown timestamps cannot rule a range out.
        assert!(p.may_overlap(&whole, None));
        assert!(!p.may_overlap(&whole, Some((0, 99))));
        assert!(p.may_overlap(&whole, Some((0, 100))));
        assert!(p.may_overlap(&whole, Some((150, 160))));
        assert!(p.may_overlap(&whole, Some((199, 500))));
        assert!(!p.may_overlap(&whole, Some((200, 500))));
        assert!(p.may_overlap(&whole, Some((0, 500))));

        let p = FramePredicate {
            frames: (Bound::Unbounded, Bound::Unbounded),
            time_ns: (Bound::Excluded(100), Bound::Included(200)),
        };
        assert!(!p.may_overlap(&whole, Some((0, 100))));
        assert!(p.may_overlap(&whole, Some((0, 101))));
        assert!(p.may_overlap(&whole, Some((200, 500))));
        assert!(!p.may_overlap(&whole, Some((201, 500))));

        // Both must allow the range.
        let p = FramePredicate {
            frames: (Bound::Included(10), Bound::Unbounded),
            time_ns: (Bound::Included(100), Bound::Unbounded),
        };
        assert!(!p.may_overlap(&range(1, Some(10)), Some((100, 200))));
        assert!(!p.may_overlap(&range(10, Some(20)), Some((0, 99))));
        assert!(p.may_overlap(&range(10, Some(20)), Some((0, 100))));
    }
}
