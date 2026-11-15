//! Filter pushdown: what the filters DuckDB offers a scan say about the frames to read, as a
//! [`FramePredicate`], and which of them the scan takes over.
//!
//! ```sql
//! SELECT * FROM read_tcp('capture.pcap') WHERE frame_number <= 2000;
//! SELECT count(*) FROM read_dns('capture.pcap')
//! WHERE timestamp >= TIMESTAMP '2024-05-01 12:00:00' AND timestamp < TIMESTAMP '2024-05-01 12:05:00';
//! ```
//!
//! DuckDB's optimizer hands a table function the conjuncts of the `WHERE` clause above it. A
//! conjunct the function *accepts* is removed from the plan: DuckDB no longer evaluates it, so
//! the function must return exactly the rows it holds for, no more and no fewer. The scan layer
//! can promise that for one kind of predicate, a range of frame numbers and a range of
//! timestamps (`FramePredicate`, which core's driver enforces packet by packet before anything
//! is parsed, and which lets it skip the partitions and end the reads that cannot match). So a
//! conjunct is accepted when it says exactly what a `FramePredicate` can say, and left to
//! DuckDB otherwise. This file is the whole of that decision; the scan never sees an
//! expression.
//!
//! # What is accepted
//!
//! A conjunct is accepted when it is one of these, or an `AND` of them:
//!
//! | Shape | Constant |
//! |---|---|
//! | `frame_number <op> c`, `c <op> frame_number` | a `UBIGINT` |
//! | `CAST(frame_number AS HUGEINT) <op> c`, and reversed | a `HUGEINT` |
//! | `timestamp <op> c`, `c <op> timestamp` | a `TIMESTAMP_NS` |
//!
//! with `<op>` one of `=`, `<`, `<=`, `>`, `>=`. The types are those of the bound expression,
//! after DuckDB has inserted its casts, folded constants and rewritten what it rewrites, which
//! is why there are so few rows: `frame_number <= 5` arrives with the 5 as a `UBIGINT`,
//! `timestamp >= TIMESTAMP '2024-05-01 12:00:00'`, `timestamp >= DATE '2024-05-01'` and
//! `timestamp >= '2024-05-01 12:00:00'` arrive with a `TIMESTAMP_NS` constant,
//! `NOT (frame_number > 5)` arrives as `frame_number <= 5` and `frame_number + 1 < 5` as
//! `frame_number < 4`.
//!
//! # Why each is exact
//!
//! - **`frame_number` against a `UBIGINT`.** The column holds `PacketRef::frame_number`, a
//!   `u64` that is never NULL, and DuckDB would compare that `u64` with the constant. The
//!   predicate compares the same two numbers with the same operator.
//! - **`timestamp` against a `TIMESTAMP_NS`.** The column holds `PacketRef::timestamp_ns`, an
//!   `i64` of nanoseconds that is never NULL, as it is (`engine::types::TIMESTAMPS` is
//!   nanoseconds, so nothing is rounded on the way out). DuckDB compares `TIMESTAMP_NS` values
//!   as those integers, the infinities included, and so does the predicate. A constant of a
//!   coarser type (`TIMESTAMP`, `DATE`, text) was converted to nanoseconds by DuckDB's own cast
//!   before it got here, which is exact or an error (out of range): this file never multiplies
//!   or rounds a timestamp.
//! - **`CAST(frame_number AS HUGEINT)` against a `HUGEINT`.** This is what a comparison with a
//!   signed value can become. The cast of a `UBIGINT` to `HUGEINT` cannot fail and keeps the
//!   order, so the comparison is that of the `u64` with the constant as an integer: a constant
//!   below 0 or above `u64::MAX` makes the comparison true for every frame or for none, and
//!   any other constant is a `u64`.
//! - **`AND`.** A conjunction of exact predicates is the intersection of their ranges.
//!
//! With several files `frame_number` counts the frames of each file, and the predicate is
//! applied to each file's frames: `frame_number <= 10` gives the first ten frames of every
//! file. That is what DuckDB's own filter on the column would keep, so it is still exact.
//!
//! # What is used without being accepted: `BETWEEN`
//!
//! Two bounds on one column do not arrive as two comparisons. DuckDB's optimizer has combined
//! them into one `BETWEEN` node by then, whether the query said `BETWEEN` or
//! `frame_number > 3 AND frame_number < 7`, and whether each bound is inclusive is in that
//! node's bind data, which the C API does not expose (DuckDB 2.0.0). Such a node cannot be
//! accepted: the scan would not know whether to return the frames at the bounds.
//!
//! It is still used. Read with both bounds inclusive it is a range that holds every frame the
//! real filter holds for, and at most the frames at its two ends besides. The scan filters by
//! that range, so it skips and stops as for an accepted filter, and the node is *not*
//! accepted, so DuckDB goes on applying the real filter to the rows the scan returns and
//! removes what the scan let through. The result is exact; the cost is DuckDB's comparison on
//! the rows that are returned anyway. A time window is such a filter, so this is the case that
//! matters most.
//!
//! The same holds inside an `AND`: the parts that are understood narrow what the scan reads,
//! and the conjunct is accepted only if every part is exact.
//!
//! # What is not used
//!
//! Everything else stays with DuckDB, which evaluates it on the rows the scan returns:
//!
//! - `<>`, `IN`, `IS [NOT] DISTINCT FROM`, `IS [NOT] NULL`, `OR`, `CASE`, function calls;
//! - a comparison with anything but a constant on the other side: another column, a prepared
//!   statement's parameter (but see below), an expression DuckDB did not fold;
//! - a NULL constant (the comparison is never true; DuckDB knows what to do with it);
//! - any other cast around the column. `CAST(timestamp AS TIMESTAMP)`, `AS DATE` or
//!   `AS TIMESTAMP WITH TIME ZONE` round the nanoseconds away, so the comparison is not one on
//!   the stored value; `CAST(frame_number AS BIGINT)` can fail, and `AS DOUBLE` or `AS DECIMAL`
//!   lose digits. DuckDB wraps the column this way when the other side has such a type
//!   (`frame_number < 2.5`), or when the query says so (`timestamp::DATE = ...`);
//! - a constant whose type is not the one in the table above;
//! - predicates on any other column. The scan layer's `RowPredicate` for protocol fields is
//!   conservative (it may keep rows that do not match), which is not good enough to accept.
//!
//! # Parameters
//!
//! A filter with a prepared statement's parameter in it (`frame_number <= $1`) is offered as
//! such when the statement is prepared, and not understood. DuckDB plans such a statement
//! again when it is executed, with the value in place of the parameter, so the filter is then
//! offered as a comparison with a constant and accepted like any other.
//!
//! # More than one call
//!
//! The optimizer may call the callback again for the same scan, with the filters that are
//! still above it; the accepted ones are gone from the plan by then. So what the scan filters
//! by is never replaced: every filter that is understood is intersected into the scan's
//! predicate (`Pushed::accept`). Intersecting is idempotent, so a filter that is offered
//! twice changes nothing the second time.

use std::ops::Bound;
use std::sync::Mutex;

use duckdb_neo::{
    enums::LogicalTypeID,
    expression::{Expression, ExpressionType},
    table_function::PushdownData,
    types::TimestampNsValue,
    Result,
};
use pcapsql_core::scan::{CmpOp, FramePredicate};

/// The columns a [`FramePredicate`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    /// `frame_number`, a `UBIGINT`.
    FrameNumber,
    /// `timestamp`, a `TIMESTAMP_NS`.
    Timestamp,
}

/// One side of a comparison, as far as the translation reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A reference to the column itself, with no cast around it.
    Column(Column),
    /// `CAST(frame_number AS HUGEINT)`.
    WideFrameNumber,
    /// A `UBIGINT` constant that is not NULL.
    Unsigned(u64),
    /// A `HUGEINT` constant that is not NULL.
    Wide(i128),
    /// A `TIMESTAMP_NS` constant that is not NULL: nanoseconds since the Unix epoch.
    Nanos(i64),
    /// Anything else.
    Other,
}

/// A filter expression, as far as the translation reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// `left <op> right`. `<>` is never read: its frames are not a range.
    Compare(CmpOp, Operand, Operand),
    /// `value BETWEEN lower AND upper`, in that order, each bound inclusive or not: the
    /// expression does not say which.
    Between(Operand, Operand, Operand),
    And(Vec<Filter>),
    /// Anything else: not understood.
    Other,
}

/// What a filter says about the frames it holds for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reading {
    /// Every frame the filter holds for is accepted by this.
    pub predicate: FramePredicate,
    /// The filter holds for every frame `predicate` accepts, too: the two are the same, and
    /// the filter can be accepted. If not, `predicate` only narrows what must be read.
    pub exact: bool,
}

/// The frames whose number `n` satisfies `n <comparison> constant`, both taken as integers.
fn wide_frames(comparison: CmpOp, constant: i128) -> Option<FramePredicate> {
    if let Ok(constant) = u64::try_from(constant) {
        return FramePredicate::frame_number(comparison, constant);
    }
    // Every frame number is above a negative constant and below one past `u64::MAX`.
    let above = constant < 0;
    let holds = match comparison {
        CmpOp::Eq => false,
        CmpOp::Lt | CmpOp::LtEq => !above,
        CmpOp::Gt | CmpOp::GtEq => above,
        CmpOp::NotEq => return None,
    };
    Some(if holds {
        FramePredicate::all()
    } else {
        FramePredicate::none()
    })
}

/// The frames `column <comparison> constant` holds for, if the two are a column and a constant
/// of the one type DuckDB compares the column's stored values with.
fn compared(comparison: CmpOp, column: &Operand, constant: &Operand) -> Option<FramePredicate> {
    match (column, constant) {
        (Operand::Column(Column::FrameNumber), Operand::Unsigned(constant)) => {
            FramePredicate::frame_number(comparison, *constant)
        }
        (Operand::WideFrameNumber, Operand::Wide(constant)) => wide_frames(comparison, *constant),
        (Operand::Column(Column::Timestamp), Operand::Nanos(constant)) => {
            FramePredicate::timestamp_ns(comparison, *constant)
        }
        _ => None,
    }
}

/// What `filter` says about the frames it holds for, if anything (see the module documentation
/// for which filters are read, and why what is read is exact or at least leaves no frame out).
pub fn read(filter: &Filter) -> Option<Reading> {
    match filter {
        Filter::Other => None,
        Filter::Compare(comparison, left, right) => {
            // Bring the column to the left.
            let (comparison, column, constant) = match (left, right) {
                (Operand::Column(_) | Operand::WideFrameNumber, _) => (*comparison, left, right),
                (_, Operand::Column(_) | Operand::WideFrameNumber) => {
                    (comparison.swapped(), right, left)
                }
                _ => return None,
            };
            Some(Reading {
                predicate: compared(comparison, column, constant)?,
                exact: true,
            })
        }
        Filter::Between(value, lower, upper) => {
            // With both bounds inclusive: every frame the filter holds for, whichever its
            // bounds are, and at most the frames at the two bounds besides.
            let from = compared(CmpOp::GtEq, value, lower)?;
            let to = compared(CmpOp::LtEq, value, upper)?;
            Some(Reading {
                predicate: from.intersect(&to),
                exact: false,
            })
        }
        Filter::And(filters) => {
            // A frame the conjunction holds for is one every part holds for. So each part
            // that is read narrows the frames, and the whole is exact when every part is read
            // and exact.
            let mut all = Reading {
                predicate: FramePredicate::all(),
                exact: true,
            };
            let mut any = false;
            for filter in filters {
                match read(filter) {
                    Some(part) => {
                        all.predicate = all.predicate.intersect(&part.predicate);
                        all.exact &= part.exact;
                        any = true;
                    }
                    None => all.exact = false,
                }
            }
            any.then_some(all)
        }
    }
}

/// `predicate` in words, for the log: `frame_number in [3, 10)`, `timestamp in [x, ..) ns`.
pub fn describe(predicate: &FramePredicate) -> String {
    fn interval<T: std::fmt::Display>((lower, upper): &(Bound<T>, Bound<T>)) -> Option<String> {
        let lower = match lower {
            Bound::Unbounded if matches!(upper, Bound::Unbounded) => return None,
            Bound::Unbounded => "(..".to_owned(),
            Bound::Included(bound) => format!("[{bound}"),
            Bound::Excluded(bound) => format!("({bound}"),
        };
        let upper = match upper {
            Bound::Unbounded => "..)".to_owned(),
            Bound::Included(bound) => format!("{bound}]"),
            Bound::Excluded(bound) => format!("{bound})"),
        };
        Some(format!("{lower}, {upper}"))
    }
    if predicate.is_empty() {
        return "no frame".to_owned();
    }
    let parts: Vec<String> = [
        interval(&predicate.frames).map(|frames| format!("frame_number in {frames}")),
        interval(&predicate.time_ns).map(|time| format!("timestamp in {time} ns")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if parts.is_empty() {
        "every frame".to_owned()
    } else {
        parts.join(" and ")
    }
}

/// What a scan function knows about filters: which of its declared columns a predicate can be
/// about, and the predicate of the filters it has understood. It is part of the bind data,
/// which the pushdown callback only gets to read, hence the lock.
#[derive(Debug)]
pub(super) struct Pushed {
    /// The index of `frame_number` among the declared columns.
    frame_number: Option<usize>,
    /// The index of `timestamp` among the declared columns.
    timestamp: Option<usize>,
    understood: Mutex<FramePredicate>,
}

impl Pushed {
    /// Nothing offered yet, for a function that declares `frame_number` and `timestamp` at
    /// these indices.
    pub(super) fn new(frame_number: Option<usize>, timestamp: Option<usize>) -> Self {
        Self {
            frame_number,
            timestamp,
            understood: Mutex::new(FramePredicate::all()),
        }
    }

    /// The frames the scan returns rows of. No frame that all of DuckDB's filters hold for is
    /// missing from them, and they are exactly the frames the accepted filters hold for
    /// unless a filter that was not accepted narrowed them further.
    pub(super) fn predicate(&self) -> FramePredicate {
        self.understood
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Narrow what the scan reads by every filter of `offered` that says something about the
    /// frames, and accept those that say exactly what a predicate says.
    pub(super) fn accept(&self, offered: &PushdownData<'_>) -> Result<()> {
        for index in 0..offered.filter_count()? {
            // An expression that cannot be read is one that is not understood: DuckDB keeps it.
            let filter = offered
                .filter(index)
                .and_then(|expression| self.filter(offered, &expression))
                .unwrap_or(Filter::Other);
            let Some(reading) = read(&filter) else {
                continue;
            };
            // The scan filters by it before DuckDB is told to stop: a filter applied twice is
            // harmless, one applied by nobody is a wrong result.
            {
                let mut understood = self
                    .understood
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *understood = understood.intersect(&reading.predicate);
            }
            if reading.exact {
                offered.accept_pushdown(index)?;
            }
        }
        Ok(())
    }

    /// The filter `expression` is, as far as [`read`] looks.
    fn filter(&self, offered: &PushdownData<'_>, expression: &Expression<'_>) -> Result<Filter> {
        let comparison = match expression.expression_type()? {
            ExpressionType::ConjunctionAnd => {
                let filters = expression
                    .children()?
                    .iter()
                    // A part that cannot be read is a part that is not understood.
                    .map(|child| self.filter(offered, child).unwrap_or(Filter::Other))
                    .collect();
                return Ok(Filter::And(filters));
            }
            ExpressionType::CompareBetween => {
                if expression.child_count()? != 3 {
                    return Ok(Filter::Other);
                }
                return Ok(Filter::Between(
                    self.operand(offered, &expression.child(0)?)?,
                    self.operand(offered, &expression.child(1)?)?,
                    self.operand(offered, &expression.child(2)?)?,
                ));
            }
            ExpressionType::CompareEqual => CmpOp::Eq,
            ExpressionType::CompareLessThan => CmpOp::Lt,
            ExpressionType::CompareLessThanOrEqualTo => CmpOp::LtEq,
            ExpressionType::CompareGreaterThan => CmpOp::Gt,
            ExpressionType::CompareGreaterThanOrEqualTo => CmpOp::GtEq,
            _ => return Ok(Filter::Other),
        };
        if expression.child_count()? != 2 {
            return Ok(Filter::Other);
        }
        Ok(Filter::Compare(
            comparison,
            self.operand(offered, &expression.child(0)?)?,
            self.operand(offered, &expression.child(1)?)?,
        ))
    }

    /// The column `expression` refers to, if it is a reference to one a predicate is about.
    fn column(
        &self,
        offered: &PushdownData<'_>,
        expression: &Expression<'_>,
    ) -> Result<Option<Column>> {
        if expression.expression_type()? != ExpressionType::BoundColumnRef {
            return Ok(None);
        }
        // The reference counts in the scan's projection, which maps to the declared columns.
        let declared = offered.get_column_index(expression.reference_index()?)?;
        // The type is checked too: a predicate is about the values the scan stores.
        let (column, stored) = if Some(declared) == self.frame_number {
            (Column::FrameNumber, LogicalTypeID::UBigInt)
        } else if Some(declared) == self.timestamp {
            (Column::Timestamp, LogicalTypeID::TimestampNs)
        } else {
            return Ok(None);
        };
        let as_stored = expression.return_type()?.id()? == stored;
        Ok(as_stored.then_some(column))
    }

    fn operand(&self, offered: &PushdownData<'_>, expression: &Expression<'_>) -> Result<Operand> {
        match expression.expression_type()? {
            ExpressionType::BoundColumnRef => Ok(self
                .column(offered, expression)?
                .map_or(Operand::Other, Operand::Column)),
            ExpressionType::OperatorCast => {
                // The one cast that keeps every value and the order: UBIGINT to HUGEINT.
                // By its text, not its id: a type defined on top of HUGEINT under another
                // name has the same id, and its cast is whatever was registered for it.
                if expression.child_count()? != 1
                    || expression.return_type()?.to_text()? != "HUGEINT"
                {
                    return Ok(Operand::Other);
                }
                let column = self.column(offered, &expression.child(0)?)?;
                Ok(match column {
                    Some(Column::FrameNumber) => Operand::WideFrameNumber,
                    _ => Operand::Other,
                })
            }
            ExpressionType::ValueConstant => {
                let value = expression.get_constant_value()?;
                if value.is_null()? {
                    return Ok(Operand::Other);
                }
                let operand = match value.logical_type()?.id()? {
                    LogicalTypeID::UBigInt => value.get::<u64>()?.map(Operand::Unsigned),
                    LogicalTypeID::HugeInt => value.get::<i128>()?.map(Operand::Wide),
                    LogicalTypeID::TimestampNs => value
                        .get::<TimestampNsValue>()?
                        .map(|nanos| Operand::Nanos(nanos.0)),
                    _ => None,
                };
                Ok(operand.unwrap_or(Operand::Other))
            }
            _ => Ok(Operand::Other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use CmpOp::{
        Eq as Equal, Gt as Greater, GtEq as GreaterOrEqual, Lt as Less, LtEq as LessOrEqual,
    };

    const FRAME: Operand = Operand::Column(Column::FrameNumber);
    const TIME: Operand = Operand::Column(Column::Timestamp);
    const COMPARISONS: [CmpOp; 5] = [Equal, Less, LessOrEqual, Greater, GreaterOrEqual];

    fn holds<T: Ord>(comparison: CmpOp, value: T, constant: T) -> bool {
        match comparison {
            Equal => value == constant,
            Less => value < constant,
            LessOrEqual => value <= constant,
            Greater => value > constant,
            GreaterOrEqual => value >= constant,
            CmpOp::NotEq => value != constant,
        }
    }

    /// Whether `predicate` accepts a frame with this number and timestamp, by its bounds
    /// (`FramePredicate::accepts` takes a packet).
    fn accepts(predicate: &FramePredicate, frame: u64, time: i64) -> bool {
        use std::ops::RangeBounds;
        predicate.frames.contains(&frame) && predicate.time_ns.contains(&time)
    }

    /// The predicate of a filter that must be exact.
    fn exact(filter: &Filter) -> FramePredicate {
        let reading = read(filter).unwrap_or_else(|| panic!("{filter:?} is not read"));
        assert!(reading.exact, "{filter:?}");
        reading.predicate
    }

    const FRAMES: [u64; 9] = [1, 2, 3, 4, 5, 6, 100, u64::MAX - 1, u64::MAX];
    const TIMES: [i64; 9] = [
        i64::MIN,
        -1_000_000_001,
        -1,
        0,
        1,
        999,
        1000,
        1001,
        i64::MAX,
    ];

    #[test]
    fn a_comparison_with_a_constant_is_its_range_in_either_order() {
        for comparison in COMPARISONS {
            for constant in FRAMES.into_iter().chain([0]) {
                let filters = [
                    Filter::Compare(comparison, FRAME, Operand::Unsigned(constant)),
                    Filter::Compare(comparison.swapped(), Operand::Unsigned(constant), FRAME),
                ];
                for filter in filters {
                    let predicate = exact(&filter);
                    for frame in FRAMES {
                        assert_eq!(
                            accepts(&predicate, frame, 0),
                            holds(comparison, frame, constant),
                            "{filter:?}: frame {frame}"
                        );
                    }
                    assert_eq!(predicate.time_ns, FramePredicate::all().time_ns);
                }
            }
            for constant in TIMES {
                let filters = [
                    Filter::Compare(comparison, TIME, Operand::Nanos(constant)),
                    Filter::Compare(comparison.swapped(), Operand::Nanos(constant), TIME),
                ];
                for filter in filters {
                    let predicate = exact(&filter);
                    for time in TIMES {
                        assert_eq!(
                            accepts(&predicate, 1, time),
                            holds(comparison, time, constant),
                            "{filter:?}: time {time}"
                        );
                    }
                    assert_eq!(predicate.frames, FramePredicate::all().frames);
                }
            }
        }
    }

    #[test]
    fn a_widened_frame_number_compares_as_an_integer() {
        let constants = [
            i128::MIN,
            -1,
            0,
            1,
            5,
            i128::from(u64::MAX) - 1,
            i128::from(u64::MAX),
            i128::from(u64::MAX) + 1,
            i128::MAX,
        ];
        for comparison in COMPARISONS {
            for constant in constants {
                let filters = [
                    Filter::Compare(
                        comparison,
                        Operand::WideFrameNumber,
                        Operand::Wide(constant),
                    ),
                    Filter::Compare(
                        comparison.swapped(),
                        Operand::Wide(constant),
                        Operand::WideFrameNumber,
                    ),
                ];
                for filter in filters {
                    let predicate = exact(&filter);
                    for frame in FRAMES {
                        assert_eq!(
                            accepts(&predicate, frame, 0),
                            holds(comparison, i128::from(frame), constant),
                            "{filter:?}: frame {frame}"
                        );
                    }
                    // Out of range one way is every frame, the other way none, and the
                    // predicate says so to whoever plans with it.
                    let every = FRAMES
                        .iter()
                        .all(|frame| holds(comparison, i128::from(*frame), constant));
                    if !(0..=i128::from(u64::MAX)).contains(&constant) {
                        assert_eq!(predicate.is_all(), every, "{filter:?}");
                        assert_eq!(predicate.is_empty(), !every, "{filter:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn what_is_not_about_the_frames_is_not_read() {
        let not_read = [
            Filter::Other,
            // The column with a constant of another type, and the other way about.
            Filter::Compare(Less, FRAME, Operand::Wide(5)),
            Filter::Compare(Less, FRAME, Operand::Nanos(5)),
            Filter::Compare(Less, TIME, Operand::Unsigned(5)),
            Filter::Compare(Less, TIME, Operand::Wide(5)),
            Filter::Compare(Less, Operand::WideFrameNumber, Operand::Unsigned(5)),
            Filter::Compare(Less, Operand::WideFrameNumber, Operand::Nanos(5)),
            // `<>`: the frames it holds for are not a range.
            Filter::Compare(CmpOp::NotEq, FRAME, Operand::Unsigned(5)),
            Filter::Compare(CmpOp::NotEq, Operand::WideFrameNumber, Operand::Wide(5)),
            Filter::Compare(CmpOp::NotEq, Operand::WideFrameNumber, Operand::Wide(-5)),
            Filter::Compare(CmpOp::NotEq, Operand::Nanos(5), TIME),
            // A NULL, a parameter, a cast, another column: anything that is not a constant.
            Filter::Compare(Equal, FRAME, Operand::Other),
            Filter::Compare(Equal, Operand::Other, TIME),
            Filter::Compare(Equal, Operand::Other, Operand::Unsigned(1)),
            Filter::Compare(Equal, Operand::Other, Operand::Other),
            // Two columns, two constants.
            Filter::Compare(Less, FRAME, FRAME),
            Filter::Compare(Less, FRAME, TIME),
            Filter::Compare(Less, FRAME, Operand::WideFrameNumber),
            Filter::Compare(Less, Operand::Unsigned(1), Operand::Unsigned(2)),
            Filter::Compare(Less, Operand::Nanos(1), Operand::Nanos(2)),
            // A range with a bound that is not a constant of the column's type, or that is
            // not on a column.
            Filter::Between(FRAME, Operand::Unsigned(1), Operand::Other),
            Filter::Between(FRAME, Operand::Other, Operand::Unsigned(9)),
            Filter::Between(FRAME, Operand::Unsigned(1), Operand::Wide(9)),
            Filter::Between(TIME, Operand::Nanos(1), Operand::Unsigned(9)),
            Filter::Between(Operand::Other, Operand::Unsigned(1), Operand::Unsigned(9)),
            Filter::Between(Operand::Unsigned(5), Operand::Unsigned(1), FRAME),
            // A conjunction without a part that is read, and one without parts.
            Filter::And(vec![
                Filter::Other,
                Filter::Compare(Equal, TIME, Operand::Other),
            ]),
            Filter::And(Vec::new()),
        ];
        for filter in not_read {
            assert_eq!(read(&filter), None, "{filter:?}");
        }
    }

    /// A range node is read with both bounds inclusive, whatever they are, and never taken
    /// for exact: for every way its bounds can be meant, no frame the filter holds for is
    /// missing.
    #[test]
    fn a_range_is_read_inclusively_and_is_not_exact() {
        for (lower, upper) in [(3_u64, 5_u64), (3, 3), (5, 3), (0, 2), (1, u64::MAX)] {
            let reading = read(&Filter::Between(
                FRAME,
                Operand::Unsigned(lower),
                Operand::Unsigned(upper),
            ))
            .unwrap();
            assert!(!reading.exact);
            assert_eq!(
                reading.predicate.frames,
                (Bound::Included(lower), Bound::Included(upper))
            );
            for frame in FRAMES {
                for (above, below) in [
                    (frame >= lower, frame <= upper),
                    (frame > lower, frame <= upper),
                    (frame >= lower, frame < upper),
                    (frame > lower, frame < upper),
                ] {
                    if above && below {
                        assert!(
                            accepts(&reading.predicate, frame, 0),
                            "[{lower}, {upper}]: {frame}"
                        );
                    }
                }
            }
        }
        // On a timestamp, and on a frame number DuckDB widened.
        let reading = read(&Filter::Between(
            TIME,
            Operand::Nanos(-7),
            Operand::Nanos(7),
        ))
        .unwrap();
        assert_eq!(
            reading,
            Reading {
                predicate: FramePredicate {
                    time_ns: (Bound::Included(-7), Bound::Included(7)),
                    ..FramePredicate::all()
                },
                exact: false
            }
        );
        let reading = read(&Filter::Between(
            Operand::WideFrameNumber,
            Operand::Wide(-7),
            Operand::Wide(7),
        ))
        .unwrap();
        assert!(!reading.exact);
        assert_eq!(
            reading.predicate.frames,
            (Bound::Unbounded, Bound::Included(7))
        );
        let reading = read(&Filter::Between(
            Operand::WideFrameNumber,
            Operand::Wide(-7),
            Operand::Wide(-2),
        ))
        .unwrap();
        assert!(reading.predicate.is_empty());
    }

    #[test]
    fn a_conjunction_is_the_intersection_of_its_parts() {
        let all_exact = Filter::And(vec![
            Filter::Compare(GreaterOrEqual, FRAME, Operand::Unsigned(3)),
            Filter::Compare(GreaterOrEqual, Operand::Unsigned(5), FRAME),
            Filter::And(vec![
                Filter::Compare(Greater, TIME, Operand::Nanos(-1)),
                Filter::Compare(Less, TIME, Operand::Nanos(1000)),
            ]),
        ]);
        let predicate = exact(&all_exact);
        assert_eq!(
            predicate,
            FramePredicate {
                frames: (Bound::Included(3), Bound::Included(5)),
                time_ns: (Bound::Excluded(-1), Bound::Excluded(1000)),
            }
        );
        for frame in FRAMES {
            for time in TIMES {
                assert_eq!(
                    accepts(&predicate, frame, time),
                    (3..=5).contains(&frame) && time > -1 && time < 1000
                );
            }
        }
        assert_eq!(
            describe(&predicate),
            "frame_number in [3, 5] and timestamp in (-1, 1000) ns"
        );

        // A part that is not read, or not exact, leaves the rest to narrow the frames, and
        // the conjunction to DuckDB.
        for part in [
            Filter::Other,
            Filter::Compare(Equal, TIME, Operand::Other),
            Filter::Between(TIME, Operand::Nanos(0), Operand::Nanos(9)),
            Filter::And(vec![Filter::Other]),
        ] {
            let narrowed = match read(&part) {
                Some(reading) => reading.predicate.time_ns,
                None => FramePredicate::all().time_ns,
            };
            let filter = Filter::And(vec![
                Filter::Compare(Less, FRAME, Operand::Unsigned(5)),
                part,
            ]);
            assert_eq!(
                read(&filter),
                Some(Reading {
                    predicate: FramePredicate {
                        frames: (Bound::Unbounded, Bound::Excluded(5)),
                        time_ns: narrowed,
                    },
                    exact: false
                }),
                "{filter:?}"
            );
        }
    }

    #[test]
    fn predicates_are_described_by_their_bounds() {
        assert_eq!(describe(&FramePredicate::all()), "every frame");
        assert_eq!(describe(&FramePredicate::none()), "no frame");
        let cases = [
            (
                Filter::Compare(Equal, FRAME, Operand::Unsigned(7)),
                "frame_number in [7, 7]",
            ),
            (
                Filter::Compare(Less, FRAME, Operand::Unsigned(7)),
                "frame_number in (.., 7)",
            ),
            (
                Filter::Compare(Greater, FRAME, Operand::Unsigned(7)),
                "frame_number in (7, ..)",
            ),
            (
                Filter::Compare(GreaterOrEqual, TIME, Operand::Nanos(-3)),
                "timestamp in [-3, ..) ns",
            ),
            (
                Filter::Compare(LessOrEqual, TIME, Operand::Nanos(1_700_000_000_000_000_001)),
                "timestamp in (.., 1700000000000000001] ns",
            ),
            // Inverted bounds accept nothing.
            (
                Filter::And(vec![
                    Filter::Compare(Greater, FRAME, Operand::Unsigned(7)),
                    Filter::Compare(Less, FRAME, Operand::Unsigned(8)),
                ]),
                "no frame",
            ),
        ];
        for (filter, text) in cases {
            assert_eq!(describe(&exact(&filter)), text, "{filter:?}");
        }
    }
}
