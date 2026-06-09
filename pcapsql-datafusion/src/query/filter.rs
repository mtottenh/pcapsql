//! Filter pushdown for streaming protocol table scans.
//!
//! DataFusion hands the conjuncts of a `WHERE` clause to
//! [`TableProvider::scan`](datafusion::datasource::TableProvider::scan). This
//! module compiles the conjuncts we understand into a [`PushdownPredicate`]
//! that the streaming scan evaluates against parsed packet fields *before*
//! materializing a row into Arrow. Non-matching packets still have their
//! headers parsed (there is no way to seek to "port 443"), but they skip
//! Arrow materialization entirely.
//!
//! # Correctness
//!
//! Pushed filters are reported as
//! [`TableProviderFilterPushDown::Inexact`](datafusion::logical_expr::TableProviderFilterPushDown),
//! so DataFusion re-applies them in a `FilterExec` above the scan. The scan
//! may therefore only drop rows that the `FilterExec` would also drop. To
//! guarantee this, evaluation mirrors exactly how `ProtocolBatchBuilder`
//! materializes a `FieldValue` into the column's Arrow type (including
//! null-on-type-mismatch and integer truncation), and uses SQL three-valued
//! logic: a row is dropped only when the predicate evaluates to FALSE or
//! NULL — precisely the rows a `WHERE` clause filters out.

use std::borrow::Cow;
use std::net::IpAddr;

use arrow::datatypes::{DataType, Schema, TimeUnit};
use datafusion::common::ScalarValue;
use datafusion::logical_expr::{Between, BinaryExpr, Expr, Operator};

use pcapsql_core::{FieldValue, OwnedParseResult, ParseResult};

/// Comparison operators for pushed-down predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

impl CompareOp {
    fn from_datafusion(op: &Operator) -> Option<Self> {
        match op {
            Operator::Eq => Some(CompareOp::Eq),
            Operator::NotEq => Some(CompareOp::NotEq),
            Operator::Lt => Some(CompareOp::Lt),
            Operator::LtEq => Some(CompareOp::LtEq),
            Operator::Gt => Some(CompareOp::Gt),
            Operator::GtEq => Some(CompareOp::GtEq),
            _ => None,
        }
    }

    /// Swap sides: `lit op col` becomes `col swapped(op) lit`.
    fn swap(self) -> Self {
        match self {
            CompareOp::Lt => CompareOp::Gt,
            CompareOp::LtEq => CompareOp::GtEq,
            CompareOp::Gt => CompareOp::Lt,
            CompareOp::GtEq => CompareOp::LtEq,
            other => other,
        }
    }

    fn compare<T: PartialOrd>(self, left: T, right: T) -> bool {
        match self {
            CompareOp::Eq => left == right,
            CompareOp::NotEq => left != right,
            CompareOp::Lt => left < right,
            CompareOp::LtEq => left <= right,
            CompareOp::Gt => left > right,
            CompareOp::GtEq => left >= right,
        }
    }
}

/// A pre-compiled literal value.
#[derive(Debug, Clone)]
enum Literal {
    /// Any integer-family literal (including timestamps in microseconds).
    Int(i128),
    /// A string literal. `canonical_ip` is set when the literal parses as an
    /// IP address whose canonical formatting round-trips, enabling
    /// allocation-free equality against `FieldValue::IpAddr`.
    Str {
        value: String,
        canonical_ip: Option<IpAddr>,
    },
    Bool(bool),
}

/// SQL three-valued logic result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    True,
    False,
    Null,
}

fn tri(b: bool) -> Tri {
    if b {
        Tri::True
    } else {
        Tri::False
    }
}

/// A predicate compiled from DataFusion filter expressions that can be
/// evaluated against parsed packet fields during a streaming scan.
#[derive(Debug, Clone)]
pub struct PushdownPredicate(Pred);

#[derive(Debug, Clone)]
enum Pred {
    /// `column <op> literal`
    Compare {
        column: String,
        column_type: DataType,
        op: CompareOp,
        value: Literal,
    },
    /// `column [NOT] IN (literal, ...)`
    InList {
        column: String,
        column_type: DataType,
        values: Vec<Literal>,
        negated: bool,
    },
    /// `column IS [NOT] NULL`
    IsNull {
        column: String,
        column_type: DataType,
        negated: bool,
    },
    /// All children must hold.
    And(Vec<Pred>),
    /// At least one child must hold.
    Or(Vec<Pred>),
}

/// Access to the fields of one row of a protocol table.
///
/// Implemented for both the borrowed [`ParseResult`] (uncached scan path)
/// and the owned [`OwnedParseResult`] (cached scan path).
pub trait PushdownFields {
    fn pushdown_field(&self, name: &str) -> Option<&FieldValue<'_>>;
    fn pushdown_encap_depth(&self) -> u8;
    fn pushdown_tunnel_type(&self) -> Option<&'static str>;
    fn pushdown_tunnel_id(&self) -> Option<u64>;
}

impl PushdownFields for ParseResult<'_> {
    fn pushdown_field(&self, name: &str) -> Option<&FieldValue<'_>> {
        self.get(name)
    }
    fn pushdown_encap_depth(&self) -> u8 {
        self.encap_depth
    }
    fn pushdown_tunnel_type(&self) -> Option<&'static str> {
        self.tunnel_type.as_str()
    }
    fn pushdown_tunnel_id(&self) -> Option<u64> {
        self.tunnel_id
    }
}

impl PushdownFields for OwnedParseResult {
    fn pushdown_field(&self, name: &str) -> Option<&FieldValue<'_>> {
        self.get(name)
    }
    fn pushdown_encap_depth(&self) -> u8 {
        self.encap_depth
    }
    fn pushdown_tunnel_type(&self) -> Option<&'static str> {
        self.tunnel_type.as_str()
    }
    fn pushdown_tunnel_id(&self) -> Option<u64> {
        self.tunnel_id
    }
}

/// Metadata of a raw frame, for evaluating predicates on the `frames` table
/// without parsing the packet.
#[derive(Debug, Clone, Copy)]
pub struct FrameRow {
    pub frame_number: u64,
    pub timestamp_us: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub link_type: u16,
}

impl PushdownPredicate {
    /// Try to compile a single filter expression against a table schema.
    ///
    /// Returns `None` when the expression contains anything the streaming
    /// scan cannot evaluate (unknown columns, unsupported types or
    /// operators); such filters are reported as `Unsupported` and DataFusion
    /// evaluates them entirely on its own.
    pub fn try_compile(expr: &Expr, schema: &Schema) -> Option<Self> {
        Pred::try_compile(expr, schema).map(PushdownPredicate)
    }

    /// Compile all pushable filters into a single conjunctive predicate.
    ///
    /// Filters that cannot be compiled are skipped; DataFusion applies them
    /// itself. Returns `None` if no filter is pushable.
    pub fn compile_all(filters: &[Expr], schema: &Schema) -> Option<Self> {
        let mut preds: Vec<Pred> = filters
            .iter()
            .filter_map(|f| Pred::try_compile(f, schema))
            .collect();
        match preds.len() {
            0 => None,
            1 => preds.pop().map(PushdownPredicate),
            _ => Some(PushdownPredicate(Pred::And(preds))),
        }
    }

    /// Evaluate against one row of a protocol table.
    ///
    /// Returns `false` only when the row would also be dropped by the
    /// re-applied filter above the scan (predicate is FALSE or NULL).
    pub fn matches_row<R: PushdownFields>(&self, frame_number: u64, row: &R) -> bool {
        self.0.eval(&|name| match name {
            "frame_number" => Some(FieldValue::UInt64(frame_number)),
            "encap_depth" => Some(FieldValue::UInt8(row.pushdown_encap_depth())),
            "tunnel_type" => Some(
                row.pushdown_tunnel_type()
                    .map_or(FieldValue::Null, FieldValue::Str),
            ),
            "tunnel_id" => Some(
                row.pushdown_tunnel_id()
                    .map_or(FieldValue::Null, FieldValue::UInt64),
            ),
            _ => row.pushdown_field(name).map(reborrow),
        }) == Tri::True
    }

    /// Evaluate against a raw frame (for the `frames` table).
    pub fn matches_frame(&self, frame: &FrameRow) -> bool {
        self.0.eval(&|name| match name {
            "frame_number" => Some(FieldValue::UInt64(frame.frame_number)),
            "timestamp" => Some(FieldValue::Int64(frame.timestamp_us)),
            "length" => Some(FieldValue::UInt32(frame.captured_len)),
            "original_length" => Some(FieldValue::UInt32(frame.original_len)),
            "link_type" => Some(FieldValue::UInt16(frame.link_type)),
            _ => None,
        }) == Tri::True
    }

    /// Upper bound on `frame_number` implied by this predicate, if any.
    ///
    /// Frames are read in order, so a bound lets the scan stop reading the
    /// file early (e.g. `WHERE frame_number <= 1000`).
    pub fn max_frame_number(&self) -> Option<u64> {
        self.0.max_frame_number()
    }
}

impl Pred {
    fn try_compile(expr: &Expr, schema: &Schema) -> Option<Self> {
        match expr {
            Expr::BinaryExpr(BinaryExpr { left, op, right }) => match op {
                Operator::And => Some(Pred::And(vec![
                    Self::try_compile(left, schema)?,
                    Self::try_compile(right, schema)?,
                ])),
                Operator::Or => Some(Pred::Or(vec![
                    Self::try_compile(left, schema)?,
                    Self::try_compile(right, schema)?,
                ])),
                _ => {
                    let op = CompareOp::from_datafusion(op)?;
                    match (left.as_ref(), right.as_ref()) {
                        (Expr::Column(col), Expr::Literal(lit, _)) => {
                            Self::compile_compare(&col.name, op, lit, schema)
                        }
                        (Expr::Literal(lit, _), Expr::Column(col)) => {
                            Self::compile_compare(&col.name, op.swap(), lit, schema)
                        }
                        _ => None,
                    }
                }
            },
            Expr::InList(in_list) => {
                let Expr::Column(col) = in_list.expr.as_ref() else {
                    return None;
                };
                let column_type = column_type(&col.name, schema)?;
                let values = in_list
                    .list
                    .iter()
                    .map(|e| match e {
                        Expr::Literal(lit, _) => convert_literal(lit, &column_type),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                if values.is_empty() {
                    return None;
                }
                Some(Pred::InList {
                    column: col.name.clone(),
                    column_type,
                    values,
                    negated: in_list.negated,
                })
            }
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => {
                let Expr::Column(col) = inner.as_ref() else {
                    return None;
                };
                let column_type = column_type(&col.name, schema)?;
                Some(Pred::IsNull {
                    column: col.name.clone(),
                    column_type,
                    negated: matches!(expr, Expr::IsNotNull(_)),
                })
            }
            Expr::Between(Between {
                expr: inner,
                negated,
                low,
                high,
            }) => {
                let Expr::Column(col) = inner.as_ref() else {
                    return None;
                };
                let (Expr::Literal(low, _), Expr::Literal(high, _)) = (low.as_ref(), high.as_ref())
                else {
                    return None;
                };
                let lower = Self::compile_compare(&col.name, CompareOp::GtEq, low, schema)?;
                let upper = Self::compile_compare(&col.name, CompareOp::LtEq, high, schema)?;
                if *negated {
                    // x NOT BETWEEN l AND h  ==  x < l OR x > h
                    let below = Self::compile_compare(&col.name, CompareOp::Lt, low, schema)?;
                    let above = Self::compile_compare(&col.name, CompareOp::Gt, high, schema)?;
                    Some(Pred::Or(vec![below, above]))
                } else {
                    Some(Pred::And(vec![lower, upper]))
                }
            }
            _ => None,
        }
    }

    fn compile_compare(
        column: &str,
        op: CompareOp,
        literal: &ScalarValue,
        schema: &Schema,
    ) -> Option<Self> {
        let column_type = column_type(column, schema)?;
        let value = convert_literal(literal, &column_type)?;
        // Ordering on booleans is not worth mirroring; reject it.
        if matches!(value, Literal::Bool(_)) && !matches!(op, CompareOp::Eq | CompareOp::NotEq) {
            return None;
        }
        Some(Pred::Compare {
            column: column.to_string(),
            column_type,
            op,
            value,
        })
    }

    /// Upper bound on `frame_number` implied by this predicate, if any.
    ///
    /// Frames are read in order, so a bound lets the scan stop reading the
    /// file early (e.g. `WHERE frame_number <= 1000`).
    fn max_frame_number(&self) -> Option<u64> {
        match self {
            Pred::Compare {
                column,
                op,
                value: Literal::Int(v),
                ..
            } if column == "frame_number" => match op {
                CompareOp::Eq | CompareOp::LtEq => Some((*v).clamp(0, u64::MAX as i128) as u64),
                CompareOp::Lt => Some((*v - 1).clamp(0, u64::MAX as i128) as u64),
                _ => None,
            },
            Pred::InList {
                column,
                values,
                negated: false,
                ..
            } if column == "frame_number" => values
                .iter()
                .map(|v| match v {
                    Literal::Int(v) => Some((*v).clamp(0, u64::MAX as i128) as u64),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .max(),
            // A conjunction is bounded by its tightest bounded conjunct.
            Pred::And(preds) => preds.iter().filter_map(|p| p.max_frame_number()).min(),
            // A disjunction is bounded only if every branch is bounded.
            Pred::Or(preds) => preds
                .iter()
                .map(|p| p.max_frame_number())
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .max(),
            _ => None,
        }
    }

    /// Evaluate with SQL three-valued logic.
    ///
    /// `resolve` returns the row's value for a column, or `None` when the
    /// column is absent from the row (materializes as NULL).
    fn eval<'a, F>(&self, resolve: &F) -> Tri
    where
        F: Fn(&str) -> Option<FieldValue<'a>>,
    {
        match self {
            Pred::Compare {
                column,
                column_type,
                op,
                value,
            } => match resolve(column) {
                Some(field) => eval_compare(column_type, &field, *op, value),
                None => Tri::Null,
            },
            Pred::InList {
                column,
                column_type,
                values,
                negated,
            } => match resolve(column) {
                Some(field) => eval_in_list(column_type, &field, values, *negated),
                None => Tri::Null,
            },
            Pred::IsNull {
                column,
                column_type,
                negated,
            } => {
                let is_null = match resolve(column) {
                    None => true,
                    Some(field) => materializes_null(column_type, &field),
                };
                tri(is_null != *negated)
            }
            Pred::And(preds) => {
                let mut result = Tri::True;
                for p in preds {
                    match p.eval(resolve) {
                        Tri::False => return Tri::False,
                        Tri::Null => result = Tri::Null,
                        Tri::True => {}
                    }
                }
                result
            }
            Pred::Or(preds) => {
                let mut result = Tri::False;
                for p in preds {
                    match p.eval(resolve) {
                        Tri::True => return Tri::True,
                        Tri::Null => result = Tri::Null,
                        Tri::False => {}
                    }
                }
                result
            }
        }
    }
}

/// Look up a column's Arrow type, returning `None` for columns or types the
/// pushdown evaluator does not support.
fn column_type(column: &str, schema: &Schema) -> Option<DataType> {
    let dt = schema.field_with_name(column).ok()?.data_type().clone();
    match dt {
        DataType::UInt8
        | DataType::UInt16
        | DataType::UInt32
        | DataType::UInt64
        | DataType::Int32
        | DataType::Int64
        | DataType::Timestamp(TimeUnit::Microsecond, _)
        | DataType::Utf8
        | DataType::Boolean => Some(dt),
        _ => None,
    }
}

/// Convert a literal into a pre-compiled value compatible with the column's
/// Arrow type. NULL literals are rejected (DataFusion simplifies those away).
fn convert_literal(literal: &ScalarValue, column_type: &DataType) -> Option<Literal> {
    let int_column = matches!(
        column_type,
        DataType::UInt8
            | DataType::UInt16
            | DataType::UInt32
            | DataType::UInt64
            | DataType::Int32
            | DataType::Int64
            | DataType::Timestamp(TimeUnit::Microsecond, _)
    );
    match literal {
        ScalarValue::Int8(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::Int16(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::Int32(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::Int64(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::UInt8(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::UInt16(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::UInt32(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::UInt64(Some(v)) if int_column => Some(Literal::Int(*v as i128)),
        ScalarValue::TimestampMicrosecond(Some(v), _)
            if matches!(column_type, DataType::Timestamp(TimeUnit::Microsecond, _)) =>
        {
            Some(Literal::Int(*v as i128))
        }
        ScalarValue::Utf8(Some(s))
        | ScalarValue::LargeUtf8(Some(s))
        | ScalarValue::Utf8View(Some(s))
            if *column_type == DataType::Utf8 =>
        {
            let canonical_ip = s.parse::<IpAddr>().ok().filter(|ip| ip.to_string() == *s);
            Some(Literal::Str {
                value: s.clone(),
                canonical_ip,
            })
        }
        ScalarValue::Boolean(Some(b)) if *column_type == DataType::Boolean => {
            Some(Literal::Bool(*b))
        }
        _ => None,
    }
}

/// Re-borrow a field value so the evaluator can also construct synthetic
/// values (frame_number, encap_depth, ...) without cloning owned data.
fn reborrow<'a>(v: &'a FieldValue<'a>) -> FieldValue<'a> {
    match v {
        FieldValue::UInt8(x) => FieldValue::UInt8(*x),
        FieldValue::UInt16(x) => FieldValue::UInt16(*x),
        FieldValue::UInt32(x) => FieldValue::UInt32(*x),
        FieldValue::UInt64(x) => FieldValue::UInt64(*x),
        FieldValue::Int64(x) => FieldValue::Int64(*x),
        FieldValue::Bool(x) => FieldValue::Bool(*x),
        FieldValue::IpAddr(x) => FieldValue::IpAddr(*x),
        FieldValue::MacAddr(x) => FieldValue::MacAddr(*x),
        FieldValue::Str(s) => FieldValue::Str(s),
        FieldValue::OwnedString(s) => FieldValue::Str(s.as_str()),
        FieldValue::Bytes(b) => FieldValue::Bytes(b),
        FieldValue::OwnedBytes(b) => FieldValue::Bytes(b.as_slice()),
        // Lists only materialize into List columns, which are rejected at
        // compile time; for supported column types they materialize as NULL.
        FieldValue::List(_) => FieldValue::Null,
        FieldValue::Null => FieldValue::Null,
    }
}

fn eval_compare(column_type: &DataType, field: &FieldValue, op: CompareOp, value: &Literal) -> Tri {
    match value {
        Literal::Int(v) => match materialized_int(column_type, field) {
            Some(x) => tri(op.compare(x, *v)),
            None => Tri::Null,
        },
        Literal::Str {
            value,
            canonical_ip,
        } => {
            // Fast path: equality against an IP field without formatting.
            if let (FieldValue::IpAddr(addr), Some(ip)) = (field, canonical_ip) {
                match op {
                    CompareOp::Eq => return tri(addr == ip),
                    CompareOp::NotEq => return tri(addr != ip),
                    _ => {}
                }
            }
            match materialized_str(field) {
                Some(s) => tri(op.compare(s.as_ref(), value.as_str())),
                None => Tri::Null,
            }
        }
        Literal::Bool(v) => match field {
            FieldValue::Bool(b) => tri(op.compare(*b, *v)),
            _ => Tri::Null,
        },
    }
}

fn eval_in_list(
    column_type: &DataType,
    field: &FieldValue,
    values: &[Literal],
    negated: bool,
) -> Tri {
    let mut found = false;
    for value in values {
        match eval_compare(column_type, field, CompareOp::Eq, value) {
            Tri::True => {
                found = true;
                break;
            }
            Tri::Null => return Tri::Null,
            Tri::False => {}
        }
    }
    tri(found != negated)
}

/// Whether a present field value would materialize as NULL in a column of
/// the given type. Mirrors `ProtocolBatchBuilder`'s type coercion.
fn materializes_null(column_type: &DataType, field: &FieldValue) -> bool {
    match column_type {
        DataType::Utf8 => materialized_str(field).is_none(),
        DataType::Boolean => !matches!(field, FieldValue::Bool(_)),
        _ => materialized_int(column_type, field).is_none(),
    }
}

/// The integer value a field would materialize as in a column of the given
/// type, or `None` if it would materialize as NULL.
///
/// This mirrors `DynamicBuilder::append_field_value` exactly, including its
/// truncating `as` casts, so comparisons agree with what `FilterExec` sees.
fn materialized_int(column_type: &DataType, field: &FieldValue) -> Option<i128> {
    use FieldValue::*;
    match column_type {
        DataType::UInt8 => match field {
            UInt8(v) => Some(*v as i128),
            UInt16(v) => Some((*v as u8) as i128),
            UInt32(v) => Some((*v as u8) as i128),
            UInt64(v) => Some((*v as u8) as i128),
            _ => None,
        },
        DataType::UInt16 => match field {
            UInt16(v) => Some(*v as i128),
            UInt8(v) => Some(*v as i128),
            UInt32(v) => Some((*v as u16) as i128),
            UInt64(v) => Some((*v as u16) as i128),
            _ => None,
        },
        DataType::UInt32 => match field {
            UInt32(v) => Some(*v as i128),
            UInt8(v) => Some(*v as i128),
            UInt16(v) => Some(*v as i128),
            UInt64(v) => Some((*v as u32) as i128),
            IpAddr(std::net::IpAddr::V4(v4)) => Some(u32::from(*v4) as i128),
            _ => None,
        },
        DataType::UInt64 => match field {
            UInt64(v) => Some(*v as i128),
            UInt8(v) => Some(*v as i128),
            UInt16(v) => Some(*v as i128),
            UInt32(v) => Some(*v as i128),
            _ => None,
        },
        DataType::Int32 => match field {
            UInt8(v) => Some((*v as i32) as i128),
            UInt16(v) => Some((*v as i32) as i128),
            UInt32(v) => Some((*v as i32) as i128),
            Int64(v) => Some((*v as i32) as i128),
            _ => None,
        },
        DataType::Int64 => match field {
            Int64(v) => Some(*v as i128),
            UInt8(v) => Some(*v as i128),
            UInt16(v) => Some(*v as i128),
            UInt32(v) => Some(*v as i128),
            UInt64(v) => Some((*v as i64) as i128),
            _ => None,
        },
        DataType::Timestamp(TimeUnit::Microsecond, _) => match field {
            Int64(v) => Some(*v as i128),
            UInt64(v) => Some((*v as i64) as i128),
            _ => None,
        },
        _ => None,
    }
}

/// The string a field would materialize as in a Utf8 column, or `None` if it
/// would materialize as NULL. Mirrors `DynamicBuilder`'s Utf8 arm.
fn materialized_str<'a>(field: &'a FieldValue<'a>) -> Option<Cow<'a, str>> {
    match field {
        FieldValue::Str(s) => Some(Cow::Borrowed(s)),
        FieldValue::OwnedString(s) => Some(Cow::Borrowed(s.as_str())),
        FieldValue::IpAddr(addr) => Some(Cow::Owned(addr.to_string())),
        FieldValue::MacAddr(mac) => Some(Cow::Owned(FieldValue::format_mac(mac))),
        FieldValue::Null => None,
        other => other.as_string().map(Cow::Owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::datatypes::Field;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;
    use pcapsql_core::TunnelType;
    use smallvec::SmallVec;
    use std::net::{IpAddr, Ipv4Addr};

    fn tcp_schema() -> Schema {
        Schema::new(vec![
            Field::new("frame_number", DataType::UInt64, false),
            Field::new("src_port", DataType::UInt16, true),
            Field::new("dst_port", DataType::UInt16, true),
            Field::new("options", DataType::Utf8, true),
            Field::new("flag_syn", DataType::Boolean, true),
            Field::new("mss", DataType::UInt16, true),
            Field::new("tunnel_type", DataType::Utf8, true),
            Field::new(
                "sack_left_edges",
                DataType::List(std::sync::Arc::new(Field::new(
                    "item",
                    DataType::UInt32,
                    true,
                ))),
                true,
            ),
        ])
    }

    fn tcp_row() -> ParseResult<'static> {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(12345)));
        fields.push(("dst_port", FieldValue::UInt16(443)));
        fields.push(("flag_syn", FieldValue::Bool(true)));
        ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    fn compile(expr: Expr) -> Option<PushdownPredicate> {
        PushdownPredicate::try_compile(&expr, &tcp_schema())
    }

    #[test]
    fn test_compare_eq() {
        let pred = compile(col("dst_port").eq(lit(443u16))).unwrap();
        assert!(pred.matches_row(1, &tcp_row()));

        let pred = compile(col("dst_port").eq(lit(80u16))).unwrap();
        assert!(!pred.matches_row(1, &tcp_row()));
    }

    #[test]
    fn test_compare_ordering() {
        let pred = compile(col("src_port").gt(lit(1024i32))).unwrap();
        assert!(pred.matches_row(1, &tcp_row()));

        let pred = compile(col("src_port").lt(lit(1024i32))).unwrap();
        assert!(!pred.matches_row(1, &tcp_row()));
    }

    #[test]
    fn test_literal_on_left() {
        // 443 <= dst_port  ==  dst_port >= 443
        let pred = compile(lit(443i32).lt_eq(col("dst_port"))).unwrap();
        assert!(pred.matches_row(1, &tcp_row()));

        let pred = compile(lit(444i32).lt_eq(col("dst_port"))).unwrap();
        assert!(!pred.matches_row(1, &tcp_row()));
    }

    #[test]
    fn test_null_field_drops_row() {
        // mss is absent from the row: any comparison is NULL, so the row is
        // dropped — matching what FilterExec would do.
        let pred = compile(col("mss").eq(lit(1460i32))).unwrap();
        assert!(!pred.matches_row(1, &tcp_row()));

        // NotEq against a NULL field is also NULL, not true.
        let pred = compile(col("mss").not_eq(lit(1460i32))).unwrap();
        assert!(!pred.matches_row(1, &tcp_row()));
    }

    #[test]
    fn test_and_or() {
        let row = tcp_row();

        let pred = compile(
            col("dst_port")
                .eq(lit(443i32))
                .and(col("src_port").gt(lit(1000i32))),
        )
        .unwrap();
        assert!(pred.matches_row(1, &row));

        let pred = compile(
            col("dst_port")
                .eq(lit(80i32))
                .or(col("src_port").eq(lit(12345i32))),
        )
        .unwrap();
        assert!(pred.matches_row(1, &row));

        let pred = compile(
            col("dst_port")
                .eq(lit(80i32))
                .or(col("src_port").eq(lit(1i32))),
        )
        .unwrap();
        assert!(!pred.matches_row(1, &row));

        // OR where one side is NULL and the other false: NULL -> dropped.
        let pred = compile(
            col("mss")
                .eq(lit(1460i32))
                .or(col("dst_port").eq(lit(80i32))),
        )
        .unwrap();
        assert!(!pred.matches_row(1, &row));

        // OR where one side is NULL and the other true: TRUE -> kept.
        let pred = compile(
            col("mss")
                .eq(lit(1460i32))
                .or(col("dst_port").eq(lit(443i32))),
        )
        .unwrap();
        assert!(pred.matches_row(1, &row));
    }

    #[test]
    fn test_in_list() {
        let row = tcp_row();

        let pred = compile(col("dst_port").in_list(vec![lit(80i32), lit(443i32)], false)).unwrap();
        assert!(pred.matches_row(1, &row));

        let pred = compile(col("dst_port").in_list(vec![lit(80i32), lit(8080i32)], false)).unwrap();
        assert!(!pred.matches_row(1, &row));

        let pred = compile(col("dst_port").in_list(vec![lit(80i32), lit(8080i32)], true)).unwrap();
        assert!(pred.matches_row(1, &row));

        // NULL field: IN and NOT IN are both NULL -> dropped.
        let pred = compile(col("mss").in_list(vec![lit(1460i32)], true)).unwrap();
        assert!(!pred.matches_row(1, &row));
    }

    #[test]
    fn test_is_null() {
        let row = tcp_row();

        let pred = compile(col("mss").is_null()).unwrap();
        assert!(pred.matches_row(1, &row));

        let pred = compile(col("mss").is_not_null()).unwrap();
        assert!(!pred.matches_row(1, &row));

        let pred = compile(col("dst_port").is_not_null()).unwrap();
        assert!(pred.matches_row(1, &row));
    }

    #[test]
    fn test_between() {
        let row = tcp_row();

        let pred = compile(col("dst_port").between(lit(100i32), lit(500i32))).unwrap();
        assert!(pred.matches_row(1, &row));

        let pred = compile(col("dst_port").not_between(lit(100i32), lit(500i32))).unwrap();
        assert!(!pred.matches_row(1, &row));
    }

    #[test]
    fn test_boolean_column() {
        let row = tcp_row();

        let pred = compile(col("flag_syn").eq(lit(true))).unwrap();
        assert!(pred.matches_row(1, &row));

        let pred = compile(col("flag_syn").eq(lit(false))).unwrap();
        assert!(!pred.matches_row(1, &row));

        // Ordering on booleans is rejected.
        assert!(compile(col("flag_syn").gt(lit(false))).is_none());
    }

    #[test]
    fn test_frame_number_synthetic_column() {
        let pred = compile(col("frame_number").lt_eq(lit(10i64))).unwrap();
        assert!(pred.matches_row(5, &tcp_row()));
        assert!(!pred.matches_row(11, &tcp_row()));
        assert_eq!(pred.max_frame_number(), Some(10));
    }

    #[test]
    fn test_max_frame_number_bounds() {
        let schema = tcp_schema();
        let c = |e: Expr| PushdownPredicate::try_compile(&e, &schema).unwrap();

        assert_eq!(
            c(col("frame_number").eq(lit(7i64))).max_frame_number(),
            Some(7)
        );
        assert_eq!(
            c(col("frame_number").lt(lit(7i64))).max_frame_number(),
            Some(6)
        );
        assert_eq!(
            c(col("frame_number").gt(lit(7i64))).max_frame_number(),
            None
        );
        assert_eq!(
            c(col("frame_number")
                .lt(lit(7i64))
                .and(col("dst_port").eq(lit(443i32))))
            .max_frame_number(),
            Some(6)
        );
        // OR is only bounded when every branch is bounded.
        assert_eq!(
            c(col("frame_number")
                .eq(lit(3i64))
                .or(col("frame_number").eq(lit(9i64))))
            .max_frame_number(),
            Some(9)
        );
        assert_eq!(
            c(col("frame_number")
                .eq(lit(3i64))
                .or(col("dst_port").eq(lit(443i32))))
            .max_frame_number(),
            None
        );
    }

    #[test]
    fn test_unsupported_expressions() {
        // Unknown column.
        assert!(compile(col("nonexistent").eq(lit(1i32))).is_none());
        // List-typed column.
        assert!(compile(col("sack_left_edges").is_null()).is_none());
        // Column-to-column comparison.
        assert!(compile(col("src_port").eq(col("dst_port"))).is_none());
        // AND with an unsupported side is rejected as a whole (DataFusion
        // keeps the original conjunct, so nothing is lost).
        assert!(compile(
            col("src_port")
                .eq(col("dst_port"))
                .and(col("dst_port").eq(lit(443i32)))
        )
        .is_none());
    }

    #[test]
    fn test_compile_all_skips_unsupported() {
        let schema = tcp_schema();
        let filters = vec![
            col("dst_port").eq(lit(443i32)),
            col("src_port").eq(col("dst_port")), // unsupported
        ];
        let pred = PushdownPredicate::compile_all(&filters, &schema).unwrap();
        assert!(pred.matches_row(1, &tcp_row()));

        let none = PushdownPredicate::compile_all(&[col("src_port").eq(col("dst_port"))], &schema);
        assert!(none.is_none());
    }

    #[test]
    fn test_ip_string_column() {
        // A Utf8 column holding an IpAddr field value (e.g. arp tables).
        let schema = Schema::new(vec![Field::new("sender_ip", DataType::Utf8, true)]);
        let mut fields = SmallVec::new();
        fields.push((
            "sender_ip",
            FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ));
        let row = ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        };

        let pred =
            PushdownPredicate::try_compile(&col("sender_ip").eq(lit("192.168.1.1")), &schema)
                .unwrap();
        assert!(pred.matches_row(1, &row));

        let pred =
            PushdownPredicate::try_compile(&col("sender_ip").eq(lit("10.0.0.1")), &schema).unwrap();
        assert!(!pred.matches_row(1, &row));
    }

    #[test]
    fn test_owned_parse_result_row() {
        let parsed = tcp_row();
        let owned = OwnedParseResult::from_parse_result(&parsed);

        let pred = compile(col("dst_port").eq(lit(443i32))).unwrap();
        assert!(pred.matches_row(1, &owned));

        let pred = compile(col("dst_port").eq(lit(80i32))).unwrap();
        assert!(!pred.matches_row(1, &owned));
    }

    #[test]
    fn test_matches_frame() {
        let schema = Schema::new(vec![
            Field::new("frame_number", DataType::UInt64, false),
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("length", DataType::UInt32, false),
        ]);
        let frame = FrameRow {
            frame_number: 5,
            timestamp_us: 1_000_000,
            captured_len: 64,
            original_len: 64,
            link_type: 1,
        };

        let pred = PushdownPredicate::try_compile(&col("length").gt(lit(100i32)), &schema).unwrap();
        assert!(!pred.matches_frame(&frame));

        let pred =
            PushdownPredicate::try_compile(&col("length").lt_eq(lit(64i32)), &schema).unwrap();
        assert!(pred.matches_frame(&frame));

        let pred =
            PushdownPredicate::try_compile(&col("frame_number").eq(lit(5i64)), &schema).unwrap();
        assert!(pred.matches_frame(&frame));
    }

    #[test]
    fn test_truncating_cast_mirrors_builder() {
        // A UInt16 field of 300 stored in a UInt8 column truncates to 44 in
        // the builder; the evaluator must agree with the materialized value.
        let schema = Schema::new(vec![Field::new("ttl", DataType::UInt8, true)]);
        let mut fields = SmallVec::new();
        fields.push(("ttl", FieldValue::UInt16(300)));
        let row = ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        };

        let pred = PushdownPredicate::try_compile(&col("ttl").eq(lit(44i32)), &schema).unwrap();
        assert!(pred.matches_row(1, &row));
        let pred = PushdownPredicate::try_compile(&col("ttl").eq(lit(300i32)), &schema).unwrap();
        assert!(!pred.matches_row(1, &row));
    }
}
