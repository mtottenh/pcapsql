//! Parse-time predicate evaluation for scoped parsing.
//!
//! Converts simple DataFusion `WHERE` expressions (pushed into `TableScan`s
//! as `Inexact` filters) into predicates evaluated against a protocol's
//! [`ParseResult`] *before* a row is materialized into Arrow.
//!
//! Evaluation is **table-scoped and conservative**: a field is resolved only
//! within the row's own protocol layer, and any uncertainty — missing field,
//! type mismatch, unsupported expression shape — keeps the row. DataFusion
//! re-applies the original filter (`Inexact` pushdown), so a kept row can
//! never produce a wrong result; only a *positively false* comparison may
//! drop a row early.

use datafusion::common::ScalarValue;
use datafusion::logical_expr::{BinaryExpr, Expr, Operator};

use pcapsql_core::{FieldValue, ParseResult};

/// Comparison operators for predicates.
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
    /// Convert from DataFusion operator.
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

    /// Evaluate comparison between two i64 values.
    fn compare_i64(self, left: i64, right: i64) -> bool {
        match self {
            CompareOp::Eq => left == right,
            CompareOp::NotEq => left != right,
            CompareOp::Lt => left < right,
            CompareOp::LtEq => left <= right,
            CompareOp::Gt => left > right,
            CompareOp::GtEq => left >= right,
        }
    }

    /// Evaluate comparison between two strings.
    fn compare_str(self, left: &str, right: &str) -> bool {
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

/// A simple predicate evaluable against one protocol layer's fields.
#[derive(Debug, Clone)]
pub enum SimplePredicate {
    /// String comparison: `column <op> 'value'`.
    StringCompare {
        field: String,
        op: CompareOp,
        value: String,
    },
    /// Integer comparison: `column <op> value`.
    IntCompare {
        field: String,
        op: CompareOp,
        value: i64,
    },
    /// AND of two predicates.
    And(Box<SimplePredicate>, Box<SimplePredicate>),
    /// Always keep the row (unsupported shape; DataFusion re-checks).
    AlwaysTrue,
}

/// Resolve a field value to i64 the way the Arrow column would compare.
///
/// IPv4 addresses map to their `u32` column representation. Anything not
/// confidently mappable returns `None` (⇒ keep the row).
fn field_as_i64(value: &FieldValue) -> Option<i64> {
    match value {
        FieldValue::UInt8(v) => Some(*v as i64),
        FieldValue::UInt16(v) => Some(*v as i64),
        FieldValue::UInt32(v) => Some(*v as i64),
        FieldValue::UInt64(v) => i64::try_from(*v).ok(),
        FieldValue::Int64(v) => Some(*v),
        FieldValue::Bool(v) => Some(*v as i64),
        FieldValue::IpAddr(std::net::IpAddr::V4(v4)) => Some(u32::from(*v4) as i64),
        _ => None,
    }
}

/// Resolve a field value to a string only when the Arrow column is a string.
fn field_as_str<'v>(value: &'v FieldValue) -> Option<&'v str> {
    match value {
        FieldValue::Str(s) => Some(s),
        FieldValue::OwnedString(s) => Some(s.as_str()),
        _ => None,
    }
}

impl SimplePredicate {
    /// Evaluate against one protocol layer's parse result.
    ///
    /// Returns `false` only for a positively-false comparison; any
    /// uncertainty keeps the row.
    pub fn matches_result(&self, result: &ParseResult<'_>) -> bool {
        match self {
            SimplePredicate::StringCompare { field, op, value } => {
                match result.get(field).and_then(field_as_str) {
                    Some(s) => op.compare_str(s, value),
                    None => true, // unknown ⇒ keep; DataFusion decides
                }
            }
            SimplePredicate::IntCompare { field, op, value } => {
                match result.get(field).and_then(field_as_i64) {
                    Some(v) => op.compare_i64(v, *value),
                    None => true,
                }
            }
            SimplePredicate::And(left, right) => {
                left.matches_result(result) && right.matches_result(result)
            }
            SimplePredicate::AlwaysTrue => true,
        }
    }

    /// True when this predicate can never drop a row.
    pub fn is_always_true(&self) -> bool {
        match self {
            SimplePredicate::AlwaysTrue => true,
            SimplePredicate::And(l, r) => l.is_always_true() && r.is_always_true(),
            _ => false,
        }
    }
}

/// Parse-time filter for one table's scan.
#[derive(Debug, Clone)]
pub struct FilterEvaluator {
    predicate: SimplePredicate,
}

impl FilterEvaluator {
    /// Build an evaluator from a scan's pushed-down filter expressions.
    ///
    /// Returns `None` when nothing useful can be evaluated at parse time
    /// (every expression converts to [`SimplePredicate::AlwaysTrue`]).
    pub fn try_from_exprs(exprs: &[Expr]) -> Option<Self> {
        if exprs.is_empty() {
            return None;
        }

        let predicates: Vec<SimplePredicate> = exprs.iter().map(convert_expr).collect();
        let predicate = predicates
            .into_iter()
            .reduce(|acc, pred| SimplePredicate::And(Box::new(acc), Box::new(pred)))
            .unwrap_or(SimplePredicate::AlwaysTrue);

        if predicate.is_always_true() {
            return None;
        }
        Some(Self { predicate })
    }

    /// Whether an expression contributes a parse-time-evaluable predicate
    /// (drives the provider's `Inexact` vs `Unsupported` pushdown answer).
    pub fn expr_is_pushable(expr: &Expr) -> bool {
        !convert_expr(expr).is_always_true()
    }

    /// Evaluate against one protocol layer's parse result (conservative).
    pub fn matches_result(&self, result: &ParseResult<'_>) -> bool {
        self.predicate.matches_result(result)
    }
}

/// Convert a DataFusion expression to a simple predicate (conservative:
/// anything unsupported becomes [`SimplePredicate::AlwaysTrue`]).
fn convert_expr(expr: &Expr) -> SimplePredicate {
    match expr {
        Expr::BinaryExpr(BinaryExpr { left, op, right }) => {
            convert_binary_expr(left.as_ref(), op, right.as_ref())
        }
        _ => SimplePredicate::AlwaysTrue,
    }
}

/// Convert a binary expression to a simple predicate.
fn convert_binary_expr(left: &Expr, op: &Operator, right: &Expr) -> SimplePredicate {
    // AND splits; both sides evaluated conservatively.
    if *op == Operator::And {
        return SimplePredicate::And(Box::new(convert_expr(left)), Box::new(convert_expr(right)));
    }

    // OR cannot be short-circuited conservatively per side: keep the row.
    if *op == Operator::Or {
        return SimplePredicate::AlwaysTrue;
    }

    let Some(compare_op) = CompareOp::from_datafusion(op) else {
        return SimplePredicate::AlwaysTrue;
    };

    // column <op> literal
    if let (Expr::Column(col), Expr::Literal(lit, _)) = (left, right) {
        return convert_column_literal_compare(&col.name, compare_op, lit);
    }

    // literal <op> column (reverse the operator)
    if let (Expr::Literal(lit, _), Expr::Column(col)) = (left, right) {
        let reversed_op = match compare_op {
            CompareOp::Lt => CompareOp::Gt,
            CompareOp::LtEq => CompareOp::GtEq,
            CompareOp::Gt => CompareOp::Lt,
            CompareOp::GtEq => CompareOp::LtEq,
            other => other,
        };
        return convert_column_literal_compare(&col.name, reversed_op, lit);
    }

    SimplePredicate::AlwaysTrue
}

/// Convert a column-vs-literal comparison to a simple predicate.
fn convert_column_literal_compare(
    column: &str,
    op: CompareOp,
    literal: &ScalarValue,
) -> SimplePredicate {
    match literal {
        ScalarValue::Utf8(Some(s)) | ScalarValue::LargeUtf8(Some(s)) => {
            SimplePredicate::StringCompare {
                field: column.to_string(),
                op,
                value: s.clone(),
            }
        }
        ScalarValue::Int8(Some(v)) => int_compare(column, op, *v as i64),
        ScalarValue::Int16(Some(v)) => int_compare(column, op, *v as i64),
        ScalarValue::Int32(Some(v)) => int_compare(column, op, *v as i64),
        ScalarValue::Int64(Some(v)) => int_compare(column, op, *v),
        ScalarValue::UInt8(Some(v)) => int_compare(column, op, *v as i64),
        ScalarValue::UInt16(Some(v)) => int_compare(column, op, *v as i64),
        ScalarValue::UInt32(Some(v)) => int_compare(column, op, *v as i64),
        ScalarValue::UInt64(Some(v)) => match i64::try_from(*v) {
            Ok(v) => int_compare(column, op, v),
            Err(_) => SimplePredicate::AlwaysTrue,
        },
        _ => SimplePredicate::AlwaysTrue,
    }
}

fn int_compare(column: &str, op: CompareOp, value: i64) -> SimplePredicate {
    SimplePredicate::IntCompare {
        field: column.to_string(),
        op,
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;
    use pcapsql_core::TunnelType;
    use smallvec::SmallVec;

    fn tcp_result() -> ParseResult<'static> {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(12345)));
        fields.push(("dst_port", FieldValue::UInt16(80)));
        fields.push(("flags", FieldValue::UInt16(0x02)));
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

    fn ipv4_result() -> ParseResult<'static> {
        use std::net::{IpAddr, Ipv4Addr};
        let mut fields = SmallVec::new();
        fields.push((
            "src_ip",
            FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ));
        fields.push(("ttl", FieldValue::UInt8(64)));
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

    #[test]
    fn test_int_compare_positive_and_negative() {
        let result = tcp_result();
        let keep = FilterEvaluator::try_from_exprs(&[col("dst_port").eq(lit(80i32))]).unwrap();
        assert!(keep.matches_result(&result));
        let drop = FilterEvaluator::try_from_exprs(&[col("dst_port").eq(lit(443i32))]).unwrap();
        assert!(!drop.matches_result(&result));
    }

    #[test]
    fn test_missing_field_keeps_row() {
        // mss is absent: SQL NULL semantics belong to DataFusion, the
        // parse-time filter must keep the row.
        let result = tcp_result();
        let f = FilterEvaluator::try_from_exprs(&[col("mss").eq(lit(1460i32))]).unwrap();
        assert!(f.matches_result(&result));
        let f = FilterEvaluator::try_from_exprs(&[col("mss").not_eq(lit(1460i32))]).unwrap();
        assert!(f.matches_result(&result));
    }

    #[test]
    fn test_ipv4_compares_as_u32_column_value() {
        let result = ipv4_result();
        let ip_as_u32 = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 1)) as i64;
        let keep = FilterEvaluator::try_from_exprs(&[col("src_ip").eq(lit(ip_as_u32))]).unwrap();
        assert!(keep.matches_result(&result));
        let drop =
            FilterEvaluator::try_from_exprs(&[col("src_ip").eq(lit(ip_as_u32 + 1))]).unwrap();
        assert!(!drop.matches_result(&result));
        // A string literal against the UInt32 ip column is not confidently
        // comparable at parse time: keep.
        let keep = SimplePredicate::StringCompare {
            field: "src_ip".to_string(),
            op: CompareOp::Eq,
            value: "10.0.0.1".to_string(),
        };
        assert!(keep.matches_result(&result));
    }

    #[test]
    fn test_and_combines() {
        let result = tcp_result();
        let f = FilterEvaluator::try_from_exprs(&[
            col("dst_port").eq(lit(80i32)),
            col("src_port").gt(lit(10000i32)),
        ])
        .unwrap();
        assert!(f.matches_result(&result));

        let f = FilterEvaluator::try_from_exprs(&[
            col("dst_port").eq(lit(80i32)),
            col("src_port").gt(lit(60000i32)),
        ])
        .unwrap();
        assert!(!f.matches_result(&result));
    }

    #[test]
    fn test_or_and_unsupported_keep_rows() {
        let result = tcp_result();
        // OR converts to AlwaysTrue → no evaluator at all.
        let or_expr = col("dst_port")
            .eq(lit(80i32))
            .or(col("dst_port").eq(lit(443i32)));
        assert!(FilterEvaluator::try_from_exprs(std::slice::from_ref(&or_expr)).is_none());
        assert!(!FilterEvaluator::expr_is_pushable(&or_expr));

        // Mixed: the convertible conjunct still applies; the rest keeps rows.
        let f =
            FilterEvaluator::try_from_exprs(&[or_expr, col("dst_port").eq(lit(443i32))]).unwrap();
        assert!(!f.matches_result(&result));
    }

    #[test]
    fn test_reversed_literal_column() {
        let result = tcp_result();
        // 100 > src_port  ⇒  src_port < 100 (12345 ⇒ false)
        let expr = lit(100i32).gt(col("src_port"));
        let f = FilterEvaluator::try_from_exprs(&[expr]).unwrap();
        assert!(!f.matches_result(&result));
    }

    #[test]
    fn test_empty_exprs() {
        assert!(FilterEvaluator::try_from_exprs(&[]).is_none());
    }
}
