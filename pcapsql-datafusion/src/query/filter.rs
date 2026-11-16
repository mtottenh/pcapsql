//! Parse-time predicates: the DataFusion front-end of
//! [`pcapsql_core::scan::RowPredicate`].
//!
//! Converts simple DataFusion `WHERE` expressions (pushed into `TableScan`s
//! as `Inexact` filters) into a [`RowPredicate`] on the scanned table, which
//! the parse pass evaluates against a protocol's parsed layer *before* a row
//! is materialized into Arrow.
//!
//! The predicate is **table-scoped and conservative**: a column is resolved
//! only within the row's own protocol layer, and any uncertainty (missing
//! field, type mismatch, unsupported expression shape) keeps the row.
//! DataFusion re-applies the original filter (`Inexact` pushdown), so a kept
//! row can never produce a wrong result; only a *positively false*
//! comparison may drop a row early. How a predicate is evaluated is defined
//! in core, with [`RowPredicate`]; this module only decides which
//! expressions become one.

use datafusion::common::ScalarValue;
use datafusion::logical_expr::{BinaryExpr, Expr, Operator};

use pcapsql_core::scan::{CmpOp, Literal, RowPredicate, TableDef};

/// The parse-time predicate for a scan of `table` with the pushed-down
/// filter expressions `exprs` (a conjunction).
///
/// The convertible parts are `column <op> literal` comparisons (either way
/// round) of a column of `table` with an integer or string literal, joined
/// by `AND`. Everything else (`OR`, functions, other literal types) is left
/// to DataFusion. Returns `None` when no part converts.
pub fn row_predicate(exprs: &[Expr], table: &TableDef) -> Option<RowPredicate> {
    let mut terms = Vec::new();
    for expr in exprs {
        collect_terms(expr, table, &mut terms);
    }
    match terms.len() {
        0 => None,
        1 => terms.pop(),
        _ => Some(RowPredicate::And(terms)),
    }
}

/// Whether an expression contributes to the parse-time predicate of a scan
/// of `table` (drives the provider's `Inexact` vs `Unsupported` pushdown
/// answer).
pub fn is_pushable(expr: &Expr, table: &TableDef) -> bool {
    row_predicate(std::slice::from_ref(expr), table).is_some()
}

/// Append the comparisons `expr` converts to (conservative: an unsupported
/// shape contributes nothing, which keeps every row).
fn collect_terms(expr: &Expr, table: &TableDef, terms: &mut Vec<RowPredicate>) {
    let Expr::BinaryExpr(BinaryExpr { left, op, right }) = expr else {
        return;
    };
    // AND splits; both sides convert on their own. OR cannot be decided per
    // side conservatively, so it (like every other operator) converts to
    // nothing.
    if *op == Operator::And {
        collect_terms(left, table, terms);
        collect_terms(right, table, terms);
        return;
    }
    let Some(op) = compare_op(op) else {
        return;
    };
    let term = match (left.as_ref(), right.as_ref()) {
        // column <op> literal
        (Expr::Column(column), Expr::Literal(literal, _)) => {
            comparison(table, &column.name, op, literal)
        }
        // literal <op> column: swap the operands
        (Expr::Literal(literal, _), Expr::Column(column)) => {
            comparison(table, &column.name, op.swapped(), literal)
        }
        _ => None,
    };
    terms.extend(term);
}

fn compare_op(op: &Operator) -> Option<CmpOp> {
    match op {
        Operator::Eq => Some(CmpOp::Eq),
        Operator::NotEq => Some(CmpOp::NotEq),
        Operator::Lt => Some(CmpOp::Lt),
        Operator::LtEq => Some(CmpOp::LtEq),
        Operator::Gt => Some(CmpOp::Gt),
        Operator::GtEq => Some(CmpOp::GtEq),
        _ => None,
    }
}

/// `column <op> literal` on `table`, when the column is one DataFusion sees
/// (a default column) and the literal is an integer that fits `i64` or a
/// string.
fn comparison(
    table: &TableDef,
    column: &str,
    op: CmpOp,
    literal: &ScalarValue,
) -> Option<RowPredicate> {
    let (column, _) = table.default_columns().find(|(_, c)| c.name == column)?;
    let value = match literal {
        ScalarValue::Utf8(Some(s)) | ScalarValue::LargeUtf8(Some(s)) => {
            Literal::Str(s.as_str().into())
        }
        ScalarValue::Int8(Some(v)) => Literal::Int(i64::from(*v)),
        ScalarValue::Int16(Some(v)) => Literal::Int(i64::from(*v)),
        ScalarValue::Int32(Some(v)) => Literal::Int(i64::from(*v)),
        ScalarValue::Int64(Some(v)) => Literal::Int(*v),
        ScalarValue::UInt8(Some(v)) => Literal::Int(i64::from(*v)),
        ScalarValue::UInt16(Some(v)) => Literal::Int(i64::from(*v)),
        ScalarValue::UInt32(Some(v)) => Literal::Int(i64::from(*v)),
        ScalarValue::UInt64(Some(v)) => Literal::Int(i64::try_from(*v).ok()?),
        _ => return None,
    };
    Some(RowPredicate::Cmp { column, op, value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;
    use pcapsql_core::scan::{Catalog, ColId};

    fn table(name: &str) -> &'static TableDef {
        Catalog::builtin().table(name).expect("table").1
    }

    fn tcp() -> &'static TableDef {
        table("tcp")
    }

    fn column(table: &TableDef, name: &str) -> ColId {
        table.column(name).expect("column").0
    }

    fn cmp(name: &str, op: CmpOp, value: impl Into<Literal>) -> RowPredicate {
        RowPredicate::cmp(column(tcp(), name), op, value)
    }

    #[test]
    fn column_literal_comparison_binds_the_column() {
        assert_eq!(
            row_predicate(&[col("dst_port").eq(lit(80i32))], tcp()),
            Some(cmp("dst_port", CmpOp::Eq, 80))
        );
        assert_eq!(
            row_predicate(&[col("tunnel_type").not_eq(lit("vxlan"))], tcp()),
            Some(cmp("tunnel_type", CmpOp::NotEq, "vxlan"))
        );
        assert!(is_pushable(&col("dst_port").eq(lit(80i32)), tcp()));
    }

    #[test]
    fn every_comparison_operator_converts() {
        let c = || col("dst_port");
        let v = || lit(80i64);
        for (expr, op) in [
            (c().eq(v()), CmpOp::Eq),
            (c().not_eq(v()), CmpOp::NotEq),
            (c().lt(v()), CmpOp::Lt),
            (c().lt_eq(v()), CmpOp::LtEq),
            (c().gt(v()), CmpOp::Gt),
            (c().gt_eq(v()), CmpOp::GtEq),
        ] {
            assert_eq!(
                row_predicate(&[expr], tcp()),
                Some(cmp("dst_port", op, 80)),
                "{op:?}"
            );
        }
    }

    #[test]
    fn literal_types() {
        let port = |literal: Expr| row_predicate(&[col("dst_port").eq(literal)], tcp());
        let int = |v: i64| Some(cmp("dst_port", CmpOp::Eq, v));
        assert_eq!(port(lit(-1i8)), int(-1));
        assert_eq!(port(lit(2i16)), int(2));
        assert_eq!(port(lit(3i32)), int(3));
        assert_eq!(port(lit(4i64)), int(4));
        assert_eq!(port(lit(5u8)), int(5));
        assert_eq!(port(lit(6u16)), int(6));
        assert_eq!(port(lit(7u32)), int(7));
        assert_eq!(port(lit(8u64)), int(8));
        assert_eq!(port(lit("x")), Some(cmp("dst_port", CmpOp::Eq, "x")));
        assert_eq!(
            port(lit(ScalarValue::LargeUtf8(Some("y".into())))),
            Some(cmp("dst_port", CmpOp::Eq, "y"))
        );
        // Out of i64 range, NULL, and types with no parse-time comparison.
        assert_eq!(port(lit(u64::MAX)), None);
        assert_eq!(port(lit(ScalarValue::Int32(None))), None);
        assert_eq!(port(lit(1.5f64)), None);
        assert_eq!(port(lit(true)), None);
    }

    #[test]
    fn several_exprs_and_nested_and_flatten_to_one_conjunction() {
        let expected = Some(RowPredicate::And(vec![
            cmp("dst_port", CmpOp::Eq, 80),
            cmp("src_port", CmpOp::Gt, 10_000),
        ]));
        assert_eq!(
            row_predicate(
                &[
                    col("dst_port").eq(lit(80i32)),
                    col("src_port").gt(lit(10_000i32)),
                ],
                tcp()
            ),
            expected
        );
        assert_eq!(
            row_predicate(
                &[col("dst_port")
                    .eq(lit(80i32))
                    .and(col("src_port").gt(lit(10_000i32)))],
                tcp()
            ),
            expected
        );
    }

    #[test]
    fn or_and_unsupported_shapes_convert_to_nothing() {
        let or_expr = col("dst_port")
            .eq(lit(80i32))
            .or(col("dst_port").eq(lit(443i32)));
        assert_eq!(row_predicate(std::slice::from_ref(&or_expr), tcp()), None);
        assert!(!is_pushable(&or_expr, tcp()));

        for expr in [
            col("dst_port").is_null(),
            col("dst_port").eq(col("src_port")),
            lit(1i32).eq(lit(1i32)),
            (col("dst_port") + lit(1i32)).eq(lit(81i32)),
            col("dst_port").like(lit("8%")),
        ] {
            assert!(!is_pushable(&expr, tcp()), "{expr}");
        }

        // Mixed: the convertible conjunct still applies; the rest keeps rows.
        assert_eq!(
            row_predicate(&[or_expr.clone(), col("dst_port").eq(lit(443i32))], tcp()),
            Some(cmp("dst_port", CmpOp::Eq, 443))
        );
        assert_eq!(
            row_predicate(&[or_expr.and(col("dst_port").eq(lit(443i32)))], tcp()),
            Some(cmp("dst_port", CmpOp::Eq, 443))
        );
    }

    #[test]
    fn reversed_literal_column_swaps_the_operator() {
        // 100 > src_port  =>  src_port < 100
        assert_eq!(
            row_predicate(&[lit(100i32).gt(col("src_port"))], tcp()),
            Some(cmp("src_port", CmpOp::Lt, 100))
        );
        assert_eq!(
            row_predicate(&[lit(100i32).lt_eq(col("src_port"))], tcp()),
            Some(cmp("src_port", CmpOp::GtEq, 100))
        );
        assert_eq!(
            row_predicate(&[lit(100i32).eq(col("src_port"))], tcp()),
            Some(cmp("src_port", CmpOp::Eq, 100))
        );
    }

    #[test]
    fn empty_exprs() {
        assert_eq!(row_predicate(&[], tcp()), None);
    }

    #[test]
    fn columns_resolve_in_the_scanned_table_only() {
        // Not a column of tcp.
        assert!(!is_pushable(&col("query_name").eq(lit("x")), tcp()));
        // An opt-in column is not a DataFusion column.
        assert!(tcp().column("timestamp").is_some());
        assert!(!is_pushable(&col("timestamp").gt(lit(0i64)), tcp()));
        // The same name binds to each table's own column.
        let udp = table("udp");
        assert_eq!(
            row_predicate(&[col("dst_port").eq(lit(53i32))], udp),
            Some(RowPredicate::cmp(column(udp, "dst_port"), CmpOp::Eq, 53))
        );
    }

    /// Converted and compiled, the predicate drops exactly the positively
    /// false rows (the evaluation itself is tested in core).
    #[test]
    fn converted_predicate_evaluates_against_a_layer() {
        use pcapsql_core::{FieldValue, ParseResult, TunnelType};
        use smallvec::SmallVec;

        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(12345)));
        fields.push(("dst_port", FieldValue::UInt16(80)));
        let layer = ParseResult {
            fields,
            remaining: &[],
            child_hints: pcapsql_core::protocol::Hints::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        };
        let keeps = |exprs: &[Expr]| {
            row_predicate(exprs, tcp())
                .and_then(|p| p.compile(tcp()))
                .is_none_or(|mut p| p.keeps(&layer))
        };
        assert!(keeps(&[col("dst_port").eq(lit(80i32))]));
        assert!(!keeps(&[col("dst_port").eq(lit(443i32))]));
        assert!(!keeps(&[
            col("dst_port").eq(lit(80i32)),
            col("src_port").gt(lit(60_000i32))
        ]));
        // Absent field: kept.
        assert!(keeps(&[col("mss").eq(lit(1460i32))]));
        // `frame_number` and the encapsulation columns are pushable (as
        // before); the context ones are also evaluated now.
        assert!(is_pushable(&col("frame_number").eq(lit(1i64)), tcp()));
        assert!(keeps(&[col("frame_number").eq(lit(7i64))]));
        assert!(keeps(&[col("encap_depth").eq(lit(0i32))]));
        assert!(!keeps(&[col("encap_depth").eq(lit(1i32))]));
    }
}
