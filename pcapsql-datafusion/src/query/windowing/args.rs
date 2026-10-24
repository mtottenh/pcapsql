//! Argument parsing shared by the window table functions.
//!
//! DataFusion hands a table function its arguments as logical expressions
//! planned against an empty schema: a bare identifier is an unresolved
//! [`Expr::Column`], a string is a `Utf8` literal and `INTERVAL '10' SECOND`
//! is an interval literal.

use arrow::datatypes::IntervalMonthDayNano;
use datafusion::common::{plan_err, Result, ScalarValue, TableReference};
use datafusion::logical_expr::Expr;

/// Microseconds per day.
const DAY_US: i64 = 24 * 60 * 60 * 1_000_000;

/// The source relation of a window function: a bare identifier (`frames`),
/// a schema- or catalog-qualified one (`public.frames`,
/// `datafusion.public.frames`) or a string literal.
pub(super) fn source_reference(expr: &Expr, func: &str) -> Result<TableReference> {
    match expr {
        // Planned against an empty schema, `a.b.c` arrives as a column `c`
        // whose relation is the reference `a.b`.
        Expr::Column(column) => Ok(match &column.relation {
            None => TableReference::bare(column.name.as_str()),
            Some(TableReference::Bare { table: schema }) => {
                TableReference::partial(schema.as_ref(), column.name.as_str())
            }
            Some(TableReference::Partial {
                schema: catalog,
                table: schema,
            }) => TableReference::full(catalog.as_ref(), schema.as_ref(), column.name.as_str()),
            Some(TableReference::Full { .. }) => {
                return plan_err!(
                    "{func}(): the source name has too many parts, got {column}; \
                     use table, schema.table or catalog.schema.table"
                )
            }
        }),
        Expr::Literal(ScalarValue::Utf8(Some(name)), _)
        | Expr::Literal(ScalarValue::LargeUtf8(Some(name)), _)
        | Expr::Literal(ScalarValue::Utf8View(Some(name)), _) => {
            Ok(TableReference::from(name.as_str()))
        }
        other => {
            plan_err!("{func}(): the first argument must be a table or view name, got {other}")
        }
    }
}

/// A column name argument: a bare identifier, a string literal, or an
/// identifier qualified by the source's table name (`frames.timestamp` for
/// source `frames`).
pub(super) fn column_name(
    expr: &Expr,
    func: &str,
    what: &str,
    source: &TableReference,
) -> Result<String> {
    match expr {
        Expr::Column(column) => match &column.relation {
            None => Ok(column.name.clone()),
            Some(relation) if relation.table() == source.table() => Ok(column.name.clone()),
            Some(relation) => plan_err!(
                "{func}(): the {what} {column} is qualified by '{relation}', which is not the \
                 source '{source}'"
            ),
        },
        Expr::Literal(ScalarValue::Utf8(Some(name)), _)
        | Expr::Literal(ScalarValue::LargeUtf8(Some(name)), _)
        | Expr::Literal(ScalarValue::Utf8View(Some(name)), _) => Ok(name.clone()),
        other => plan_err!("{func}(): the {what} must be a column name, got {other}"),
    }
}

/// A positive INTERVAL literal argument in microseconds.
///
/// Month and year components are rejected: a window needs a fixed length,
/// and months do not have one.
pub(super) fn interval_micros(expr: &Expr, func: &str, what: &str) -> Result<i64> {
    let total = match expr {
        Expr::Literal(ScalarValue::IntervalMonthDayNano(Some(v)), _) => {
            if v.months != 0 {
                return plan_err!(
                    "{func}(): the {what} must not contain months or years \
                     (months have no fixed length); use days, hours, minutes or seconds"
                );
            }
            if v.nanoseconds % 1_000 != 0 {
                return plan_err!(
                    "{func}(): the {what} has sub-microsecond precision; \
                     timestamps are microseconds"
                );
            }
            i64::from(v.days)
                .checked_mul(DAY_US)
                .and_then(|days| days.checked_add(v.nanoseconds / 1_000))
        }
        Expr::Literal(ScalarValue::IntervalDayTime(Some(v)), _) => i64::from(v.days)
            .checked_mul(DAY_US)
            .and_then(|days| days.checked_add(i64::from(v.milliseconds) * 1_000)),
        Expr::Literal(ScalarValue::IntervalYearMonth(Some(_)), _) => {
            return plan_err!(
                "{func}(): the {what} must not contain months or years \
                 (months have no fixed length); use days, hours, minutes or seconds"
            );
        }
        other => {
            return plan_err!(
                "{func}(): the {what} must be an INTERVAL literal such as \
                 INTERVAL '10' SECOND, got {other}"
            );
        }
    };
    match total {
        Some(us) if us > 0 && us <= MAX_INTERVAL_US => Ok(us),
        Some(us) if us <= 0 => plan_err!("{func}(): the {what} must be positive"),
        _ => plan_err!("{func}(): the {what} is too large"),
    }
}

/// The largest interval the planner can carry in a nanosecond interval
/// literal (`date_bin` takes its stride as `IntervalMonthDayNano`).
pub(super) const MAX_INTERVAL_US: i64 = i64::MAX / 1_000;

/// An interval literal of `micros` microseconds, as `date_bin` wants it.
pub(super) fn interval_literal(micros: i64) -> Expr {
    Expr::Literal(
        ScalarValue::IntervalMonthDayNano(Some(IntervalMonthDayNano::new(0, 0, micros * 1_000))),
        None,
    )
}

/// Split `args` into the source, the optional timestamp column that may
/// follow it, and the `fixed` trailing arguments.
///
/// Every window function is `f(source, [timestamp_column,] fixed...)`, so the
/// argument count decides whether a timestamp column was given.
pub(super) fn split_args<'a>(
    args: &'a [Expr],
    func: &str,
    fixed: usize,
    usage: &str,
) -> Result<(TableReference, Option<String>, &'a [Expr])> {
    if args.len() != fixed + 1 && args.len() != fixed + 2 {
        // DataFusion drops an argument it cannot plan against an empty schema
        // (a nested table function is the common case), so too few
        // arguments usually means a nested window function.
        let hint = if args.len() <= fixed {
            " (window functions cannot be nested; CREATE VIEW over the inner one and window \
             the view)"
        } else {
            ""
        };
        return plan_err!(
            "{func}() takes {} or {} arguments: {usage}{hint}",
            fixed + 1,
            fixed + 2
        );
    }
    let source = source_reference(&args[0], func)?;
    let timestamp = if args.len() == fixed + 2 {
        Some(column_name(&args[1], func, "timestamp column", &source)?)
    } else {
        None
    };
    let rest = &args[args.len() - fixed..];
    Ok((source, timestamp, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::datatypes::IntervalDayTime;
    use datafusion::common::Column;

    fn mdn(months: i32, days: i32, nanos: i64) -> Expr {
        Expr::Literal(
            ScalarValue::IntervalMonthDayNano(Some(IntervalMonthDayNano::new(months, days, nanos))),
            None,
        )
    }

    #[test]
    fn intervals_to_micros() {
        assert_eq!(
            interval_micros(&mdn(0, 0, 60_000_000_000), "f", "size").unwrap(),
            60_000_000
        );
        assert_eq!(
            interval_micros(&mdn(0, 1, 30_000_000_000), "f", "size").unwrap(),
            DAY_US + 30_000_000
        );
        let day_time = Expr::Literal(
            ScalarValue::IntervalDayTime(Some(IntervalDayTime::new(1, 1_500))),
            None,
        );
        assert_eq!(
            interval_micros(&day_time, "f", "size").unwrap(),
            DAY_US + 1_500_000
        );
    }

    #[test]
    fn intervals_rejected() {
        let months = interval_micros(&mdn(1, 0, 0), "tumble", "window size").unwrap_err();
        assert!(months.to_string().contains("months"), "{months}");
        let zero = interval_micros(&mdn(0, 0, 0), "tumble", "window size").unwrap_err();
        assert!(zero.to_string().contains("positive"), "{zero}");
        let negative = interval_micros(&mdn(0, 0, -1_000), "tumble", "window size").unwrap_err();
        assert!(negative.to_string().contains("positive"), "{negative}");
        let nanos = interval_micros(&mdn(0, 0, 1_500), "tumble", "window size").unwrap_err();
        assert!(nanos.to_string().contains("sub-microsecond"), "{nanos}");
        let not_interval = interval_micros(
            &Expr::Literal(ScalarValue::Int64(Some(10)), None),
            "tumble",
            "window size",
        )
        .unwrap_err();
        assert!(
            not_interval.to_string().contains("INTERVAL"),
            "{not_interval}"
        );
    }

    #[test]
    fn source_names() {
        let bare = Expr::Column(Column::from_name("frames"));
        assert_eq!(
            source_reference(&bare, "f").unwrap(),
            TableReference::bare("frames")
        );
        let qualified = Expr::Column(Column::new(Some("public"), "frames"));
        assert_eq!(
            source_reference(&qualified, "f").unwrap(),
            TableReference::partial("public", "frames")
        );
        let full = Expr::Column(Column::new(
            Some(TableReference::partial("datafusion", "public")),
            "frames",
        ));
        assert_eq!(
            source_reference(&full, "f").unwrap(),
            TableReference::full("datafusion", "public", "frames")
        );
        let too_many = Expr::Column(Column::new(
            Some(TableReference::full("a", "b", "c")),
            "frames",
        ));
        assert!(source_reference(&too_many, "f")
            .unwrap_err()
            .to_string()
            .contains("too many parts"));
        let literal = Expr::Literal(ScalarValue::Utf8(Some("tcp_packets".into())), None);
        assert_eq!(
            source_reference(&literal, "f").unwrap(),
            TableReference::bare("tcp_packets")
        );
        let bad = Expr::Literal(ScalarValue::Int64(Some(1)), None);
        assert!(source_reference(&bad, "f").is_err());
    }

    #[test]
    fn column_names() {
        let frames = TableReference::bare("frames");
        let bare = Expr::Column(Column::from_name("timestamp"));
        assert_eq!(column_name(&bare, "f", "c", &frames).unwrap(), "timestamp");
        let qualified = Expr::Column(Column::new(Some("frames"), "timestamp"));
        assert_eq!(
            column_name(&qualified, "f", "c", &frames).unwrap(),
            "timestamp"
        );
        let other = Expr::Column(Column::new(Some("udp"), "timestamp"));
        let err = column_name(&other, "f", "c", &frames)
            .unwrap_err()
            .to_string();
        assert!(err.contains("qualified by 'udp'"), "{err}");
        let literal = Expr::Literal(ScalarValue::Utf8(Some("ts".into())), None);
        assert_eq!(column_name(&literal, "f", "c", &frames).unwrap(), "ts");
    }

    #[test]
    fn split_optional_timestamp() {
        let source = Expr::Column(Column::from_name("frames"));
        let ts = Expr::Column(Column::from_name("ts"));
        let size = mdn(0, 0, 1_000);
        let two = [source.clone(), size.clone()];
        let (s, t, rest) = split_args(&two, "tumble", 1, "u").unwrap();
        assert_eq!(s, TableReference::bare("frames"));
        assert!(t.is_none());
        assert_eq!(rest.len(), 1);
        let three = [source.clone(), ts, size];
        let (_, t, rest) = split_args(&three, "tumble", 1, "u").unwrap();
        assert_eq!(t.as_deref(), Some("ts"));
        assert_eq!(rest.len(), 1);
        let err = split_args(&[source], "tumble", 1, "tumble(source, size)").unwrap_err();
        assert!(err.to_string().contains("tumble(source, size)"), "{err}");
        assert!(err.to_string().contains("cannot be nested"), "{err}");
        let err = split_args(
            &[
                two[0].clone(),
                two[1].clone(),
                two[1].clone(),
                two[1].clone(),
            ],
            "tumble",
            1,
            "u",
        )
        .unwrap_err();
        assert!(!err.to_string().contains("nested"), "{err}");
    }
}
