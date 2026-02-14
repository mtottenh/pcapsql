//! Shared argument parsing for window TVFs (TUMBLE, HOP).

use std::sync::Arc;

use arrow::datatypes::{DataType, IntervalMonthDayNano, TimeUnit};
use datafusion::common::Result;
use datafusion::datasource::TableProvider;
use datafusion::prelude::{Expr, SessionContext};
use datafusion::scalar::ScalarValue;

/// Extract a table name from a TVF argument expression.
///
/// Accepts bare identifiers (`tcp`) and string literals (`'tcp'`).
pub fn extract_table_name(expr: &Expr, func_name: &str) -> Result<String> {
    match expr {
        Expr::Column(col) => Ok(col.name.clone()),
        Expr::Literal(ScalarValue::Utf8(Some(s)), _) => Ok(s.clone()),
        other => Err(datafusion::error::DataFusionError::Plan(format!(
            "{func_name}() first argument must be a table name, got: {other:?}"
        ))),
    }
}

/// Convert an IntervalMonthDayNano to microseconds.
///
/// Only supports day and sub-day intervals (no month component since months
/// have variable length). Returns an error for month-only intervals.
pub fn interval_to_micros(interval: &IntervalMonthDayNano, context: &str) -> Result<i64> {
    if interval.months != 0 {
        return Err(datafusion::error::DataFusionError::Plan(format!(
            "{context}: month intervals are not supported for windows (months have variable length). \
             Use day/hour/minute/second intervals instead."
        )));
    }

    let days_us = interval.days as i64 * 24 * 60 * 60 * 1_000_000;
    let nanos_us = interval.nanoseconds / 1_000;

    let total = days_us + nanos_us;
    if total <= 0 {
        return Err(datafusion::error::DataFusionError::Plan(format!(
            "{context}: interval must be positive"
        )));
    }

    Ok(total)
}

/// Resolve a table name to a TableProvider and determine the timestamp column.
///
/// If the table has a `timestamp` column (e.g., views like tcp_packets), uses it.
/// If the table has a `frame_number` column but no `timestamp`, returns an error
/// suggesting the user use a view instead.
pub fn resolve_table(
    ctx: &SessionContext,
    table_name: &str,
    func_name: &str,
) -> Result<(Arc<dyn TableProvider>, String)> {
    // Look up the table from the catalog
    let state = ctx.state();
    let catalog = state.catalog_list().catalog("datafusion").ok_or_else(|| {
        datafusion::error::DataFusionError::Plan("No default catalog found".to_string())
    })?;
    let schema_provider = catalog.schema("public").ok_or_else(|| {
        datafusion::error::DataFusionError::Plan("No default schema found".to_string())
    })?;

    // Check if table exists
    if !schema_provider.table_exist(table_name) {
        return Err(datafusion::error::DataFusionError::Plan(format!(
            "{func_name}(): table or view '{table_name}' not found. \
             Use a table name like 'tcp', 'dns', or a view like 'tcp_packets'."
        )));
    }

    // Resolve the table provider. The table() method is async but for our
    // in-memory/registered tables the future is immediately ready.
    let table =
        futures::executor::block_on(schema_provider.table(table_name))?.ok_or_else(|| {
            datafusion::error::DataFusionError::Plan(format!(
                "{func_name}(): failed to resolve table '{table_name}'"
            ))
        })?;

    let schema = table.schema();

    // Determine the timestamp column
    let timestamp_col = find_timestamp_column(&schema, table_name, func_name)?;

    Ok((table, timestamp_col))
}

/// Find the timestamp column in a table schema.
///
/// Looks for columns named "timestamp" with a Timestamp type. If not found,
/// returns an error with guidance.
fn find_timestamp_column(
    schema: &arrow::datatypes::SchemaRef,
    table_name: &str,
    func_name: &str,
) -> Result<String> {
    // Look for a "timestamp" column
    if let Ok(idx) = schema.index_of("timestamp") {
        let field = schema.field(idx);
        match field.data_type() {
            DataType::Timestamp(TimeUnit::Microsecond, _) => {
                return Ok("timestamp".to_string());
            }
            DataType::Timestamp(_, _) => {
                return Ok("timestamp".to_string());
            }
            _ => {}
        }
    }

    // Look for any timestamp column
    for field in schema.fields() {
        if matches!(field.data_type(), DataType::Timestamp(_, _)) {
            return Ok(field.name().clone());
        }
    }

    Err(datafusion::error::DataFusionError::Plan(format!(
        "{func_name}(): table '{table_name}' has no timestamp column. \
         Use a view like '{table_name}_packets' which includes timestamps from the frames table, \
         e.g.: {func_name}({table_name}_packets, INTERVAL '1' MINUTE)"
    )))
}

/// Parse window TVF arguments for TUMBLE.
///
/// Handles:
/// - `tumble(table, interval)` — uses auto-detected timestamp column
/// - `tumble(table, timestamp_col, interval)` — explicit timestamp column
pub fn parse_window_args(
    ctx: &SessionContext,
    args: &[Expr],
    func_name: &str,
) -> Result<(Arc<dyn TableProvider>, String, i64)> {
    // First arg is always the table name
    let table_name = extract_table_name(&args[0], func_name)?;
    let (table_provider, auto_ts_col) = resolve_table(ctx, &table_name, func_name)?;

    match args.len() {
        2 => {
            // tumble(table, interval)
            let interval_us = match &args[1] {
                Expr::Literal(ScalarValue::IntervalMonthDayNano(Some(interval)), _) => {
                    interval_to_micros(interval, &format!("{func_name} window size"))
                }
                other => Err(datafusion::error::DataFusionError::Plan(format!(
                    "{func_name}() second argument must be an INTERVAL, got: {other:?}"
                ))),
            }?;

            Ok((table_provider, auto_ts_col, interval_us))
        }
        3 => {
            // tumble(table, timestamp_col, interval)
            let ts_col = match &args[1] {
                Expr::Column(col) => col.name.clone(),
                Expr::Literal(ScalarValue::Utf8(Some(s)), _) => s.clone(),
                other => {
                    return Err(datafusion::error::DataFusionError::Plan(format!(
                        "{func_name}() second argument must be a column name when 3 arguments are provided, got: {other:?}"
                    )));
                }
            };

            // Verify the column exists in the table schema
            let schema = table_provider.schema();
            if schema.index_of(&ts_col).is_err() {
                return Err(datafusion::error::DataFusionError::Plan(format!(
                    "{func_name}(): column '{ts_col}' not found in table '{table_name}'. \
                     Available columns: {:?}",
                    schema
                        .fields()
                        .iter()
                        .map(|f| f.name().as_str())
                        .collect::<Vec<_>>()
                )));
            }

            let interval_us = match &args[2] {
                Expr::Literal(ScalarValue::IntervalMonthDayNano(Some(interval)), _) => {
                    interval_to_micros(interval, &format!("{func_name} window size"))
                }
                other => Err(datafusion::error::DataFusionError::Plan(format!(
                    "{func_name}() third argument must be an INTERVAL, got: {other:?}"
                ))),
            }?;

            Ok((table_provider, ts_col, interval_us))
        }
        _ => Err(datafusion::error::DataFusionError::Plan(format!(
            "{func_name}() requires 2-3 arguments"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_to_micros_seconds() {
        let interval = IntervalMonthDayNano {
            months: 0,
            days: 0,
            nanoseconds: 60_000_000_000, // 60 seconds
        };
        assert_eq!(interval_to_micros(&interval, "test").unwrap(), 60_000_000);
    }

    #[test]
    fn test_interval_to_micros_days() {
        let interval = IntervalMonthDayNano {
            months: 0,
            days: 1,
            nanoseconds: 0,
        };
        assert_eq!(
            interval_to_micros(&interval, "test").unwrap(),
            24 * 60 * 60 * 1_000_000
        );
    }

    #[test]
    fn test_interval_to_micros_days_and_seconds() {
        let interval = IntervalMonthDayNano {
            months: 0,
            days: 1,
            nanoseconds: 30_000_000_000, // 30 seconds
        };
        let expected = 24 * 60 * 60 * 1_000_000 + 30_000_000;
        assert_eq!(interval_to_micros(&interval, "test").unwrap(), expected);
    }

    #[test]
    fn test_interval_to_micros_rejects_months() {
        let interval = IntervalMonthDayNano {
            months: 1,
            days: 0,
            nanoseconds: 0,
        };
        assert!(interval_to_micros(&interval, "test").is_err());
    }

    #[test]
    fn test_interval_to_micros_rejects_zero() {
        let interval = IntervalMonthDayNano {
            months: 0,
            days: 0,
            nanoseconds: 0,
        };
        assert!(interval_to_micros(&interval, "test").is_err());
    }

    #[test]
    fn test_extract_table_name_column() {
        let expr = Expr::Column(datafusion::common::Column::from_name("tcp"));
        assert_eq!(extract_table_name(&expr, "TEST").unwrap(), "tcp");
    }

    #[test]
    fn test_extract_table_name_string() {
        let expr = Expr::Literal(ScalarValue::Utf8(Some("tcp".to_string())), None);
        assert_eq!(extract_table_name(&expr, "TEST").unwrap(), "tcp");
    }

    #[test]
    fn test_extract_table_name_invalid() {
        let expr = Expr::Literal(ScalarValue::Int64(Some(42)), None);
        assert!(extract_table_name(&expr, "TEST").is_err());
    }
}
