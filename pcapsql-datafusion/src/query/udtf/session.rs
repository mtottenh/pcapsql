//! SESSION() table-valued function.
//!
//! Groups events into variable-length sessions based on per-key activity gaps.
//! Events within a gap duration of each other for the same key are grouped
//! into the same session window.
//!
//! ## SQL Syntax
//!
//! ```sql
//! -- Session windows with 30-second gap, partitioned by src_ip
//! SELECT window_start, window_end, src_ip, COUNT(*) as packets
//! FROM session(tcp_packets, src_ip, INTERVAL '30' SECOND)
//! GROUP BY window_start, window_end, src_ip;
//! ```

use std::fmt::Debug;
use std::sync::Arc;

use datafusion::common::Result;
use datafusion::datasource::TableProvider;
use datafusion::prelude::{Expr, SessionContext};
use datafusion::scalar::ScalarValue;
use datafusion_catalog::TableFunctionImpl;

use pcapsql_core::windowing::WindowType;

use super::window_args::{extract_table_name, interval_to_micros, resolve_table};
use super::window_provider::WindowTableProvider;

/// Table function implementation for SESSION().
pub struct SessionFunction {
    ctx: SessionContext,
}

impl Debug for SessionFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionFunction").finish()
    }
}

impl SessionFunction {
    pub fn new(ctx: SessionContext) -> Self {
        Self { ctx }
    }
}

impl TableFunctionImpl for SessionFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        // Parse arguments: session(table, key_col, gap_interval)
        if args.len() != 3 {
            return Err(datafusion::error::DataFusionError::Plan(
                "SESSION() requires exactly 3 arguments: session(table, key_column, gap_interval)"
                    .to_string(),
            ));
        }

        // First arg: table name
        let table_name = extract_table_name(&args[0], "SESSION")?;
        let (table_provider, timestamp_col) = resolve_table(&self.ctx, &table_name, "SESSION")?;

        // Second arg: key column name
        let key_col = match &args[1] {
            Expr::Column(col) => col.name.clone(),
            Expr::Literal(ScalarValue::Utf8(Some(s)), _) => s.clone(),
            other => {
                return Err(datafusion::error::DataFusionError::Plan(format!(
                    "SESSION() second argument must be a column name for session partitioning, got: {other:?}"
                )));
            }
        };

        // Verify the key column exists in the table schema
        let schema = table_provider.schema();
        if schema.index_of(&key_col).is_err() {
            return Err(datafusion::error::DataFusionError::Plan(format!(
                "SESSION(): key column '{key_col}' not found in table '{table_name}'. \
                 Available columns: {:?}",
                schema
                    .fields()
                    .iter()
                    .map(|f| f.name().as_str())
                    .collect::<Vec<_>>()
            )));
        }

        // Third arg: gap interval
        let gap_us = match &args[2] {
            Expr::Literal(ScalarValue::IntervalMonthDayNano(Some(interval)), _) => {
                interval_to_micros(interval, "SESSION gap")
            }
            other => Err(datafusion::error::DataFusionError::Plan(format!(
                "SESSION() third argument must be a gap INTERVAL, got: {other:?}"
            ))),
        }?;

        let gap = std::time::Duration::from_micros(gap_us as u64);
        let window_type = WindowType::session(gap);

        Ok(Arc::new(WindowTableProvider::new_session(
            table_provider,
            window_type,
            timestamp_col,
            key_col,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_function_debug() {
        let ctx = SessionContext::new();
        let func = SessionFunction::new(ctx);
        let debug = format!("{:?}", func);
        assert!(debug.contains("SessionFunction"));
    }
}
