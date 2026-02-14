//! HOP() table-valued function.
//!
//! Assigns each row to one or more overlapping hopping windows.
//!
//! ## SQL Syntax
//!
//! ```sql
//! -- Hopping window: 30s slide, 5 minute window size
//! SELECT window_start, window_end, src_ip, SUM(length) as bytes
//! FROM hop(tcp_packets, INTERVAL '30' SECOND, INTERVAL '5' MINUTE)
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

/// Table function implementation for HOP().
pub struct HopFunction {
    ctx: SessionContext,
}

impl Debug for HopFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopFunction").finish()
    }
}

impl HopFunction {
    pub fn new(ctx: SessionContext) -> Self {
        Self { ctx }
    }
}

impl TableFunctionImpl for HopFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        // Parse arguments: hop(table, slide_interval, size_interval)
        if args.len() != 3 {
            return Err(datafusion::error::DataFusionError::Plan(
                "HOP() requires exactly 3 arguments: hop(table, slide_interval, size_interval)"
                    .to_string(),
            ));
        }

        // First arg: table name
        let table_name = extract_table_name(&args[0], "HOP")?;
        let (table_provider, timestamp_col) = resolve_table(&self.ctx, &table_name, "HOP")?;

        // Second arg: slide interval
        let slide_us = match &args[1] {
            Expr::Literal(ScalarValue::IntervalMonthDayNano(Some(interval)), _) => {
                interval_to_micros(interval, "HOP slide")
            }
            other => Err(datafusion::error::DataFusionError::Plan(format!(
                "HOP() second argument must be a slide INTERVAL, got: {other:?}"
            ))),
        }?;

        // Third arg: size interval
        let size_us = match &args[2] {
            Expr::Literal(ScalarValue::IntervalMonthDayNano(Some(interval)), _) => {
                interval_to_micros(interval, "HOP size")
            }
            other => Err(datafusion::error::DataFusionError::Plan(format!(
                "HOP() third argument must be a size INTERVAL, got: {other:?}"
            ))),
        }?;

        if slide_us <= 0 {
            return Err(datafusion::error::DataFusionError::Plan(
                "HOP() slide interval must be positive".to_string(),
            ));
        }
        if size_us <= 0 {
            return Err(datafusion::error::DataFusionError::Plan(
                "HOP() size interval must be positive".to_string(),
            ));
        }
        if slide_us > size_us {
            return Err(datafusion::error::DataFusionError::Plan(format!(
                "HOP() slide ({slide_us}us) must be <= size ({size_us}us)"
            )));
        }

        let slide = std::time::Duration::from_micros(slide_us as u64);
        let size = std::time::Duration::from_micros(size_us as u64);
        let window_type = WindowType::hop(slide, size);

        Ok(Arc::new(WindowTableProvider::new(
            table_provider,
            window_type,
            timestamp_col,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_function_debug() {
        let ctx = SessionContext::new();
        let func = HopFunction::new(ctx);
        let debug = format!("{:?}", func);
        assert!(debug.contains("HopFunction"));
    }
}
