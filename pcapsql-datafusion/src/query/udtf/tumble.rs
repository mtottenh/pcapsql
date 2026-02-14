//! TUMBLE() table-valued function.
//!
//! Assigns each row to a fixed-size, non-overlapping tumbling window.
//!
//! ## SQL Syntax
//!
//! ```sql
//! SELECT window_start, window_end, src_ip, COUNT(*)
//! FROM tumble(tcp_packets, INTERVAL '1' MINUTE)
//! GROUP BY window_start, window_end, src_ip;
//!
//! -- With explicit timestamp column
//! SELECT window_start, window_end, COUNT(*)
//! FROM tumble(tcp, timestamp_col, INTERVAL '1' MINUTE)
//! GROUP BY 1, 2;
//! ```

use std::fmt::Debug;
use std::sync::Arc;

use datafusion::common::Result;
use datafusion::datasource::TableProvider;
use datafusion::prelude::{Expr, SessionContext};
use datafusion_catalog::TableFunctionImpl;

use pcapsql_core::windowing::WindowType;

use super::window_args::parse_window_args;
use super::window_provider::WindowTableProvider;

/// Table function implementation for TUMBLE().
pub struct TumbleFunction {
    ctx: SessionContext,
}

impl Debug for TumbleFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TumbleFunction").finish()
    }
}

impl TumbleFunction {
    pub fn new(ctx: SessionContext) -> Self {
        Self { ctx }
    }
}

impl TableFunctionImpl for TumbleFunction {
    fn call(&self, args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        // Parse arguments: tumble(table, [timestamp_col,] interval)
        if args.len() < 2 || args.len() > 3 {
            return Err(datafusion::error::DataFusionError::Plan(
                "TUMBLE() requires 2-3 arguments: tumble(table, [timestamp_col,] INTERVAL)"
                    .to_string(),
            ));
        }

        let (table_provider, timestamp_col, interval_us) =
            parse_window_args(&self.ctx, args, "TUMBLE")?;

        let window_size = std::time::Duration::from_micros(interval_us as u64);
        let window_type = WindowType::tumble(window_size);

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
    fn test_tumble_function_debug() {
        let ctx = SessionContext::new();
        let func = TumbleFunction::new(ctx);
        let debug = format!("{:?}", func);
        assert!(debug.contains("TumbleFunction"));
    }
}
