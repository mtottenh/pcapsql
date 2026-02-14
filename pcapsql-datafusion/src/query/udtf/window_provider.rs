//! Table providers for window TVFs.
//!
//! These providers wrap an input table and add window assignment via
//! `WindowAssignExec` at scan time.

use std::any::Any;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::common::Result;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::physical_plan::ExecutionPlan;
use datafusion::prelude::Expr;

use pcapsql_core::windowing::WindowType;

use super::window_exec::{build_window_schema, WindowAssignExec};

/// Table provider that wraps an input table with window assignment.
///
/// When scanned, it creates the child execution plan from the wrapped
/// table provider and adds a `WindowAssignExec` on top that computes
/// `window_start` and `window_end` for each row.
#[derive(Debug)]
pub struct WindowTableProvider {
    /// The input table being windowed.
    input: Arc<dyn TableProvider>,
    /// Window specification (tumble or hop).
    window_type: WindowType,
    /// Name of the timestamp column in the input table.
    timestamp_col: String,
    /// Output schema (window_start, window_end, + input columns).
    output_schema: SchemaRef,
}

impl WindowTableProvider {
    /// Create a new window table provider.
    ///
    /// # Arguments
    ///
    /// * `input` - The input table to add windows to
    /// * `window_type` - The window specification (tumble or hop)
    /// * `timestamp_col` - Name of the timestamp column
    pub fn new(
        input: Arc<dyn TableProvider>,
        window_type: WindowType,
        timestamp_col: String,
    ) -> Self {
        let input_schema = input.schema();
        let output_schema = build_window_schema(&input_schema);

        Self {
            input,
            window_type,
            timestamp_col,
            output_schema,
        }
    }
}

#[async_trait]
impl TableProvider for WindowTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.output_schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Temporary
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        // Get the child execution plan from the input table.
        // Pass through projection for input columns only (skip window_start/window_end).
        // We cannot push projection through the window assignment since the
        // window columns don't exist in the child.
        let child_plan = self.input.scan(state, None, filters, limit).await?;

        // Wrap with window assignment
        let window_exec = WindowAssignExec::new(
            child_plan,
            self.window_type.clone(),
            self.timestamp_col.clone(),
        );

        // If there's a projection, apply it on top of the window exec
        if let Some(proj) = projection {
            use datafusion::physical_expr::expressions::col;
            use datafusion::physical_plan::projection::ProjectionExec;

            let window_schema = window_exec.schema();
            let exprs: Vec<_> = proj
                .iter()
                .map(|&idx| {
                    let field = window_schema.field(idx);
                    let expr = col(field.name(), &window_schema)?;
                    Ok((
                        expr as Arc<dyn datafusion::physical_expr::PhysicalExpr>,
                        field.name().to_string(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;

            let projection_exec = ProjectionExec::try_new(exprs, Arc::new(window_exec))?;
            Ok(Arc::new(projection_exec))
        } else {
            Ok(Arc::new(window_exec))
        }
    }
}
