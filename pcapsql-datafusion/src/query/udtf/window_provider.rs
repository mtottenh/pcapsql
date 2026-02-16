//! Table providers for window TVFs.
//!
//! These providers wrap an input table and add window assignment via
//! `WindowAssignExec` (tumble/hop) or `SessionAssignExec` (session) at scan time.

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

use super::session_exec::SessionAssignExec;
use super::window_exec::{build_window_schema, WindowAssignExec};

/// Table provider that wraps an input table with window assignment.
///
/// When scanned, it creates the child execution plan from the wrapped
/// table provider and adds window assignment on top:
/// - For tumble/hop: `WindowAssignExec` (per-batch, O(1) per row)
/// - For session: `SessionAssignExec` (buffering, requires all data)
#[derive(Debug)]
pub struct WindowTableProvider {
    /// The input table being windowed.
    input: Arc<dyn TableProvider>,
    /// Window specification (tumble, hop, or session).
    window_type: WindowType,
    /// Name of the timestamp column in the input table.
    timestamp_col: String,
    /// Name of the key column for session partitioning (None for tumble/hop).
    key_col: Option<String>,
    /// Output schema (window_start, window_end, + input columns).
    output_schema: SchemaRef,
}

impl WindowTableProvider {
    /// Create a new window table provider for tumble or hop windows.
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
            key_col: None,
            output_schema,
        }
    }

    /// Create a new window table provider for session windows.
    ///
    /// # Arguments
    ///
    /// * `input` - The input table to add windows to
    /// * `window_type` - The window specification (session)
    /// * `timestamp_col` - Name of the timestamp column
    /// * `key_col` - Name of the key column for session partitioning
    pub fn new_session(
        input: Arc<dyn TableProvider>,
        window_type: WindowType,
        timestamp_col: String,
        key_col: String,
    ) -> Self {
        let input_schema = input.schema();
        let output_schema = build_window_schema(&input_schema);

        Self {
            input,
            window_type,
            timestamp_col,
            key_col: Some(key_col),
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
        let child_plan = self.input.scan(state, None, filters, limit).await?;

        // Create the appropriate window exec based on window type
        let window_exec: Arc<dyn ExecutionPlan> = match &self.window_type {
            WindowType::Session { gap } => {
                let key_col = self.key_col.as_ref().ok_or_else(|| {
                    datafusion::error::DataFusionError::Internal(
                        "Session window requires a key column".to_string(),
                    )
                })?;
                Arc::new(SessionAssignExec::new(
                    child_plan,
                    key_col.clone(),
                    self.timestamp_col.clone(),
                    *gap,
                ))
            }
            _ => Arc::new(WindowAssignExec::new(
                child_plan,
                self.window_type.clone(),
                self.timestamp_col.clone(),
            )),
        };

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

            let projection_exec = ProjectionExec::try_new(exprs, window_exec)?;
            Ok(Arc::new(projection_exec))
        } else {
            Ok(window_exec)
        }
    }
}
