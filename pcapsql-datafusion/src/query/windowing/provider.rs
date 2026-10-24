//! The table a window function returns: a logical plan to inline.

use std::any::Any;
use std::borrow::Cow;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{plan_err, Result};
use datafusion::datasource::TableType;
use datafusion::logical_expr::{Expr, LogicalPlan};
use datafusion::physical_plan::ExecutionPlan;
use pcapsql_core::windowing::WindowType;

/// The provider a window table function returns.
///
/// It carries the window assignment as a logical plan over the source.
/// `LogicalPlanBuilder::scan` inlines a provider's `get_logical_plan` where
/// the function is referenced — the mechanism views use — so by the time the
/// SQL is planned the query reads the real protocol tables and the engine's
/// harvest, projection and filter pushdown see them. `scan` is therefore
/// never reached.
#[derive(Debug)]
pub struct WindowTableProvider {
    plan: LogicalPlan,
    schema: SchemaRef,
    window: WindowType,
}

impl WindowTableProvider {
    pub(super) fn new(plan: LogicalPlan, window: WindowType) -> Self {
        let schema = Arc::clone(plan.schema().inner());
        Self {
            plan,
            schema,
            window,
        }
    }

    /// The window this provider assigns.
    pub fn window(&self) -> &WindowType {
        &self.window
    }
}

#[async_trait]
impl TableProvider for WindowTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::View
    }

    fn get_logical_plan(&self) -> Option<Cow<'_, LogicalPlan>> {
        Some(Cow::Borrowed(&self.plan))
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        _projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        plan_err!(
            "{} is expanded into the query plan when the SQL is planned and cannot be \
             scanned directly",
            self.window
        )
    }
}
