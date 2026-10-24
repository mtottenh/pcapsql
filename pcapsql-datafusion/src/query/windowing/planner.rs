//! Physical planning of the window extension nodes.

use std::sync::Arc;

use async_trait::async_trait;
use datafusion::common::Result;
use datafusion::execution::context::QueryPlanner;
use datafusion::execution::session_state::SessionState;
use datafusion::logical_expr::{LogicalPlan, UserDefinedLogicalNode};
use datafusion::physical_plan::ExecutionPlan;
use datafusion::physical_planner::{DefaultPhysicalPlanner, ExtensionPlanner, PhysicalPlanner};

use super::hop::{HopAssign, HopAssignExec};
use super::session::{SessionAssign, SessionAssignExec};
use super::timestamp_index;

/// The engine's query planner: DataFusion's default planner plus the
/// planner for [`HopAssign`] and [`SessionAssign`].
#[derive(Debug, Default)]
pub struct WindowQueryPlanner;

#[async_trait]
impl QueryPlanner for WindowQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let planner =
            DefaultPhysicalPlanner::with_extension_planners(vec![Arc::new(WindowExtensionPlanner)]);
        planner
            .create_physical_plan(logical_plan, session_state)
            .await
    }
}

/// Plans `HopAssign` → `HopAssignExec` and `SessionAssign` →
/// `SessionAssignExec`; leaves other extension nodes to other planners.
#[derive(Debug)]
struct WindowExtensionPlanner;

#[async_trait]
impl ExtensionPlanner for WindowExtensionPlanner {
    async fn plan_extension(
        &self,
        _planner: &dyn PhysicalPlanner,
        node: &dyn UserDefinedLogicalNode,
        logical_inputs: &[&LogicalPlan],
        physical_inputs: &[Arc<dyn ExecutionPlan>],
        _session_state: &SessionState,
    ) -> Result<Option<Arc<dyn ExecutionPlan>>> {
        // Column positions are resolved on the logical input schema; the
        // physical input has the same columns in the same order.
        if let Some(hop) = node.as_any().downcast_ref::<HopAssign>() {
            let input_schema = logical_inputs[0].schema();
            let ts = timestamp_index(input_schema, hop.timestamp())?;
            let exec = HopAssignExec::try_new(
                Arc::clone(&physical_inputs[0]),
                ts,
                hop.slide_us(),
                hop.size_us(),
            )?;
            return Ok(Some(Arc::new(exec)));
        }
        if let Some(session) = node.as_any().downcast_ref::<SessionAssign>() {
            let input_schema = logical_inputs[0].schema();
            let ts = timestamp_index(input_schema, session.timestamp())?;
            let key = input_schema.index_of_column(session.key())?;
            let exec = SessionAssignExec::try_new(
                Arc::clone(&physical_inputs[0]),
                ts,
                key,
                session.gap_us(),
            )?;
            return Ok(Some(Arc::new(exec)));
        }
        Ok(None)
    }
}
