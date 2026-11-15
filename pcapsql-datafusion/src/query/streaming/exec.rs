//! The fused streaming window aggregate operator.

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use arrow::datatypes::{DataType, SchemaRef};
use datafusion::common::{plan_err, Result};
use datafusion::execution::memory_pool::MemoryConsumer;
use datafusion::execution::TaskContext;
use datafusion::physical_expr::aggregate::AggregateFunctionExpr;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::{EquivalenceProperties, PhysicalExpr};
use datafusion::physical_plan::aggregates::PhysicalGroupBy;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::metrics::{ExecutionPlanMetricsSet, MetricsSet};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};

use super::config::{ContinuousConfig, MemoryLimitPolicy, WindowSpec};
use super::state::AggregateState;
// Named by the documentation only.
use super::stream::StreamingAggregateStream;
#[cfg(doc)]
use super::FuseWindowAggregate;
use crate::query::windowing::{WINDOW_END, WINDOW_START};

/// Streaming window aggregate over an unbounded, single-partition input.
///
/// Built only by [`FuseWindowAggregate`]; see the module documentation.
pub struct StreamingWindowAggregateExec {
    input: Arc<dyn ExecutionPlan>,
    pub(super) spec: WindowSpec,
    /// Timestamp column in `input` (appended by the rule under a reserved
    /// alias), and the source column's name for display.
    pub(super) ts_index: usize,
    ts_name: String,
    pub(super) group_by: PhysicalGroupBy,
    pub(super) aggr_expr: Vec<Arc<AggregateFunctionExpr>>,
    pub(super) filter_expr: Vec<Option<Arc<dyn PhysicalExpr>>>,
    /// Position of `window_start` / `window_end` among the group expressions.
    pub(super) window_start_pos: usize,
    pub(super) window_end_pos: Option<usize>,
    pub(super) schema: SchemaRef,
    pub(super) config: ContinuousConfig,
    properties: PlanProperties,
    pub(super) metrics: ExecutionPlanMetricsSet,
}

impl fmt::Debug for StreamingWindowAggregateExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingWindowAggregateExec")
            .field("spec", &self.spec)
            .field("ts_index", &self.ts_index)
            .finish()
    }
}

impl StreamingWindowAggregateExec {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_new(
        input: Arc<dyn ExecutionPlan>,
        spec: WindowSpec,
        ts_index: usize,
        ts_name: String,
        group_by: PhysicalGroupBy,
        aggr_expr: Vec<Arc<AggregateFunctionExpr>>,
        filter_expr: Vec<Option<Arc<dyn PhysicalExpr>>>,
        schema: SchemaRef,
        config: ContinuousConfig,
    ) -> Result<Self> {
        if !group_by.is_single() {
            return plan_err!(
                "continuous queries do not support GROUPING SETS, ROLLUP or CUBE; \
                 GROUP BY window_start and plain columns"
            );
        }
        let is_window_col = |name: &str, (expr, alias): &(Arc<dyn PhysicalExpr>, String)| {
            alias == name
                && expr
                    .as_any()
                    .downcast_ref::<Column>()
                    .is_some_and(|c| c.name() == name)
        };
        let Some(window_start_pos) = group_by
            .expr()
            .iter()
            .position(|g| is_window_col(WINDOW_START, g))
        else {
            return plan_err!(
                "a continuous query must GROUP BY window_start (the column tumble() / hop() \
                 adds), so that each window can be emitted when it closes"
            );
        };
        let window_end_pos = group_by
            .expr()
            .iter()
            .position(|g| is_window_col(WINDOW_END, g));
        for agg in &aggr_expr {
            if !agg.order_bys().is_empty() {
                return plan_err!(
                    "continuous queries do not support ORDER BY inside an aggregate ({})",
                    agg.name()
                );
            }
        }
        if schema.fields().len() != group_by.expr().len() + aggr_expr.len() {
            return plan_err!(
                "streaming aggregate: output schema does not match {} group and {} aggregate \
                 expressions",
                group_by.expr().len(),
                aggr_expr.len()
            );
        }
        match input.schema().field(ts_index).data_type() {
            DataType::Timestamp(arrow::datatypes::TimeUnit::Microsecond, _) => {}
            other => {
                return plan_err!(
                    "streaming aggregate: timestamp column has type {other}, expected \
                     Timestamp(Microsecond)"
                )
            }
        }
        let properties = PlanProperties::new(
            EquivalenceProperties::new(Arc::clone(&schema)),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            },
        );
        Ok(Self {
            input,
            spec,
            ts_index,
            ts_name,
            group_by,
            aggr_expr,
            filter_expr,
            window_start_pos,
            window_end_pos,
            schema,
            config,
            properties,
            metrics: ExecutionPlanMetricsSet::new(),
        })
    }

    /// The window the aggregate groups by.
    pub fn spec(&self) -> &WindowSpec {
        &self.spec
    }
}

impl DisplayAs for StreamingWindowAggregateExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        let groups: Vec<&str> = self
            .group_by
            .expr()
            .iter()
            .map(|(_, name)| name.as_str())
            .collect();
        let aggs: Vec<&str> = self.aggr_expr.iter().map(|a| a.name()).collect();
        write!(
            f,
            "StreamingWindowAggregateExec: window={}, timestamp={}, gby=[{}], aggr=[{}], \
             allowed_lateness={:?}",
            self.spec.window_type(),
            self.ts_name,
            groups.join(", "),
            aggs.join(", "),
            self.config.allowed_lateness
        )?;
        if let Some(idle) = self.config.idle_timeout {
            write!(f, ", idle_timeout={idle:?}")?;
        }
        if self.spec.sliced() {
            write!(f, ", sliced")?;
        }
        if self.config.on_memory_limit == MemoryLimitPolicy::CloseOldest {
            write!(f, ", on_memory_limit=close-oldest")?;
        }
        Ok(())
    }
}

impl ExecutionPlan for StreamingWindowAggregateExec {
    fn name(&self) -> &str {
        "StreamingWindowAggregateExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn required_input_distribution(&self) -> Vec<Distribution> {
        vec![Distribution::SinglePartition]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let Some(input) = children.into_iter().next() else {
            return plan_err!("StreamingWindowAggregateExec expects one child");
        };
        Ok(Arc::new(Self::try_new(
            input,
            self.spec.clone(),
            self.ts_index,
            self.ts_name.clone(),
            self.group_by.clone(),
            self.aggr_expr.clone(),
            self.filter_expr.clone(),
            Arc::clone(&self.schema),
            self.config.clone(),
        )?))
    }

    fn metrics(&self) -> Option<MetricsSet> {
        Some(self.metrics.clone_inner())
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return plan_err!("StreamingWindowAggregateExec has one partition, got {partition}");
        }
        let reservation = MemoryConsumer::new(format!("StreamingWindowAggregateExec[{partition}]"))
            .register(context.memory_pool());
        let input = self.input.execute(0, context)?;
        let state = AggregateState::try_new(self, partition, reservation)?;
        Ok(Box::pin(StreamingAggregateStream {
            input,
            state,
            queue: VecDeque::new(),
            schema: Arc::clone(&self.schema),
            idle_timeout: self.config.idle_timeout,
            idle: None,
            done: false,
        }))
    }
}
