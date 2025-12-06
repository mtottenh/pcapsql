//! Streaming TableProvider for PCAP files.
//!
//! This module provides a TableProvider that reads PCAP files on-demand
//! using streaming execution, supporting filter and limit pushdown.

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown};
use datafusion::physical_plan::ExecutionPlan;

use crate::protocol::ProtocolRegistry;

use super::streaming::PcapStreamingExec;

/// A streaming TableProvider for PCAP files.
///
/// Unlike `PcapTableProvider` which loads all data into memory upfront,
/// this provider reads packets on-demand during query execution.
#[derive(Debug)]
pub struct StreamingPcapProvider {
    pcap_path: PathBuf,
    schema: SchemaRef,
    registry: Arc<ProtocolRegistry>,
    batch_size: usize,
}

impl StreamingPcapProvider {
    /// Create a new streaming provider.
    pub fn new(
        pcap_path: PathBuf,
        schema: SchemaRef,
        registry: Arc<ProtocolRegistry>,
        batch_size: usize,
    ) -> Self {
        Self {
            pcap_path,
            schema,
            registry,
            batch_size,
        }
    }
}

#[async_trait]
impl TableProvider for StreamingPcapProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    /// Indicate which filters can be pushed down.
    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DFResult<Vec<TableProviderFilterPushDown>> {
        // Return Inexact for simple predicates we can evaluate early
        // Return Unsupported for complex expressions
        let result = filters
            .iter()
            .map(|expr| classify_filter(expr))
            .collect();
        Ok(result)
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        Ok(Arc::new(PcapStreamingExec::new(
            self.pcap_path.clone(),
            self.schema.clone(),
            self.registry.clone(),
            self.batch_size,
            projection.cloned(),
            filters.to_vec(),
            limit,
        )))
    }
}

/// Classify a filter expression for pushdown support.
fn classify_filter(expr: &Expr) -> TableProviderFilterPushDown {
    match expr {
        // Simple column comparisons can be pushed down
        Expr::BinaryExpr(binary) => {
            use datafusion::logical_expr::Operator;

            match binary.op {
                // Comparison operators are good candidates
                Operator::Eq
                | Operator::NotEq
                | Operator::Lt
                | Operator::LtEq
                | Operator::Gt
                | Operator::GtEq => {
                    // Check if it's column vs literal
                    if is_simple_comparison(&binary.left, &binary.right) {
                        TableProviderFilterPushDown::Inexact
                    } else {
                        TableProviderFilterPushDown::Unsupported
                    }
                }
                // AND is pushable if both sides are
                Operator::And => {
                    let left = classify_filter(&binary.left);
                    let right = classify_filter(&binary.right);
                    combine_pushdown(left, right)
                }
                // OR is harder to optimize, don't push down
                Operator::Or => TableProviderFilterPushDown::Unsupported,
                _ => TableProviderFilterPushDown::Unsupported,
            }
        }
        // Column references alone (for boolean columns) are not supported
        Expr::Column(_) => TableProviderFilterPushDown::Unsupported,
        // Literals are technically pushable but useless
        Expr::Literal(_) => TableProviderFilterPushDown::Unsupported,
        // NOT can be pushed if inner is pushable
        Expr::Not(inner) => classify_filter(inner),
        // Everything else is unsupported
        _ => TableProviderFilterPushDown::Unsupported,
    }
}

/// Check if a binary expression is a simple column vs literal comparison.
fn is_simple_comparison(left: &Expr, right: &Expr) -> bool {
    matches!(
        (left, right),
        (Expr::Column(_), Expr::Literal(_)) | (Expr::Literal(_), Expr::Column(_))
    )
}

/// Combine two pushdown classifications (for AND).
fn combine_pushdown(
    left: TableProviderFilterPushDown,
    right: TableProviderFilterPushDown,
) -> TableProviderFilterPushDown {
    use TableProviderFilterPushDown::*;

    match (left, right) {
        // If either side is unsupported, the whole AND can still be partially pushed
        // but DataFusion will also apply the filter
        (Exact, Exact) => Exact,
        (Exact, Inexact) | (Inexact, Exact) | (Inexact, Inexact) => Inexact,
        (Unsupported, Inexact) | (Inexact, Unsupported) => Inexact,
        (Unsupported, Exact) | (Exact, Unsupported) => Inexact,
        (Unsupported, Unsupported) => Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;

    #[test]
    fn test_classify_simple_equality() {
        // protocol = 'TCP'
        let expr = col("protocol").eq(lit("TCP"));
        let result = classify_filter(&expr);
        assert!(matches!(result, TableProviderFilterPushDown::Inexact));
    }

    #[test]
    fn test_classify_port_comparison() {
        // dst_port = 80
        let expr = col("dst_port").eq(lit(80i32));
        let result = classify_filter(&expr);
        assert!(matches!(result, TableProviderFilterPushDown::Inexact));

        // dst_port > 1024
        let expr = col("dst_port").gt(lit(1024i32));
        let result = classify_filter(&expr);
        assert!(matches!(result, TableProviderFilterPushDown::Inexact));
    }

    #[test]
    fn test_classify_and_expression() {
        // protocol = 'TCP' AND dst_port = 80
        let expr = col("protocol")
            .eq(lit("TCP"))
            .and(col("dst_port").eq(lit(80i32)));
        let result = classify_filter(&expr);
        assert!(matches!(result, TableProviderFilterPushDown::Inexact));
    }

    #[test]
    fn test_classify_or_expression() {
        // protocol = 'TCP' OR protocol = 'UDP'
        let expr = col("protocol")
            .eq(lit("TCP"))
            .or(col("protocol").eq(lit("UDP")));
        let result = classify_filter(&expr);
        assert!(matches!(result, TableProviderFilterPushDown::Unsupported));
    }

    #[test]
    fn test_classify_column_only() {
        // Just a column reference (for boolean check)
        let expr = col("some_flag");
        let result = classify_filter(&expr);
        assert!(matches!(result, TableProviderFilterPushDown::Unsupported));
    }
}
