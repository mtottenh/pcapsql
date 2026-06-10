//! Protocol table provider backed by the engine's per-query parse state.
//!
//! Every provider holds the same [`EngineTables`] handle. `QueryEngine::query`
//! installs each query's scoped parse result (or cache entries) before
//! executing the physical plan, and the provider serves its table from that
//! state — so a query touching N tables still parses the capture exactly
//! once, scoped to what the query needs.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::common::DataFusionError;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown};
use datafusion::physical_plan::ExecutionPlan;

use super::shared::TableData;
use super::ProtocolScanExec;
use crate::query::filter::FilterEvaluator;

/// The tables currently materialized for query execution.
///
/// - `current` holds the per-query scoped parse result
///   (`RetentionPolicy::None`, cleared after each query) or the accumulated
///   cache (`RetentionPolicy::CacheOnTouch`).
/// - `pinned` holds tables installed once at engine open and never cleared
///   (the keylog-decrypted `http2` table, until migration phase P4 folds the
///   stream pass into the shared parse).
#[derive(Debug, Default)]
pub struct EngineTables {
    current: RwLock<HashMap<String, Arc<TableData>>>,
    pinned: RwLock<HashMap<String, Arc<TableData>>>,
}

impl EngineTables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or replace) table entries for the current query / cache.
    pub fn install(&self, tables: HashMap<String, Arc<TableData>>) {
        self.current
            .write()
            .expect("EngineTables lock poisoned")
            .extend(tables);
    }

    /// Pin a table for the lifetime of the engine (survives `clear`).
    pub fn pin(&self, name: String, data: Arc<TableData>) {
        self.pinned
            .write()
            .expect("EngineTables lock poisoned")
            .insert(name, data);
    }

    /// Drop all non-pinned entries (`RetentionPolicy::None`, post-query).
    pub fn clear(&self) {
        self.current
            .write()
            .expect("EngineTables lock poisoned")
            .clear();
    }

    /// Fetch a table's data (pinned entries win).
    pub fn get(&self, name: &str) -> Option<Arc<TableData>> {
        if let Some(data) = self
            .pinned
            .read()
            .expect("EngineTables lock poisoned")
            .get(name)
        {
            return Some(data.clone());
        }
        self.current
            .read()
            .expect("EngineTables lock poisoned")
            .get(name)
            .cloned()
    }

    /// Whether the table is already materialized (pinned or current).
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

/// Table provider for a single protocol table, serving from [`EngineTables`].
pub struct ProtocolTableProvider {
    table_name: String,
    /// The table's full schema (planning surface; data may be a subset).
    schema: SchemaRef,
    tables: Arc<EngineTables>,
}

impl ProtocolTableProvider {
    pub fn new(table_name: String, schema: SchemaRef, tables: Arc<EngineTables>) -> Self {
        Self {
            table_name,
            schema,
            tables,
        }
    }
}

#[async_trait]
impl TableProvider for ProtocolTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DFResult<Vec<TableProviderFilterPushDown>> {
        Ok(filters
            .iter()
            .map(|expr| {
                // frames columns are packet metadata, not parse fields — the
                // parse-time evaluator cannot see them.
                if self.table_name != "frames" && FilterEvaluator::expr_is_pushable(expr) {
                    // Inexact: rows may be pre-dropped at parse time;
                    // DataFusion re-applies the filter to whatever is kept.
                    TableProviderFilterPushDown::Inexact
                } else {
                    TableProviderFilterPushDown::Unsupported
                }
            })
            .collect())
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        let data = self.tables.get(&self.table_name).ok_or_else(|| {
            DataFusionError::Execution(format!(
                "table '{}' was not prepared for this query; \
                 run queries through QueryEngine::query",
                self.table_name
            ))
        })?;

        // `projection` indexes the FULL table schema; the materialized data
        // may be a column subset. Remap by field name into the data's schema.
        let remapped: Option<Vec<usize>> = match projection {
            Some(indices) => Some(
                indices
                    .iter()
                    .map(|&i| {
                        let name = self.schema.field(i).name();
                        data.schema.index_of(name).map_err(|_| {
                            DataFusionError::Execution(format!(
                                "column '{}' of table '{}' was not materialized for this query",
                                name, self.table_name
                            ))
                        })
                    })
                    .collect::<DFResult<Vec<usize>>>()?,
            ),
            None => {
                // Full-schema scan: only valid when the data is full-width.
                if data.schema.fields().len() != self.schema.fields().len() {
                    return Err(DataFusionError::Execution(format!(
                        "table '{}' was materialized with a column subset but \
                         scanned without a projection",
                        self.table_name
                    )));
                }
                None
            }
        };

        Ok(Arc::new(ProtocolScanExec::new(
            self.table_name.clone(),
            data.schema.clone(),
            Arc::new(data.partitions.clone()),
            remapped,
        )))
    }
}

impl std::fmt::Debug for ProtocolTableProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolTableProvider")
            .field("table_name", &self.table_name)
            .finish()
    }
}
