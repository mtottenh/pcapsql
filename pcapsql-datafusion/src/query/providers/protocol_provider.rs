//! Protocol table provider resolving its data from the query's own context.
//!
//! `QueryEngine::query` prepares the tables one query needs into a
//! [`QueryTables`] (materialized batches, or per-partition streaming
//! receivers) and carries it to the providers as a `SessionConfig` extension
//! of a per-query `SessionState`. DataFusion hands that state to
//! [`TableProvider::scan`] while it builds the physical plan — views are
//! inlined at logical planning, so every protocol scan reaches the provider
//! as a plain `TableScan` — and the provider serves its table from that
//! context. Nothing a query prepares is visible to another query, so
//! independent queries on one engine do not interfere; a query touching N
//! tables still parses the capture exactly once, scoped to what it needs.
//!
//! Under `RetentionPolicy::CacheOnTouch` materialized tables are also kept in
//! the engine-global [`TableCache`]; a later query snapshots the entries it
//! hits into its own `QueryTables`.
//!
//! When `scan` runs with no query context at all (EXPLAIN, DDL, or a query
//! issued directly on the session context) it yields a plan-only scan over
//! the table's full schema, so the plan can be built and displayed without
//! a parse; executing it fails with a clear message. A query context that
//! lacks the table is an error at planning time.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use super::exchange::BatchReceiver;
use super::shared::{StreamingHandle, TableData};
use super::ProtocolScanExec;
use crate::query::filter::FilterEvaluator;
use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::common::DataFusionError;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result as DFResult;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown};
use datafusion::physical_plan::ExecutionPlan;

/// Per-partition batch receivers for a streamed table (taken once at
/// `execute`).
pub type PartitionReceivers = Arc<Vec<Mutex<Option<BatchReceiver>>>>;

/// A table prepared for one query: either materialized batches (a cache
/// entry, the on-demand stream pass, or a materialize-path query) or
/// per-partition streaming receivers (`RetentionPolicy::None`).
pub enum PreparedTable {
    Batches(Arc<TableData>),
    Stream {
        schema: SchemaRef,
        /// One batch receiver per partition, taken once at `execute`.
        receivers: PartitionReceivers,
    },
}

impl PreparedTable {
    fn schema(&self) -> SchemaRef {
        match self {
            PreparedTable::Batches(d) => d.schema.clone(),
            PreparedTable::Stream { schema, .. } => schema.clone(),
        }
    }
}

/// The tables prepared for **one** query.
///
/// Built by `QueryEngine::query` before planning, carried to the providers as
/// a `SessionConfig` extension of that query's `SessionState`, and dropped
/// with the query: its stream receivers go away with it, so a cancelled query
/// releases its producers by ownership. Immutable once handed to DataFusion.
#[derive(Default)]
pub struct QueryTables {
    tables: HashMap<String, Arc<PreparedTable>>,
}

impl QueryTables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve `name` from materialized batches.
    pub fn insert_batches(&mut self, name: String, data: Arc<TableData>) {
        self.tables
            .insert(name, Arc::new(PreparedTable::Batches(data)));
    }

    /// Serve the streamed tables of an in-flight parse (takes the handle's
    /// receivers).
    pub fn insert_streams(&mut self, handle: &mut StreamingHandle) {
        for (name, receivers) in handle.receivers.drain() {
            let schema = handle
                .schemas
                .get(&name)
                .expect("streaming table schema")
                .clone();
            let slots: Vec<Mutex<Option<BatchReceiver>>> = receivers
                .into_iter()
                .map(|rx| Mutex::new(Some(rx)))
                .collect();
            self.tables.insert(
                name,
                Arc::new(PreparedTable::Stream {
                    schema,
                    receivers: Arc::new(slots),
                }),
            );
        }
    }

    /// The prepared table, if any.
    pub fn get(&self, name: &str) -> Option<Arc<PreparedTable>> {
        self.tables.get(name).cloned()
    }

    /// Whether the table is prepared for this query.
    pub fn contains(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }

    /// The partition count the query's plan is built for: the largest
    /// partition count among its prepared tables (1 when nothing is
    /// prepared). The tables of one parse pass share a count; a cache entry
    /// or a one-partition table (the `count(*)` fast path, a stream table)
    /// may differ, and a scan with fewer partitions than this is repartitioned
    /// from one, which keeps its order.
    pub fn partitions(&self) -> usize {
        self.tables
            .values()
            .map(|table| match table.as_ref() {
                PreparedTable::Batches(data) => data.partitions.len(),
                PreparedTable::Stream { receivers, .. } => receivers.len(),
            })
            .max()
            .unwrap_or(1)
            .max(1)
    }
}

/// The engine-global, column-aware table cache of
/// `RetentionPolicy::CacheOnTouch` (always empty under `RetentionPolicy::None`).
///
/// Shared by every query on the engine. A query reads the entries it hits
/// once, into its own [`QueryTables`], so a concurrent re-install can never
/// remove a column a running query planned against.
#[derive(Default)]
pub struct TableCache {
    entries: RwLock<HashMap<String, Arc<TableData>>>,
}

impl TableCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install materialized tables, widening only: an entry is replaced only
    /// when the new column set is a superset of the current one, so a
    /// concurrent narrower query cannot shrink what a wider one cached (the
    /// installing query runs on its own data regardless). With `{a, b}`
    /// cached and `{a, c}` arriving, the latter is discarded and a later
    /// `{c}` query re-parses the union `{a, b, c}`.
    pub fn install(&self, tables: HashMap<String, Arc<TableData>>) {
        let mut entries = self.entries.write().expect("TableCache lock poisoned");
        for (name, data) in tables {
            let widens = entries
                .get(&name)
                .is_none_or(|current| column_names(current).is_subset(&column_names(&data)));
            if widens {
                entries.insert(name, data);
            }
        }
    }

    /// The cached table, if any.
    pub fn get(&self, name: &str) -> Option<Arc<TableData>> {
        self.entries
            .read()
            .expect("TableCache lock poisoned")
            .get(name)
            .cloned()
    }

    /// Whether the table is cached (with any column set).
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// The column names of a cached table (`None` if not cached).
    pub fn cached_columns(&self, name: &str) -> Option<HashSet<String>> {
        self.get(name).map(|data| column_names(&data))
    }

    /// One entry per cached table, sorted by name: what the REPL's
    /// `.cachestats` reports.
    pub fn summary(&self) -> Vec<CachedTable> {
        let entries = self.entries.read().expect("TableCache lock poisoned");
        let mut out: Vec<CachedTable> = entries
            .iter()
            .map(|(name, data)| CachedTable {
                name: name.clone(),
                columns: data.schema.fields().len(),
                rows: data.total_rows(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Drop every cached table. Running queries keep the snapshot they took
    /// at preparation; later queries re-parse on first touch.
    pub fn clear(&self) {
        self.entries
            .write()
            .expect("TableCache lock poisoned")
            .clear();
    }
}

/// A cached table as reported by [`TableCache::summary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedTable {
    /// Table name.
    pub name: String,
    /// Columns materialized for it (the cache is column-aware).
    pub columns: usize,
    /// Rows cached.
    pub rows: usize,
}

/// The column names of a materialized table.
pub fn column_names(data: &TableData) -> HashSet<String> {
    data.schema
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect()
}

/// Table provider for a single protocol table, serving from the query's
/// [`QueryTables`].
pub struct ProtocolTableProvider {
    table_name: String,
    /// The table's full schema (planning surface; data may be a subset).
    schema: SchemaRef,
    /// Nominal partition count reported by a plan-only scan (the engine's
    /// parse parallelism).
    default_partitions: usize,
}

impl ProtocolTableProvider {
    pub fn new(table_name: String, schema: SchemaRef, default_partitions: usize) -> Self {
        Self {
            table_name,
            schema,
            default_partitions,
        }
    }

    /// Scan a table prepared for this query, remapping the projection from
    /// the full schema to the (possibly column-subset) prepared data.
    fn scan_prepared(
        &self,
        prepared: &PreparedTable,
        projection: Option<&Vec<usize>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        let data_schema = prepared.schema();

        // `projection` indexes the FULL table schema; the materialized/streamed
        // data may be a column subset. Remap by field name into that schema.
        let remapped: Option<Vec<usize>> = match projection {
            Some(indices) => Some(
                indices
                    .iter()
                    .map(|&i| {
                        let name = self.schema.field(i).name();
                        data_schema.index_of(name).map_err(|_| {
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
                if data_schema.fields().len() != self.schema.fields().len() {
                    return Err(DataFusionError::Execution(format!(
                        "table '{}' was materialized with a column subset but \
                         scanned without a projection",
                        self.table_name
                    )));
                }
                None
            }
        };

        let exec = match prepared {
            PreparedTable::Batches(data) => ProtocolScanExec::batches(
                self.table_name.clone(),
                data.schema.clone(),
                Arc::new(data.partitions.clone()),
                remapped,
            ),
            PreparedTable::Stream { schema, receivers } => ProtocolScanExec::streaming(
                self.table_name.clone(),
                schema.clone(),
                receivers.clone(),
                remapped,
            ),
        };
        Ok(Arc::new(exec))
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
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        // The query's prepared tables travel on the session config; the
        // physical planner passes the per-query state straight into `scan`.
        let Some(tables) = state.config().get_extension::<QueryTables>() else {
            // No query context: the statement is plan-only (EXPLAIN) or
            // bypassed `QueryEngine::query`. Plan over the full schema; fail
            // at execute.
            return Ok(Arc::new(ProtocolScanExec::plan_only(
                self.table_name.clone(),
                self.schema.clone(),
                projection.cloned(),
                self.default_partitions,
            )));
        };
        // A query context that lacks this table means the engine's harvest
        // missed a scan: fail at planning, never serve a plan-only exec.
        let prepared = tables.get(&self.table_name).ok_or_else(|| {
            DataFusionError::Execution(format!(
                "table '{}' was not prepared for this query; \
                 run queries through QueryEngine::query",
                self.table_name
            ))
        })?;
        self.scan_prepared(&prepared, projection)
    }
}

impl std::fmt::Debug for ProtocolTableProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolTableProvider")
            .field("table_name", &self.table_name)
            .finish()
    }
}
