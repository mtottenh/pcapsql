//! cache_stats() table function for querying cache statistics.

use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

use arrow::array::{Float64Builder, Int64Builder, RecordBatch, UInt64Builder};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::common::Result;
use datafusion_catalog::TableFunctionImpl;
use datafusion::datasource::{TableProvider, TableType};
use datafusion_datasource::memory::MemorySourceConfig;
use datafusion::physical_plan::ExecutionPlan;
use datafusion::prelude::Expr;

use pcapsql_core::CacheStats;

/// Schema for cache_stats() output.
fn cache_stats_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("hits", DataType::UInt64, false),
        Field::new("misses", DataType::UInt64, false),
        Field::new("hit_ratio", DataType::Float64, false),
        Field::new("entries", DataType::Int64, false),
        Field::new("max_entries", DataType::Int64, false),
        Field::new("utilization", DataType::Float64, false),
        Field::new("evictions_lru", DataType::UInt64, false),
        Field::new("evictions_reader", DataType::UInt64, false),
        Field::new("evictions_total", DataType::UInt64, false),
        Field::new("peak_entries", DataType::Int64, false),
        Field::new("active_readers", DataType::Int64, false),
        Field::new("memory_bytes", DataType::Int64, false),
    ]))
}

/// Build a RecordBatch from CacheStats.
fn stats_to_batch(stats: &CacheStats) -> Result<RecordBatch> {
    let mut hits = UInt64Builder::with_capacity(1);
    let mut misses = UInt64Builder::with_capacity(1);
    let mut hit_ratio = Float64Builder::with_capacity(1);
    let mut entries = Int64Builder::with_capacity(1);
    let mut max_entries = Int64Builder::with_capacity(1);
    let mut utilization = Float64Builder::with_capacity(1);
    let mut evictions_lru = UInt64Builder::with_capacity(1);
    let mut evictions_reader = UInt64Builder::with_capacity(1);
    let mut evictions_total = UInt64Builder::with_capacity(1);
    let mut peak_entries = Int64Builder::with_capacity(1);
    let mut active_readers = Int64Builder::with_capacity(1);
    let mut memory_bytes = Int64Builder::with_capacity(1);

    hits.append_value(stats.hits);
    misses.append_value(stats.misses);
    hit_ratio.append_value(stats.hit_ratio());
    entries.append_value(stats.entries as i64);
    max_entries.append_value(stats.max_entries as i64);
    utilization.append_value(stats.utilization());
    evictions_lru.append_value(stats.evictions_lru);
    evictions_reader.append_value(stats.evictions_reader);
    evictions_total.append_value(stats.total_evictions());
    peak_entries.append_value(stats.peak_entries as i64);
    active_readers.append_value(stats.active_readers as i64);
    memory_bytes.append_value(stats.memory_bytes_estimate as i64);

    RecordBatch::try_new(
        cache_stats_schema(),
        vec![
            Arc::new(hits.finish()),
            Arc::new(misses.finish()),
            Arc::new(hit_ratio.finish()),
            Arc::new(entries.finish()),
            Arc::new(max_entries.finish()),
            Arc::new(utilization.finish()),
            Arc::new(evictions_lru.finish()),
            Arc::new(evictions_reader.finish()),
            Arc::new(evictions_total.finish()),
            Arc::new(peak_entries.finish()),
            Arc::new(active_readers.finish()),
            Arc::new(memory_bytes.finish()),
        ],
    )
    .map_err(|e| datafusion::error::DataFusionError::ArrowError(Box::new(e), None))
}

/// Table provider that returns cache statistics.
#[derive(Debug)]
pub struct CacheStatsTable {
    stats: CacheStats,
}

impl CacheStatsTable {
    pub fn new(stats: CacheStats) -> Self {
        Self { stats }
    }
}

#[async_trait]
impl TableProvider for CacheStatsTable {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        cache_stats_schema()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let batch = stats_to_batch(&self.stats)?;
        let schema = self.schema();

        // Let MemorySourceConfig handle the projection - pass full batch and schema
        Ok(MemorySourceConfig::try_new_exec(
            &[vec![batch]],
            schema,
            projection.cloned(),
        )? as Arc<dyn ExecutionPlan>)
    }
}

/// Table function implementation for cache_stats().
pub struct CacheStatsFunction {
    /// Function to get current stats (called at scan time).
    stats_fn: Arc<dyn Fn() -> Option<CacheStats> + Send + Sync>,
}

impl Debug for CacheStatsFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheStatsFunction").finish()
    }
}

impl CacheStatsFunction {
    pub fn new<F>(stats_fn: F) -> Self
    where
        F: Fn() -> Option<CacheStats> + Send + Sync + 'static,
    {
        Self {
            stats_fn: Arc::new(stats_fn),
        }
    }
}

impl TableFunctionImpl for CacheStatsFunction {
    fn call(&self, _args: &[Expr]) -> Result<Arc<dyn TableProvider>> {
        let stats = (self.stats_fn)().unwrap_or_default();
        Ok(Arc::new(CacheStatsTable::new(stats)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stats_schema() {
        let schema = cache_stats_schema();
        assert_eq!(schema.fields().len(), 12);
        assert!(schema.field_with_name("hits").is_ok());
        assert!(schema.field_with_name("misses").is_ok());
        assert!(schema.field_with_name("hit_ratio").is_ok());
        assert!(schema.field_with_name("entries").is_ok());
        assert!(schema.field_with_name("max_entries").is_ok());
        assert!(schema.field_with_name("utilization").is_ok());
        assert!(schema.field_with_name("evictions_lru").is_ok());
        assert!(schema.field_with_name("evictions_reader").is_ok());
        assert!(schema.field_with_name("evictions_total").is_ok());
        assert!(schema.field_with_name("peak_entries").is_ok());
        assert!(schema.field_with_name("active_readers").is_ok());
        assert!(schema.field_with_name("memory_bytes").is_ok());
    }

    #[test]
    fn test_stats_to_batch() {
        let stats = CacheStats {
            hits: 100,
            misses: 50,
            entries: 75,
            max_entries: 100,
            evictions_lru: 10,
            evictions_reader: 5,
            peak_entries: 80,
            active_readers: 2,
            memory_bytes_estimate: 76800,
        };

        let batch = stats_to_batch(&stats).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 12);
    }

    #[test]
    fn test_stats_to_batch_default() {
        let stats = CacheStats::default();
        let batch = stats_to_batch(&stats).unwrap();
        assert_eq!(batch.num_rows(), 1);
    }

    #[test]
    fn test_cache_stats_function_with_none() {
        let func = CacheStatsFunction::new(|| None);
        let result = func.call(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_stats_function_with_stats() {
        let func = CacheStatsFunction::new(|| {
            Some(CacheStats {
                hits: 50,
                misses: 25,
                ..Default::default()
            })
        });
        let result = func.call(&[]);
        assert!(result.is_ok());
    }
}
