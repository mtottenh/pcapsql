//! What a parse pass reports: the tables it materialized ([`TableData`]),
//! its statistics ([`ParseStats`], what `--stats` prints) and one streaming
//! producer's share of them ([`PartitionStat`]).

use std::collections::HashMap;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;

use super::exchange::OverflowStats;

/// One table's materialized data: its (possibly column-subset) schema and
/// per-partition batches in frame order.
#[derive(Clone, Debug)]
pub struct TableData {
    pub schema: SchemaRef,
    pub partitions: Vec<Vec<RecordBatch>>,
}

impl TableData {
    /// Total rows across all partitions.
    pub fn total_rows(&self) -> usize {
        self.partitions
            .iter()
            .flat_map(|p| p.iter())
            .map(|b| b.num_rows())
            .sum()
    }
}

/// Where a query's rows came from — what `--stats` reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServedFrom {
    /// A scoped parse pass over the capture.
    #[default]
    Parse,
    /// Entirely from the `CacheOnTouch` cache: nothing parsed.
    Cache,
    /// The boundary index (`count(*) FROM frames` fast path): nothing parsed.
    Index,
    /// The statement never executed a scan (`EXPLAIN`, DDL, `DESCRIBE`,
    /// `SET`, …): nothing was prepared. The only parse it can report is the
    /// one-time header-only time-range bootstrap of a source without a
    /// boundary index.
    PlanOnly,
}

/// Instrumentation for the most recent parse pass.
#[derive(Clone, Debug, Default)]
pub struct ParseStats {
    /// Parse passes performed for the query (0 = served from cache or the
    /// index). Includes the one-time header-only time-range bootstrap that a
    /// time-UDF query pays on a source without a boundary index.
    pub parse_passes: usize,
    /// Packets read from the source during the pass.
    pub packets_scanned: u64,
    /// Partitions the pass was split into.
    pub partitions: usize,
    /// Rows materialized per table.
    pub rows_built: HashMap<String, usize>,
    /// Observed timestamp range (microseconds), valid when packets > 0.
    pub start_ts_us: i64,
    pub end_ts_us: i64,
    /// False when a row cap (LIMIT) stopped the pass before end of input.
    pub complete_scan: bool,
    /// Streaming only: per table, bytes of batches that went through a
    /// producer's overflow buffer because DataFusion was not draining that
    /// table while it drained another (e.g. a hash-join probe side waiting
    /// on the build side). Zero when consumers keep pace.
    pub overflowed_bytes: HashMap<String, usize>,
    /// Streaming only: per table, the most bytes the overflow buffers held
    /// at once (summed over partitions) — the memory the exchange used
    /// beyond its channel bound.
    pub overflow_peak_bytes: HashMap<String, usize>,
    /// Stream-analysis tables built by this pass (sorted).
    /// Non-empty means the pass ran as one partition for reassembly order.
    pub stream_tables: Vec<String>,
    /// Where the rows came from; distinguishes a cache hit, the index fast
    /// path and a plan-only statement, which all report `parse_passes == 0`.
    pub served_from: ServedFrom,
    /// Continuous queries only: rows the streaming window aggregate dropped
    /// because their window had already been emitted when they arrived
    /// (later than `allowed_lateness` behind the stream, or after an idle
    /// timeout closed the window).
    pub late_rows: u64,
    /// Continuous queries only: windows the streaming window aggregate
    /// emitted before their time because the memory limit was reached
    /// (`--on-memory-limit close-oldest`).
    pub windows_forced: u64,
}

/// One partition producer's contribution to the pass statistics.
pub struct PartitionStat {
    pub min_us: i64,
    pub max_us: i64,
    pub packets: u64,
    pub capped: bool,
    /// What the producer did for each table of the pass, indexed by the
    /// table's [`OutputId`](pcapsql_core::scan::OutputId).
    pub outputs: Vec<OutputStat>,
}

/// One table's share of a [`PartitionStat`].
pub struct OutputStat {
    /// The table's name ([`SubscribedOutput::name`](super::SubscribedOutput::name)).
    pub table: Arc<str>,
    /// Rows built.
    pub rows: u64,
    /// What went through the exchange's overflow buffer (see
    /// [`ParseStats::overflowed_bytes`] / [`ParseStats::overflow_peak_bytes`]).
    pub overflow: OverflowStats,
}
