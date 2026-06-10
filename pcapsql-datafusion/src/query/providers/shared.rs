//! The scoped, shared single-pass parse.
//!
//! A query touching N protocol tables parses the capture **once**, not once
//! per table — and only as much of it as the query needs. The engine
//! harvests each query's optimized plan into a [`ParseSubscription`]
//! (which tables, which columns, parse-time predicates, row caps), and
//! [`run_shared_parse`] performs one fan-out parse pass restricted to that
//! subscription, in parallel across partitions for seekable sources.
//!
//! Partitions are range-partitioned by frame number and reassembled in frame
//! order, so the result is identical to a single-partition parse — the
//! property the partition-equivalence tests assert.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use datafusion::error::Result as DFResult;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;

use pcapsql_core::io::PacketRange;
use pcapsql_core::{
    parse_packet, PacketReader, ParseScope, ProtocolRegistry, SeekablePacketSource,
};

use crate::error::Error;
use crate::query::builders::NormalizedBatchSet;
use crate::query::filter::FilterEvaluator;
use crate::query::tables;

/// Minimum object size before a `Cheap`-seek source is partitioned.
const CHEAP_MIN_BYTES: u64 = 4 * 1024 * 1024;
/// Minimum object size before a `RangeRequest`-seek source is partitioned
/// (network round trips must be amortized).
const RANGE_MIN_BYTES: u64 = 16 * 1024 * 1024;

/// Progress callback: invoked with the cumulative packet count during parse.
pub type ProgressFn = Arc<dyn Fn(u64) + Send + Sync>;

/// One table's subscription within a parse pass.
#[derive(Clone, Debug, Default)]
pub struct TableSubscription {
    /// Columns to materialize (schema order is preserved); `None` = all.
    pub columns: Option<HashSet<String>>,
    /// Parse-time predicate (conservative; DataFusion re-checks).
    pub predicate: Option<FilterEvaluator>,
    /// Per-partition row cap from a pushed-down `LIMIT`.
    pub fetch: Option<usize>,
}

/// What one parse pass materializes: the tables a query references, each
/// with optional column scoping, predicates and row caps.
#[derive(Clone, Debug, Default)]
pub struct ParseSubscription {
    pub tables: HashMap<String, TableSubscription>,
}

impl ParseSubscription {
    /// Subscribe to the given tables with full columns, no predicates, no
    /// caps (the cache-fill shape).
    pub fn tables_full<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            tables: names
                .into_iter()
                .map(|n| (n.into(), TableSubscription::default()))
                .collect(),
        }
    }

    /// The protocol-level scope for this subscription: the subscribed
    /// tables' protocols plus dependency closure, with per-protocol field
    /// projections where columns are scoped.
    fn parse_scope(&self, registry: &ProtocolRegistry) -> ParseScope {
        let names: Vec<&str> = self.tables.keys().map(String::as_str).collect();
        let mut scope = ParseScope::for_tables(&names, registry);

        for (table, sub) in &self.tables {
            if table == "frames" {
                continue; // frames come from packet metadata, not parsing
            }
            if let Some(columns) = &sub.columns {
                // Pseudo-columns are populated from ParseResult context, not
                // extracted fields; they don't belong in the field projection.
                let fields: HashSet<String> = columns
                    .iter()
                    .filter(|c| {
                        !matches!(
                            c.as_str(),
                            "frame_number" | "encap_depth" | "tunnel_type" | "tunnel_id"
                        )
                    })
                    .cloned()
                    .collect();
                scope = scope.with_projection(table.clone(), fields);
            }
        }
        scope
    }

    /// The column-subset Arrow schema a subscribed table materializes.
    pub fn table_schema(&self, table: &str) -> Option<SchemaRef> {
        let full = tables::get_table_schema(table)?;
        let sub = self.tables.get(table)?;
        match &sub.columns {
            None => Some(Arc::new(full)),
            Some(cols) => {
                let fields: Vec<_> = full
                    .fields()
                    .iter()
                    .filter(|f| cols.contains(f.name().as_str()))
                    .cloned()
                    .collect();
                Some(Arc::new(arrow::datatypes::Schema::new(fields)))
            }
        }
    }
}

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

/// Instrumentation for the most recent parse pass.
#[derive(Clone, Debug, Default)]
pub struct ParseStats {
    /// Parse passes performed for the last query (0 = served from cache).
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
}

/// Result of one scoped parse pass.
pub struct SharedParseState {
    tables: HashMap<String, Arc<TableData>>,
    stats: ParseStats,
}

impl SharedParseState {
    /// Decompose into the materialized tables and the pass statistics.
    pub fn into_tables(self) -> (HashMap<String, Arc<TableData>>, ParseStats) {
        (self.tables, self.stats)
    }

    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }
}

/// Decide the partition ranges for a source, gating on seek cost and size.
fn decide_ranges<S: SeekablePacketSource>(
    source: &S,
    target_partitions: usize,
) -> Result<Vec<PacketRange>, Error> {
    use pcapsql_core::SeekCost;
    let size = source.metadata().size_bytes.unwrap_or(0);
    let target = target_partitions.max(1);
    let want = match source.seek_cost() {
        SeekCost::Free => target,
        SeekCost::Cheap => {
            if size >= CHEAP_MIN_BYTES {
                target
            } else {
                1
            }
        }
        SeekCost::RangeRequest => {
            if size >= RANGE_MIN_BYTES {
                target
            } else {
                1
            }
        }
    };
    if want <= 1 {
        Ok(vec![PacketRange::whole()])
    } else {
        Ok(source.partitions(want)?)
    }
}

/// Per-partition parse output.
struct PartitionOutput {
    batches: HashMap<String, Vec<RecordBatch>>,
    min_us: i64,
    max_us: i64,
    packets: u64,
    capped: bool,
}

/// Parse a single partition into per-table batches restricted to the
/// subscription.
#[allow(clippy::too_many_arguments)]
fn parse_partition<S: SeekablePacketSource>(
    source: &S,
    registry: &ProtocolRegistry,
    scope: &ParseScope,
    subscription: &ParseSubscription,
    batch_size: usize,
    range: &PacketRange,
    single: bool,
    progress: Option<(&AtomicU64, &ProgressFn)>,
) -> Result<PartitionOutput, Error> {
    let mut reader = if single {
        source.sequential_reader()?
    } else {
        source.reader_at(range)?
    };

    let mut batch_set = NormalizedBatchSet::new(batch_size, subscription)?;
    let mut min_us = i64::MAX;
    let mut max_us = i64::MIN;
    let mut packets: u64 = 0;
    let mut capped = false;

    loop {
        let processed = reader.process_packets(1024, |packet| {
            let us = packet.timestamp_ns / 1_000;
            if us < min_us {
                min_us = us;
            }
            if us > max_us {
                max_us = us;
            }
            // Per-packet link type is correct even for PCAPNG multi-interface.
            let parsed = parse_packet(registry, packet.link_type, packet.data, scope);
            batch_set.add_packet_from_ref(packet, &parsed)?;
            Ok(())
        })?;
        packets += processed as u64;
        if let Some((counter, cb)) = progress {
            let total = counter.fetch_add(processed as u64, Ordering::Relaxed) + processed as u64;
            cb(total);
        }
        if processed == 0 {
            break;
        }
        if batch_set.all_capped() {
            capped = true;
            break;
        }
    }

    Ok(PartitionOutput {
        batches: batch_set.finish()?,
        min_us,
        max_us,
        packets,
        capped,
    })
}

/// Run one scoped parse pass over a seekable source, fanning out to the
/// subscribed tables. Parses partitions in parallel when more than one;
/// each worker owns its reader and builders — no shared mutable state.
pub fn run_shared_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    target_partitions: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
) -> Result<SharedParseState, Error> {
    let scope = subscription.parse_scope(registry);
    let ranges = decide_ranges(source.as_ref(), target_partitions)?;
    let single = ranges.len() == 1;
    let progress_count = AtomicU64::new(0);

    let results: Vec<Result<PartitionOutput, Error>> = if single {
        vec![parse_partition(
            source.as_ref(),
            registry,
            &scope,
            subscription,
            batch_size,
            &ranges[0],
            true,
            progress.as_ref().map(|cb| (&progress_count, cb)),
        )]
    } else {
        std::thread::scope(|thread_scope| {
            let handles: Vec<_> = ranges
                .iter()
                .map(|range| {
                    let source = source.clone();
                    let registry = registry.clone();
                    let range = range.clone();
                    let scope = &scope;
                    let progress = progress.as_ref().map(|cb| (&progress_count, cb));
                    thread_scope.spawn(move || {
                        parse_partition(
                            source.as_ref(),
                            &registry,
                            scope,
                            subscription,
                            batch_size,
                            &range,
                            false,
                            progress,
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| {
                        Err(Error::Query(crate::error::QueryError::Execution(
                            "parse worker panicked".into(),
                        )))
                    })
                })
                .collect()
        })
    };

    // Surface the first error, if any; otherwise collect partition outputs.
    let mut outputs: Vec<HashMap<String, Vec<RecordBatch>>> = Vec::with_capacity(results.len());
    let mut start_ts_us = i64::MAX;
    let mut end_ts_us = i64::MIN;
    let mut packets_scanned: u64 = 0;
    let mut complete_scan = true;
    for r in results {
        let out = r?;
        if out.min_us != i64::MAX {
            start_ts_us = start_ts_us.min(out.min_us);
        }
        if out.max_us != i64::MIN {
            end_ts_us = end_ts_us.max(out.max_us);
        }
        packets_scanned += out.packets;
        complete_scan &= !out.capped;
        outputs.push(out.batches);
    }
    if start_ts_us == i64::MAX {
        start_ts_us = 0;
        end_ts_us = 0;
    }

    // Reorganize: table -> per-partition Vec<RecordBatch> (frame order).
    let num_partitions = outputs.len();
    let mut tables_out: HashMap<String, Arc<TableData>> = HashMap::new();
    let mut rows_built: HashMap<String, usize> = HashMap::new();
    for table in subscription.tables.keys() {
        let schema = subscription.table_schema(table).ok_or_else(|| {
            Error::Query(crate::error::QueryError::Execution(format!(
                "Unknown table: {table}"
            )))
        })?;
        let partitions: Vec<Vec<RecordBatch>> = outputs
            .iter_mut()
            .map(|pb| pb.remove(table).unwrap_or_default())
            .collect();
        let data = TableData { schema, partitions };
        rows_built.insert(table.clone(), data.total_rows());
        tables_out.insert(table.clone(), Arc::new(data));
    }

    Ok(SharedParseState {
        tables: tables_out,
        stats: ParseStats {
            parse_passes: 1,
            packets_scanned,
            partitions: num_partitions,
            rows_built,
            start_ts_us,
            end_ts_us,
            complete_scan,
        },
    })
}

// ============================================================================
// Streaming parse (RetentionPolicy::None) — bounded-memory pipeline.
// ============================================================================

/// One partition producer's contribution to the pass statistics.
pub struct PartitionStat {
    pub min_us: i64,
    pub max_us: i64,
    pub packets: u64,
    pub capped: bool,
    pub rows_built: HashMap<String, usize>,
}

/// Handle to an in-flight streaming parse.
///
/// Per subscribed table it holds one batch receiver per partition (in
/// partition order); `ProtocolScanExec` takes a receiver to serve
/// `execute(partition)`. The producer join handles are awaited by the engine
/// after query execution to fold statistics and surface parse errors.
pub struct StreamingHandle {
    pub receivers: HashMap<String, Vec<UnboundedReceiver<DFResult<RecordBatch>>>>,
    pub producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    pub num_partitions: usize,
    pub schemas: HashMap<String, SchemaRef>,
}

/// Start one scoped parse pass that **streams** each subscribed table's
/// batches to per-(table, partition) unbounded channels.
///
/// One `spawn_blocking` producer per partition owns its reader and builders
/// and runs the parse to completion, sending completed batches as they form.
/// Channels are unbounded, so a producer never blocks on a consumer — the
/// pass is deadlock-free regardless of how DataFusion drains the tables.
/// Memory stays bounded when consumers keep pace (the sort-merge-join,
/// frame-ordered common case) and degrades to buffering a table otherwise.
pub fn run_streaming_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    target_partitions: usize,
    progress: Option<ProgressFn>,
    subscription: &ParseSubscription,
) -> Result<StreamingHandle, Error> {
    let scope = Arc::new(subscription.parse_scope(registry));
    let ranges = decide_ranges(source.as_ref(), target_partitions)?;
    let single = ranges.len() == 1;
    let num_partitions = ranges.len();
    let progress_count = Arc::new(AtomicU64::new(0));

    let table_names: Vec<String> = subscription.tables.keys().cloned().collect();
    let mut schemas = HashMap::with_capacity(table_names.len());
    for name in &table_names {
        let schema = subscription.table_schema(name).ok_or_else(|| {
            Error::Query(crate::error::QueryError::Execution(format!(
                "Unknown table: {name}"
            )))
        })?;
        schemas.insert(name.clone(), schema);
    }

    // receivers[table] = one receiver per partition, in partition order.
    let mut receivers: HashMap<String, Vec<UnboundedReceiver<DFResult<RecordBatch>>>> = table_names
        .iter()
        .map(|n| (n.clone(), Vec::with_capacity(num_partitions)))
        .collect();
    let mut producers = Vec::with_capacity(num_partitions);

    for range in ranges {
        // Per-table channel for this partition.
        let mut senders = HashMap::with_capacity(table_names.len());
        for name in &table_names {
            let (tx, rx) = unbounded_channel::<DFResult<RecordBatch>>();
            senders.insert(name.clone(), tx);
            receivers.get_mut(name).expect("receiver slot").push(rx);
        }

        let source = source.clone();
        let registry = registry.clone();
        let scope = scope.clone();
        let subscription = subscription.clone();
        let progress = progress.clone();
        let progress_count = progress_count.clone();
        let tables: Vec<String> = table_names.clone();

        producers.push(tokio::task::spawn_blocking(move || {
            let mut reader = if single {
                source.sequential_reader()?
            } else {
                source.reader_at(&range)?
            };
            let mut batch_set =
                NormalizedBatchSet::new_streaming(batch_size, &subscription, &senders)?;
            let mut min_us = i64::MAX;
            let mut max_us = i64::MIN;
            let mut packets: u64 = 0;
            let mut capped = false;

            loop {
                let processed = reader.process_packets(1024, |packet| {
                    let us = packet.timestamp_ns / 1_000;
                    min_us = min_us.min(us);
                    max_us = max_us.max(us);
                    let parsed = parse_packet(&registry, packet.link_type, packet.data, &scope);
                    batch_set.add_packet_from_ref(packet, &parsed)?;
                    Ok(())
                })?;
                packets += processed as u64;
                if let Some(cb) = &progress {
                    let total = progress_count.fetch_add(processed as u64, Ordering::Relaxed)
                        + processed as u64;
                    cb(total);
                }
                if processed == 0 {
                    break;
                }
                if batch_set.all_capped() {
                    capped = true;
                    break;
                }
            }

            let rows_built: HashMap<String, usize> = tables
                .iter()
                .map(|t| (t.clone(), batch_set.row_count(t)))
                .collect();
            // finish() flushes final batches and drops the sink senders; the
            // remaining `senders` map drops at return, closing the channels.
            batch_set.finish()?;
            drop(senders);

            Ok(PartitionStat {
                min_us,
                max_us,
                packets,
                capped,
                rows_built,
            })
        }));
    }

    Ok(StreamingHandle {
        receivers,
        producers,
        num_partitions,
        schemas,
    })
}
