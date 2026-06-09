//! Shared single-pass parse — the implementation of #6 and #9.
//!
//! A query touching N protocol tables must parse the capture **once**, not once
//! per table. This module performs a single fan-out parse pass over the source,
//! routing every packet into per-protocol Arrow builders ([`NormalizedBatchSet`])
//! exactly as the in-memory path does, and memoizes the per-table batches so all
//! table providers share them.
//!
//! For a [`SeekablePacketSource`] the single pass is split into partitions and
//! parsed in parallel — one worker per partition, each owning its own reader and
//! builders, with no shared mutable state to lock (mmap is the zero-cost case).
//! The cost hint gates whether partitioning is worthwhile. Non-seekable sources
//! degrade honestly to a single partition.
//!
//! Partitions are range-partitioned by frame number and reassembled in frame
//! order, so the result is identical to a single-partition parse — the property
//! the partition-equivalence tests assert.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::record_batch::RecordBatch;

use pcapsql_core::io::PacketRange;
use pcapsql_core::{parse_packet, PacketReader, ProtocolRegistry, SeekablePacketSource};

use crate::error::Error;
use crate::query::builders::{NormalizedBatchSet, ProtocolBatches};

/// Minimum object size before a `Cheap`-seek source is partitioned.
const CHEAP_MIN_BYTES: u64 = 4 * 1024 * 1024;
/// Minimum object size before a `RangeRequest`-seek source is partitioned
/// (network round trips must be amortized).
const RANGE_MIN_BYTES: u64 = 16 * 1024 * 1024;

/// Result of the shared parse pass: per-table batches grouped by partition.
pub struct SharedParseState {
    /// table name -> (one `Vec<RecordBatch>` per partition, in frame order).
    tables: HashMap<String, Vec<Vec<RecordBatch>>>,
    /// Number of partitions the pass used.
    num_partitions: usize,
    /// Number of parse passes performed (always 1; exposed for instrumentation).
    parse_passes: usize,
    /// Earliest / latest packet timestamp seen (microseconds), for time UDFs.
    start_ts_us: i64,
    end_ts_us: i64,
    /// Total frames across all partitions.
    total_frames: usize,
}

impl SharedParseState {
    /// Per-partition batches for a table (empty vec of partitions if unknown).
    pub fn table_partitions(&self, table: &str) -> Vec<Vec<RecordBatch>> {
        self.tables.get(table).cloned().unwrap_or_default()
    }

    /// Number of output partitions.
    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    /// Number of parse passes performed over the source (instrumentation for #6).
    pub fn parse_passes(&self) -> usize {
        self.parse_passes
    }

    /// (start, end) timestamps in microseconds.
    pub fn timestamp_range_us(&self) -> (i64, i64) {
        (self.start_ts_us, self.end_ts_us)
    }

    /// Total number of frames parsed.
    pub fn total_frames(&self) -> usize {
        self.total_frames
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

/// Parse a single partition into per-protocol batches, returning the batches and
/// the (min, max) timestamps (microseconds) seen.
fn parse_partition<S: SeekablePacketSource>(
    source: &S,
    registry: &ProtocolRegistry,
    batch_size: usize,
    range: &PacketRange,
    single: bool,
) -> Result<(ProtocolBatches, i64, i64), Error> {
    let mut reader = if single {
        source.sequential_reader()?
    } else {
        source.reader_at(range)?
    };

    let mut batch_set = NormalizedBatchSet::new(batch_size);
    let mut min_us = i64::MAX;
    let mut max_us = i64::MIN;

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
            let parsed = parse_packet(registry, packet.link_type, packet.data);
            batch_set.add_packet_from_ref(packet, &parsed)?;
            Ok(())
        })?;
        if processed == 0 {
            break;
        }
    }

    Ok((batch_set.finish()?, min_us, max_us))
}

/// Run the shared parse pass over a seekable source, fanning out to all protocol
/// tables. Parses partitions in parallel when more than one.
pub fn run_shared_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
    target_partitions: usize,
) -> Result<SharedParseState, Error> {
    let ranges = decide_ranges(source.as_ref(), target_partitions)?;
    let single = ranges.len() == 1;

    // Parse each partition in its own worker. Each worker owns its reader and
    // builders — no shared mutable state, so nothing to lock.
    let results: Vec<Result<(ProtocolBatches, i64, i64), Error>> = if single {
        vec![parse_partition(
            source.as_ref(),
            registry,
            batch_size,
            &ranges[0],
            true,
        )]
    } else {
        std::thread::scope(|scope| {
            let handles: Vec<_> = ranges
                .iter()
                .map(|range| {
                    let source = source.clone();
                    let registry = registry.clone();
                    let range = range.clone();
                    scope.spawn(move || {
                        parse_partition(source.as_ref(), &registry, batch_size, &range, false)
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

    // Surface the first error, if any; otherwise collect partition batches.
    let mut partition_batches: Vec<ProtocolBatches> = Vec::with_capacity(results.len());
    let mut start_ts_us = i64::MAX;
    let mut end_ts_us = i64::MIN;
    for r in results {
        let (batches, min_us, max_us) = r?;
        if min_us != i64::MAX {
            start_ts_us = start_ts_us.min(min_us);
        }
        if max_us != i64::MIN {
            end_ts_us = end_ts_us.max(max_us);
        }
        partition_batches.push(batches);
    }
    if start_ts_us == i64::MAX {
        start_ts_us = 0;
        end_ts_us = 0;
    }

    // Reorganize: table -> [per-partition Vec<RecordBatch>] (partition/frame order).
    let mut tables: HashMap<String, Vec<Vec<RecordBatch>>> = HashMap::new();
    let mut total_frames = 0usize;
    if let Some(first) = partition_batches.first() {
        let keys: Vec<String> = first.keys().cloned().collect();
        for key in keys {
            let per_partition: Vec<Vec<RecordBatch>> = partition_batches
                .iter()
                .map(|pb| pb.get(&key).cloned().unwrap_or_default())
                .collect();
            if key == "frames" {
                total_frames = per_partition
                    .iter()
                    .flat_map(|v| v.iter())
                    .map(|b| b.num_rows())
                    .sum();
            }
            tables.insert(key, per_partition);
        }
    }

    Ok(SharedParseState {
        num_partitions: partition_batches.len(),
        tables,
        parse_passes: 1,
        start_ts_us,
        end_ts_us,
        total_frames,
    })
}
