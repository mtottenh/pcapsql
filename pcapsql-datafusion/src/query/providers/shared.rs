//! Shared single-pass parse: one parse of the capture feeds every table.
//!
//! A query touching N protocol tables must parse the capture **once**, not once
//! per table. This module performs a single fan-out parse pass over the source,
//! routing every packet into per-protocol Arrow builders ([`NormalizedBatchSet`])
//! exactly as the in-memory path does, and memoizes the per-table batches so all
//! table providers share them.
//!
//! Batches are stored per partition (`Vec<Vec<RecordBatch>>`) so the scan plan
//! can expose DataFusion partitions; this pass currently always produces one
//! partition (a sequential read), which keeps the door open for splitting the
//! same pass across seekable sources later without reshaping the output.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::record_batch::RecordBatch;

use pcapsql_core::{parse_packet, PacketReader, PacketSource, ProtocolRegistry};

use crate::error::Error;
use crate::query::builders::{NormalizedBatchSet, ProtocolBatches};

/// Result of the shared parse pass: per-table batches grouped by partition.
pub struct SharedParseState {
    /// table name -> (one `Vec<RecordBatch>` per partition, in frame order).
    tables: HashMap<String, Vec<Vec<RecordBatch>>>,
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

    /// Number of parse passes performed over the source (the instrumentation
    /// behind "a view over N tables parses the file once").
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

/// Parse the whole source sequentially into per-protocol batches, returning the
/// batches and the (min, max) timestamps (microseconds) seen.
fn parse_source<S: PacketSource>(
    source: &S,
    registry: &ProtocolRegistry,
    batch_size: usize,
) -> Result<(ProtocolBatches, i64, i64), Error> {
    let mut reader = source.sequential_reader()?;

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

/// Run the shared parse pass over a source, fanning out to all protocol tables.
pub fn run_shared_parse<S: PacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    batch_size: usize,
) -> Result<SharedParseState, Error> {
    let (batches, min_us, max_us) = parse_source(source.as_ref(), registry, batch_size)?;

    let (start_ts_us, end_ts_us) = if min_us == i64::MAX {
        (0, 0)
    } else {
        (min_us, max_us)
    };

    // Reorganize: table -> [per-partition Vec<RecordBatch>] (one partition).
    let mut tables: HashMap<String, Vec<Vec<RecordBatch>>> = HashMap::new();
    let mut total_frames = 0usize;
    for (key, partition) in batches {
        if key == "frames" {
            total_frames = partition.iter().map(|b| b.num_rows()).sum();
        }
        tables.insert(key, vec![partition]);
    }

    Ok(SharedParseState {
        tables,
        parse_passes: 1,
        start_ts_us,
        end_ts_us,
        total_frames,
    })
}
