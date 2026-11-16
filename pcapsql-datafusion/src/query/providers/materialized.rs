//! The materializing pass: every subscribed table in memory, whole.
//!
//! This is the cache-fill path (`RetentionPolicy::CacheOnTouch`), the path
//! of a query no streaming pass can serve, and the only pass that builds
//! stream tables: those are complete only when the capture ends, and the
//! scan writes their rows then.
//!
//! Partitions are range-partitioned by frame number and reassembled in frame
//! order, so the result is identical to a single-partition parse — the
//! property the partition-equivalence tests assert.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use arrow::record_batch::RecordBatch;

use pcapsql_core::io::PacketRange;
use pcapsql_core::{PacketReader, PacketSource, ProtocolRegistry, SeekablePacketSource};

use super::delivery::{BatchDelivery, Delivered};
use super::pass::{
    decide_ranges, partition_scan, push_partition, time_range_us, Feed, PassOptions, Progress,
};
use super::stats::{ParseStats, ServedFrom, TableData};
use super::subscription::{CompiledSubscription, ParseSubscription};
use crate::error::{Error, QueryError};

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

/// Per-partition parse output.
struct PartitionOutput {
    /// Each output's batches, indexed by
    /// [`OutputId`](pcapsql_core::scan::OutputId).
    batches: Vec<Vec<RecordBatch>>,
    min_us: i64,
    max_us: i64,
    packets: u64,
    capped: bool,
}

/// Parse one partition through `reader` into per-output batches restricted
/// to the subscription. The reader is already positioned: a sequential
/// reader (the whole source) or a seekable source's reader at a range start.
///
/// A partition with stream tables is read to its end whatever the row caps
/// of the other tables: stream tables are complete only at end of capture.
fn parse_partition<R: PacketReader>(
    reader: R,
    registry: &Arc<ProtocolRegistry>,
    subscription: &CompiledSubscription,
    options: &PassOptions,
    progress: Option<Progress<'_>>,
) -> Result<PartitionOutput, Error> {
    let (mut delivery, mut sinks) = BatchDelivery::accumulating(options.batch_size, subscription);
    let mut scan = partition_scan(reader, registry, subscription, options);
    let capped = push_partition(
        &mut scan,
        &mut delivery,
        &mut sinks,
        progress,
        Feed::Materialize,
    )?;
    let (stats, _) = scan.finish();
    let batches = delivery
        .finish(sinks)?
        .into_iter()
        .map(|delivered| match delivered {
            Delivered::Batches(batches) => batches,
            Delivered::Streamed(_) => Vec::new(),
        })
        .collect();
    let (min_us, max_us) = time_range_us(&stats);

    Ok(PartitionOutput {
        batches,
        min_us,
        max_us,
        packets: stats.packets,
        capped,
    })
}

/// Fold the partitions' outputs (in partition order) into the pass result:
/// per table, one `Vec<RecordBatch>` per partition in frame order, plus the
/// pass statistics. Surfaces the first partition error.
fn assemble_pass(
    results: Vec<Result<PartitionOutput, Error>>,
    subscription: &CompiledSubscription,
) -> Result<SharedParseState, Error> {
    let mut partitions: Vec<Vec<Vec<RecordBatch>>> = Vec::with_capacity(results.len());
    let mut start_ts_us = i64::MAX;
    let mut end_ts_us = i64::MIN;
    let mut packets_scanned: u64 = 0;
    let mut complete_scan = true;
    for result in results {
        let out = result?;
        if out.min_us != i64::MAX {
            start_ts_us = start_ts_us.min(out.min_us);
        }
        if out.max_us != i64::MIN {
            end_ts_us = end_ts_us.max(out.max_us);
        }
        packets_scanned += out.packets;
        complete_scan &= !out.capped;
        partitions.push(out.batches);
    }
    if start_ts_us == i64::MAX {
        start_ts_us = 0;
        end_ts_us = 0;
    }

    // Reorganize: table -> per-partition Vec<RecordBatch> (frame order).
    let num_partitions = partitions.len();
    let mut tables: HashMap<String, Arc<TableData>> = HashMap::new();
    let mut rows_built: HashMap<String, usize> = HashMap::new();
    for (index, (output, _)) in subscription.outputs().enumerate() {
        let data = TableData {
            schema: Arc::clone(&output.schema),
            partitions: partitions
                .iter_mut()
                .map(|batches| std::mem::take(&mut batches[index]))
                .collect(),
        };
        rows_built.insert(output.name.to_string(), data.total_rows());
        tables.insert(output.name.to_string(), Arc::new(data));
    }

    let mut stream_tables: Vec<String> = subscription.stream_tables().map(String::from).collect();
    stream_tables.sort();

    Ok(SharedParseState {
        tables,
        stats: ParseStats {
            late_rows: 0,
            windows_forced: 0,
            parse_passes: 1,
            packets_scanned,
            partitions: num_partitions,
            rows_built,
            start_ts_us,
            end_ts_us,
            complete_scan,
            overflowed_bytes: HashMap::new(),
            overflow_peak_bytes: HashMap::new(),
            stream_tables,
            served_from: ServedFrom::Parse,
        },
    })
}

/// Run one scoped parse pass over a seekable source, fanning out to the
/// subscribed tables. Parses partitions in parallel when more than one;
/// each worker owns its reader and builders — no shared mutable state.
///
/// A subscription with stream tables has the scan reassemble the TCP
/// streams of the same pass (→ TLS → HTTP, decrypted with
/// [`PassOptions::keylog`]); reassembly needs the capture in order, so such
/// a pass is pinned to a single partition. A pass that ends up with one
/// partition (stream tables, a compressed or small source, an unavailable
/// index) is exactly [`run_shared_parse_sequential`].
pub fn run_shared_parse<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    subscription: &ParseSubscription,
    options: &PassOptions,
) -> Result<SharedParseState, Error> {
    let subscription = &subscription.compile(registry)?;
    let ranges = if subscription.scan().requires_single_partition() {
        vec![PacketRange::whole()]
    } else {
        decide_ranges(source.as_ref(), options.target_partitions)?
    };
    if ranges.len() == 1 {
        return sequential_pass(source.as_ref(), registry, subscription, options);
    }

    let progress_count = AtomicU64::new(0);
    let results: Vec<Result<PartitionOutput, Error>> = std::thread::scope(|thread_scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|range| {
                let progress = options.progress(&progress_count);
                thread_scope.spawn(move || {
                    let reader = source.reader_at(range)?;
                    parse_partition(reader, registry, subscription, options, progress)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    Err(Error::Query(QueryError::Execution(
                        "parse worker panicked".into(),
                    )))
                })
            })
            .collect()
    });
    assemble_pass(results, subscription)
}

/// Run one scoped parse pass over any source as a **single partition**,
/// through its sequential reader.
///
/// This is the whole of a pass over a non-seekable source (a pipe, stdin:
/// [`pcapsql_core::StdinPacketSource`]), and the one-partition case of
/// [`run_shared_parse`]. Stream tables, when subscribed, are built by the
/// scan of the same pass.
pub fn run_shared_parse_sequential<S: PacketSource>(
    source: &S,
    registry: &Arc<ProtocolRegistry>,
    subscription: &ParseSubscription,
    options: &PassOptions,
) -> Result<SharedParseState, Error> {
    let subscription = subscription.compile(registry)?;
    sequential_pass(source, registry, &subscription, options)
}

/// [`run_shared_parse_sequential`] for a compiled subscription.
fn sequential_pass<S: PacketSource>(
    source: &S,
    registry: &Arc<ProtocolRegistry>,
    subscription: &CompiledSubscription,
    options: &PassOptions,
) -> Result<SharedParseState, Error> {
    let progress_count = AtomicU64::new(0);
    let reader = source.sequential_reader()?;
    let result = parse_partition(
        reader,
        registry,
        subscription,
        options,
        options.progress(&progress_count),
    );
    assemble_pass(vec![result], subscription)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::providers::subscription::testing::{fused, names};
    use crate::query::providers::{ProgressFn, TableSubscription};
    use arrow::array::{Array, UInt16Array, UInt64Array};
    use pcapsql_core::io::{ReadPacketReader, StreamHeader};
    use pcapsql_core::scan::{Catalog, CmpOp, RowPredicate};
    use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
    use std::io::Cursor;
    use std::sync::Mutex;

    fn eth(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00];
        p.extend_from_slice(payload);
        p
    }

    fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 1, 0x40, 0x00, 64, proto, 0, 0]);
        p.extend_from_slice(&[192, 168, 0, 1, 192, 168, 0, 2]);
        p.extend_from_slice(payload);
        p
    }

    fn udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        eth(&ipv4(17, &udp))
    }

    fn tcp_frame(dst_port: u16) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&40_000u16.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 100, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        eth(&ipv4(6, &tcp))
    }

    /// `inner` inside VXLAN: a second row in `ethernet`, `ipv4` and `udp`.
    fn vxlan(src_port: u16, inner: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x08, 0, 0, 0, 0, 0, 7, 0];
        payload.extend_from_slice(inner);
        udp_frame(src_port, 4789, &payload)
    }

    /// What [`parse`] gives: a partition's output, its batches by table
    /// name.
    struct Parsed {
        batches: HashMap<String, Vec<RecordBatch>>,
        min_us: i64,
        max_us: i64,
        packets: u64,
        capped: bool,
    }

    /// Parse `frames` as one partition, the way a materializing pass does.
    fn parse(
        sub: &ParseSubscription,
        batch_size: usize,
        frames: &[Vec<u8>],
        progress: Option<Progress<'_>>,
    ) -> Parsed {
        let packets: Vec<GenPacket> = frames
            .iter()
            .enumerate()
            .map(|(i, data)| GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: 5,
                data: data.clone(),
                origlen: data.len() as u32,
            })
            .collect();
        let capture = legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes;
        let mut read = Cursor::new(capture);
        let (header, head) = StreamHeader::probe(&mut read).unwrap();
        let reader = ReadPacketReader::sequential(read, &header, head).unwrap();
        let registry = Arc::new(pcapsql_core::default_registry());
        let compiled = sub.compile(&registry).unwrap();
        let options = PassOptions::new(batch_size);
        let out = parse_partition(reader, &registry, &compiled, &options, progress).unwrap();
        let names = compiled
            .outputs()
            .map(|(output, _)| output.name.to_string());
        Parsed {
            batches: names.zip(out.batches).collect(),
            min_us: out.min_us,
            max_us: out.max_us,
            packets: out.packets,
            capped: out.capped,
        }
    }

    fn rows(batches: &[RecordBatch]) -> usize {
        batches.iter().map(RecordBatch::num_rows).sum()
    }

    fn u64s(batches: &[RecordBatch], column: &str) -> Vec<u64> {
        batches
            .iter()
            .flat_map(|batch| {
                let array = batch.column_by_name(column).unwrap();
                let array = array.as_any().downcast_ref::<UInt64Array>().unwrap();
                array.values().to_vec()
            })
            .collect()
    }

    fn u16s(batches: &[RecordBatch], column: &str) -> Vec<u16> {
        batches
            .iter()
            .flat_map(|batch| {
                let array = batch.column_by_name(column).unwrap();
                let array = array.as_any().downcast_ref::<UInt16Array>().unwrap();
                array.values().to_vec()
            })
            .collect()
    }

    #[test]
    fn partition_builds_only_subscribed_tables() {
        let sub = ParseSubscription::tables_full(["frames", "tcp"]).unwrap();
        let frames = [tcp_frame(80), udp_frame(1, 2, &[]), tcp_frame(443)];
        let out = parse(&sub, 1000, &frames, None);
        // Unsubscribed layers (ethernet, ipv4, udp) are not built.
        let mut tables: Vec<&str> = out.batches.keys().map(String::as_str).collect();
        tables.sort_unstable();
        assert_eq!(tables, ["frames", "tcp"]);
        assert_eq!(u64s(&out.batches["frames"], "frame_number"), [1, 2, 3]);
        assert_eq!(u64s(&out.batches["tcp"], "frame_number"), [1, 3]);
        assert_eq!(out.packets, 3);
        assert!(!out.capped);
        // Microseconds, from the packets' nanosecond timestamps.
        assert_eq!(out.min_us, 1_700_000_000_000_005);
        assert_eq!(out.max_us, 1_700_000_002_000_005);
    }

    #[test]
    fn partition_without_packets_has_no_time_range() {
        let sub = ParseSubscription::tables_full(["frames"]).unwrap();
        let out = parse(&sub, 1000, &[], None);
        assert_eq!((out.min_us, out.max_us), (i64::MAX, i64::MIN));
        assert_eq!(out.packets, 0);
        assert!(!out.capped);
        assert!(out.batches["frames"].is_empty());
    }

    #[test]
    fn partition_materializes_the_column_subset() {
        let mut sub = ParseSubscription::default();
        sub.subscribe_table(
            "tcp",
            TableSubscription {
                columns: names(&["frame_number", "dst_port"]),
                ..Default::default()
            },
        )
        .unwrap();
        let out = parse(&sub, 1000, &[tcp_frame(80)], None);
        let tcp = &out.batches["tcp"];
        assert_eq!(tcp.len(), 1);
        let schema = tcp[0].schema();
        assert_eq!(schema.fields().len(), 2);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("dst_port").is_ok());
        assert_eq!(u16s(tcp, "dst_port"), [80]);
    }

    #[test]
    fn partition_applies_the_parse_time_predicate() {
        let (_, tcp) = Catalog::builtin().table("tcp").unwrap();
        let (dst_port, _) = tcp.column("dst_port").unwrap();
        let mut sub = ParseSubscription::default();
        sub.subscribe_table(
            "tcp",
            TableSubscription {
                predicate: Some(RowPredicate::cmp(dst_port, CmpOp::Eq, 443)),
                ..Default::default()
            },
        )
        .unwrap();
        let frames = [
            tcp_frame(80),
            tcp_frame(443),
            tcp_frame(8080),
            tcp_frame(443),
        ];
        let out = parse(&sub, 1000, &frames, None);
        assert_eq!(u64s(&out.batches["tcp"], "frame_number"), [2, 4]);
    }

    /// A row cap on every table stops the partition at the frame that
    /// reaches the last of them.
    #[test]
    fn row_caps_stop_the_partition() {
        let mut sub = ParseSubscription::default();
        sub.subscribe_table(
            "frames",
            TableSubscription {
                fetch: Some(2),
                ..Default::default()
            },
        )
        .unwrap();
        let frames: Vec<Vec<u8>> = (0..5).map(|_| tcp_frame(80)).collect();
        let out = parse(&sub, 1000, &frames, None);
        assert_eq!(u64s(&out.batches["frames"], "frame_number"), [1, 2]);
        assert!(out.capped);
        assert_eq!(out.packets, 2);

        // An uncapped table keeps the partition going to its end; the
        // capped one still stops at its cap.
        sub.subscribe_table("tcp", TableSubscription::default())
            .unwrap();
        let out = parse(&sub, 1000, &frames, None);
        assert_eq!(rows(&out.batches["frames"]), 2);
        assert_eq!(rows(&out.batches["tcp"]), 5);
        assert!(!out.capped);
        assert_eq!(out.packets, 5);
    }

    #[test]
    fn batch_size_triggers_intermediate_batches() {
        let sub = ParseSubscription::tables_full(["frames"]).unwrap();
        let frames: Vec<Vec<u8>> = (0..5).map(|_| tcp_frame(80)).collect();
        let out = parse(&sub, 2, &frames, None);
        // 5 rows at batch size 2 -> 2 full batches + 1 partial.
        let sizes: Vec<usize> = out.batches["frames"].iter().map(|b| b.num_rows()).collect();
        assert_eq!(sizes, [2, 2, 1]);
        assert_eq!(
            u64s(&out.batches["frames"], "frame_number"),
            [1, 2, 3, 4, 5]
        );
    }

    /// A frame with several rows in one table (a tunnel) may straddle a
    /// batch boundary: no batch exceeds the batch size, and every row is
    /// there once, in order.
    #[test]
    fn multi_row_frames_split_across_batches() {
        let sub = ParseSubscription::tables_full(["frames", "udp"]).unwrap();
        // 1, 2 or 3 udp layers per frame; the outermost first.
        let mut frames = Vec::new();
        let mut expected = Vec::new();
        for frame in 1..=7u16 {
            let mut data = udp_frame(1000 * frame, 9999, &[]);
            let mut ports = vec![1000 * frame];
            for depth in 1..=(frame % 3) {
                data = vxlan(1000 * frame + depth, &data);
                ports.insert(0, 1000 * frame + depth);
            }
            expected.extend(ports.into_iter().map(|port| (u64::from(frame), port)));
            frames.push(data);
        }
        assert_eq!(expected.len(), 7 + 3 + 2 * 2);
        for batch_size in [1, 2, 3, 4, 100] {
            let out = parse(&sub, batch_size, &frames, None);
            let udp = &out.batches["udp"];
            assert!(
                udp.iter().all(|b| b.num_rows() <= batch_size),
                "batch size {batch_size}"
            );
            let got: Vec<(u64, u16)> = u64s(udp, "frame_number")
                .into_iter()
                .zip(u16s(udp, "src_port"))
                .collect();
            assert_eq!(got, expected, "batch size {batch_size}");
            assert_eq!(rows(&out.batches["frames"]), 7);
            assert_eq!(out.packets, 7);
        }
    }

    /// Progress is reported per chunk of 1024 packets with the running
    /// total, however often a batch is handed on in between, and once more
    /// when the reader has nothing left.
    #[test]
    fn progress_is_reported_per_chunk() {
        let sub = ParseSubscription::tables_full(["frames", "udp"]).unwrap();
        let frames: Vec<Vec<u8>> = (0..2500).map(|_| udp_frame(1, 2, &[])).collect();
        for batch_size in [7, 100, 1024, 10_000] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let callback: ProgressFn = {
                let seen = Arc::clone(&seen);
                Arc::new(move |total| seen.lock().unwrap().push(total))
            };
            let counter = AtomicU64::new(0);
            let out = parse(&sub, batch_size, &frames, Some((&counter, &callback)));
            assert_eq!(out.packets, 2500);
            assert_eq!(
                *seen.lock().unwrap(),
                [1024, 2048, 2500, 2500],
                "batch size {batch_size}"
            );
            assert_eq!(rows(&out.batches["udp"]), 2500);
        }
    }

    /// A fused join is built alongside the routed tables, from the same
    /// frames, each frame once; its row cap ends the partition when nothing
    /// else wants frames.
    #[test]
    fn fused_joins_are_fed_once_per_frame() {
        let frames: Vec<Vec<u8>> = (0..10).map(|i| tcp_frame(80 + i)).collect();
        let mut spec = fused("fused_a");
        spec.fetch = None;
        let mut sub = ParseSubscription::tables_full(["tcp"]).unwrap();
        sub.subscribe_fused(spec).unwrap();
        // `tcp` batches of one row: every frame is handed on mid-chunk.
        for batch_size in [1, 3, 100] {
            let out = parse(&sub, batch_size, &frames, None);
            let joined = &out.batches["fused_a"];
            assert_eq!(
                u64s(joined, "f__frame_number"),
                (1..=10).collect::<Vec<u64>>()
            );
            assert_eq!(
                u16s(joined, "tcp__dst_port"),
                (80..90).collect::<Vec<u16>>()
            );
            assert_eq!(rows(&out.batches["tcp"]), 10);
            assert!(!out.capped);
        }

        // Capped at 4 rows and alone: the partition is cut short.
        let mut sub = ParseSubscription::default();
        sub.subscribe_fused(fused("fused_a")).unwrap();
        let out = parse(&sub, 100, &frames, None);
        assert_eq!(
            u64s(&out.batches["fused_a"], "f__frame_number"),
            [1, 2, 3, 4]
        );
        assert!(out.capped);
    }
}
