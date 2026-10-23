//! Memory-ceiling test for the streaming (`RetentionPolicy::None`) exchange.
//!
//! A counting global allocator measures peak heap while a one-shot query
//! streams a capture whose `frames.raw_data` alone is tens of megabytes:
//!
//! - a single-table scan keeps its consumer in step with the parse through
//!   backpressure: nothing overflows and peak heap is a small fraction of the
//!   capture;
//! - the frame-ordered sort-merge join stays well below the materialized
//!   footprint and overflows at most the consumer's demand window, never the
//!   table;
//! - a join whose one side must be sorted first drains that side before
//!   polling the other, so the other table *must* overflow, the overflow must
//!   be reported in `ParseStats`, and the result must still be correct.
//!
//! This binary holds exactly one test because the allocator counters are
//! process-global. Partition count is pinned (2) because DataFusion's own
//! repartition buffering, not the exchange, dominates at higher counts.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use arrow::util::pretty::pretty_format_batches;
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, RetentionPolicy, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
use tempfile::TempDir;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn reset_peak() -> usize {
    let now = CURRENT.load(Ordering::Relaxed);
    PEAK.store(now, Ordering::Relaxed);
    now
}

fn peak_since(base: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

const FRAMES: usize = 100_000;
const PAYLOAD: usize = 200;

/// Ethernet/IPv4/TCP frame with a `PAYLOAD`-byte payload (~254 bytes).
fn tcp_frame(i: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + 20 + 20 + PAYLOAD);
    p.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    p.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    p.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + 20 + PAYLOAD) as u16;
    p.push(0x45);
    p.push(0);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&(i as u16).to_be_bytes());
    p.extend_from_slice(&[0x40, 0]);
    p.push(64);
    p.push(6);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&[10, 0, 0, 1]);
    p.extend_from_slice(&[10, 0, 0, 2]);
    // TCP: vary the source port so hash-join keys are not all identical.
    p.extend_from_slice(&(40_000 + (i % 1000) as u16).to_be_bytes());
    p.extend_from_slice(&443u16.to_be_bytes());
    p.extend_from_slice(&(i as u32).to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.push(0x50);
    p.push(0x18); // PSH|ACK
    p.extend_from_slice(&((i % 64) as u16 * 1024).to_be_bytes()); // window
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend(std::iter::repeat_n((i % 251) as u8, PAYLOAD));
    p
}

fn write_capture(dir: &TempDir) -> std::path::PathBuf {
    let packets: Vec<GenPacket> = (0..FRAMES)
        .map(|i| {
            let data = tcp_frame(i);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + (i / 1000) as u32,
                ts_frac: (i % 1000) as u32 * 1000,
                data,
                origlen,
            }
        })
        .collect();
    let path = dir.path().join("big.pcap");
    std::fs::write(
        &path,
        legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes,
    )
    .unwrap();
    path
}

async fn engine(path: &std::path::Path, retention: RetentionPolicy) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(2),
            retention,
            ..Default::default()
        },
    )
    .await
    .expect("open engine")
}

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine
        .query(sql)
        .await
        .unwrap_or_else(|e| panic!("query failed: {sql}\n{e}"));
    pretty_format_batches(&batches).unwrap().to_string()
}

/// Run `sql` on a fresh engine with `retention`, returning (result, peak heap
/// growth during the query, overflowed bytes per table).
async fn measure(
    path: &std::path::Path,
    retention: RetentionPolicy,
    sql: &str,
) -> (String, usize, usize) {
    let eng = engine(path, retention).await;
    let base = reset_peak();
    let out = run(&eng, sql).await;
    let peak = peak_since(base);
    let stats = eng.last_parse_stats();
    eprintln!(
        "    overflow per table: total {:?}, peak {:?}",
        stats.overflowed_bytes, stats.overflow_peak_bytes
    );
    let overflow = stats.overflow_peak_bytes.values().sum();
    drop(eng);
    (out, peak, overflow)
}

const MIB: usize = 1024 * 1024;

#[test]
fn streaming_exchange_bounds_memory_and_reports_overflow() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let dir = TempDir::new().unwrap();
        let path = write_capture(&dir);
        let capture_bytes = std::fs::metadata(&path).unwrap().len() as usize;
        eprintln!(
            "capture: {} frames, {:.1} MiB",
            FRAMES,
            capture_bytes as f64 / MIB as f64
        );

        // --- Single table: backpressure keeps the consumer in step ----------
        let scan = "SELECT count(*) AS n, max(raw_data) AS m FROM frames";
        let (_, scan_peak, scan_overflow) = measure(&path, RetentionPolicy::None, scan).await;
        eprintln!(
            "scan: streaming peak {:.1} MiB, overflow {} B",
            scan_peak as f64 / MIB as f64,
            scan_overflow
        );
        assert_eq!(scan_overflow, 0, "a single consumer must never overflow");
        assert!(
            scan_peak < capture_bytes / 4,
            "streaming scan peak {scan_peak} not well below capture size {capture_bytes}"
        );

        // --- Frame-ordered sort-merge join: consumers keep pace -------------
        let smj = "SELECT count(*) AS n, max(f.raw_data) AS m \
                   FROM frames f JOIN tcp t USING (frame_number)";
        let (materialized, mat_peak, _) = measure(&path, RetentionPolicy::CacheOnTouch, smj).await;
        let (streamed, stream_peak, stream_overflow) =
            measure(&path, RetentionPolicy::None, smj).await;
        eprintln!(
            "sort-merge: materialized peak {:.1} MiB, streaming peak {:.1} MiB, overflow {} B",
            mat_peak as f64 / MIB as f64,
            stream_peak as f64 / MIB as f64,
            stream_overflow
        );
        assert_eq!(streamed, materialized, "streaming result differs");
        // Materializing holds every projected column of both tables (raw_data
        // alone is the capture size). Streaming holds the channel bound plus
        // DataFusion's own working set (repartition, coalesce, join buffers),
        // and the exchange buffers at most the consumer's demand window past
        // its bound — never the table.
        assert!(
            mat_peak > capture_bytes,
            "materialized peak {mat_peak} should exceed the capture size {capture_bytes}"
        );
        assert!(
            stream_peak < mat_peak * 2 / 3,
            "streaming peak {stream_peak} not well below materialized peak {mat_peak}"
        );
        assert!(
            stream_peak < capture_bytes,
            "streaming peak {stream_peak} not below capture size {capture_bytes}"
        );
        assert!(
            stream_overflow < capture_bytes / 2,
            "sort-merge overflow {stream_overflow} should be a demand window, not the table"
        );

        // --- Join on a non-frame key: the tcp side is sorted first ----------
        // SortMergeJoin needs tcp sorted on `seq + 1`, so DataFusion drains tcp
        // into a SortExec before it polls frames at all; frames must overflow
        // (and be accounted) rather than stall the pass.
        let sorted = "SELECT count(*) AS n FROM frames f JOIN tcp t ON f.frame_number = t.seq + 1";
        let (materialized, _, _) = measure(&path, RetentionPolicy::CacheOnTouch, sorted).await;
        let (streamed, sorted_peak, sorted_overflow) =
            measure(&path, RetentionPolicy::None, sorted).await;
        eprintln!(
            "sorted join: streaming peak {:.1} MiB, overflow {:.1} MiB",
            sorted_peak as f64 / MIB as f64,
            sorted_overflow as f64 / MIB as f64
        );
        assert_eq!(
            streamed, materialized,
            "sorted-join streaming result differs"
        );
        assert!(
            streamed.contains("100000"),
            "every frame should join: {streamed}"
        );
        assert!(
            sorted_overflow > 0,
            "the table not polled until the other is sorted must report overflow"
        );
    });
}
