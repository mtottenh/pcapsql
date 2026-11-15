//! Reallocation count of the Arrow sink in steady state.
//!
//! A counting global allocator counts the `realloc` calls of a scan of
//! `frames`, `ipv4` and `udp` into [`ArrowSink`]s, over a capture of `N`
//! packets and over one of `2 * N`. What the second scan reallocates beyond
//! the first is what the extra `N` packets cost: with builders that start
//! each batch at the size the last one reached, that is nothing, whatever the
//! first batches cost to find the size.
//!
//! This binary holds exactly one test because the counter is process-global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pcapsql_core::io::{ReadPacketReader, StreamHeader};
use pcapsql_core::scan::{Catalog, PartitionScan, ScanPlan, Step, TableScan};
use pcapsql_datafusion::query::builders::ArrowSink;
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};

struct Counting;

static REALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Rows per batch: small, so that the captures span many batches.
const BATCH_SIZE: usize = 1024;
/// Packets of the shorter capture: 16 batches per table.
const N: usize = 16 * BATCH_SIZE;

/// Ethernet/IPv4/UDP with a payload of 200 to 327 bytes, so that the bytes
/// of `frames.raw_data` differ from one batch to the next.
fn udp_frame(i: usize) -> Vec<u8> {
    let payload = 200 + (i.wrapping_mul(2_654_435_761) >> 7) % 128;
    let mut p = Vec::with_capacity(42 + payload);
    p.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&((28 + payload) as u16).to_be_bytes());
    p.extend_from_slice(&(i as u16).to_be_bytes());
    p.extend_from_slice(&[0x40, 0, 64, 17, 0, 0]);
    p.extend_from_slice(&[192, 168, 0, 1, 192, 168, 0, 2]);
    p.extend_from_slice(&(10_000 + (i % 5000) as u16).to_be_bytes());
    p.extend_from_slice(&4000u16.to_be_bytes());
    p.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.resize(42 + payload, 0xAB);
    p
}

fn capture(packets: usize) -> Vec<u8> {
    let packets: Vec<GenPacket> = (0..packets)
        .map(|i| {
            let data = udp_frame(i);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + (i / 1000) as u32,
                ts_frac: (i as u32 * 251) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

/// Scan `bytes` into sinks of every column of `frames`, `ipv4` and `udp`,
/// dropping each batch as it is taken. Returns the `realloc` calls of the
/// scan and the rows it produced.
fn scan(bytes: &[u8]) -> (u64, usize) {
    let catalog = Catalog::builtin();
    let registry = Arc::new(pcapsql_core::default_registry());
    let tables = ["frames", "ipv4", "udp"]
        .iter()
        .map(|name| {
            let (id, def) = catalog.table(name).expect("a built-in table");
            TableScan::new(id, def.columns().map(|(id, _)| id).collect())
        })
        .collect();
    let plan = ScanPlan {
        tables,
        ..ScanPlan::default()
    }
    .compile(catalog, &registry)
    .expect("the plan compiles");
    let mut sinks: Vec<ArrowSink> = plan
        .outputs()
        .iter()
        .map(|output| ArrowSink::new(&output.columns, BATCH_SIZE))
        .collect();

    let mut read = Cursor::new(bytes);
    let (header, head) = StreamHeader::probe(&mut read).expect("probe the capture");
    let reader = ReadPacketReader::sequential(read, &header, head).expect("a reader");
    let mut scan = PartitionScan::new(reader, Arc::new(plan), registry);

    let before = REALLOCS.load(Ordering::Relaxed);
    let mut rows = 0;
    loop {
        match scan.step(&mut sinks, 1024).expect("step") {
            Step::More => {}
            Step::Flush(output) => {
                let batch = sinks[usize::from(output.0)].take_batch().expect("a batch");
                rows += batch.map_or(0, |b| b.num_rows());
            }
            Step::Done | Step::End => break,
        }
    }
    for sink in &mut sinks {
        rows += sink
            .take_batch()
            .expect("a batch")
            .map_or(0, |b| b.num_rows());
    }
    (REALLOCS.load(Ordering::Relaxed) - before, rows)
}

#[test]
fn sink_does_not_reallocate_in_steady_state() {
    let short = capture(N);
    let long = capture(2 * N);
    // Once to warm up whatever the first scan of a process allocates.
    scan(&short);

    let (short_reallocs, short_rows) = scan(&short);
    let (long_reallocs, long_rows) = scan(&long);
    assert_eq!(short_rows, 3 * N);
    assert_eq!(long_rows, 6 * N);

    let extra = long_reallocs.saturating_sub(short_reallocs);
    let per_packet = extra as f64 / N as f64;
    println!(
        "reallocs: {short_reallocs} over {N} packets, {long_reallocs} over {} packets; \
         steady state {per_packet:.5} per packet",
        2 * N
    );
    // Before the builders were sized from the batch they had just given,
    // this was about 0.04 per packet (every batch of every variable-width
    // column regrowing from empty).
    assert!(
        per_packet < 0.001,
        "{extra} reallocations for {N} more packets ({per_packet:.5} per packet)"
    );
}
