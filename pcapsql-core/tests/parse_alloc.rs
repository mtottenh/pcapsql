//! A partition scan does not allocate per packet.
//!
//! [`PartitionScan`] keeps the storage for a packet's layers from one packet
//! to the next (a `LayerBuf`), and a scan of `frames` alone parses nothing.
//! With a sink that stores nothing, what is left to allocate per packet is
//! nothing: this test counts.
//!
//! The count is taken as a slope: a capture of `2N` packets may not cost
//! more allocations than one of `N`. What a scan allocates once (the reader's
//! buffer, the router, the first packet's layer storage) is in both and
//! cancels out.
//!
//! This is a test binary of its own because of the counting global
//! allocator. It counts per thread, so the test harness's own threads do not
//! disturb it.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ops::ControlFlow;
use std::sync::Arc;

use common::{full_plan, legacy_capture, nested, reader, udp_frame};
use pcapsql_core::scan::{Full, ListSink, OutCol, PartitionScan, RowSink, Step};
use pcapsql_core::{default_registry, ProtocolRegistry};

struct Counting;

thread_local! {
    // Const-initialised and without a destructor, so the allocator can read
    // it at any point of a thread's life without allocating itself.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<u64> = const { Cell::new(0) };
}

fn count(bytes: usize) {
    ALLOCATIONS.with(|n| n.set(n.get() + 1));
    ALLOCATED_BYTES.with(|n| n.set(n.get() + bytes as u64));
}

// SAFETY: every method forwards to `System` with the arguments it was given,
// so `System`'s guarantees are this allocator's; the counters are plain
// thread-local integers.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: the caller's contract, passed on unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: the caller's contract, passed on unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        // SAFETY: the caller's contract, passed on unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, passed on unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// (allocations, bytes requested) by this thread while `f` ran.
fn allocations_during<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    let before = (ALLOCATIONS.get(), ALLOCATED_BYTES.get());
    let value = f();
    (
        value,
        ALLOCATIONS.get() - before.0,
        ALLOCATED_BYTES.get() - before.1,
    )
}

/// Counts rows and cells, stores nothing.
#[derive(Default)]
struct NullSink {
    rows: u64,
    cells: u64,
}

impl RowSink for NullSink {
    fn null(&mut self, _: OutCol) {
        self.cells += 1;
    }
    fn bool(&mut self, _: OutCol, _: bool) {
        self.cells += 1;
    }
    fn u8(&mut self, _: OutCol, _: u8) {
        self.cells += 1;
    }
    fn u16(&mut self, _: OutCol, _: u16) {
        self.cells += 1;
    }
    fn u32(&mut self, _: OutCol, _: u32) {
        self.cells += 1;
    }
    fn u64(&mut self, _: OutCol, _: u64) {
        self.cells += 1;
    }
    fn i8(&mut self, _: OutCol, _: i8) {
        self.cells += 1;
    }
    fn i64(&mut self, _: OutCol, _: i64) {
        self.cells += 1;
    }
    fn f64(&mut self, _: OutCol, _: f64) {
        self.cells += 1;
    }
    fn str(&mut self, _: OutCol, _: &str) {
        self.cells += 1;
    }
    fn bytes(&mut self, _: OutCol, _: &[u8]) {
        self.cells += 1;
    }
    fn timestamp(&mut self, _: OutCol, _: i64) {
        self.cells += 1;
    }

    type List<'s> = NullList;

    fn list(&mut self, _: OutCol) -> NullList {
        self.cells += 1;
        NullList
    }

    fn end_row(&mut self) -> ControlFlow<Full> {
        self.rows += 1;
        ControlFlow::Continue(())
    }
}

struct NullList;

impl ListSink for NullList {
    fn null(&mut self) {}
    fn u16(&mut self, _: u16) {}
    fn u32(&mut self, _: u32) {}
    fn str(&mut self, _: &str) {}
    fn bytes(&mut self, _: &[u8]) {}
    fn finish(self) {}
}

/// What scanning `tables` over a capture of `packets` frames costs.
struct Cost {
    allocations: u64,
    bytes: u64,
    rows: u64,
}

fn scan_cost(
    tables: &[&str],
    frame: fn(usize) -> Vec<u8>,
    packets: usize,
    registry: &Arc<ProtocolRegistry>,
) -> Cost {
    let frames: Vec<Vec<u8>> = (0..packets).map(frame).collect();
    let capture = legacy_capture(&frames);
    let plan = full_plan(tables, registry);
    let mut sinks: Vec<NullSink> = plan.outputs().iter().map(|_| NullSink::default()).collect();
    let reader = reader(&capture);
    let (stats, allocations, bytes) = allocations_during(|| {
        let mut scan = PartitionScan::new(reader, Arc::clone(&plan), Arc::clone(registry));
        loop {
            match scan.step(&mut sinks, 1024).unwrap() {
                Step::More => {}
                Step::Flush(output) => panic!("a null sink is never full: {output:?}"),
                Step::Done | Step::End => break,
            }
        }
        scan.finish().0
    });
    assert_eq!(stats.packets, packets as u64);
    let rows: u64 = sinks.iter().map(|sink| sink.rows).sum();
    assert_eq!(rows, stats.rows.iter().sum::<u64>());
    assert!(sinks.iter().all(|sink| sink.cells > 0));
    Cost {
        allocations,
        bytes,
        rows,
    }
}

/// Packets of the smaller capture: enough that it does not fit the reader's
/// buffer, so both scans refill it.
const N: usize = 5_000;

/// The allocations (and bytes) that `N` further packets cost.
fn slope(
    tables: &[&str],
    frame: fn(usize) -> Vec<u8>,
    rows_per_packet: u64,
    registry: &Arc<ProtocolRegistry>,
) -> (u64, u64) {
    let small = scan_cost(tables, frame, N, registry);
    let large = scan_cost(tables, frame, 2 * N, registry);
    assert_eq!(small.rows, N as u64 * rows_per_packet, "{tables:?}");
    assert_eq!(large.rows, 2 * N as u64 * rows_per_packet, "{tables:?}");
    let allocations = large.allocations.saturating_sub(small.allocations);
    let bytes = large.bytes.saturating_sub(small.bytes);
    println!(
        "{tables:?}: {} allocations ({} bytes) for {N} packets, {} ({} bytes) for {}: \
         {:.3} allocations and {:.1} bytes per further packet",
        small.allocations,
        small.bytes,
        large.allocations,
        large.bytes,
        2 * N,
        allocations as f64 / N as f64,
        bytes as f64 / N as f64,
    );
    (allocations, bytes)
}

/// A UDP frame inside three VXLAN tunnels: fifteen layers.
fn tunnelled(i: usize) -> Vec<u8> {
    nested(i, 3)
}

/// One test, so that nothing else runs on this thread while it counts.
#[test]
fn a_partition_scan_does_not_allocate_per_packet() {
    let registry = Arc::new(default_registry());
    // Compile the scopes and warm every lazily initialised table once.
    for tables in [&["frames"][..], &["udp"], &["ethernet", "ipv4", "udp"]] {
        scan_cost(tables, udp_frame, 16, &registry);
    }

    // `frames` alone: nothing is parsed, nothing is stored.
    assert_eq!(slope(&["frames"], udp_frame, 1, &registry), (0, 0));
    // One protocol table: three layers per packet, in reused storage.
    assert_eq!(slope(&["udp"], udp_frame, 1, &registry), (0, 0));
    // Every layer of the packet routed to a table of its own.
    assert_eq!(
        slope(
            &["frames", "ethernet", "ipv4", "udp"],
            udp_frame,
            4,
            &registry
        ),
        (0, 0)
    );
    // More layers than the storage first holds: it grows once, for the
    // first packet, and is kept.
    assert_eq!(
        slope(&["ethernet", "ipv4"], tunnelled, 8, &registry),
        (0, 0)
    );
}
