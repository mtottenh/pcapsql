//! A partition scan does not allocate per packet.
//!
//! [`PartitionScan`] keeps the storage for a packet's layers from one packet
//! to the next (a `ParseBuf`: the fields, the layers, and an arena for the
//! values a parser constructs), and a scan of `frames` alone parses nothing.
//! With a sink that stores nothing, what is left to allocate per packet is
//! what a third-party parser allocates for itself: nothing for `frames`,
//! `udp`, `tcp` (options and SACK blocks included) and `http`; for `dns`,
//! what `simple_dns::Packet::parse` allocates and not one allocation more.
//! This test counts.
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

use common::{eth, full_plan, ipv4, legacy_capture, nested, reader, udp, udp_frame};
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

/// A TCP segment with these option bytes (a multiple of four) and payload.
fn tcp_segment(i: usize, port: u16, options: &[u8], payload: &[u8]) -> Vec<u8> {
    assert!(options.len().is_multiple_of(4) && options.len() <= 40);
    let mut p = Vec::new();
    p.extend_from_slice(&40_000u16.to_be_bytes());
    p.extend_from_slice(&port.to_be_bytes());
    p.extend_from_slice(&(1_000 + i as u32).to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push((((20 + options.len()) / 4) as u8) << 4);
    p.push(0x18);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend_from_slice(options);
    p.extend_from_slice(payload);
    eth(&ipv4(6, i as u16, &p))
}

/// TCP segments with every kind of option field: none; a timestamp; a SYN's
/// MSS, SACK-permitted, timestamp and window scale; four SACK blocks; three
/// SACK blocks and a timestamp; and two combinations whose `options` text
/// has to be assembled (one of them with more names than fit the usual
/// four).
fn tcp_with_options(i: usize) -> Vec<u8> {
    const TS: [u8; 10] = [8, 10, 0, 0, 0x10, 0, 0, 0, 0x20, 0];
    let sack = |blocks: usize| {
        let mut option = vec![5, (2 + 8 * blocks) as u8];
        for block in 0..blocks as u32 {
            option.extend_from_slice(&(1_000 * block).to_be_bytes());
            option.extend_from_slice(&(1_000 * block + 500).to_be_bytes());
        }
        option
    };
    let options: Vec<u8> = match i % 7 {
        0 => vec![],
        1 => [&[1, 1][..], &TS].concat(),
        2 => [&[2, 4, 0x05, 0xB4, 4, 2][..], &TS, &[1, 3, 3, 7]].concat(),
        3 => [&[1, 1][..], &sack(4)].concat(),
        4 => [&[1, 1][..], &TS, &[1, 1], &sack(3)].concat(),
        // MSS and SACK: not one of the common combinations.
        5 => [&[2, 4, 0x05, 0xB4][..], &sack(1), &[1, 1]].concat(),
        // Eight names: MSS three times, window scale twice, SACK-permitted
        // three times.
        _ => [
            &[2, 4, 0x05, 0xB4, 2, 4, 0x05, 0xB4, 2, 4, 0x05, 0xB4][..],
            &[3, 3, 7, 3, 3, 7, 4, 2, 4, 2, 4, 2],
        ]
        .concat(),
    };
    tcp_segment(i, 5001, &options, &[0xCD; 16])
}

/// A `GET` request: a start line and three headers.
fn http_request(i: usize) -> Vec<u8> {
    let request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
    tcp_segment(i, 80, &[], request)
}

/// The payload of a DNS response: `www.example.com A`, answered with a
/// CNAME and two addresses, the names compressed.
fn dns_response(id: u16) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0]);
    dns.extend_from_slice(b"\x03www\x07example\x03com\x00");
    dns.extend_from_slice(&[0, 1, 0, 1]);
    // www.example.com CNAME host.example.com
    dns.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7]);
    dns.extend_from_slice(b"\x04host\xc0\x10");
    // host.example.com A, twice
    for last in [1u8, 2] {
        dns.extend_from_slice(&[0xc0, 0x2d, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, last]);
    }
    dns
}

fn dns_frame(i: usize) -> Vec<u8> {
    eth(&ipv4(
        17,
        i as u16,
        &udp(53, 30_000 + (i % 1000) as u16, &dns_response(i as u16)),
    ))
}

/// One test, so that nothing else runs on this thread while it counts.
#[test]
fn a_partition_scan_does_not_allocate_per_packet() {
    let registry = Arc::new(default_registry());
    // Compile the scopes and warm every lazily initialised table once.
    for tables in [&["frames"][..], &["udp"], &["ethernet", "ipv4", "udp"]] {
        scan_cost(tables, udp_frame, 16, &registry);
    }
    scan_cost(&["tcp"], tcp_with_options, 16, &registry);
    scan_cost(&["http"], http_request, 16, &registry);
    scan_cost(&["dns"], dns_frame, 16, &registry);

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

    // TCP: twenty-four fields a segment, the `options` text of an uncommon
    // combination and the SACK edge lists, all in reused storage.
    assert_eq!(slope(&["tcp"], tcp_with_options, 1, &registry), (0, 0));
    assert_eq!(
        slope(&["ethernet", "ipv4", "tcp"], tcp_with_options, 3, &registry),
        (0, 0)
    );

    // HTTP: `httparse` allocates nothing, and neither does the layer.
    assert_eq!(slope(&["http"], http_request, 1, &registry), (0, 0));
    assert_eq!(slope(&["tcp", "http"], http_request, 2, &registry), (0, 0));

    // DNS: `simple_dns` allocates for the message it decodes (its record
    // vectors and the labels of every name). The scan allocates exactly
    // that: the names it formats and the answer lists it builds are in the
    // arena.
    let message = dns_response(7);
    let (answers, parser_allocations, parser_bytes) = allocations_during(|| {
        let packet = simple_dns::Packet::parse(&message).expect("the response parses");
        packet.answers.len()
    });
    assert_eq!(answers, 3);
    assert!(parser_allocations > 0, "simple_dns allocates per message");
    println!("simple_dns: {parser_allocations} allocations ({parser_bytes} bytes) per message");
    assert_eq!(
        slope(&["dns"], dns_frame, 1, &registry),
        (N as u64 * parser_allocations, N as u64 * parser_bytes)
    );
}
