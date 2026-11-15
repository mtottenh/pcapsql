//! What parsing costs per packet, for a profiler and an allocation count.
//!
//! ```text
//! parse_cost parse <kind> <packets>          # parse_packet, full scope, one ParseBuf
//! parse_cost scan <table> <kind> <packets>   # PartitionScan into a sink that stores nothing
//! ```
//!
//! `<kind>` is the frame that is repeated: `udp` (Ethernet/IPv4/UDP to a port
//! without a parser), `tcp` (a segment with a timestamp option), `dns` (a
//! response with one answer) or `http` (a `GET` request).
//!
//! The measured work is in functions named `measured_*` and nothing else is,
//! so that callgrind can be told to count those alone, and a per-packet cost
//! is the difference of two runs:
//!
//! ```text
//! cargo build -p pcapsql-core --example parse_cost --profile bench
//! for n in 20000 40000; do
//!   valgrind --tool=callgrind --callgrind-out-file=/dev/null \
//!     --toggle-collect='*measured_*' target/release/examples/parse_cost scan udp udp $n
//! done    # (Collected(40000) - Collected(20000)) / 20000 instructions per packet
//! ```
//!
//! The program prints the allocations the measured part made itself
//! (a counting global allocator), which give allocations per packet the same
//! way.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::Cursor;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pcapsql_core::io::{ReadPacketReader, StreamHeader};
use pcapsql_core::protocol::{parse_packet, ParseBuf, ParseScope};
use pcapsql_core::scan::{
    Catalog, Full, ListSink, OutCol, PartitionScan, RowSink, ScanPlan, Step, TableScan,
    TimestampUnit,
};
use pcapsql_core::{default_registry, ProtocolRegistry};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

fn count(bytes: usize) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    ALLOCATED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the arguments it was given,
// so `System`'s guarantees are this allocator's; the counters are atomics.
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

fn eth(payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
    p.extend_from_slice(payload);
    p
}

fn ipv4(proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0x00];
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x40, 0x00, 64, proto, 0x00, 0x00]);
    p.extend_from_slice(&[192, 168, 0, 1, 192, 168, 0, 2]);
    p.extend_from_slice(payload);
    p
}

fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(payload);
    p
}

/// A segment with NOP, NOP and a timestamp option, as most segments of an
/// established connection have.
fn tcp(sp: u16, dp: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let options = [1, 1, 8, 10, 0, 0, 0x10, 0x00, 0, 0, 0x20, 0x00];
    let mut p = Vec::new();
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push((((20 + options.len()) / 4) as u8) << 4);
    p.push(0x18);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend_from_slice(&options);
    p.extend_from_slice(payload);
    p
}

fn frame(kind: &str, i: usize) -> Vec<u8> {
    let id = i as u16;
    match kind {
        "udp" => eth(&ipv4(17, id, &udp(10_000 + id % 1000, 9999, &[0xAB; 8]))),
        "tcp" => eth(&ipv4(
            6,
            id,
            &tcp(40_000, 5001, 1_000 + i as u32, &[0xCD; 16]),
        )),
        "dns" => {
            // A response: `foo.com A`, answered with a compressed name.
            let mut dns = Vec::new();
            dns.extend_from_slice(&id.to_be_bytes());
            dns.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            dns.extend_from_slice(b"\x03foo\x03com\x00");
            dns.extend_from_slice(&[0, 1, 0, 1]);
            dns.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
            eth(&ipv4(17, id, &udp(53, 30_000 + id % 1000, &dns)))
        }
        "http" => eth(&ipv4(
            6,
            id,
            &tcp(
                40_000,
                80,
                1_000 + i as u32,
                b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n",
            ),
        )),
        other => panic!("unknown frame kind {other}: udp, tcp, dns or http"),
    }
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

/// `parse_packet` over every frame, into one buffer; the number of fields it
/// extracted.
#[inline(never)]
fn measured_parse(registry: &ProtocolRegistry, frames: &[Vec<u8>]) -> u64 {
    let scope = ParseScope::full();
    let mut buf = ParseBuf::new();
    let mut fields = 0u64;
    for frame in frames {
        let layers = parse_packet(registry, 1, black_box(frame), &scope, &mut buf);
        fields += layers
            .iter()
            .map(|layer| layer.fields().len() as u64)
            .sum::<u64>();
        black_box(&layers);
    }
    fields
}

/// A scan of `table` over `capture`; the rows and cells written.
#[inline(never)]
fn measured_scan(registry: &Arc<ProtocolRegistry>, table: &str, capture: Vec<u8>) -> (u64, u64) {
    let catalog = Catalog::builtin();
    let (id, entry) = catalog
        .table(table)
        .unwrap_or_else(|| panic!("unknown table {table}"));
    let plan = ScanPlan {
        tables: vec![TableScan::new(
            id,
            entry.default_columns().map(|(c, _)| c).collect(),
        )],
        timestamps: TimestampUnit::Nanos,
        ..Default::default()
    };
    let plan = Arc::new(plan.compile(catalog, registry).expect("the plan compiles"));
    let mut sinks = [NullSink::default()];

    let mut read = Cursor::new(capture);
    let (header, head) = StreamHeader::probe(&mut read).expect("a capture header");
    let reader = ReadPacketReader::sequential(read, &header, head).expect("a reader");
    let mut scan = PartitionScan::new(reader, plan, Arc::clone(registry));
    loop {
        match scan.step(&mut sinks, 1024).expect("the scan reads") {
            Step::More => {}
            Step::Flush(output) => panic!("a null sink is never full: {output:?}"),
            Step::Done | Step::End => break,
        }
    }
    (sinks[0].rows, sinks[0].cells)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let registry = Arc::new(default_registry());
    let counted = |f: &mut dyn FnMut() -> String| {
        let before = (
            ALLOCATIONS.load(Ordering::Relaxed),
            ALLOCATED_BYTES.load(Ordering::Relaxed),
        );
        let what = f();
        println!(
            "{what}; {} allocations, {} bytes",
            ALLOCATIONS.load(Ordering::Relaxed) - before.0,
            ALLOCATED_BYTES.load(Ordering::Relaxed) - before.1,
        );
    };
    match args[..] {
        ["parse", kind, packets] => {
            let packets: usize = packets.parse().expect("a packet count");
            let frames: Vec<Vec<u8>> = (0..packets).map(|i| frame(kind, i)).collect();
            counted(&mut || {
                let fields = measured_parse(&registry, &frames);
                format!("parse {kind}: {packets} packets, {fields} fields")
            });
        }
        ["scan", table, kind, packets] => {
            let count: usize = packets.parse().expect("a packet count");
            let packets: Vec<GenPacket> = (0..count)
                .map(|i| {
                    let data = frame(kind, i);
                    GenPacket {
                        ts_sec: 1_700_000_000 + i as u32,
                        ts_frac: i as u32 % 1_000_000,
                        origlen: data.len() as u32,
                        data,
                    }
                })
                .collect();
            let mut capture = Some(legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes);
            drop(packets);
            counted(&mut || {
                let capture = capture.take().expect("one run");
                let (rows, cells) = measured_scan(&registry, table, capture);
                format!("scan {table} over {kind}: {count} packets, {rows} rows, {cells} cells")
            });
        }
        _ => {
            eprintln!("usage: parse_cost parse <kind> <packets>");
            eprintln!("       parse_cost scan <table> <kind> <packets>");
            std::process::exit(2);
        }
    }
}
