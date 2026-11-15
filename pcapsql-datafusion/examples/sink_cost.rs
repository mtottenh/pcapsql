//! What storing a scan's rows in Arrow costs, for a profiler.
//!
//! ```text
//! sink_cost <sink> <tables> <kind> <packets>
//! ```
//!
//! `<sink>` is `arrow` (an [`ArrowSink`] per table, a batch of 10,000 rows
//! taken and dropped whenever one is full) or `none` (a sink that stores
//! nothing): the difference of the two is what the Arrow sink costs, the
//! rest being the reader, the parsers and the row writers of
//! `pcapsql_core::scan`. `<tables>` is a comma-separated list of tables, or
//! `all` for every per-packet table; every column of each is written.
//! `<kind>` is the frame that is repeated: `udp` (Ethernet/IPv4/UDP with a
//! payload of 256 bytes), `tcp` (segments cycling through a SYN with
//! options, a segment with SACK blocks and one without options, so that
//! list columns are filled and optional ones are NULL) or `mix` (those two,
//! a DNS response and a VXLAN-encapsulated frame in turn).
//!
//! The measured work is in the function `measured_scan` and nothing else
//! is, so that callgrind can be told to count it alone, and a per-packet
//! cost is the difference of two runs:
//!
//! ```text
//! cargo build -p pcapsql-datafusion --example sink_cost --profile bench
//! for n in 20000 40000; do
//!   valgrind --tool=callgrind --callgrind-out-file=/dev/null \
//!     --toggle-collect='*measured_scan*' \
//!     target/release/examples/sink_cost arrow frames,ipv4,udp udp $n
//! done    # (Collected(40000) - Collected(20000)) / 20000 instructions per packet
//! ```
//!
//! The program prints the rows and cells written, which turn that into
//! instructions per row and per cell.

use std::hint::black_box;
use std::io::Cursor;
use std::ops::ControlFlow;
use std::sync::Arc;

use pcapsql_core::io::{ReadPacketReader, StreamHeader};
use pcapsql_core::scan::{
    Catalog, CompiledScan, Full, ListSink, OutCol, PartitionScan, RowSink, ScanPlan, Step,
    TableScan,
};
use pcapsql_core::{default_registry, ProtocolRegistry};
use pcapsql_datafusion::query::builders::ArrowSink;
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};

/// Rows per batch, as the CLI's default engine uses for a one-shot query.
const BATCH_SIZE: usize = 10_000;

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

fn udp_frame(i: usize) -> Vec<u8> {
    let port = 10_000 + (i % 5000) as u16;
    eth(&ipv4(17, i as u16, &udp(port, 9999, &[0xAB; 256])))
}

/// A SYN with MSS, SACK permitted, timestamps and window scale; a segment
/// with timestamps and two SACK blocks; a segment without options.
fn tcp_frame(i: usize) -> Vec<u8> {
    let seq = 1_000 + i as u32 * 100;
    let mut options = Vec::new();
    let timestamps = |options: &mut Vec<u8>| {
        options.extend_from_slice(&[8, 10]);
        options.extend_from_slice(&(i as u32).to_be_bytes());
        options.extend_from_slice(&(i as u32 + 1).to_be_bytes());
    };
    let flags = match i % 3 {
        0 => {
            options.extend_from_slice(&[2, 4, 0x05, 0xB4, 4, 2]);
            timestamps(&mut options);
            options.extend_from_slice(&[3, 3, 7]);
            0x02
        }
        1 => {
            timestamps(&mut options);
            options.extend_from_slice(&[5, 18]);
            for edge in [seq + 200, seq + 300, seq + 500, seq + 600] {
                options.extend_from_slice(&edge.to_be_bytes());
            }
            0x10
        }
        _ => 0x18,
    };
    options.resize(options.len().next_multiple_of(4), 1);
    let mut p = Vec::new();
    p.extend_from_slice(&40_000u16.to_be_bytes());
    p.extend_from_slice(&443u16.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push((((20 + options.len()) / 4) as u8) << 4);
    p.push(flags);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend_from_slice(&options);
    p.extend_from_slice(&[0xCD; 64]);
    eth(&ipv4(6, i as u16, &p))
}

/// A response: `foo.com A`, answered with a compressed name.
fn dns_frame(i: usize) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&(i as u16).to_be_bytes());
    dns.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    dns.extend_from_slice(b"\x03foo\x03com\x00");
    dns.extend_from_slice(&[0, 1, 0, 1]);
    dns.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
    eth(&ipv4(17, i as u16, &udp(53, 30_000, &dns)))
}

fn vxlan_frame(i: usize) -> Vec<u8> {
    let mut vxlan = vec![0x08, 0, 0, 0];
    vxlan.extend_from_slice(&(i as u32 % 4096).to_be_bytes()[1..]);
    vxlan.push(0);
    vxlan.extend_from_slice(&udp_frame(i));
    eth(&ipv4(17, i as u16, &udp(50_000, 4789, &vxlan)))
}

fn frame(kind: &str, i: usize) -> Vec<u8> {
    match kind {
        "udp" => udp_frame(i),
        "tcp" => tcp_frame(i),
        "mix" => match i % 4 {
            0 => udp_frame(i),
            1 => tcp_frame(i / 4),
            2 => dns_frame(i),
            _ => vxlan_frame(i),
        },
        other => panic!("unknown frame kind {other}: udp, tcp or mix"),
    }
}

/// Every column of `tables`, or of every per-packet table for `all`.
fn plan(tables: &str, registry: &ProtocolRegistry) -> CompiledScan {
    let catalog = Catalog::builtin();
    let tables = catalog
        .tables()
        .filter(|(_, def)| match tables {
            "all" => !def.is_stream(),
            names => names.split(',').any(|name| name == def.name),
        })
        .map(|(id, def)| TableScan::new(id, def.columns().map(|(c, _)| c).collect()))
        .collect::<Vec<_>>();
    assert!(!tables.is_empty(), "no such table");
    ScanPlan {
        tables,
        ..Default::default()
    }
    .compile(catalog, registry)
    .expect("the plan compiles")
}

/// Counts rows and cells, stores nothing.
#[derive(Default)]
struct Counter {
    rows: u64,
    cells: u64,
}

impl RowSink for Counter {
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

    type List<'s> = NoList;

    fn list(&mut self, _: OutCol) -> NoList {
        self.cells += 1;
        NoList
    }

    fn end_row(&mut self) -> ControlFlow<Full> {
        self.rows += 1;
        ControlFlow::Continue(())
    }
}

struct NoList;

impl ListSink for NoList {
    fn null(&mut self) {}
    fn u16(&mut self, _: u16) {}
    fn u32(&mut self, _: u32) {}
    fn str(&mut self, _: &str) {}
    fn bytes(&mut self, _: &[u8]) {}
    fn finish(self) {}
}

/// A scan of `capture` into `sinks`, one per output of `plan`; `take` is
/// called with a sink that is full, and with every sink at the end.
#[inline(never)]
fn measured_scan<S: RowSink>(
    registry: &Arc<ProtocolRegistry>,
    plan: Arc<CompiledScan>,
    capture: &[u8],
    sinks: &mut [S],
    mut take: impl FnMut(&mut S),
) {
    let mut read = Cursor::new(capture);
    let (header, head) = StreamHeader::probe(&mut read).expect("a capture header");
    let reader = ReadPacketReader::sequential(read, &header, head).expect("a reader");
    let mut scan = PartitionScan::new(reader, plan, Arc::clone(registry));
    loop {
        match scan.step(sinks, 1024).expect("the scan reads") {
            Step::More => {}
            Step::Flush(output) => take(&mut sinks[usize::from(output.0)]),
            Step::Done | Step::End => break,
        }
    }
    sinks.iter_mut().for_each(take);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [sink, tables, kind, packets] = &args[..] else {
        eprintln!("usage: sink_cost <arrow|none> <tables|all> <udp|tcp|mix> <packets>");
        std::process::exit(2);
    };
    let count: usize = packets.parse().expect("a packet count");
    let registry = Arc::new(default_registry());
    let plan = Arc::new(plan(tables, &registry));
    let packets: Vec<GenPacket> = (0..count)
        .map(|i| {
            let data = frame(kind, i);
            GenPacket {
                ts_sec: 1_700_000_000 + (i / 1000) as u32,
                ts_frac: (i as u32 * 251) % 1_000_000,
                origlen: data.len() as u32,
                data,
            }
        })
        .collect();
    let capture = legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes;
    drop(packets);

    let (rows, cells) = match sink.as_str() {
        "arrow" => {
            let mut sinks: Vec<ArrowSink> = plan
                .outputs()
                .iter()
                .map(|output| ArrowSink::new(&output.columns, BATCH_SIZE))
                .collect();
            let (mut rows, mut cells) = (0u64, 0u64);
            measured_scan(&registry, Arc::clone(&plan), &capture, &mut sinks, |sink| {
                if let Some(batch) = sink.take_batch().expect("the batch builds") {
                    rows += batch.num_rows() as u64;
                    cells += (batch.num_rows() * batch.num_columns()) as u64;
                    black_box(&batch);
                }
            });
            (rows, cells)
        }
        "none" => {
            let mut sinks: Vec<Counter> =
                plan.outputs().iter().map(|_| Counter::default()).collect();
            measured_scan(&registry, Arc::clone(&plan), &capture, &mut sinks, |_| {});
            sinks
                .iter()
                .fold((0, 0), |(r, c), s| (r + s.rows, c + s.cells))
        }
        other => panic!("unknown sink {other}: arrow or none"),
    };
    println!("{sink} sink, {tables} over {kind}: {count} packets, {rows} rows, {cells} cells");
}
