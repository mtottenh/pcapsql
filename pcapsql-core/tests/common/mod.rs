//! Shared by the scan tests: frames, captures, plans, and a scan driven
//! through [`PartitionScan::step`] into [`RecordingSink`]s.
#![allow(dead_code)]

use std::io::Cursor;
use std::sync::Arc;

use pcapsql_core::io::{
    build_boundary_index, header_hash, BoundaryIndex, PacketRange, PacketReader, ReadPacketReader,
    StreamHeader,
};
use pcapsql_core::scan::testing::{Cell, RecordingSink};
use pcapsql_core::scan::{
    Catalog, CompiledScan, OutputId, PartitionScan, ScanPlan, ScanStats, Step, TableScan,
    TimestampUnit,
};
use pcapsql_core::ProtocolRegistry;
use pcapsql_testgen::{
    legacy_pcap, pcapng, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};

const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

pub fn eth_type(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&ethertype.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

pub fn eth(payload: &[u8]) -> Vec<u8> {
    eth_type(0x0800, payload)
}

pub fn ipv4(proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x40, 0x00]);
    p.push(64);
    p.push(proto);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[192, 168, 0, 1]);
    p.extend_from_slice(&[192, 168, 0, 2]);
    p.extend_from_slice(payload);
    p
}

pub fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(payload);
    p
}

/// TCP segment; every third one carries MSS and SACK-permitted options.
pub fn tcp(i: usize) -> Vec<u8> {
    let options: &[u8] = if i.is_multiple_of(3) {
        &[2, 4, 0x05, 0xB4, 4, 2, 1, 1]
    } else {
        &[]
    };
    let mut p = Vec::new();
    p.extend_from_slice(&40_000u16.to_be_bytes());
    p.extend_from_slice(&443u16.to_be_bytes());
    p.extend_from_slice(&(1_000 + i as u32).to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push((((20 + options.len()) / 4) as u8) << 4);
    p.push(0x18);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend_from_slice(options);
    p.extend_from_slice(&[0xCD; 16]);
    p
}

pub fn udp_frame(i: usize) -> Vec<u8> {
    eth(&ipv4(
        17,
        i as u16,
        &udp(10_000 + i as u16, 9999, &[0xAB; 8]),
    ))
}

pub fn tcp_frame(i: usize) -> Vec<u8> {
    eth(&ipv4(6, i as u16, &tcp(i)))
}

/// A DNS query for `foo.com`.
pub fn dns_frame(i: usize) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&(i as u16).to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    dns.extend_from_slice(b"\x03foo\x03com\x00");
    dns.extend_from_slice(&[0, 1, 0, 1]);
    eth(&ipv4(17, i as u16, &udp(30_000 + i as u16, 53, &dns)))
}

/// An ARP request.
pub fn arp_frame(i: usize) -> Vec<u8> {
    let mut arp = vec![0, 1, 0x08, 0x00, 6, 4, 0, 1];
    arp.extend_from_slice(&MAC_A);
    arp.extend_from_slice(&[10, 0, 0, 1]);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&[10, 0, 0, i as u8]);
    eth_type(0x0806, &arp)
}

/// An ICMP echo request.
pub fn icmp_frame(i: usize) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0, 1];
    icmp.extend_from_slice(&(i as u16).to_be_bytes());
    icmp.extend_from_slice(&[0x61; 8]);
    eth(&ipv4(1, i as u16, &icmp))
}

/// `inner` (an Ethernet frame) inside Ethernet/IPv4/UDP/VXLAN.
pub fn vxlan(i: usize, inner: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + inner.len());
    v.extend_from_slice(&[0x08, 0, 0, 0]);
    v.extend_from_slice(&(i as u32 % 4096).to_be_bytes()[1..]);
    v.push(0);
    v.extend_from_slice(inner);
    eth(&ipv4(17, i as u16, &udp(50_000, 4789, &v)))
}

/// A UDP frame inside `depth` VXLAN tunnels: `depth + 1` rows in each of
/// `ethernet`, `ipv4` and `udp`, and `depth` in `vxlan`.
pub fn nested(i: usize, depth: usize) -> Vec<u8> {
    (0..depth).fold(udp_frame(i), |inner, level| vxlan(i + level, &inner))
}

/// The number of tunnels around [`frame_of_kind`]`(_, DEEP)`.
pub const DEEP_TUNNELS: usize = 6;
/// The kind of the frame with more rows per table than a small sink holds.
pub const DEEP: u8 = 5;
/// Kinds are taken modulo this.
pub const KINDS: u8 = 9;

/// Frame `i` of one of [`KINDS`] kinds: with one, two, three and seven
/// rows per table, and of protocols that give rows to different tables.
pub fn frame_of_kind(i: usize, kind: u8) -> Vec<u8> {
    match kind % KINDS {
        0 => udp_frame(i),
        1 => vxlan(i, &udp_frame(i)),
        2 => tcp_frame(i),
        3 => vxlan(i, &vxlan(i + 1, &tcp_frame(i))),
        4 => vxlan(i, &vxlan(i + 1, &udp_frame(i))),
        DEEP => nested(i, DEEP_TUNNELS),
        6 => dns_frame(i),
        7 => arp_frame(i),
        _ => icmp_frame(i),
    }
}

/// A mix of frames with one, two and three rows per table.
pub fn frames(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| frame_of_kind(i, (i % 5) as u8))
        .collect()
}

pub fn legacy_capture(frames: &[Vec<u8>]) -> Vec<u8> {
    let packets: Vec<GenPacket> = frames
        .iter()
        .enumerate()
        .map(|(i, data)| GenPacket {
            ts_sec: 1_700_000_000 + i as u32,
            ts_frac: i as u32 * 7,
            data: data.clone(),
            origlen: data.len() as u32,
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

pub fn pcapng_capture(frames: &[Vec<u8>]) -> Vec<u8> {
    let packets = frames
        .iter()
        .enumerate()
        .map(|(i, data)| PcapngPacket {
            interface_id: 0,
            ts_sec: 1_700_000_000 + i as u64,
            ts_frac_units: i as u64,
            data: data.clone(),
            origlen: data.len() as u32,
        })
        .collect();
    pcapng(&[PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: 1,
            tsresol: 9,
            snaplen: 65535,
            if_tsoffset: 0,
        }],
        packets,
    }])
    .bytes
}

/// Every default column of each of `tables`, in nanoseconds.
pub fn full_plan(tables: &[&str], registry: &ProtocolRegistry) -> Arc<CompiledScan> {
    let catalog = Catalog::builtin();
    let tables = tables
        .iter()
        .map(|name| {
            let (id, table) = catalog.table(name).unwrap();
            TableScan::new(id, table.default_columns().map(|(c, _)| c).collect())
        })
        .collect();
    let plan = ScanPlan {
        tables,
        timestamps: TimestampUnit::Nanos,
        ..Default::default()
    };
    Arc::new(plan.compile(catalog, registry).unwrap())
}

/// The names of every per-packet table of the catalogue: `frames` and the
/// protocol tables.
pub fn packet_tables() -> Vec<&'static str> {
    Catalog::builtin()
        .tables()
        .filter(|(_, table)| !table.is_stream())
        .map(|(_, table)| table.name)
        .collect()
}

/// The rows of each output, in output order.
pub type Rows = Vec<Vec<Vec<Cell>>>;

/// A reader over the whole of `capture`.
pub fn reader(capture: &[u8]) -> ReadPacketReader<Cursor<Vec<u8>>> {
    let mut read = Cursor::new(capture.to_vec());
    let (header, head) = StreamHeader::probe(&mut read).unwrap();
    ReadPacketReader::sequential(read, &header, head).unwrap()
}

/// The boundary index of `capture` (a checkpoint every `stride` frames)
/// and at most `partitions` ranges covering it.
pub fn index_ranges(
    capture: &[u8],
    stride: u64,
    partitions: usize,
) -> (StreamHeader, BoundaryIndex, Vec<PacketRange>) {
    let (header, _) = StreamHeader::probe(&mut Cursor::new(capture)).unwrap();
    let index = build_boundary_index(
        Cursor::new(capture),
        header.format,
        stride,
        capture.len() as u64,
        None,
        header_hash(&capture[..capture.len().min(4096)]),
    )
    .unwrap();
    let ranges = index.partition_ranges(partitions);
    (header, index, ranges)
}

/// A reader over `range` of `capture`.
pub fn reader_at(
    capture: &[u8],
    header: &StreamHeader,
    index: &BoundaryIndex,
    range: &PacketRange,
) -> ReadPacketReader<Cursor<Vec<u8>>> {
    let mut cursor = Cursor::new(capture.to_vec());
    cursor.set_position(range.start.byte_offset);
    ReadPacketReader::at(cursor, header.format, index, range).unwrap()
}

/// What a scan produced.
#[derive(Debug, PartialEq)]
pub struct Scanned {
    pub rows: Rows,
    /// `Step::Done` or `Step::End`.
    pub last: Step,
    pub stats: ScanStats,
    /// Times an output was handed out by `Step::Flush`.
    pub flushes: usize,
}

/// Scan what `reader` delivers the way a pull engine does: every output
/// has a sink of `capacity` rows (`None`: unbounded), `step` is called
/// until the scan is over, and rows leave a sink only when `step` says so
/// (and at the end). `max_packets` is asked before every step.
///
/// Panics (in [`RecordingSink`]) when a sink is written to beyond its
/// capacity, and here when a flush is reported for a sink that need not be
/// taken.
pub fn scan_with<R: PacketReader>(
    reader: R,
    plan: &Arc<CompiledScan>,
    registry: &Arc<ProtocolRegistry>,
    capacity: Option<usize>,
    mut max_packets: impl FnMut() -> usize,
) -> Scanned {
    let mut sinks: Vec<RecordingSink> = plan
        .outputs()
        .iter()
        .map(|o| RecordingSink::new(&o.columns, capacity))
        .collect();
    let mut rows: Rows = vec![Vec::new(); sinks.len()];
    let mut scan = PartitionScan::new(reader, Arc::clone(plan), Arc::clone(registry));
    let mut flushes = 0;
    let last = loop {
        let before = scan.stats().packets;
        let max = max_packets();
        let step = scan.step(&mut sinks, max).unwrap();
        assert!(
            scan.stats().packets - before <= max as u64,
            "a step consumes at most max_packets"
        );
        match step {
            Step::More => {}
            Step::Flush(OutputId(output)) => {
                let sink = &mut sinks[usize::from(output)];
                assert!(
                    sink.is_full() || scan.output_done(OutputId(output)),
                    "output {output} was handed out neither full nor capped"
                );
                rows[usize::from(output)].extend(sink.take_rows());
                flushes += 1;
            }
            last @ (Step::Done | Step::End) => break last,
        }
    };
    for (sink, rows) in sinks.iter_mut().zip(&mut rows) {
        assert!(!sink.is_full(), "a full sink was left at the end");
        rows.extend(sink.take_rows());
    }
    // Once over, always over.
    assert_eq!(scan.step(&mut sinks, 1).unwrap(), last);
    assert!(sinks.iter().all(|sink| sink.rows() == 0));
    let (stats, _) = scan.finish();
    for (output, rows) in rows.iter().enumerate() {
        assert_eq!(stats.rows[output], rows.len() as u64, "output {output}");
    }
    Scanned {
        rows,
        last,
        stats,
        flushes,
    }
}

/// [`scan_with`] over the whole of `capture`, `max_packets` per step.
pub fn scan(
    capture: &[u8],
    plan: &Arc<CompiledScan>,
    registry: &Arc<ProtocolRegistry>,
    capacity: Option<usize>,
    max_packets: usize,
) -> Scanned {
    scan_with(reader(capture), plan, registry, capacity, || max_packets)
}
