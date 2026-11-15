//! Routing a capture into bounded sinks.
//!
//! Property: whatever the capacity of the sinks, a scan yields exactly the
//! rows of a scan into unbounded sinks, in order: none lost, none
//! duplicated. The captures include tunnelled frames, which add several rows
//! to one table, so that a sink fills in the middle of a frame.
//!
//! The scan is run both ways a frontend can drive a [`Router`]: handing rows
//! on from inside the packet callback (push), and leaving the packet
//! callback whenever rows must be handed on, with the reader delivering an
//! unfinished packet again (pull).

use std::io::Cursor;
use std::ops::ControlFlow;

use pcapsql_core::io::{PacketReader, Pause, ReadPacketReader, StreamHeader};
use pcapsql_core::scan::testing::{Cell, RecordingSink};
use pcapsql_core::scan::{
    Catalog, CmpOp, CompiledScan, OutputId, Routed, Router, RowPredicate, ScanPlan, TableScan,
    TimestampUnit,
};
use pcapsql_core::{default_registry, parse_packet, ProtocolRegistry};
use pcapsql_testgen::{
    legacy_pcap, pcapng, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};

const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

fn eth(payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&0x0800u16.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ipv4(proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
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

fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(payload);
    p
}

/// TCP segment; every third one carries MSS and SACK-permitted options.
fn tcp(i: usize) -> Vec<u8> {
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

fn udp_frame(i: usize) -> Vec<u8> {
    eth(&ipv4(
        17,
        i as u16,
        &udp(10_000 + i as u16, 9999, &[0xAB; 8]),
    ))
}

fn tcp_frame(i: usize) -> Vec<u8> {
    eth(&ipv4(6, i as u16, &tcp(i)))
}

/// `inner` (an Ethernet frame) inside Ethernet/IPv4/UDP/VXLAN.
fn vxlan(i: usize, inner: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + inner.len());
    v.extend_from_slice(&[0x08, 0, 0, 0]);
    v.extend_from_slice(&(i as u32 % 4096).to_be_bytes()[1..]);
    v.push(0);
    v.extend_from_slice(inner);
    eth(&ipv4(17, i as u16, &udp(50_000, 4789, &v)))
}

/// A mix of frames with one, two and three rows per table.
fn frames(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| match i % 5 {
            0 => udp_frame(i),
            1 => vxlan(i, &udp_frame(i)),
            2 => tcp_frame(i),
            3 => vxlan(i, &vxlan(i + 1, &tcp_frame(i))),
            _ => vxlan(i, &vxlan(i + 1, &udp_frame(i))),
        })
        .collect()
}

fn legacy_capture(frames: &[Vec<u8>]) -> Vec<u8> {
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

fn pcapng_capture(frames: &[Vec<u8>]) -> Vec<u8> {
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

const TABLES: [&str; 6] = ["frames", "ethernet", "ipv4", "udp", "tcp", "vxlan"];

/// Every default column of each of `TABLES`, in nanoseconds.
fn full_plan(registry: &ProtocolRegistry) -> CompiledScan {
    let catalog = Catalog::builtin();
    let tables = TABLES
        .iter()
        .map(|name| {
            let (id, table) = catalog.table(name).unwrap();
            TableScan::new(id, table.default_columns().map(|(c, _)| c).collect())
        })
        .collect();
    ScanPlan {
        tables,
        timestamps: TimestampUnit::Nanos,
        ..Default::default()
    }
    .compile(catalog, registry)
    .unwrap()
}

type Rows = Vec<Vec<Vec<Cell>>>;

struct Scan<'a> {
    plan: &'a CompiledScan,
    registry: &'a ProtocolRegistry,
    router: Router,
    sinks: Vec<RecordingSink>,
    rows: Rows,
    /// Times a frame was routed again.
    redeliveries: usize,
}

impl<'a> Scan<'a> {
    fn new(
        plan: &'a CompiledScan,
        registry: &'a ProtocolRegistry,
        capacity: Option<usize>,
    ) -> Self {
        let sinks: Vec<RecordingSink> = plan
            .outputs()
            .iter()
            .map(|o| RecordingSink::new(&o.columns, capacity))
            .collect();
        Self {
            plan,
            registry,
            router: Router::new(plan),
            rows: vec![Vec::new(); sinks.len()],
            sinks,
            redeliveries: 0,
        }
    }

    fn take_flushes(&mut self) {
        while let Some(OutputId(output)) = self.router.take_flush() {
            let i = usize::from(output);
            self.rows[i].extend(self.sinks[i].take_rows());
        }
    }

    fn finish(mut self) -> (Rows, usize) {
        self.take_flushes();
        for (i, sink) in self.sinks.iter_mut().enumerate() {
            self.rows[i].extend(sink.take_rows());
        }
        (self.rows, self.redeliveries)
    }
}

fn reader(capture: &[u8]) -> ReadPacketReader<Cursor<Vec<u8>>> {
    let mut read = Cursor::new(capture.to_vec());
    let (header, head) = StreamHeader::probe(&mut read).unwrap();
    ReadPacketReader::sequential(read, &header, head).unwrap()
}

/// Rows are handed on inside the packet callback; an unfinished frame is
/// routed again on the spot.
fn scan_push(
    capture: &[u8],
    plan: &CompiledScan,
    registry: &ProtocolRegistry,
    capacity: Option<usize>,
) -> (Rows, usize) {
    let mut reader = reader(capture);
    let mut scan = Scan::new(plan, registry, capacity);
    loop {
        let delivered = reader
            .process_packets_flow(64, |packet| {
                let layers = parse_packet(
                    scan.registry,
                    packet.link_type,
                    packet.data,
                    scan.plan.scope(),
                );
                loop {
                    let routed = scan.router.route_frame(&mut scan.sinks, &packet, &layers);
                    scan.take_flushes();
                    match routed {
                        Routed::Consumed => break,
                        Routed::Redeliver => scan.redeliveries += 1,
                    }
                }
                ControlFlow::Continue(())
            })
            .unwrap();
        if delivered.consumed == 0 {
            break;
        }
    }
    scan.finish()
}

/// Rows are handed on outside the packet callback only: the callback
/// pauses the reader, before the packet when its frame is unfinished.
fn scan_pull(
    capture: &[u8],
    plan: &CompiledScan,
    registry: &ProtocolRegistry,
    capacity: Option<usize>,
) -> (Rows, usize) {
    let mut reader = reader(capture);
    let mut scan = Scan::new(plan, registry, capacity);
    let mut packets = 0;
    loop {
        let delivered = reader
            .process_packets_flow(64, |packet| {
                let layers = parse_packet(
                    scan.registry,
                    packet.link_type,
                    packet.data,
                    scan.plan.scope(),
                );
                match scan.router.route_frame(&mut scan.sinks, &packet, &layers) {
                    Routed::Redeliver => {
                        scan.redeliveries += 1;
                        ControlFlow::Break(Pause::Before)
                    }
                    Routed::Consumed if scan.router.has_flush() => ControlFlow::Break(Pause::After),
                    Routed::Consumed => ControlFlow::Continue(()),
                }
            })
            .unwrap();
        packets += delivered.consumed;
        scan.take_flushes();
        if delivered.consumed == 0 && delivered.paused.is_none() {
            break;
        }
    }
    let (rows, redeliveries) = scan.finish();
    assert_eq!(rows[0].len(), packets, "one frames row per consumed packet");
    (rows, redeliveries)
}

const N_FRAMES: usize = 203;

#[test]
fn any_capacity_yields_the_rows_of_an_unbounded_scan() {
    let registry = default_registry();
    let plan = full_plan(&registry);
    let frames = frames(N_FRAMES);
    for (format, capture) in [
        ("pcap", legacy_capture(&frames)),
        ("pcapng", pcapng_capture(&frames)),
    ] {
        let (expected, redeliveries) = scan_push(&capture, &plan, &registry, None);
        assert_eq!(redeliveries, 0);

        // The capture is what it is meant to be: one frames row per frame,
        // and one to three rows per frame in the other tables.
        let count = |table: &str| expected[TABLES.iter().position(|t| *t == table).unwrap()].len();
        let of_kind = |k: usize| (0..N_FRAMES).filter(|i| i % 5 == k).count();
        let layers = of_kind(0) + 2 * of_kind(1) + of_kind(2) + 3 * of_kind(3) + 3 * of_kind(4);
        assert_eq!(count("frames"), N_FRAMES, "{format}");
        assert_eq!(count("ethernet"), layers, "{format}");
        assert_eq!(count("ipv4"), layers, "{format}");
        assert_eq!(count("tcp"), of_kind(2) + of_kind(3), "{format}");
        assert_eq!(count("udp"), layers - count("tcp"), "{format}");
        assert_eq!(
            count("vxlan"),
            of_kind(1) + 2 * of_kind(3) + 2 * of_kind(4),
            "{format}"
        );
        // Frame numbers ascend in every table, and each frames row is its
        // frame's.
        for (table, rows) in TABLES.iter().zip(&expected) {
            let numbers: Vec<u64> = rows
                .iter()
                .map(|row| match &row[0] {
                    Cell::U64(n) => *n,
                    other => panic!("{table}.frame_number is {other:?}"),
                })
                .collect();
            assert!(numbers.windows(2).all(|w| w[0] <= w[1]), "{format} {table}");
        }

        for capacity in [1, 2, 3, 7, 64, 2048] {
            let (pushed, push_redeliveries) = scan_push(&capture, &plan, &registry, Some(capacity));
            assert!(
                pushed == expected,
                "{format}: push at capacity {capacity} differs from the unbounded scan"
            );
            let (pulled, pull_redeliveries) = scan_pull(&capture, &plan, &registry, Some(capacity));
            assert!(
                pulled == expected,
                "{format}: pull at capacity {capacity} differs from the unbounded scan"
            );
            assert_eq!(push_redeliveries, pull_redeliveries, "{format} {capacity}");
            if capacity <= 2 {
                // Three rows of one frame do not fit: frames were split.
                assert!(pull_redeliveries > 0, "{format} {capacity}");
            }
            if capacity == 2048 {
                assert_eq!(pull_redeliveries, 0, "{format}");
            }
        }
    }
}

/// The same with a row predicate and row caps: the capped tables stop where
/// the unbounded scan's do.
#[test]
fn predicates_and_row_caps_do_not_depend_on_capacity() {
    let registry = default_registry();
    let catalog = Catalog::builtin();
    let scan = |name: &str, columns: &[&str]| {
        let (id, table) = catalog.table(name).unwrap();
        let columns = columns.iter().map(|c| table.column(c).unwrap().0).collect();
        (TableScan::new(id, columns), table)
    };
    let (frames_scan, _) = scan("frames", &["frame_number", "timestamp", "raw_data"]);
    let (mut udp_scan, udp_table) = scan("udp", &["frame_number", "src_port", "encap_depth"]);
    udp_scan.predicate = Some(RowPredicate::cmp(
        udp_table.column("dst_port").unwrap().0,
        CmpOp::Eq,
        4789,
    ));
    let (mut ipv4_scan, _) = scan("ipv4", &["frame_number", "encap_depth", "tunnel_type"]);
    ipv4_scan.fetch = Some(40);
    let (mut ethernet_scan, _) = scan("ethernet", &[]);
    ethernet_scan.fetch = Some(41);
    let plan = ScanPlan {
        tables: vec![frames_scan, udp_scan, ipv4_scan, ethernet_scan],
        ..Default::default()
    }
    .compile(catalog, &registry)
    .unwrap();

    let capture = legacy_capture(&frames(N_FRAMES));
    let (expected, _) = scan_push(&capture, &plan, &registry, None);
    assert_eq!(expected[0].len(), N_FRAMES);
    // Only the tunnels' outer UDP layers are kept.
    let of_kind = |k: usize| (0..N_FRAMES).filter(|i| i % 5 == k).count();
    assert_eq!(
        expected[1].len(),
        of_kind(1) + 2 * of_kind(3) + 2 * of_kind(4)
    );
    assert_eq!(expected[2].len(), 40);
    assert_eq!(expected[3], vec![Vec::<Cell>::new(); 41]);

    for capacity in [1, 2, 3, 7, 39, 40, 41, 2048] {
        let (pushed, _) = scan_push(&capture, &plan, &registry, Some(capacity));
        assert!(pushed == expected, "push at capacity {capacity}");
        let (pulled, _) = scan_pull(&capture, &plan, &registry, Some(capacity));
        assert!(pulled == expected, "pull at capacity {capacity}");
    }
}
