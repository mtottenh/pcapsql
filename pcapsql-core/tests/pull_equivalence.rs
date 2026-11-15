//! Pull-equivalence: a scan read step by step into sinks of any size yields
//! the rows of one unbounded scan.
//!
//! For generated captures (legacy and pcapng; frames with one row per table,
//! tunnelled frames with several, and frames with more rows than a small
//! sink holds) the properties are:
//!
//! 1. For **every per-packet table of the catalogue** at once, with all of
//!    its columns: scanning into sinks of capacity 1, 2, 3 and 2048 through
//!    repeated [`PartitionScan::step`](pcapsql_core::scan::PartitionScan::step)
//!    calls, with any number of packets allowed per step, yields exactly the
//!    rows of a scan into unbounded sinks, in order.
//! 2. The same with row caps and a row predicate: the capped outputs hold
//!    the same rows, and the scan stops at the same packet.
//! 3. The partitions of a capture, each scanned through a
//!    [`ReadPacketReader::at`](pcapsql_core::io::ReadPacketReader::at) and
//!    concatenated in partition order, equal the sequential scan.
//!
//! No sink is ever written to beyond its capacity (the recording sink
//! panics), and no row leaves a sink before a step asks for it.
//!
//! This is the regression test for the defects a chunk-at-a-time consumer
//! is prone to: an over-full chunk, a row emitted twice, a row dropped at a
//! chunk boundary.

mod common;

use std::sync::{Arc, OnceLock};

use common::{
    frame_of_kind, full_plan, index_ranges, legacy_capture, packet_tables, pcapng_capture,
    reader_at, scan, scan_with, Rows, Scanned, DEEP, DEEP_TUNNELS, KINDS,
};
use pcapsql_core::scan::{
    Catalog, CmpOp, CompiledScan, RowPredicate, ScanPlan, Step, TableScan, TimestampUnit,
};
use pcapsql_core::{default_registry, ProtocolRegistry};
use proptest::prelude::*;

const CAPACITIES: [usize; 4] = [1, 2, 3, 2048];

fn registry() -> &'static Arc<ProtocolRegistry> {
    static REGISTRY: OnceLock<Arc<ProtocolRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Arc::new(default_registry()))
}

/// Every per-packet table of the catalogue with all its default columns.
fn every_table() -> &'static (Vec<&'static str>, Arc<CompiledScan>) {
    static PLAN: OnceLock<(Vec<&'static str>, Arc<CompiledScan>)> = OnceLock::new();
    PLAN.get_or_init(|| {
        let tables = packet_tables();
        let plan = full_plan(&tables, registry());
        (tables, plan)
    })
}

#[derive(Debug, Clone)]
struct Capture {
    /// The kind of each frame.
    kinds: Vec<u8>,
    pcapng: bool,
}

impl Capture {
    fn bytes(&self) -> Vec<u8> {
        let frames: Vec<Vec<u8>> = self
            .kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| frame_of_kind(i, *kind))
            .collect();
        if self.pcapng {
            pcapng_capture(&frames)
        } else {
            legacy_capture(&frames)
        }
    }
}

fn capture(max_frames: usize) -> impl Strategy<Value = Capture> {
    (
        prop::collection::vec(0..KINDS, 0..max_frames),
        any::<bool>(),
    )
        .prop_map(|(kinds, pcapng)| Capture { kinds, pcapng })
}

/// How many packets each step may consume, cycled.
fn step_sizes() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(
        prop_oneof![Just(1usize), Just(2), 3usize..40, Just(usize::MAX)],
        1..6,
    )
}

fn cycled(sizes: &[usize]) -> impl FnMut() -> usize + '_ {
    let mut turn = 0;
    move || {
        turn += 1;
        sizes[(turn - 1) % sizes.len()]
    }
}

/// A plan over a few tables with optional row caps and a predicate on
/// `udp` (`dst_port = 4789`: the tunnels' outer layers).
#[derive(Debug, Clone)]
struct Capped {
    /// `frames`, `ethernet`, `ipv4`, `udp`, `tcp`, `vxlan`.
    fetch: [Option<u64>; 6],
    predicate: bool,
    nanos: bool,
}

impl Capped {
    const TABLES: [&'static str; 6] = ["frames", "ethernet", "ipv4", "udp", "tcp", "vxlan"];

    fn compile(&self) -> Arc<CompiledScan> {
        let catalog = Catalog::builtin();
        let tables = Self::TABLES
            .iter()
            .zip(self.fetch)
            .map(|(name, fetch)| {
                let (id, table) = catalog.table(name).unwrap();
                let predicate = (self.predicate && *name == "udp").then(|| {
                    RowPredicate::cmp(table.column("dst_port").unwrap().0, CmpOp::Eq, 4789)
                });
                TableScan {
                    table: id,
                    columns: table.default_columns().map(|(c, _)| c).collect(),
                    predicate,
                    fetch,
                }
            })
            .collect();
        let plan = ScanPlan {
            tables,
            timestamps: if self.nanos {
                TimestampUnit::Nanos
            } else {
                TimestampUnit::Micros
            },
            ..Default::default()
        };
        Arc::new(plan.compile(catalog, registry()).unwrap())
    }
}

fn capped() -> impl Strategy<Value = Capped> {
    let fetch = prop_oneof![
        3 => Just(None),
        1 => Just(Some(0u64)),
        4 => (1u64..60).prop_map(Some),
    ];
    (prop::array::uniform6(fetch), any::<bool>(), any::<bool>()).prop_map(
        |(fetch, predicate, nanos)| Capped {
            fetch,
            predicate,
            nanos,
        },
    )
}

fn assert_same(scanned: &Scanned, expected: &Scanned, what: &str) {
    for (output, (got, want)) in scanned.rows.iter().zip(&expected.rows).enumerate() {
        assert!(
            got == want,
            "{what}: output {output} has {} rows, the unbounded scan {}{}",
            got.len(),
            want.len(),
            match got.iter().zip(want).position(|(g, w)| g != w) {
                Some(row) => format!("; first difference in row {row}"),
                None => String::new(),
            }
        );
    }
    assert_eq!(scanned.last, expected.last, "{what}");
    assert_eq!(scanned.stats, expected.stats, "{what}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Property 1: every table, every capacity.
    #[test]
    fn every_table_at_every_capacity(capture in capture(70), sizes in step_sizes()) {
        let (tables, plan) = every_table();
        let bytes = capture.bytes();
        let expected = scan(&bytes, plan, registry(), None, usize::MAX);
        prop_assert_eq!(expected.last, Step::End);
        prop_assert_eq!(expected.flushes, 0);
        prop_assert_eq!(expected.stats.packets, capture.kinds.len() as u64);
        let rows_of = |table: &str| {
            &expected.rows[tables.iter().position(|t| *t == table).unwrap()]
        };
        prop_assert_eq!(rows_of("frames").len(), capture.kinds.len());
        // A deep frame has more rows in a table than the small sinks hold.
        let deep = capture.kinds.iter().filter(|k| **k == DEEP).count();
        prop_assert!(rows_of("vxlan").len() >= deep * DEEP_TUNNELS);
        prop_assert!(DEEP_TUNNELS > 3);

        for capacity in CAPACITIES {
            let scanned = scan_with(
                common::reader(&bytes),
                plan,
                registry(),
                Some(capacity),
                cycled(&sizes),
            );
            assert_same(&scanned, &expected, &format!("capacity {capacity}"));
            let full: usize = expected.rows.iter().map(|r| r.len() / capacity).sum();
            prop_assert_eq!(scanned.flushes, full, "capacity {}", capacity);
        }
    }

    /// Property 2: row caps and a predicate.
    #[test]
    fn row_caps_and_predicates_at_every_capacity(
        capture in capture(70),
        capped in capped(),
        sizes in step_sizes(),
    ) {
        let plan = capped.compile();
        let bytes = capture.bytes();
        let expected = scan(&bytes, &plan, registry(), None, usize::MAX);
        for (rows, fetch) in expected.rows.iter().zip(capped.fetch) {
            prop_assert!(fetch.is_none_or(|cap| rows.len() as u64 <= cap));
        }
        if capped.fetch.iter().all(Option::is_some) {
            // Every output is capped: the scan ends early, unless the
            // capture ran out first.
            let reached = expected
                .rows
                .iter()
                .zip(capped.fetch)
                .all(|(rows, fetch)| Some(rows.len() as u64) == fetch);
            prop_assert_eq!(expected.last == Step::Done, reached);
        } else {
            prop_assert_eq!(expected.last, Step::End);
        }
        for capacity in CAPACITIES {
            let scanned = scan_with(
                common::reader(&bytes),
                &plan,
                registry(),
                Some(capacity),
                cycled(&sizes),
            );
            assert_same(&scanned, &expected, &format!("capacity {capacity}"));
        }
    }

    /// Property 3: partitions in order equal the sequential scan.
    #[test]
    fn partitions_concatenate_to_the_sequential_scan(
        capture in capture(120),
        stride in 1u64..12,
        partitions in 1usize..7,
        capacity in prop::sample::select(vec![None, Some(1usize), Some(2), Some(3), Some(2048)]),
        sizes in step_sizes(),
    ) {
        let (_, plan) = every_table();
        let bytes = capture.bytes();
        let expected = scan(&bytes, plan, registry(), None, usize::MAX);

        let (header, index, ranges) = index_ranges(&bytes, stride, partitions);
        prop_assert!(ranges.len() <= partitions);
        let mut rows: Rows = vec![Vec::new(); expected.rows.len()];
        let mut packets = 0;
        let mut time_range: Option<(i64, i64)> = None;
        for range in &ranges {
            let scanned = scan_with(
                reader_at(&bytes, &header, &index, range),
                plan,
                registry(),
                capacity,
                cycled(&sizes),
            );
            prop_assert_eq!(scanned.last, Step::End);
            packets += scanned.stats.packets;
            if let Some((min, max)) = scanned.stats.time_range_ns() {
                time_range = Some(match time_range {
                    Some((lo, hi)) => (lo.min(min), hi.max(max)),
                    None => (min, max),
                });
            }
            for (all, part) in rows.iter_mut().zip(scanned.rows) {
                all.extend(part);
            }
        }
        prop_assert_eq!(packets, expected.stats.packets);
        prop_assert_eq!(time_range, expected.stats.time_range_ns());
        for (output, (got, want)) in rows.iter().zip(&expected.rows).enumerate() {
            prop_assert!(
                got == want,
                "output {}: {} rows from {} partitions, {} from the sequential scan",
                output,
                got.len(),
                ranges.len(),
                want.len()
            );
        }
    }
}

/// The generated captures do exercise what the properties are about: every
/// kind of frame parses into the layers it is meant to have, so that the
/// tables the frames are for all get rows.
#[test]
fn the_generated_frames_fill_the_tables_they_are_meant_to() {
    let (tables, plan) = every_table();
    let capture = Capture {
        kinds: (0..KINDS).collect(),
        pcapng: false,
    };
    let scanned = scan(&capture.bytes(), plan, registry(), None, usize::MAX);
    let rows = |table: &str| scanned.rows[tables.iter().position(|t| *t == table).unwrap()].len();
    let frames = usize::from(KINDS);
    assert_eq!(rows("frames"), frames);
    // Per kind: 1, 2, 1, 3, 3, DEEP_TUNNELS + 1, 1, 1, 1 Ethernet layers.
    assert_eq!(rows("ethernet"), 13 + DEEP_TUNNELS + 1);
    assert_eq!(rows("vxlan"), 1 + 2 + 2 + DEEP_TUNNELS);
    assert_eq!(rows("tcp"), 2);
    assert_eq!(rows("dns"), 1);
    assert_eq!(rows("arp"), 1);
    assert_eq!(rows("icmp"), 1);
    assert_eq!(rows("ipv4"), rows("ethernet") - 1);
    assert_eq!(rows("udp"), rows("ipv4") - rows("tcp") - rows("icmp"));
}
