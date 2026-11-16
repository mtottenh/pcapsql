//! Scanning a capture into bounded sinks.
//!
//! Property: whatever the capacity of the sinks, and however many packets a
//! step may consume, a scan yields exactly the rows of a scan into unbounded
//! sinks, in order: none lost, none duplicated. The captures include
//! tunnelled frames, which add several rows to one table, so that a sink
//! fills in the middle of a frame.
//!
//! The scan is driven through `pcapsql_core::scan::PartitionScan::step`,
//! with rows leaving a sink only when a step says so: the way a pull engine
//! uses it. The generated cases are in `pull_equivalence.rs`.

mod common;

use std::sync::Arc;

use common::{
    frames, full_plan, legacy_capture, nested, pcapng_capture, scan, udp_frame, DEEP_TUNNELS,
};
use pcapsql_core::default_registry;
use pcapsql_core::scan::testing::Cell;
use pcapsql_core::scan::{Catalog, CmpOp, RowPredicate, ScanPlan, Step, TableScan};

const TABLES: [&str; 6] = ["frames", "ethernet", "ipv4", "udp", "tcp", "vxlan"];
const N_FRAMES: usize = 203;
const STEP_SIZES: [usize; 4] = [1, 7, 64, usize::MAX];

#[test]
fn any_capacity_yields_the_rows_of_an_unbounded_scan() {
    let registry = Arc::new(default_registry());
    let plan = full_plan(&TABLES, &registry);
    let frames = frames(N_FRAMES);
    for (format, capture) in [
        ("pcap", legacy_capture(&frames)),
        ("pcapng", pcapng_capture(&frames)),
    ] {
        let expected = scan(&capture, &plan, &registry, None, usize::MAX);
        assert_eq!(expected.flushes, 0, "{format}");
        assert_eq!(expected.last, Step::End, "{format}");
        assert_eq!(expected.stats.packets, N_FRAMES as u64, "{format}");
        let last = N_FRAMES as i64 - 1;
        assert_eq!(
            expected.stats.time_range_ns(),
            Some((
                1_700_000_000_000_000_000,
                (1_700_000_000 + last) * 1_000_000_000
                    + match format {
                        // 7 microseconds per frame; 1 nanosecond per frame.
                        "pcap" => last * 7_000,
                        _ => last,
                    }
            )),
            "{format}"
        );

        // The capture is what it is meant to be: one frames row per frame,
        // and one to three rows per frame in the other tables.
        let rows = &expected.rows;
        let count = |table: &str| rows[TABLES.iter().position(|t| *t == table).unwrap()].len();
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
        // Frame numbers ascend in every table.
        for (table, rows) in TABLES.iter().zip(rows) {
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
            for max_packets in STEP_SIZES {
                let scanned = scan(&capture, &plan, &registry, Some(capacity), max_packets);
                assert!(
                    scanned.rows == expected.rows,
                    "{format}: capacity {capacity}, {max_packets} packets per step: \
                     rows differ from the unbounded scan"
                );
                assert_eq!(scanned.last, Step::End);
                assert_eq!(scanned.stats, expected.stats, "{format} {capacity}");
                // Every sink that filled was handed out, and only those.
                let full: usize = expected.rows.iter().map(|r| r.len() / capacity).sum();
                assert_eq!(scanned.flushes, full, "{format} {capacity} {max_packets}");
            }
        }
    }
}

/// The same with a row predicate and row caps: the capped tables stop where
/// the unbounded scan's do.
#[test]
fn predicates_and_row_caps_do_not_depend_on_capacity() {
    let registry = Arc::new(default_registry());
    let catalog = Catalog::builtin();
    let table_scan = |name: &str, columns: &[&str]| {
        let (id, table) = catalog.table(name).unwrap();
        let columns = columns.iter().map(|c| table.column(c).unwrap().0).collect();
        (TableScan::new(id, columns), table)
    };
    let (frames_scan, _) = table_scan("frames", &["frame_number", "timestamp", "raw_data"]);
    let (mut udp_scan, udp_table) = table_scan("udp", &["frame_number", "src_port", "encap_depth"]);
    udp_scan.predicate = Some(RowPredicate::cmp(
        udp_table.column("dst_port").unwrap().0,
        CmpOp::Eq,
        4789,
    ));
    let (mut ipv4_scan, _) = table_scan("ipv4", &["frame_number", "encap_depth", "tunnel_type"]);
    ipv4_scan.fetch = Some(40);
    let (mut ethernet_scan, _) = table_scan("ethernet", &[]);
    ethernet_scan.fetch = Some(41);
    let mut plan = ScanPlan {
        tables: vec![frames_scan, udp_scan, ipv4_scan, ethernet_scan],
        ..Default::default()
    };
    let compiled = Arc::new(plan.compile(catalog, &registry).unwrap());

    let capture = legacy_capture(&frames(N_FRAMES));
    let expected = scan(&capture, &compiled, &registry, None, usize::MAX);
    // `frames` has no cap: the scan runs to the end.
    assert_eq!(expected.last, Step::End);
    assert_eq!(expected.stats.packets, N_FRAMES as u64);
    assert_eq!(expected.rows[0].len(), N_FRAMES);
    // Only the tunnels' outer UDP layers are kept.
    let of_kind = |k: usize| (0..N_FRAMES).filter(|i| i % 5 == k).count();
    assert_eq!(
        expected.rows[1].len(),
        of_kind(1) + 2 * of_kind(3) + 2 * of_kind(4)
    );
    assert_eq!(expected.rows[2].len(), 40);
    assert_eq!(expected.rows[3], vec![Vec::<Cell>::new(); 41]);
    // The capped outputs were handed out when they reached their caps.
    assert_eq!(expected.flushes, 2);

    for capacity in [1, 2, 3, 7, 39, 40, 41, 2048] {
        for max_packets in STEP_SIZES {
            let scanned = scan(&capture, &compiled, &registry, Some(capacity), max_packets);
            assert!(
                scanned.rows == expected.rows,
                "capacity {capacity}, {max_packets} packets per step"
            );
            assert_eq!(scanned.last, Step::End);
            assert_eq!(scanned.stats, expected.stats);
        }
    }

    // With a cap on every table the scan is over at the frame that reaches
    // the last of them, whatever the capacity: nothing after it is read.
    plan.tables[0].fetch = Some(30);
    plan.tables[1].fetch = Some(5);
    let compiled = Arc::new(plan.compile(catalog, &registry).unwrap());
    let expected = scan(&capture, &compiled, &registry, None, usize::MAX);
    assert_eq!(expected.last, Step::Done);
    let lens: Vec<usize> = expected.rows.iter().map(Vec::len).collect();
    assert_eq!(lens, [30, 5, 40, 41]);
    // The 30th frame is the last one any table needs.
    assert_eq!(expected.stats.packets, 30);
    for capacity in [1, 2, 3, 7, 29, 30, 2048] {
        for max_packets in STEP_SIZES {
            let scanned = scan(&capture, &compiled, &registry, Some(capacity), max_packets);
            assert!(
                scanned.rows == expected.rows,
                "capacity {capacity}, {max_packets} packets per step"
            );
            assert_eq!(scanned.last, Step::Done);
            assert_eq!(scanned.stats, expected.stats, "capacity {capacity}");
        }
    }
}

/// A frame with more rows in one table than a sink holds spans several
/// sinks' worth: it is shown to the scan once per sink it fills.
#[test]
fn a_frame_with_more_rows_than_a_sink_holds() {
    let registry = Arc::new(default_registry());
    let plan = full_plan(&TABLES, &registry);
    let frames = vec![udp_frame(0), nested(1, DEEP_TUNNELS), udp_frame(2)];
    for capture in [legacy_capture(&frames), pcapng_capture(&frames)] {
        let expected = scan(&capture, &plan, &registry, None, usize::MAX);
        let lens: Vec<usize> = expected.rows.iter().map(Vec::len).collect();
        let deep = DEEP_TUNNELS + 1;
        assert_eq!(lens, [3, deep + 2, deep + 2, deep + 2, 0, DEEP_TUNNELS]);
        // The tunnelled frame's rows are in layer order: outermost first.
        let depth_column = plan.outputs()[1]
            .columns
            .iter()
            .position(|c| c.name == "encap_depth")
            .unwrap();
        let depths: Vec<Cell> = expected.rows[1]
            .iter()
            .map(|r| r[depth_column].clone())
            .collect();
        let expected_depths: Vec<Cell> = [0]
            .into_iter()
            .chain(0..deep as u8)
            .chain([0])
            .map(Cell::U8)
            .collect();
        assert_eq!(depths, expected_depths);

        for capacity in [1, 2, 3, 4, 6, 7, 8] {
            for max_packets in STEP_SIZES {
                let scanned = scan(&capture, &plan, &registry, Some(capacity), max_packets);
                assert!(
                    scanned.rows == expected.rows,
                    "capacity {capacity}, {max_packets} packets per step"
                );
                assert_eq!(scanned.stats, expected.stats);
            }
        }
    }
}
