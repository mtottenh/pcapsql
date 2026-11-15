//! Fused joins: the joined rows of a frame, written by the scan itself.
//!
//! Properties, over generated captures with plain, tunnelled and deeply
//! tunnelled frames (legacy and pcapng):
//!
//! 1. **A fused join is the join.** The rows of every `*_packets` view
//!    ([`PacketsView`]), and of joins made up here to have several matches
//!    and none, equal the join computed the slow way from the rows of the
//!    tables it names: nested loops over the tables' rows on `frame_number`
//!    and `encap_depth`, with the view's computed columns and filter
//!    evaluated on the joined cells. Same rows, same order, NULLs included.
//! 2. **Sinks of any size.** Scanned into sinks of capacity 1, 2, 3, 7 and
//!    2048 with any number of packets per step, a fused output yields the
//!    rows of an unbounded scan, in order; a frame with more joined rows
//!    than a sink holds spans several flushes.
//! 3. **Partitions.** The partitions of a capture, scanned one by one and
//!    concatenated, equal the sequential scan.
//! 4. **Row caps and frame predicates** apply to a fused output as to a
//!    table.

mod common;

use std::collections::HashMap;
use std::ops::Bound;
use std::sync::Arc;

use common::{
    frame_of_kind, index_ranges, legacy_capture, pcapng_capture, reader_at, scan, scan_with, Rows,
    KINDS,
};
use pcapsql_core::scan::testing::Cell;
use pcapsql_core::scan::{
    Catalog, ColId, CompiledScan, FramePredicate, FusedColumn, FusedFilter, FusedMember, FusedScan,
    FusedValue, JoinKind, MemberJoin, PacketsView, ScanPlan, Step, TableScan, TimestampUnit,
};
use pcapsql_core::{default_registry, ProtocolRegistry};

const N_FRAMES: usize = 4 * KINDS as usize * 5 + 3;
const CAPACITIES: [usize; 5] = [1, 2, 3, 7, 2048];
const STEP_SIZES: [usize; 3] = [1, 5, usize::MAX];

/// Frames of every kind `common` has: UDP, TCP, DNS, ARP and ICMP, plain
/// and inside one, two and six VXLAN tunnels.
fn frames() -> Vec<Vec<u8>> {
    (0..N_FRAMES)
        .map(|i| frame_of_kind(i, (i % KINDS as usize) as u8))
        .collect()
}

fn captures() -> [(&'static str, Vec<u8>); 2] {
    let frames = frames();
    [
        ("pcap", legacy_capture(&frames)),
        ("pcapng", pcapng_capture(&frames)),
    ]
}

/// A join for the tests: its members by table name, and its scan.
struct Join {
    name: String,
    tables: Vec<&'static str>,
    scan: FusedScan,
}

impl Join {
    fn of_view(view: &PacketsView) -> Self {
        Self {
            name: view.name.to_owned(),
            tables: view.members().iter().map(|m| m.table).collect(),
            scan: view.full_scan(),
        }
    }
}

fn table_id(name: &str) -> pcapsql_core::scan::TableId {
    Catalog::builtin().table(name).unwrap().0
}

fn column(table: &str, name: &str) -> ColId {
    let (_, def) = Catalog::builtin().table(table).unwrap();
    def.column(name)
        .unwrap_or_else(|| panic!("{table}.{name}"))
        .0
}

fn join(kind: JoinKind, with: usize, depth: bool) -> Option<MemberJoin> {
    Some(MemberJoin { kind, with, depth })
}

/// Joins no view has: several matches per row, a join between levels, a
/// left join that never matches, a filter on a left-joined member.
fn made_up_joins() -> Vec<Join> {
    let members = |tables: &[(&'static str, Option<MemberJoin>)]| -> Vec<FusedMember> {
        tables
            .iter()
            .map(|(table, join)| FusedMember {
                table: table_id(table),
                join: *join,
            })
            .collect()
    };
    let col =
        |member: u16, table: &str, name: &str| FusedColumn::from((member, column(table, name)));
    vec![
        // Every ipv4 header of the frame beside every udp header: a
        // six-fold tunnel has 7 x 7 rows.
        Join {
            name: "udp x ipv4 on the frame".to_owned(),
            tables: vec!["udp", "ipv4"],
            scan: FusedScan {
                members: members(&[("udp", None), ("ipv4", join(JoinKind::Inner, 0, false))]),
                columns: vec![
                    col(0, "udp", "frame_number"),
                    col(0, "udp", "encap_depth"),
                    col(0, "udp", "dst_port"),
                    col(1, "ipv4", "encap_depth"),
                    col(1, "ipv4", "identification"),
                ],
                filter: None,
                fetch: None,
            },
        },
        // A root that is not `frames`, a chain (vxlan joins udp, tcp joins
        // ethernet), a left join without a match on most rows, and a
        // member without an output column.
        Join {
            name: "ethernet chain".to_owned(),
            tables: vec!["ethernet", "udp", "vxlan", "tcp", "frames"],
            scan: FusedScan {
                members: members(&[
                    ("ethernet", None),
                    ("udp", join(JoinKind::Left, 0, true)),
                    ("vxlan", join(JoinKind::Left, 1, true)),
                    ("tcp", join(JoinKind::Left, 0, true)),
                    ("frames", join(JoinKind::Inner, 0, false)),
                ]),
                columns: vec![
                    col(4, "frames", "timestamp"),
                    col(4, "frames", "length"),
                    col(0, "ethernet", "frame_number"),
                    col(0, "ethernet", "encap_depth"),
                    col(0, "ethernet", "src_mac"),
                    col(1, "udp", "dst_port"),
                    col(2, "vxlan", "vni"),
                    col(2, "vxlan", "tunnel_id"),
                    FusedColumn {
                        name: Some("port"),
                        value: FusedValue::Coalesce(vec![
                            (3, column("tcp", "dst_port")),
                            (1, column("udp", "dst_port")),
                        ]),
                    },
                    FusedColumn {
                        name: Some("what"),
                        value: FusedValue::Present {
                            cases: vec![(2, "tunnel"), (3, "tcp"), (1, "udp")],
                            otherwise: "other",
                        },
                    },
                ],
                filter: None,
                fetch: None,
            },
        },
        // A filter on a left-joined member: the rows without it go, as
        // `WHERE udp.dst_port IN (...)` drops a NULL.
        Join {
            name: "filtered".to_owned(),
            tables: vec!["frames", "ipv4", "udp"],
            scan: FusedScan {
                members: members(&[
                    ("frames", None),
                    ("ipv4", join(JoinKind::Inner, 0, false)),
                    ("udp", join(JoinKind::Left, 1, true)),
                ]),
                columns: vec![
                    col(0, "frames", "frame_number"),
                    col(1, "ipv4", "encap_depth"),
                    col(2, "udp", "src_port"),
                ],
                filter: Some(FusedFilter {
                    member: 2,
                    column: column("udp", "dst_port"),
                    any_of: vec![4789, 53],
                }),
                fetch: None,
            },
        },
    ]
}

fn every_join() -> Vec<Join> {
    PacketsView::all()
        .iter()
        .map(Join::of_view)
        .chain(made_up_joins())
        .collect()
}

/// A plan of `tables` with every column each has, then `joins`.
fn plan(
    tables: &[&str],
    joins: &[FusedScan],
    frames: FramePredicate,
    registry: &ProtocolRegistry,
) -> Arc<CompiledScan> {
    let catalog = Catalog::builtin();
    let plan = ScanPlan {
        tables: tables
            .iter()
            .map(|name| {
                let (id, table) = catalog.table(name).unwrap();
                TableScan::new(id, table.columns().map(|(c, _)| c).collect())
            })
            .collect(),
        fused: joins.to_vec(),
        frames,
        timestamps: TimestampUnit::Nanos,
        ..ScanPlan::default()
    };
    Arc::new(plan.compile(catalog, registry).unwrap())
}

/// The rows of one table, by frame.
struct TableRows<'a> {
    by_frame: HashMap<u64, Vec<&'a Vec<Cell>>>,
    depth: Option<usize>,
}

impl<'a> TableRows<'a> {
    fn new(table: &str, rows: &'a [Vec<Cell>]) -> Self {
        let (_, def) = Catalog::builtin().table(table).unwrap();
        let position = |name: &str| def.column(name).map(|(id, _)| usize::from(id.0));
        let frame_number = position("frame_number").unwrap();
        let mut by_frame: HashMap<u64, Vec<&Vec<Cell>>> = HashMap::new();
        for row in rows {
            let Cell::U64(frame) = row[frame_number] else {
                panic!("{table}.frame_number is {:?}", row[frame_number]);
            };
            by_frame.entry(frame).or_default().push(row);
        }
        Self {
            by_frame,
            depth: position("encap_depth"),
        }
    }
}

/// The join of `join`, computed from the tables' rows: nested loops in
/// member order.
fn reference(
    join: &Join,
    tables: &HashMap<&str, &[Vec<Cell>]>,
    frame_count: u64,
) -> Vec<Vec<Cell>> {
    let members: Vec<TableRows<'_>> = join
        .tables
        .iter()
        .map(|table| TableRows::new(table, tables[table]))
        .collect();
    let scan = &join.scan;
    let cell = |tuple: &[Option<&Vec<Cell>>], member: u16, column: ColId| -> Cell {
        match tuple[usize::from(member)] {
            Some(row) => row[usize::from(column.0)].clone(),
            None => Cell::Null,
        }
    };
    let mut out = Vec::new();
    for frame in 1..=frame_count {
        let rows_of = |m: usize| members[m].by_frame.get(&frame).cloned().unwrap_or_default();
        let mut tuples: Vec<Vec<Option<&Vec<Cell>>>> =
            rows_of(0).into_iter().map(|row| vec![Some(row)]).collect();
        for (m, member) in scan.members.iter().enumerate().skip(1) {
            let on = member.join.unwrap();
            let candidates = rows_of(m);
            let mut next = Vec::new();
            for tuple in tuples {
                let matches: Vec<&Vec<Cell>> = match tuple[on.with] {
                    None => Vec::new(),
                    Some(anchor) => candidates
                        .iter()
                        .copied()
                        .filter(|candidate| {
                            if !on.depth {
                                return true;
                            }
                            // `frames` has no depth: NULL = NULL is not true.
                            match (members[on.with].depth, members[m].depth) {
                                (Some(a), Some(c)) => anchor[a] == candidate[c],
                                _ => false,
                            }
                        })
                        .collect(),
                };
                if matches.is_empty() {
                    if on.kind == JoinKind::Left {
                        let mut tuple = tuple.clone();
                        tuple.push(None);
                        next.push(tuple);
                    }
                    continue;
                }
                for row in matches {
                    let mut tuple = tuple.clone();
                    tuple.push(Some(row));
                    next.push(tuple);
                }
            }
            tuples = next;
        }
        for tuple in tuples {
            if let Some(filter) = &scan.filter {
                let keep = match cell(&tuple, filter.member, filter.column) {
                    Cell::U8(v) => filter.any_of.contains(&i64::from(v)),
                    Cell::U16(v) => filter.any_of.contains(&i64::from(v)),
                    Cell::U32(v) => filter.any_of.contains(&i64::from(v)),
                    Cell::Null => false,
                    other => panic!("a filter on {other:?}"),
                };
                if !keep {
                    continue;
                }
            }
            out.push(
                scan.columns
                    .iter()
                    .map(|column| match &column.value {
                        FusedValue::Column { member, column } => cell(&tuple, *member, *column),
                        FusedValue::Coalesce(arguments) => arguments
                            .iter()
                            .map(|(member, column)| cell(&tuple, *member, *column))
                            .find(|cell| *cell != Cell::Null)
                            .unwrap_or(Cell::Null),
                        FusedValue::Present { cases, otherwise } => Cell::Str(
                            cases
                                .iter()
                                .find(|(member, _)| tuple[usize::from(*member)].is_some())
                                .map_or(*otherwise, |(_, label)| *label)
                                .to_owned(),
                        ),
                    })
                    .collect(),
            );
        }
    }
    out
}

/// The tables the joins name, each once.
fn tables_of(joins: &[Join]) -> Vec<&'static str> {
    let mut tables: Vec<&str> = joins
        .iter()
        .flat_map(|j| j.tables.iter().copied())
        .collect();
    tables.sort_unstable();
    tables.dedup();
    tables
}

#[test]
fn a_fused_join_is_the_join_of_its_tables() {
    let registry = Arc::new(default_registry());
    let joins = every_join();
    let tables = tables_of(&joins);
    let scans: Vec<FusedScan> = joins.iter().map(|j| j.scan.clone()).collect();
    let plan = plan(&tables, &scans, FramePredicate::all(), &registry);
    for (format, capture) in captures() {
        let scanned = scan(&capture, &plan, &registry, None, usize::MAX);
        assert_eq!(scanned.last, Step::End, "{format}");
        let by_table: HashMap<&str, &[Vec<Cell>]> = tables
            .iter()
            .copied()
            .zip(scanned.rows.iter().map(Vec::as_slice))
            .collect();
        let mut with_rows = 0;
        for (join, rows) in joins.iter().zip(&scanned.rows[tables.len()..]) {
            let expected = reference(join, &by_table, N_FRAMES as u64);
            assert_eq!(rows.len(), expected.len(), "{format}: {}", join.name);
            for (n, (got, want)) in rows.iter().zip(&expected).enumerate() {
                assert_eq!(got, want, "{format}: {} row {n}", join.name);
            }
            with_rows += usize::from(!rows.is_empty());
        }
        // The capture has rows for the views of the protocols it holds and
        // for every made-up join; the other views are empty, as their
        // joins are.
        let rows = |name: &str| {
            let index = joins.iter().position(|j| j.name == name).unwrap();
            scanned.rows[tables.len() + index].len()
        };
        let table_rows = |name: &str| by_table[name].len();
        for anchor in ["tcp", "udp", "dns", "arp", "icmp", "vxlan"] {
            assert_eq!(
                rows(&format!("{anchor}_packets")),
                table_rows(anchor),
                "{anchor}"
            );
            assert!(table_rows(anchor) > 0, "{anchor}");
        }
        assert!(with_rows >= 9, "{format}: {with_rows} joins have rows");
        // A six-fold tunnel: 7 udp headers, each beside 7 ipv4 headers.
        assert!(rows("udp x ipv4 on the frame") > table_rows("udp") * 2);
        assert!(rows("filtered") > 0 && rows("filtered") < table_rows("ipv4"));
    }
}

#[test]
fn any_capacity_yields_the_rows_of_an_unbounded_scan() {
    let registry = Arc::new(default_registry());
    let joins = every_join();
    let scans: Vec<FusedScan> = joins.iter().map(|j| j.scan.clone()).collect();
    // Two tables beside the joins: a sink of each kind fills in one frame.
    let plan = plan(&["frames", "udp"], &scans, FramePredicate::all(), &registry);
    for (format, capture) in captures() {
        let expected = scan(&capture, &plan, &registry, None, usize::MAX);
        assert_eq!(expected.flushes, 0, "{format}");
        for capacity in CAPACITIES {
            for step in STEP_SIZES {
                let got = scan(&capture, &plan, &registry, Some(capacity), step);
                assert_eq!(got.last, Step::End, "{format} {capacity} {step}");
                assert_eq!(got.stats.packets, expected.stats.packets);
                for (output, (got, want)) in got.rows.iter().zip(&expected.rows).enumerate() {
                    assert!(
                        got == want,
                        "{format}: output {output} differs at capacity {capacity}, \
                         {step} packets per step: {} rows for {}",
                        got.len(),
                        want.len()
                    );
                }
                if capacity == 1 {
                    // Every row but the last of an output is handed out by
                    // a flush.
                    let rows: usize = expected.rows.iter().map(Vec::len).sum();
                    assert!(got.flushes >= rows - expected.rows.len(), "{format}");
                }
            }
        }
    }
}

#[test]
fn partitions_concatenate_to_the_sequential_scan() {
    let registry = Arc::new(default_registry());
    let joins = every_join();
    let scans: Vec<FusedScan> = joins.iter().map(|j| j.scan.clone()).collect();
    let plan = plan(&[], &scans, FramePredicate::all(), &registry);
    for (format, capture) in captures() {
        let expected = scan(&capture, &plan, &registry, None, usize::MAX);
        for (stride, partitions, capacity) in [(1, 7, Some(2)), (16, 4, None), (5, 3, Some(1))] {
            let (header, index, ranges) = index_ranges(&capture, stride, partitions);
            assert!(ranges.len() > 1, "{format}: {stride} {partitions}");
            let mut rows: Rows = vec![Vec::new(); expected.rows.len()];
            for range in &ranges {
                let part = scan_with(
                    reader_at(&capture, &header, &index, range),
                    &plan,
                    &registry,
                    capacity,
                    || 3,
                );
                assert_eq!(part.last, Step::End);
                for (all, part) in rows.iter_mut().zip(part.rows) {
                    all.extend(part);
                }
            }
            assert!(rows == expected.rows, "{format}: {stride} {partitions}");
        }
    }
}

#[test]
fn a_row_cap_and_a_frame_predicate_apply_to_a_fused_output() {
    let registry = Arc::new(default_registry());
    let view = PacketsView::get("udp_packets").unwrap();
    let all = plan(&[], &[view.full_scan()], FramePredicate::all(), &registry);
    let (_, capture) = captures().into_iter().next().unwrap();
    let expected = scan(&capture, &all, &registry, None, usize::MAX)
        .rows
        .remove(0);
    let frame_of = |row: &Vec<Cell>| match row[0] {
        Cell::U64(frame) => frame,
        ref other => panic!("frame_number is {other:?}"),
    };

    // A row cap that ends inside a frame with several rows (frame 6 is a
    // six-fold tunnel): exactly that many rows, and the scan stops there.
    for cap in [1, 9, 10, 11, 40] {
        let capped = FusedScan {
            fetch: Some(cap),
            ..view.full_scan()
        };
        let plan = plan(&[], &[capped], FramePredicate::all(), &registry);
        for capacity in [None, Some(1), Some(4)] {
            let got = scan(&capture, &plan, &registry, capacity, usize::MAX);
            assert_eq!(got.last, Step::Done, "{cap} {capacity:?}");
            assert_eq!(got.rows[0], expected[..cap as usize], "{cap} {capacity:?}");
            // Not a frame further than the row that filled the cap.
            let last = frame_of(&expected[cap as usize - 1]);
            assert_eq!(got.stats.packets, last, "{cap} {capacity:?}");
        }
    }

    // A frame range: the rows of those frames, and no frame behind the
    // range is read.
    let frames = FramePredicate {
        frames: (Bound::Included(5), Bound::Excluded(25)),
        ..FramePredicate::all()
    };
    let ranged = plan(&[], &[view.full_scan()], frames, &registry);
    for capacity in [None, Some(1), Some(3)] {
        let got = scan(&capture, &ranged, &registry, capacity, usize::MAX);
        let want: Vec<&Vec<Cell>> = expected
            .iter()
            .filter(|row| (5..25).contains(&frame_of(row)))
            .collect();
        assert!(!want.is_empty());
        assert_eq!(got.rows[0].iter().collect::<Vec<_>>(), want, "{capacity:?}");
        assert_eq!(got.stats.packets, 24, "{capacity:?}");
        assert_eq!(got.stats.skipped, 4, "{capacity:?}");
    }
}
