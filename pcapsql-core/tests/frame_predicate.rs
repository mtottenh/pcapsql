//! The frame predicate is exact: a scan with a
//! [`FramePredicate`] yields the rows of exactly the packets it accepts,
//! however the capture is partitioned and trimmed.
//!
//! For generated captures (legacy and pcapng, with timestamps that do not
//! ascend), random frame-number and timestamp bounds (inclusive, exclusive,
//! absent; ranges that are empty or inverted included) and random index
//! strides, the properties are:
//!
//! 1. **Exactness.** The rows of a scan with the predicate are the rows of
//!    a scan without it whose frame the predicate accepts, in order, in
//!    every output, at sink capacities 1, 2, 3, 2048 and unbounded. This
//!    holds for the capture read sequentially, for the index's partitions
//!    read one by one, and for the ranges
//!    [`plan_ranges`](pcapsql_core::scan::plan_ranges) leaves.
//! 2. **Trimming is sound.** Every packet the predicate accepts lies in
//!    exactly one planned range; the ranges start and end on checkpoints,
//!    ascend, and are no more than the index would give. With frame bounds
//!    alone it is also tight: a planned range that does not run to the end
//!    of the capture holds an accepted packet.
//! 3. **An upper frame bound stops the reading.** A scan consumes no
//!    packet behind the last frame the bound admits: of a partition
//!    starting at frame `s`, with the inclusive bound `n`, at most
//!    `n - s + 1` packets, and exactly `min(n, frames)` of a whole capture.
//!
//! The expectation is computed here from the generated timestamps with
//! `RangeBounds::contains`, not with the predicate's own code.

mod common;

use std::collections::HashSet;
use std::ops::{Bound, RangeBounds};
use std::sync::{Arc, OnceLock};

use common::{frame_of_kind, index_ranges, reader, reader_at, scan_with, Rows, KINDS};
use pcapsql_core::io::PacketRange;
use pcapsql_core::scan::testing::Cell;
use pcapsql_core::scan::{
    plan_ranges, Catalog, CompiledScan, FramePredicate, ScanPlan, Step, TableScan, TimestampUnit,
};
use pcapsql_core::{default_registry, ProtocolRegistry};
use pcapsql_testgen::{
    legacy_pcap, pcapng, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};
use proptest::prelude::*;

const CAPACITIES: [Option<usize>; 5] = [None, Some(1), Some(2), Some(3), Some(2048)];
const TABLES: [&str; 9] = [
    "frames", "ethernet", "ipv4", "udp", "tcp", "vxlan", "dns", "arp", "icmp",
];
const BASE_SEC: u32 = 1_700_000_000;
/// Timestamps are `BASE_SEC` plus this many microseconds, at most.
const TICKS: u32 = 40;

fn registry() -> &'static Arc<ProtocolRegistry> {
    static REGISTRY: OnceLock<Arc<ProtocolRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Arc::new(default_registry()))
}

/// Every default column of [`TABLES`], for the frames `frames` accepts.
fn compile(frames: FramePredicate) -> Arc<CompiledScan> {
    let catalog = Catalog::builtin();
    let tables = TABLES
        .iter()
        .map(|name| {
            let (id, table) = catalog.table(name).unwrap();
            TableScan::new(id, table.default_columns().map(|(c, _)| c).collect())
        })
        .collect();
    let plan = ScanPlan {
        tables,
        frames,
        timestamps: TimestampUnit::Nanos,
        ..Default::default()
    };
    Arc::new(plan.compile(catalog, registry()).unwrap())
}

fn unfiltered() -> &'static Arc<CompiledScan> {
    static PLAN: OnceLock<Arc<CompiledScan>> = OnceLock::new();
    PLAN.get_or_init(|| compile(FramePredicate::all()))
}

fn tick_ns(tick: i64) -> i64 {
    i64::from(BASE_SEC) * 1_000_000_000 + tick * 1_000
}

#[derive(Debug, Clone)]
struct Capture {
    /// The kind of each frame.
    kinds: Vec<u8>,
    /// The timestamp of each frame, in microseconds after `BASE_SEC`.
    ticks: Vec<u32>,
    pcapng: bool,
}

impl Capture {
    fn len(&self) -> u64 {
        self.kinds.len() as u64
    }

    fn bytes(&self) -> Vec<u8> {
        let frames = self
            .kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| frame_of_kind(i, *kind));
        if self.pcapng {
            let packets = frames
                .zip(&self.ticks)
                .map(|(data, tick)| PcapngPacket {
                    interface_id: 0,
                    ts_sec: u64::from(BASE_SEC),
                    ts_frac_units: u64::from(*tick) * 1_000,
                    origlen: data.len() as u32,
                    data,
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
        } else {
            let packets: Vec<GenPacket> = frames
                .zip(&self.ticks)
                .map(|(data, tick)| GenPacket {
                    ts_sec: BASE_SEC,
                    ts_frac: *tick,
                    origlen: data.len() as u32,
                    data,
                })
                .collect();
            legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
        }
    }

    /// The numbers of the frames `predicate` accepts, by the bounds alone.
    fn accepted(&self, predicate: &FramePredicate) -> Vec<u64> {
        self.ticks
            .iter()
            .enumerate()
            .map(|(i, tick)| (i as u64 + 1, tick_ns(i64::from(*tick))))
            .filter(|(frame, ts)| {
                predicate.frames.contains(frame) && predicate.time_ns.contains(ts)
            })
            .map(|(frame, _)| frame)
            .collect()
    }

    fn time_range(&self, frames: &[u64]) -> Option<(i64, i64)> {
        let ts = |frame: &u64| tick_ns(i64::from(self.ticks[*frame as usize - 1]));
        Some((frames.iter().map(ts).min()?, frames.iter().map(ts).max()?))
    }

    fn ascends(&self) -> bool {
        self.ticks.windows(2).all(|w| w[0] <= w[1])
    }
}

/// Captures of up to `max_frames` frames whose timestamps are either
/// unrelated to the frame order, or drift upwards with jitter (later
/// frames tend to be later, as in a real capture, but neighbours are often
/// out of order): the second kind gives index windows narrow time ranges,
/// so that time bounds do rule windows out.
fn capture(max_frames: usize) -> impl Strategy<Value = Capture> {
    (
        prop::collection::vec((0..KINDS, 0..=TICKS, 0..6u32), 0..max_frames),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(frames, drift, pcapng)| {
            let count = frames.len().max(1) as u32;
            Capture {
                kinds: frames.iter().map(|f| f.0).collect(),
                ticks: frames
                    .iter()
                    .enumerate()
                    .map(|(i, (_, anywhere, jitter))| {
                        if drift {
                            (i as u32 * (TICKS - 5) / count + jitter).min(TICKS)
                        } else {
                            *anywhere
                        }
                    })
                    .collect(),
                pcapng,
            }
        })
}

fn bound<T: Clone + std::fmt::Debug + 'static>(
    values: impl Strategy<Value = T> + Clone + 'static,
) -> impl Strategy<Value = Bound<T>> {
    prop_oneof![
        2 => Just(Bound::Unbounded),
        3 => values.clone().prop_map(Bound::Included),
        3 => values.prop_map(Bound::Excluded),
    ]
}

/// Bounds around the frames and timestamps a capture of up to `max_frames`
/// frames has, and a little beyond on both sides.
fn predicate(max_frames: u64) -> impl Strategy<Value = FramePredicate> {
    let frame = 0..max_frames + 3;
    let time = (-2..i64::from(TICKS) + 3).prop_map(tick_ns);
    (
        bound(frame.clone()),
        bound(frame),
        bound(time.clone()),
        bound(time),
        0..4u8,
    )
        .prop_map(|(lower, upper, earliest, latest, which)| FramePredicate {
            // Half of the predicates bound one of the two only.
            frames: if which == 0 {
                (Bound::Unbounded, Bound::Unbounded)
            } else {
                (lower, upper)
            },
            time_ns: if which == 1 {
                (Bound::Unbounded, Bound::Unbounded)
            } else {
                (earliest, latest)
            },
        })
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

/// The rows of `rows` (of a scan of `plan`) whose frame is in `frames`.
fn rows_of_frames(plan: &CompiledScan, rows: &Rows, frames: &[u64]) -> Rows {
    let frames: HashSet<u64> = frames.iter().copied().collect();
    plan.outputs()
        .iter()
        .zip(rows)
        .map(|(output, rows)| {
            let column = output
                .columns
                .iter()
                .position(|c| c.name == "frame_number")
                .expect("every per-packet table has a frame_number");
            rows.iter()
                .filter(|row| match &row[column] {
                    Cell::U64(frame) => frames.contains(frame),
                    other => panic!("frame_number is {other:?}"),
                })
                .cloned()
                .collect()
        })
        .collect()
}

/// The last frame number the upper frame bound admits; `None` without one.
fn last_admitted(predicate: &FramePredicate) -> Option<u64> {
    match predicate.frames.1 {
        Bound::Unbounded => None,
        Bound::Included(n) => Some(n),
        Bound::Excluded(n) => Some(n.saturating_sub(1)),
    }
}

fn assert_rows(got: &Rows, want: &Rows, what: &str) {
    for (output, (got, want)) in got.iter().zip(want).enumerate() {
        assert!(
            got == want,
            "{what}: {} has {} rows, the filtered scan {}{}",
            TABLES[output],
            got.len(),
            want.len(),
            match got.iter().zip(want).position(|(g, w)| g != w) {
                Some(row) => format!("; first difference in row {row}"),
                None => String::new(),
            }
        );
    }
}

/// What scanning `ranges` one after the other gave.
struct Partitioned {
    rows: Rows,
    packets: u64,
    skipped: u64,
    time_range: Option<(i64, i64)>,
}

/// Scan each of `ranges` with `plan` and concatenate, checking per range
/// that the upper frame bound stopped the reading (property 3).
fn scan_ranges(
    bytes: &[u8],
    header: &pcapsql_core::io::StreamHeader,
    index: &pcapsql_core::io::BoundaryIndex,
    ranges: &[PacketRange],
    plan: &Arc<CompiledScan>,
    capacity: Option<usize>,
    sizes: &[usize],
) -> Partitioned {
    let mut all = Partitioned {
        rows: vec![Vec::new(); plan.outputs().len()],
        packets: 0,
        skipped: 0,
        time_range: None,
    };
    for range in ranges {
        let scanned = scan_with(
            reader_at(bytes, header, index, range),
            plan,
            registry(),
            capacity,
            cycled(sizes),
        );
        assert_eq!(scanned.last, Step::End);
        if let Some(last) = last_admitted(plan.frames()) {
            let most = (last + 1).saturating_sub(range.start.frame_number);
            assert!(
                scanned.stats.packets <= most,
                "{} packets consumed from frame {} on, with frames up to {last} wanted",
                scanned.stats.packets,
                range.start.frame_number
            );
        }
        all.packets += scanned.stats.packets;
        all.skipped += scanned.stats.skipped;
        if let Some((min, max)) = scanned.stats.time_range_ns() {
            all.time_range = Some(match all.time_range {
                Some((lo, hi)) => (lo.min(min), hi.max(max)),
                None => (min, max),
            });
        }
        for (all, part) in all.rows.iter_mut().zip(scanned.rows) {
            all.extend(part);
        }
    }
    all
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Properties 1 and 3, sequentially.
    #[test]
    fn a_scan_with_the_predicate_is_the_scan_filtered_afterwards(
        capture in capture(60),
        predicate in predicate(60),
        sizes in step_sizes(),
    ) {
        let bytes = capture.bytes();
        let everything = scan_with(reader(&bytes), unfiltered(), registry(), None, || usize::MAX);
        prop_assert_eq!(everything.rows[0].len() as u64, capture.len());
        prop_assert_eq!(everything.stats.skipped, 0);

        let accepted = capture.accepted(&predicate);
        let expected = rows_of_frames(unfiltered(), &everything.rows, &accepted);
        prop_assert_eq!(expected[0].len(), accepted.len());
        // What a scan of the whole capture reads: up to the last frame the
        // upper frame bound admits, and nothing when nothing can match.
        let consumed = if predicate.is_empty() {
            0
        } else {
            last_admitted(&predicate).map_or(capture.len(), |last| last.min(capture.len()))
        };
        prop_assert!(accepted.last().is_none_or(|frame| *frame <= consumed));

        let plan = compile(predicate.clone());
        for capacity in CAPACITIES {
            let scanned = scan_with(reader(&bytes), &plan, registry(), capacity, cycled(&sizes));
            assert_rows(&scanned.rows, &expected, &format!("capacity {capacity:?}"));
            prop_assert_eq!(scanned.last, Step::End);
            prop_assert_eq!(scanned.stats.packets, consumed);
            prop_assert_eq!(scanned.stats.skipped, consumed - accepted.len() as u64);
            prop_assert_eq!(scanned.stats.time_range_ns(), capture.time_range(&accepted));
        }
    }

    /// Properties 1, 2 and 3 over partitions: the index's, and those
    /// `plan_ranges` leaves of them.
    #[test]
    fn planned_ranges_hold_every_accepted_packet_and_scan_to_the_same_rows(
        capture in capture(120),
        predicate in predicate(120),
        stride in 1u64..12,
        want in 1usize..8,
        capacity in prop::sample::select(CAPACITIES.to_vec()),
        sizes in step_sizes(),
    ) {
        let bytes = capture.bytes();
        let everything = scan_with(reader(&bytes), unfiltered(), registry(), None, || usize::MAX);
        let accepted = capture.accepted(&predicate);
        let expected = rows_of_frames(unfiltered(), &everything.rows, &accepted);

        let (header, index, untrimmed) = index_ranges(&bytes, stride, want);
        prop_assert_eq!(&plan_ranges(Some(&index), want, &FramePredicate::all()), &untrimmed);
        let planned = plan_ranges(Some(&index), want, &predicate);

        // Property 2: sound.
        for frame in &accepted {
            let holding = planned.iter().filter(|r| r.contains(*frame)).count();
            prop_assert_eq!(holding, 1, "frame {} is in {} of {:?}", frame, holding, &planned);
        }
        // Well formed: on checkpoints, ascending, no more than untrimmed.
        prop_assert!(planned.len() <= untrimmed.len());
        let mut previous_end = Some(0);
        for range in &planned {
            if *range != PacketRange::whole() {
                let start = index.checkpoint_at(range.start.frame_number);
                prop_assert_eq!(start.map(|c| c.byte_offset), Some(range.start.byte_offset));
            }
            prop_assert!(previous_end.is_some_and(|end| end <= range.start.frame_number));
            previous_end = range.end.as_ref().map(|e| e.frame_number);
            if let Some(end) = &range.end {
                prop_assert!(end.frame_number > range.start.frame_number);
                let checkpoint = index.checkpoint_at(end.frame_number);
                prop_assert_eq!(checkpoint.map(|c| c.byte_offset), Some(end.byte_offset));
                // Tight, for frame bounds: the range is there for a packet.
                if predicate.time_ns == FramePredicate::all().time_ns {
                    prop_assert!(
                        accepted.iter().any(|frame| range.contains(*frame)),
                        "{:?} holds no accepted frame", range
                    );
                }
            }
        }

        // Property 1, and 3 inside `scan_ranges`.
        let plan = compile(predicate.clone());
        let whole = scan_ranges(&bytes, &header, &index, &untrimmed, &plan, capacity, &sizes);
        assert_rows(&whole.rows, &expected, "the index's partitions");
        let trimmed = scan_ranges(&bytes, &header, &index, &planned, &plan, capacity, &sizes);
        assert_rows(&trimmed.rows, &expected, "the planned ranges");
        for scanned in [&whole, &trimmed] {
            prop_assert_eq!(scanned.packets - scanned.skipped, accepted.len() as u64);
            prop_assert_eq!(scanned.time_range, capture.time_range(&accepted));
        }
        // Trimming only ever saves reading.
        prop_assert!(trimmed.packets <= whole.packets);
        prop_assert!(whole.packets <= capture.len());
    }
}

/// The properties are not vacuous: the generated timestamps do not ascend,
/// a time bound does rule ranges out, and a frame bound does stop a scan
/// short of the end of the capture.
#[test]
fn a_time_bound_trims_a_capture_whose_timestamps_do_not_ascend() {
    let frames = 120u32;
    let capture = Capture {
        kinds: (0..frames).map(|i| (i % u32::from(KINDS)) as u8).collect(),
        // Drifting upwards, each pair of neighbours swapped.
        ticks: (0..frames).map(|i| (i ^ 1) * TICKS / frames).collect(),
        pcapng: true,
    };
    assert!(!capture.ascends());
    let bytes = capture.bytes();
    let everything = scan_with(reader(&bytes), unfiltered(), registry(), None, || {
        usize::MAX
    });

    let (header, index, untrimmed) = index_ranges(&bytes, 10, 4);
    assert_eq!(untrimmed.len(), 4);
    let predicate = FramePredicate {
        time_ns: (Bound::Included(tick_ns(12)), Bound::Excluded(tick_ns(15))),
        ..FramePredicate::all()
    };
    let accepted = capture.accepted(&predicate);
    assert!(!accepted.is_empty() && accepted.len() < 20);
    let expected = rows_of_frames(unfiltered(), &everything.rows, &accepted);

    let planned = plan_ranges(Some(&index), 4, &predicate);
    // The range of the matching windows, and the last window of the
    // capture, which a time bound never rules out.
    assert_eq!(planned.len(), 2, "{planned:?}");
    assert!(accepted.iter().all(|frame| planned[0].contains(*frame)));
    assert_eq!(planned[1].start.frame_number, 111);
    assert_eq!(planned[1].end, None);

    let plan = compile(predicate.clone());
    let trimmed = scan_ranges(&bytes, &header, &index, &planned, &plan, Some(3), &[7]);
    assert_rows(&trimmed.rows, &expected, "the planned ranges");
    assert!(trimmed.packets <= 30, "{} packets read", trimmed.packets);
    let whole = scan_ranges(&bytes, &header, &index, &untrimmed, &plan, Some(3), &[7]);
    assert_rows(&whole.rows, &expected, "the index's partitions");
    // A time bound alone never ends a scan.
    assert_eq!(whole.packets, u64::from(frames));

    // A frame bound ends it: frames 31 to 45 of the range starting at 31.
    let predicate = FramePredicate {
        frames: (Bound::Excluded(33), Bound::Included(45)),
        ..FramePredicate::all()
    };
    let planned = plan_ranges(Some(&index), 4, &predicate);
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].start.frame_number, 31);
    assert_eq!(planned[0].end.as_ref().map(|e| e.frame_number), Some(51));
    let plan = compile(predicate.clone());
    let trimmed = scan_ranges(
        &bytes,
        &header,
        &index,
        &planned,
        &plan,
        None,
        &[usize::MAX],
    );
    let accepted = capture.accepted(&predicate);
    assert_eq!(accepted, (34..=45).collect::<Vec<u64>>());
    assert_rows(
        &trimmed.rows,
        &rows_of_frames(unfiltered(), &everything.rows, &accepted),
        "frames 34 to 45",
    );
    assert_eq!((trimmed.packets, trimmed.skipped), (15, 3));
}
