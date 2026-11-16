//! Partition planning: how many partitions to split a capture into, and a
//! queue that hands them to workers.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! Splitting a capture costs a boundary index (a header-only scan, and a
//! sidecar write) and one reader per partition, so it only pays off above a
//! size that depends on what starting a reader costs
//! ([`SeekCost`]). [`partition_target`] is that decision; the ranges
//! themselves come from the index
//! ([`BoundaryIndex::partition_ranges`]), less what the plan's frame
//! predicate rules out ([`plan_ranges`]).

use std::sync::atomic::{AtomicUsize, Ordering};

use super::predicate::FramePredicate;
use crate::io::{BoundaryIndex, Checkpoint, PacketPosition, PacketRange, SeekCost};

/// The sizes below which a capture is read as one partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionPolicy {
    /// For a [`SeekCost::Free`] source (a memory map), and only when the
    /// caller did not ask for a partition count: an index build, a sidecar
    /// and a thread per partition cost more than they save below this.
    pub free_min_bytes: u64,
    /// For a [`SeekCost::Cheap`] source (a local seek).
    pub cheap_min_bytes: u64,
    /// For a [`SeekCost::RangeRequest`] source: the network round trips
    /// must be amortized.
    pub range_min_bytes: u64,
}

impl Default for PartitionPolicy {
    /// 1 MiB, 4 MiB and 16 MiB.
    fn default() -> Self {
        Self {
            free_min_bytes: 1024 * 1024,
            cheap_min_bytes: 4 * 1024 * 1024,
            range_min_bytes: 16 * 1024 * 1024,
        }
    }
}

/// How many partitions to ask the boundary index for; 1 means: do not
/// partition (and do not build an index).
///
/// `size_bytes` is the size of the capture (0 when unknown, which never
/// reaches a threshold). `requested` is a partition count the caller asked
/// for; `None` leaves it to `parallelism`, the number of workers available.
///
/// - A [`SeekCost::Free`] source is split as asked. Left to itself, it is
///   split `parallelism` ways from [`PartitionPolicy::free_min_bytes`] on.
/// - A [`SeekCost::Cheap`] or [`SeekCost::RangeRequest`] source is split
///   (as requested, or `parallelism` ways) from its threshold on, and not
///   at all below it, whatever was requested.
///
/// The result is at least 1. The index may give fewer ranges than asked
/// for (it has a range per checkpoint at most).
pub fn partition_target(
    cost: SeekCost,
    size_bytes: u64,
    requested: Option<usize>,
    parallelism: usize,
    policy: &PartitionPolicy,
) -> usize {
    let target = match requested {
        Some(count) => count,
        None if cost == SeekCost::Free && size_bytes < policy.free_min_bytes => 1,
        None => parallelism,
    }
    .max(1);
    let worth_it = match cost {
        SeekCost::Free => true,
        SeekCost::Cheap => size_bytes >= policy.cheap_min_bytes,
        SeekCost::RangeRequest => size_bytes >= policy.range_min_bytes,
    };
    if worth_it {
        target
    } else {
        1
    }
}

/// The ranges to scan for a plan whose frame predicate is `frames`: the
/// index's partition ranges
/// ([`BoundaryIndex::partition_ranges`]`(want)`), each shrunk to the part
/// that can hold a matching packet, and left out when no part can. They
/// are in capture order and do not overlap. The result is empty when no
/// packet of the capture can match.
///
/// Trimming only saves reading. The scan driver applies the predicate to
/// every packet it reads, so the rows are those of the untrimmed ranges as
/// long as no matching packet is left out, and none is:
///
/// - The index has a checkpoint every `stride` frames; the *window* of a
///   checkpoint is the frames from it up to the next checkpoint (to the
///   end of the capture for the last). A window is ruled out by the frame
///   bounds exactly (its frame numbers are known), and by the time bounds
///   when the smallest and largest timestamp the index recorded for it
///   show that none of its packets is inside them. Timestamps need not
///   ascend, so every window is tested on its own.
/// - The **last window** of the capture is ruled out by the upper frame
///   bound only. The index describes the packets that were there when it
///   was built, and a range to the end of the capture also delivers packets
///   appended since: nothing is known of their timestamps, nor of how many
///   there are.
/// - A window whose timestamps the index does not have is kept.
///
/// A range is shrunk to run from its first window that may match to its
/// last one. It therefore still starts and ends on checkpoints, as a
/// partition reader needs (the reader finds the capture's interface state
/// at the checkpoint it starts on). Windows ruled out *between* two that
/// may match stay inside the range: their packets are read and rejected by
/// the driver, unparsed. A range is never split, so there are at most as
/// many ranges as the index would give for `want`, and fewer workers than
/// `want` may find work when the predicate is narrow.
///
/// With a predicate that accepts [all](FramePredicate::all) packets the
/// result is `partition_ranges(want)` unchanged. Without an index it is
/// the one [whole](PacketRange::whole) range a caller reads a capture it
/// cannot split with, whatever the predicate (the driver ends such a scan
/// at the upper frame bound).
pub fn plan_ranges(
    index: Option<&BoundaryIndex>,
    want: usize,
    frames: &FramePredicate,
) -> Vec<PacketRange> {
    let Some(index) = index else {
        return vec![PacketRange::whole()];
    };
    let ranges = index.partition_ranges(want);
    if frames.is_all() {
        return ranges;
    }
    if frames.is_empty() {
        return Vec::new();
    }
    ranges
        .into_iter()
        .filter_map(|range| trim(index, range, frames))
        .collect()
}

/// `range` shrunk to its windows that may hold a packet `frames` accepts;
/// `None` when none may.
fn trim(index: &BoundaryIndex, range: PacketRange, frames: &FramePredicate) -> Option<PacketRange> {
    let checkpoints = &index.checkpoints;
    let at = |frame: u64| {
        checkpoints
            .binary_search_by_key(&frame, |c| c.frame_number)
            .ok()
    };
    // The range's windows are those of `checkpoints[first..end]`.
    let first = at(range.start.frame_number);
    let end = match &range.end {
        Some(end) => at(end.frame_number),
        None => Some(checkpoints.len()),
    };
    let (Some(first), Some(end)) = (first, end) else {
        // Not a range of this index (an index without checkpoints gives
        // the whole capture): it can only be taken or left as it is.
        return frames.may_overlap(&range, None).then_some(range);
    };
    let position = |checkpoint: &Checkpoint| PacketPosition {
        byte_offset: checkpoint.byte_offset,
        frame_number: checkpoint.frame_number,
    };
    let window = |i: usize| PacketRange {
        start: position(&checkpoints[i]),
        end: checkpoints.get(i + 1).map(position),
    };
    let may_match = |i: usize| {
        let checkpoint = &checkpoints[i];
        // The last window may have grown since the index was built.
        let time_ns = match (checkpoint.min_ts, checkpoint.max_ts) {
            (Some(min), Some(max)) if i + 1 < checkpoints.len() => Some((min, max)),
            _ => None,
        };
        frames.may_overlap(&window(i), time_ns)
    };
    let from = (first..end).find(|i| may_match(*i))?;
    let to = (from..end).rfind(|i| may_match(*i))?;
    Some(PacketRange {
        start: position(&checkpoints[from]),
        // The range's own end when its last window is kept, which is `None`
        // for the range that runs to the end of the capture.
        end: if to + 1 == end {
            range.end
        } else {
            Some(position(&checkpoints[to + 1]))
        },
    })
}

/// The partitions of one scan, claimed one at a time by any number of
/// workers: what an engine that pulls (each worker asks for its next piece
/// of work) uses in place of a thread per partition.
#[derive(Debug)]
pub struct PartitionQueue {
    ranges: Box<[PacketRange]>,
    next: AtomicUsize,
}

impl PartitionQueue {
    /// A queue of `ranges`, in capture order.
    pub fn new(ranges: Vec<PacketRange>) -> Self {
        Self {
            ranges: ranges.into(),
            next: AtomicUsize::new(0),
        }
    }

    /// The next unclaimed partition and its ordinal, or `None` when all are
    /// claimed. Every partition is handed out exactly once, in order;
    /// rows of partition `n` precede those of partition `n + 1` in the
    /// capture, so the ordinal can serve as an engine's batch index.
    pub fn claim(&self) -> Option<(usize, &PacketRange)> {
        // Past the end the counter keeps counting, which is harmless: it
        // cannot wrap within the number of claims a scan makes.
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        self.ranges.get(index).map(|range| (index, range))
    }

    /// The number of partitions, claimed or not.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// True for a queue without partitions.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Bound;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    /// What `pcapsql-datafusion` decided before this function existed, kept
    /// verbatim as the reference: `auto_target_partitions` (applied when no
    /// count was requested) followed by the gating of `decide_ranges`.
    fn legacy(cost: SeekCost, size: u64, requested: Option<usize>, default: usize) -> usize {
        const CHEAP_MIN_BYTES: u64 = 4 * 1024 * 1024;
        const FREE_MIN_BYTES: u64 = 1024 * 1024;
        const RANGE_MIN_BYTES: u64 = 16 * 1024 * 1024;
        let auto_target_partitions = || {
            if cost == SeekCost::Free && size < FREE_MIN_BYTES {
                1
            } else {
                default.max(1)
            }
        };
        let target_partitions = requested.unwrap_or_else(auto_target_partitions);
        let target = target_partitions.max(1);
        match cost {
            SeekCost::Free => target,
            SeekCost::Cheap => {
                if size >= CHEAP_MIN_BYTES {
                    target
                } else {
                    1
                }
            }
            SeekCost::RangeRequest => {
                if size >= RANGE_MIN_BYTES {
                    target
                } else {
                    1
                }
            }
        }
    }

    #[test]
    fn default_policy_has_the_datafusion_thresholds() {
        assert_eq!(
            PartitionPolicy::default(),
            PartitionPolicy {
                free_min_bytes: MIB,
                cheap_min_bytes: 4 * MIB,
                range_min_bytes: 16 * MIB,
            }
        );
    }

    /// The decisions DataFusion made, spelled out.
    #[test]
    fn decisions_are_pinned() {
        use SeekCost::{Cheap, Free, RangeRequest};
        let policy = PartitionPolicy::default();
        #[rustfmt::skip]
        let cases: &[(SeekCost, u64, Option<usize>, usize, usize)] = &[
            // A memory map: as requested, whatever the size.
            (Free, 0, Some(4), 8, 4),
            (Free, 10 * KIB, Some(4), 8, 4),
            (Free, 10 * KIB, Some(1), 8, 1),
            (Free, 10 * KIB, Some(0), 8, 1),
            (Free, 64 * MIB, Some(16), 8, 16),
            // Left to itself: one partition under 1 MiB.
            (Free, 0, None, 8, 1),
            (Free, MIB - 1, None, 8, 1),
            (Free, MIB, None, 8, 8),
            (Free, 64 * MIB, None, 8, 8),
            (Free, 64 * MIB, None, 0, 1),
            // A local file: partitioned from 4 MiB on, requested or not.
            (Cheap, 0, Some(4), 8, 1),
            (Cheap, 4 * MIB - 1, Some(4), 8, 1),
            (Cheap, 4 * MIB, Some(4), 8, 4),
            (Cheap, 4 * MIB, Some(0), 8, 1),
            (Cheap, MIB, None, 8, 1),
            (Cheap, 4 * MIB - 1, None, 8, 1),
            (Cheap, 4 * MIB, None, 8, 8),
            (Cheap, 4 * MIB, None, 0, 1),
            // A remote object: from 16 MiB on.
            (RangeRequest, 0, Some(4), 8, 1),
            (RangeRequest, 16 * MIB - 1, Some(4), 8, 1),
            (RangeRequest, 16 * MIB, Some(4), 8, 4),
            (RangeRequest, 4 * MIB, None, 8, 1),
            (RangeRequest, 16 * MIB - 1, None, 8, 1),
            (RangeRequest, 16 * MIB, None, 8, 8),
            (RangeRequest, u64::MAX, None, 3, 3),
        ];
        for &(cost, size, requested, parallelism, expected) in cases {
            assert_eq!(
                partition_target(cost, size, requested, parallelism, &policy),
                expected,
                "{cost:?} {size} {requested:?} {parallelism}"
            );
            assert_eq!(
                legacy(cost, size, requested, parallelism),
                expected,
                "legacy {cost:?} {size} {requested:?} {parallelism}"
            );
        }
    }

    /// And equal to the old code over a grid around every threshold.
    #[test]
    fn decisions_equal_the_legacy_code() {
        let policy = PartitionPolicy::default();
        let sizes: Vec<u64> = [0, 1, MIB, 4 * MIB, 16 * MIB, 1 << 40, u64::MAX]
            .into_iter()
            .flat_map(|s: u64| [s.saturating_sub(1), s, s.saturating_add(1)])
            .collect();
        let requests = [None, Some(0), Some(1), Some(2), Some(7), Some(64)];
        for cost in [SeekCost::Free, SeekCost::Cheap, SeekCost::RangeRequest] {
            for &size in &sizes {
                for requested in requests {
                    for parallelism in [0, 1, 2, 16] {
                        assert_eq!(
                            partition_target(cost, size, requested, parallelism, &policy),
                            legacy(cost, size, requested, parallelism),
                            "{cost:?} {size} {requested:?} {parallelism}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn thresholds_come_from_the_policy() {
        let policy = PartitionPolicy {
            free_min_bytes: 10,
            cheap_min_bytes: 20,
            range_min_bytes: 30,
        };
        assert_eq!(partition_target(SeekCost::Free, 9, None, 4, &policy), 1);
        assert_eq!(partition_target(SeekCost::Free, 10, None, 4, &policy), 4);
        assert_eq!(partition_target(SeekCost::Cheap, 19, None, 4, &policy), 1);
        assert_eq!(partition_target(SeekCost::Cheap, 20, None, 4, &policy), 4);
        let range = SeekCost::RangeRequest;
        assert_eq!(partition_target(range, 29, Some(4), 2, &policy), 1);
        assert_eq!(partition_target(range, 30, Some(4), 2, &policy), 4);
    }

    fn ranges(count: u64) -> Vec<PacketRange> {
        let at = |i: u64| PacketPosition {
            byte_offset: 24 + 100 * i,
            frame_number: 1 + 10 * i,
        };
        (0..count)
            .map(|i| PacketRange {
                start: at(i),
                end: (i + 1 < count).then(|| at(i + 1)),
            })
            .collect()
    }

    /// An index with a checkpoint every 10 frames: checkpoint `i` at frame
    /// `1 + 10 * i`, with the window timestamps given (`None`: not known).
    fn index(windows: &[Option<(i64, i64)>]) -> BoundaryIndex {
        BoundaryIndex {
            source_len: 24 + 100 * windows.len() as u64,
            source_mtime: None,
            header_hash: 0,
            source_etag: None,
            format: crate::io::PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 65535,
            packet_count: 10 * windows.len() as u64,
            stride: 10,
            checkpoints: windows
                .iter()
                .enumerate()
                .map(|(i, time)| Checkpoint {
                    frame_number: 1 + 10 * i as u64,
                    byte_offset: 24 + 100 * i as u64,
                    interface_state: None,
                    min_ts: time.map(|t| t.0),
                    max_ts: time.map(|t| t.1),
                })
                .collect(),
        }
    }

    /// Ranges as `(first frame, end frame)`.
    fn spans(ranges: &[PacketRange]) -> Vec<(u64, Option<u64>)> {
        ranges
            .iter()
            .map(|r| (r.start.frame_number, r.end.as_ref().map(|e| e.frame_number)))
            .collect()
    }

    fn frame_bounds(lower: Bound<u64>, upper: Bound<u64>) -> FramePredicate {
        FramePredicate {
            frames: (lower, upper),
            ..FramePredicate::all()
        }
    }

    fn time_bounds(lower: Bound<i64>, upper: Bound<i64>) -> FramePredicate {
        FramePredicate {
            time_ns: (lower, upper),
            ..FramePredicate::all()
        }
    }

    /// Eight windows whose timestamps do not ascend: the fourth is earlier
    /// than the ones around it.
    fn eight() -> BoundaryIndex {
        index(&[
            Some((100, 199)),
            Some((200, 299)),
            Some((300, 399)),
            Some((50, 60)),
            Some((400, 499)),
            Some((500, 599)),
            Some((600, 699)),
            Some((700, 799)),
        ])
    }

    #[test]
    fn plan_ranges_without_an_index_or_a_predicate_changes_nothing() {
        let all = FramePredicate::all();
        let narrow = frame_bounds(Bound::Included(3), Bound::Included(4));
        assert_eq!(plan_ranges(None, 4, &all), [PacketRange::whole()]);
        assert_eq!(plan_ranges(None, 4, &narrow), [PacketRange::whole()]);
        let index = eight();
        for want in 0..12 {
            assert_eq!(
                plan_ranges(Some(&index), want, &all),
                index.partition_ranges(want)
            );
        }
        // An index of an empty capture has the whole range only.
        let empty = BoundaryIndex {
            packet_count: 0,
            checkpoints: Vec::new(),
            ..eight()
        };
        assert_eq!(
            plan_ranges(Some(&empty), 4, &narrow),
            [PacketRange::whole()]
        );
    }

    #[test]
    fn plan_ranges_trims_by_frame_number_exactly() {
        use Bound::*;
        let index = eight();
        // Four ranges of two windows: frames 1-20, 21-40, 41-60, 61-.
        assert_eq!(
            spans(&index.partition_ranges(4)),
            [(1, Some(21)), (21, Some(41)), (41, Some(61)), (61, None)]
        );
        let planned =
            |lower, upper| spans(&plan_ranges(Some(&index), 4, &frame_bounds(lower, upper)));
        // Inside one window: the range shrinks to it.
        assert_eq!(planned(Included(25), Included(26)), [(21, Some(31))]);
        assert_eq!(planned(Included(31), Excluded(41)), [(31, Some(41))]);
        // The window boundaries, with both kinds of bound.
        assert_eq!(planned(Included(30), Included(31)), [(21, Some(41))]);
        assert_eq!(planned(Excluded(30), Included(31)), [(31, Some(41))]);
        assert_eq!(planned(Included(30), Excluded(31)), [(21, Some(31))]);
        assert_eq!(planned(Excluded(30), Excluded(31)), []);
        // Across ranges: the first and the last one shrink.
        assert_eq!(
            planned(Included(15), Included(45)),
            [(11, Some(21)), (21, Some(41)), (41, Some(51))]
        );
        // An upper bound alone, also in the range to the end of the capture.
        assert_eq!(
            planned(Unbounded, Included(65)),
            [
                (1, Some(21)),
                (21, Some(41)),
                (41, Some(61)),
                (61, Some(71))
            ]
        );
        assert_eq!(planned(Unbounded, Excluded(1)), []);
        // A lower bound alone. The last window stays whatever the bound:
        // the capture may have grown since the index was built.
        assert_eq!(
            planned(Included(55), Unbounded),
            [(51, Some(61)), (61, None)]
        );
        assert_eq!(planned(Included(75), Unbounded), [(71, None)]);
        assert_eq!(planned(Excluded(1_000), Unbounded), [(71, None)]);
        // Nothing can match: no ranges.
        assert_eq!(planned(Included(9), Included(8)), []);
        assert_eq!(planned(Excluded(8), Excluded(9)), []);
        // One partition: the same, as one range.
        assert_eq!(
            spans(&plan_ranges(
                Some(&index),
                1,
                &frame_bounds(Included(15), Included(45))
            )),
            [(11, Some(51))]
        );
    }

    #[test]
    fn plan_ranges_trims_by_time_window_by_window() {
        use Bound::*;
        let index = eight();
        let planned = |want, lower, upper| {
            spans(&plan_ranges(Some(&index), want, &time_bounds(lower, upper)))
        };
        // Window 3 (frames 21-30): its range shrinks, the others go, except
        // the last window of the capture, which a time bound never rules
        // out.
        assert_eq!(
            planned(4, Included(300), Included(399)),
            [(21, Some(31)), (71, None)]
        );
        // The bounds of a window, inclusive and exclusive.
        assert_eq!(
            planned(8, Included(299), Included(300)),
            [(11, Some(21)), (21, Some(31)), (71, None)]
        );
        assert_eq!(
            planned(8, Excluded(299), Unbounded).first(),
            Some(&(21, Some(31)))
        );
        assert_eq!(
            planned(8, Excluded(399), Unbounded).first(),
            Some(&(41, Some(51)))
        );
        assert_eq!(
            planned(8, Unbounded, Excluded(200)),
            [(1, Some(11)), (31, Some(41)), (71, None)]
        );
        assert_eq!(
            planned(8, Unbounded, Included(200)),
            [(1, Some(11)), (11, Some(21)), (31, Some(41)), (71, None)]
        );
        // Timestamps do not ascend: the early window in the middle matches
        // on its own, and a range is not cut around a window that does not.
        assert_eq!(
            planned(8, Unbounded, Included(60)),
            [(31, Some(41)), (71, None)]
        );
        assert_eq!(
            planned(2, Unbounded, Included(199)),
            [(1, Some(41)), (71, None)]
        );
        assert_eq!(planned(1, Unbounded, Included(199)), [(1, None)]);
        assert_eq!(planned(1, Included(300), Included(450)), [(21, None)]);
        // Nothing can match.
        assert_eq!(planned(8, Included(5), Excluded(5)), []);

        // Frame and time bounds together.
        let both = FramePredicate {
            frames: (Included(12), Included(64)),
            time_ns: (Included(250), Included(450)),
        };
        assert_eq!(
            spans(&plan_ranges(Some(&index), 8, &both)),
            [(11, Some(21)), (21, Some(31)), (41, Some(51))]
        );
        assert_eq!(
            spans(&plan_ranges(Some(&index), 2, &both)),
            [(11, Some(31)), (41, Some(51))]
        );
    }

    /// A window without timestamps in the index is never ruled out by time.
    #[test]
    fn plan_ranges_keeps_windows_of_unknown_time() {
        let index = index(&[Some((100, 199)), None, Some((300, 399)), Some((400, 499))]);
        let late = time_bounds(Bound::Included(1_000), Bound::Unbounded);
        assert_eq!(
            spans(&plan_ranges(Some(&index), 4, &late)),
            [(11, Some(21)), (31, None)]
        );
    }

    /// Whatever the predicate, a planned range starts and ends on
    /// checkpoints of the index and the ranges ascend without overlap.
    #[test]
    fn planned_ranges_are_checkpoint_aligned() {
        use Bound::*;
        let index = eight();
        let frame_bounds_of = |v: u64| [Unbounded, Included(v), Excluded(v)];
        let time_bounds_of = |v: i64| [Unbounded, Included(v), Excluded(v)];
        for want in [1, 2, 3, 8] {
            for low in (0..90).step_by(7) {
                for high in (0..90).step_by(11) {
                    for (fl, tl) in frame_bounds_of(low)
                        .into_iter()
                        .zip(time_bounds_of(low as i64 * 9))
                    {
                        for (fu, tu) in frame_bounds_of(high)
                            .into_iter()
                            .zip(time_bounds_of(high as i64 * 9))
                        {
                            for predicate in [
                                frame_bounds(fl, fu),
                                time_bounds(tl, tu),
                                FramePredicate {
                                    frames: (fl, Unbounded),
                                    time_ns: (Unbounded, tu),
                                },
                            ] {
                                let ranges = plan_ranges(Some(&index), want, &predicate);
                                assert!(ranges.len() <= index.partition_ranges(want).len());
                                let mut previous_end = Some(0);
                                for range in &ranges {
                                    let start = index.checkpoint_at(range.start.frame_number);
                                    assert_eq!(
                                        start.map(|c| c.byte_offset),
                                        Some(range.start.byte_offset),
                                        "{predicate:?}"
                                    );
                                    assert!(previous_end
                                        .is_some_and(|end| end <= range.start.frame_number));
                                    previous_end = range.end.as_ref().map(|e| e.frame_number);
                                    if let Some(end) = &range.end {
                                        assert!(end.frame_number > range.start.frame_number);
                                        assert_eq!(
                                            index
                                                .checkpoint_at(end.frame_number)
                                                .map(|c| c.byte_offset),
                                            Some(end.byte_offset)
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn partitions_are_claimed_in_order() {
        let queue = PartitionQueue::new(ranges(3));
        assert_eq!(queue.len(), 3);
        assert!(!queue.is_empty());
        let all = ranges(3);
        for (i, range) in all.iter().enumerate() {
            assert_eq!(queue.claim(), Some((i, range)));
        }
        assert_eq!(queue.claim(), None);
        assert_eq!(queue.claim(), None);
        assert_eq!(queue.len(), 3);

        let empty = PartitionQueue::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.claim(), None);
    }

    /// Workers claiming at once get every partition exactly once, each
    /// worker's in ascending order, and each ordinal with its own range.
    #[test]
    fn concurrent_claims_hand_out_each_partition_once() {
        const PARTITIONS: u64 = 5_000;
        const WORKERS: usize = 8;
        for _ in 0..20 {
            let all = ranges(PARTITIONS);
            let queue = PartitionQueue::new(all.clone());
            let start = std::sync::Barrier::new(WORKERS);
            let claimed: Vec<Vec<usize>> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..WORKERS)
                    .map(|_| {
                        scope.spawn(|| {
                            start.wait();
                            let mut mine = Vec::new();
                            while let Some((index, range)) = queue.claim() {
                                assert_eq!(*range, all[index]);
                                mine.push(index);
                            }
                            mine
                        })
                    })
                    .collect();
                workers.into_iter().map(|w| w.join().unwrap()).collect()
            });
            assert_eq!(queue.claim(), None);
            for mine in &claimed {
                assert!(mine.windows(2).all(|w| w[0] < w[1]));
            }
            let mut every: Vec<usize> = claimed.into_iter().flatten().collect();
            every.sort_unstable();
            assert_eq!(every, (0..PARTITIONS as usize).collect::<Vec<_>>());
        }
    }
}
