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
//! ([`BoundaryIndex::partition_ranges`](crate::io::BoundaryIndex::partition_ranges)).

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::io::{PacketRange, SeekCost};

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
        let len = self.ranges.len();
        let index = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next < len).then_some(next + 1)
            })
            .ok()?;
        Some((index, &self.ranges[index]))
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
    use crate::io::PacketPosition;

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
