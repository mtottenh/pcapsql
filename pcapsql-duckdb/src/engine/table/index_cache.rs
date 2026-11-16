//! The boundary indexes of the captures a database has split, kept for its later scans.
//!
//! A capture is split at the checkpoints of a `BoundaryIndex`, which one pass over its record
//! headers builds on one thread before any worker starts (`layout`). The pass costs about what
//! counting the capture's frames costs. [`IndexCache`] keeps the index of every capture a scan
//! split, so that a later scan of the same capture skips the pass. The cache is in memory
//! only, and there is one per database: the scan functions `register` makes for a database
//! share it, and it goes when the database is closed.
//!
//! # When an entry is used
//!
//! DuckDB's file API tells a file's size and nothing else about it: no modification time, no
//! inode, no entity tag (the table of limits in the upgrade runbook). An entry is found by
//! the path as the scan opened it and by the checkpoint stride (`pcapsql_index_stride`), and it
//! is used only if the file still looks like the one it was built from:
//!
//! - the same size;
//! - the same first and the same last [`EDGE_BYTES`] (a hash of each, [`Fingerprint`]);
//! - at every checkpoint where the scan starts or ends a partition, and at the last
//!   checkpoint (where a strict scan reads the tail from), the same first [`MARK_BYTES`]
//!   bytes (a hash, [`Cached::check_records`]). A record that moved, or another record
//!   written there, changes them. They do not show that a record still starts there.
//!
//! These checks read 128 KiB and 32 bytes per checkpoint used, before the scan starts. An
//! entry that fails one is dropped and the index is built again, so a stale entry costs the
//! pass it was to save and nothing else.
//!
//! While the scan runs, a partition that is read to its end must end where the index says the
//! next one starts (`report::misaligned`). If it does not, the records between two checkpoints
//! are not those the index counted (the file changed): the query fails, says so, and the entry
//! is dropped, so that the next scan builds the index again. The rows the partition returned
//! before that may be wrong, which is why this is the last check and not the first.
//!
//! # What the checks miss
//!
//! A file rewritten in place with the same size, the same first and last 64 KiB and the same
//! bytes at the checkpoints a scan uses, whose records between those checkpoints differ. For
//! example two records merged into one by rewriting one length field: every byte at every
//! checkpoint is as it was, and each record after the merge is one frame earlier than the
//! index says.
//!
//! - **In number.** Only a scan that reads the partition holding the change to its end finds
//!   it, and fails once. A scan that does not (a filter on `frame_number` or `timestamp` that
//!   leaves that part out, a `LIMIT`) reads the partitions after it, which start and end on
//!   unchanged bytes, and numbers their frames by the index: `frame_number` is off, and a
//!   filter on it selects the wrong frames, with no error. After the merge above, `WHERE
//!   frame_number BETWEEN 9001 AND 9003` returns frames 9000 to 9002 numbered 9001 to 9003.
//!   In a pcapng file the scan that reads the changed part misses it too when the extra
//!   packets come after a block that is not a frame (an interface description, a statistics
//!   block): those frames are then missing from the result.
//! - **Only in their content** (timestamps, addresses, payload): the rows are those of the new
//!   records, with two exceptions. A filter on `timestamp` decides which windows of
//!   checkpoints to read by the times the index recorded, and may skip one that now has
//!   matching frames. In a pcapng file, an interface description changed in place after the
//!   first 64 KiB is not seen: the partitions after it are read with the interface state the
//!   index recorded (link type, time resolution).
//!
//! A file that changes while it is scanned is the same risk with or without the cache.
//!
//! # What is kept
//!
//! Only an index of the whole capture ([`is_whole`]): one built for a scan with an upper bound
//! on `frame_number` stops at the bound and is not kept, while a whole index serves any bound.
//! An index of more than [`MAX_CHECKPOINTS`] checkpoints is not kept either (each checkpoint
//! costs a read when the index is stored). The cache holds at most [`MAX_ENTRIES`] indexes and
//! about [`MAX_BYTES`] bytes; past either, the index used longest ago goes first.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hasher};
use std::io;
use std::mem::size_of;
use std::sync::{Arc, Mutex, MutexGuard};

use pcapsql_core::io::{BoundaryIndex, Checkpoint, InterfaceInfo, PacketRange};

use crate::engine::fs::DuckFile;

/// Bytes at the start and at the end of a capture whose hash an entry is checked against.
pub(super) const EDGE_BYTES: u64 = 64 << 10;

/// Bytes at a checkpoint whose hash an entry is checked against: the header of a record in
/// either format (16 bytes in a pcap file, 28 in a pcapng Enhanced Packet Block) and the
/// start of its packet.
pub(super) const MARK_BYTES: u64 = 32;

/// The most checkpoints an index may have to be kept: 4 billion frames at the default stride.
pub(super) const MAX_CHECKPOINTS: usize = 1 << 16;

/// The most indexes the cache holds.
pub(super) const MAX_ENTRIES: usize = 1024;

/// About the most bytes of memory the cache holds (see [`weight`]).
pub(super) const MAX_BYTES: usize = 64 << 20;

/// A file that can be read at any offset: a capture through DuckDB's file system, or bytes in
/// memory in the unit tests.
pub(super) trait ReadAt {
    /// Fill `out` from byte `offset`. A file that ends before `out` is full is an error.
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> io::Result<()>;
}

impl ReadAt for DuckFile {
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        DuckFile::read_exact_at(self, offset, out).map_err(io::Error::other)
    }
}

impl ReadAt for &[u8] {
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let bytes = start
            .checked_add(out.len())
            .and_then(|end| self.get(start..end))
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        out.copy_from_slice(bytes);
        Ok(())
    }
}

/// The hash of `len` bytes of `file` from `offset`.
fn hash_at(file: &mut impl ReadAt, offset: u64, len: u64) -> io::Result<u64> {
    let mut bytes = vec![0; usize::try_from(len).map_err(io::Error::other)?];
    file.read_exact_at(offset, &mut bytes)?;
    // In memory only, and only compared within the process: any hash will do.
    let mut hasher = DefaultHasher::new();
    hasher.write(&bytes);
    Ok(hasher.finish())
}

/// The hash of the bytes a record at `offset` of a file of `size` bytes starts with.
fn mark(file: &mut impl ReadAt, offset: u64, size: u64) -> io::Result<u64> {
    hash_at(file, offset, MARK_BYTES.min(size.saturating_sub(offset)))
}

/// What a file is checked by before the index of an earlier scan is used for it: its size,
/// and a hash of its first and of its last [`EDGE_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Fingerprint {
    size: u64,
    head: u64,
    tail: u64,
}

impl Fingerprint {
    /// The fingerprint of `file`, which has `size` bytes.
    pub(super) fn of(file: &mut impl ReadAt, size: u64) -> io::Result<Self> {
        let tail = size.saturating_sub(EDGE_BYTES);
        Ok(Self {
            size,
            head: hash_at(file, 0, size.min(EDGE_BYTES))?,
            tail: hash_at(file, tail, size - tail)?,
        })
    }
}

/// Why the index of an earlier scan is not used for a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Stale {
    /// The file has another size.
    Size { was: u64, is: u64 },
    /// Its first [`EDGE_BYTES`] changed.
    Head,
    /// Its last [`EDGE_BYTES`] changed.
    Tail,
    /// The first bytes at the checkpoint of this frame changed: the record there moved, or
    /// another one is there.
    Record { frame: u64 },
    /// The file could not be read for the checks.
    Unreadable(String),
}

impl std::fmt::Display for Stale {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Size { was, is } => write!(out, "the file was {was} bytes and is {is}"),
            Self::Head => write!(
                out,
                "the first {} KiB of the file changed",
                EDGE_BYTES >> 10
            ),
            Self::Tail => write!(out, "the last {} KiB of the file changed", EDGE_BYTES >> 10),
            Self::Record { frame } => write!(out, "the record of frame {frame} changed"),
            Self::Unreadable(error) => write!(out, "the file could not be read: {error}"),
        }
    }
}

/// An index as the cache keeps it: with what the file it was built from looked like.
#[derive(Debug)]
pub(super) struct Cached {
    pub(super) index: Arc<BoundaryIndex>,
    fingerprint: Fingerprint,
    /// The hash of the first [`MARK_BYTES`] at each checkpoint of `index`, in its order.
    marks: Box<[u64]>,
}

impl Cached {
    /// `index` with the fingerprint of the file it was built from, and the marks of its
    /// checkpoints read from `file`, which must be that file.
    pub(super) fn new(
        index: Arc<BoundaryIndex>,
        fingerprint: Fingerprint,
        file: &mut impl ReadAt,
    ) -> io::Result<Self> {
        let marks = index
            .checkpoints
            .iter()
            .map(|checkpoint| mark(file, checkpoint.byte_offset, fingerprint.size))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            index,
            fingerprint,
            marks,
        })
    }

    /// Whether a file of fingerprint `now` may be the one the index was built from: the same
    /// size, head and tail.
    pub(super) fn check_file(&self, now: &Fingerprint) -> Result<(), Stale> {
        let was = &self.fingerprint;
        if was.size != now.size {
            return Err(Stale::Size {
                was: was.size,
                is: now.size,
            });
        }
        if was.head != now.head {
            return Err(Stale::Head);
        }
        if was.tail != now.tail {
            return Err(Stale::Tail);
        }
        Ok(())
    }

    /// Whether the first [`MARK_BYTES`] at the checkpoints of `frames` (frame numbers; a frame
    /// that is not a checkpoint's is passed over) are those that were there when the index was
    /// built. `file` is the file as it is now, of the size [`check_file`] accepted.
    ///
    /// [`check_file`]: Self::check_file
    pub(super) fn check_records(
        &self,
        file: &mut impl ReadAt,
        frames: impl IntoIterator<Item = u64>,
    ) -> Result<(), Stale> {
        let checkpoints = &self.index.checkpoints;
        for frame in frames {
            let Ok(at) = checkpoints.binary_search_by_key(&frame, |c| c.frame_number) else {
                continue;
            };
            let now = mark(file, checkpoints[at].byte_offset, self.fingerprint.size)
                .map_err(|error| Stale::Unreadable(error.to_string()))?;
            if now != self.marks[at] {
                return Err(Stale::Record { frame });
            }
        }
        Ok(())
    }
}

/// The frames of the checkpoints a scan of `ranges` relies on a record to start at: where each
/// range starts and ends, and the last checkpoint of `index`, from which a strict scan reads
/// the capture's tail.
pub(super) fn relied_on(index: &BoundaryIndex, ranges: &[PacketRange]) -> Vec<u64> {
    let mut frames: Vec<u64> = ranges
        .iter()
        .flat_map(|range| {
            std::iter::once(range.start.frame_number)
                .chain(range.end.as_ref().map(|end| end.frame_number))
        })
        .chain(index.checkpoints.last().map(|last| last.frame_number))
        .collect();
    frames.sort_unstable();
    frames.dedup();
    frames
}

/// Whether an index built up to frame `last_frame` (`build_boundary_index_to`) is the index of
/// the whole capture: the pass was not given a last frame, or the capture ended before it.
/// A pass that stopped at the frame did not see the end, so its index is of the capture's
/// first frames only.
pub(super) fn is_whole(index: &BoundaryIndex, last_frame: Option<u64>) -> bool {
    last_frame.is_none_or(|last| index.packet_count < last)
}

/// Whether the cache takes `index`: an index of the whole capture with few enough checkpoints.
pub(super) fn worth_keeping(index: &BoundaryIndex, last_frame: Option<u64>) -> bool {
    is_whole(index, last_frame) && index.checkpoints.len() <= MAX_CHECKPOINTS
}

/// About how much memory an entry for `path` of `index` takes: the index with what its vectors
/// have room for, a mark per checkpoint, the two `Arc`s, and the entry in the cache's map,
/// which keeps a slot of a key and a value for up to twice as many entries as it holds.
fn weight(path: &str, index: &BoundaryIndex) -> usize {
    let interfaces: usize = index
        .checkpoints
        .iter()
        .filter_map(|checkpoint| checkpoint.interface_state.as_ref())
        .map(|state| state.interfaces.capacity() * size_of::<InterfaceInfo>())
        .sum();
    2 * size_of::<(Key, Slot)>()
        + path.len()
        + 4 * size_of::<usize>()
        + size_of::<Cached>()
        + size_of::<BoundaryIndex>()
        + index.source_etag.as_ref().map_or(0, String::capacity)
        + index.checkpoints.capacity() * size_of::<Checkpoint>()
        + index.checkpoints.len() * size_of::<u64>()
        + interfaces
}

/// What an entry is found by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    /// The path as the scan opened it: as given, or as a pattern expanded to.
    path: String,
    /// The checkpoint stride the index was built with.
    stride: u64,
}

#[derive(Debug)]
struct Slot {
    cached: Arc<Cached>,
    /// [`weight`] of the entry.
    weight: usize,
    /// When the entry was last stored or found, on the cache's clock.
    used: u64,
}

#[derive(Debug)]
struct Slots {
    map: HashMap<Key, Slot>,
    /// The sum of the weights of the entries.
    bytes: usize,
    /// Advanced by every store and find.
    clock: u64,
    max_entries: usize,
    max_bytes: usize,
}

/// The indexes of earlier scans, by path and stride, least recently used out.
///
/// It is safe to use from any number of threads: one lock is held for each call, never while
/// a file is read.
#[derive(Debug)]
pub(super) struct IndexCache {
    slots: Mutex<Slots>,
}

impl Default for IndexCache {
    fn default() -> Self {
        Self::with_limits(MAX_ENTRIES, MAX_BYTES)
    }
}

impl IndexCache {
    /// A cache of at most `max_entries` indexes and about `max_bytes` bytes.
    pub(super) fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            slots: Mutex::new(Slots {
                map: HashMap::new(),
                bytes: 0,
                clock: 0,
                max_entries,
                max_bytes,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Slots> {
        // A panic while the lock was held left nothing half done: every change is made in
        // one step.
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The index kept for `path` with checkpoints `stride` frames apart, unchecked: see
    /// [`Cached::check_file`] and [`Cached::check_records`].
    pub(super) fn get(&self, path: &str, stride: u64) -> Option<Arc<Cached>> {
        let mut slots = self.lock();
        slots.clock += 1;
        let now = slots.clock;
        let key = Key {
            path: path.to_owned(),
            stride,
        };
        let slot = slots.map.get_mut(&key)?;
        slot.used = now;
        Some(slot.cached.clone())
    }

    /// Whether the cache would keep `index` for `path`: not if the index alone is over a
    /// quarter of the memory limit. For a caller to ask before it reads the marks.
    pub(super) fn admits(&self, path: &str, index: &BoundaryIndex) -> bool {
        let slots = self.lock();
        slots.max_entries > 0 && weight(path, index) <= slots.max_bytes / 4
    }

    /// Keep `cached` for `path`, in place of what was kept for it with the same stride, and
    /// drop the indexes used longest ago until the cache is within its limits. An index the
    /// cache does not [admit](Self::admits) is not kept. Returns whether it was.
    pub(super) fn insert(&self, path: &str, cached: Cached) -> bool {
        let weight = weight(path, &cached.index);
        let mut slots = self.lock();
        if weight > slots.max_bytes / 4 || slots.max_entries == 0 {
            return false;
        }
        let key = Key {
            path: path.to_owned(),
            stride: cached.index.stride,
        };
        slots.clock += 1;
        let used = slots.clock;
        let slot = Slot {
            cached: Arc::new(cached),
            weight,
            used,
        };
        if let Some(old) = slots.map.insert(key, slot) {
            slots.bytes -= old.weight;
        }
        slots.bytes += weight;
        while slots.map.len() > slots.max_entries || slots.bytes > slots.max_bytes {
            let oldest = slots
                .map
                .iter()
                .min_by_key(|(_, slot)| slot.used)
                .map(|(key, _)| key.clone())
                .expect("a cache over its limits has an entry");
            let gone = slots.map.remove(&oldest).expect("the key was just found");
            slots.bytes -= gone.weight;
        }
        true
    }

    /// Drop what is kept for `path` with checkpoints `stride` frames apart: an index found
    /// stale. (Should another scan have kept a new one for it in the meantime, that goes too,
    /// and costs the next scan a pass.)
    pub(super) fn forget(&self, path: &str, stride: u64) {
        let mut slots = self.lock();
        let key = Key {
            path: path.to_owned(),
            stride,
        };
        if let Some(gone) = slots.map.remove(&key) {
            slots.bytes -= gone.weight;
        }
    }

    /// The number of indexes kept and their weight, for the tests.
    #[cfg(test)]
    pub(super) fn usage(&self) -> (usize, usize) {
        let slots = self.lock();
        (slots.map.len(), slots.bytes)
    }
}

#[cfg(test)]
mod tests;
