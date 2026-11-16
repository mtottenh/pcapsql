//! The partitions of one file of a scan, and the row estimate of a file.

use std::sync::Arc;

use duckdb_neo::{connection::Context, Result};
use pcapsql_core::io::{
    build_boundary_index_to, BoundaryIndex, PacketPosition, PacketRange, PacketReader,
    ReadPacketReader, SeekCost, StreamHeader,
};
use pcapsql_core::scan::{partition_target, plan_ranges, FramePredicate, PartitionPolicy};

use super::index_cache::{relied_on, worth_keeping, Cached, Fingerprint, Stale};
use super::{function::CaptureFunction, PcapScan, PACKETS_PER_STEP};
use crate::engine::{
    fs::{self, DuckFile},
    settings::{self, ScanSettings},
};

/// Bytes of capture file per frame, for the row estimate DuckDB's optimizer is given at bind:
/// a record header and a few hundred bytes of packet. The true figure is between 60 bytes
/// (bare TCP ACKs) and 1,500 and more (bulk transfers).
const ESTIMATED_BYTES_PER_FRAME: u64 = 512;

/// How much larger a compressed capture is taken to be once decompressed, for the same estimate.
const ESTIMATED_COMPRESSION_RATIO: u64 = 4;

/// Where the index a file is cut at comes from.
enum Source {
    /// The pass of this scan. `stale`: why the index the cache had for the file was not used.
    Pass { stale: Option<Stale> },
    /// The cache, from an earlier scan.
    Cache,
}

/// The index of the first `last_frame` frames of a capture, cut from `index`, the index of all
/// of it: the index the pass builds when it stops at that frame, but for the timestamps of its
/// last window, which take in the frames after it (`plan_ranges` does not look at the times of
/// the last window). `index` itself when there is no bound or the capture ends before it.
pub(super) fn first_frames(
    index: &Arc<BoundaryIndex>,
    last_frame: Option<u64>,
) -> Arc<BoundaryIndex> {
    let Some(last) = last_frame.filter(|last| *last < index.packet_count) else {
        return index.clone();
    };
    Arc::new(BoundaryIndex {
        packet_count: last,
        checkpoints: index
            .checkpoints
            .iter()
            .take_while(|checkpoint| checkpoint.frame_number <= last)
            .cloned()
            .collect(),
        source_etag: index.source_etag.clone(),
        ..*index.as_ref()
    })
}

/// The partitions of one file: what [`PcapScan::layout`] decided.
#[derive(Debug)]
pub(super) struct Layout {
    /// The byte ranges to scan, in capture order.
    pub(super) ranges: Vec<PacketRange>,
    /// The index `ranges` were cut from. `None`: `ranges` is the whole capture, read from its
    /// first byte.
    pub(super) index: Option<Arc<BoundaryIndex>>,
    /// The decision in words, for the log.
    pub(super) note: String,
}

impl Layout {
    /// The whole capture as one partition, because of `why`.
    fn sequential(why: impl std::fmt::Display) -> Self {
        Self {
            ranges: vec![PacketRange::whole()],
            index: None,
            note: format!("1 ({why})"),
        }
    }

    /// The whole capture as one partition, for a plan that cannot be scanned any other way
    /// (`CompiledScan::requires_single_partition`): a stream table is what the TCP streams of
    /// a capture hold once all of it was read, in order. No setting changes this.
    pub(super) fn in_order() -> Self {
        Self::sequential("a stream table is built from the whole capture, read in order")
    }
}

/// Whether a file can be split at all: it is read through the local file system, and it is
/// not compressed. A file that cannot is one partition, whatever its size, and its bytes are
/// not part of the `scan_bytes` the others share the threads by ([`thread_share`]).
pub(super) fn can_split(remote: bool, header: &StreamHeader) -> bool {
    !remote && !header.compression.is_compressed()
}

/// How many of a scan's `threads` one file of `size` bytes is split for, when the files of
/// the scan that can be split ([`can_split`]) have `scan_bytes` together: its share by size,
/// rounded. A file that is the only one that can be split gets them all; four files of one
/// size on four threads get one each, and are not split.
pub(super) fn thread_share(threads: usize, size: u64, scan_bytes: u64) -> usize {
    if scan_bytes <= size {
        return threads;
    }
    let share =
        (threads as u128 * u128::from(size) + u128::from(scan_bytes) / 2) / u128::from(scan_bytes);
    usize::try_from(share).unwrap_or(threads)
}

impl PcapScan {
    /// Decide the partitions of one file of a scan (see the module documentation).
    ///
    /// `scan_bytes` is the size of the files of the scan that can be split ([`can_split`])
    /// together, as `bind` found them.
    pub(super) fn layout(
        &self,
        context: &Context,
        settings: &ScanSettings,
        path: &str,
        scan_bytes: u64,
        strict: bool,
        frames: &FramePredicate,
    ) -> Result<Layout> {
        if frames.is_empty() {
            // Nothing to read, and so nothing to open.
            return Ok(Layout {
                ranges: Vec::new(),
                index: None,
                note: "0 (the filter accepts no frame)".to_owned(),
            });
        }
        if !settings.parallel {
            return Ok(Layout::sequential(format_args!(
                "{} is off",
                settings::PARALLEL_SCAN
            )));
        }
        if settings.threads == 1 {
            return Ok(Layout::sequential("DuckDB has one thread"));
        }
        if fs::is_remote(context, path)? {
            return Ok(Layout::sequential("a remote file is not indexed"));
        }
        // The file as it is now, which is not that of `bind` when a prepared statement is run
        // again.
        let mut file = DuckFile::open(context, path)?;
        let header = self.probe(&mut file, path)?;
        if !can_split(false, &header) {
            return Ok(Layout::sequential("a compressed capture cannot be split"));
        }
        let size = file.size()?;
        let policy = PartitionPolicy {
            cheap_min_bytes: settings.min_file_size,
            ..PartitionPolicy::default()
        };
        if partition_target(SeekCost::Cheap, size, None, settings.threads, &policy) <= 1 {
            return Ok(Layout::sequential(format_args!(
                "{size} bytes is less than {} = {}",
                settings::PARALLEL_MIN_FILE_SIZE,
                settings.min_file_size
            )));
        }
        // The pass below reads the whole file on this one thread before any worker starts, so
        // it is only worth its time where the threads would otherwise have nothing to do: the
        // files of a scan are partitions already, and a file is split for its share of the
        // threads only.
        let threads = thread_share(settings.threads, size, scan_bytes);
        let want = partition_target(SeekCost::Cheap, size, None, threads, &policy);
        if want <= 1 {
            return Ok(Layout::sequential(format_args!(
                "the other files of the scan keep DuckDB's {} threads busy",
                settings.threads
            )));
        }

        // Frames past an upper bound on `frame_number` are not read, nor indexed by the pass
        // below. A strict scan needs the index to reach the end, where the capture may be cut
        // off.
        let last_frame = if strict { None } else { frames.last_frame() };

        // The index an earlier scan built, if the file still looks like the one it was built
        // from (the `index_cache` module). With a bound the index is cut there, so the
        // partitions are those of the frames the scan reads, as they would be with the pass.
        // `fingerprint`: the file's before the pass, to keep the index with.
        let mut fingerprint = None;
        let mut stale = None;
        if settings.index_cache {
            if let Some(cached) = self.indexes.get(path, settings.index_stride) {
                let now = Fingerprint::of(&mut file, size)
                    .map_err(|error| Stale::Unreadable(error.to_string()));
                fingerprint = now.clone().ok();
                let planned = first_frames(&cached.index, last_frame);
                let usable = now.and_then(|now| cached.check_file(&now)).and_then(|()| {
                    // The records the partitions will start and end at.
                    let ranges = plan_ranges(Some(&planned), want, frames);
                    cached.check_records(&mut file, relied_on(&planned, &ranges))
                });
                match usable {
                    Ok(()) => {
                        return self.cut(
                            &mut file,
                            path,
                            planned,
                            want,
                            strict,
                            frames,
                            Source::Cache,
                        )
                    }
                    Err(why) => {
                        self.indexes.forget(path, settings.index_stride);
                        stale = Some(why);
                    }
                }
            }
        }

        if settings.index_cache && fingerprint.is_none() {
            fingerprint = Fingerprint::of(&mut file, size).ok();
        }

        // One pass over the record headers, to the last frame the scan reads: the index is
        // then that of the capture's beginning, which is what an index is of a capture that
        // has grown since, and `plan_ranges` and the scan treat it as that. It is kept for
        // later scans only if it is of the whole capture.
        file.seek(0)?;
        let built = build_boundary_index_to(
            &mut file,
            header.format,
            settings.index_stride,
            size,
            None,
            0,
            last_frame,
        );
        let index = match built {
            // The pass grew the vector of checkpoints, which may have room for twice as many as
            // it holds. The cache holds it for as long as it holds the index.
            Ok(mut index) => {
                index.checkpoints.shrink_to_fit();
                Arc::new(index)
            }
            // A record the pass cannot get past. The scan cannot either, but it returns the
            // rows before it first and then says where it is.
            Err(error) => {
                return Ok(Layout::sequential(format_args!(
                    "the index pass failed: {error}"
                )))
            }
        };
        if let Some(before) = fingerprint {
            if worth_keeping(&index, last_frame) {
                self.keep(&mut file, path, &index, before);
            }
        }
        self.cut(
            &mut file,
            path,
            index,
            want,
            strict,
            frames,
            Source::Pass { stale },
        )
    }

    /// Keep `index`, just built from `file`, for later scans, with `before`, the fingerprint
    /// the file had before the pass, if the file has it still. A file that cannot be read for
    /// the marks is not kept, and the scan goes on: it reports what is wrong when it gets there.
    fn keep(
        &self,
        file: &mut DuckFile,
        path: &str,
        index: &Arc<BoundaryIndex>,
        before: Fingerprint,
    ) {
        // Before the marks are read, which is a read per checkpoint.
        if !self.indexes.admits(path, index) {
            return;
        }
        let Ok(cached) = Cached::new(index.clone(), before, file) else {
            return;
        };
        // A file that changed under the pass may have been indexed half before the change and
        // half after.
        let unchanged = file
            .size()
            .ok()
            .and_then(|size| Fingerprint::of(file, size).ok())
            .is_some_and(|after| cached.check_file(&after).is_ok());
        if unchanged {
            self.indexes.insert(path, cached);
        }
    }

    /// The partitions of a file cut at the checkpoints of `index`, from `source`, for `want`
    /// threads, without what `frames` rules out.
    #[allow(clippy::too_many_arguments)]
    fn cut(
        &self,
        file: &mut DuckFile,
        path: &str,
        index: Arc<BoundaryIndex>,
        want: usize,
        strict: bool,
        frames: &FramePredicate,
        source: Source,
    ) -> Result<Layout> {
        // What the index counts: the frames of the capture, or those up to the filter's last.
        let last_frame = if strict { None } else { frames.last_frame() };
        let counted = if last_frame.is_some_and(|last| index.packet_count >= last) {
            "the first "
        } else {
            ""
        };
        // Where it is from.
        let from = match source {
            Source::Pass { stale } => stale.map_or_else(String::new, |why| {
                format!("; the kept index no longer matched ({why}) and was built again")
            }),
            Source::Cache => "; index kept from an earlier scan".to_owned(),
        };
        let whole = plan_ranges(Some(&index), want, &FramePredicate::all()).len();
        if whole <= 1 {
            return Ok(Layout::sequential(format_args!(
                "{counted}{} frames give no place to split at, with a checkpoint every {} \
                 frames{from}",
                index.packet_count, index.stride
            )));
        }
        // The partitions, without those the filter rules out and each shrunk to the checkpoint
        // windows that may hold a frame it accepts. There may be none left.
        let ranges = plan_ranges(Some(&index), want, frames);
        if strict {
            // Workers do not wait for each other, so the one at the end of the capture could
            // find a broken tail before or after a `LIMIT` is filled by the others. Whether a
            // strict scan fails must not depend on that: the tail is looked at now.
            if let Some(last_frame) = self.truncated_tail(file, &index) {
                return Err(self.truncation_error(path, last_frame));
            }
        }
        let filtered = if frames.is_all() {
            String::new()
        } else {
            let covered: u64 = ranges
                .iter()
                .map(|range| {
                    let end = range
                        .end
                        .as_ref()
                        .map_or(index.packet_count + 1, |end| end.frame_number);
                    end.saturating_sub(range.start.frame_number)
                })
                .sum();
            format!(
                "; the filter leaves {covered} frames in {} of {whole} partitions",
                ranges.len()
            )
        };
        Ok(Layout {
            note: format!(
                "{} (of {counted}{} frames, cut at checkpoints {} frames apart{filtered}{from})",
                ranges.len(),
                index.packet_count,
                index.stride
            ),
            ranges,
            index: Some(index),
        })
    }

    /// Whether the capture ends inside a record: the number of its last complete frame if so.
    /// Reads the capture from the last checkpoint of `index` to its end.
    pub(super) fn truncated_tail(&self, file: &mut DuckFile, index: &BoundaryIndex) -> Option<u64> {
        let last = index.checkpoints.last()?;
        let tail = PacketRange {
            start: PacketPosition {
                byte_offset: last.byte_offset,
                frame_number: last.frame_number,
            },
            end: None,
        };
        // A tail that cannot be read is the scan's to report, where it gets to it.
        file.seek(tail.start.byte_offset).ok()?;
        let mut reader = ReadPacketReader::at(file, index.format, index, &tail).ok()?;
        while reader.process_packets(PACKETS_PER_STEP, |_| Ok(())).ok()? > 0 {}
        reader.truncated().then(|| reader.position().frame_number)
    }
}

/// The number of rows a scan of one file is estimated to return. It is a guess from the file size: only
/// reading the capture tells how many frames it has, and how many of them a protocol is in.
pub(super) fn estimated_rows(file_size: u64, header: &StreamHeader) -> usize {
    let capture_bytes = if header.compression.is_compressed() {
        file_size.saturating_mul(ESTIMATED_COMPRESSION_RATIO)
    } else {
        file_size
    };
    usize::try_from((capture_bytes / ESTIMATED_BYTES_PER_FRAME).max(1)).unwrap_or(usize::MAX)
}
