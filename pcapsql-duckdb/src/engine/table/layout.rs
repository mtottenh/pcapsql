//! The partitions of one file of a scan, and the row estimate of a file.

use duckdb_neo::{connection::Context, Result};
use pcapsql_core::io::{
    build_boundary_index, BoundaryIndex, PacketPosition, PacketRange, PacketReader,
    ReadPacketReader, SeekCost, StreamHeader,
};
use pcapsql_core::scan::{partition_target, plan_ranges, FramePredicate, PartitionPolicy};

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

/// The partitions of one file: what [`PcapScan::layout`] decided.
#[derive(Debug)]
pub(super) struct Layout {
    /// The byte ranges to scan, in capture order.
    pub(super) ranges: Vec<PacketRange>,
    /// The index `ranges` were cut from. `None`: `ranges` is the whole capture, read from its
    /// first byte.
    pub(super) index: Option<BoundaryIndex>,
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

impl PcapScan {
    /// Decide the partitions of one file of a scan (see the module documentation).
    pub(super) fn layout(
        &self,
        context: &Context,
        settings: &ScanSettings,
        path: &str,
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
        if header.compression.is_compressed() {
            return Ok(Layout::sequential("a compressed capture cannot be split"));
        }
        let size = file.size()?;
        let policy = PartitionPolicy {
            cheap_min_bytes: settings.min_file_size,
            ..PartitionPolicy::default()
        };
        let want = partition_target(SeekCost::Cheap, size, None, settings.threads, &policy);
        if want <= 1 {
            return Ok(Layout::sequential(format_args!(
                "{size} bytes is less than {} = {}",
                settings::PARALLEL_MIN_FILE_SIZE,
                settings.min_file_size
            )));
        }

        // One pass over the record headers. Nothing is kept of the index beyond this scan, so
        // what would tell a later reader that the file has changed is left out.
        file.seek(0)?;
        let built = build_boundary_index(
            &mut file,
            header.format,
            settings.index_stride,
            size,
            None,
            0,
        );
        let index = match built {
            Ok(index) => index,
            // A record the pass cannot get past. The scan cannot either, but it returns the
            // rows before it first and then says where it is.
            Err(error) => {
                return Ok(Layout::sequential(format_args!(
                    "the index pass failed: {error}"
                )))
            }
        };
        let whole = plan_ranges(Some(&index), want, &FramePredicate::all()).len();
        if whole <= 1 {
            return Ok(Layout::sequential(format_args!(
                "{} frames give no place to split at, with a checkpoint every {} frames",
                index.packet_count, index.stride
            )));
        }
        if strict {
            // Workers do not wait for each other, so the one at the end of the capture could
            // find a broken tail before or after a `LIMIT` is filled by the others. Whether a
            // strict scan fails must not depend on that: the tail is looked at now.
            if let Some(last_frame) = self.truncated_tail(&mut file, &index) {
                return Err(self.truncation_error(path, last_frame));
            }
        }
        // The partitions, without those the filter rules out and each shrunk to the checkpoint
        // windows that may hold a frame it accepts. There may be none left.
        let ranges = plan_ranges(Some(&index), want, frames);
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
                "{} (of {} frames, cut at checkpoints {} frames apart{filtered})",
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
