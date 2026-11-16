//! What a scan says: the line on what it reads for the log, and the check of how a partition
//! ended. The read and truncation errors are those of every function over capture files
//! ([`CaptureFunction`]).

use std::sync::atomic::Ordering;

use duckdb_neo::{
    connection::Context,
    error::DuckDBError,
    log::{Log, LogLevel},
    Error, Result,
};
use pcapsql_core::io::{PacketPosition, PacketReader, PCAPNG_FRAME_BLOCK_TYPES};
use pcapsql_core::scan::CompiledScan;

use super::{
    function::CaptureFunction, keylog::Keys, layout::Layout, reader::Scanning, BindData, PcapScan,
    Shared, Worker, LOG_TYPE, PACKETS_PER_STEP,
};
use crate::engine::{fs::DuckFile, pushdown};

impl PcapScan {
    /// One line on what a scan reads of one of its files, and parses.
    pub(super) fn describe(
        &self,
        path: &str,
        plan: &CompiledScan,
        layout: &Layout,
        keylog: Option<&Keys>,
    ) -> String {
        let columns: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
        let columns = if columns.is_empty() {
            "none (row count)".to_owned()
        } else {
            columns.join(", ")
        };
        let filter = if plan.frames().is_all() {
            String::new()
        } else {
            format!("; filter: {}", pushdown::describe(plan.frames()))
        };
        // How much the key log holds, which is what tells a wrong one from a right one.
        // Skipped entries (labels pcapsql does not read) are counted, never named.
        let keylog = keylog.map_or_else(String::new, |keys| {
            let skipped = match keys.skipped() {
                0 => String::new(),
                n => format!(" ({n} entries of other labels skipped)"),
            };
            format!(
                "; key log: secrets of {} TLS sessions{skipped}",
                keys.sessions()
            )
        });
        format!(
            "{}: scanning '{}': partitions: {}; columns: {columns}; protocols parsed: \
             {}{filter}{keylog}",
            self.name,
            path,
            layout.note,
            parsed_protocols(plan)
        )
    }

    /// Read the rest of a scan's file, packet by packet and parsing nothing, so that its reader
    /// knows whether the capture ends inside a record. A scan that got to the end reads
    /// nothing more.
    pub(super) fn read_to_the_end(&self, bound: &BindData, scanning: &mut Scanning) -> Result<()> {
        let reader = scanning.scan.reader_mut();
        loop {
            match reader.process_packets(PACKETS_PER_STEP, |_| Ok(())) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) => {
                    let frame = reader.position().frame_number;
                    return Err(self.read_error(&bound.files[scanning.file], frame, &error));
                }
            }
        }
    }

    /// Check how the scan of a partition ended: with an error the reader swallowed, inside a
    /// record, or well.
    pub(super) fn end_of_partition(
        &self,
        context: &Context,
        bound: &BindData,
        shared: &Shared,
        worker: &Worker,
        finished: &Scanning,
    ) -> Result<()> {
        let reader = finished.scan.reader();
        let last_frame = reader.position().frame_number;
        let path = bound.files[finished.file].as_str();
        if let Some(error) = finished.fault.get() {
            return Err(self.read_error(path, last_frame, &error));
        }
        // A partition that was read to its end ends where the next one starts, if the index
        // it was cut from is the index of the file as it is: the records between the two
        // checkpoints are those the index counted. The index may be one of an earlier scan
        // that the checks before the scan could not tell from that of the file (the
        // `index_cache` module), or the file changed after the pass.
        if let (Some(index), Some(end)) = (&shared.files[finished.file].index, &finished.end) {
            let filtered = shared.plan.frames().past_end(last_frame.saturating_add(1));
            let next_is_frame = || {
                index.format.is_pcapng()
                    && starts_a_frame_block(context, path, reader.source_offset())
            };
            if let Some(why) = misaligned(
                index.format.is_pcapng(),
                last_frame,
                reader.source_offset(),
                end,
                filtered,
                next_is_frame,
            ) {
                self.indexes.forget(path, index.stride);
                return Err(self.changed_error(path, &why));
            }
        }
        // Which worker read what, for whoever asks the log how a scan was spread.
        let stats = finished.scan.stats();
        let skipped = if shared.plan.frames().is_all() {
            String::new()
        } else {
            format!(", {} of them not accepted by the filter", stats.skipped)
        };
        let _ = Log::log_on_context(
            context,
            LogLevel::Debug,
            &format!(
                "{}: worker {} finished partition {} of {} of '{}': {} packets from frame \
                 {}{skipped}",
                self.name,
                worker.id,
                worker.ordinal.map_or(0, |ordinal| ordinal + 1),
                shared.queue.len(),
                path,
                stats.packets,
                finished.first_frame,
            ),
            LOG_TYPE,
        );
        if !reader.truncated() {
            return Ok(());
        }
        if bound.strict {
            return Err(self.truncation_error(path, last_frame));
        }
        // Only a reader that gets to the end of the file sees this, which is one reader unless
        // the file shrank under the scan.
        let reported = &shared.files[finished.file].truncation_reported;
        if reported.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        // The rows are what the query asked for; a log that cannot take the record is no
        // reason to fail it.
        let _ = Log::log_on_context(
            context,
            LogLevel::Warn,
            &format!(
                "{}; the complete frames were returned (strict := true makes this an error)",
                self.truncation(path, last_frame)
            ),
            LOG_TYPE,
        );
        Ok(())
    }
}

impl PcapScan {
    /// The error of a scan that found the file it reads is not the file its index is of.
    fn changed_error(&self, path: &str, why: &str) -> Error {
        self.error(
            DuckDBError::IoReadFailure,
            format_args!(
                "'{path}' changed after its index was built: {why}. Rows of the scan may be \
                 wrong. The index is dropped: run the query again"
            ),
        )
    }
}

/// Why a partition that is not the last of its file did not end where the next one starts,
/// or `None` if it did, or if it was not read that far because the filter ends it before.
///
/// `last_frame` is the number of the partition's last frame, `offset` the file offset of what
/// its reader would read next, and `end` where the next partition starts by the index.
/// `filtered`: the frame after `last_frame` is past the filter's last. In a pcapng capture
/// blocks that are not frames may come between a partition's last frame and the next
/// partition's first; `next_is_frame` says whether what is at `offset` is a block the reader
/// would number.
pub(super) fn misaligned(
    pcapng: bool,
    last_frame: u64,
    offset: u64,
    end: &PacketPosition,
    filtered: bool,
    next_is_frame: impl FnOnce() -> bool,
) -> Option<String> {
    let next = last_frame.saturating_add(1);
    if next < end.frame_number {
        // The reader ran out of records before the partition's last frame.
        return (!filtered).then(|| {
            format!(
                "by the index frame {} starts at byte {}, but the records end after frame \
                 {last_frame}",
                end.frame_number, end.byte_offset
            )
        });
    }
    let aligned =
        offset == end.byte_offset || (pcapng && offset < end.byte_offset && !next_is_frame());
    (!aligned).then(|| {
        format!(
            "by the index frame {} starts at byte {}, but frame {last_frame} ends at byte \
             {offset}",
            end.frame_number, end.byte_offset
        )
    })
}

/// Whether a pcapng block that is a frame starts at byte `offset` of `path`, in either byte
/// order: one of the types the reader and the index pass number (`PCAPNG_FRAME_BLOCK_TYPES`),
/// and no other, so that a block they pass over is not taken for a frame. A file that cannot be
/// read there says no: the scan reports what is wrong with it.
fn starts_a_frame_block(context: &Context, path: &str, offset: u64) -> bool {
    let mut block_type = [0; 4];
    let read = DuckFile::open(context, path)
        .and_then(|mut file| file.read_exact_at(offset, &mut block_type));
    read.is_ok()
        && [
            u32::from_le_bytes(block_type),
            u32::from_be_bytes(block_type),
        ]
        .iter()
        .any(|found| PCAPNG_FRAME_BLOCK_TYPES.contains(found))
}

/// The protocols the parse of a compiled plan is restricted to, each with the fields it
/// extracts when those are restricted too: `none`, `all`, or for example
/// `ethernet, ipv4, tcp (fields: dst_port)`.
pub(super) fn parsed_protocols(plan: &CompiledScan) -> String {
    let scope = plan.scope();
    let Some(required) = scope.required() else {
        return "all".to_owned();
    };
    // `frames` stands for the packet record, which is not parsed.
    let mut names: Vec<&str> = required
        .iter()
        .map(String::as_str)
        .filter(|name| *name != "frames")
        .collect();
    if names.is_empty() {
        return "none".to_owned();
    }
    names.sort_unstable();
    names
        .into_iter()
        .map(|name| match scope.projections().get(name) {
            None => name.to_owned(),
            Some(fields) if fields.is_empty() => format!("{name} (no fields)"),
            Some(fields) => {
                let mut fields: Vec<&str> = fields.iter().map(String::as_str).collect();
                fields.sort_unstable();
                format!("{name} (fields: {})", fields.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
