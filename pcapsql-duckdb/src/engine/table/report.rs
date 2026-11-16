//! What a scan says: the line on what it reads for the log, its read and truncation errors,
//! and the check of how a partition ended.

use std::sync::atomic::Ordering;

use duckdb_neo::{
    connection::Context,
    error::DuckDBError,
    log::{Log, LogLevel},
    Error, Result,
};
use pcapsql_core::io::PacketReader;
use pcapsql_core::scan::CompiledScan;

use super::{
    layout::Layout, reader::Scanning, BindData, PcapScan, Shared, Worker, LOG_TYPE,
    PACKETS_PER_STEP,
};
use crate::engine::pushdown;

impl PcapScan {
    /// One line on what a scan reads of one of its files, and parses.
    pub(super) fn describe(&self, path: &str, plan: &CompiledScan, layout: &Layout) -> String {
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
        format!(
            "{}: scanning '{}': partitions: {}; columns: {columns}; protocols parsed: {}{filter}",
            self.name,
            path,
            layout.note,
            parsed_protocols(plan)
        )
    }

    /// The error of a read of the capture `path` that failed after `frame` complete frames.
    pub(super) fn read_error(
        &self,
        path: &str,
        frame: u64,
        error: &dyn std::fmt::Display,
    ) -> Error {
        self.error(
            DuckDBError::IoReadFailure,
            format_args!("cannot read '{path}' after frame {frame}: {error}"),
        )
    }

    /// What is wrong with the capture `path`, which ends inside the record after `last_frame`.
    pub(super) fn truncation(&self, path: &str, last_frame: u64) -> String {
        format!(
            "{}: '{path}' is truncated: the capture ends inside the record that follows frame \
             {last_frame}, the last complete one",
            self.name
        )
    }

    /// The error of a strict scan of such a capture.
    pub(super) fn truncation_error(&self, path: &str, last_frame: u64) -> Error {
        Error {
            code: DuckDBError::IoEof,
            message: format!(
                "{}; without strict := true the complete frames are returned",
                self.truncation(path, last_frame)
            ),
        }
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
