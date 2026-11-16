//! What every table function over capture files has in common, whatever it does with them: the
//! files argument and what it expands to, a named parameter, the probe of a capture's head, and
//! the errors that name the function.
//!
//! The scan functions ([`PcapScan`](super::PcapScan)) and `pcap_time_range`
//! ([`TimeRange`](super::time_range::TimeRange)) are the two implementations.

use duckdb_neo::{
    bind_arguments::BindArgument, connection::Context, error::DuckDBError, types::FromValue, Error,
    Result,
};
use pcapsql_core::io::StreamHeader;

use crate::engine::fs::{self, DuckFile};

/// A table function whose one positional argument names capture files.
pub(super) trait CaptureFunction {
    /// The SQL name of the function, for messages.
    fn name(&self) -> &str;

    /// An error of this function: `message` with the function's SQL name in front, as every
    /// message of such a function starts.
    fn error(&self, code: DuckDBError, message: impl std::fmt::Display) -> Error {
        Error {
            code,
            message: format!("{}: {message}", self.name()),
        }
    }

    /// An [`error`](Self::error) about what the call was given.
    fn invalid(&self, message: impl std::fmt::Display) -> Error {
        self.error(DuckDBError::InputInvalid, message)
    }

    /// The entries of the one positional argument, which is the first: the path or pattern, or
    /// those of the list, in its order.
    fn file_argument(&self, arguments: &[BindArgument]) -> Result<Vec<String>> {
        let argument = arguments
            .first()
            .ok_or_else(|| self.invalid("a capture file is required"))?;
        let value = argument
            .value
            .as_ref()
            .ok_or_else(|| self.invalid("the capture file must be a constant"))?;
        if value.is_null()? {
            return Err(self.invalid("the capture file must not be NULL"));
        }
        let entry = |value: &duckdb_neo::value::Value| -> Result<String> {
            if value.is_null()? {
                return Err(self.invalid("the capture file must not be NULL"));
            }
            let path = value.get::<String>()?.unwrap_or_default();
            if path.is_empty() {
                return Err(self.invalid("the capture file must not be an empty path"));
            }
            Ok(path)
        };
        // The type by its text, which is also what the last message quotes. Its id would not
        // tell a VARCHAR from a type defined on top of one (JSON), which is not a path.
        let declared = argument.logical_type.to_text()?;
        match declared.as_str() {
            "VARCHAR" => Ok(vec![entry(value)?]),
            // The type of `[]` is not a list of VARCHAR, whatever DuckDB calls it.
            _ if declared.ends_with("[]") && value.child_count()? == 0 => {
                Err(self.invalid("the list of capture files is empty"))
            }
            "VARCHAR[]" => value.children()?.iter().map(entry).collect(),
            _ => Err(self.invalid(format_args!(
                "the capture files must be a VARCHAR path or pattern, or a list of them, not \
                 {declared}"
            ))),
        }
    }

    /// The files of a call: every entry of the argument expanded through DuckDB's file system
    /// (see the documentation of the [`table`](super) module on files).
    fn files(&self, context: &Context, entries: &[String]) -> Result<Vec<String>> {
        let mut files = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut matched = fs::glob(context, entry)?;
            if matched.is_empty() {
                if has_wildcard(entry) {
                    return Err(self.error(
                        DuckDBError::IoFileNotFound,
                        format_args!("no file matches the pattern '{entry}'"),
                    ));
                }
                // Not a pattern: the open says what is wrong with the path.
                matched.push(entry.clone());
            }
            // `glob` promises no order.
            matched.sort_unstable();
            files.append(&mut matched);
        }
        Ok(files)
    }

    /// A named parameter. DuckDB delivers its default when the call does not give it.
    fn named<T: FromValue>(
        &self,
        arguments: &[BindArgument],
        index: usize,
        parameter: &str,
    ) -> Result<T> {
        arguments
            .get(index)
            .and_then(|argument| argument.value.as_ref())
            .map(|value| value.get::<T>())
            .transpose()?
            .flatten()
            .ok_or_else(|| {
                self.invalid(format_args!(
                    "{parameter} must be a constant and must not be NULL"
                ))
            })
    }

    /// Learn the capture's compression, format and link type from the head of `file`.
    fn probe(&self, file: &mut DuckFile, path: &str) -> Result<StreamHeader> {
        match StreamHeader::probe(file) {
            Ok((header, _head)) => Ok(header),
            Err(error) => Err(self.invalid(format_args!(
                "'{path}' is not a capture file pcapsql can read \
                 (pcap or pcapng, optionally gzip- or zstd-compressed): {error}"
            ))),
        }
    }

    /// The error of a read of the capture `path` that failed after `frame` complete frames.
    fn read_error(&self, path: &str, frame: u64, error: &dyn std::fmt::Display) -> Error {
        self.error(
            DuckDBError::IoReadFailure,
            format_args!("cannot read '{path}' after frame {frame}: {error}"),
        )
    }

    /// What is wrong with the capture `path`, which ends inside the record after `last_frame`.
    fn truncation(&self, path: &str, last_frame: u64) -> String {
        format!(
            "{}: '{path}' is truncated: the capture ends inside the record that follows frame \
             {last_frame}, the last complete one",
            self.name()
        )
    }

    /// The error of a strict read of such a capture.
    fn truncation_error(&self, path: &str, last_frame: u64) -> Error {
        Error {
            code: DuckDBError::IoEof,
            message: format!(
                "{}; without strict := true the complete frames are returned",
                self.truncation(path, last_frame)
            ),
        }
    }
}

/// Whether an entry of the files argument is a pattern rather than a path: the characters
/// DuckDB's file systems take for wildcards (`FileSystem::HasGlob`).
pub(super) fn has_wildcard(entry: &str) -> bool {
    entry.contains(['*', '?', '['])
}
