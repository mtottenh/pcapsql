//! `pcap_time_range(files)`: when each capture begins and ends, and how many frames it has.
//!
//! ```sql
//! SELECT * FROM pcap_time_range('capture.pcap');
//! SELECT min(start_time), max(end_time), sum(frames) FROM pcap_time_range('logs/*.pcap.gz');
//! ```
//!
//! One row per file. It is what the macros `start_time(files)`, `end_time(files)` and
//! `relative_time(ts, files)` are defined over (`engine::macros`): the command-line tool has
//! one capture per session and its functions of these names take none; DuckDB has no capture
//! of the session, so here the capture is an argument.
//!
//! | Column | Type | |
//! |---|---|---|
//! | `filename` | `VARCHAR` | The path of the file, as the files argument expanded to it |
//! | `start_time` | `TIMESTAMP_NS` | The smallest timestamp of a frame; NULL without frames |
//! | `end_time` | `TIMESTAMP_NS` | The largest; NULL without frames |
//! | `frames` | `UBIGINT` | The number of complete frames |
//! | `duration` | `DOUBLE` | Seconds from `start_time` to `end_time`; NULL without frames |
//! | `link_type` | `UINTEGER` | The link type the capture's header declares (pcapng: its first interface) |
//! | `truncated` | `BOOLEAN` | Whether the capture ends inside a record |
//!
//! The smallest and largest timestamp are not those of the first and last frame when the
//! frames are not in time order: the range is over all of them, as the command-line tool's is.
//!
//! # How a file is read
//!
//! The files argument is that of the scan functions ([`CaptureFunction`]): a path, a pattern
//! or a list, expanded, opened and probed at bind. A row is the result of one pass over the
//! records of its file, through the packet reader the scans use (compressed captures
//! included), which reads every record and parses none: no protocol parser runs and no
//! `PartitionScan` is built. Nothing already knows the range: the extension keeps no index of
//! a capture between statements (the boundary index of a split scan is built by that scan,
//! from a pass like this one, and dropped with it), so there is none to ask.
//!
//! Each `exec` call claims one file and returns its row, so DuckDB reads several files on
//! several threads. The rows therefore come back in no particular order; `ORDER BY filename`
//! where it matters.
//!
//! # Truncation
//!
//! As for a scan: a capture that ends inside a record gives the row of its complete frames,
//! here with `truncated` true instead of a warning in the log, and with `strict := true` the
//! statement fails. The pass always reads to the end of the file, so unlike a scan under a
//! `LIMIT` it always finds a broken tail.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    data_chunk::DataChunkRef,
    extension::Extension,
    signature::{FunctionParameter, FunctionParameterKind, SignatureBuilder},
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionCallbacks},
    types::Any,
    Result,
};
use pcapsql_core::io::{Compression, PacketReader, ReadPacketReader, StreamHeader};
use pcapsql_core::scan::{ColKind, ColumnSource, OutCol, OutColumn, RowSink};

use super::function::CaptureFunction;
use super::reader::{Fault, Tracked};
use super::PACKETS_PER_STEP;
use crate::engine::{fs::DuckFile, guard, types, writer::ChunkWriter};

/// The SQL name of the function.
const NAME: &str = "pcap_time_range";

/// Where `strict` is in the arguments of `bind`: after the files.
const STRICT: usize = 1;

pub(super) fn register(extension: &Extension) -> Result<()> {
    let signature = SignatureBuilder::new()
        .param(FunctionParameter::new::<Any>("files"))
        .param(
            FunctionParameter::with_default::<bool>("strict", false)
                .kind(FunctionParameterKind::Named),
        );
    guard::table_function(NAME, signature, TimeRange).register(extension)
}

const fn column(name: &'static str, kind: ColKind, nullable: bool) -> OutColumn {
    OutColumn {
        name,
        kind,
        nullable,
        source: ColumnSource::Field(name),
    }
}

/// The columns, in the order of the constants below.
const COLUMNS: &[OutColumn] = &[
    column("filename", ColKind::Str, false),
    column("start_time", ColKind::TsNanos, true),
    column("end_time", ColKind::TsNanos, true),
    column("frames", ColKind::U64, false),
    column("duration", ColKind::F64, true),
    column("link_type", ColKind::U32, false),
    column("truncated", ColKind::Bool, false),
];
const FILENAME: OutCol = OutCol(0);
const START_TIME: OutCol = OutCol(1);
const END_TIME: OutCol = OutCol(2);
const FRAMES: OutCol = OutCol(3);
const DURATION: OutCol = OutCol(4);
const LINK_TYPE: OutCol = OutCol(5);
const TRUNCATED: OutCol = OutCol(6);

/// `pcap_time_range`.
#[derive(Debug)]
pub(super) struct TimeRange;

impl CaptureFunction for TimeRange {
    fn name(&self) -> &str {
        NAME
    }
}

/// What `bind` learned.
#[derive(Debug)]
pub(super) struct Bound {
    /// The paths of the files, in the order of the argument. Never empty.
    files: Box<[String]>,
    strict: bool,
}

/// What one pass over the records of a capture finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Summary {
    /// The smallest and the largest timestamp of a frame, in nanoseconds; `None` without
    /// frames.
    range_ns: Option<(i64, i64)>,
    /// Complete frames.
    frames: u64,
    /// The link type of the capture's header.
    link_type: u32,
    /// Whether the capture ends inside a record.
    truncated: bool,
}

impl Summary {
    /// Seconds from the first timestamp to the last.
    fn duration(&self) -> Option<f64> {
        // The difference first: a timestamp of this century has more digits than an f64.
        self.range_ns
            .map(|(start, end)| end.saturating_sub(start) as f64 / 1e9)
    }
}

/// Read the records of `reader` to its end and summarize them. `link_type` is what the
/// capture's header declares.
fn summarize<R: PacketReader>(
    reader: &mut R,
    link_type: u32,
) -> std::result::Result<Summary, pcapsql_core::Error> {
    let mut range_ns: Option<(i64, i64)> = None;
    let mut frames = 0_u64;
    loop {
        let delivered = reader.process_packets(PACKETS_PER_STEP, |packet| {
            let at = packet.timestamp_ns;
            range_ns = Some(range_ns.map_or((at, at), |(start, end)| (start.min(at), end.max(at))));
            frames += 1;
            Ok(())
        })?;
        if delivered == 0 {
            break;
        }
    }
    Ok(Summary {
        range_ns,
        frames,
        link_type,
        truncated: reader.truncated(),
    })
}

impl TimeRange {
    /// One pass over the capture `path`.
    fn read(&self, context: &Context, path: &str, strict: bool) -> Result<Summary> {
        let fault = Fault::default();
        // The file as it is now, which is not that of `bind` when a prepared statement is run
        // again.
        let mut file = DuckFile::open(context, path)?;
        let header = self.probe(&mut file, path)?;
        file.seek(0)?;
        let failed =
            |frame: u64, error: &dyn std::fmt::Display| self.read_error(path, frame, error);
        // The reader stack of a scan's whole-capture partition. Nobody asks how far this pass
        // is, so the bytes it counts are not looked at.
        let tracked = Tracked::new(
            file,
            header.compression,
            &Arc::new(AtomicU64::new(0)),
            &fault,
        )
        .map_err(|error| failed(0, &error))?;
        let plain = StreamHeader {
            compression: Compression::None,
            ..header
        };
        let mut reader = ReadPacketReader::sequential(tracked, &plain, Vec::new())
            .map_err(|error| failed(0, &error))?;
        let summary = summarize(&mut reader, header.link_type)
            .map_err(|error| failed(reader.position().frame_number, &error))?;
        // A read error a layer in between took for the end of the file.
        if let Some(error) = fault.get() {
            return Err(failed(summary.frames, &error));
        }
        if summary.truncated && strict {
            return Err(self.truncation_error(path, summary.frames));
        }
        Ok(summary)
    }
}

impl TableFunctionCallbacks for TimeRange {
    type BindData = Bound;
    /// The index of the next file no `exec` call has claimed.
    type GlobalState = AtomicUsize;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Bound> {
        let entries = self.file_argument(&arguments)?;
        let strict: bool = self.named(&arguments, STRICT, "strict")?;
        for column in COLUMNS {
            let logical_type = types::logical_type(context, column.kind)?;
            bind_handle.add_result_column(column.name, &logical_type)?;
        }
        // Opened and probed now, as a scan does, so that a file that is missing, out of bounds
        // for the session or not a capture fails the statement at bind.
        let files = self.files(context, &entries)?;
        for path in &files {
            let mut file = DuckFile::open(context, path)?;
            self.probe(&mut file, path)?;
        }
        bind_handle.set_cardinality(files.len(), true)?;
        Ok(Bound {
            files: files.into(),
            strict,
        })
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bound: &Bound,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicUsize>> {
        Ok(Some(AtomicUsize::new(0)))
    }

    fn max_threads(
        &self,
        _context: &Context,
        bound: &Bound,
        _next: Option<&AtomicUsize>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<std::num::NonZeroUsize>> {
        // A file is read by one call; DuckDB runs no more of them at once than it has threads.
        Ok(std::num::NonZeroUsize::new(bound.files.len()))
    }

    fn exec(
        &self,
        context: &Context,
        bound: &Bound,
        _local_state: Option<&mut ()>,
        next: Option<&AtomicUsize>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let next = next.expect("init_global_state always returns a state");
        // Projection pushdown is off, so the chunk holds every declared column in order.
        let mut writer = ChunkWriter::new(output, COLUMNS)?;
        // Claimed atomically: every file is read by exactly one call, on whatever thread. A
        // call that finds none left returns no row, which ends the scan on its thread.
        let claimed = next.fetch_add(1, Ordering::Relaxed);
        if let Some(path) = bound.files.get(claimed) {
            let summary = self.read(context, path, bound.strict)?;
            writer.str(FILENAME, path);
            match summary.range_ns {
                Some((start, end)) => {
                    writer.timestamp(START_TIME, start);
                    writer.timestamp(END_TIME, end);
                }
                None => {
                    writer.null(START_TIME);
                    writer.null(END_TIME);
                }
            }
            writer.u64(FRAMES, summary.frames);
            match summary.duration() {
                Some(seconds) => writer.f64(DURATION, seconds),
                None => writer.null(DURATION),
            }
            writer.u32(LINK_TYPE, summary.link_type);
            writer.bool(TRUNCATED, summary.truncated);
            // One row a call: the chunk is never full.
            let _ = writer.end_row();
        }
        writer.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pcapsql_core::io::Compression;
    use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};

    use super::*;

    fn summary_of(bytes: &[u8]) -> Summary {
        let mut head = bytes;
        let (header, _) = StreamHeader::probe(&mut head).unwrap();
        assert_eq!(header.compression, Compression::None);
        let mut reader = ReadPacketReader::sequential(bytes, &header, Vec::new()).unwrap();
        summarize(&mut reader, header.link_type).unwrap()
    }

    fn packet(ts_sec: u32, ts_frac: u32) -> GenPacket {
        GenPacket {
            ts_sec,
            ts_frac,
            data: vec![0; 60],
            origlen: 60,
        }
    }

    #[test]
    fn the_range_is_over_all_frames_not_the_first_and_last() {
        let capture = legacy_pcap(
            LegacyVariant::LeNano,
            1,
            65535,
            &[packet(5, 7), packet(1, 1), packet(9, 3), packet(0, 2)],
        );
        let summary = summary_of(&capture.bytes);
        assert_eq!(summary.range_ns, Some((2, 9_000_000_003)));
        assert_eq!(summary.frames, 4);
        assert_eq!(summary.link_type, 1);
        assert!(!summary.truncated);
        assert_eq!(summary.duration(), Some(9.000000001));
    }

    #[test]
    fn the_duration_is_exact_for_timestamps_an_f64_cannot_hold() {
        // 2024: more than 2^53 nanoseconds since 1970.
        let capture = legacy_pcap(
            LegacyVariant::LeNano,
            1,
            65535,
            &[packet(1_704_067_200, 1), packet(1_704_067_200, 3)],
        );
        let summary = summary_of(&capture.bytes);
        assert_eq!(summary.duration(), Some(2e-9));
    }

    #[test]
    fn a_capture_without_frames_has_no_range() {
        let capture = legacy_pcap(LegacyVariant::LeMicro, 101, 65535, &[]);
        let summary = summary_of(&capture.bytes);
        assert_eq!(
            summary,
            Summary {
                range_ns: None,
                frames: 0,
                link_type: 101,
                truncated: false,
            }
        );
        assert_eq!(summary.duration(), None);
    }

    #[test]
    fn a_capture_cut_inside_a_record_is_summarized_up_to_it() {
        let capture = legacy_pcap(
            LegacyVariant::LeMicro,
            1,
            65535,
            &[packet(1, 0), packet(3, 0), packet(7, 0)],
        );
        let cut = &capture.bytes[..capture.bytes.len() - 10];
        let summary = summary_of(cut);
        assert_eq!(summary.range_ns, Some((1_000_000_000, 3_000_000_000)));
        assert_eq!(summary.frames, 2);
        assert!(summary.truncated);
        assert_eq!(summary.duration(), Some(2.0));
    }

    #[test]
    fn the_columns_are_in_the_order_of_their_constants() {
        let names: Vec<&str> = COLUMNS.iter().map(|column| column.name).collect();
        assert_eq!(names[usize::from(FILENAME.0)], "filename");
        assert_eq!(names[usize::from(START_TIME.0)], "start_time");
        assert_eq!(names[usize::from(END_TIME.0)], "end_time");
        assert_eq!(names[usize::from(FRAMES.0)], "frames");
        assert_eq!(names[usize::from(DURATION.0)], "duration");
        assert_eq!(names[usize::from(LINK_TYPE.0)], "link_type");
        assert_eq!(names[usize::from(TRUNCATED.0)], "truncated");
        assert_eq!(names.len(), 7);
    }
}
