//! The scan table functions: `read_pcap(file, protocol := 'frames')` and one `read_<table>(file)`
//! per table of the catalogue this engine reads.
//!
//! ```sql
//! SELECT * FROM read_tcp('capture.pcap') WHERE dst_port = 443;
//! SELECT * FROM read_pcap('capture.pcapng.gz', protocol := 'dns');
//! SELECT count(*) FROM read_frames('capture.pcap', strict := true);
//! ```
//!
//! All of them are one implementation, [`PcapScan`], which holds no scan logic: which columns a
//! table has, what a cell holds, which rows a frame adds and where a chunk ends are decided by
//! `pcapsql_core::scan`, the layer the DataFusion frontend runs too. What is here is the DuckDB
//! side of that layer:
//!
//! | Callback | Work | State |
//! |---|---|---|
//! | `bind` | Resolve the table, declare its columns, open the file through DuckDB's file system and probe it, estimate the row count | [`Bound`]: path, table, file size, `strict` |
//! | `init_global_state` | Map the projected columns to a `ScanPlan` and compile it | [`Shared`]: the compiled plan, the progress counter, the claim on the file |
//! | `max_threads` | 1 | |
//! | `init_local_state` | Claim the file, open it, build the reader and the `PartitionScan` | [`Worker`]: the scan, which owns the reader and through it the open file |
//! | `exec` | `PartitionScan::step` into a [`ChunkWriter`] over the output chunk until the chunk must be returned | |
//! | `progress` | Bytes read from the file over its size | |
//!
//! # Arguments
//!
//! The capture is the only positional argument. It is declared `ANY` so that a later version can
//! accept a list of files there without a new function; today anything but a `VARCHAR` is
//! refused. Everything else is a named parameter: `strict` on every function, and `protocol` on
//! `read_pcap`.
//!
//! # One thread
//!
//! A scan runs on one thread, so its rows come back in capture order. The file is claimed
//! through [`Shared::claimed`] by the worker that scans it, so that even if DuckDB created a
//! second worker the capture would be read once.
//!
//! # Errors and truncation
//!
//! A read error or a malformed record fails the query; `exec` never takes an error for the end
//! of the data. A read error is also remembered by the file reader ([`Tracked`]) and reported
//! again at the end of the scan, in case a layer in between took it for the end of the file.
//!
//! A capture that ends inside a record (a capture cut short, or one still being written) is
//! detected at the end of the scan: the reader was handed more bytes than the complete records
//! it consumed. The rows of the complete records are returned and a warning goes to DuckDB's
//! log; with `strict := true` the query fails instead.

use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    data_chunk::DataChunkRef,
    error::DuckDBError,
    extension::Extension,
    log::{Log, LogLevel},
    signature::{FunctionParameter, FunctionParameterKind, SignatureBuilder},
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionCallbacks},
    types::Any,
    Error, Result,
};
use pcapsql_core::io::{
    Compression, DecompressReader, PacketReader, ReadPacketReader, StreamHeader,
};
use pcapsql_core::scan::{
    Catalog, ColId, CompiledScan, OutColumn, PartitionScan, ScanPlan, Step, TableDef, TableId,
    TableScan,
};
use pcapsql_core::{default_registry, ProtocolRegistry};

use super::{fs::DuckFile, guard, registry, types, writer::ChunkWriter};

/// The table `read_pcap` reads when `protocol` is not given.
const DEFAULT_PROTOCOL: &str = "frames";

/// The log type of the records this module writes to DuckDB's log.
const LOG_TYPE: &str = "pcapsql";

/// Packets one `PartitionScan::step` may consume. A step ends earlier when the chunk is full.
const PACKETS_PER_STEP: usize = 1024;

/// Packets after which `exec` returns a chunk that holds rows but is not full.
///
/// A table with few rows per packet (`read_dns` over a capture that is mostly something else)
/// would otherwise read to the end of the capture before the first row reaches DuckDB, and a
/// `LIMIT` could not stop the scan early. A chunk without rows cannot be returned: DuckDB takes
/// it for the end of the scan.
const PACKETS_PER_CHUNK: usize = 8 * PACKETS_PER_STEP;

/// Bytes of capture file per frame, for the row estimate DuckDB's optimizer is given at bind:
/// a record header and a few hundred bytes of packet. The true figure is between 60 bytes
/// (bare TCP ACKs) and 1,500 and more (bulk transfers).
const ESTIMATED_BYTES_PER_FRAME: u64 = 512;

/// How much larger a compressed capture is taken to be once decompressed, for the same estimate.
const ESTIMATED_COMPRESSION_RATIO: u64 = 4;

/// The parsers every scan uses, built once.
fn protocols() -> &'static Arc<ProtocolRegistry> {
    static PROTOCOLS: OnceLock<Arc<ProtocolRegistry>> = OnceLock::new();
    PROTOCOLS.get_or_init(|| Arc::new(default_registry()))
}

pub(super) fn register(extension: &Extension) -> Result<()> {
    for (table, definition) in registry::scan_tables() {
        let name = format!("read_{}", definition.name);
        builder(&name, Some(table)).register(extension)?;
    }
    builder("read_pcap", None).register(extension)
}

type Builder = duckdb_neo::table_function::TableFunctionBuilder<guard::Guarded<PcapScan>>;

fn builder(name: &str, table: Option<TableId>) -> Builder {
    let scan = PcapScan {
        name: name.to_owned(),
        table,
    };
    guard::table_function(name, scan.signature(), scan)
        .with_projection_pushdown(true)
        .with_progress()
}

/// A scan function: `read_<table>` when the table is fixed, `read_pcap` when the `protocol`
/// parameter names it.
#[derive(Debug)]
struct PcapScan {
    /// The SQL name of the function, for messages.
    name: String,
    table: Option<TableId>,
}

/// Where each argument is in the list `bind` is handed: the positional parameters, then the
/// named ones in the order [`PcapScan::signature`] declares them.
struct ArgumentPositions {
    protocol: Option<usize>,
    strict: usize,
}

impl PcapScan {
    const FILE: usize = 0;

    fn positions(&self) -> ArgumentPositions {
        match self.table {
            Some(_) => ArgumentPositions {
                protocol: None,
                strict: 1,
            },
            None => ArgumentPositions {
                protocol: Some(1),
                strict: 2,
            },
        }
    }

    fn signature(&self) -> SignatureBuilder {
        let mut signature = SignatureBuilder::new().param(FunctionParameter::new::<Any>("file"));
        if self.table.is_none() {
            signature = signature.param(
                FunctionParameter::with_default::<String>("protocol", DEFAULT_PROTOCOL.to_owned())
                    .kind(FunctionParameterKind::Named),
            );
        }
        signature.param(
            FunctionParameter::with_default::<bool>("strict", false)
                .kind(FunctionParameterKind::Named),
        )
    }

    /// The capture path: the one positional argument.
    fn file_argument(&self, arguments: &[BindArgument]) -> Result<String> {
        let name = &self.name;
        let argument = arguments
            .get(Self::FILE)
            .ok_or_else(|| Error::invalid_input(format!("{name}: a capture file is required")))?;
        let value = argument.value.as_ref().ok_or_else(|| {
            Error::invalid_input(format!("{name}: the capture file must be a constant"))
        })?;
        if value.is_null()? {
            return Err(Error::invalid_input(format!(
                "{name}: the capture file must not be NULL"
            )));
        }
        let declared = argument.logical_type.to_text()?;
        if declared.ends_with(']') {
            return Err(Error::invalid_input(format!(
                "{name}: a list of capture files is not supported yet; pass one path"
            )));
        }
        if declared != "VARCHAR" {
            return Err(Error::invalid_input(format!(
                "{name}: the capture file must be a VARCHAR path, not {declared}"
            )));
        }
        let path = value.get::<String>()?.unwrap_or_default();
        if path.is_empty() {
            return Err(Error::invalid_input(format!(
                "{name}: the capture file must not be an empty path"
            )));
        }
        Ok(path)
    }

    /// A named parameter. DuckDB delivers its default when the call does not give it.
    fn named<T: duckdb_neo::types::FromValue>(
        &self,
        arguments: &[BindArgument],
        index: usize,
        parameter: &str,
    ) -> Result<T> {
        let name = &self.name;
        arguments
            .get(index)
            .and_then(|argument| argument.value.as_ref())
            .map(|value| value.get::<T>())
            .transpose()?
            .flatten()
            .ok_or_else(|| {
                Error::invalid_input(format!(
                    "{name}: {parameter} must be a constant and must not be NULL"
                ))
            })
    }

    fn table(&self, arguments: &[BindArgument]) -> Result<(TableId, &'static TableDef)> {
        if let Some(table) = self.table {
            return Ok((table, Catalog::builtin().get(table)));
        }
        let index = self.positions().protocol.expect("read_pcap has protocol");
        let protocol: String = self.named(arguments, index, "protocol")?;
        // Table names are lower case; any case is accepted, as `pcap_schema` does.
        registry::scan_table(&protocol.to_ascii_lowercase()).ok_or_else(|| {
            Error::invalid_input(format!(
                "{}: there is no protocol table '{protocol}'; pcap_protocols() lists the tables",
                self.name
            ))
        })
    }
}

/// What `bind` learned.
#[derive(Debug)]
struct Bound {
    path: String,
    table: TableId,
    /// The columns declared to DuckDB, in declaration order: a projected column index is an
    /// index into this.
    columns: Box<[ColId]>,
    /// The size of the file in bytes at bind.
    file_size: u64,
    strict: bool,
}

/// What the workers of one scan share.
#[derive(Debug)]
struct Shared {
    plan: Arc<CompiledScan>,
    /// The columns of the output chunk, in its order; empty when the query needs only the
    /// number of rows.
    columns: Box<[OutColumn]>,
    /// Set by the worker that scans the file.
    claimed: AtomicBool,
    /// Bytes read from the file so far, for `progress`.
    file_bytes: Arc<AtomicU64>,
}

/// The state of the worker that scans the file.
struct Scanning {
    scan: PartitionScan<ReadPacketReader<Tracked>>,
    tally: Arc<Tally>,
}

/// One worker of a scan.
struct Worker {
    /// `None` for a worker that has nothing to read: another one claimed the file, or the scan
    /// has reached its end.
    scanning: Option<Scanning>,
}

impl TableFunctionCallbacks for PcapScan {
    type BindData = Bound;
    type GlobalState = Shared;
    type LocalState = Worker;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Bound> {
        let path = self.file_argument(&arguments)?;
        let (table, definition) = self.table(&arguments)?;
        let strict: bool = self.named(&arguments, self.positions().strict, "strict")?;

        let mut columns = Vec::new();
        for (id, column) in registry::exposed_columns(definition) {
            let logical_type = types::logical_type(context, types::column_kind(column))?;
            bind_handle.add_result_column(column.name, &logical_type)?;
            columns.push(id);
        }

        // Open and probe now, so that a file that is missing, out of bounds for the session or
        // not a capture fails the statement at bind, with the path in the message.
        let mut file = DuckFile::open(context, &path)?;
        let file_size = file.size()?;
        let header = self.probe(&mut file, &path)?;

        bind_handle.set_cardinality(estimated_rows(file_size, &header), false)?;
        Ok(Bound {
            path,
            table,
            columns: columns.into(),
            file_size,
            strict,
        })
    }

    fn init_global_state(
        &self,
        context: &Context,
        bound: &Bound,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<Shared>> {
        let projected = (0..column_data.count()?)
            .map(|position| column_data.get_column_index(position))
            .collect::<Result<Vec<_>>>()?;
        let columns = self.projected_columns(bound, &projected)?;
        let plan = ScanPlan {
            tables: vec![TableScan::new(bound.table, columns)],
            timestamps: types::TIMESTAMPS,
            ..ScanPlan::default()
        }
        .compile(Catalog::builtin(), protocols())
        .map_err(|error| Error {
            code: DuckDBError::QueryPlanner,
            message: format!("{}: {error}", self.name),
        })?;
        let columns = plan.outputs()[0].columns.clone();
        // What the scan will do, for whoever asks DuckDB's log (`enable_logging`) why a query
        // is slow. As for the truncation warning, the log is not worth failing a query for.
        let _ = Log::log_on_context(
            context,
            LogLevel::Debug,
            &self.describe(bound, &plan),
            LOG_TYPE,
        );
        Ok(Some(Shared {
            plan: Arc::new(plan),
            columns,
            claimed: AtomicBool::new(false),
            file_bytes: Arc::new(AtomicU64::new(0)),
        }))
    }

    fn max_threads(
        &self,
        _context: &Context,
        _bound: &Bound,
        _shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        Ok(NonZeroUsize::new(1))
    }

    fn init_local_state(
        &self,
        context: &Context,
        bound: &Bound,
        shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Worker>> {
        let shared = shared.expect("init_global_state always returns a state");
        if shared.claimed.swap(true, Ordering::AcqRel) {
            return Ok(Some(Worker { scanning: None }));
        }

        let mut file = DuckFile::open(context, &bound.path)?;
        // Probed again: the header that counts is that of the file as it is read.
        let header = self.probe(&mut file, &bound.path)?;
        file.seek(0)?;

        let tally = Arc::new(Tally::default());
        let counted = Counted {
            file,
            bytes: shared.file_bytes.clone(),
        };
        // The decompressor is ours rather than the reader's, so that the bytes the capture
        // parser is handed can be counted (`Tracked`).
        let decoded = DecompressReader::new(counted, header.compression)
            .map_err(|error| self.read_error(bound, 0, &error))?;
        let tracked = Tracked {
            inner: decoded,
            tally: tally.clone(),
        };
        let plain = StreamHeader {
            compression: Compression::None,
            ..header
        };
        let reader = ReadPacketReader::sequential(tracked, &plain, Vec::new())
            .map_err(|error| self.read_error(bound, 0, &error))?;
        let scan = PartitionScan::new(reader, shared.plan.clone(), protocols().clone());
        Ok(Some(Worker {
            scanning: Some(Scanning { scan, tally }),
        }))
    }

    fn exec(
        &self,
        context: &Context,
        bound: &Bound,
        worker: Option<&mut Worker>,
        shared: Option<&Shared>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let shared = shared.expect("init_global_state always returns a state");
        let worker = worker.expect("init_local_state always returns a state");
        let mut writer = ChunkWriter::new(output, &shared.columns)?;

        let mut packets_before = None;
        while let Some(scanning) = worker.scanning.as_mut() {
            let scan = &mut scanning.scan;
            let before = *packets_before.get_or_insert(scan.stats().packets);
            let step = scan
                .step(std::slice::from_mut(&mut writer), PACKETS_PER_STEP)
                .map_err(|error| {
                    let frame = scan.reader().position().frame_number;
                    self.read_error(bound, frame, &error)
                })?;
            match step {
                // The chunk is full: it goes back to DuckDB before the scan is stepped again.
                Step::Flush(_) => break,
                Step::More => {
                    let read = scan.stats().packets - before;
                    if writer.rows() > 0 && read >= PACKETS_PER_CHUNK as u64 {
                        break;
                    }
                }
                Step::End => {
                    let finished = worker.scanning.take().expect("the scan was just stepped");
                    self.end_of_capture(context, bound, &finished)?;
                }
                // Nothing more is wanted (no plan built here has a row cap, so this does not
                // happen): the rest of the capture was not read, and nothing is known about it.
                Step::Done => worker.scanning = None,
            }
        }
        // A chunk without rows ends the scan, which is the case exactly when nothing is left
        // to read: a step only returns without rows at the end of the capture.
        writer.finish()?;
        Ok(())
    }

    fn progress(
        &self,
        _context: &Context,
        bound: &Bound,
        shared: Option<&Shared>,
    ) -> Result<Option<f64>> {
        let Some(shared) = shared else {
            return Ok(None);
        };
        if bound.file_size == 0 {
            return Ok(None);
        }
        let read = shared.file_bytes.load(Ordering::Relaxed);
        Ok(Some((read as f64 / bound.file_size as f64).min(1.0)))
    }
}

impl PcapScan {
    /// The catalogue columns of a projection DuckDB reports, in its order.
    ///
    /// DuckDB always projects at least one column. For a query that needs no column
    /// (`count(*)`) it is either a declared column of DuckDB's choosing, which is then read like
    /// any other, or DuckDB's row identifier, which is not a declared column: the plan then has
    /// no columns, and the scan layer only counts the rows.
    fn projected_columns(&self, bound: &Bound, projected: &[usize]) -> Result<Vec<ColId>> {
        let declared: Vec<Option<ColId>> = projected
            .iter()
            .map(|&index| bound.columns.get(index).copied())
            .collect();
        if declared.iter().all(Option::is_none) {
            return Ok(Vec::new());
        }
        let all: Option<Vec<ColId>> = declared.into_iter().collect();
        all.ok_or_else(|| Error {
            code: DuckDBError::QueryNotImplemented,
            message: format!(
                "{}: DuckDB asked for a column the function did not declare \
                 (columns {projected:?} of {})",
                self.name,
                bound.columns.len()
            ),
        })
    }

    /// One line on what a scan reads and parses.
    fn describe(&self, bound: &Bound, plan: &CompiledScan) -> String {
        let columns: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
        let columns = if columns.is_empty() {
            "none (row count)".to_owned()
        } else {
            columns.join(", ")
        };
        format!(
            "{}: scanning '{}': columns: {columns}; protocols parsed: {}",
            self.name,
            bound.path,
            parsed_protocols(plan)
        )
    }

    /// Learn the capture's compression, format and link type from the head of `file`.
    fn probe(&self, file: &mut DuckFile, path: &str) -> Result<StreamHeader> {
        match StreamHeader::probe(file) {
            Ok((header, _head)) => Ok(header),
            Err(error) => Err(Error {
                code: DuckDBError::InputInvalid,
                message: format!(
                    "{}: '{path}' is not a capture file pcapsql can read \
                     (pcap or pcapng, optionally gzip- or zstd-compressed): {error}",
                    self.name
                ),
            }),
        }
    }

    /// The error of a read that failed after `frame` complete frames.
    fn read_error(&self, bound: &Bound, frame: u64, error: &dyn std::fmt::Display) -> Error {
        Error {
            code: DuckDBError::IoReadFailure,
            message: format!(
                "{}: cannot read '{}' after frame {frame}: {error}",
                self.name, bound.path
            ),
        }
    }

    /// Check how the scan ended: with an error the reader swallowed, inside a record, or well.
    fn end_of_capture(&self, context: &Context, bound: &Bound, finished: &Scanning) -> Result<()> {
        let position = finished.scan.reader().position();
        if let Some(error) = finished.tally.error() {
            return Err(self.read_error(bound, position.frame_number, &error));
        }
        let handed = finished.tally.bytes.load(Ordering::Relaxed);
        let Some(left_over) = handed.checked_sub(position.byte_offset).filter(|n| *n > 0) else {
            return Ok(());
        };
        let message = format!(
            "{}: '{}' is truncated: the capture ends inside a record ({left_over} bytes follow \
             frame {}, the last complete one, which ends at byte {} of the capture)",
            self.name, bound.path, position.frame_number, position.byte_offset
        );
        if bound.strict {
            return Err(Error {
                code: DuckDBError::IoEof,
                message: format!(
                    "{message}; without strict := true the complete frames are returned"
                ),
            });
        }
        // The rows are what the query asked for; a log that cannot take the record is no
        // reason to fail it.
        let _ = Log::log_on_context(
            context,
            LogLevel::Warn,
            &format!(
                "{message}; the complete frames were returned (strict := true makes this an error)"
            ),
            LOG_TYPE,
        );
        Ok(())
    }
}

/// The protocols the parse of a compiled plan is restricted to, each with the fields it
/// extracts when those are restricted too: `none`, `all`, or for example
/// `ethernet, ipv4, tcp (fields: dst_port)`.
fn parsed_protocols(plan: &CompiledScan) -> String {
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

/// The number of rows a scan is estimated to return. It is a guess from the file size: only
/// reading the capture tells how many frames it has, and how many of them a protocol is in.
fn estimated_rows(file_size: u64, header: &StreamHeader) -> usize {
    let capture_bytes = if header.compression.is_compressed() {
        file_size.saturating_mul(ESTIMATED_COMPRESSION_RATIO)
    } else {
        file_size
    };
    usize::try_from((capture_bytes / ESTIMATED_BYTES_PER_FRAME).max(1)).unwrap_or(usize::MAX)
}

/// What a worker's reader stack reports to the worker, which cannot reach into the stack once
/// the packet reader owns it.
#[derive(Debug, Default)]
struct Tally {
    /// Bytes of (decompressed) capture handed to the capture parser.
    bytes: AtomicU64,
    /// The first read error.
    error: Mutex<Option<String>>,
}

impl Tally {
    fn error(&self) -> Option<String> {
        self.error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// The capture file, counting the bytes read from it for `progress`.
struct Counted {
    file: DuckFile,
    bytes: Arc<AtomicU64>,
}

impl Read for Counted {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.file.read(out)?;
        self.bytes.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

/// The decompressed capture as the capture parser reads it: counts the bytes it hands out and
/// keeps failing once a read has failed.
///
/// The count is how a truncated capture is told from a complete one (see the module
/// documentation). The sticky error is a guard: a reader that answers a retried read after an
/// error with "end of file" would turn a failed read into a short result.
struct Tracked {
    inner: DecompressReader<Counted>,
    tally: Arc<Tally>,
}

impl Read for Tracked {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = self.tally.error() {
            return Err(io::Error::other(error));
        }
        match self.inner.read(out) {
            Ok(read) => {
                self.tally.bytes.fetch_add(read as u64, Ordering::Relaxed);
                Ok(read)
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(error),
            Err(error) => {
                let mut first = self
                    .tally
                    .error
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                first.get_or_insert_with(|| error.to_string());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(table: &str) -> (Bound, &'static TableDef) {
        let (id, definition) = registry::scan_table(table).unwrap();
        let bound = Bound {
            path: "x.pcap".to_owned(),
            table: id,
            columns: registry::exposed_columns(definition)
                .map(|(id, _)| id)
                .collect(),
            file_size: 0,
            strict: false,
        };
        (bound, definition)
    }

    fn scan(table: &str) -> PcapScan {
        PcapScan {
            name: format!("read_{table}"),
            table: registry::scan_table(table).map(|(id, _)| id),
        }
    }

    /// The plan `init_global_state` compiles for a projection.
    fn compiled(table: &str, projected: &[usize]) -> CompiledScan {
        let (bound, _) = bound(table);
        let columns = scan(table).projected_columns(&bound, projected).unwrap();
        ScanPlan {
            tables: vec![TableScan::new(bound.table, columns)],
            timestamps: types::TIMESTAMPS,
            ..ScanPlan::default()
        }
        .compile(Catalog::builtin(), protocols())
        .unwrap()
    }

    #[test]
    fn a_frames_projection_parses_no_protocol() {
        let (bound, definition) = bound("frames");
        let all: Vec<usize> = (0..bound.columns.len()).collect();
        // frame_number alone, every column, and no column at all (a row count).
        for projection in [&[0][..], &all[..], &[usize::MAX][..]] {
            let plan = compiled("frames", projection);
            assert_eq!(parsed_protocols(&plan), "none", "{projection:?}");
            assert!(plan.scope().projections().is_empty());
        }
        assert_eq!(definition.columns[0].name, "frame_number");
    }

    #[test]
    fn a_protocol_table_parses_its_protocol_and_what_it_depends_on_only() {
        let plan = compiled("tcp", &[0]);
        let protocols = parsed_protocols(&plan);
        assert!(protocols.contains("tcp (no fields)"), "{protocols}");
        // Nothing above TCP. (UDP is there: a tunnel over UDP can carry TCP.)
        for other in ["dns", "http", "tls", "icmp", "bgp", "arp"] {
            assert!(!protocols.contains(other), "{protocols}");
        }
        // frame_number comes from the packet record: no TCP field is extracted for it.
        assert_eq!(
            plan.scope()
                .projections()
                .get("tcp")
                .map(|fields| fields.len()),
            Some(0)
        );

        // A field column extracts that field and no other.
        let (bound, definition) = bound("tcp");
        let dst_port = bound
            .columns
            .iter()
            .position(|id| definition.get(*id).name == "dst_port")
            .unwrap();
        let plan = compiled("tcp", &[0, dst_port]);
        let fields = &plan.scope().projections()["tcp"];
        assert_eq!(fields.len(), 1);
        assert!(fields.contains("dst_port"));
        assert!(parsed_protocols(&plan).contains("tcp (fields: dst_port)"));

        // Every column: the parser runs unprojected.
        let all: Vec<usize> = (0..bound.columns.len()).collect();
        let protocols = parsed_protocols(&compiled("tcp", &all));
        assert!(protocols.contains("tcp, "), "{protocols}");
    }

    #[test]
    fn the_output_columns_follow_the_projection_order() {
        let (bound, definition) = bound("tcp");
        let index = |name: &str| {
            bound
                .columns
                .iter()
                .position(|id| definition.get(*id).name == name)
                .unwrap()
        };
        let plan = compiled("tcp", &[index("dst_port"), index("timestamp"), 0]);
        let names: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
        assert_eq!(names, ["dst_port", "timestamp", "frame_number"]);
        // The opt-in timestamp of a protocol table, in this engine's unit.
        assert_eq!(
            types::sql_name(plan.outputs()[0].columns[1].kind),
            "TIMESTAMP_NS"
        );
    }

    #[test]
    fn a_projection_of_no_declared_column_counts_rows() {
        let (bound, _) = bound("udp");
        let scan = scan("udp");
        assert!(scan
            .projected_columns(&bound, &[usize::MAX])
            .unwrap()
            .is_empty());
        assert!(scan.projected_columns(&bound, &[]).unwrap().is_empty());
        // A mix of declared and undeclared columns is refused, not guessed at.
        let error = scan
            .projected_columns(&bound, &[0, usize::MAX])
            .unwrap_err();
        assert_eq!(error.code, DuckDBError::QueryNotImplemented);
        assert!(error.message.starts_with("read_udp: "), "{}", error.message);
    }

    #[test]
    fn every_scan_table_gets_a_function_and_none_is_called_pcap() {
        // `read_pcap` is the generic function; a table of that name would collide with it.
        assert!(registry::scan_table("pcap").is_none());
        assert!(registry::scan_table(DEFAULT_PROTOCOL).is_some());
        for (id, _) in registry::scan_tables() {
            let function = PcapScan {
                name: String::new(),
                table: Some(id),
            };
            assert_eq!(function.positions().strict, 1);
        }
    }

    #[test]
    fn the_row_estimate_grows_with_the_file_and_is_never_zero() {
        let header = |compression| StreamHeader {
            compression,
            format: pcapsql_core::io::PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 65535,
            header_len: 24,
        };
        let plain = header(Compression::None);
        assert_eq!(estimated_rows(0, &plain), 1);
        assert_eq!(estimated_rows(24, &plain), 1);
        assert_eq!(estimated_rows(512 * 1000, &plain), 1000);
        assert_eq!(estimated_rows(512 * 1000, &header(Compression::Gzip)), 4000);
        assert!(estimated_rows(u64::MAX, &header(Compression::Gzip)) > 0);
    }
}
