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
//! table has, what a cell holds, which rows a frame adds, where a chunk ends and where a capture
//! can be split are decided by `pcapsql_core::scan`, the layer the DataFusion frontend runs too.
//! What is here is the DuckDB side of that layer:
//!
//! | Callback | Work | State |
//! |---|---|---|
//! | `bind` | Resolve the table, declare its columns, open the file through DuckDB's file system and probe it, estimate the row count | [`Bound`]: path, table, file size, `strict` |
//! | `init_global_state` | Map the projected columns to a `ScanPlan` and compile it; decide the partitions, which for a capture worth splitting takes one pass over it | [`Shared`]: the compiled plan, the partition queue and the index it was cut from, the progress counter |
//! | `max_threads` | The number of partitions | |
//! | `init_local_state` | Number the worker; no file yet | [`Worker`] |
//! | `claim_batch` | Claim the next partition, open the file at its offset, build the reader and the `PartitionScan` | [`Scanning`], in the worker: the scan, which owns the reader and through it the open file |
//! | `exec` | `PartitionScan::step` into a [`ChunkWriter`] over the output chunk until the chunk must be returned; no rows at the end of the partition | |
//! | `partition_data` | The ordinal of the worker's partition, as the batch index | |
//! | `progress` | Bytes read from the file by all workers over its size | |
//!
//! # Arguments
//!
//! The capture is the only positional argument. It is declared `ANY` so that a later version can
//! accept a list of files there without a new function; today anything but a `VARCHAR` is
//! refused. Everything else is a named parameter: `strict` on every function, and `protocol` on
//! `read_pcap`.
//!
//! # Partitions
//!
//! A scan reads a capture as one or more partitions: byte ranges that start at a record and
//! together cover every record once, in capture order. [`PcapScan::layout`] decides them when
//! the scan starts:
//!
//! - One partition, the whole capture read from its first byte, when the capture is compressed
//!   (a compressed stream has no place to start reading but its beginning), when DuckDB's file
//!   system reads it over a network (the pass that finds the record boundaries would read all
//!   of it first), when it is smaller than `pcapsql_parallel_min_file_size`, when DuckDB has one
//!   thread, or when `pcapsql_parallel_scan` is off. This is the scan as it was before there
//!   were partitions.
//! - Otherwise as many partitions as DuckDB has threads (`partition_target`), cut at the
//!   checkpoints of a `BoundaryIndex` that one pass over the record headers of the capture
//!   builds (`build_boundary_index`). If that pass fails (a damaged record), the capture is read
//!   as one partition and the scan reports the damage where it reads it, after the rows before
//!   it, as it always did.
//!
//! The partitions are in a `PartitionQueue`. A worker claims the next one in `claim_batch`,
//! scans it to its end and claims again; DuckDB runs up to as many workers as there are
//! partitions.
//!
//! # Row order
//!
//! A scan returns its rows in capture order without an `ORDER BY`, on any number of threads.
//! The rows of one partition are produced in order by the one worker that scans it, and
//! `partition_data` tells DuckDB which partition the rows of a chunk are from: the partition's
//! ordinal is the chunk's batch index, and DuckDB puts the chunks of several workers in
//! batch-index order wherever the order of the rows matters (a plain `SELECT`, `LIMIT`,
//! `CREATE TABLE AS`, `INSERT`).
//!
//! DuckDB wants batch indices that never decrease on one worker and that no two workers share
//! (it scrambles the result or fails with an INTERNAL error otherwise). Both hold by
//! construction: the queue hands out every ordinal once, in ascending order, so no two workers
//! hold the same one and each worker's next ordinal is larger than its last; and a worker
//! reports the ordinal of the partition it holds, which is the partition every row of the chunk
//! it just returned is from, because a chunk is never continued across a claim.
//!
//! # Errors and truncation
//!
//! A read error or a malformed record fails the query; `exec` never takes an error for the end
//! of the data. A read error is also remembered by the file reader ([`Tracked`]) and reported
//! again at the end of the partition, in case a layer in between took it for the end of the
//! file. The first worker that fails sets [`Shared::failed`]; the others stop at their next
//! call instead of reading on for a query that has failed.
//!
//! A capture that ends inside a record (a capture cut short, or one still being written) is
//! reported by the packet reader that reads to the end of the file (`PacketReader::truncated`),
//! which under a partitioned scan is the reader of the last partition. The rows of the complete
//! records are returned and a warning goes to DuckDB's log, once; with `strict := true` the
//! query fails instead.
//!
//! A scan that is not run to the end of the capture (a `LIMIT`) may not get to the broken tail.
//! A scan of one partition then reports nothing, strict or not. With several partitions the
//! worker at the end of the capture gets there whenever it does, before or after the others
//! have filled the `LIMIT`: the warning may or may not be logged, and so that a strict scan
//! does not fail by chance, a strict scan of several partitions reads the tail of the capture
//! when it starts and fails there, whatever the query goes on to read.

use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    data_chunk::DataChunkRef,
    error::DuckDBError,
    extension::Extension,
    log::{Log, LogLevel},
    signature::{FunctionParameter, FunctionParameterKind, SignatureBuilder},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, OrderPreservation, PartitionData,
        TableClaimBatchCallbacks, TableFunctionCallbacks, TablePartitioningCallbacks,
    },
    types::Any,
    Error, Result,
};
use pcapsql_core::io::{
    build_boundary_index, BoundaryIndex, Compression, DecompressReader, PacketPosition,
    PacketRange, PacketReader, ReadPacketReader, SeekCost, StreamHeader,
};
use pcapsql_core::scan::{
    partition_target, plan_ranges, Catalog, ColId, CompiledScan, FramePredicate, OutColumn,
    PartitionPolicy, PartitionQueue, PartitionScan, ScanPlan, Step, TableDef, TableId, TableScan,
};
use pcapsql_core::{default_registry, ProtocolRegistry};

use super::{
    fs::{self, DuckFile},
    guard, registry,
    settings::{self, ScanSettings},
    types,
    writer::ChunkWriter,
};

/// The table `read_pcap` reads when `protocol` is not given.
const DEFAULT_PROTOCOL: &str = "frames";

/// The log type of the records this module writes to DuckDB's log.
const LOG_TYPE: &str = "pcapsql";

/// Packets one `PartitionScan::step` may consume. A step ends earlier when the chunk is full.
const PACKETS_PER_STEP: usize = 1024;

/// Packets after which `exec` returns a chunk that holds rows but is not full.
///
/// A table with few rows per packet (`read_dns` over a capture that is mostly something else)
/// would otherwise read to the end of its partition before the first row reaches DuckDB, and a
/// `LIMIT` could not stop the scan early. A chunk without rows cannot be returned for that: it
/// ends the partition.
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
        .with_claim_batch()
        .with_partitioning()
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

/// The partitions of one scan: what [`PcapScan::layout`] decided.
#[derive(Debug)]
struct Layout {
    /// The byte ranges to scan, in capture order.
    ranges: Vec<PacketRange>,
    /// The index `ranges` were cut from. `None`: `ranges` is the whole capture, read from its
    /// first byte.
    index: Option<BoundaryIndex>,
    /// The decision in words, for the log.
    note: String,
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
}

/// What the workers of one scan share.
#[derive(Debug)]
struct Shared {
    plan: Arc<CompiledScan>,
    /// The columns of the output chunk, in its order; empty when the query needs only the
    /// number of rows.
    columns: Box<[OutColumn]>,
    /// The partitions. Each is claimed by one worker.
    queue: PartitionQueue,
    /// The index the partitions were cut from; `None` when the one partition is the whole
    /// capture (see [`Layout::index`]).
    index: Option<BoundaryIndex>,
    /// Bytes read from the file so far by all workers, for `progress`.
    file_bytes: Arc<AtomicU64>,
    /// Workers created so far: the next worker's number.
    workers: AtomicUsize,
    /// Set by the first worker whose scan fails. The others stop.
    failed: AtomicBool,
    /// Set by the worker that reports a truncated capture, so that it is reported once.
    truncation_reported: AtomicBool,
}

impl Shared {
    /// Note that the scan has failed, and pass the error on.
    fn fail(&self, error: Error) -> Error {
        self.failed.store(true, Ordering::Release);
        error
    }
}

/// A partition being scanned by a worker.
struct Scanning {
    scan: PartitionScan<ReadPacketReader<Tracked>>,
    /// The first read error of the reader stack under `scan`.
    fault: Fault,
    /// The number of the partition's first frame.
    first_frame: u64,
}

/// One worker of a scan.
struct Worker {
    /// The worker's number in its scan, for the log.
    id: usize,
    /// `None` between partitions: before the first claim, and once a partition is scanned to
    /// its end.
    scanning: Option<Scanning>,
    /// The ordinal of the partition last claimed: the batch index of the rows this worker
    /// returns until it claims again.
    ordinal: Option<usize>,
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

        // The rows come back in capture order, which `partition_data` lets DuckDB keep on
        // several threads.
        bind_handle.set_order(OrderPreservation::Insertion)?;
        // An estimate: the frames are only counted when the scan starts, and then only for a
        // capture that is split (see `layout`).
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
        let layout = self.layout(context, bound)?;
        // What the scan will do, for whoever asks DuckDB's log (`enable_logging`) why a query
        // is slow. As for the truncation warning, the log is not worth failing a query for.
        let _ = Log::log_on_context(
            context,
            LogLevel::Debug,
            &self.describe(bound, &plan, &layout),
            LOG_TYPE,
        );
        Ok(Some(Shared {
            plan: Arc::new(plan),
            columns,
            queue: PartitionQueue::new(layout.ranges),
            index: layout.index,
            file_bytes: Arc::new(AtomicU64::new(0)),
            workers: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            truncation_reported: AtomicBool::new(false),
        }))
    }

    fn max_threads(
        &self,
        _context: &Context,
        _bound: &Bound,
        shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        // A worker per partition at most; DuckDB runs no more of them than it has threads.
        let partitions = shared.map_or(1, |shared| shared.queue.len());
        Ok(NonZeroUsize::new(partitions.max(1)))
    }

    fn init_local_state(
        &self,
        _context: &Context,
        _bound: &Bound,
        shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Worker>> {
        let shared = shared.expect("init_global_state always returns a state");
        Ok(Some(Worker {
            id: shared.workers.fetch_add(1, Ordering::Relaxed),
            scanning: None,
            ordinal: None,
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

        if shared.failed.load(Ordering::Acquire) {
            // Another worker's scan failed, and with it the query: nothing more is wanted.
            worker.scanning = None;
        }
        let mut packets_before = None;
        while let Some(scanning) = worker.scanning.as_mut() {
            let scan = &mut scanning.scan;
            let before = *packets_before.get_or_insert(scan.stats().packets);
            let step = scan
                .step(std::slice::from_mut(&mut writer), PACKETS_PER_STEP)
                .map_err(|error| {
                    let frame = scan.reader().position().frame_number;
                    shared.fail(self.read_error(bound, frame, &error))
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
                    self.end_of_partition(context, bound, shared, worker, &finished)
                        .map_err(|error| shared.fail(error))?;
                }
                // Nothing more is wanted (no plan built here has a row cap, so this does not
                // happen): the rest of the partition was not read, and nothing is known about
                // it.
                Step::Done => worker.scanning = None,
            }
        }
        // A chunk without rows ends the partition, which is the case exactly when nothing is
        // left of it to read: a step only returns without rows at the end of its partition.
        // DuckDB then has the worker claim the next one.
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
        // Every worker reads ahead of the packets it has parsed, so the sum can pass the size.
        let read = shared.file_bytes.load(Ordering::Relaxed);
        Ok(Some((read as f64 / bound.file_size as f64).min(1.0)))
    }
}

impl TableClaimBatchCallbacks for PcapScan {
    /// Claim the next partition for this worker and open it. DuckDB calls this before the
    /// worker's first `exec` and after every `exec` that returned no rows.
    fn claim_batch(
        &self,
        context: &Context,
        bound: &Bound,
        worker: Option<&mut Worker>,
        shared: Option<&Shared>,
    ) -> Result<bool> {
        let shared = shared.expect("init_global_state always returns a state");
        let worker = worker.expect("init_local_state always returns a state");
        // Whatever the worker held is finished: `exec` returns no rows only then.
        worker.scanning = None;
        if shared.failed.load(Ordering::Acquire) {
            return Ok(false);
        }
        let Some((ordinal, range)) = shared.queue.claim() else {
            return Ok(false);
        };
        let scanning = self
            .open(context, bound, shared, range)
            .map_err(|error| shared.fail(error))?;
        worker.scanning = Some(scanning);
        // Larger than the worker's last ordinal, and no other worker's: see `PartitionQueue`.
        worker.ordinal = Some(ordinal);
        Ok(true)
    }
}

impl TablePartitioningCallbacks for PcapScan {
    /// The batch index of the chunk `exec` just returned on this worker: the ordinal of the
    /// partition its rows are from (see the module documentation on row order).
    fn partition_data(
        &self,
        _context: &Context,
        _bound: &Bound,
        worker: Option<&mut Worker>,
        _shared: Option<&Shared>,
        _partition_data: PartitionData<'_>,
    ) -> Result<usize> {
        // DuckDB asks after a chunk that has rows, and rows only come out of a claimed
        // partition. Should it ever ask earlier, an error is the answer: an index made up here
        // could be another worker's.
        worker
            .and_then(|worker| worker.ordinal)
            .ok_or_else(|| Error {
                code: DuckDBError::QueryExecutor,
                message: format!(
                    "{}: DuckDB asked where rows belong before the worker claimed a partition",
                    self.name
                ),
            })
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

    /// Decide the partitions of a scan (see the module documentation).
    fn layout(&self, context: &Context, bound: &Bound) -> Result<Layout> {
        let settings = ScanSettings::read(context)?;
        if !settings.parallel {
            return Ok(Layout::sequential(format_args!(
                "{} is off",
                settings::PARALLEL_SCAN
            )));
        }
        if settings.threads == 1 {
            return Ok(Layout::sequential("DuckDB has one thread"));
        }
        if fs::is_remote(context, &bound.path)? {
            return Ok(Layout::sequential("a remote file is not indexed"));
        }
        // The file as it is now, which is not that of `bind` when a prepared statement is run
        // again.
        let mut file = DuckFile::open(context, &bound.path)?;
        let header = self.probe(&mut file, &bound.path)?;
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
        let ranges = plan_ranges(Some(&index), want, &FramePredicate::all());
        if ranges.len() <= 1 {
            return Ok(Layout::sequential(format_args!(
                "{} frames give no place to split at, with a checkpoint every {} frames",
                index.packet_count, index.stride
            )));
        }
        if bound.strict {
            // Workers do not wait for each other, so the one at the end of the capture could
            // find a broken tail before or after a `LIMIT` is filled by the others. Whether a
            // strict scan fails must not depend on that: the tail is looked at now.
            if let Some(last_frame) = self.truncated_tail(&mut file, &index) {
                return Err(self.truncation_error(bound, last_frame));
            }
        }
        Ok(Layout {
            note: format!(
                "{} (of {} frames, cut at checkpoints {} frames apart)",
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
    fn truncated_tail(&self, file: &mut DuckFile, index: &BoundaryIndex) -> Option<u64> {
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

    /// Open the capture for the partition `range` and build its scan.
    fn open(
        &self,
        context: &Context,
        bound: &Bound,
        shared: &Shared,
        range: &PacketRange,
    ) -> Result<Scanning> {
        let fault = Fault::default();
        let first_frame = range.start.frame_number;
        let failed = |error: &dyn std::fmt::Display| {
            self.read_error(bound, first_frame.saturating_sub(1), error)
        };
        let reader = match &shared.index {
            // The whole capture, from its first byte.
            None => {
                let mut file = DuckFile::open(context, &bound.path)?;
                // Probed again: the header that counts is that of the file as it is read.
                let header = self.probe(&mut file, &bound.path)?;
                file.seek(0)?;
                // The decompressor is ours rather than the reader's, so that a read error
                // can be remembered between the two (`Tracked`).
                let tracked = Tracked::new(file, header.compression, shared, &fault)
                    .map_err(|error| failed(&error))?;
                let plain = StreamHeader {
                    compression: Compression::None,
                    ..header
                };
                ReadPacketReader::sequential(tracked, &plain, Vec::new())
            }
            // A range of an uncompressed capture: the file is read from the range's first
            // record, and the reader is told by the index what the capture's header said.
            Some(index) => {
                let file = DuckFile::open_at(context, &bound.path, range.start.byte_offset)?;
                let tracked = Tracked::new(file, Compression::None, shared, &fault)
                    .map_err(|error| failed(&error))?;
                ReadPacketReader::at(tracked, index.format, index, range)
            }
        }
        .map_err(|error| failed(&error))?;
        let scan = PartitionScan::new(reader, shared.plan.clone(), protocols().clone());
        Ok(Scanning {
            scan,
            fault,
            first_frame,
        })
    }

    /// One line on what a scan reads and parses.
    fn describe(&self, bound: &Bound, plan: &CompiledScan, layout: &Layout) -> String {
        let columns: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
        let columns = if columns.is_empty() {
            "none (row count)".to_owned()
        } else {
            columns.join(", ")
        };
        format!(
            "{}: scanning '{}': partitions: {}; columns: {columns}; protocols parsed: {}",
            self.name,
            bound.path,
            layout.note,
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

    /// What is wrong with a capture that ends inside the record after `last_frame`.
    fn truncation(&self, bound: &Bound, last_frame: u64) -> String {
        format!(
            "{}: '{}' is truncated: the capture ends inside the record that follows frame \
             {last_frame}, the last complete one",
            self.name, bound.path
        )
    }

    /// The error of a strict scan of such a capture.
    fn truncation_error(&self, bound: &Bound, last_frame: u64) -> Error {
        Error {
            code: DuckDBError::IoEof,
            message: format!(
                "{}; without strict := true the complete frames are returned",
                self.truncation(bound, last_frame)
            ),
        }
    }

    /// Check how the scan of a partition ended: with an error the reader swallowed, inside a
    /// record, or well.
    fn end_of_partition(
        &self,
        context: &Context,
        bound: &Bound,
        shared: &Shared,
        worker: &Worker,
        finished: &Scanning,
    ) -> Result<()> {
        let reader = finished.scan.reader();
        let last_frame = reader.position().frame_number;
        if let Some(error) = finished.fault.get() {
            return Err(self.read_error(bound, last_frame, &error));
        }
        // Which worker read what, for whoever asks the log how a scan was spread.
        let _ = Log::log_on_context(
            context,
            LogLevel::Debug,
            &format!(
                "{}: worker {} finished partition {} of {} of '{}': {} packets from frame {}",
                self.name,
                worker.id,
                worker.ordinal.map_or(0, |ordinal| ordinal + 1),
                shared.queue.len(),
                bound.path,
                finished.scan.stats().packets,
                finished.first_frame,
            ),
            LOG_TYPE,
        );
        if !reader.truncated() {
            return Ok(());
        }
        if bound.strict {
            return Err(self.truncation_error(bound, last_frame));
        }
        // Only a reader that gets to the end of the file sees this, which is one reader unless
        // the file shrank under the scan.
        if shared.truncation_reported.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        // The rows are what the query asked for; a log that cannot take the record is no
        // reason to fail it.
        let _ = Log::log_on_context(
            context,
            LogLevel::Warn,
            &format!(
                "{}; the complete frames were returned (strict := true makes this an error)",
                self.truncation(bound, last_frame)
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

/// The first read error of a worker's reader stack, which the worker cannot reach into once
/// the packet reader owns it.
#[derive(Debug, Default, Clone)]
struct Fault(Arc<Mutex<Option<String>>>);

impl Fault {
    fn get(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Keep `error` if it is the first.
    fn set(&self, error: &io::Error) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_or_insert_with(|| error.to_string());
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

/// The decompressed capture as the capture parser reads it, which keeps failing once a read
/// has failed.
///
/// The sticky error is a guard: a reader that answers a retried read after an error with "end
/// of file" would turn a failed read into a short result.
struct Tracked {
    inner: DecompressReader<Counted>,
    fault: Fault,
}

impl Tracked {
    /// `file` from its position on, decompressed, counted against the scan's progress.
    fn new(
        file: DuckFile,
        compression: Compression,
        shared: &Shared,
        fault: &Fault,
    ) -> io::Result<Self> {
        let counted = Counted {
            file,
            bytes: shared.file_bytes.clone(),
        };
        Ok(Self {
            inner: DecompressReader::new(counted, compression)?,
            fault: fault.clone(),
        })
    }
}

impl Read for Tracked {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = self.fault.get() {
            return Err(io::Error::other(error));
        }
        match self.inner.read(out) {
            Err(error) if error.kind() != io::ErrorKind::Interrupted => {
                self.fault.set(&error);
                Err(error)
            }
            result => result,
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
