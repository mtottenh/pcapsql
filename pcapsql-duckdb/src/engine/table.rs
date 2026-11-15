//! The scan table functions: `read_pcap(files, protocol := 'frames')`, one
//! `read_<table>(files)` per table of the catalogue this engine reads, and one
//! `read_<proto>_packets(files)` per `*_packets` view of the shared scan layer.
//!
//! ```sql
//! SELECT * FROM read_tcp('capture.pcap') WHERE dst_port = 443;
//! SELECT * FROM read_pcap('capture.pcapng.gz', protocol := 'dns');
//! SELECT count(*) FROM read_frames('capture.pcap', strict := true);
//! SELECT filename, count(*) FROM read_dns(['monday/*.pcap', 'tuesday.pcapng.gz'], filename := true)
//! GROUP BY ALL;
//! SELECT timestamp, ip4_to_string(src_ip_v4), dst_port FROM read_tcp_packets('capture.pcap');
//! ```
//!
//! All of them are one implementation, [`PcapScan`], which holds no scan logic: which columns a
//! table has, what a cell holds, which rows a frame adds, where a chunk ends and where a capture
//! can be split are decided by `pcapsql_core::scan`, the layer the DataFusion frontend runs too.
//! What a function reads is a [`Relation`]: a table, or a view, which is a join of tables that
//! the scan layer evaluates frame by frame (a fused scan: one pass, one output, no join
//! operator). Everything below is the same for both.
//! What is here is the DuckDB side of that layer:
//!
//! | Callback | Work | State |
//! |---|---|---|
//! | `bind` | Resolve the table or view, declare its columns, expand the files argument through DuckDB's file system, open and probe every file, estimate the row count | [`BindData`]: the files, table, `strict`, `filename`, and the predicate `pushdown_filter` fills in |
//! | `pushdown_filter` | Read what the filters say about `frame_number` and `timestamp` as a `FramePredicate` (`engine::pushdown`), accepting none | The predicate, in [`BindData`] |
//! | `init_global_state` | Map the projected columns and the predicate to a `ScanPlan` (a table scan, or a view's fused scan) and compile it; decide the partitions of every file, which for a capture worth splitting takes one pass over it, and leave out those the predicate rules out | [`Shared`]: the compiled plan, the partition queue over all files and the indexes it was cut from, the progress counter |
//! | `max_threads` | The number of partitions | |
//! | `init_local_state` | Number the worker; no file yet | [`Worker`] |
//! | `claim_batch` | Claim the next partition, open its file at its offset, build the reader and the `PartitionScan` | [`Scanning`], in the worker: the scan, which owns the reader and through it the open file |
//! | `exec` | `PartitionScan::step` into a [`ChunkWriter`] over the output chunk until the chunk must be returned; no rows at the end of the partition | |
//! | `partition_data` | The ordinal of the worker's partition, as the batch index | |
//! | `progress` | Bytes read from the files by all workers over their total size | |
//!
//! # Arguments
//!
//! The captures are the only positional argument, declared `ANY` because it is a `VARCHAR` or a
//! list of them. Everything else is a named parameter: `strict` and `filename` on every
//! function, and `protocol` on `read_pcap`.
//!
//! # Files
//!
//! The positional argument is a path, a glob pattern, or a list of either
//! ([`PcapScan::files`]). DuckDB's multi-file reader is not used (it passes on neither named
//! parameters nor filters, decision D9 of the roadmap); this is the whole of the multi-file
//! handling:
//!
//! - **Expansion** happens at bind, through `FileSystem::glob` of DuckDB's file system, so a
//!   pattern is whatever that file system takes for one (`*`, `?`, `[...]`, `**` for a local
//!   path) and the session's access rules apply.
//! - **Order.** The files are read in the order of the list. The files one entry expands to are
//!   in ascending order of their paths, compared byte by byte: `FileSystem::glob` promises no
//!   order, so they are sorted here, as DuckDB's own readers sort what it returns.
//! - An entry that names a file twice, or two entries that match the same file, read it twice:
//!   nothing is removed.
//! - An entry with a wildcard that matches nothing is an error that names it. An entry without
//!   one that matches nothing is opened as it is, so the error is the file system's own (no such
//!   file, or a file system that cannot list).
//! - **Every file is opened and probed at bind**: one that is missing, out of bounds for the
//!   session or not a capture fails the statement there, with its path in the message.
//! - All files of one call are read as the same table, so they have the same columns by
//!   construction. `frame_number` counts the frames of a file: it starts at 1 in each.
//! - `filename := true` adds a `filename VARCHAR` column after the table's columns, which
//!   holds the path of the row's file as it was expanded. It is a column of the call, not of
//!   the table (`pcap_schema` does not list it), and like any column it is only produced when
//!   the query uses it: `exec` gives the output chunk's `filename` vector the path of the one
//!   file the chunk's rows are from ([`ChunkWriter::with_constant`]).
//!
//! # Partitions
//!
//! A scan reads each capture as one or more partitions: byte ranges that start at a record and
//! together cover every record once, in capture order. [`PcapScan::layout`] decides them for
//! every file when the scan starts:
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
//! The partitions of all files are in one `PartitionQueue`, those of the first file first and
//! each file's in capture order ([`Shared::owners`] says which file a partition is of). A
//! worker claims the next one in `claim_batch`, scans it to its end and claims again; DuckDB
//! runs up to as many workers as there are partitions. Work is therefore spread across files
//! and within a large one alike: eight small captures are read by eight workers, one each.
//!
//! # Filters
//!
//! DuckDB offers the scan the filters above it, and [`engine::pushdown`](super::pushdown)
//! turns what they say about `frame_number` and `timestamp` into one predicate: a range of
//! frame numbers and a range of timestamps. The predicate goes into the plan
//! (`ScanPlan::frames`), and core's driver gives rows for exactly the packets it accepts,
//! whatever the partitions are. Rejected packets are read and not parsed. No filter is
//! accepted: each stays in DuckDB's plan and is applied there to the rows the scan returns,
//! because a filter that left the plan would no longer tell two scans of one file apart (see
//! `engine::pushdown`, "Why no filter is accepted").
//!
//! The predicate also saves reading, which is the point of it:
//!
//! - A predicate no frame satisfies (`frame_number < 1`, an inverted range) reads nothing: no
//!   file is opened.
//! - A capture that is split is split by `plan_ranges` with the predicate: partitions are
//!   shrunk to the checkpoint windows that can hold a matching frame, by frame number and by
//!   the smallest and largest timestamp the index recorded for each window, and partitions
//!   with no such window are left out. `plan_ranges` keeps the window at the end of a
//!   capture unless an upper bound on `frame_number` rules it out (packets may have been
//!   appended since the index was built, and nothing is known of them), so a bound on
//!   `timestamp` never leaves a whole file unread.
//! - A capture that is read as one partition (compressed, remote, small, one thread) is read
//!   from its first byte, since nothing says where a frame is. The read ends after the last
//!   frame an upper bound on `frame_number` admits. A bound on `timestamp` ends nothing:
//!   timestamps need not ascend.
//!
//! With several files the predicate applies to each file, whose frames are numbered from 1.
//!
//! A read that ends early does not get to the end of the capture, so it does not find a
//! capture truncated, as with `LIMIT`, unless the scan is strict (see below).
//!
//! # Row order
//!
//! A scan returns its rows in file order, and within a file in capture order, without an
//! `ORDER BY` and on any number of threads.
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
//! which under a partitioned scan is the reader of the file's last partition. The rows of the
//! complete records are returned and a warning that names the file goes to DuckDB's log, once
//! per file; with `strict := true` the query fails instead. With several files each is treated
//! on its own: the files after a truncated one are read as if it were not there.
//!
//! A scan that is not run to the end of the capture (a `LIMIT`, or an upper bound on
//! `frame_number`, which ends the read) may not get to the broken tail. Without `strict`, a
//! scan of one partition then reports nothing; with several partitions the worker at the end
//! of the capture gets there whenever it does, before or after the others have filled the
//! `LIMIT`, so the warning may or may not be logged.
//!
//! `strict := true` is about the whole capture, whatever the query reads of it, so that
//! whether a strict scan fails does not depend on the threads or the file's size. A strict
//! scan of several partitions reads the tail of the capture when it starts and fails there.
//! A strict scan of one partition whose read a frame bound ended reads on to the end of the
//! file (`read_to_the_end`: the record headers, nothing parsed) and fails there. That costs
//! the rest of the file, which is what the split scan's index pass costs too. A `LIMIT` is the
//! one exception: DuckDB stops calling a scan once it has its rows, so a strict scan of one
//! partition under a `LIMIT` that ends before the tail returns its rows.

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
        PushdownData, TableClaimBatchCallbacks, TableFilterPushdownCallbacks,
        TableFunctionCallbacks, TablePartitioningCallbacks,
    },
    types::{Any, DuckDBType},
    Error, Result,
};
use pcapsql_core::io::{
    build_boundary_index, BoundaryIndex, Compression, DecompressReader, PacketPosition,
    PacketRange, PacketReader, ReadPacketReader, SeekCost, StreamHeader,
};
use pcapsql_core::scan::{
    partition_target, plan_ranges, Catalog, CompiledScan, FramePredicate, OutColumn,
    PartitionPolicy, PartitionQueue, PartitionScan, Step,
};
use pcapsql_core::{default_registry, ProtocolRegistry};

use super::{
    fs::{self, DuckFile},
    guard,
    pushdown::{self, Pushed},
    registry::{self, FrameColumn, Relation},
    settings::{self, ScanSettings},
    types,
    writer::ChunkWriter,
};

/// The table `read_pcap` reads when `protocol` is not given.
const DEFAULT_PROTOCOL: &str = "frames";

/// The column `filename := true` adds. No table of the catalogue has a column of this name
/// (a unit test below says so).
const FILENAME: &str = "filename";

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
    // No view has the name of a table (a test in core says so), so no two functions collide.
    for relation in registry::relations() {
        let name = format!("read_{}", relation.name());
        builder(&name, Some(relation)).register(extension)?;
    }
    builder("read_pcap", None).register(extension)
}

type Builder = duckdb_neo::table_function::TableFunctionBuilder<guard::Guarded<PcapScan>>;

fn builder(name: &str, relation: Option<Relation>) -> Builder {
    let scan = PcapScan {
        name: name.to_owned(),
        relation,
    };
    guard::table_function(name, scan.signature(), scan)
        .with_projection_pushdown(true)
        .with_filter_pushdown()
        .with_progress()
        .with_claim_batch()
        .with_partitioning()
}

/// A scan function: `read_<table>` or `read_<view>` when what it reads is fixed, `read_pcap`
/// when the `protocol` parameter names it.
#[derive(Debug)]
struct PcapScan {
    /// The SQL name of the function, for messages.
    name: String,
    relation: Option<Relation>,
}

/// Where each argument is in the list `bind` is handed: the positional parameters, then the
/// named ones in the order [`PcapScan::signature`] declares them.
struct ArgumentPositions {
    protocol: Option<usize>,
    strict: usize,
    filename: usize,
}

impl PcapScan {
    const FILE: usize = 0;

    /// An error of this function: `message` with the function's SQL name in front, as every
    /// message of a scan function starts.
    fn error(&self, code: DuckDBError, message: impl std::fmt::Display) -> Error {
        Error {
            code,
            message: format!("{}: {message}", self.name),
        }
    }

    /// An [`error`](Self::error) about what the call was given.
    fn invalid(&self, message: impl std::fmt::Display) -> Error {
        self.error(DuckDBError::InputInvalid, message)
    }

    fn positions(&self) -> ArgumentPositions {
        match self.relation {
            Some(_) => ArgumentPositions {
                protocol: None,
                strict: 1,
                filename: 2,
            },
            None => ArgumentPositions {
                protocol: Some(1),
                strict: 2,
                filename: 3,
            },
        }
    }

    fn signature(&self) -> SignatureBuilder {
        let mut signature = SignatureBuilder::new().param(FunctionParameter::new::<Any>("files"));
        if self.relation.is_none() {
            signature = signature.param(
                FunctionParameter::with_default::<String>("protocol", DEFAULT_PROTOCOL.to_owned())
                    .kind(FunctionParameterKind::Named),
            );
        }
        signature
            .param(
                FunctionParameter::with_default::<bool>("strict", false)
                    .kind(FunctionParameterKind::Named),
            )
            .param(
                FunctionParameter::with_default::<bool>(FILENAME, false)
                    .kind(FunctionParameterKind::Named),
            )
    }

    /// The entries of the one positional argument: the path or pattern, or those of the list,
    /// in its order.
    fn file_argument(&self, arguments: &[BindArgument]) -> Result<Vec<String>> {
        let argument = arguments
            .get(Self::FILE)
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
    /// (see the module documentation on files).
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
    fn named<T: duckdb_neo::types::FromValue>(
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

    /// What the call reads: the function's own table or view, or the one `protocol` names.
    fn relation(&self, arguments: &[BindArgument]) -> Result<Relation> {
        if let Some(relation) = self.relation {
            return Ok(relation);
        }
        let index = self.positions().protocol.expect("read_pcap has protocol");
        let protocol: String = self.named(arguments, index, "protocol")?;
        // The names are lower case; any case is accepted, as `pcap_schema` does.
        Relation::find(&protocol.to_ascii_lowercase()).ok_or_else(|| {
            self.invalid(format_args!(
                "there is no protocol table '{protocol}'; {}",
                registry::WHERE_TO_LOOK
            ))
        })
    }
}

/// What `bind` learned.
#[derive(Debug)]
struct BindData {
    /// The paths of the files, as the file system's `glob` returned them, in the order they
    /// are read. Never empty.
    files: Box<[String]>,
    /// The sum of the sizes of the files at bind.
    total_size: u64,
    /// The table or view the call reads.
    relation: Relation,
    /// The number of columns of `relation` declared to DuckDB, in the order of
    /// [`Relation::columns`]: a projected column index below it is an index into those.
    columns: usize,
    /// The index of the `filename` column, which is declared after the relation's, if the call
    /// asked for it.
    filename: Option<usize>,
    strict: bool,
    /// What the filters DuckDB offered the scan say about the frames to read, as one
    /// predicate.
    pushed: Pushed,
}

/// What a projection DuckDB reports asks for.
#[derive(Debug, PartialEq, Eq)]
struct Projection {
    /// The relation's columns (indices into [`Relation::columns`]), in the order of the output
    /// chunk.
    columns: Vec<usize>,
    /// The vector of the output chunk that is the `filename` column. The relation's columns
    /// are the other vectors.
    filename: Option<usize>,
}

/// The partitions of one file: what [`PcapScan::layout`] decided.
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
    /// The vector of the output chunk that is the `filename` column, if the query uses it.
    filename: Option<usize>,
    /// The partitions of all files: those of the first file, then those of the second, each
    /// file's in capture order. Each is claimed by one worker.
    queue: PartitionQueue,
    /// The file of every partition of `queue`, as an index into `files` and `BindData::files`.
    /// It never decreases.
    owners: Box<[usize]>,
    /// What the scan keeps per file, in the order of `BindData::files`.
    files: Box<[ScannedFile]>,
    /// Bytes read from the files so far by all workers, for `progress`.
    file_bytes: Arc<AtomicU64>,
    /// Workers created so far: the next worker's number.
    workers: AtomicUsize,
    /// Set by the first worker whose scan fails. The others stop.
    failed: AtomicBool,
}

/// What a scan keeps for one of its files.
#[derive(Debug)]
struct ScannedFile {
    /// The index the file's partitions were cut from; `None` when its one partition is the
    /// whole capture (see [`Layout::index`]).
    index: Option<BoundaryIndex>,
    /// Set by the worker that reports the file truncated, so that it is reported once.
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
    /// The file the partition is of: an index into `BindData::files`.
    file: usize,
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
    type BindData = BindData;
    type GlobalState = Shared;
    type LocalState = Worker;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<BindData> {
        let entries = self.file_argument(&arguments)?;
        let relation = self.relation(&arguments)?;
        let positions = self.positions();
        let strict: bool = self.named(&arguments, positions.strict, "strict")?;
        let filename: bool = self.named(&arguments, positions.filename, FILENAME)?;

        // Where the two columns a pushed-down filter can be about are declared. In a view they
        // are the frame's own, so a filter on them says which frames to read, as for a table.
        let (mut frame_number, mut timestamp) = (None, None);
        let declared = relation.columns();
        for (index, column) in declared.iter().enumerate() {
            let logical_type = types::logical_type(context, column.kind)?;
            bind_handle.add_result_column(column.name, &logical_type)?;
            match column.frame {
                Some(FrameColumn::Number) => frame_number = Some(index),
                Some(FrameColumn::Timestamp) => timestamp = Some(index),
                None => {}
            }
        }
        let columns = declared.len();
        // After the relation's columns, where DuckDB's own readers put theirs.
        let filename = if filename {
            bind_handle.add_result_column(FILENAME, &String::logical_type(context)?)?;
            Some(columns)
        } else {
            None
        };

        // Open and probe every file now, so that one that is missing, out of bounds for the
        // session or not a capture fails the statement at bind, with its path in the message.
        let mut files = Vec::new();
        let (mut total_size, mut rows) = (0_u64, 0_usize);
        for path in self.files(context, &entries)? {
            let mut file = DuckFile::open(context, &path)?;
            let size = file.size()?;
            let header = self.probe(&mut file, &path)?;
            total_size = total_size.saturating_add(size);
            rows = rows.saturating_add(estimated_rows(size, &header));
            files.push(path);
        }

        // The rows come back in file and capture order, which `partition_data` lets DuckDB
        // keep on several threads.
        bind_handle.set_order(OrderPreservation::Insertion)?;
        // An estimate: the frames are only counted when the scan starts, and then only for a
        // capture that is split (see `layout`).
        bind_handle.set_cardinality(rows, false)?;
        Ok(BindData {
            files: files.into(),
            total_size,
            relation,
            columns,
            filename,
            strict,
            pushed: Pushed::new(frame_number, timestamp),
        })
    }

    fn init_global_state(
        &self,
        context: &Context,
        bound: &BindData,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<Shared>> {
        let projected = (0..column_data.count()?)
            .map(|position| column_data.get_column_index(position))
            .collect::<Result<Vec<_>>>()?;
        let projection = self.projection(bound, &projected)?;
        // The frames the filters above the scan may leave: it returns rows of these only, and
        // DuckDB applies the filters themselves to those rows.
        let frames = bound.pushed.predicate();
        // One output either way: the table's rows, or the view's joined rows.
        let plan = bound
            .relation
            .plan(&projection.columns, frames.clone())
            .compile(Catalog::builtin(), protocols())
            .map_err(|error| self.error(DuckDBError::QueryPlanner, error))?;
        let columns = plan.outputs()[0].columns.clone();

        let settings = ScanSettings::read(context)?;
        let (mut ranges, mut owners) = (Vec::new(), Vec::new());
        let mut files = Vec::with_capacity(bound.files.len());
        for (number, path) in bound.files.iter().enumerate() {
            let layout = self.layout(context, &settings, path, bound.strict, &frames)?;
            // What the scan will do, for whoever asks DuckDB's log (`enable_logging`) why a
            // query is slow. As for the truncation warning, the log is not worth failing a
            // query for.
            let _ = Log::log_on_context(
                context,
                LogLevel::Debug,
                &self.describe(path, &plan, &layout),
                LOG_TYPE,
            );
            owners.resize(owners.len() + layout.ranges.len(), number);
            ranges.extend(layout.ranges);
            files.push(ScannedFile {
                index: layout.index,
                truncation_reported: AtomicBool::new(false),
            });
        }
        Ok(Some(Shared {
            plan: Arc::new(plan),
            columns,
            filename: projection.filename,
            queue: PartitionQueue::new(ranges),
            owners: owners.into(),
            files: files.into(),
            file_bytes: Arc::new(AtomicU64::new(0)),
            workers: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
        }))
    }

    fn max_threads(
        &self,
        _context: &Context,
        _bound: &BindData,
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
        _bound: &BindData,
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
        bound: &BindData,
        worker: Option<&mut Worker>,
        shared: Option<&Shared>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let shared = shared.expect("init_global_state always returns a state");
        let worker = worker.expect("init_local_state always returns a state");
        if shared.failed.load(Ordering::Acquire) {
            // Another worker's scan failed, and with it the query: nothing more is wanted.
            worker.scanning = None;
        }
        let mut writer = match shared.filename {
            None => ChunkWriter::new(output, &shared.columns)?,
            // The rows of this chunk are all from the partition the worker holds, and so from
            // one file: the loop below ends where the partition does.
            Some(vector) => {
                let path = worker
                    .scanning
                    .as_ref()
                    .map_or("", |scanning| bound.files[scanning.file].as_str());
                ChunkWriter::with_constant(output, &shared.columns, vector, path)?
            }
        };
        let mut packets_before = None;
        while let Some(scanning) = worker.scanning.as_mut() {
            let scan = &mut scanning.scan;
            let before = *packets_before.get_or_insert(scan.stats().packets);
            let step = scan
                .step(std::slice::from_mut(&mut writer), PACKETS_PER_STEP)
                .map_err(|error| {
                    let frame = scan.reader().position().frame_number;
                    let path = &bound.files[scanning.file];
                    shared.fail(self.read_error(path, frame, &error))
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
                    let mut finished = worker.scanning.take().expect("the scan was just stepped");
                    if bound.strict && shared.files[finished.file].index.is_none() {
                        // A strict scan is about the whole capture. One read as one partition
                        // is read on to its end when a frame bound ended the scan before it,
                        // as a split one looks at its tail when it starts.
                        self.read_to_the_end(bound, &mut finished)
                            .map_err(|error| shared.fail(error))?;
                    }
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
        bound: &BindData,
        shared: Option<&Shared>,
    ) -> Result<Option<f64>> {
        let Some(shared) = shared else {
            return Ok(None);
        };
        if bound.total_size == 0 {
            return Ok(None);
        }
        // Every worker reads ahead of the packets it has parsed, so the sum can pass the size.
        let read = shared.file_bytes.load(Ordering::Relaxed);
        Ok(Some((read as f64 / bound.total_size as f64).min(1.0)))
    }
}

impl TableClaimBatchCallbacks for PcapScan {
    /// Claim the next partition for this worker and open it. DuckDB calls this before the
    /// worker's first `exec` and after every `exec` that returned no rows.
    fn claim_batch(
        &self,
        context: &Context,
        bound: &BindData,
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
            .open(context, bound, shared, shared.owners[ordinal], range)
            .map_err(|error| shared.fail(error))?;
        worker.scanning = Some(scanning);
        // Larger than the worker's last ordinal, and no other worker's: see `PartitionQueue`.
        worker.ordinal = Some(ordinal);
        Ok(true)
    }
}

impl TableFilterPushdownCallbacks for PcapScan {
    /// Narrow the scan by the filters that are about its frames, accepting none, so that DuckDB
    /// still applies each (see [`engine::pushdown`](super::pushdown)). DuckDB calls this while
    /// it plans the statement, and may call it more than once.
    fn pushdown_filter(
        &self,
        context: &Context,
        bound: &BindData,
        offered: PushdownData<'_>,
    ) -> Result<()> {
        if !settings::filter_pushdown(context)? {
            return Ok(());
        }
        bound.pushed.narrow(&offered)
    }
}

impl TablePartitioningCallbacks for PcapScan {
    /// The batch index of the chunk `exec` just returned on this worker: the ordinal of the
    /// partition its rows are from (see the module documentation on row order).
    fn partition_data(
        &self,
        _context: &Context,
        _bound: &BindData,
        worker: Option<&mut Worker>,
        _shared: Option<&Shared>,
        _partition_data: PartitionData<'_>,
    ) -> Result<usize> {
        // DuckDB asks after a chunk that has rows, and rows only come out of a claimed
        // partition. Should it ever ask earlier, an error is the answer: an index made up here
        // could be another worker's.
        worker.and_then(|worker| worker.ordinal).ok_or_else(|| {
            self.error(
                DuckDBError::QueryExecutor,
                "DuckDB asked where rows belong before the worker claimed a partition",
            )
        })
    }
}

impl PcapScan {
    /// The relation's columns of a projection DuckDB reports, in its order, and where in it the
    /// `filename` column is.
    ///
    /// DuckDB always projects at least one column. For a query that needs no column
    /// (`count(*)`) it is either a declared column of DuckDB's choosing, which is then read like
    /// any other, or DuckDB's row identifier, which is not a declared column: the plan then has
    /// no columns, and the scan layer only counts the rows. The same goes for a query that
    /// uses no column but `filename`.
    fn projection(&self, bound: &BindData, projected: &[usize]) -> Result<Projection> {
        let filename = bound
            .filename
            .and_then(|declared| projected.iter().position(|&index| index == declared));
        let declared: Vec<Option<usize>> = projected
            .iter()
            .enumerate()
            .filter(|(position, _)| Some(*position) != filename)
            .map(|(_, &index)| (index < bound.columns).then_some(index))
            .collect();
        if declared.iter().all(Option::is_none) {
            return Ok(Projection {
                columns: Vec::new(),
                filename,
            });
        }
        let all: Option<Vec<usize>> = declared.into_iter().collect();
        let columns = all.ok_or_else(|| {
            self.error(
                DuckDBError::QueryNotImplemented,
                format_args!(
                    "DuckDB asked for a column the function did not declare \
                     (columns {projected:?} of {})",
                    bound.columns + usize::from(bound.filename.is_some())
                ),
            )
        })?;
        Ok(Projection { columns, filename })
    }

    /// Decide the partitions of one file of a scan (see the module documentation).
    fn layout(
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

    /// Read the rest of a scan's file, packet by packet and parsing nothing, so that its reader
    /// knows whether the capture ends inside a record. A scan that got to the end reads
    /// nothing more.
    fn read_to_the_end(&self, bound: &BindData, scanning: &mut Scanning) -> Result<()> {
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

    /// Open file `number` of the scan for its partition `range` and build the partition's scan.
    fn open(
        &self,
        context: &Context,
        bound: &BindData,
        shared: &Shared,
        number: usize,
        range: &PacketRange,
    ) -> Result<Scanning> {
        let fault = Fault::default();
        let first_frame = range.start.frame_number;
        let path = bound.files[number].as_str();
        let failed = |error: &dyn std::fmt::Display| {
            self.read_error(path, first_frame.saturating_sub(1), error)
        };
        let reader = match &shared.files[number].index {
            // The whole capture, from its first byte.
            None => {
                let mut file = DuckFile::open(context, path)?;
                // Probed again: the header that counts is that of the file as it is read.
                let header = self.probe(&mut file, path)?;
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
                let file = DuckFile::open_at(context, path, range.start.byte_offset)?;
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
            file: number,
            first_frame,
        })
    }

    /// One line on what a scan reads of one of its files, and parses.
    fn describe(&self, path: &str, plan: &CompiledScan, layout: &Layout) -> String {
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
            self.name
        )
    }

    /// The error of a strict scan of such a capture.
    fn truncation_error(&self, path: &str, last_frame: u64) -> Error {
        Error {
            code: DuckDBError::IoEof,
            message: format!(
                "{}; without strict := true the complete frames are returned",
                self.truncation(path, last_frame)
            ),
        }
    }

    /// Check how the scan of a partition ended: with an error the reader swallowed, inside a
    /// record, or well.
    fn end_of_partition(
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

/// Whether an entry of the files argument is a pattern rather than a path: the characters
/// DuckDB's file systems take for wildcards (`FileSystem::HasGlob`).
fn has_wildcard(entry: &str) -> bool {
    entry.contains(['*', '?', '['])
}

/// The number of rows a scan of one file is estimated to return. It is a guess from the file size: only
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

    fn bound(relation: &str) -> BindData {
        let relation = Relation::find(relation).unwrap();
        BindData {
            files: Box::new(["x.pcap".to_owned()]),
            total_size: 0,
            relation,
            columns: relation.columns().len(),
            filename: None,
            strict: false,
            pushed: Pushed::new(Some(0), Some(1)),
        }
    }

    fn scan(relation: &str) -> PcapScan {
        PcapScan {
            name: format!("read_{relation}"),
            relation: Relation::find(relation),
        }
    }

    /// Where the column `name` of `relation` is declared.
    fn index(relation: &str, name: &str) -> usize {
        Relation::find(relation)
            .unwrap()
            .columns()
            .iter()
            .position(|column| column.name == name)
            .unwrap_or_else(|| panic!("{relation}.{name}"))
    }

    /// The plan `init_global_state` compiles for a projection.
    fn compiled(relation: &str, projected: &[usize]) -> CompiledScan {
        let bound = bound(relation);
        let projection = scan(relation).projection(&bound, projected).unwrap();
        bound
            .relation
            .plan(&projection.columns, FramePredicate::all())
            .compile(Catalog::builtin(), protocols())
            .unwrap()
    }

    #[test]
    fn a_frames_projection_parses_no_protocol() {
        let bound = bound("frames");
        let all: Vec<usize> = (0..bound.columns).collect();
        // frame_number alone, every column, and no column at all (a row count).
        for projection in [&[0][..], &all[..], &[usize::MAX][..]] {
            let plan = compiled("frames", projection);
            assert_eq!(parsed_protocols(&plan), "none", "{projection:?}");
            assert!(plan.scope().projections().is_empty());
        }
        assert_eq!(index("frames", "frame_number"), 0);
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
        let plan = compiled("tcp", &[0, index("tcp", "dst_port")]);
        let fields = &plan.scope().projections()["tcp"];
        assert_eq!(fields.len(), 1);
        assert!(fields.contains("dst_port"));
        assert!(parsed_protocols(&plan).contains("tcp (fields: dst_port)"));

        // Every column: the parser runs unprojected.
        let all: Vec<usize> = (0..bound("tcp").columns).collect();
        let protocols = parsed_protocols(&compiled("tcp", &all));
        assert!(protocols.contains("tcp, "), "{protocols}");
    }

    #[test]
    fn the_output_columns_follow_the_projection_order() {
        let index = |name: &str| index("tcp", name);
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
    fn a_view_is_one_fused_output_that_parses_what_its_columns_need() {
        let index = |name: &str| index("tcp_packets", name);
        // The frame's columns and the anchor's level: every member is parsed (its rows decide
        // which joined rows there are), none has a field extracted.
        let plan = compiled(
            "tcp_packets",
            &[index("encap_depth"), index("timestamp"), 0],
        );
        assert_eq!(plan.outputs().len(), 1);
        assert_eq!(plan.outputs()[0].table, None);
        let names: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
        assert_eq!(names, ["encap_depth", "timestamp", "frame_number"]);
        assert_eq!(
            types::sql_name(plan.outputs()[0].columns[1].kind),
            "TIMESTAMP_NS"
        );
        let protocols = parsed_protocols(&plan);
        for member in ["ethernet", "ipv4", "ipv6", "tcp"] {
            assert!(
                protocols.contains(&format!("{member} (no fields)")),
                "{protocols}"
            );
        }
        for other in ["dns", "http", "tls"] {
            assert!(!protocols.contains(other), "{protocols}");
        }

        // The view's own names; a computed column extracts each of its arguments.
        let plan = compiled("tcp_packets", &[index("src_ip_v4"), index("ttl")]);
        let fields = |protocol: &str| {
            let mut fields: Vec<&str> = plan.scope().projections()[protocol]
                .iter()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            fields
        };
        assert_eq!(fields("ipv4"), ["src_ip", "ttl"]);
        assert_eq!(fields("ipv6"), ["hop_limit"]);
        assert!(fields("tcp").is_empty() && fields("ethernet").is_empty());

        // A row count still needs the join: a view has a row per anchor row that the required
        // layers stand beside.
        let plan = compiled("tls_packets", &[usize::MAX]);
        assert!(plan.outputs()[0].columns.is_empty());
        let protocols = parsed_protocols(&plan);
        assert!(protocols.contains("tls (no fields)"), "{protocols}");
        assert!(protocols.contains("tcp (no fields)"), "{protocols}");
    }

    #[test]
    fn a_view_declares_the_frame_s_number_and_time_for_pushdown() {
        for relation in registry::relations() {
            let columns = relation.columns();
            let of = |frame: FrameColumn| {
                let found: Vec<usize> = columns
                    .iter()
                    .enumerate()
                    .filter(|(_, column)| column.frame == Some(frame))
                    .map(|(index, _)| index)
                    .collect();
                assert_eq!(found.len(), 1, "{}: {frame:?}", relation.name());
                found[0]
            };
            assert_eq!(of(FrameColumn::Number), 0, "{}", relation.name());
            assert_eq!(of(FrameColumn::Timestamp), 1, "{}", relation.name());
            assert_eq!(columns[0].name, "frame_number", "{}", relation.name());
            assert_eq!(columns[1].name, "timestamp", "{}", relation.name());
            assert_eq!(
                types::sql_name(columns[1].kind),
                "TIMESTAMP_NS",
                "{}",
                relation.name()
            );
        }
    }

    #[test]
    fn a_projection_of_no_declared_column_counts_rows() {
        let bound = bound("udp");
        let scan = scan("udp");
        let columns = |projected: &[usize]| scan.projection(&bound, projected).unwrap().columns;
        assert!(columns(&[usize::MAX]).is_empty());
        assert!(columns(&[]).is_empty());
        // A mix of declared and undeclared columns is refused, not guessed at.
        let error = scan.projection(&bound, &[0, usize::MAX]).unwrap_err();
        assert_eq!(error.code, DuckDBError::QueryNotImplemented);
        assert!(error.message.starts_with("read_udp: "), "{}", error.message);
    }

    #[test]
    fn the_filename_column_is_taken_out_of_the_projection() {
        for relation in ["udp", "udp_packets"] {
            let mut bound = bound(relation);
            let scan = scan(relation);
            let filename = bound.columns;
            // Not declared: its index is no column of the function.
            assert_eq!(
                scan.projection(&bound, &[filename]).unwrap(),
                Projection {
                    columns: Vec::new(),
                    filename: None
                }
            );
            assert!(scan.projection(&bound, &[0, filename]).is_err());

            bound.filename = Some(filename);
            let projection = |projected: &[usize]| scan.projection(&bound, projected).unwrap();
            // Wherever it is among the projected columns, the others keep their order.
            for (projected, columns, vector) in [
                (&[0, 1, filename][..], vec![0, 1], Some(2)),
                (&[filename, 1, 0][..], vec![1, 0], Some(0)),
                (&[1, filename, 0][..], vec![1, 0], Some(1)),
                (&[1, 0][..], vec![1, 0], None),
                // Alone, or with DuckDB's row identifier: the rows are counted.
                (&[filename][..], vec![], Some(0)),
                (&[usize::MAX, filename][..], vec![], Some(1)),
                (&[usize::MAX][..], vec![], None),
            ] {
                assert_eq!(
                    projection(projected),
                    Projection {
                        columns,
                        filename: vector
                    },
                    "{relation} {projected:?}"
                );
            }
            assert!(scan.projection(&bound, &[0, usize::MAX, filename]).is_err());
        }
    }

    #[test]
    fn no_relation_has_a_column_called_filename() {
        for relation in registry::relations() {
            for column in relation.columns() {
                assert_ne!(column.name, FILENAME, "{}", relation.name());
            }
        }
    }

    #[test]
    fn a_pattern_is_an_entry_with_a_wildcard() {
        for pattern in ["*.pcap", "a?.pcap", "day[12].pcap", "captures/**/x.pcap"] {
            assert!(has_wildcard(pattern), "{pattern}");
        }
        for path in ["a.pcap", "/var/captures/a b.pcap.gz", "s3://bucket/a.pcap"] {
            assert!(!has_wildcard(path), "{path}");
        }
    }

    #[test]
    fn every_scan_table_gets_a_function_and_none_is_called_pcap() {
        // `read_pcap` is the generic function; a table of that name would collide with it.
        assert!(Relation::find("pcap").is_none());
        assert!(registry::scan_table(DEFAULT_PROTOCOL).is_some());
        let mut names = std::collections::HashSet::new();
        for relation in registry::relations() {
            assert!(names.insert(relation.name()), "{} twice", relation.name());
            let function = PcapScan {
                name: String::new(),
                relation: Some(relation),
            };
            assert_eq!(function.positions().strict, 1);
            assert_eq!(function.positions().filename, 2);
        }
        // The tables, then the views.
        assert_eq!(
            names.len(),
            registry::scan_tables().count() + registry::views().len()
        );
        assert!(names.contains("tcp") && names.contains("tcp_packets"));
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
