//! The scan table functions: `read_pcap(files, protocol := 'frames')`, one
//! `read_<table>(files)` per table of the catalogue (the four stream tables among them), and
//! one `read_<proto>_packets(files)` per `*_packets` view of the shared scan layer.
//!
//! ```sql
//! SELECT * FROM read_tcp('capture.pcap') WHERE dst_port = 443;
//! SELECT sni, is_decrypted FROM read_tls_sessions('capture.pcap', keylog := 'keys.log');
//! SELECT * FROM read_pcap('capture.pcapng.gz', protocol := 'dns');
//! SELECT count(*) FROM read_frames('capture.pcap', strict := true);
//! SELECT filename, count(*) FROM read_dns(['monday/*.pcap', 'tuesday.pcapng.gz'], filename := true)
//! GROUP BY ALL;
//! SELECT timestamp, ip4_to_string(src_ip_v4), dst_port FROM read_tcp_packets('capture.pcap');
//! ```
//!
//! (`pcap_time_range(files)`, which says when each capture begins and ends, is registered here
//! too and takes the same files argument; it is described in its own module, `time_range`.)
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
//! | `bind` | Resolve the table or view, declare its columns, expand the files argument through DuckDB's file system, open and probe every file, read the key log of a stream table, estimate the row count | [`BindData`]: the files, table, `strict`, `filename`, the key log, and the predicate `pushdown_filter` fills in |
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
//! function, `protocol` on `read_pcap`, and `keylog` on `read_pcap` and the functions of the
//! stream tables (the `keylog` module).
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
//! # Stream tables
//!
//! `tcp_connections`, `tls_sessions`, `http_messages` and `http2` are not rows of a frame. The
//! scan layer reassembles the TCP streams of a capture while it reads it, and the tables are
//! what that holds when the capture ends (`pcapsql_core::scan`, `ScanPlan::streams`). The
//! functions of these tables are the same implementation as the others, and differ where the
//! scan layer does:
//!
//! - **One partition per file, always.** Reassembly needs the frames of a capture in order
//!   from the first (`CompiledScan::requires_single_partition`), so a capture is never split,
//!   whatever its size and the settings. Several files are still several partitions, read by
//!   as many workers.
//! - **A file is a scan of its own.** Connections are numbered within a capture, so
//!   `connection_id` starts again in each file, as `frame_number` does: across the files of a
//!   call a connection is its `connection_id` and its file (`filename := true`). A
//!   connection whose packets are in two files is two connections.
//! - **No frame predicate.** Every frame goes into reassembly, and a plan with a stream table
//!   compiles with no other predicate. None arises: no column of a stream table is the
//!   frame's own (its `frame_number` is where the row begins or was complete, a value like
//!   any other), so [`engine::pushdown`](super::pushdown) finds nothing to use among the
//!   filters DuckDB offers, and DuckDB applies them all to the rows.
//! - **The rows come at the end.** `PartitionScan::step` reports `More` without a row for as
//!   long as it reads the capture, then the rows. `exec` steps until its chunk is full or the
//!   partition ends and never returns a chunk without rows before that, so the first `exec`
//!   of a partition lasts as long as the read of its file. A callback cannot ask whether the
//!   query was interrupted, and DuckDB looks when a chunk with rows comes back: a query is
//!   cancelled once the file that is being read has been read. Returning to DuckDB during
//!   the read was tried and gains nothing: a chunk without rows makes it claim and call
//!   again without looking (DuckDB 2.0.0; a 16 s read interrupted after 1.6 s ended after
//!   17 s either way). The same holds for a packet table over a capture that has no row of
//!   it. A `LIMIT` saves writing rows, not reading: the capture is read to its end first.
//! - **`strict` and truncation** are as for any scan of one partition: the capture is read
//!   to its end, so a truncated one is always found, and with `strict := true` the query
//!   fails with no row returned.
//! - **A key log** decrypts TLS (the `keylog` module): `tls_sessions.is_decrypted`, and the
//!   rows of `http2`, which without one has none.
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
//! of the data. A read error is also remembered by the file reader ([`Tracked`](reader::Tracked)) and reported
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

mod args;
mod function;
mod keylog;
mod layout;
mod reader;
mod report;
#[cfg(test)]
mod tests;
mod time_range;

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    data_chunk::DataChunkRef,
    error::DuckDBError,
    extension::Extension,
    log::{Log, LogLevel},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, OrderPreservation, PartitionData,
        PushdownData, TableClaimBatchCallbacks, TableFilterPushdownCallbacks,
        TableFunctionCallbacks, TablePartitioningCallbacks,
    },
    types::DuckDBType,
    Error, Result,
};
use pcapsql_core::io::{BoundaryIndex, PacketReader};
use pcapsql_core::scan::{Catalog, CompiledScan, OutColumn, PartitionQueue, Step};
use pcapsql_core::{default_registry, ProtocolRegistry};

use self::function::CaptureFunction;
use self::keylog::Keys;
use self::layout::{estimated_rows, Layout};
use self::reader::Scanning;
use super::{
    fs::DuckFile,
    guard,
    pushdown::Pushed,
    relation::{self, FrameColumn, Relation},
    settings::{self, ScanSettings},
    types,
    writer::ChunkWriter,
};

/// The column `filename := true` adds. No table of the catalogue has a column of this name
/// (a unit test below says so).
const FILENAME: &str = "filename";

/// The parameter that names a TLS key log (see the `keylog` module).
const KEYLOG: &str = "keylog";

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

/// The parsers every scan uses, built once.
fn protocols() -> &'static Arc<ProtocolRegistry> {
    static PROTOCOLS: OnceLock<Arc<ProtocolRegistry>> = OnceLock::new();
    PROTOCOLS.get_or_init(|| Arc::new(default_registry()))
}

pub(super) fn register(extension: &Extension) -> Result<()> {
    // No view has the name of a table (a test in core says so), so no two functions collide.
    for relation in relation::relations() {
        let name = format!("read_{}", relation.name());
        builder(&name, Some(relation)).register(extension)?;
    }
    builder("read_pcap", None).register(extension)?;
    time_range::register(extension)
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

impl CaptureFunction for PcapScan {
    fn name(&self) -> &str {
        &self.name
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
    /// The key log a scan of a stream table decrypts TLS with, if the call or the setting
    /// names one.
    keylog: Option<Keys>,
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
    /// whole capture (see [`Layout::index`](layout::Layout::index)).
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
        let keylog = self.keylog(context, &arguments, relation)?;

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
            keylog,
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
            let layout = if plan.requires_single_partition() {
                Layout::in_order()
            } else {
                self.layout(context, &settings, path, bound.strict, &frames)?
            };
            // What the scan will do, for whoever asks DuckDB's log (`enable_logging`) why a
            // query is slow. As for the truncation warning, the log is not worth failing a
            // query for.
            let _ = Log::log_on_context(
                context,
                LogLevel::Debug,
                &self.describe(path, &plan, &layout, bound.keylog.as_ref()),
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
                    // Without rows the scan goes on, however long: a stream table has none
                    // before its capture is read, and a chunk without rows would not give
                    // DuckDB a chance to cancel the query (see the module documentation).
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
}
