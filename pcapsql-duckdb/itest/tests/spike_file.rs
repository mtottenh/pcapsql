//! Spike U4: a `duckdb_neo::file::File` kept in a worker's local state.
//!
//! The reader design opens one file per worker through DuckDB's file system and keeps reading
//! from it in later `exec` calls. Two test functions read a real file that way and report what
//! they read, so the totals can be checked against the file:
//!
//! - `blocks_opened_in_init(path)` opens the file in `init_local_state` and reads it front to
//!   back with the file's own cursor, one block per `exec` call.
//! - `blocks_opened_in_claim(path)` cuts the file into byte ranges that workers claim; a worker
//!   opens its file in its first `claim_batch` and reads every range it claims from that handle
//!   by offset, on up to four threads.
//!
//! What this establishes for DuckDB 2.0.0 and `duckdb-neo` 0.20000.2:
//!
//! - A `File` outlives the callback, the `Context` and the `FileSystem` it was opened with, and
//!   is usable from later `exec` and `claim_batch` calls of the same local state. It is `Send`,
//!   which local state requires.
//! - The cursor of `read_into` persists between `exec` calls; `read_exact_at` reads by offset.
//! - Opens go through DuckDB's file system: with `enable_external_access` off they are refused,
//!   and an `https://` or `s3://` path is handed to the httpfs extension (not available where
//!   this was written, so reading a remote file is not covered).

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    ops::Range,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    error::{DuckDBError, Error},
    file::{File, FileBuilder, FileSystem},
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, TableClaimBatchCallbacks,
        TableFunctionBuilder, TableFunctionCallbacks,
    },
    DuckDBType, Parameters, Result,
};
use pcapsql_duckdb_itest::{connect, rows, value};

/// Bytes read per `exec` call.
const BLOCK: usize = 16 * 1024;
/// Bytes per claimed range: several `exec` calls each.
const RANGE: u64 = 4 * BLOCK as u64 + 1000;

fn open(context: &Context, path: &str) -> Result<File> {
    let file_system = FileSystem::new(context)?;
    let file = FileBuilder::new(&file_system, path)?.read().open()?;
    // `file_system` is dropped here; the file is not.
    Ok(file)
}

fn path_argument(arguments: &[BindArgument]) -> Result<String> {
    arguments[0]
        .value
        .as_ref()
        .and_then(|value| value.get::<String>().transpose())
        .ok_or_else(|| Error::invalid_input("expected a file path"))?
}

fn newlines(bytes: &[u8]) -> i64 {
    bytes.iter().filter(|byte| **byte == b'\n').count() as i64
}

/// Emit one row of BIGINTs.
fn emit(output: &mut DataChunkRef<'_>, row: &[i64]) -> Result<()> {
    for (column, cell) in row.iter().enumerate() {
        let mut vector = output.get_vector_at_mut::<i64>(column)?;
        vector.set_size(1)?;
        vector.writer()?.set(0, cell)?;
    }
    Ok(())
}

/// Counts how often each function opened a file.
#[derive(Default)]
struct Opens(AtomicUsize);

// ---------------------------------------------------------------------------------------------
// Opened in init_local_state, read sequentially
// ---------------------------------------------------------------------------------------------

struct OpenedInInit(Arc<Opens>);

impl TableFunctionCallbacks for OpenedInInit {
    /// The path.
    type BindData = String;
    type GlobalState = ();
    type LocalState = File;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<String> {
        bind_handle.add_result_column("bytes", &i64::logical_type(context)?)?;
        bind_handle.add_result_column("newlines", &i64::logical_type(context)?)?;
        path_argument(&arguments)
    }

    fn init_local_state(
        &self,
        context: &Context,
        path: &String,
        _global_state: Option<&()>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<File>> {
        self.0 .0.fetch_add(1, Ordering::Relaxed);
        open(context, path).map(Some)
    }

    fn exec(
        &self,
        _context: &Context,
        _path: &String,
        file: Option<&mut File>,
        _global_state: Option<&()>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let file = file.expect("init_local_state opened the file");
        let mut block = vec![0; BLOCK];
        let read = file.read_into(&mut block)?;
        if read == 0 {
            return Ok(());
        }
        emit(&mut output, &[read as i64, newlines(&block[..read])])
    }
}

// ---------------------------------------------------------------------------------------------
// Opened in claim_batch, read by offset on several threads
// ---------------------------------------------------------------------------------------------

struct OpenedInClaim(Arc<Opens>);

struct Shared {
    file_size: u64,
    next_range: AtomicU64,
    next_worker: AtomicU64,
}

struct Worker {
    id: i64,
    file: Option<File>,
    /// What is left of the claimed range.
    range: Range<u64>,
    range_index: i64,
}

impl TableFunctionCallbacks for OpenedInClaim {
    type BindData = String;
    type GlobalState = Shared;
    type LocalState = Worker;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<String> {
        for name in ["worker", "range_index", "bytes", "newlines"] {
            bind_handle.add_result_column(name, &i64::logical_type(context)?)?;
        }
        path_argument(&arguments)
    }

    fn init_global_state(
        &self,
        context: &Context,
        path: &String,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Shared>> {
        Ok(Some(Shared {
            file_size: open(context, path)?.size()?,
            next_range: AtomicU64::new(0),
            next_worker: AtomicU64::new(0),
        }))
    }

    fn max_threads(
        &self,
        _context: &Context,
        _path: &String,
        _shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<std::num::NonZeroUsize>> {
        Ok(std::num::NonZeroUsize::new(4))
    }

    fn init_local_state(
        &self,
        _context: &Context,
        _path: &String,
        shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Worker>> {
        Ok(Some(Worker {
            id: shared.unwrap().next_worker.fetch_add(1, Ordering::Relaxed) as i64,
            file: None,
            range: 0..0,
            range_index: -1,
        }))
    }

    fn exec(
        &self,
        _context: &Context,
        _path: &String,
        worker: Option<&mut Worker>,
        _shared: Option<&Shared>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let worker = worker.unwrap();
        if worker.range.is_empty() {
            // An empty chunk ends the batch; DuckDB then asks this worker to claim the next one.
            return Ok(());
        }
        let length = (worker.range.end - worker.range.start).min(BLOCK as u64) as usize;
        let mut block = vec![0; length];
        let file = worker.file.as_ref().expect("claim_batch opened the file");
        file.read_exact_at(worker.range.start as usize, &mut block)?;
        worker.range.start += length as u64;

        // Give the other workers time to start, so that the test sees more than one of them.
        std::thread::sleep(std::time::Duration::from_millis(1));
        emit(
            &mut output,
            &[
                worker.id,
                worker.range_index,
                length as i64,
                newlines(&block),
            ],
        )
    }
}

impl TableClaimBatchCallbacks for OpenedInClaim {
    fn claim_batch(
        &self,
        context: &Context,
        path: &String,
        worker: Option<&mut Worker>,
        shared: Option<&Shared>,
    ) -> Result<bool> {
        let (worker, shared) = (worker.unwrap(), shared.unwrap());
        let index = shared.next_range.fetch_add(1, Ordering::Relaxed);
        let start = index * RANGE;
        if start >= shared.file_size {
            return Ok(false);
        }
        worker.range = start..(start + RANGE).min(shared.file_size);
        worker.range_index = index as i64;
        if worker.file.is_none() {
            self.0 .0.fetch_add(1, Ordering::Relaxed);
            worker.file = Some(open(context, path)?);
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------------------------

struct Fixture {
    _directory: tempfile::TempDir,
    path: String,
    size: u64,
    lines: u64,
}

/// A text file of about 1.6 MB: enough for dozens of blocks and ranges.
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lines.txt");
    let lines = 60_000;
    let mut file = std::fs::File::create(&path).unwrap();
    for line in 0..lines {
        writeln!(file, "line {line} of the fixture").unwrap();
    }
    drop(file);
    Fixture {
        size: std::fs::metadata(&path).unwrap().len(),
        path: path.to_str().unwrap().to_owned(),
        lines,
        _directory: directory,
    }
}

fn register(connection: &Connection) -> Result<(Arc<Opens>, Arc<Opens>)> {
    let (in_init, in_claim) = (Arc::new(Opens::default()), Arc::new(Opens::default()));
    let signature = || SignatureBuilder::new().param(FunctionParameter::new::<String>("path"));
    TableFunctionBuilder::new(
        "blocks_opened_in_init",
        signature(),
        OpenedInInit(in_init.clone()),
    )
    .register(connection)?;
    TableFunctionBuilder::new(
        "blocks_opened_in_claim",
        signature(),
        OpenedInClaim(in_claim.clone()),
    )
    .with_claim_batch()
    .register(connection)?;
    Ok((in_init, in_claim))
}

fn row(cells: &[u64]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

#[test]
fn file_opened_in_init_local_state_is_read_by_later_exec_calls() -> Result<()> {
    let connection = connect()?;
    let (opens, _) = register(&connection)?;
    let fixture = fixture();
    let blocks = fixture.size.div_ceil(BLOCK as u64);
    assert!(blocks > 20, "the fixture should span many exec calls");

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*), sum(bytes), sum(newlines) FROM blocks_opened_in_init('{}')",
                fixture.path
            ),
        )?,
        [row(&[blocks, fixture.size, fixture.lines])]
    );
    // One open served every block.
    assert_eq!(opens.0.load(Ordering::Relaxed), 1);
    Ok(())
}

/// What one run of `blocks_opened_in_claim` read: the worker of each range, and the totals.
struct ClaimedRead {
    worker_of_range: BTreeMap<u64, u64>,
    bytes: u64,
    newlines: u64,
}

impl ClaimedRead {
    fn workers(&self) -> usize {
        self.worker_of_range.values().collect::<BTreeSet<_>>().len()
    }
}

fn read_claimed(connection: &Connection, path: &str) -> Result<ClaimedRead> {
    // Grouping without DISTINCT aggregates: those make DuckDB run the scan on one thread.
    let groups = rows(
        connection,
        &format!(
            "SELECT worker, range_index, sum(bytes), sum(newlines) \
             FROM blocks_opened_in_claim('{path}') GROUP BY ALL"
        ),
    )?;
    let mut read = ClaimedRead {
        worker_of_range: BTreeMap::new(),
        bytes: 0,
        newlines: 0,
    };
    for group in groups {
        let cell = |index: usize| group[index].parse::<u64>().unwrap();
        // Every block of a range has to come from the worker that claimed the range.
        let previous = read.worker_of_range.insert(cell(1), cell(0));
        assert_eq!(previous, None, "range {} was read by two workers", cell(1));
        read.bytes += cell(2);
        read.newlines += cell(3);
    }
    Ok(read)
}

#[test]
fn file_opened_in_claim_batch_is_read_across_batches_and_threads() -> Result<()> {
    let connection = connect()?;
    let (_, opens) = register(&connection)?;
    let fixture = fixture();
    let ranges = fixture.size.div_ceil(RANGE);
    assert!(ranges > 8, "the fixture should span many batches");

    for threads in [1, 4] {
        connection.execute(
            format!("SET threads = {threads}").as_str(),
            Parameters::None,
        )?;
        let read = read_claimed(&connection, &fixture.path)?;
        assert!(read.worker_of_range.keys().copied().eq(0..ranges));
        assert_eq!((read.bytes, read.newlines), (fixture.size, fixture.lines));

        let workers = read.workers();
        if threads == 1 {
            assert_eq!(workers, 1);
        } else {
            assert!(
                (2..=4).contains(&workers),
                "{workers} workers read the file"
            );
        }
        // Each worker opened the file once and kept it for every range it claimed.
        assert_eq!(opens.0.swap(0, Ordering::Relaxed), workers);
    }
    Ok(())
}

#[test]
fn opens_go_through_the_file_system_of_the_database() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    let fixture = fixture();
    let query = format!(
        "SELECT sum(bytes) FROM blocks_opened_in_init('{}')",
        fixture.path
    );
    assert_eq!(value(&connection, &query)?, fixture.size.to_string());

    // A missing file is DuckDB's error, not ours.
    let error = value(
        &connection,
        "SELECT sum(bytes) FROM blocks_opened_in_init('/nonexistent/x.txt')",
    )
    .unwrap_err();
    assert!(error.message.contains("/nonexistent/x.txt"), "{error}");

    // With external access switched off, the same open is refused.
    connection.execute("SET enable_external_access = false", Parameters::None)?;
    let error = value(&connection, &query).unwrap_err();
    assert_eq!(error.code, DuckDBError::ConfigurationPermission, "{error}");
    assert!(
        error.message.contains("disabled by configuration"),
        "{error}"
    );
    Ok(())
}

/// Remote paths are not read here (that needs the httpfs extension, see roadmap U7), but the
/// open is dispatched by scheme: without httpfs, DuckDB names the extension that would serve it.
#[test]
fn remote_paths_are_left_to_the_file_system_that_serves_them() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    // Keep DuckDB from fetching httpfs, so that the outcome does not depend on the network.
    connection.execute("SET autoinstall_known_extensions = false", Parameters::None)?;
    connection.execute("SET autoload_known_extensions = false", Parameters::None)?;

    for url in ["https://example.invalid/lines.txt", "s3://bucket/lines.txt"] {
        let error = value(
            &connection,
            &format!("SELECT sum(bytes) FROM blocks_opened_in_init('{url}')"),
        )
        .unwrap_err();
        assert_eq!(error.code, DuckDBError::ResourceMissingExtension, "{error}");
        assert!(
            error
                .message
                .contains("requires the extension httpfs to be loaded"),
            "{error}"
        );
    }
    Ok(())
}
