//! Spike U5: batch indices and row order under a parallel scan.
//!
//! The reader splits a capture into partitions that several workers scan, and its output has to
//! come back in frame order without an ORDER BY. The test function `batches(n, rows)` emits `n`
//! batches of `rows` rows each. Workers claim batches in increasing order through `claim_batch`,
//! emit each batch as several chunks, and (depending on the variant) report the batch's ordinal
//! through `partition_data`.
//!
//! What this establishes for DuckDB 2.0.0 and `duckdb-neo` 0.20000.2:
//!
//! - Consecutive chunks of one worker may report the same batch index. The index must not
//!   decrease on a worker (an ordinary error says so) and must stay below 10^13
//!   (`PipelineBuildState::BATCH_INCREMENT`, read in the DuckDB source).
//! - With batch indices reported, DuckDB runs the scan on several threads and still returns,
//!   inserts and limits rows in batch-index order.
//! - `partition_data` is only called when something downstream needs the order: not for an
//!   aggregate.
//! - Without `partition_data`, an order-preserving query runs the scan on one thread; queries
//!   whose sink does not care about order still run in parallel. Declaring
//!   `OrderPreservation::None` lets every query run in parallel, in whatever order.
//! - Two workers that report the same batch index break the ordered result: see
//!   `duplicate_batch_indices_across_workers`.

use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    error::{DuckDBError, Error},
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, OrderPreservation, PartitionData,
        TableClaimBatchCallbacks, TableFunctionBuilder, TableFunctionCallbacks,
        TablePartitioningCallbacks,
    },
    DuckDBType, Parameters, Result,
};
use pcapsql_duckdb_itest::{connect, rows};

/// Rows per chunk: a batch of 1000 rows takes four `exec` calls.
const CHUNK: u64 = 300;

/// The batch index `partition_data` reports for the chunk a worker just produced.
#[derive(Clone, Copy)]
enum Reported {
    /// The ordinal of the batch the chunk belongs to.
    Ordinal,
    /// Zero, whatever the batch: every worker reports the same index.
    AlwaysZero,
    /// Counting down from the last batch: decreases whenever a worker claims a new batch.
    CountingDown,
}

#[derive(Default)]
struct Observed {
    partition_data_calls: AtomicUsize,
    /// Calls that reported the same index as the previous call on that worker.
    repeated_index_calls: AtomicUsize,
}

struct Batches {
    reported: Reported,
    order: OrderPreservation,
    /// Hold back output until a second worker exists, so that two workers certainly emit rows.
    wait_for_second_worker: bool,
    observed: Arc<Observed>,
}

struct Plan {
    batches: u64,
    rows_per_batch: u64,
}

struct Shared {
    next_batch: AtomicU64,
    workers: AtomicU64,
}

struct Worker {
    id: i64,
    batch: u64,
    /// Next row of `batch` to emit; `rows_per_batch` once the batch is exhausted.
    next_row: u64,
    last_reported: Option<usize>,
}

impl TableFunctionCallbacks for Batches {
    type BindData = Plan;
    type GlobalState = Shared;
    type LocalState = Worker;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Plan> {
        for name in ["batch", "row_in_batch", "worker"] {
            bind_handle.add_result_column(name, &i64::logical_type(context)?)?;
        }
        bind_handle.set_order(self.order)?;
        let argument = |index: usize| {
            arguments[index]
                .value
                .as_ref()
                .and_then(|value| value.get::<i64>().ok().flatten())
                .map(|value| value as u64)
                .ok_or_else(|| Error::invalid_input("expected two BIGINT arguments"))
        };
        Ok(Plan {
            batches: argument(0)?,
            rows_per_batch: argument(1)?,
        })
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _plan: &Plan,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Shared>> {
        Ok(Some(Shared {
            next_batch: AtomicU64::new(0),
            workers: AtomicU64::new(0),
        }))
    }

    fn max_threads(
        &self,
        _context: &Context,
        _plan: &Plan,
        _shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        Ok(NonZeroUsize::new(4))
    }

    fn init_local_state(
        &self,
        _context: &Context,
        plan: &Plan,
        shared: Option<&Shared>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Worker>> {
        Ok(Some(Worker {
            id: shared.unwrap().workers.fetch_add(1, Ordering::Relaxed) as i64,
            batch: 0,
            next_row: plan.rows_per_batch,
            last_reported: None,
        }))
    }

    fn exec(
        &self,
        _context: &Context,
        plan: &Plan,
        worker: Option<&mut Worker>,
        shared: Option<&Shared>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let worker = worker.unwrap();
        // An empty chunk ends the batch; DuckDB then has this worker claim the next one.
        let rows = (plan.rows_per_batch - worker.next_row).min(CHUNK) as usize;
        if rows == 0 {
            return Ok(());
        }

        if self.wait_for_second_worker {
            let deadline = Instant::now() + Duration::from_secs(10);
            while shared.unwrap().workers.load(Ordering::Relaxed) < 2 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // Give the other workers time to claim batches of their own.
        std::thread::sleep(Duration::from_micros(300));

        let columns: [&dyn Fn(usize) -> i64; 3] = [
            &|_| worker.batch as i64,
            &|row| (worker.next_row + row as u64) as i64,
            &|_| worker.id,
        ];
        for (column, cell) in columns.iter().enumerate() {
            let mut vector = output.get_vector_at_mut::<i64>(column)?;
            vector.set_size(rows)?;
            let mut writer = vector.writer()?;
            for row in 0..rows {
                writer.set(row, &cell(row))?;
            }
        }
        worker.next_row += rows as u64;
        Ok(())
    }
}

impl TableClaimBatchCallbacks for Batches {
    fn claim_batch(
        &self,
        _context: &Context,
        plan: &Plan,
        worker: Option<&mut Worker>,
        shared: Option<&Shared>,
    ) -> Result<bool> {
        let worker = worker.unwrap();
        // Batches are handed out in increasing order, so each worker's batches increase too.
        worker.batch = shared.unwrap().next_batch.fetch_add(1, Ordering::Relaxed);
        worker.next_row = 0;
        Ok(worker.batch < plan.batches)
    }
}

impl TablePartitioningCallbacks for Batches {
    fn partition_data(
        &self,
        _context: &Context,
        plan: &Plan,
        worker: Option<&mut Worker>,
        _shared: Option<&Shared>,
        _partition_data: PartitionData<'_>,
    ) -> Result<usize> {
        let worker = worker.unwrap();
        let index = match self.reported {
            Reported::Ordinal => worker.batch,
            Reported::AlwaysZero => 0,
            Reported::CountingDown => plan.batches - worker.batch,
        } as usize;
        self.observed
            .partition_data_calls
            .fetch_add(1, Ordering::Relaxed);
        if worker.last_reported.replace(index) == Some(index) {
            self.observed
                .repeated_index_calls
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(index)
    }
}

fn signature() -> SignatureBuilder {
    SignatureBuilder::new()
        .param(FunctionParameter::new::<i64>("batches"))
        .param(FunctionParameter::new::<i64>("rows_per_batch"))
}

/// Register `name` as a batch function that reports batch indices as `reported` says.
fn register_reporting(
    connection: &Connection,
    name: &str,
    reported: Reported,
) -> Result<Arc<Observed>> {
    let observed = Arc::new(Observed::default());
    let batches = Batches {
        reported,
        order: OrderPreservation::Insertion,
        wait_for_second_worker: matches!(reported, Reported::AlwaysZero),
        observed: observed.clone(),
    };
    TableFunctionBuilder::new(name, signature(), batches)
        .with_claim_batch()
        .with_partitioning()
        .register(connection)?;
    Ok(observed)
}

/// Register `name` as a batch function without a `partition_data` callback.
fn register_silent(connection: &Connection, name: &str, order: OrderPreservation) -> Result<()> {
    let batches = Batches {
        reported: Reported::Ordinal,
        order,
        wait_for_second_worker: false,
        observed: Arc::default(),
    };
    TableFunctionBuilder::new(name, signature(), batches)
        .with_claim_batch()
        .register(connection)
}

/// `(batch, row_in_batch)` of every row, in the order a sequential scan produces them.
fn in_order(batches: u64, rows_per_batch: u64) -> Vec<(u64, u64)> {
    (0..batches)
        .flat_map(|batch| (0..rows_per_batch).map(move |row| (batch, row)))
        .collect()
}

struct Scan {
    /// `(batch, row_in_batch)` in result order.
    rows: Vec<(u64, u64)>,
    workers: usize,
}

/// Run a query that returns `batch, row_in_batch, worker`.
fn scan(connection: &Connection, sql: &str) -> Result<Scan> {
    let result = rows(connection, sql)?;
    let cell = |row: &Vec<String>, index: usize| row[index].parse::<u64>().unwrap();
    Ok(Scan {
        rows: result
            .iter()
            .map(|row| (cell(row, 0), cell(row, 1)))
            .collect(),
        workers: result
            .iter()
            .map(|row| cell(row, 2))
            .collect::<BTreeSet<_>>()
            .len(),
    })
}

fn connect_with_threads(threads: usize) -> Result<Connection> {
    let connection = connect()?;
    connection.execute(
        format!("SET threads = {threads}").as_str(),
        Parameters::None,
    )?;
    Ok(connection)
}

#[test]
fn reported_batch_indices_keep_row_order_on_several_threads() -> Result<()> {
    let connection = connect_with_threads(4)?;
    let observed = register_reporting(&connection, "batches", Reported::Ordinal)?;

    let result = scan(&connection, "SELECT * FROM batches(40, 1000)")?;
    assert!(
        result.workers >= 2,
        "the scan ran on {} worker",
        result.workers
    );
    assert!(
        result.rows == in_order(40, 1000),
        "rows are not in batch order"
    );

    // 40 batches of four chunks each: every chunk was reported, and three of every four calls
    // repeated the index of the chunk before it on that worker.
    assert_eq!(observed.partition_data_calls.load(Ordering::Relaxed), 160);
    assert_eq!(observed.repeated_index_calls.load(Ordering::Relaxed), 120);

    // An operator between the scan and the result keeps the order.
    let filtered = scan(
        &connection,
        "SELECT * FROM batches(40, 1000) WHERE row_in_batch % 7 = 3",
    )?;
    let expected: Vec<_> = in_order(40, 1000)
        .into_iter()
        .filter(|(_, row)| row % 7 == 3)
        .collect();
    assert!(filtered.workers >= 2);
    assert!(
        filtered.rows == expected,
        "filtered rows are not in batch order"
    );
    Ok(())
}

#[test]
fn create_table_as_and_limit_follow_batch_order() -> Result<()> {
    let connection = connect_with_threads(4)?;
    register_reporting(&connection, "batches", Reported::Ordinal)?;

    connection.execute(
        "CREATE TABLE t AS SELECT * FROM batches(40, 1000)",
        Parameters::None,
    )?;
    let stored = scan(&connection, "SELECT * FROM t")?;
    assert!(
        stored.workers >= 2,
        "the insert ran on {} worker",
        stored.workers
    );
    assert!(
        stored.rows == in_order(40, 1000),
        "the table is not in batch order"
    );

    connection.execute(
        "INSERT INTO t SELECT * FROM batches(3, 500)",
        Parameters::None,
    )?;
    let appended = scan(&connection, "SELECT * FROM t")?;
    assert!(
        appended.rows[40_000..] == in_order(3, 500),
        "appended rows are not in batch order"
    );

    let all = in_order(40, 1000);
    let limited = scan(&connection, "SELECT * FROM batches(40, 1000) LIMIT 2500")?;
    assert!(
        limited.rows == all[..2500],
        "LIMIT did not return the first rows"
    );
    let window = scan(
        &connection,
        "SELECT * FROM batches(40, 1000) LIMIT 10 OFFSET 12345",
    )?;
    assert_eq!(window.rows, all[12345..12355]);
    Ok(())
}

#[test]
fn partition_data_is_not_called_when_order_does_not_matter() -> Result<()> {
    let connection = connect_with_threads(4)?;
    let observed = register_reporting(&connection, "batches", Reported::Ordinal)?;

    let groups = rows(
        &connection,
        "SELECT worker, count(*) FROM batches(40, 1000) GROUP BY worker",
    )?;
    assert!(groups.len() >= 2, "the scan ran on {} worker", groups.len());
    assert_eq!(observed.partition_data_calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn without_partition_data_an_ordered_query_scans_on_one_thread() -> Result<()> {
    let connection = connect_with_threads(4)?;
    register_silent(&connection, "batches", OrderPreservation::Insertion)?;

    // DuckDB keeps the order by not parallelising the pipeline at all.
    let result = scan(&connection, "SELECT * FROM batches(40, 1000)")?;
    assert_eq!(result.workers, 1);
    assert!(result.rows == in_order(40, 1000));

    connection.execute(
        "CREATE TABLE t AS SELECT * FROM batches(40, 1000)",
        Parameters::None,
    )?;
    let stored = scan(&connection, "SELECT * FROM t")?;
    assert_eq!(stored.workers, 1);
    assert!(stored.rows == in_order(40, 1000));

    // A sink that does not depend on order still gets a parallel scan.
    let groups = rows(
        &connection,
        "SELECT worker, count(*) FROM batches(40, 1000) GROUP BY worker",
    )?;
    assert!(groups.len() >= 2, "the scan ran on {} worker", groups.len());
    Ok(())
}

#[test]
fn order_preservation_none_scans_in_parallel_without_an_order() -> Result<()> {
    let connection = connect_with_threads(4)?;
    register_silent(&connection, "batches", OrderPreservation::None)?;

    let mut result = scan(&connection, "SELECT * FROM batches(40, 1000)")?;
    assert!(
        result.workers >= 2,
        "the scan ran on {} worker",
        result.workers
    );
    // Every row once; their order is whatever the workers produced.
    result.rows.sort_unstable();
    assert!(result.rows == in_order(40, 1000));
    Ok(())
}

#[test]
fn a_decreasing_batch_index_is_an_ordinary_error() -> Result<()> {
    let connection = connect_with_threads(4)?;
    register_reporting(&connection, "decreasing", Reported::CountingDown)?;

    let error = rows(&connection, "SELECT * FROM decreasing(40, 1000)").unwrap_err();
    assert_eq!(error.code, DuckDBError::InputInvalid, "{error}");
    assert!(
        error.message.contains("the batch index must not decrease"),
        "{error}"
    );
    assert_eq!(rows(&connection, "SELECT 42")?, [["42"]]);
    Ok(())
}

/// Batch indices have to differ between workers. If they do not, a plain SELECT returns every
/// row but in no particular order, and an insert fails with an INTERNAL error, which
/// invalidates the database.
#[test]
fn duplicate_batch_indices_across_workers() -> Result<()> {
    let connection = connect_with_threads(4)?;
    register_reporting(&connection, "duplicate", Reported::AlwaysZero)?;

    let mut result = scan(&connection, "SELECT * FROM duplicate(40, 1000)")?;
    assert!(
        result.workers >= 2,
        "the scan ran on {} worker",
        result.workers
    );
    result.rows.sort_unstable();
    assert!(result.rows == in_order(40, 1000));

    let error = connection
        .execute(
            "CREATE TABLE t AS SELECT * FROM duplicate(40, 1000)",
            Parameters::None,
        )
        .unwrap_err();
    assert_eq!(error.code, DuckDBError::RuntimeInternal, "{error}");
    assert!(
        error
            .message
            .contains("batch indexes are not uniquely distributed over threads"),
        "{error}"
    );
    let after = rows(&connection, "SELECT 42").unwrap_err();
    assert_eq!(after.code, DuckDBError::RuntimeFatal, "{after}");
    Ok(())
}
