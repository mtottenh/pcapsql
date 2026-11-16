//! `engine::guard` for an aggregate function: a panic in a callback fails the statement and
//! nothing else, the callback that cannot fail (`init`) included, and a state DuckDB destroys
//! is dropped.
//!
//! # The states DuckDB 2.0.0 does not destroy
//!
//! The states are counted exactly here, which shows what the memory of a process only hints
//! at: DuckDB destroys the states of a grouped aggregation as it returns their groups, and the
//! states of groups it never returns are not destroyed at all. That is a grouped aggregation
//! under a `LIMIT` without an `ORDER BY`, and a statement that fails while its groups are
//! combined or returned. (`RadixHTGlobalSinkState::Destroy` in
//! `src/execution/radix_partitioned_hashtable.cpp` of DuckDB 2.0.0 returns at once in the
//! state every hash aggregation starts in.) It holds for any aggregate function whose state
//! owns memory, and nothing an extension does in its callbacks can change it: the callback
//! that would free is the one that is not called. The last test pins it, so that a DuckDB
//! release that destroys those states is noticed.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use duckdb_neo::{
    aggregate::ReturnTypeHandle,
    bind_arguments::BindArguments,
    connection::{Connection, Context},
    data_chunk::VectorCollection,
    error::DuckDBError,
    signature::{FunctionParameter, SignatureBuilder},
    vector::{Unknown, Vector},
    DuckDBType, Parameters, Result,
};
use pcapsql_duckdb::engine::guard::{self, Aggregate, Slots, SourceSlots};
use pcapsql_duckdb_itest::{connect, rows, value};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Callback {
    Bind,
    Init,
    Update,
    Combine,
    Finalize,
    Never,
}

impl Callback {
    /// The callback's name in the guard's error message.
    fn label(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Init => "init",
            Self::Update => "update",
            Self::Combine => "combine",
            Self::Finalize => "finalize",
            Self::Never => unreachable!(),
        }
    }
}

/// What the callbacks of a [`GuardedSum`] did.
#[derive(Debug, Default)]
struct Counters {
    /// States `init` returned.
    made: AtomicU64,
    /// States made and not yet dropped.
    live: AtomicI64,
    /// States `combine` added to another.
    combined: AtomicU64,
}

/// The state of a group: its sum, and the count it is taken off when DuckDB destroys it.
struct Sum {
    total: i64,
    counters: Arc<Counters>,
}

impl Drop for Sum {
    fn drop(&mut self) {
        self.counters.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `sum(BIGINT)`, unless it reaches its callback first.
struct GuardedSum {
    panic_in: Callback,
    counters: Arc<Counters>,
}

impl GuardedSum {
    fn reached(&self, callback: Callback) {
        if self.panic_in == callback {
            panic!("deliberate panic in {callback:?}");
        }
    }
}

impl Aggregate for GuardedSum {
    type BindData = ();
    type State = Sum;

    fn bind(
        &self,
        _context: &Context,
        _arguments: BindArguments<'_>,
        _result_type: ReturnTypeHandle<'_>,
    ) -> Result<()> {
        self.reached(Callback::Bind);
        Ok(())
    }

    fn init(&self, _bind_data: Option<&()>) -> Sum {
        self.reached(Callback::Init);
        self.counters.made.fetch_add(1, Ordering::SeqCst);
        self.counters.live.fetch_add(1, Ordering::SeqCst);
        Sum {
            total: 0,
            counters: self.counters.clone(),
        }
    }

    fn update(
        &self,
        _bind_data: Option<&()>,
        data: &mut VectorCollection,
        mut states: Slots<'_, '_, Sum>,
    ) -> Result<()> {
        self.reached(Callback::Update);
        let values = data.get_vector_at::<i64>(0)?;
        for (row, value) in values.reader()?.iter().enumerate() {
            if let Some(value) = value {
                states.get_mut(row)?.total += value;
            }
        }
        Ok(())
    }

    fn combine(
        &self,
        _bind_data: Option<&()>,
        source: &SourceSlots<'_, '_, Sum>,
        mut target: Slots<'_, '_, Sum>,
    ) -> Result<()> {
        self.reached(Callback::Combine);
        assert_eq!(source.len(), target.len());
        assert_eq!(source.is_empty(), target.is_empty());
        for index in 0..target.len() {
            target.get_mut(index)?.total += source.get(index)?.total;
            self.counters.combined.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn finalize(
        &self,
        _bind_data: Option<&()>,
        states: &[&Sum],
        result: Vector<'_, Unknown>,
        result_offset: usize,
    ) -> Result<()> {
        self.reached(Callback::Finalize);
        let mut result = result.cast::<i64>()?;
        let mut writer = result.writer()?;
        for (index, state) in states.iter().enumerate() {
            writer.set(result_offset + index, &state.total)?;
        }
        Ok(())
    }
}

/// Register `name` as a guarded sum that panics in `panic_in`, and return its counters.
fn register(connection: &Connection, name: &str, panic_in: Callback) -> Result<Arc<Counters>> {
    let counters = Arc::new(Counters::default());
    let signature = SignatureBuilder::new()
        .param(FunctionParameter::new::<i64>("x"))
        .return_type(i64::logical_type(connection)?);
    let function = GuardedSum {
        panic_in,
        counters: counters.clone(),
    };
    guard::aggregate_function(name, signature, function).register(connection)?;
    Ok(counters)
}

/// Keep the panics these tests cause on purpose out of the test output; DuckDB's worker threads
/// are not covered by the test harness's output capture.
fn quiet_deliberate_panics() {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            if !message.is_some_and(|text| text.starts_with("deliberate panic")) {
                default_hook(info);
            }
        }));
    });
}

/// A connection with four threads and a table DuckDB scans on several of them: `numbers(i)`,
/// 600,000 rows.
fn connection_with_numbers() -> Result<Connection> {
    let connection = connect()?;
    connection.execute("SET threads = 4", Parameters::None)?;
    connection.execute(
        "CREATE TABLE numbers AS SELECT i FROM range(600000) t(i)",
        Parameters::None,
    )?;
    Ok(connection)
}

/// The connection answers a plain query and runs the extension's own aggregate function.
fn assert_usable(connection: &Connection) {
    assert_eq!(value(connection, "SELECT 42").unwrap(), "42");
    assert_eq!(
        value(
            connection,
            "SELECT hdr_count(hdr_histogram(i)) FROM range(1000) t(i)"
        )
        .unwrap(),
        "1000"
    );
}

#[test]
fn guarded_aggregate_panic_is_an_ordinary_error() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connection_with_numbers()?;
    for callback in [
        Callback::Bind,
        Callback::Init,
        Callback::Update,
        Callback::Combine,
        Callback::Finalize,
    ] {
        let name = format!("sum_panic_in_{}", callback.label());
        let counters = register(&connection, &name, callback)?;
        // Many groups over a table scanned on four threads: every callback is reached.
        let statement =
            format!("SELECT i % 1000 AS g, {name}(i) FROM numbers GROUP BY g ORDER BY g");

        let error = rows(&connection, &statement).unwrap_err();
        assert_eq!(error.code, DuckDBError::QueryExecutor, "{error}");
        assert!(
            error.message.contains(&format!(
                "pcapsql: panic in {name} ({}): deliberate panic in {callback:?}",
                callback.label()
            )),
            "{error}"
        );

        // The same connection keeps working, and so does the function that panicked: it fails
        // the same way again, which an invalidated database would not let it reach.
        assert_usable(&connection);
        let again = rows(&connection, &statement).unwrap_err();
        assert_eq!(again.code, DuckDBError::QueryExecutor, "{again}");
        // A window and an aggregate without groups reach the callback too. (`combine` is not
        // one a window over a few rows needs.)
        if callback != Callback::Combine {
            let window = format!("SELECT {name}(i) OVER (ORDER BY i) FROM range(10) t(i)");
            let error = rows(&connection, &window).unwrap_err();
            assert_eq!(error.code, DuckDBError::QueryExecutor, "{window}: {error}");
        }

        // A state whose `init` panicked was never made, and the states of a statement that
        // failed while it read its rows were destroyed. Those of one that failed later, while
        // DuckDB combined or returned its groups, are the ones it leaves (see the module
        // documentation).
        assert_usable(&connection);
        let (made, live) = (
            counters.made.load(Ordering::SeqCst),
            counters.live.load(Ordering::SeqCst),
        );
        match callback {
            Callback::Bind | Callback::Init => assert_eq!((made, live), (0, 0), "{callback:?}"),
            Callback::Update => assert!(made > 0 && live == 0, "{callback:?}: {made} {live}"),
            _ => assert!(made > 0, "{callback:?}"),
        }
    }
    Ok(())
}

#[test]
fn guarded_aggregate_without_a_panic_aggregates_and_frees_every_state() -> Result<()> {
    let connection = connection_with_numbers()?;
    let counters = register(&connection, "guarded_sum", Callback::Never)?;

    // Grouped, on four threads: the sums are DuckDB's own.
    let differing = value(
        &connection,
        "SELECT count(*) FILTER (ours IS DISTINCT FROM theirs) || ' of ' || count(*)
         FROM (SELECT i % 5000 AS g, guarded_sum(i) AS ours, sum(i)::BIGINT AS theirs
               FROM numbers GROUP BY g)",
    )?;
    assert_eq!(differing, "0 of 5000");
    // DuckDB aggregated on several threads and combined their states: more states than
    // groups were made, and `combine` ran.
    let made = counters.made.load(Ordering::SeqCst);
    let combined = counters.combined.load(Ordering::SeqCst);
    assert!(made > 5000, "{made} states for 5000 groups");
    assert!(combined >= 5000, "{combined} states were combined");

    // Without groups, with FILTER and DISTINCT, as a window, and over no rows.
    assert_eq!(
        rows(
            &connection,
            "SELECT guarded_sum(i), guarded_sum(i) FILTER (i < 10), guarded_sum(DISTINCT i % 3),
                    guarded_sum(NULL::BIGINT)
             FROM numbers",
        )?,
        [["179999700000", "45", "3", "0"].map(String::from).to_vec()]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT sum(running) FROM (SELECT guarded_sum(i) OVER (ORDER BY i ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS running
                                       FROM range(100000) t(i))",
        )?,
        "14999550004"
    );
    assert_eq!(
        value(
            &connection,
            "SELECT guarded_sum(i) FROM numbers WHERE false"
        )?,
        "0"
    );

    // A `LIMIT` over groups that were all aggregated and sorted first.
    assert_eq!(
        rows(
            &connection,
            "SELECT i % 50000 AS g, guarded_sum(i) FROM numbers GROUP BY g ORDER BY g LIMIT 3",
        )?,
        [["0", "3300000"], ["1", "3300012"], ["2", "3300024"]]
            .map(|cells| cells.map(String::from).to_vec())
    );

    // Every state that was made was destroyed: in all, some hundred thousand.
    assert_eq!(value(&connection, "SELECT 42")?, "42");
    assert!(counters.made.load(Ordering::SeqCst) > made + 150_000);
    assert_eq!(counters.live.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Not what the guard does, but what DuckDB 2.0.0 does to any aggregate function with a state
/// to free (see the module documentation): the states of groups a grouped aggregation never
/// returns are not destroyed.
#[test]
fn duckdb_does_not_destroy_the_states_of_groups_it_does_not_return() -> Result<()> {
    let connection = connection_with_numbers()?;
    let counters = register(&connection, "pinned_sum", Callback::Never)?;
    let live = || counters.live.load(Ordering::SeqCst);

    // Read to its end: every state is destroyed.
    assert_eq!(
        rows(
            &connection,
            "SELECT i % 50000 AS g, pinned_sum(i) FROM numbers GROUP BY g",
        )?
        .len(),
        50000
    );
    assert_eq!(live(), 0);

    // Three groups of 50,000 returned: the states of most of the others stay, also once the
    // result and the connection are gone.
    assert_eq!(
        rows(
            &connection,
            "SELECT i % 50000 AS g, pinned_sum(i) FROM numbers GROUP BY g LIMIT 3",
        )?
        .len(),
        3
    );
    assert_eq!(value(&connection, "SELECT 42")?, "42");
    let left = live();
    assert!(left > 40_000, "{left} states are left");
    drop(connection);
    assert_eq!(live(), left);
    Ok(())
}
