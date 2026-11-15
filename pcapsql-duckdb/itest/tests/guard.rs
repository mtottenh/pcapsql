//! `engine::guard`: a panic in a callback fails the query and nothing else.

use std::num::NonZeroUsize;

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::{DataChunkRef, VectorCollection},
    error::DuckDBError,
    multi_file::MultiFileFunctionBuilder,
    scalar::{ScalarCallbacks, ScalarFunctionBuilder},
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{
        BindFunctionHandle, BindInfoApi, ExecColumnInfo, InitColumnData, PartitionData,
        PartitioningData, PushdownData, TableClaimBatchCallbacks, TableFilterPushdownCallbacks,
        TableFunctionBuilder, TableFunctionCallbacks, TableGetBindInfoCallbacks,
        TablePartitionInfo, TablePartitioningCallbacks,
    },
    vector::{Unknown, Vector},
    DuckDBType, Parameters, Result,
};
use pcapsql_duckdb::engine::guard;
use pcapsql_duckdb_itest::{connect, value};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Callback {
    Bind,
    InitGlobalState,
    MaxThreads,
    InitLocalState,
    ClaimBatch,
    Exec,
    PushdownFilter,
    PartitionData,
    Partitioning,
    BindInfo,
    Never,
}

/// A table function that returns one row of one BIGINT, unless it reaches its callback first.
struct PanicIn(Callback);

impl PanicIn {
    fn reached(&self, callback: Callback) {
        if self.0 == callback {
            panic!("deliberate panic in {callback:?}");
        }
    }
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
            let deliberate = message.is_some_and(|text| text.starts_with("deliberate panic"));
            if !deliberate {
                default_hook(info);
            }
        }));
    });
}

impl TableFunctionCallbacks for PanicIn {
    type BindData = ();
    type GlobalState = ();
    /// Whether this worker has produced its row.
    type LocalState = bool;

    fn bind(
        &self,
        context: &Context,
        _arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<()> {
        self.reached(Callback::Bind);
        bind_handle.add_result_column("x", &i64::logical_type(context)?)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bind_data: &(),
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<()>> {
        self.reached(Callback::InitGlobalState);
        Ok(None)
    }

    fn max_threads(
        &self,
        _context: &Context,
        _bind_data: &(),
        _global_state: Option<&()>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        self.reached(Callback::MaxThreads);
        Ok(None)
    }

    fn init_local_state(
        &self,
        _context: &Context,
        _bind_data: &(),
        _global_state: Option<&()>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<bool>> {
        self.reached(Callback::InitLocalState);
        Ok(Some(false))
    }

    fn exec(
        &self,
        _context: &Context,
        _bind_data: &(),
        done: Option<&mut bool>,
        _global_state: Option<&()>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        self.reached(Callback::Exec);
        let done = done.expect("init_local_state returns a state");
        if !std::mem::replace(done, true) {
            let mut vector = output.get_vector_at_mut::<i64>(0)?;
            vector.set_size(1)?;
            vector.writer()?.set(0, &42)?;
        }
        Ok(())
    }
}

impl TableClaimBatchCallbacks for PanicIn {
    fn claim_batch(
        &self,
        _context: &Context,
        _bind_data: &(),
        done: Option<&mut bool>,
        _global_state: Option<&()>,
    ) -> Result<bool> {
        self.reached(Callback::ClaimBatch);
        Ok(!*done.expect("init_local_state returns a state"))
    }
}

impl TableFilterPushdownCallbacks for PanicIn {
    fn pushdown_filter(
        &self,
        _context: &Context,
        _bind_data: &(),
        _pushdown_data: PushdownData<'_>,
    ) -> Result<()> {
        self.reached(Callback::PushdownFilter);
        Ok(())
    }
}

impl TablePartitioningCallbacks for PanicIn {
    fn partition_data(
        &self,
        _context: &Context,
        _bind_data: &(),
        _done: Option<&mut bool>,
        _global_state: Option<&()>,
        _partition_data: PartitionData<'_>,
    ) -> Result<usize> {
        self.reached(Callback::PartitionData);
        Ok(0)
    }

    fn partitioning(
        &self,
        _context: &Context,
        _bind_data: &(),
        _partitioning_data: PartitioningData<'_>,
    ) -> Result<TablePartitionInfo> {
        self.reached(Callback::Partitioning);
        Ok(TablePartitionInfo::NotPartitioned)
    }
}

impl TableGetBindInfoCallbacks for PanicIn {
    fn bind_info(&self, _context: &Context, _bind_data: &(), _api: BindInfoApi<'_>) -> Result<()> {
        self.reached(Callback::BindInfo);
        Ok(())
    }
}

/// A scalar function that panics on every call.
struct PanickingScalar;

impl ScalarCallbacks for PanickingScalar {
    type BindData = ();
    type InitData = ();

    fn exec(
        &self,
        _context: &Context,
        _bind_data: Option<&()>,
        _init_data: Option<&mut ()>,
        _vectors: &mut VectorCollection,
        _output: Vector<'_, Unknown>,
    ) -> Result<()> {
        panic!("deliberate panic in a scalar");
    }
}

fn scalar_signature(connection: &Connection) -> Result<SignatureBuilder> {
    Ok(SignatureBuilder::new()
        .param(FunctionParameter::new::<i64>("x"))
        .return_type(i64::logical_type(connection)?))
}

/// The connection answers a plain query and runs the extension's own functions.
fn assert_usable(connection: &Connection) {
    assert_eq!(value(connection, "SELECT 42").unwrap(), "42");
    assert_eq!(
        value(connection, "SELECT count(*) FROM pcap_protocols()").unwrap(),
        "28"
    );
    assert_eq!(
        value(connection, "SELECT ip4_to_string(ip4('10.0.0.1'))").unwrap(),
        "10.0.0.1"
    );
}

/// The query that makes DuckDB call `callback` of the function `name`, and the callback's name
/// in the guard's error message.
fn query_reaching(callback: Callback, name: &str) -> (String, &'static str) {
    match callback {
        Callback::Bind => (format!("SELECT x FROM {name}()"), "bind"),
        Callback::InitGlobalState => (format!("SELECT x FROM {name}()"), "init_global_state"),
        Callback::MaxThreads => (format!("SELECT x FROM {name}()"), "max_threads"),
        Callback::InitLocalState => (format!("SELECT x FROM {name}()"), "init_local_state"),
        Callback::ClaimBatch => (format!("SELECT x FROM {name}()"), "claim_batch"),
        Callback::Exec => (format!("SELECT x FROM {name}()"), "exec"),
        // Filters are offered when the optimizer has some to push down.
        Callback::PushdownFilter => (
            format!("SELECT x FROM {name}() WHERE x > 0"),
            "pushdown_filter",
        ),
        // An ordered result on more than one thread asks every chunk for its batch index.
        Callback::PartitionData => (format!("SELECT x FROM {name}()"), "partition_data"),
        // The optimizer asks how the scan is partitioned by the grouping columns.
        Callback::Partitioning => (
            format!("SELECT x, count(*) FROM {name}() GROUP BY x"),
            "partitioning",
        ),
        Callback::BindInfo | Callback::Never => unreachable!(),
    }
}

#[test]
fn guarded_table_function_panic_is_an_ordinary_error() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connect()?;
    connection.execute("SET threads = 4", Parameters::None)?;
    for (name, callback) in [
        ("panic_in_bind", Callback::Bind),
        ("panic_in_init_global_state", Callback::InitGlobalState),
        ("panic_in_max_threads", Callback::MaxThreads),
        ("panic_in_init_local_state", Callback::InitLocalState),
        ("panic_in_claim_batch", Callback::ClaimBatch),
        ("panic_in_exec", Callback::Exec),
        ("panic_in_pushdown_filter", Callback::PushdownFilter),
        ("panic_in_partition_data", Callback::PartitionData),
        ("panic_in_partitioning", Callback::Partitioning),
    ] {
        guard::table_function(name, SignatureBuilder::new(), PanicIn(callback))
            .with_claim_batch()
            .with_filter_pushdown()
            .with_partitioning()
            .register(&connection)?;
        let (query, label) = query_reaching(callback, name);

        let error = value(&connection, &query).unwrap_err();
        assert_eq!(error.code, DuckDBError::QueryExecutor, "{error}");
        assert!(
            error.message.contains(&format!(
                "pcapsql: panic in {name} ({label}): deliberate panic in {callback:?}"
            )),
            "{error}"
        );

        // The same connection keeps working, and so does the function that panicked: here it
        // fails the same way again, which an invalidated database would not let it reach.
        assert_usable(&connection);
        let again = value(&connection, &query).unwrap_err();
        assert_eq!(again.code, DuckDBError::QueryExecutor, "{again}");
    }
    assert_usable(&connection);
    Ok(())
}

/// `bind_info` is called by the multi-file wrapper, for each file it binds.
#[test]
fn guarded_bind_info_panic_is_an_ordinary_error() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connect()?;
    guard::table_function(
        "panic_in_bind_info_file",
        SignatureBuilder::new().param(FunctionParameter::new::<String>("file")),
        PanicIn(Callback::BindInfo),
    )
    .with_claim_batch()
    .with_get_bind_info()
    .register(&connection)?;
    MultiFileFunctionBuilder::new("panic_in_bind_info", "panic_in_bind_info_file")
        .register(&connection)?;
    let file = tempfile::NamedTempFile::new().unwrap();
    let query = format!(
        "SELECT x FROM panic_in_bind_info('{}')",
        file.path().display()
    );

    let error = value(&connection, &query).unwrap_err();
    assert_eq!(error.code, DuckDBError::QueryExecutor, "{error}");
    assert!(
        error.message.contains(
            "pcapsql: panic in panic_in_bind_info_file (bind_info): deliberate panic in BindInfo"
        ),
        "{error}"
    );
    assert_usable(&connection);
    Ok(())
}

#[test]
fn guarded_table_function_without_a_panic_returns_rows() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connect()?;
    guard::table_function(
        "guarded_ok",
        SignatureBuilder::new(),
        PanicIn(Callback::Never),
    )
    .with_claim_batch()
    .register(&connection)?;
    assert_eq!(value(&connection, "SELECT x FROM guarded_ok()")?, "42");
    Ok(())
}

#[test]
fn guarded_scalar_panic_is_an_ordinary_error() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connect()?;
    guard::scalar_function(
        "guarded_scalar_panic",
        scalar_signature(&connection)?,
        PanickingScalar,
    )
    .register(&connection)?;

    let error = value(
        &connection,
        "SELECT guarded_scalar_panic(i) FROM range(3) t(i)",
    )
    .unwrap_err();
    assert_eq!(error.code, DuckDBError::QueryExecutor, "{error}");
    assert!(
        error.message.contains(
            "pcapsql: panic in guarded_scalar_panic (exec): deliberate panic in a scalar"
        ),
        "{error}"
    );
    assert_usable(&connection);
    Ok(())
}

/// What the guard prevents: without it, `duckdb-neo` reports the panic as INTERNAL, and DuckDB
/// then refuses every later query on the database.
#[test]
fn unguarded_panic_invalidates_the_database() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connect()?;
    TableFunctionBuilder::new(
        "unguarded_panic",
        SignatureBuilder::new(),
        PanicIn(Callback::Exec),
    )
    .with_claim_batch()
    .register(&connection)?;
    ScalarFunctionBuilder::new(
        "unguarded_scalar_panic",
        scalar_signature(&connection)?,
        PanickingScalar,
    )
    .register(&connection)?;
    assert_usable(&connection);

    let error = value(&connection, "SELECT x FROM unguarded_panic()").unwrap_err();
    assert_eq!(error.code, DuckDBError::RuntimeInternal, "{error}");
    assert!(error.message.contains("Panic occurred"), "{error}");

    let after = value(&connection, "SELECT 42").unwrap_err();
    assert_eq!(after.code, DuckDBError::RuntimeFatal, "{after}");
    assert!(
        after.message.contains("database has been invalidated"),
        "{after}"
    );

    // A scalar panic does the same to a fresh database.
    let connection = connect()?;
    ScalarFunctionBuilder::new(
        "unguarded_scalar_panic",
        scalar_signature(&connection)?,
        PanickingScalar,
    )
    .register(&connection)?;
    let error = value(
        &connection,
        "SELECT unguarded_scalar_panic(i) FROM range(3) t(i)",
    )
    .unwrap_err();
    assert_eq!(error.code, DuckDBError::RuntimeInternal, "{error}");
    let after = value(&connection, "SELECT 42").unwrap_err();
    assert_eq!(after.code, DuckDBError::RuntimeFatal, "{after}");
    Ok(())
}
