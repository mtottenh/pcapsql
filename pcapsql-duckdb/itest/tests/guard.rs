//! `engine::guard`: a panic in a callback fails the query and nothing else.

use std::num::NonZeroUsize;

use duckdb_neo::{
    DuckDBType, Result,
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::{DataChunkRef, VectorCollection},
    error::DuckDBError,
    scalar::{ScalarCallbacks, ScalarFunctionBuilder},
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, TableClaimBatchCallbacks,
        TableFunctionBuilder, TableFunctionCallbacks,
    },
    vector::{Unknown, Vector},
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

#[test]
fn guarded_table_function_panic_is_an_ordinary_error() -> Result<()> {
    let connection = connect()?;
    for (name, callback, label) in [
        ("panic_in_bind", Callback::Bind, "bind"),
        (
            "panic_in_init_global_state",
            Callback::InitGlobalState,
            "init_global_state",
        ),
        ("panic_in_max_threads", Callback::MaxThreads, "max_threads"),
        (
            "panic_in_init_local_state",
            Callback::InitLocalState,
            "init_local_state",
        ),
        ("panic_in_claim_batch", Callback::ClaimBatch, "claim_batch"),
        ("panic_in_exec", Callback::Exec, "exec"),
    ] {
        guard::table_function(name, SignatureBuilder::new(), PanicIn(callback))
            .with_claim_batch()
            .register(&connection)?;

        let error = value(&connection, &format!("SELECT x FROM {name}()")).unwrap_err();
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
        let again = value(&connection, &format!("SELECT x FROM {name}()")).unwrap_err();
        assert_eq!(again.code, DuckDBError::QueryExecutor, "{again}");
    }
    assert_usable(&connection);
    Ok(())
}

#[test]
fn guarded_table_function_without_a_panic_returns_rows() -> Result<()> {
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
