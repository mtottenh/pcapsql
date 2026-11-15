//! `engine::guard` for a copy function: a panic in a callback of `COPY ... TO` fails the
//! statement and nothing else.

use std::num::NonZeroUsize;

use duckdb_neo::{
    column_data_collection::ColumnDataCollection,
    connection::{Connection, Context},
    copy_function::{
        CopyToBindInfo, CopyToFunctionCallbacks, CopyToStatistics, CopyToStatisticsCallbacks,
    },
    error::DuckDBError,
    Parameters, Result,
};
use pcapsql_duckdb::engine::guard;
use pcapsql_duckdb_itest::{connect, value, Fixture};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Callback {
    Bind,
    BatchSize,
    Init,
    Batch,
    Flush,
    Finalize,
    Statistics,
    Never,
}

impl Callback {
    /// The callback's name in the guard's error message.
    fn label(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::BatchSize => "batch_size",
            Self::Init => "init",
            Self::Batch => "batch",
            Self::Flush => "flush",
            Self::Finalize => "finalize",
            Self::Statistics => "statistics",
            Self::Never => unreachable!(),
        }
    }
}

/// A copy function that writes nothing, unless it reaches its callback first.
struct PanicIn(Callback);

impl PanicIn {
    fn reached(&self, callback: Callback) {
        if self.0 == callback {
            panic!("deliberate panic in {callback:?}");
        }
    }
}

impl CopyToFunctionCallbacks for PanicIn {
    type InitData = ();
    type BindData = ();
    type BatchData = ();

    fn bind(&self, _context: &Context, _bind_info: &CopyToBindInfo) -> Result<()> {
        self.reached(Callback::Bind);
        Ok(())
    }

    fn init(&self, _context: &Context, _bind_data: &(), _file_path: &str) -> Result<()> {
        self.reached(Callback::Init);
        Ok(())
    }

    fn batch(
        &self,
        _context: &Context,
        _bind_data: &(),
        _init_data: &(),
        _input: &ColumnDataCollection<'_>,
    ) -> Result<()> {
        self.reached(Callback::Batch);
        Ok(())
    }

    fn batch_size(&self, _context: &Context, _bind_data: &()) -> Result<Option<NonZeroUsize>> {
        self.reached(Callback::BatchSize);
        Ok(None)
    }

    fn flush(
        &self,
        _context: &Context,
        _bind_data: &(),
        _init_data: &(),
        _input: &ColumnDataCollection<'_>,
        _batch_data: &mut (),
    ) -> Result<()> {
        self.reached(Callback::Flush);
        Ok(())
    }

    fn finalize(&self, _context: &Context, _bind_data: &(), _init_data: &()) -> Result<()> {
        self.reached(Callback::Finalize);
        Ok(())
    }
}

impl CopyToStatisticsCallbacks for PanicIn {
    fn statistics(
        &self,
        _context: &Context,
        _bind_data: &(),
        _init_data: &(),
    ) -> Result<CopyToStatistics> {
        self.reached(Callback::Statistics);
        Ok(CopyToStatistics::default())
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
            if !message.is_some_and(|text| text.starts_with("deliberate panic")) {
                default_hook(info);
            }
        }));
    });
}

/// The connection answers a plain query and runs the extension's own copy function.
fn assert_usable(connection: &Connection, fixture: &Fixture) {
    assert_eq!(value(connection, "SELECT 42").unwrap(), "42");
    let output = fixture.path("usable.pcap");
    let copied = value(
        connection,
        &format!(
            "COPY (SELECT ''::BLOB AS raw_data, TIMESTAMP_NS '2024-01-01' AS timestamp) \
             TO '{output}' (FORMAT pcap)"
        ),
    );
    assert_eq!(copied.unwrap(), "1");
}

#[test]
fn guarded_copy_function_panic_is_an_ordinary_error() -> Result<()> {
    quiet_deliberate_panics();
    let connection = connect()?;
    let fixture = Fixture::new();
    connection.execute("SET threads = 4", Parameters::None)?;
    for callback in [
        Callback::Bind,
        Callback::BatchSize,
        Callback::Init,
        Callback::Batch,
        Callback::Flush,
        Callback::Finalize,
        Callback::Statistics,
    ] {
        let name = format!("panic_in_{}", callback.label());
        guard::copy_function(&name, PanicIn(callback))
            .with_statistics()
            .register(&connection)?;
        let statement = format!(
            "COPY (SELECT i FROM range(5000) t(i)) TO '{}' (FORMAT {name}, RETURN_STATS)",
            fixture.path(&format!("{name}.out"))
        );

        let error = value(&connection, &statement).unwrap_err();
        assert_eq!(error.code, DuckDBError::QueryExecutor, "{error}");
        assert!(
            error.message.contains(&format!(
                "pcapsql: panic in COPY TO (FORMAT {name}) ({}): deliberate panic in {callback:?}",
                callback.label()
            )),
            "{error}"
        );

        // The same connection keeps working, and so does the format that panicked: it fails
        // the same way again, which an invalidated database would not let it reach.
        assert_usable(&connection, &fixture);
        let again = value(&connection, &statement).unwrap_err();
        assert_eq!(again.code, DuckDBError::QueryExecutor, "{again}");
    }
    assert_usable(&connection, &fixture);
    Ok(())
}

#[test]
fn guarded_copy_function_without_a_panic_copies() -> Result<()> {
    let connection = connect()?;
    let fixture = Fixture::new();
    guard::copy_function("guarded_copy_ok", PanicIn(Callback::Never))
        .with_statistics()
        .register(&connection)?;
    let copied = value(
        &connection,
        &format!(
            "COPY (SELECT i FROM range(5000) t(i)) TO '{}' (FORMAT guarded_copy_ok)",
            fixture.path("ok.out")
        ),
    )?;
    assert_eq!(copied, "5000");
    Ok(())
}
