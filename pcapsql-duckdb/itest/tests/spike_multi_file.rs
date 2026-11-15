//! Spikes U6 and U9: a single-file table function behind DuckDB's multi-file wrapper, and a
//! replacement scan in front of it.
//!
//! `numbers_file(file, scale := 1)` reads a text file of one integer per line. It claims batches
//! of 100 lines, asks for three threads, supports projection pushdown and registers a
//! filter-pushdown callback that accepts nothing. `MultiFileFunctionBuilder` wraps it as
//! `numbers(files, ...)`.
//!
//! What this establishes for DuckDB 2.0.0 and `duckdb-neo` 0.20000.2:
//!
//! - The wrapper reads a path, a glob, a list of paths and a directory (files with the registered
//!   extension), adds `filename`, and returns rows in file order and, within a file, in batch
//!   order, also on several threads.
//! - The single-file function is bound once per file. A VARCHAR parameter receives the path. An
//!   ANY parameter receives the path for a file the caller named, and for a file the wrapper
//!   found by globbing a STRUCT(filename, etag, file_size, last_modified, type).
//! - The wrapper claims the function's batches (`claim_batch`) and honours its `max_threads` for a
//!   single file; over several files it uses up to the configured number of threads.
//! - Projection pushdown is forwarded: the function is asked only for the columns in use.
//! - Named parameters do NOT pass through the wrapper. It rejects the single-file function's
//!   named parameters, and binds each file with the file argument alone: not even the declared
//!   default arrives. (The wrapper forwards "typed kwargs", which the C API cannot declare.)
//! - The function's `pushdown_filter` callback is NOT called through the wrapper: DuckDB applies
//!   the filters itself. Only a direct call of the single-file function is offered the filters.
//! - A replacement scan can route `FROM 'x.num'` and `FROM 'dir/*.num'` to the wrapper, and can
//!   add a named parameter when it targets the single-file function, but not both.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    ops::Range,
    sync::{
        atomic::{AtomicI64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    error::{DuckDBError, Error},
    file::{FileBuilder, FileSystem},
    multi_file::MultiFileFunctionBuilder,
    qualified_name::QualifiedName,
    replacement_scan::{
        ReplacementHandle, ReplacementScanBuilder, ReplacementScanCallbacks, ReplacementType,
    },
    signature::{FunctionParameter, FunctionParameterKind, SignatureBuilder},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, PushdownData, TableClaimBatchCallbacks,
        TableFilterPushdownCallbacks, TableFunctionBuilder, TableFunctionCallbacks,
    },
    types::Any,
    DuckDBType, Parameters, Result, ToValue,
};
use pcapsql_duckdb_itest::{column, connect, rows, value};

/// Lines per claimed batch.
const BATCH: usize = 100;

/// A small number that identifies the calling OS thread.
fn thread_number() -> i64 {
    static NEXT: AtomicI64 = AtomicI64::new(0);
    thread_local! {
        static NUMBER: i64 = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    NUMBER.with(|number| *number)
}

/// What the single-file function saw.
#[derive(Default)]
struct Observed {
    /// Type and value of the positional argument of every bind, and the `scale` argument if the
    /// bind received one.
    binds: Mutex<Vec<(String, String, Option<i64>)>>,
    /// The declared-column indices each scan was initialised with.
    projections: Mutex<BTreeSet<Vec<usize>>>,
    pushdown_calls: AtomicUsize,
    filters_offered: AtomicUsize,
    claimed_batches: AtomicUsize,
}

struct NumbersFile(Arc<Observed>);

struct FileContents {
    values: Vec<i64>,
    scale: i64,
}

impl TableFunctionCallbacks for NumbersFile {
    type BindData = FileContents;
    /// The next batch to hand out.
    type GlobalState = AtomicUsize;
    /// The lines of the batch this worker claimed and has not emitted yet.
    type LocalState = Option<Range<usize>>;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<FileContents> {
        // Positional parameters come first, then named ones in declaration order. A direct call
        // always delivers `scale`, given or defaulted; the multi-file wrapper delivers the file only.
        let file = &arguments[0];
        let file_type = file.logical_type.to_text()?;
        let file_value = file
            .value
            .as_ref()
            .ok_or_else(|| Error::invalid_input("the file must be a constant"))?;
        // An ANY parameter receives either a path or a file struct whose first field is the path.
        let path = if file_type.starts_with("STRUCT") {
            file_value.get_child(0)?.get::<String>()?
        } else {
            file_value.get::<String>()?
        }
        .ok_or_else(|| Error::invalid_input("the file must not be NULL"))?;
        let scale = match arguments.get(1) {
            None => None,
            Some(scale) => Some(
                scale
                    .value
                    .as_ref()
                    .and_then(|value| value.get::<i64>().ok().flatten())
                    .ok_or_else(|| Error::invalid_input("scale must be a BIGINT"))?,
            ),
        };
        self.0
            .binds
            .lock()
            .unwrap()
            .push((file_type, path.clone(), scale));
        let scale = scale.unwrap_or(1);

        let file_system = FileSystem::new(context)?;
        let file = FileBuilder::new(&file_system, &path)?.read().open()?;
        let text = String::from_utf8(file.read(file.size()? as usize)?)
            .map_err(|_| Error::invalid_input(format!("{path} is not text")))?;
        let values = text
            .lines()
            .map(|line| line.parse::<i64>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| Error::invalid_input(format!("{path}: {error}")))?;

        for name in ["value", "line", "thread"] {
            bind_handle.add_result_column(name, &i64::logical_type(context)?)?;
        }
        bind_handle.set_cardinality(values.len(), true)?;
        Ok(FileContents { values, scale })
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _contents: &FileContents,
        column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicUsize>> {
        let projection = (0..column_data.count()?)
            .map(|index| column_data.get_column_index(index))
            .collect::<Result<Vec<_>>>()?;
        self.0.projections.lock().unwrap().insert(projection);
        Ok(Some(AtomicUsize::new(0)))
    }

    fn max_threads(
        &self,
        _context: &Context,
        _contents: &FileContents,
        _next_batch: Option<&AtomicUsize>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        Ok(NonZeroUsize::new(3))
    }

    fn init_local_state(
        &self,
        _context: &Context,
        _contents: &FileContents,
        _next_batch: Option<&AtomicUsize>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Option<Range<usize>>>> {
        Ok(Some(None))
    }

    fn exec(
        &self,
        _context: &Context,
        contents: &FileContents,
        claimed: Option<&mut Option<Range<usize>>>,
        _next_batch: Option<&AtomicUsize>,
        mut output: DataChunkRef<'_>,
        column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        // A batch is one chunk; the empty chunk after it ends the batch.
        let Some(lines) = claimed.unwrap().take() else {
            return Ok(());
        };
        // Let other threads claim batches too.
        std::thread::sleep(Duration::from_micros(300));

        let thread = thread_number();
        for position in 0..column_info.count()? {
            let declared = column_info.get_column_index(position)?;
            let mut vector = output.get_vector_at_mut::<i64>(position)?;
            vector.set_size(lines.len())?;
            let mut writer = vector.writer()?;
            for (row, line) in lines.clone().enumerate() {
                let cell = match declared {
                    0 => contents.values[line] * contents.scale,
                    1 => line as i64,
                    _ => thread,
                };
                writer.set(row, &cell)?;
            }
        }
        Ok(())
    }
}

impl TableClaimBatchCallbacks for NumbersFile {
    fn claim_batch(
        &self,
        _context: &Context,
        contents: &FileContents,
        claimed: Option<&mut Option<Range<usize>>>,
        next_batch: Option<&AtomicUsize>,
    ) -> Result<bool> {
        let start = next_batch.unwrap().fetch_add(1, Ordering::Relaxed) * BATCH;
        if start >= contents.values.len() {
            return Ok(false);
        }
        self.0.claimed_batches.fetch_add(1, Ordering::Relaxed);
        *claimed.unwrap() = Some(start..(start + BATCH).min(contents.values.len()));
        Ok(true)
    }
}

impl TableFilterPushdownCallbacks for NumbersFile {
    fn pushdown_filter(
        &self,
        _context: &Context,
        _contents: &FileContents,
        pushdown_data: PushdownData<'_>,
    ) -> Result<()> {
        // Nothing is accepted, so DuckDB keeps applying every filter.
        self.0.pushdown_calls.fetch_add(1, Ordering::Relaxed);
        self.0
            .filters_offered
            .fetch_add(pushdown_data.filter_count()?, Ordering::Relaxed);
        Ok(())
    }
}

/// Register `<name>_file` and its multi-file wrapper `<name>`.
fn register<F: DuckDBType>(connection: &Connection, name: &str) -> Result<Arc<Observed>> {
    let observed = Arc::new(Observed::default());
    let single_file = format!("{name}_file");
    TableFunctionBuilder::new(
        &single_file,
        SignatureBuilder::new()
            .param(FunctionParameter::new::<F>("file"))
            .param(
                FunctionParameter::with_default::<i64>("scale", 1)
                    .kind(FunctionParameterKind::Named),
            ),
        NumbersFile(observed.clone()),
    )
    .with_projection_pushdown(true)
    .with_filter_pushdown()
    .with_claim_batch()
    .register(connection)?;

    MultiFileFunctionBuilder::new(name, single_file)
        .reader_type("Numbers")
        .file_extension("num")
        .register(connection)?;
    Ok(observed)
}

/// `a.num` holds 0..1000, `b.num` 1000..1700 and `c.num` 1700..2000; `other.txt` is not ours.
struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        for (name, values) in [
            ("a.num", 0..1000),
            ("b.num", 1000..1700),
            ("c.num", 1700..2000),
        ] {
            let text: String = values.map(|value| format!("{value}\n")).collect();
            std::fs::write(directory.path().join(name), text).unwrap();
        }
        std::fs::write(directory.path().join("other.txt"), "not numbers\n").unwrap();
        Self { directory }
    }

    fn path(&self, name: &str) -> String {
        self.directory
            .path()
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn directory(&self) -> String {
        self.directory.path().to_str().unwrap().to_owned()
    }
}

fn connect_with_threads(threads: usize) -> Result<Connection> {
    let connection = connect()?;
    connection.execute(
        format!("SET threads = {threads}").as_str(),
        Parameters::None,
    )?;
    Ok(connection)
}

fn numbers(range: Range<i64>) -> Vec<String> {
    range.map(|value| value.to_string()).collect()
}

#[test]
fn wrapper_reads_paths_globs_lists_and_directories_in_order() -> Result<()> {
    let connection = connect_with_threads(4)?;
    let observed = register::<String>(&connection, "numbers")?;
    let fixture = Fixture::new();
    let (a, b, c) = (
        fixture.path("a.num"),
        fixture.path("b.num"),
        fixture.path("c.num"),
    );
    let glob = fixture.path("*.num");

    assert_eq!(
        column(&connection, &format!("SELECT value FROM numbers('{a}')"))?,
        numbers(0..1000)
    );
    // Files in glob order, lines in file order, without an ORDER BY and on four threads.
    assert_eq!(
        column(&connection, &format!("SELECT value FROM numbers('{glob}')"))?,
        numbers(0..2000)
    );
    assert_eq!(
        column(
            &connection,
            &format!("SELECT value FROM numbers(['{c}', '{a}'])")
        )?,
        [numbers(1700..2000), numbers(0..1000)].concat()
    );
    // A directory is read through the registered file extension; other.txt is not touched.
    assert_eq!(
        column(
            &connection,
            &format!("SELECT value FROM numbers('{}')", fixture.directory())
        )?,
        numbers(0..2000)
    );

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT filename, count(*), min(value), max(value) \
                 FROM numbers('{glob}', filename := true) GROUP BY ALL ORDER BY ALL"
            ),
        )?,
        [
            vec![a.clone(), "1000".into(), "0".into(), "999".into()],
            vec![b.clone(), "700".into(), "1000".into(), "1699".into()],
            vec![c.clone(), "300".into(), "1700".into(), "1999".into()],
        ]
    );

    let error = value(
        &connection,
        &format!("SELECT count(*) FROM numbers('{}')", fixture.path("*.nope")),
    )
    .unwrap_err();
    assert!(error.message.contains("No files found"), "{error}");

    // Every bind received one file's path as a VARCHAR, and nothing else.
    let binds = observed.binds.lock().unwrap();
    assert!(
        binds
            .iter()
            .all(|(file_type, _, scale)| file_type == "VARCHAR" && scale.is_none()),
        "{binds:?}"
    );
    let paths: BTreeSet<&str> = binds.iter().map(|(_, path, _)| path.as_str()).collect();
    assert_eq!(paths, BTreeSet::from([a.as_str(), b.as_str(), c.as_str()]));
    Ok(())
}

#[test]
fn named_parameters_do_not_pass_through_the_wrapper() -> Result<()> {
    let connection = connect()?;
    let observed = register::<String>(&connection, "numbers")?;
    let fixture = Fixture::new();
    let a = fixture.path("a.num");
    let last_scale = || observed.binds.lock().unwrap().last().unwrap().2;

    // Called directly, the function receives its named parameter, given or defaulted.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT max(value) FROM numbers_file('{a}', scale := 10)")
        )?,
        "9990"
    );
    assert_eq!(last_scale(), Some(10));
    assert_eq!(
        value(
            &connection,
            &format!("SELECT max(value) FROM numbers_file('{a}')")
        )?,
        "999"
    );
    assert_eq!(last_scale(), Some(1));

    // The wrapper does not know the parameter...
    let error = value(
        &connection,
        &format!("SELECT max(value) FROM numbers('{a}', scale := 10)"),
    )
    .unwrap_err();
    assert_eq!(error.code, DuckDBError::QueryBinder, "{error}");
    assert!(
        error
            .message
            .contains("Invalid named parameter \"scale\" for function numbers"),
        "{error}"
    );
    // ...and binds the file without it: the declared default is not delivered either.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT max(value) FROM numbers('{a}')")
        )?,
        "999"
    );
    assert_eq!(last_scale(), None);
    Ok(())
}

#[test]
fn an_any_parameter_receives_the_file_with_its_metadata() -> Result<()> {
    let connection = connect()?;
    let observed = register::<Any>(&connection, "numbers_any")?;
    let fixture = Fixture::new();
    let a = fixture.path("a.num");
    let file_types = || {
        let binds = std::mem::take(&mut *observed.binds.lock().unwrap());
        binds
            .into_iter()
            .map(|(file_type, _, _)| file_type)
            .collect::<BTreeSet<_>>()
    };
    let count = |from: String| value(&connection, &format!("SELECT count(*) FROM {from}"));
    const FILE_STRUCT: &str = "STRUCT(filename VARCHAR, etag BLOB, file_size BIGINT, \
                               last_modified TIMESTAMP, \"type\" VARCHAR)";

    // Called directly, the function gets what the caller wrote.
    assert_eq!(count(format!("numbers_any_file('{a}')"))?, "1000");
    assert_eq!(file_types(), BTreeSet::from(["VARCHAR".to_owned()]));

    // A file the wrapper found by globbing arrives as a struct with what the listing knew.
    assert_eq!(
        count(format!("numbers_any('{}')", fixture.path("*.num")))?,
        "2000"
    );
    assert_eq!(file_types(), BTreeSet::from([FILE_STRUCT.to_owned()]));

    // A file the caller named arrives as its path.
    assert_eq!(count(format!("numbers_any('{a}')"))?, "1000");
    assert_eq!(file_types(), BTreeSet::from(["VARCHAR".to_owned()]));
    Ok(())
}

/// The threads that produced rows, per file name.
fn threads_per_file(
    connection: &Connection,
    sql: &str,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut threads = BTreeMap::<String, BTreeSet<String>>::new();
    for row in rows(connection, sql)? {
        threads
            .entry(row[0].clone())
            .or_default()
            .insert(row[1].clone());
    }
    Ok(threads)
}

#[test]
fn wrapper_claims_batches_and_honours_max_threads_within_a_file() -> Result<()> {
    let connection = connect_with_threads(4)?;
    let observed = register::<String>(&connection, "numbers")?;
    let fixture = Fixture::new();
    let a = fixture.path("a.num");

    // One file: its ten batches are claimed by more than one thread, and by no more than the
    // three the single-file function asked for, although DuckDB has four.
    let threads = threads_per_file(
        &connection,
        &format!("SELECT 'a', thread, count(*) FROM numbers('{a}') GROUP BY ALL"),
    )?;
    assert!((2..=3).contains(&threads["a"].len()), "{threads:?}");
    assert_eq!(observed.claimed_batches.swap(0, Ordering::Relaxed), 10);

    // The same holds without the wrapper.
    let threads = threads_per_file(
        &connection,
        &format!("SELECT 'a', thread, count(*) FROM numbers_file('{a}') GROUP BY ALL"),
    )?;
    assert!((2..=3).contains(&threads["a"].len()), "{threads:?}");
    assert_eq!(observed.claimed_batches.swap(0, Ordering::Relaxed), 10);

    // Several files: batches of 10 + 7 + 3, and threads share a file.
    let threads = threads_per_file(
        &connection,
        &format!(
            "SELECT filename, thread, count(*) FROM numbers('{}', filename := true) GROUP BY ALL",
            fixture.path("*.num")
        ),
    )?;
    assert_eq!(threads.len(), 3);
    assert_eq!(observed.claimed_batches.load(Ordering::Relaxed), 20);
    assert!(
        threads[&a].len() >= 2,
        "a.num was read by one thread: {threads:?}"
    );
    let all: BTreeSet<&String> = threads.values().flatten().collect();
    assert!(all.len() <= 4, "{threads:?}");
    Ok(())
}

#[test]
fn wrapper_forwards_the_projection() -> Result<()> {
    let connection = connect()?;
    let observed = register::<String>(&connection, "numbers")?;
    let fixture = Fixture::new();
    let glob = fixture.path("*.num");
    let projections = || std::mem::take(&mut *observed.projections.lock().unwrap());

    assert_eq!(
        value(
            &connection,
            &format!("SELECT sum(line) FROM numbers('{glob}')")
        )?,
        "789000"
    );
    assert_eq!(projections(), BTreeSet::from([vec![1]]));

    assert_eq!(
        value(
            &connection,
            &format!("SELECT sum(value + line) FROM numbers('{glob}') WHERE line < 10")
        )?,
        "27270"
    );
    // In the order DuckDB wants them, which is not the declared order.
    assert_eq!(projections(), BTreeSet::from([vec![1, 0]]));

    // Rows only: the function is asked for its first column.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM numbers('{glob}')")
        )?,
        "2000"
    );
    assert_eq!(projections(), BTreeSet::from([vec![0]]));
    Ok(())
}

#[test]
fn filters_reach_pushdown_filter_only_on_a_direct_call() -> Result<()> {
    let connection = connect()?;
    let observed = register::<String>(&connection, "numbers")?;
    let fixture = Fixture::new();
    let (a, glob) = (fixture.path("a.num"), fixture.path("*.num"));
    let calls = || {
        (
            observed.pushdown_calls.swap(0, Ordering::Relaxed),
            observed.filters_offered.swap(0, Ordering::Relaxed),
        )
    };

    // Called directly, the function is offered both conjuncts. It accepts neither, and DuckDB
    // applies them.
    assert_eq!(
        column(
            &connection,
            &format!("SELECT value FROM numbers_file('{a}') WHERE value >= 995 AND line % 2 = 1"),
        )?,
        ["995", "997", "999"]
    );
    assert_eq!(calls(), (1, 2));
    // No filter, no call.
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM numbers_file('{a}')")
        )?,
        "1000"
    );
    assert_eq!(calls(), (0, 0));

    // Through the wrapper the callback is never called, for one file or for several.
    for files in [&a, &glob] {
        assert_eq!(
            column(
                &connection,
                &format!(
                    "SELECT value FROM numbers('{files}') WHERE value >= 995 AND value < 1000 AND line % 2 = 1"
                ),
            )?,
            ["995", "997", "999"]
        );
        assert_eq!(calls(), (0, 0));
    }
    Ok(())
}

/// Routes a quoted name that ends in `.num` to `function(name)`, with `scale := scale` if set.
struct NumFiles {
    function: &'static str,
    scale: Option<i64>,
}

impl ReplacementScanCallbacks for NumFiles {
    fn scan(
        &self,
        context: &Context,
        name: &QualifiedName,
        handle: ReplacementHandle<'_>,
    ) -> Result<()> {
        let path = name.get_view()?.table;
        if path.to_ascii_lowercase().ends_with(".num") {
            handle.set_reference(ReplacementType::Table(self.function.try_into()?))?;
            handle.add_parameter(path.value(context)?)?;
            if let Some(scale) = self.scale {
                handle.add_parameter_with_name("scale", scale.value(context)?)?;
            }
        }
        Ok(())
    }
}

fn connect_with_replacement_scan(function: &'static str, scale: Option<i64>) -> Result<Connection> {
    let connection = connect()?;
    register::<String>(&connection, "numbers")?;
    ReplacementScanBuilder::new(NumFiles { function, scale }).register(&connection)?;
    Ok(connection)
}

#[test]
fn replacement_scan_routes_a_quoted_path_to_the_wrapper() -> Result<()> {
    let connection = connect_with_replacement_scan("numbers", None)?;
    let fixture = Fixture::new();
    let (a, glob) = (fixture.path("a.num"), fixture.path("*.num"));

    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), max(value) FROM '{a}'")
        )?,
        [["1000", "999"]]
    );
    // A glob in the quoted name reaches the multi-file wrapper as a glob.
    assert_eq!(
        column(&connection, &format!("SELECT value FROM '{glob}'"))?,
        numbers(0..2000)
    );
    assert_eq!(
        column(
            &connection,
            &format!("SELECT value FROM '{a}' WHERE line < 3")
        )?,
        ["0", "1", "2"]
    );

    // The wrapper stays callable by name, with its own options.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT filename, count(*) FROM numbers('{a}', filename := true) GROUP BY ALL"
            ),
        )?,
        [[a.as_str(), "1000"]]
    );

    // Names the callback does not claim are left to DuckDB.
    let error = value(&connection, "SELECT count(*) FROM 'no_such_file.xyz'").unwrap_err();
    assert!(error.message.contains("no_such_file.xyz"), "{error}");
    // A real table of that name wins over the replacement scan.
    connection.execute(
        format!("CREATE TABLE \"{a}\" AS SELECT 7 AS value").as_str(),
        Parameters::None,
    )?;
    assert_eq!(
        value(&connection, &format!("SELECT max(value) FROM '{a}'"))?,
        "7"
    );
    Ok(())
}

#[test]
fn replacement_scan_can_add_a_named_parameter_only_without_the_wrapper() -> Result<()> {
    let fixture = Fixture::new();
    let (a, glob) = (fixture.path("a.num"), fixture.path("*.num"));

    // Routed to the single-file function, the named parameter is applied; a glob is then just a
    // file name that does not exist.
    let connection = connect_with_replacement_scan("numbers_file", Some(100))?;
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), max(value) FROM '{a}'")
        )?,
        [["1000", "99900"]]
    );
    assert!(value(&connection, &format!("SELECT count(*) FROM '{glob}'")).is_err());

    // Routed to the wrapper, the same named parameter is refused.
    let connection = connect_with_replacement_scan("numbers", Some(100))?;
    let error = value(&connection, &format!("SELECT count(*) FROM '{a}'")).unwrap_err();
    assert!(
        error
            .message
            .contains("Invalid named parameter \"scale\" for function numbers"),
        "{error}"
    );
    Ok(())
}
