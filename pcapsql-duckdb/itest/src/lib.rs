//! In-process tests of the pcapsql extension.
//!
//! The crate links DuckDB and registers the extension's entrypoint statically, so the tests under
//! `tests/` are ordinary `cargo test` tests that run SQL against the functions
//! `pcapsql_duckdb::register` installs. The entrypoint is the same as the loadable extension's
//! (`../ext`); only the way DuckDB reaches it differs.
//!
//! The tests named `spike_*` do not test pcapsql. They pin down DuckDB 2.0.0 and `duckdb-neo`
//! behaviour the design relies on (section 10 of `docs/duckdb-v2-extension-roadmap.md`), with
//! test-only table functions, so that an upgrade of either shows what changed.
//!
//! [`replay`] holds `chunk_rows`, the test-only table function that drives the extension's
//! `ChunkWriter` from a list of rows, for the tests of the writer. [`golden`] holds the captures
//! and queries of the DataFusion frontend's golden corpus and the frame builders they are made
//! with. [`Fixture`] writes captures to files, and [`reference_rows`] reads a capture with the
//! shared scan layer alone, which is what a scan function must return.

pub mod golden;
pub mod replay;

use std::io::Cursor;
use std::sync::Arc;

use duckdb_neo::{
    connection::Connection,
    duckdb_entrypoint_c_api_v2,
    environment::{Environment, StorageLocation},
    extension::{register_static_extension, Extension},
    vector::Unknown,
    Parameters, Result,
};
use pcapsql_core::io::{ReadPacketReader, StreamHeader};
use pcapsql_core::scan::{
    testing::{Cell, RecordingSink},
    Catalog, OutColumn, PartitionScan, ScanPlan, Step, TableScan, TimestampUnit,
};

/// A directory of capture files that is removed when the value is dropped.
#[derive(Debug)]
pub struct Fixture(tempfile::TempDir);

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Fixture {
    pub fn new() -> Self {
        Self(tempfile::tempdir().expect("create a temporary directory"))
    }

    /// The path of the file `name`, existing or not, as SQL text takes it between quotes.
    pub fn path(&self, name: &str) -> String {
        let path = self.0.path().join(name);
        let path = path.to_str().expect("the temporary path is UTF-8");
        assert!(!path.contains('\''), "{path} needs quoting");
        path.to_owned()
    }

    /// Write `bytes` to the file `name` and return its path.
    pub fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path(name);
        std::fs::write(&path, bytes).unwrap_or_else(|error| panic!("{path}: {error}"));
        path
    }
}

/// The rows of `table` in the capture `bytes`, every column the extension exposes, as the
/// shared scan layer produces them without DuckDB: core's driver over an in-memory reader into
/// a recording sink that never fills. Timestamps are in nanoseconds, as in the extension.
pub fn reference_rows(bytes: &[u8], table: &str) -> (Vec<OutColumn>, Vec<Vec<Cell>>) {
    let catalog = Catalog::builtin();
    let (id, definition) = catalog.table(table).expect("the table is in the catalogue");
    let registry = Arc::new(pcapsql_core::default_registry());
    let plan = ScanPlan {
        tables: vec![TableScan::new(
            id,
            definition.columns().map(|(column, _)| column).collect(),
        )],
        timestamps: TimestampUnit::Nanos,
        ..ScanPlan::default()
    }
    .compile(catalog, &registry)
    .expect("the plan compiles");
    let columns = plan.outputs()[0].columns.to_vec();

    let mut input = Cursor::new(bytes);
    let (header, head) = StreamHeader::probe(&mut input).expect("the capture has a header");
    let reader = ReadPacketReader::sequential(input, &header, head).expect("the reader opens");
    let mut scan = PartitionScan::new(reader, Arc::new(plan), registry);
    let mut sinks = [RecordingSink::new(&columns, None)];
    loop {
        match scan.step(&mut sinks, 1000).expect("the capture reads") {
            Step::More => {}
            Step::Flush(_) => unreachable!("an unbounded sink is never full"),
            Step::Done | Step::End => break,
        }
    }
    (columns, sinks[0].take_rows())
}

#[duckdb_entrypoint_c_api_v2(extension_name = "pcapsql", api_version = "v2.0.0")]
fn entrypoint(extension: &Extension) -> Result<()> {
    pcapsql_duckdb::register(extension)
}

/// A connection to a new in-memory database that has the pcapsql extension loaded.
pub fn connect() -> Result<Connection> {
    // SAFETY: the describe function is the one `#[duckdb_entrypoint_c_api_v2]` emitted above.
    // Registration is process-wide and repeating it is a no-op.
    unsafe { register_static_extension(duckdb_extension_pcapsql_describe)? };
    Environment::new()?
        .open(StorageLocation::InMemory)?
        .connect()
}

/// Run `sql` and return every row, each cell as DuckDB renders it (`NULL` for SQL NULL).
pub fn rows(connection: &Connection, sql: &str) -> Result<Vec<Vec<String>>> {
    let mut result = connection.query(sql, Parameters::None)?;
    let mut rows = Vec::new();
    while let Some(chunk) = result.next_chunk()? {
        let first_row = rows.len();
        rows.resize_with(first_row + chunk.row_count()?, Vec::new);
        for column in 0..chunk.col_count() {
            let vector = chunk.get_vector_at::<Unknown>(column)?;
            for (index, row) in rows[first_row..].iter_mut().enumerate() {
                row.push(vector.get_value_slow(index)?.to_string());
            }
        }
    }
    Ok(rows)
}

/// Run `sql` and return its first column.
pub fn column(connection: &Connection, sql: &str) -> Result<Vec<String>> {
    Ok(rows(connection, sql)?
        .into_iter()
        .map(|mut row| row.swap_remove(0))
        .collect())
}

/// Run `sql`, which must return one row, and return its first column.
pub fn value(connection: &Connection, sql: &str) -> Result<String> {
    let mut column = column(connection, sql)?;
    assert_eq!(column.len(), 1, "{sql} returned {} rows", column.len());
    Ok(column.remove(0))
}
