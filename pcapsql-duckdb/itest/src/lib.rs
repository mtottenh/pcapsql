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

use duckdb_neo::{
    connection::Connection,
    duckdb_entrypoint_c_api_v2,
    environment::{Environment, StorageLocation},
    extension::{register_static_extension, Extension},
    vector::Unknown,
    Parameters, Result,
};

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
