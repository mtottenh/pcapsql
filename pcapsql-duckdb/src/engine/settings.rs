//! The extension's settings, and the DuckDB settings a scan reads.
//!
//! | Setting | Type | Default | Meaning |
//! |---|---|---|---|
//! | `pcapsql_parallel_scan` | `BOOLEAN` | `true` | Split a large local capture into partitions that several threads scan. `false` reads every capture on one thread |
//! | `pcapsql_parallel_min_file_size` | `UBIGINT` | 4194304 | The size in bytes from which a capture is split. Below it the index pass costs more than it saves |
//! | `pcapsql_index_stride` | `UBIGINT` | 65536 | Frames between two places a capture can be split at. A capture has at most one partition per stride |
//! | `pcapsql_index_cache` | `BOOLEAN` | `true` | Keep the index of a capture a scan split, in memory, for later scans of it in the same database (`engine::table`, module `index_cache`). `false`: every split scan builds the index, and none is kept |
//! | `pcapsql_filter_pushdown` | `BOOLEAN` | `true` | Let a scan take over the filters on `frame_number` and `timestamp` it can apply exactly (`engine::pushdown`). `false` leaves every filter to DuckDB, which then applies it to the rows of a full scan |
//! | `pcapsql_keylog` | `VARCHAR` | empty | The path of a TLS key log (NSS key log format, `SSLKEYLOGFILE`) that a scan of a stream table decrypts TLS with when its `keylog` parameter is not given. Empty: none. It is how a scan that cannot be given the parameter gets one: a view over `read_tls_sessions`, a prepared statement |
//!
//! They are ordinary DuckDB settings (`SET`, `RESET`, `current_setting`, global or per session).
//! The two numbers are there for tests and for experiments: with a stride of a few frames and a
//! minimum size of 0, a capture of a hundred frames is scanned in partitions.

use duckdb_neo::{
    connection::{Context, SettingScope},
    custom_option::{CustomOptionBuilder, CustomOptionCallbacks},
    extension::Extension,
    types::{DuckDBType, ToValue},
    value::Value,
    Error, Result,
};
use pcapsql_core::io::DEFAULT_CHECKPOINT_STRIDE;
use pcapsql_core::scan::PartitionPolicy;

pub const PARALLEL_SCAN: &str = "pcapsql_parallel_scan";
pub const PARALLEL_MIN_FILE_SIZE: &str = "pcapsql_parallel_min_file_size";
pub const INDEX_STRIDE: &str = "pcapsql_index_stride";
pub const FILTER_PUSHDOWN: &str = "pcapsql_filter_pushdown";
pub const KEYLOG: &str = "pcapsql_keylog";
pub const INDEX_CACHE: &str = "pcapsql_index_cache";

/// DuckDB's own setting: the number of threads a query may run on.
const THREADS: &str = "threads";

/// What a scan is planned with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanSettings {
    /// `pcapsql_parallel_scan`.
    pub parallel: bool,
    /// `pcapsql_parallel_min_file_size`.
    pub min_file_size: u64,
    /// `pcapsql_index_stride`: at least 1.
    pub index_stride: u64,
    /// `pcapsql_index_cache`.
    pub index_cache: bool,
    /// DuckDB's `threads`: at least 1.
    pub threads: usize,
}

impl ScanSettings {
    /// The settings in effect for the query `context` belongs to.
    pub fn read(context: &Context) -> Result<Self> {
        let config = context.config()?;
        let number = |name: &str| -> Result<u64> {
            let (value, _scope) = config.get_value(name)?;
            // Whatever integer type DuckDB keeps the setting in.
            let value = value.cast(context, &u64::logical_type(context)?)?;
            value
                .get::<u64>()?
                .ok_or_else(|| Error::invalid_input(format!("the setting {name} is NULL")))
        };
        let switch = |name: &str| -> Result<bool> {
            let (value, _scope) = config.get_value(name)?;
            Ok(value.get::<bool>()?.unwrap_or(true))
        };
        Ok(Self {
            parallel: switch(PARALLEL_SCAN)?,
            min_file_size: number(PARALLEL_MIN_FILE_SIZE)?,
            index_stride: number(INDEX_STRIDE)?.max(1),
            index_cache: switch(INDEX_CACHE)?,
            threads: usize::try_from(number(THREADS)?)
                .unwrap_or(usize::MAX)
                .max(1),
        })
    }
}

/// `pcapsql_filter_pushdown`, as it is for the statement `context` belongs to.
///
/// It is read when DuckDB's optimizer offers a scan its filters, which is when a statement is
/// planned: a prepared statement keeps what was decided when it was prepared.
pub fn filter_pushdown(context: &Context) -> Result<bool> {
    let (value, _scope) = context.config()?.get_value(FILTER_PUSHDOWN)?;
    Ok(value.get::<bool>()?.unwrap_or(true))
}

/// `pcapsql_keylog`, as it is for the statement `context` belongs to: the path of the key log
/// for the scans that are not given one, empty for none.
///
/// It is read when a scan is bound. The file is opened then too, not when the setting is set,
/// so a path that cannot be read fails the queries that would use it.
pub fn keylog(context: &Context) -> Result<String> {
    let (value, _scope) = context.config()?.get_value(KEYLOG)?;
    Ok(value.get::<String>()?.unwrap_or_default())
}

/// A setting that takes any value of its type but NULL.
struct NotNull {
    name: &'static str,
    /// The least value of a numeric setting.
    min: Option<u64>,
}

impl CustomOptionCallbacks for NotNull {
    fn update(
        &self,
        _context: &Context,
        value: Value,
        _scope: SettingScope,
        _is_reset: bool,
    ) -> Result<Value> {
        let name = self.name;
        if value.is_null()? {
            return Err(Error::invalid_input(format!("{name} must not be NULL")));
        }
        if let Some(min) = self.min {
            // DuckDB has cast the value to the setting's type, UBIGINT.
            if value.get::<u64>()?.is_some_and(|given| given < min) {
                return Err(Error::invalid_input(format!(
                    "{name} must be at least {min}"
                )));
            }
        }
        Ok(value)
    }
}

pub(super) fn register(extension: &Extension) -> Result<()> {
    let switches: [(&'static str, &str); 3] = [
        (
            PARALLEL_SCAN,
            "Scan a large local capture in partitions, on several threads",
        ),
        (
            INDEX_CACHE,
            "Keep the index of a capture that a scan split, so that a later scan of it in this \
             database splits it without reading it first",
        ),
        (
            FILTER_PUSHDOWN,
            "Apply filters on frame_number and timestamp in the scan of a capture",
        ),
    ];
    for (name, description) in switches {
        CustomOptionBuilder::new(
            name,
            description,
            bool::logical_type(extension)?,
            NotNull { name, min: None },
        )
        .default_value(true.value(extension)?)
        .register(extension)?;
    }

    let numbers: [(&'static str, &str, u64, u64); 2] = [
        (
            PARALLEL_MIN_FILE_SIZE,
            "The size in bytes from which a capture is scanned in partitions",
            PartitionPolicy::default().cheap_min_bytes,
            0,
        ),
        (
            INDEX_STRIDE,
            "Frames between two places a capture can be split into partitions at",
            DEFAULT_CHECKPOINT_STRIDE,
            1,
        ),
    ];
    for (name, description, default, min) in numbers {
        CustomOptionBuilder::new(
            name,
            description,
            u64::logical_type(extension)?,
            NotNull {
                name,
                min: Some(min),
            },
        )
        .default_value(default.value(extension)?)
        .register(extension)?;
    }

    CustomOptionBuilder::new(
        KEYLOG,
        "The TLS key log (SSLKEYLOGFILE) the stream tables are decrypted with when a scan is \
         given none",
        String::logical_type(extension)?,
        NotNull {
            name: KEYLOG,
            min: None,
        },
    )
    .default_value("".value(extension)?)
    .register(extension)
}
