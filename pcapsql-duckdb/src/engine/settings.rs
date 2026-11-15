//! The extension's settings, and the DuckDB settings a scan reads.
//!
//! | Setting | Type | Default | Meaning |
//! |---|---|---|---|
//! | `pcapsql_parallel_scan` | `BOOLEAN` | `true` | Split a large local capture into partitions that several threads scan. `false` reads every capture on one thread |
//! | `pcapsql_parallel_min_file_size` | `UBIGINT` | 4194304 | The size in bytes from which a capture is split. Below it the index pass costs more than it saves |
//! | `pcapsql_index_stride` | `UBIGINT` | 65536 | Frames between two places a capture can be split at. A capture has at most one partition per stride |
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
        let (parallel, _scope) = config.get_value(PARALLEL_SCAN)?;
        Ok(Self {
            parallel: parallel.get::<bool>()?.unwrap_or(true),
            min_file_size: number(PARALLEL_MIN_FILE_SIZE)?,
            index_stride: number(INDEX_STRIDE)?.max(1),
            threads: usize::try_from(number(THREADS)?)
                .unwrap_or(usize::MAX)
                .max(1),
        })
    }
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
    CustomOptionBuilder::new(
        PARALLEL_SCAN,
        "Scan a large local capture in partitions, on several threads",
        bool::logical_type(extension)?,
        NotNull {
            name: PARALLEL_SCAN,
            min: None,
        },
    )
    .default_value(true.value(extension)?)
    .register(extension)?;

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
    Ok(())
}
