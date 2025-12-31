//! SQLite export functionality with Arrow type mapping.

use std::io;
use std::path::Path;

use arrow::array::{
    Array, BinaryArray, BooleanArray, FixedSizeBinaryArray, Float32Array, Float64Array, Int16Array,
    Int32Array, Int64Array, Int8Array, LargeBinaryArray, LargeStringArray, RecordBatch,
    StringArray, TimestampMicrosecondArray, TimestampMillisecondArray, TimestampNanosecondArray,
    TimestampSecondArray, UInt16Array, UInt32Array, UInt64Array, UInt8Array,
};
use arrow::datatypes::{DataType, TimeUnit};
use rusqlite::{params_from_iter, Connection, ToSql};

/// SQLite column type derived from Arrow type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteType {
    Integer,
    Real,
    Text,
    Blob,
}

impl SqliteType {
    /// Returns the SQLite type keyword for CREATE TABLE statements.
    pub fn as_sql_keyword(&self) -> &'static str {
        match self {
            SqliteType::Integer => "INTEGER",
            SqliteType::Real => "REAL",
            SqliteType::Text => "TEXT",
            SqliteType::Blob => "BLOB",
        }
    }
}

/// Convert Arrow DataType to SQLite type.
///
/// Mapping rules:
/// - Int8/16/32/64, UInt8/16/32/64, Boolean -> INTEGER
/// - Float32/64 -> REAL
/// - Utf8, LargeUtf8 -> TEXT
/// - Binary, LargeBinary, FixedSizeBinary -> BLOB
/// - Timestamp (any unit) -> TEXT (ISO 8601 format)
/// - Date32, Date64 -> TEXT (ISO 8601 date)
/// - List, Struct -> TEXT (JSON serialization)
pub fn arrow_to_sqlite_type(arrow_type: &DataType) -> SqliteType {
    match arrow_type {
        // Integer types
        DataType::Boolean
        | DataType::Int8
        | DataType::Int16
        | DataType::Int32
        | DataType::Int64
        | DataType::UInt8
        | DataType::UInt16
        | DataType::UInt32
        | DataType::UInt64 => SqliteType::Integer,

        // Real types
        DataType::Float16 | DataType::Float32 | DataType::Float64 => SqliteType::Real,

        // Text types
        DataType::Utf8 | DataType::LargeUtf8 => SqliteType::Text,

        // Binary types
        DataType::Binary | DataType::LargeBinary | DataType::FixedSizeBinary(_) => SqliteType::Blob,

        // Temporal types -> TEXT (ISO 8601)
        DataType::Timestamp(_, _)
        | DataType::Date32
        | DataType::Date64
        | DataType::Time32(_)
        | DataType::Time64(_) => SqliteType::Text,

        // Complex types -> TEXT (JSON representation)
        DataType::List(_)
        | DataType::LargeList(_)
        | DataType::Struct(_)
        | DataType::Map(_, _)
        | DataType::Null => SqliteType::Text,

        // Any other type -> TEXT for flexibility
        _ => SqliteType::Text,
    }
}

/// Escape a SQL identifier (table/column name) by doubling quotes.
fn escape_identifier(name: &str) -> String {
    name.replace('"', "\"\"")
}

/// Format a timestamp in microseconds as ISO 8601 string.
fn format_timestamp_iso8601(timestamp_us: i64) -> String {
    let secs = timestamp_us / 1_000_000;
    let micros = (timestamp_us % 1_000_000).unsigned_abs() as u32;

    // Convert to datetime components
    // Using a simple approach: seconds since Unix epoch
    let datetime = chrono_like_format(secs, micros);
    datetime
}

/// Simple timestamp formatting without chrono dependency.
/// Formats Unix timestamp as ISO 8601 string.
fn chrono_like_format(secs: i64, micros: u32) -> String {
    // Constants for date calculation
    const SECS_PER_DAY: i64 = 86400;
    const SECS_PER_HOUR: i64 = 3600;
    const SECS_PER_MIN: i64 = 60;

    // Handle negative timestamps (before 1970)
    let (days_since_epoch, time_of_day) = if secs >= 0 {
        (secs / SECS_PER_DAY, secs % SECS_PER_DAY)
    } else {
        let days = (secs - SECS_PER_DAY + 1) / SECS_PER_DAY;
        let tod = secs - days * SECS_PER_DAY;
        (days, tod)
    };

    // Calculate year, month, day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    // Calculate time components
    let hours = time_of_day / SECS_PER_HOUR;
    let minutes = (time_of_day % SECS_PER_HOUR) / SECS_PER_MIN;
    let seconds = time_of_day % SECS_PER_MIN;

    if micros > 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            year, month, day, hours, minutes, seconds, micros
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Algorithm from Howard Hinnant's date library
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    (y as i32, m, d)
}

/// A value that can be bound to a SQLite statement.
enum SqliteValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl ToSql for SqliteValue {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            SqliteValue::Null => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Null,
            )),
            SqliteValue::Integer(i) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Integer(*i),
            )),
            SqliteValue::Real(f) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Real(*f),
            )),
            SqliteValue::Text(s) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Text(s.clone()),
            )),
            SqliteValue::Blob(b) => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Blob(b.clone()),
            )),
        }
    }
}

/// Extract a value from an Arrow array as a SQLite-compatible value.
fn extract_value(array: &dyn Array, row_idx: usize, data_type: &DataType) -> SqliteValue {
    if array.is_null(row_idx) {
        return SqliteValue::Null;
    }

    match data_type {
        DataType::Boolean => {
            let arr = array.as_any().downcast_ref::<BooleanArray>().unwrap();
            SqliteValue::Integer(if arr.value(row_idx) { 1 } else { 0 })
        }
        DataType::Int8 => {
            let arr = array.as_any().downcast_ref::<Int8Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::Int16 => {
            let arr = array.as_any().downcast_ref::<Int16Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::Int32 => {
            let arr = array.as_any().downcast_ref::<Int32Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::Int64 => {
            let arr = array.as_any().downcast_ref::<Int64Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx))
        }
        DataType::UInt8 => {
            let arr = array.as_any().downcast_ref::<UInt8Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::UInt16 => {
            let arr = array.as_any().downcast_ref::<UInt16Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::UInt32 => {
            let arr = array.as_any().downcast_ref::<UInt32Array>().unwrap();
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::UInt64 => {
            let arr = array.as_any().downcast_ref::<UInt64Array>().unwrap();
            // Note: UInt64 can overflow i64; we cast anyway (documented limitation)
            SqliteValue::Integer(arr.value(row_idx) as i64)
        }
        DataType::Float32 => {
            let arr = array.as_any().downcast_ref::<Float32Array>().unwrap();
            SqliteValue::Real(arr.value(row_idx) as f64)
        }
        DataType::Float64 => {
            let arr = array.as_any().downcast_ref::<Float64Array>().unwrap();
            SqliteValue::Real(arr.value(row_idx))
        }
        DataType::Utf8 => {
            let arr = array.as_any().downcast_ref::<StringArray>().unwrap();
            SqliteValue::Text(arr.value(row_idx).to_string())
        }
        DataType::LargeUtf8 => {
            let arr = array.as_any().downcast_ref::<LargeStringArray>().unwrap();
            SqliteValue::Text(arr.value(row_idx).to_string())
        }
        DataType::Binary => {
            let arr = array.as_any().downcast_ref::<BinaryArray>().unwrap();
            SqliteValue::Blob(arr.value(row_idx).to_vec())
        }
        DataType::LargeBinary => {
            let arr = array.as_any().downcast_ref::<LargeBinaryArray>().unwrap();
            SqliteValue::Blob(arr.value(row_idx).to_vec())
        }
        DataType::FixedSizeBinary(_) => {
            let arr = array
                .as_any()
                .downcast_ref::<FixedSizeBinaryArray>()
                .unwrap();
            SqliteValue::Blob(arr.value(row_idx).to_vec())
        }
        DataType::Timestamp(unit, _) => {
            let timestamp_us = match unit {
                TimeUnit::Second => {
                    let arr = array
                        .as_any()
                        .downcast_ref::<TimestampSecondArray>()
                        .unwrap();
                    arr.value(row_idx) * 1_000_000
                }
                TimeUnit::Millisecond => {
                    let arr = array
                        .as_any()
                        .downcast_ref::<TimestampMillisecondArray>()
                        .unwrap();
                    arr.value(row_idx) * 1_000
                }
                TimeUnit::Microsecond => {
                    let arr = array
                        .as_any()
                        .downcast_ref::<TimestampMicrosecondArray>()
                        .unwrap();
                    arr.value(row_idx)
                }
                TimeUnit::Nanosecond => {
                    let arr = array
                        .as_any()
                        .downcast_ref::<TimestampNanosecondArray>()
                        .unwrap();
                    arr.value(row_idx) / 1_000
                }
            };
            SqliteValue::Text(format_timestamp_iso8601(timestamp_us))
        }
        // For any other type, use Arrow's display function
        _ => {
            let value_str = arrow::util::display::array_value_to_string(array, row_idx)
                .unwrap_or_else(|_| "null".to_string());
            SqliteValue::Text(value_str)
        }
    }
}

/// Exports Arrow RecordBatches to SQLite database.
pub struct SqliteExporter;

impl SqliteExporter {
    /// Export RecordBatches to a SQLite database file.
    ///
    /// Creates a table named `table_name` with columns derived from the Arrow schema.
    /// Uses transactions with batch commits for performance.
    ///
    /// Returns the number of rows exported.
    pub fn export<P: AsRef<Path>>(
        path: P,
        batches: &[RecordBatch],
        table_name: &str,
    ) -> io::Result<usize> {
        if batches.is_empty() {
            return Ok(0);
        }

        let schema = batches[0].schema();
        let conn = Connection::open(path.as_ref())
            .map_err(|e| io::Error::other(format!("Failed to open SQLite database: {e}")))?;

        // Create table
        Self::create_table(&conn, &schema, table_name)?;

        // Insert data in batched transactions
        let total_rows = Self::insert_batches(&conn, batches, table_name)?;

        Ok(total_rows)
    }

    /// Create the table with schema derived from Arrow types.
    fn create_table(
        conn: &Connection,
        schema: &arrow::datatypes::Schema,
        table_name: &str,
    ) -> io::Result<()> {
        // Build column definitions
        let columns: Vec<String> = schema
            .fields()
            .iter()
            .map(|field| {
                let sqlite_type = arrow_to_sqlite_type(field.data_type());
                let null_constraint = if field.is_nullable() { "" } else { " NOT NULL" };
                format!(
                    "\"{}\" {}{}",
                    escape_identifier(field.name()),
                    sqlite_type.as_sql_keyword(),
                    null_constraint
                )
            })
            .collect();

        let escaped_table = escape_identifier(table_name);

        // Drop existing table and create new one
        let create_sql = format!(
            "DROP TABLE IF EXISTS \"{}\"; CREATE TABLE \"{}\" ({})",
            escaped_table,
            escaped_table,
            columns.join(", ")
        );

        conn.execute_batch(&create_sql)
            .map_err(|e| io::Error::other(format!("Failed to create table: {e}")))?;

        Ok(())
    }

    /// Insert all batches using transactions for performance.
    fn insert_batches(
        conn: &Connection,
        batches: &[RecordBatch],
        table_name: &str,
    ) -> io::Result<usize> {
        const BATCH_SIZE: usize = 1000;

        let schema = batches[0].schema();
        let num_columns = schema.fields().len();

        // Build INSERT statement with placeholders
        let placeholders: Vec<&str> = (0..num_columns).map(|_| "?").collect();
        let column_names: Vec<String> = schema
            .fields()
            .iter()
            .map(|f| format!("\"{}\"", escape_identifier(f.name())))
            .collect();

        let insert_sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            escape_identifier(table_name),
            column_names.join(", "),
            placeholders.join(", ")
        );

        let mut total_rows = 0usize;
        let mut pending_rows = 0usize;

        // Start transaction
        conn.execute("BEGIN TRANSACTION", [])
            .map_err(|e| io::Error::other(format!("Failed to begin transaction: {e}")))?;

        let mut stmt = conn
            .prepare_cached(&insert_sql)
            .map_err(|e| io::Error::other(format!("Failed to prepare statement: {e}")))?;

        for batch in batches {
            for row_idx in 0..batch.num_rows() {
                // Build row values
                let values: Vec<SqliteValue> = (0..num_columns)
                    .map(|col_idx| {
                        let col = batch.column(col_idx);
                        let dtype = schema.field(col_idx).data_type();
                        extract_value(col.as_ref(), row_idx, dtype)
                    })
                    .collect();

                // Execute insert
                stmt.execute(params_from_iter(values.iter()))
                    .map_err(|e| io::Error::other(format!("Failed to insert row: {e}")))?;

                total_rows += 1;
                pending_rows += 1;

                // Commit transaction every BATCH_SIZE rows
                if pending_rows >= BATCH_SIZE {
                    conn.execute("COMMIT", [])
                        .map_err(|e| io::Error::other(format!("Failed to commit: {e}")))?;
                    conn.execute("BEGIN TRANSACTION", []).map_err(|e| {
                        io::Error::other(format!("Failed to begin transaction: {e}"))
                    })?;
                    pending_rows = 0;
                }
            }
        }

        // Commit remaining rows
        if pending_rows > 0 {
            conn.execute("COMMIT", [])
                .map_err(|e| io::Error::other(format!("Failed to commit: {e}")))?;
        }

        Ok(total_rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int32Array, StringArray, TimestampMicrosecondArray};
    use arrow::datatypes::{Field, Schema};
    use std::sync::Arc;
    use tempfile::tempdir;

    // ==========================================================================
    // Type Mapping Tests
    // ==========================================================================

    #[test]
    fn test_arrow_to_sqlite_integer_types() {
        assert_eq!(arrow_to_sqlite_type(&DataType::Int8), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::Int16), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::Int32), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::Int64), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::UInt8), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::UInt16), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::UInt32), SqliteType::Integer);
        assert_eq!(arrow_to_sqlite_type(&DataType::UInt64), SqliteType::Integer);
        assert_eq!(
            arrow_to_sqlite_type(&DataType::Boolean),
            SqliteType::Integer
        );
    }

    #[test]
    fn test_arrow_to_sqlite_real_types() {
        assert_eq!(arrow_to_sqlite_type(&DataType::Float32), SqliteType::Real);
        assert_eq!(arrow_to_sqlite_type(&DataType::Float64), SqliteType::Real);
    }

    #[test]
    fn test_arrow_to_sqlite_text_types() {
        assert_eq!(arrow_to_sqlite_type(&DataType::Utf8), SqliteType::Text);
        assert_eq!(arrow_to_sqlite_type(&DataType::LargeUtf8), SqliteType::Text);
    }

    #[test]
    fn test_arrow_to_sqlite_blob_types() {
        assert_eq!(arrow_to_sqlite_type(&DataType::Binary), SqliteType::Blob);
        assert_eq!(
            arrow_to_sqlite_type(&DataType::LargeBinary),
            SqliteType::Blob
        );
        assert_eq!(
            arrow_to_sqlite_type(&DataType::FixedSizeBinary(16)),
            SqliteType::Blob
        );
    }

    #[test]
    fn test_arrow_to_sqlite_timestamp_types() {
        assert_eq!(
            arrow_to_sqlite_type(&DataType::Timestamp(TimeUnit::Microsecond, None)),
            SqliteType::Text
        );
        assert_eq!(
            arrow_to_sqlite_type(&DataType::Timestamp(TimeUnit::Second, Some("UTC".into()))),
            SqliteType::Text
        );
    }

    #[test]
    fn test_sqlite_type_sql_keyword() {
        assert_eq!(SqliteType::Integer.as_sql_keyword(), "INTEGER");
        assert_eq!(SqliteType::Real.as_sql_keyword(), "REAL");
        assert_eq!(SqliteType::Text.as_sql_keyword(), "TEXT");
        assert_eq!(SqliteType::Blob.as_sql_keyword(), "BLOB");
    }

    #[test]
    fn test_escape_identifier() {
        assert_eq!(escape_identifier("simple"), "simple");
        assert_eq!(escape_identifier("with\"quote"), "with\"\"quote");
        assert_eq!(escape_identifier("src_ip"), "src_ip");
    }

    // ==========================================================================
    // Timestamp Formatting Tests
    // ==========================================================================

    #[test]
    fn test_format_timestamp_iso8601() {
        // 2024-01-15 12:40:45.123456 UTC
        // = 1705322445.123456 seconds since epoch
        let ts = 1705322445_123456i64;
        let formatted = format_timestamp_iso8601(ts);
        assert!(formatted.starts_with("2024-01-15T12:40:45"));
        assert!(formatted.contains("123456"));
    }

    #[test]
    fn test_format_timestamp_no_micros() {
        // Exact second: 2024-01-15 12:40:45 UTC
        let ts = 1705322445_000000i64;
        let formatted = format_timestamp_iso8601(ts);
        assert_eq!(formatted, "2024-01-15T12:40:45Z");
    }

    // ==========================================================================
    // Integration Tests
    // ==========================================================================

    fn create_test_batch() -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
        ]));

        let id_array = Int32Array::from(vec![1, 2, 3]);
        let name_array = StringArray::from(vec![Some("Alice"), Some("Bob"), None]);

        RecordBatch::try_new(schema, vec![Arc::new(id_array), Arc::new(name_array)]).unwrap()
    }

    #[test]
    fn test_export_sqlite_basic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");

        let batch = create_test_batch();
        let result = SqliteExporter::export(&path, &[batch], "data");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        // Verify database content
        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM data", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3);

        // Verify data
        let name: String = conn
            .query_row("SELECT name FROM data WHERE id = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(name, "Alice");
    }

    #[test]
    fn test_export_sqlite_with_nulls() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");

        let batch = create_test_batch();
        SqliteExporter::export(&path, &[batch], "data").unwrap();

        // Verify NULL handling
        let conn = Connection::open(&path).unwrap();
        let name: Option<String> = conn
            .query_row("SELECT name FROM data WHERE id = 3", [], |row| row.get(0))
            .unwrap();
        assert!(name.is_none());
    }

    #[test]
    fn test_export_sqlite_with_timestamp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");

        let schema = Arc::new(Schema::new(vec![Field::new(
            "ts",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        )]));

        // 2024-01-15 12:40:45.123456 UTC
        let ts_array = TimestampMicrosecondArray::from(vec![1705322445123456i64]);
        let batch = RecordBatch::try_new(schema, vec![Arc::new(ts_array)]).unwrap();

        let result = SqliteExporter::export(&path, &[batch], "data");
        assert!(result.is_ok());

        // Verify ISO 8601 format
        let conn = Connection::open(&path).unwrap();
        let ts: String = conn
            .query_row("SELECT ts FROM data", [], |row| row.get(0))
            .unwrap();
        assert!(ts.contains("2024-01-15"));
        assert!(ts.contains("12:40:45"));
    }

    #[test]
    fn test_export_sqlite_with_binary() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("payload", DataType::Binary, true),
        ]));

        let id_array = Int32Array::from(vec![1, 2]);
        let binary_array = BinaryArray::from_opt_vec(vec![
            Some(b"\x00\x01\x02".as_slice()),
            Some(b"\xff\xfe".as_slice()),
        ]);

        let batch =
            RecordBatch::try_new(schema, vec![Arc::new(id_array), Arc::new(binary_array)]).unwrap();

        let result = SqliteExporter::export(&path, &[batch], "data");
        assert!(result.is_ok());

        // Verify binary data
        let conn = Connection::open(&path).unwrap();
        let payload: Vec<u8> = conn
            .query_row("SELECT payload FROM data WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(payload, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn test_export_sqlite_empty_batches() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.sqlite");

        let result = SqliteExporter::export(&path, &[], "data");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_export_sqlite_multiple_batches() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multi.sqlite");

        let batch1 = create_test_batch();
        let batch2 = create_test_batch();

        let result = SqliteExporter::export(&path, &[batch1, batch2], "data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 6); // 3 rows * 2 batches

        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM data", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_export_sqlite_special_table_name() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");

        let batch = create_test_batch();
        let result = SqliteExporter::export(&path, &[batch], "my-table");

        assert!(result.is_ok());

        // Verify table was created with quoted name
        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM \"my-table\"", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }
}
