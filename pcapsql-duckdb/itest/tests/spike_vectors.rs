//! Spike U8: how a table function's `exec` fills the output chunk.
//!
//! The scan tables need UBIGINT, TIMESTAMP_NS, VARCHAR, BLOB, BOOLEAN, UINTEGER, LIST(UINTEGER)
//! and LIST(VARCHAR) columns with NULLs. Two test functions emit the same rows of those types:
//! `typed_rows` through `duckdb-neo`'s checked writers, and `raw_rows` the way a row sink has to
//! work when it does not know a chunk's row count in advance. Both are compared with the same rows
//! computed in SQL.
//!
//! What this establishes for DuckDB 2.0.0 and `duckdb-neo` 0.20000.2:
//!
//! - The output chunk holds 2048 rows (`DataChunkRef::capacity`).
//! - The chunk's row count is the size of its first vector (`Vector::set_size`), which DuckDB
//!   copies to the other vectors; a chunk whose first vector has size zero ends the scan.
//! - `set_size` accepts a size past the capacity. The oversized chunk survives plans that only
//!   forward or count it and raises an INTERNAL error, which invalidates the database, in the
//!   first operator that sizes a vector of its own from it. Staying within `capacity()` is the
//!   function's job.
//! - Checked writers exist for every type above: `VectorWriter::{set, set_option, set_null}` and
//!   `ListWriter::{set_elements, set_null}`.
//! - A per-chunk raw path exists: `VectorWriter::as_mut_ptr` for the data, `validity_mut` for the
//!   mask (both `unsafe` to use), `write_slice` as a safe bulk copy for fixed-width types, and
//!   `arena` for string and blob payloads. The data pointer of a vector does not move while rows
//!   are written, nor when the vector is shrunk to the final row count.
//! - A LIST child can be grown between rows with `set_child_size`; the elements written so far
//!   are kept, but the child's data pointer moves, so element writers must be re-created.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use duckdb_neo::{
    DuckDBType, Result,
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    error::{DuckDBError, Error},
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{
        BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionBuilder,
        TableFunctionCallbacks,
    },
    types::{BlobValue, List, ListIndex, TimestampNsValue},
    vector::{DuckDBBytes, Vector},
};
use pcapsql_duckdb_itest::{connect, rows, value};

const LONG_TEXT: &str = "a string longer than the twelve bytes DuckDB stores inline: ";

// The value of each column in row `i`. `expected_sql` computes the same in SQL.
fn timestamp(i: u64) -> Option<i64> {
    (i % 10 != 9).then_some(1_700_000_000_000_000_000 + i as i64)
}
fn text(i: u64) -> Option<String> {
    match i % 3 {
        0 => Some(format!("row-{i}")),
        1 => Some(format!("{LONG_TEXT}{i}")),
        _ => None,
    }
}
fn bytes(i: u64) -> Option<Vec<u8>> {
    (i % 4 != 3).then(|| {
        let mut bytes = format!("blob-{i}").into_bytes();
        bytes.extend([0x00, 0xff]);
        bytes
    })
}
fn flag(i: u64) -> Option<bool> {
    (i % 5 != 4).then_some(i.is_multiple_of(2))
}
fn small(i: u64) -> Option<u32> {
    (i % 8 != 7).then_some((i * 2) as u32)
}
fn numbers(i: u64) -> Option<Vec<u32>> {
    (i % 7 != 6).then(|| (0..i % 4).map(|k| (i + k) as u32).collect())
}
fn words(i: u64) -> Option<Vec<Option<String>>> {
    (i % 6 != 5).then(|| {
        (0..i % 3)
            .map(|k| (k != 1).then(|| format!("w{i}-{k}")))
            .collect()
    })
}

fn expected_sql(row_count: u64) -> String {
    format!(
        "SELECT i::UBIGINT AS id,
                CASE WHEN i % 10 <> 9 THEN make_timestamp_ns(1700000000000000000 + i) END AS ts,
                CASE i % 3 WHEN 0 THEN 'row-' || i WHEN 1 THEN '{LONG_TEXT}' || i END AS text,
                CASE WHEN i % 4 <> 3 THEN ('blob-' || i)::BLOB || '\\x00\\xFF'::BLOB END AS bytes,
                CASE WHEN i % 5 <> 4 THEN i % 2 = 0 END AS flag,
                CASE WHEN i % 8 <> 7 THEN (i * 2)::UINTEGER END AS small,
                CASE WHEN i % 7 <> 6
                     THEN list_transform(range(i % 4), lambda k: (i + k)::UINTEGER) END AS numbers,
                CASE WHEN i % 6 <> 5
                     THEN list_transform(range(i % 3),
                                         lambda k: CASE WHEN k <> 1 THEN 'w' || i || '-' || k END)
                END AS words
         FROM range({row_count}) t(i)"
    )
}

/// What a function observed while it ran, for the test to assert on.
#[derive(Default)]
struct Observed {
    capacity: AtomicUsize,
    chunks: AtomicUsize,
    /// Set if a vector's data pointer changed between sizing it and the end of `exec`.
    data_pointer_moved: AtomicBool,
    /// Set if growing a LIST child moved the child's data pointer.
    list_child_moved: AtomicBool,
}

#[derive(Clone, Copy)]
enum Style {
    Typed,
    Raw,
}

struct Rows {
    style: Style,
    observed: Arc<Observed>,
}

impl TableFunctionCallbacks for Rows {
    /// Number of rows to produce.
    type BindData = u64;
    /// Next row to produce.
    type GlobalState = AtomicU64;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<u64> {
        bind_handle.add_result_column("id", &u64::logical_type(context)?)?;
        bind_handle.add_result_column("ts", &TimestampNsValue::logical_type(context)?)?;
        bind_handle.add_result_column("text", &String::logical_type(context)?)?;
        bind_handle.add_result_column("bytes", &BlobValue::logical_type(context)?)?;
        bind_handle.add_result_column("flag", &bool::logical_type(context)?)?;
        bind_handle.add_result_column("small", &u32::logical_type(context)?)?;
        bind_handle.add_result_column("numbers", &List::<u32>::logical_type(context)?)?;
        bind_handle.add_result_column("words", &List::<String>::logical_type(context)?)?;

        let row_count = arguments[0]
            .value
            .as_ref()
            .and_then(|v| v.get::<i64>().ok());
        match row_count {
            Some(Some(row_count)) if row_count >= 0 => Ok(row_count as u64),
            _ => Err(Error::invalid_input("the row count must be a BIGINT >= 0")),
        }
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _row_count: &u64,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicU64>> {
        Ok(Some(AtomicU64::new(0)))
    }

    fn exec(
        &self,
        _context: &Context,
        row_count: &u64,
        _local_state: Option<&mut ()>,
        next_row: Option<&AtomicU64>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let capacity = output.capacity()?;
        self.observed.capacity.store(capacity, Ordering::Relaxed);
        let first = next_row
            .unwrap()
            .fetch_add(capacity as u64, Ordering::Relaxed)
            .min(*row_count);
        let rows = (*row_count - first).min(capacity as u64) as usize;
        if rows > 0 {
            self.observed.chunks.fetch_add(1, Ordering::Relaxed);
        }
        match self.style {
            Style::Typed => write_typed(output, first, rows),
            Style::Raw => write_raw(output, first, rows, capacity, &self.observed),
        }
    }
}

/// Every column through the checked writers. The row count is known before writing.
fn write_typed(mut output: DataChunkRef<'_>, first: u64, rows: usize) -> Result<()> {
    let row_ids = || (0..rows).map(|row| (row, first + row as u64));

    let mut ids = output.get_vector_at_mut::<u64>(0)?;
    ids.set_size(rows)?;
    let mut writer = ids.writer()?;
    for (row, i) in row_ids() {
        writer.set(row, &i)?;
    }

    let mut timestamps = output.get_vector_at_mut::<TimestampNsValue>(1)?;
    timestamps.set_size(rows)?;
    let mut writer = timestamps.writer()?;
    for (row, i) in row_ids() {
        writer.set_option(row, timestamp(i).map(TimestampNsValue).as_ref())?;
    }

    let mut texts = output.get_vector_at_mut::<String>(2)?;
    texts.set_size(rows)?;
    let mut writer = texts.writer()?;
    for (row, i) in row_ids() {
        writer.set_option(row, text(i).as_deref())?;
    }

    let mut blobs = output.get_vector_at_mut::<BlobValue>(3)?;
    blobs.set_size(rows)?;
    let mut writer = blobs.writer()?;
    for (row, i) in row_ids() {
        writer.set_option(row, bytes(i).as_deref())?;
    }

    let mut flags = output.get_vector_at_mut::<bool>(4)?;
    flags.set_size(rows)?;
    let mut writer = flags.writer()?;
    for (row, i) in row_ids() {
        writer.set_option(row, flag(i).as_ref())?;
    }

    let mut smalls = output.get_vector_at_mut::<u32>(5)?;
    smalls.set_size(rows)?;
    let mut writer = smalls.writer()?;
    for (row, i) in row_ids() {
        writer.set_option(row, small(i).as_ref())?;
    }

    // A LIST vector's elements live in a child vector, which is sized before it is written.
    let mut lists = output.get_vector_at_mut::<List<u32>>(6)?;
    lists.set_size(rows)?;
    lists.set_child_size(
        row_ids()
            .map(|(_, i)| numbers(i).map_or(0, |l| l.len()))
            .sum(),
    )?;
    let mut writer = lists.list_writer()?;
    for (row, i) in row_ids() {
        match numbers(i) {
            Some(list) => writer.set_elements(row, list.iter().map(Some))?,
            None => writer.set_null(row)?,
        }
    }

    let mut lists = output.get_vector_at_mut::<List<String>>(7)?;
    lists.set_size(rows)?;
    lists.set_child_size(
        row_ids()
            .map(|(_, i)| words(i).map_or(0, |l| l.len()))
            .sum(),
    )?;
    let mut writer = lists.list_writer()?;
    for (row, i) in row_ids() {
        match words(i) {
            Some(list) => writer.set_elements(row, list.iter().map(|word| word.as_deref()))?,
            None => writer.set_null(row)?,
        }
    }
    Ok(())
}

fn clear_bit(validity: &mut [u64], row: usize) {
    validity[row / 64] &= !(1 << (row % 64));
}

/// The same rows as a sink that learns the row count only when the chunk is full: size every
/// vector to the chunk's capacity, take the data pointers once, write row by row, then shrink.
fn write_raw(
    mut output: DataChunkRef<'_>,
    first: u64,
    rows: usize,
    capacity: usize,
    observed: &Observed,
) -> Result<()> {
    let [
        ids,
        timestamps,
        texts,
        blobs,
        flags,
        smalls,
        numbers_list,
        words_list,
    ] = output.get_vector_array_mut([0, 1, 2, 3, 4, 5, 6, 7])?;
    let mut ids = ids.cast::<u64>()?;
    let mut timestamps = timestamps.cast::<TimestampNsValue>()?;
    let mut texts = texts.cast::<String>()?;
    let mut blobs = blobs.cast::<BlobValue>()?;
    let mut flags = flags.cast::<bool>()?;
    let mut smalls = smalls.cast::<u32>()?;
    let mut numbers_list = numbers_list.cast::<List<u32>>()?;
    let mut words_list = words_list.cast::<List<String>>()?;

    ids.set_size(capacity)?;
    timestamps.set_size(capacity)?;
    texts.set_size(capacity)?;
    blobs.set_size(capacity)?;
    flags.set_size(capacity)?;
    smalls.set_size(capacity)?;
    numbers_list.set_size(capacity)?;
    words_list.set_size(capacity)?;

    // Fixed-width columns: one data pointer and one validity mask per column, per chunk.
    let (id_data, timestamp_data, flag_data, small_data);
    {
        let mut id_writer = ids.writer()?;
        let mut timestamp_writer = timestamps.writer()?;
        let mut flag_writer = flags.writer()?;
        let mut small_writer = smalls.writer()?;
        id_data = id_writer.as_mut_ptr();
        timestamp_data = timestamp_writer.as_mut_ptr();
        flag_data = flag_writer.as_mut_ptr();
        small_data = small_writer.as_mut_ptr();
        // SAFETY: every row marked valid below is written first; the masks are sized for
        // `capacity` rows and `rows <= capacity`.
        let (timestamp_valid, flag_valid, small_valid) = unsafe {
            (
                timestamp_writer.validity_mut()?,
                flag_writer.validity_mut()?,
                small_writer.validity_mut()?,
            )
        };
        for row in 0..rows {
            let i = first + row as u64;
            // SAFETY: `row < rows <= capacity`, the size of each vector, and each pointer has the
            // physical type of its column (TIMESTAMP_NS is stored as i64 nanoseconds).
            unsafe {
                id_data.add(row).write(i);
                match timestamp(i) {
                    Some(value) => timestamp_data.add(row).write(TimestampNsValue(value)),
                    None => clear_bit(timestamp_valid, row),
                }
                match flag(i) {
                    Some(value) => flag_data.add(row).write(value),
                    None => clear_bit(flag_valid, row),
                }
                match small(i) {
                    Some(value) => small_data.add(row).write(value),
                    None => clear_bit(small_valid, row),
                }
            }
        }
    }

    // VARCHAR and BLOB: a 16-byte slot per row; payloads over 12 bytes go to the vector's arena.
    let (text_data, blob_data);
    {
        let mut writer = texts.writer()?;
        text_data = writer.as_mut_ptr();
        for row in 0..rows {
            match text(first + row as u64) {
                Some(value) => {
                    let encoded = writer.arena()?.add_str(&value)?;
                    // SAFETY: the row is in bounds and the payload is UTF-8 owned by this
                    // vector's arena. The cast only renames the slot's arena lifetime.
                    unsafe { text_data.cast::<DuckDBBytes<'_>>().add(row).write(encoded) };
                }
                // SAFETY: a NULL row needs no value.
                None => unsafe { writer.set_row_validity(row, false)? },
            }
        }

        let mut writer = blobs.writer()?;
        blob_data = writer.as_mut_ptr();
        for row in 0..rows {
            match bytes(first + row as u64) {
                Some(value) => {
                    let encoded = writer.arena()?.add_bytes(&value)?;
                    // SAFETY: as for the VARCHAR column; any bytes are a valid BLOB.
                    unsafe { blob_data.cast::<DuckDBBytes<'_>>().add(row).write(encoded) };
                }
                // SAFETY: a NULL row needs no value.
                None => unsafe { writer.set_row_validity(row, false)? },
            }
        }
    }

    // LIST columns: the number of elements is not known up front, so the child grows as rows
    // arrive. Growing needs the vector itself, so the list writer is re-created afterwards, and
    // rows are pointed at explicit child offsets because a new writer starts again at zero.
    let mut child_size = 0;
    let mut child_used = 0;
    for row in 0..rows {
        let list = numbers(first + row as u64);
        let needed = child_used + list.as_ref().map_or(0, Vec::len);
        if needed > child_size {
            let before = child_data_pointer(&numbers_list);
            child_size = needed.max(child_size * 2).max(8);
            numbers_list.set_child_size(child_size)?;
            if child_used > 0 && before != child_data_pointer(&numbers_list) {
                observed.list_child_moved.store(true, Ordering::Relaxed);
            }
        }
        let mut writer = numbers_list.list_writer()?;
        match list {
            Some(list) => {
                for (offset, element) in list.iter().enumerate() {
                    writer.elements().set(child_used + offset, element)?;
                }
                writer.set_entry(row, ListIndex::new(child_used as u64, list.len() as u64))?;
                child_used = needed;
            }
            None => writer.set_null(row)?,
        }
    }
    let numbers_used = child_used;

    let mut child_size = 0;
    let mut child_used = 0;
    for row in 0..rows {
        let list = words(first + row as u64);
        let needed = child_used + list.as_ref().map_or(0, Vec::len);
        if needed > child_size {
            child_size = needed.max(child_size * 2).max(8);
            words_list.set_child_size(child_size)?;
        }
        let mut writer = words_list.list_writer()?;
        match list {
            Some(list) => {
                for (offset, element) in list.iter().enumerate() {
                    writer
                        .elements()
                        .set_option(child_used + offset, element.as_deref())?;
                }
                writer.set_entry(row, ListIndex::new(child_used as u64, list.len() as u64))?;
                child_used = needed;
            }
            None => writer.set_null(row)?,
        }
    }
    let words_used = child_used;

    // Shrink to what was written. The first vector's size is the chunk's row count.
    ids.set_size(rows)?;
    timestamps.set_size(rows)?;
    texts.set_size(rows)?;
    blobs.set_size(rows)?;
    flags.set_size(rows)?;
    smalls.set_size(rows)?;
    numbers_list.set_size(rows)?;
    numbers_list.set_child_size(numbers_used)?;
    words_list.set_size(rows)?;
    words_list.set_child_size(words_used)?;

    // Were the pointers taken after sizing still the vectors' data pointers at the end?
    let moved = id_data != ids.writer()?.as_mut_ptr()
        || timestamp_data != timestamps.writer()?.as_mut_ptr()
        || flag_data != flags.writer()?.as_mut_ptr()
        || small_data != smalls.writer()?.as_mut_ptr()
        || text_data != texts.writer()?.as_mut_ptr()
        || blob_data != blobs.writer()?.as_mut_ptr();
    if rows > 0 && moved {
        observed.data_pointer_moved.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Address of the element storage of a LIST(UINTEGER) vector, for comparing before and after.
fn child_data_pointer(list: &Vector<'_, List<u32>>) -> usize {
    let child = list.children().unwrap().get_vector_at::<u32>(0).unwrap();
    child.reader().unwrap().as_ptr() as usize
}

fn register(connection: &Connection, name: &str, style: Style) -> Result<Arc<Observed>> {
    let observed = Arc::new(Observed::default());
    TableFunctionBuilder::new(
        name,
        SignatureBuilder::new().param(FunctionParameter::new::<i64>("row_count")),
        Rows {
            style,
            observed: observed.clone(),
        },
    )
    .register(connection)?;
    Ok(observed)
}

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

/// `function(5000)` returns exactly the rows `expected_sql` computes, in order.
fn assert_matches_sql(connection: &Connection, function: &str) -> Result<()> {
    let expected = expected_sql(5000);
    assert_eq!(
        rows(
            connection,
            &format!("SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM {function}(1))"),
        )?,
        [
            row(&["id", "UBIGINT"]),
            row(&["ts", "TIMESTAMP_NS"]),
            row(&["text", "VARCHAR"]),
            row(&["bytes", "BLOB"]),
            row(&["flag", "BOOLEAN"]),
            row(&["small", "UINTEGER"]),
            row(&["numbers", "UINTEGER[]"]),
            row(&["words", "VARCHAR[]"]),
        ]
    );
    for (left, right) in [
        (format!("SELECT * FROM {function}(5000)"), expected.clone()),
        (expected.clone(), format!("SELECT * FROM {function}(5000)")),
    ] {
        assert_eq!(
            value(
                connection,
                &format!("SELECT count(*) FROM (({left}) EXCEPT ALL ({right}))")
            )?,
            "0",
            "rows of ({left}) that are not in ({right})"
        );
    }
    // Row order, and a few rows spelled out.
    assert_eq!(
        value(
            connection,
            &format!("SELECT list(id) = range(5000)::UBIGINT[] FROM {function}(5000)")
        )?,
        "true"
    );
    assert_eq!(
        rows(
            connection,
            &format!("SELECT * FROM {function}(12) WHERE id IN (1, 11)")
        )?,
        [
            vec![
                "1".to_owned(),
                "2023-11-14 22:13:20.000000001".to_owned(),
                format!("{LONG_TEXT}1"),
                "blob-1\\x00\\xFF".to_owned(),
                "false".to_owned(),
                "2".to_owned(),
                "[1]".to_owned(),
                "[w1-0]".to_owned(),
            ],
            row(&[
                "11",
                "2023-11-14 22:13:20.000000011",
                "NULL",
                "NULL",
                "false",
                "22",
                "[11, 12, 13]",
                "NULL"
            ]),
        ]
    );
    assert_eq!(
        rows(
            connection,
            &format!("SELECT words, numbers, flag, ts, small FROM {function}(100) WHERE id = 79")
        )?,
        [row(&["[w79-0]", "[79, 80, 81]", "NULL", "NULL", "NULL"])]
    );
    assert_eq!(
        value(
            connection,
            &format!("SELECT words FROM {function}(100) WHERE id = 8")
        )?,
        "[w8-0, NULL]"
    );
    assert_eq!(
        value(connection, &format!("SELECT count(*) FROM {function}(0)"))?,
        "0"
    );
    Ok(())
}

#[test]
fn checked_writers_cover_the_scan_column_types() -> Result<()> {
    let connection = connect()?;
    let observed = register(&connection, "typed_rows", Style::Typed)?;
    assert_matches_sql(&connection, "typed_rows")?;

    assert_eq!(observed.capacity.load(Ordering::Relaxed), 2048);
    observed.chunks.store(0, Ordering::Relaxed);
    assert_eq!(
        value(&connection, "SELECT count(*) FROM typed_rows(5000)")?,
        "5000"
    );
    // 2048 + 2048 + 904 rows, then an empty chunk ends the scan.
    assert_eq!(observed.chunks.load(Ordering::Relaxed), 3);
    Ok(())
}

#[test]
fn raw_pointers_write_a_chunk_sized_to_capacity_then_shrunk() -> Result<()> {
    let connection = connect()?;
    let observed = register(&connection, "raw_rows", Style::Raw)?;
    assert_matches_sql(&connection, "raw_rows")?;

    assert_eq!(observed.capacity.load(Ordering::Relaxed), 2048);
    assert!(
        !observed.data_pointer_moved.load(Ordering::Relaxed),
        "a data pointer changed while a chunk was written or when it was shrunk"
    );
    // Growing a LIST child reallocates it; element pointers do not survive `set_child_size`.
    assert!(observed.list_child_moved.load(Ordering::Relaxed));
    Ok(())
}

/// A table function that emits one chunk of `capacity + 1` rows.
struct Oversized;

impl TableFunctionCallbacks for Oversized {
    type BindData = ();
    /// Whether the chunk has been emitted.
    type GlobalState = AtomicBool;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        _arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<()> {
        bind_handle.add_result_column("x", &u64::logical_type(context)?)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bind_data: &(),
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicBool>> {
        Ok(Some(AtomicBool::new(false)))
    }

    fn exec(
        &self,
        _context: &Context,
        _bind_data: &(),
        _local_state: Option<&mut ()>,
        emitted: Option<&AtomicBool>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        if emitted.unwrap().swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        let rows = output.capacity()? + 1;
        let mut vector = output.get_vector_at_mut::<u64>(0)?;
        // Not refused: the vector's buffer grows to fit.
        vector.set_size(rows)?;
        let mut writer = vector.writer()?;
        (0..rows).try_for_each(|row| writer.set(row, &(row as u64)))
    }
}

/// Nothing stops `exec` from sizing a vector past the chunk's capacity, and the oversized chunk
/// is passed on. Plans that only forward or count it work; the first operator that sizes a
/// standard vector from it raises an INTERNAL error, which invalidates the database. A sink
/// must therefore stop at `capacity()` rows itself.
#[test]
fn a_chunk_past_the_capacity_is_accepted_and_breaks_a_later_operator() -> Result<()> {
    let connection = connect()?;
    TableFunctionBuilder::new("oversized", SignatureBuilder::new(), Oversized)
        .register(&connection)?;

    assert_eq!(
        value(&connection, "SELECT count(*) FROM oversized()")?,
        "2049"
    );
    assert_eq!(rows(&connection, "SELECT x FROM oversized()")?.len(), 2049);

    let error = value(&connection, "SELECT sum(x) FROM oversized()").unwrap_err();
    assert_eq!(error.code, DuckDBError::RuntimeInternal, "{error}");
    assert!(
        error
            .message
            .contains("trying to set size to 2049 for vector with capacity 2048"),
        "{error}"
    );

    let after = value(&connection, "SELECT 42").unwrap_err();
    assert_eq!(after.code, DuckDBError::RuntimeFatal, "{after}");
    Ok(())
}

/// A table function that emits one chunk of 100 rows of two BIGINT columns, sizing only one of
/// the two vectors: the first if `size_first`, otherwise the second.
struct OneVectorSized {
    size_first: bool,
}

impl TableFunctionCallbacks for OneVectorSized {
    type BindData = ();
    /// Whether the chunk has been emitted.
    type GlobalState = AtomicBool;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        _arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<()> {
        bind_handle.add_result_column("a", &i64::logical_type(context)?)?;
        bind_handle.add_result_column("b", &i64::logical_type(context)?)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bind_data: &(),
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicBool>> {
        Ok(Some(AtomicBool::new(false)))
    }

    fn exec(
        &self,
        _context: &Context,
        _bind_data: &(),
        _local_state: Option<&mut ()>,
        emitted: Option<&AtomicBool>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        if emitted.unwrap().swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        let values: Vec<i64> = (0..100).collect();
        let (sized, unsized_) = if self.size_first { (0, 1) } else { (1, 0) };

        let mut vector = output.get_vector_at_mut::<i64>(sized)?;
        vector.set_size(values.len())?;
        vector.writer()?.write_slice(0, &values)?;

        let mut vector = output.get_vector_at_mut::<i64>(unsized_)?;
        let data = vector.writer()?.as_mut_ptr();
        for (row, value) in values.iter().enumerate() {
            // SAFETY: the vector's buffer holds `capacity()` BIGINT slots whatever its size.
            unsafe { data.add(row).write(value * 10) };
        }
        Ok(())
    }
}

#[test]
fn the_first_vector_sets_the_row_count_of_the_chunk() -> Result<()> {
    let connection = connect()?;
    for (name, size_first) in [("first_sized", true), ("second_sized", false)] {
        TableFunctionBuilder::new(name, SignatureBuilder::new(), OneVectorSized { size_first })
            .register(&connection)?;
    }

    // The size of the first vector becomes the size of the second.
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), sum(a), sum(b), bool_and(b = a * 10) FROM first_sized()"
        )?,
        [row(&["100", "4950", "49500", "true"])]
    );
    // A size set only on a later vector is ignored: the chunk is empty, which ends the scan.
    assert_eq!(
        value(&connection, "SELECT count(*) FROM second_sized()")?,
        "0"
    );
    Ok(())
}
