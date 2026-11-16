//! `chunk_rows(case)`: a test-only table function that writes given rows through
//! [`ChunkWriter`], and the reader that takes them back out of a query result.
//!
//! A test hands [`Replay::add`] the columns and rows of a [`Case`] and queries
//! `chunk_rows(<id>)`. Each `exec` call wraps DuckDB's output chunk in a `ChunkWriter` and writes
//! rows until the writer reports [`Full`] or the rows run out, exactly as a scan does, so what
//! the query returns went through real chunks, with DuckDB's projection and chunk boundaries.
//! [`query_cells`] reads a result back as the engine-neutral [`Cell`]s of the shared sink
//! conformance suite.
//!
//! The function is registered on a connection by the tests; the extension does not have it.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc, Mutex,
};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionCallbacks},
    types::{BlobValue, List, TimestampNsValue, TimestampValue},
    vector::RowReader,
    Error, Parameters, Result,
};
use pcapsql_core::scan::{
    testing::Cell, ColKind, ColumnSource, Full, ListSink, OutCol, OutColumn, RowSink,
};
use pcapsql_duckdb::engine::{guard, types, writer::ChunkWriter};

/// What `exec` does with the rows of a [`Case`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Write them, a chunk per `exec` call, and finish each chunk.
    #[default]
    Rows,
    /// Fill the first chunk, then write one more row to the full writer.
    PastFull,
    /// Call `u16` on the first column, whatever its kind.
    WrongKind,
    /// Tell the writer that every column is a `Str`, whatever DuckDB's vectors are.
    WrongColumns,
    /// Write the rows of a chunk and drop the writer without `finish`.
    Unfinished,
    /// Start a list in every list column of the first row and drop it without `finish`, then
    /// write the rows as usual.
    AbandonedList,
}

/// The rows a query of `chunk_rows` returns, and how they are written.
#[derive(Debug, Clone, Default)]
pub struct Case {
    /// The columns of the function's result. With none, the function declares one column it
    /// never writes (a table function cannot have none), and the writer gets an output without
    /// columns.
    pub columns: Vec<OutColumn>,
    /// One `Vec` per row, one [`Cell`] per column.
    pub rows: Vec<Vec<Cell>>,
    /// Rows per chunk, if less than DuckDB's chunk capacity.
    pub row_limit: Option<usize>,
    pub mode: Mode,
}

/// A registered [`Case`] and what its `exec` calls observed.
#[derive(Debug)]
struct Registered {
    case: Case,
    /// Rows of each non-empty chunk, in the order written.
    chunks: Mutex<Vec<usize>>,
    /// The declared column each chunk vector stood for, for every `exec` call that wrote rows.
    projections: Mutex<Vec<Vec<usize>>>,
}

/// The cases `chunk_rows` can replay.
#[derive(Debug, Default)]
pub struct Replay {
    cases: Mutex<HashMap<i64, Arc<Registered>>>,
    next_id: AtomicI64,
}

impl Replay {
    /// Register `chunk_rows(case BIGINT)` on `connection`.
    pub fn register(connection: &Connection) -> Result<Arc<Self>> {
        let replay = Arc::new(Self::default());
        // Under the extension's guard, as its own functions are: a panic of the writer is an
        // ordinary error.
        guard::table_function(
            "chunk_rows",
            SignatureBuilder::new().param(FunctionParameter::new::<i64>("case")),
            ChunkRows(replay.clone()),
        )
        .with_projection_pushdown(true)
        .register(connection)?;
        Ok(replay)
    }

    /// Add a case; `chunk_rows(<the id returned>)` replays it.
    pub fn add(&self, case: Case) -> i64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let registered = Registered {
            case,
            chunks: Mutex::default(),
            projections: Mutex::default(),
        };
        self.cases.lock().unwrap().insert(id, Arc::new(registered));
        id
    }

    /// Forget a case.
    pub fn remove(&self, id: i64) {
        self.cases.lock().unwrap().remove(&id);
    }

    fn get(&self, id: i64) -> Option<Arc<Registered>> {
        self.cases.lock().unwrap().get(&id).cloned()
    }

    /// The row counts of the non-empty chunks written for case `id` so far, and forget them.
    pub fn take_chunks(&self, id: i64) -> Vec<usize> {
        let case = self.get(id).expect("the case is registered");
        let mut chunks = case.chunks.lock().unwrap();
        std::mem::take(&mut *chunks)
    }

    /// For every chunk written for case `id` so far, the declared column of each of its
    /// vectors, and forget them.
    pub fn take_projections(&self, id: i64) -> Vec<Vec<usize>> {
        let case = self.get(id).expect("the case is registered");
        let mut projections = case.projections.lock().unwrap();
        std::mem::take(&mut *projections)
    }
}

/// An output column named `name` of `kind`.
pub fn column(name: &'static str, kind: ColKind) -> OutColumn {
    OutColumn {
        name,
        kind,
        nullable: true,
        source: ColumnSource::Field(name),
    }
}

/// Write `row` to `sink` through the method of each column's kind, then end the row.
pub fn write_cells<S: RowSink>(
    sink: &mut S,
    columns: &[OutColumn],
    row: &[Cell],
) -> ControlFlow<Full> {
    assert_eq!(columns.len(), row.len());
    for (index, (column, cell)) in columns.iter().zip(row).enumerate() {
        let col = OutCol(index as u16);
        match (column.kind, cell) {
            (_, Cell::Null) => sink.null(col),
            (ColKind::Bool, Cell::Bool(v)) => sink.bool(col, *v),
            (ColKind::U8, Cell::U8(v)) => sink.u8(col, *v),
            (ColKind::U16, Cell::U16(v)) => sink.u16(col, *v),
            (ColKind::U32, Cell::U32(v)) => sink.u32(col, *v),
            (ColKind::U64, Cell::U64(v)) => sink.u64(col, *v),
            (ColKind::I8, Cell::I8(v)) => sink.i8(col, *v),
            (ColKind::I64, Cell::I64(v)) => sink.i64(col, *v),
            (ColKind::F64, Cell::F64(v)) => sink.f64(col, *v),
            (ColKind::Str, Cell::Str(v)) => sink.str(col, v),
            (ColKind::Bin, Cell::Bytes(v)) => sink.bytes(col, v),
            (ColKind::Fixed(_), Cell::Bytes(v)) => sink.fixed(col, v),
            (ColKind::TsMicros | ColKind::TsNanos, Cell::Timestamp(v)) => sink.timestamp(col, *v),
            (
                ColKind::ListU16 | ColKind::ListU32 | ColKind::ListStr | ColKind::ListFixed(_),
                Cell::List(items),
            ) => {
                let mut list = sink.list(col);
                for item in items {
                    match item {
                        Cell::Null => list.null(),
                        Cell::U16(v) => list.u16(*v),
                        Cell::U32(v) => list.u32(*v),
                        Cell::Str(v) => list.str(v),
                        Cell::Bytes(v) => list.bytes(v),
                        other => panic!("{other:?} is not a list item"),
                    }
                }
                list.finish();
            }
            (kind, cell) => panic!("a {kind:?} column cannot store {cell:?}"),
        }
    }
    sink.end_row()
}

struct ChunkRows(Arc<Replay>);

impl TableFunctionCallbacks for ChunkRows {
    type BindData = Arc<Registered>;
    /// Index of the next row to write.
    type GlobalState = Mutex<usize>;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Self::BindData> {
        let id = arguments
            .first()
            .and_then(|argument| argument.value.as_ref())
            .map(|value| value.get::<i64>())
            .transpose()?
            .flatten()
            .ok_or_else(|| Error::invalid_input("chunk_rows: the case must be a BIGINT"))?;
        let registered = self
            .0
            .get(id)
            .ok_or_else(|| Error::invalid_input(format!("chunk_rows: no case {id}")))?;
        for column in &registered.case.columns {
            let logical_type = types::logical_type(context, column.kind)?;
            bind_handle.add_result_column(column.name, &logical_type)?;
        }
        if registered.case.columns.is_empty() {
            let logical_type = types::logical_type(context, ColKind::U64)?;
            bind_handle.add_result_column("never_written", &logical_type)?;
        }
        Ok(registered)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _case: &Self::BindData,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Self::GlobalState>> {
        Ok(Some(Mutex::new(0)))
    }

    /// One thread: the chunks come back in the order the rows were given.
    fn max_threads(
        &self,
        _context: &Context,
        _case: &Self::BindData,
        _global_state: Option<&Self::GlobalState>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<NonZeroUsize>> {
        Ok(NonZeroUsize::new(1))
    }

    fn exec(
        &self,
        _context: &Context,
        registered: &Self::BindData,
        _local_state: Option<&mut Self::LocalState>,
        next_row: Option<&Self::GlobalState>,
        output: DataChunkRef<'_>,
        column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let case = &registered.case;
        let mut next_row = next_row
            .expect("init_global_state always returns a state")
            .lock()
            .unwrap();

        // With projection pushdown the chunk holds only the columns the query uses.
        let projection = (0..column_info.count()?)
            .map(|index| column_info.get_column_index(index))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(output.col_count(), projection.len());
        let columns: Vec<OutColumn> = if case.columns.is_empty() {
            Vec::new()
        } else {
            projection
                .iter()
                .map(|&index| case.columns[index])
                .collect()
        };
        let project = |row: &[Cell]| -> Vec<Cell> {
            if case.columns.is_empty() {
                Vec::new()
            } else {
                projection.iter().map(|&index| row[index].clone()).collect()
            }
        };

        let chunk_capacity = output.capacity()?;
        let expected_capacity = case.row_limit.map_or(chunk_capacity, |limit| {
            assert!(limit > 0);
            limit.min(chunk_capacity)
        });
        let writer_columns = if case.mode == Mode::WrongColumns {
            columns
                .iter()
                .map(|column| OutColumn {
                    kind: ColKind::Str,
                    ..*column
                })
                .collect()
        } else {
            columns.clone()
        };
        let mut writer = match case.row_limit {
            Some(limit) => ChunkWriter::with_row_limit(output, &writer_columns, limit)?,
            None => ChunkWriter::new(output, &writer_columns)?,
        };
        if writer.capacity() != expected_capacity {
            return Err(Error::invalid_input(format!(
                "the writer holds {} rows, expected {expected_capacity}",
                writer.capacity()
            )));
        }

        if case.mode == Mode::WrongKind {
            writer.u16(OutCol(0), 7);
        }
        if case.mode == Mode::AbandonedList && *next_row == 0 {
            for (index, column) in columns.iter().enumerate() {
                let col = OutCol(index as u16);
                match column.kind {
                    ColKind::ListU16 => writer.list(col).u16(0xDEAD),
                    ColKind::ListU32 => writer.list(col).u32(0xDEAD_BEEF),
                    ColKind::ListStr => writer.list(col).str("abandoned, and long enough"),
                    ColKind::ListFixed(n) => writer.list(col).bytes(&vec![0xEE; usize::from(n)]),
                    _ => {}
                }
            }
        }

        while let Some(row) = case.rows.get(*next_row) {
            let flow = write_cells(&mut writer, &columns, &project(row));
            *next_row += 1;
            // `Full` exactly with the row that reaches the capacity.
            let at_capacity = writer.rows() == expected_capacity;
            if flow.is_break() != at_capacity || writer.is_full() != at_capacity {
                return Err(Error::invalid_input(format!(
                    "end_row returned {flow:?} and is_full() is {} with {} of \
                     {expected_capacity} rows",
                    writer.is_full(),
                    writer.rows()
                )));
            }
            if flow.is_break() {
                break;
            }
        }

        match case.mode {
            Mode::PastFull => {
                // Whatever the row holds, storing it would be past the chunk.
                let row = project(&case.rows[0]);
                let _ = write_cells(&mut writer, &columns, &row);
                unreachable!("the full writer accepted a row");
            }
            Mode::Unfinished => {
                drop(writer);
                return Ok(());
            }
            _ => {}
        }

        let written = writer.finish()?;
        if written > 0 {
            registered.chunks.lock().unwrap().push(written);
            registered.projections.lock().unwrap().push(projection);
        }
        Ok(())
    }
}

/// Append column `$index` of `$chunk`, read as `$type`, to `$rows`.
macro_rules! read {
    ($chunk:expr, $index:expr, $rows:expr, $type:ty, |$value:ident| $cell:expr) => {{
        let vector = $chunk.get_vector_at::<$type>($index)?;
        let reader = vector.reader()?;
        assert_eq!(reader.len(), $rows.len());
        for (row, cells) in $rows.iter_mut().enumerate() {
            cells.push(match reader.get(row)? {
                Some($value) => $cell,
                None => Cell::Null,
            });
        }
    }};
}

/// Append LIST column `$index` of `$chunk`, its items read as `$type`, to `$rows`.
macro_rules! read_list {
    ($chunk:expr, $index:expr, $rows:expr, $type:ty, |$value:ident| $cell:expr) => {{
        let vector = $chunk.get_vector_at::<List<$type>>($index)?;
        let reader = vector.list_reader()?;
        assert_eq!(reader.len(), $rows.len());
        for (row, cells) in $rows.iter_mut().enumerate() {
            cells.push(match reader.get(row)? {
                Some(items) => Cell::List(
                    items
                        .iter()
                        .map(|item| match item {
                            Some($value) => $cell,
                            None => Cell::Null,
                        })
                        .collect(),
                ),
                None => Cell::Null,
            });
        }
    }};
}

/// Run `sql` and return its rows as [`Cell`]s, reading column `i` as `kinds[i]`.
///
/// The values are read from the result's vectors with `duckdb-neo`'s typed readers, not parsed
/// from text, so a value comes back exactly as DuckDB holds it.
pub fn query_cells(
    connection: &Connection,
    sql: &str,
    kinds: &[ColKind],
) -> Result<Vec<Vec<Cell>>> {
    let mut result = connection.query(sql, Parameters::None)?;
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    while let Some(chunk) = result.next_chunk()? {
        assert_eq!(chunk.col_count(), kinds.len(), "{sql}");
        let first = rows.len();
        rows.resize_with(first + chunk.row_count()?, Vec::new);
        let out = &mut rows[first..];
        for (index, kind) in kinds.iter().enumerate() {
            match kind {
                ColKind::Bool => read!(chunk, index, out, bool, |v| Cell::Bool(*v)),
                ColKind::U8 => read!(chunk, index, out, u8, |v| Cell::U8(*v)),
                ColKind::U16 => read!(chunk, index, out, u16, |v| Cell::U16(*v)),
                ColKind::U32 => read!(chunk, index, out, u32, |v| Cell::U32(*v)),
                ColKind::U64 => read!(chunk, index, out, u64, |v| Cell::U64(*v)),
                ColKind::I8 => read!(chunk, index, out, i8, |v| Cell::I8(*v)),
                ColKind::I64 => read!(chunk, index, out, i64, |v| Cell::I64(*v)),
                ColKind::F64 => read!(chunk, index, out, f64, |v| Cell::F64(*v)),
                ColKind::Str => read!(chunk, index, out, String, |v| Cell::Str(v.to_owned())),
                ColKind::Bin | ColKind::Fixed(_) => {
                    read!(chunk, index, out, BlobValue, |v| Cell::Bytes(v.to_vec()))
                }
                ColKind::TsMicros => {
                    read!(chunk, index, out, TimestampValue, |v| Cell::Timestamp(v.0))
                }
                ColKind::TsNanos => {
                    read!(chunk, index, out, TimestampNsValue, |v| Cell::Timestamp(
                        v.0
                    ))
                }
                ColKind::ListU16 => read_list!(chunk, index, out, u16, |v| Cell::U16(*v)),
                ColKind::ListU32 => read_list!(chunk, index, out, u32, |v| Cell::U32(*v)),
                ColKind::ListStr => {
                    read_list!(chunk, index, out, String, |v| Cell::Str(v.to_owned()))
                }
                ColKind::ListFixed(_) => {
                    read_list!(chunk, index, out, BlobValue, |v| Cell::Bytes(v.to_vec()))
                }
            }
        }
    }
    Ok(rows)
}
