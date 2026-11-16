//! [`ChunkWriter`]: the scan layer's [`RowSink`] over a table function's output chunk.
//!
//! The shared scan layer writes a row as one typed call per column, then `end_row()`. This sink
//! stores each value straight into the DuckDB vector of its column, at the current row:
//!
//! - **Fixed-width values** (integers, DOUBLE, BOOLEAN, timestamps) are stored through the
//!   vector's data pointer, which is fetched once when the writer is created.
//! - **VARCHAR and BLOB** values of up to 12 bytes are stored inline in the row's 16-byte slot;
//!   longer ones are copied into the vector's arena (one call into DuckDB), and the slot points
//!   there. A fixed-size binary value (a MAC or IPv6 address) is a BLOB.
//! - **LIST** values append their items to the vector's child and store the child range in the
//!   row. The child grows by doubling; growing moves its buffers, so its pointers are fetched
//!   again each time it grows.
//! - **NULL** clears the row's bit in the vector's validity mask.
//!
//! # Capacity
//!
//! DuckDB hands `exec` a chunk of a fixed capacity (2,048 rows in DuckDB 2.0.0) and does not
//! refuse a chunk reported larger: the first operator that sizes a vector from it raises an
//! INTERNAL error, which invalidates the database. The writer therefore counts rows itself:
//! [`RowSink::end_row`] returns `Break(Full)` with the row that reaches the capacity, and any
//! write after that panics (which `guard` reports as an ordinary error) instead of storing.
//!
//! # Projection
//!
//! The chunk holds one vector per projected column, and the writer is given the [`OutColumn`]s
//! of the same columns in the same order. An output without columns (the scan layer's row count)
//! is accepted for any chunk: DuckDB never hands `exec` a chunk without vectors (for `count(*)`
//! it projects one column of its choosing), so the row count is set on the vectors that are
//! there and their rows are NULL.
//!
//! One vector of the chunk may be a *constant*: a VARCHAR column that is not the scan layer's
//! and has the same value in every row of the chunk (the `filename` column of a scan function,
//! whose chunks never span two files). [`ChunkWriter::with_constant`] is told which vector it
//! is; the scan layer's columns are then the other vectors, in order, and [`finish`] stores the
//! value in every row it reports. It is stored through `duckdb-neo`'s checked writer, not
//! through the pointers below.
//!
//! [`finish`]: ChunkWriter::finish
//!
//! # Soundness
//!
//! This is the only module of the crate with `unsafe` code, apart from one private module of
//! `engine::scalar` (`valid`, which reads; see there).
//!
//! `duckdb-neo`'s checked writers
//! borrow one vector at a time and need the row count before the first write; a row sink writes
//! all columns of a row before the next row and learns the row count last. So the writer keeps,
//! per column, the raw data and validity pointers `duckdb-neo` hands out, and upholds these
//! invariants, which every `unsafe` block below refers to:
//!
//! 1. **Type.** A column's pointers are stored in the [`Data`] (or [`Items`]) variant of the
//!    type the vector was validated as by `duckdb-neo` (`get_vector_at_mut::<T>`) when they
//!    were fetched, and a value is only stored through the variant of its own type. A typed
//!    call on a column of another kind panics before anything is written.
//! 2. **Bounds.** Every vector is sized to `limit` rows, at most the chunk's capacity, before
//!    its pointers are fetched, and a row index is checked against `limit` before each write.
//!    A list child is sized to `reserved` items and an item index is checked against it.
//! 3. **Stability.** The writer owns the chunk, so nothing else can resize a vector. A parent
//!    vector is resized only in `finish` and on drop, after the pointers are discarded; a list
//!    child is resized only in `ListColumn::reserve`, which replaces the child's pointers.
//!    (That a vector's buffers stay put while its rows are written is pinned by the
//!    `spike_vectors` test.)
//! 4. **Initialisation.** `Vector::set_size` zero-fills the rows it exposes, which is a value of
//!    every type used here (0, `''`, an empty list). A row or item the caller skips is therefore
//!    still a valid value, and a NULL row holds initialised storage.
#![allow(unsafe_code)]

use std::ops::ControlFlow;
use std::ptr::NonNull;

use duckdb_neo::{
    data_chunk::DataChunkRef,
    types::{BlobValue, List, ListIndex, TimestampNsValue, TimestampValue},
    vector::{Arena, DuckDBBytes, HasDuckDBBytes, NativeElement, Unknown, VectorWriter},
    AsRaw, Error, FromRaw, Result,
};
use pcapsql_core::scan::{ColKind, Full, ListSink, OutCol, OutColumn, RowSink};

/// A [`RowSink`] that stores rows in the output chunk of one `exec` call.
///
/// Create one per `exec`, hand it to the scan, then call [`finish`](Self::finish), which gives
/// the chunk its row count. A writer dropped without `finish` (an early return with an error)
/// leaves the chunk empty.
///
/// A storage failure inside a typed call (DuckDB could not allocate a string, or grow a list)
/// cannot be returned from the call. The cell becomes NULL, and [`finish`](Self::finish) returns
/// the first such error, so the query fails instead of returning the NULL.
#[derive(Debug)]
pub struct ChunkWriter<'chunk> {
    chunk: DataChunkRef<'chunk>,
    /// One per output column; empty when the output has no columns.
    columns: Box<[Column]>,
    /// The vector that is not the scan layer's, and the text every row of it gets.
    constant: Option<(usize, Box<str>)>,
    /// Complete rows stored so far: the index of the row being written.
    row: usize,
    /// Rows the chunk may hold; no vector is written at or past it.
    limit: usize,
    /// The first storage error, reported by `finish`.
    error: Option<Error>,
    finished: bool,
}

impl<'chunk> ChunkWriter<'chunk> {
    /// A writer that fills `chunk` up to its capacity.
    ///
    /// `columns` are the output columns of the scan, one per vector of the chunk and in the
    /// chunk's order, or empty for an output without columns. Fails if a vector does not have
    /// the DuckDB type of its column's kind (`engine::types::logical_type`).
    pub fn new(chunk: DataChunkRef<'chunk>, columns: &[OutColumn]) -> Result<Self> {
        Self::with_row_limit(chunk, columns, usize::MAX)
    }

    /// As [`new`](Self::new), for a writer that is full after `limit` rows, or at the chunk's
    /// capacity if that is less. A limit of zero is an error: a sink holds at least one row.
    pub fn with_row_limit(
        chunk: DataChunkRef<'chunk>,
        columns: &[OutColumn],
        limit: usize,
    ) -> Result<Self> {
        Self::build(chunk, columns, None, limit)
    }

    /// As [`new`](Self::new), for a chunk whose vector `vector` is a VARCHAR that is not one of
    /// `columns`: every row of it is `text`. `columns` are the other vectors of the chunk, in
    /// the chunk's order.
    pub fn with_constant(
        chunk: DataChunkRef<'chunk>,
        columns: &[OutColumn],
        vector: usize,
        text: &str,
    ) -> Result<Self> {
        Self::build(chunk, columns, Some((vector, text.into())), usize::MAX)
    }

    fn build(
        mut chunk: DataChunkRef<'chunk>,
        columns: &[OutColumn],
        constant: Option<(usize, Box<str>)>,
        limit: usize,
    ) -> Result<Self> {
        let limit = limit.min(chunk.capacity()?);
        if limit == 0 {
            return Err(Error::invalid_input(
                "pcapsql: an output chunk must have room for a row",
            ));
        }
        let vectors = chunk.col_count();
        if vectors == 0 {
            // A chunk's row count is the size of its first vector: without one, rows written
            // here would be lost silently.
            return Err(Error::invalid_input(
                "pcapsql: DuckDB handed the scan an output chunk without vectors",
            ));
        }
        let constant_vector = constant.as_ref().map(|(vector, _)| *vector);
        if let Some(vector) = constant_vector {
            if vector >= vectors {
                return Err(Error::invalid_input(format!(
                    "pcapsql: the output chunk has {vectors} vectors and no vector {vector}"
                )));
            }
            // Fail now, not in `finish`, if the vector is not a VARCHAR.
            chunk.get_vector_at_mut::<String>(vector)?;
        }
        let own = vectors - usize::from(constant_vector.is_some());
        if !columns.is_empty() && columns.len() != own {
            return Err(Error::invalid_input(format!(
                "pcapsql: the scan produces {} columns and the output chunk has {own}",
                columns.len()
            )));
        }

        let mut built = Vec::with_capacity(columns.len());
        for (index, column) in columns.iter().enumerate() {
            let vector = vector_of(constant_vector, index);
            match Column::new(&mut chunk, vector, column.kind, limit) {
                Ok(column) => built.push(column),
                Err(error) => {
                    // The vectors sized so far must not be taken for rows.
                    let _ = resize(&mut chunk, &built, constant_vector, 0);
                    return Err(error);
                }
            }
        }
        Ok(Self {
            chunk,
            columns: built.into(),
            constant,
            row: 0,
            limit,
            error: None,
            finished: false,
        })
    }

    /// The number of complete rows stored.
    pub fn rows(&self) -> usize {
        self.row
    }

    /// The number of rows the writer holds when it reports [`Full`].
    pub fn capacity(&self) -> usize {
        self.limit
    }

    /// True when no further row fits.
    pub fn is_full(&self) -> bool {
        self.row >= self.limit
    }

    /// Give the chunk its row count, the number of complete rows stored, and return it.
    /// A chunk of zero rows tells DuckDB that the scan has ended.
    ///
    /// Returns the first storage error of a typed call, if there was one; the chunk is then
    /// left empty.
    pub fn finish(mut self) -> Result<usize> {
        self.finished = true;
        // The pointers die here, before any vector is resized (invariant 3).
        let columns = std::mem::take(&mut self.columns);
        let constant = self.constant.as_ref().map(|(vector, _)| *vector);
        if let Some(error) = self.error.take() {
            let _ = resize(&mut self.chunk, &columns, constant, 0);
            return Err(error);
        }
        let stored = resize(&mut self.chunk, &columns, constant, self.row)
            .and_then(|()| self.store_constant());
        if let Err(error) = stored {
            let _ = resize(&mut self.chunk, &columns, constant, 0);
            return Err(error);
        }
        Ok(self.row)
    }

    /// Store the constant in every row of its vector, which has been sized to the row count.
    fn store_constant(&mut self) -> Result<()> {
        let Some((vector, text)) = &self.constant else {
            return Ok(());
        };
        if self.row == 0 {
            return Ok(());
        }
        let mut vector = self.chunk.get_vector_at_mut::<String>(*vector)?;
        let mut writer = vector.writer()?;
        for row in 0..self.row {
            writer.set(row, text)?;
        }
        Ok(())
    }

    /// The current row and the storage of column `col`.
    ///
    /// Panics when the writer is full or the output has no such column. Everything that stores
    /// a value goes through here, which is what keeps writes inside the chunk (invariant 2).
    #[inline(always)]
    fn cell(&mut self, col: OutCol) -> (usize, &mut Column) {
        let row = self.row;
        if row >= self.limit {
            full();
        }
        match self.columns.get_mut(usize::from(col.0)) {
            Some(column) => (row, column),
            None => no_column(col),
        }
    }

    /// Remember the first storage error for `finish`.
    #[cold]
    fn fail(&mut self, error: Error) {
        self.error.get_or_insert(error);
    }
}

impl Drop for ChunkWriter<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Not finished: an error or a panic is on its way out of `exec`. The vectors were
            // sized to the limit for writing; leave no rows behind.
            let columns = std::mem::take(&mut self.columns);
            let constant = self.constant.as_ref().map(|(vector, _)| *vector);
            let _ = resize(&mut self.chunk, &columns, constant, 0);
        }
    }
}

/// The vector of the scan layer's column `column` in a chunk whose vector `constant` is not
/// the scan layer's: the columns are the other vectors, in order.
fn vector_of(constant: Option<usize>, column: usize) -> usize {
    match constant {
        Some(constant) if column >= constant => column + 1,
        _ => column,
    }
}

/// The scan layer's column that vector `vector` holds; `None` for the constant vector.
fn column_of(constant: Option<usize>, vector: usize) -> Option<usize> {
    match constant {
        Some(constant) if vector == constant => None,
        Some(constant) if vector > constant => Some(vector - 1),
        _ => Some(vector),
    }
}

/// Size every vector of `chunk` to `rows` rows and every list child to the items its rows use.
/// With no `columns` (an output without columns) the rows of every vector but the `constant`
/// one become NULL.
fn resize(
    chunk: &mut DataChunkRef<'_>,
    columns: &[Column],
    constant: Option<usize>,
    rows: usize,
) -> Result<()> {
    for index in 0..chunk.col_count() {
        let mut vector = chunk.get_vector_at_mut::<Unknown>(index)?;
        vector.set_size(rows)?;
        let Some(column) = column_of(constant, index) else {
            // The constant vector: `finish` stores its rows.
            continue;
        };
        match columns.get(column).map(|column| &column.data) {
            Some(Data::List(list)) => {
                let used = if rows == 0 { 0 } else { list.used };
                match list.items {
                    Items::U16(_) => vector.cast::<List<u16>>()?.set_child_size(used)?,
                    Items::U32(_) => vector.cast::<List<u32>>()?.set_child_size(used)?,
                    Items::Str(_) => vector.cast::<List<String>>()?.set_child_size(used)?,
                    Items::Blob(_) => vector.cast::<List<BlobValue>>()?.set_child_size(used)?,
                }
            }
            Some(_) => {}
            None if columns.is_empty() && rows > 0 => vector.writer()?.fill_null()?,
            None => {}
        }
    }
    Ok(())
}

#[cold]
#[inline(never)]
fn full() -> ! {
    panic!("a row is written to a full output chunk");
}

#[cold]
#[inline(never)]
fn no_column(col: OutCol) -> ! {
    panic!("the output chunk has no column {}", col.0);
}

#[cold]
#[inline(never)]
fn mismatch(col: OutCol, value: &str) -> ! {
    panic!("output column {} does not store {value} values", col.0);
}

#[cold]
#[inline(never)]
fn item_mismatch(column: usize, value: &str) -> ! {
    panic!("the list of output column {column} does not store {value} items");
}

/// What the writer keeps of one vector: its validity mask and its typed storage.
#[derive(Debug)]
struct Column {
    validity: NonNull<u64>,
    data: Data,
}

/// The data pointer of a vector, by the type DuckDB stores in its slots (invariant 1).
#[derive(Debug)]
enum Data {
    Bool(NonNull<bool>),
    U8(NonNull<u8>),
    U16(NonNull<u16>),
    U32(NonNull<u32>),
    U64(NonNull<u64>),
    I8(NonNull<i8>),
    I64(NonNull<i64>),
    F64(NonNull<f64>),
    /// TIMESTAMP (microseconds) or TIMESTAMP_NS (nanoseconds): an `i64` either way.
    Timestamp(NonNull<i64>),
    /// VARCHAR: the payloads must be UTF-8.
    Str(Bytes),
    /// BLOB.
    Blob(Bytes),
    List(ListColumn),
}

impl Column {
    /// Size vector `index` of `chunk` to `rows` rows and take what writing a column of `kind`
    /// needs. Fails if the vector does not have the DuckDB type of `kind`.
    fn new(chunk: &mut DataChunkRef<'_>, index: usize, kind: ColKind, rows: usize) -> Result<Self> {
        let (validity, data) = match kind {
            ColKind::Bool => plain::<bool>(chunk, index, rows, Data::Bool)?,
            ColKind::U8 => plain::<u8>(chunk, index, rows, Data::U8)?,
            ColKind::U16 => plain::<u16>(chunk, index, rows, Data::U16)?,
            ColKind::U32 => plain::<u32>(chunk, index, rows, Data::U32)?,
            ColKind::U64 => plain::<u64>(chunk, index, rows, Data::U64)?,
            ColKind::I8 => plain::<i8>(chunk, index, rows, Data::I8)?,
            ColKind::I64 => plain::<i64>(chunk, index, rows, Data::I64)?,
            ColKind::F64 => plain::<f64>(chunk, index, rows, Data::F64)?,
            // Both value types are `#[repr(transparent)]` over the `i64` DuckDB stores.
            ColKind::TsMicros => {
                plain::<TimestampValue>(chunk, index, rows, |data| Data::Timestamp(data.cast()))?
            }
            ColKind::TsNanos => {
                plain::<TimestampNsValue>(chunk, index, rows, |data| Data::Timestamp(data.cast()))?
            }
            ColKind::Str => bytes::<String>(chunk, index, rows, Data::Str)?,
            ColKind::Bin | ColKind::Fixed(_) => bytes::<BlobValue>(chunk, index, rows, Data::Blob)?,
            ColKind::ListU16 => list::<u16>(chunk, index, rows)?,
            ColKind::ListU32 => list::<u32>(chunk, index, rows)?,
            ColKind::ListStr => list::<String>(chunk, index, rows)?,
            ColKind::ListFixed(_) => list::<BlobValue>(chunk, index, rows)?,
        };
        Ok(Self { validity, data })
    }
}

/// The data and validity pointers behind `writer`, for rows below `writer.len()`.
fn pointers<T: NativeElement>(
    writer: &mut VectorWriter<'_, T>,
) -> Result<(NonNull<T::Native<'static>>, NonNull<u64>)> {
    let data = NonNull::new(writer.as_mut_ptr());
    // SAFETY: `validity_mut` requires that a row marked valid holds a value. Every row does:
    // the vector was sized with `set_size`, which zero-fills (invariant 4). The slice is only
    // used for its address.
    let validity = NonNull::new(unsafe { writer.validity_mut()? }.as_mut_ptr());
    data.zip(validity).ok_or_else(|| {
        Error::invalid_input("pcapsql: DuckDB gave an output vector without storage")
    })
}

/// Size a fixed-width vector and take its pointers.
fn plain<T: NativeElement>(
    chunk: &mut DataChunkRef<'_>,
    index: usize,
    rows: usize,
    data: impl FnOnce(NonNull<T::Native<'static>>) -> Data,
) -> Result<(NonNull<u64>, Data)> {
    let mut vector = chunk.get_vector_at_mut::<T>(index)?;
    vector.set_size(rows)?;
    let (slots, validity) = pointers(&mut vector.writer()?)?;
    Ok((validity, data(slots)))
}

/// Size a VARCHAR or BLOB vector and take its pointers and arena.
fn bytes<T>(
    chunk: &mut DataChunkRef<'_>,
    index: usize,
    rows: usize,
    data: impl FnOnce(Bytes) -> Data,
) -> Result<(NonNull<u64>, Data)>
where
    T: HasDuckDBBytes + for<'a> NativeElement<Native<'a> = DuckDBBytes<'a>>,
{
    let mut vector = chunk.get_vector_at_mut::<T>(index)?;
    vector.set_size(rows)?;
    let (bytes, validity) = Bytes::of(&mut vector.writer()?)?;
    Ok((validity, data(bytes)))
}

/// Mark `row` not NULL.
///
/// # Safety
///
/// `validity` is the mask of a vector that has more than `row` rows (invariants 2 and 3).
#[inline(always)]
unsafe fn mark_valid(validity: NonNull<u64>, row: usize) {
    // SAFETY: the caller guarantees that the mask covers `row`.
    unsafe {
        let word = validity.as_ptr().add(row / 64);
        let bit = 1u64 << (row % 64);
        // A mask starts all valid, so this is almost never a store.
        if *word & bit == 0 {
            *word |= bit;
        }
    }
}

/// Mark `row` NULL.
///
/// # Safety
///
/// As for [`mark_valid`].
#[inline(always)]
unsafe fn mark_null(validity: NonNull<u64>, row: usize) {
    // SAFETY: the caller guarantees that the mask covers `row`.
    unsafe { *validity.as_ptr().add(row / 64) &= !(1u64 << (row % 64)) };
}

/// Store `value` in `row` and mark the row not NULL.
///
/// # Safety
///
/// `data` and `validity` are the pointers of one vector that has more than `row` rows and
/// stores `T` in its slots (invariants 1 to 3).
#[inline(always)]
unsafe fn put<T>(data: NonNull<T>, validity: NonNull<u64>, row: usize, value: T) {
    // SAFETY: the caller guarantees that slot `row` exists, holds a `T`, and is covered by the
    // mask.
    unsafe {
        data.as_ptr().add(row).write(value);
        mark_valid(validity, row);
    }
}

/// The storage of a VARCHAR or BLOB vector: a 16-byte slot per row, and the arena for payloads
/// that do not fit in the slot.
#[derive(Debug)]
struct Bytes {
    slots: NonNull<DuckDBBytes<'static>>,
    arena: Arena,
}

impl Bytes {
    fn of<T>(writer: &mut VectorWriter<'_, T>) -> Result<(Self, NonNull<u64>)>
    where
        T: HasDuckDBBytes + for<'a> NativeElement<Native<'a> = DuckDBBytes<'a>>,
    {
        let (slots, validity) = pointers(writer)?;
        let arena = writer.arena()?;
        // SAFETY: `Arena` is a borrowing wrapper around the handle (it has no destructor), so a
        // second wrapper of the same handle frees nothing twice. `duckdb-neo` ties the arena's
        // borrow to the vector wrapper, which cannot be kept here; the handle itself is valid
        // until the vector is resized, which does not happen while this copy is alive
        // (invariant 3).
        let arena = unsafe { Arena::from_raw(arena.get_raw()) };
        Ok((Self { slots, arena }, validity))
    }

    /// Store `value` in `row`, or NULL if DuckDB cannot hold it.
    ///
    /// # Safety
    ///
    /// `self` and `validity` come from one vector that has more than `row` rows (invariants 2
    /// and 3), and `value` is UTF-8 if that vector is a VARCHAR.
    #[inline]
    unsafe fn put(&self, validity: NonNull<u64>, row: usize, value: &[u8]) -> Result<()> {
        match self.arena.add_bytes(value) {
            // SAFETY: slot `row` exists and holds a `DuckDBBytes` (invariant 1); the payload is
            // inline or in this vector's own arena, so it lives as long as the vector does. The
            // cast only renames the arena lifetime of the slot type.
            Ok(encoded) => unsafe {
                put(self.slots.cast::<DuckDBBytes<'_>>(), validity, row, encoded);
                Ok(())
            },
            Err(error) => {
                // SAFETY: the mask covers `row`.
                unsafe { mark_null(validity, row) };
                Err(error)
            }
        }
    }
}

/// The storage of a LIST vector: an entry (offset and length into the child) per row, and the
/// child vector that holds the items of all rows.
#[derive(Debug)]
struct ListColumn {
    /// The index of the LIST vector in the chunk, to reach it again when the child must grow.
    vector: usize,
    entries: NonNull<ListIndex>,
    items: Items,
    item_validity: NonNull<u64>,
    /// The size of the child: items below it can be written.
    reserved: usize,
    /// Items that belong to finished cells; the next cell starts here.
    used: usize,
}

/// The data pointer of a LIST vector's child, by item type (invariant 1).
#[derive(Debug)]
enum Items {
    U16(NonNull<u16>),
    U32(NonNull<u32>),
    Str(Bytes),
    Blob(Bytes),
}

/// The pointers of a list vector after its child was sized.
struct ListPointers {
    entries: NonNull<ListIndex>,
    validity: NonNull<u64>,
    items: Items,
    item_validity: NonNull<u64>,
}

/// An item type of a list column.
trait Item: NativeElement {
    /// Take the pointers of a child vector of this type.
    fn items(writer: &mut VectorWriter<'_, Self>) -> Result<(Items, NonNull<u64>)>;
}

impl Item for u16 {
    fn items(writer: &mut VectorWriter<'_, Self>) -> Result<(Items, NonNull<u64>)> {
        let (data, validity) = pointers(writer)?;
        Ok((Items::U16(data), validity))
    }
}

impl Item for u32 {
    fn items(writer: &mut VectorWriter<'_, Self>) -> Result<(Items, NonNull<u64>)> {
        let (data, validity) = pointers(writer)?;
        Ok((Items::U32(data), validity))
    }
}

impl Item for String {
    fn items(writer: &mut VectorWriter<'_, Self>) -> Result<(Items, NonNull<u64>)> {
        let (bytes, validity) = Bytes::of(writer)?;
        Ok((Items::Str(bytes), validity))
    }
}

impl Item for BlobValue {
    fn items(writer: &mut VectorWriter<'_, Self>) -> Result<(Items, NonNull<u64>)> {
        let (bytes, validity) = Bytes::of(writer)?;
        Ok((Items::Blob(bytes), validity))
    }
}

/// Size the child of LIST vector `index` to `items` items, and the vector itself to `rows` rows
/// if given, then take the pointers of both.
fn list_pointers<T: Item>(
    chunk: &mut DataChunkRef<'_>,
    index: usize,
    rows: Option<usize>,
    items: usize,
) -> Result<ListPointers> {
    let mut vector = chunk.get_vector_at_mut::<List<T>>(index)?;
    if let Some(rows) = rows {
        vector.set_size(rows)?;
    }
    vector.set_child_size(items)?;
    let (items, item_validity) = {
        let mut children = vector
            .children_mut()
            .ok_or_else(|| Error::invalid_input("pcapsql: a LIST vector without a child"))?;
        let mut child = children.get_vector_at_mut::<T>(0)?;
        T::items(&mut child.writer()?)?
    };
    let (entries, validity) = pointers(&mut vector.writer()?)?;
    Ok(ListPointers {
        entries,
        validity,
        items,
        item_validity,
    })
}

/// Size a LIST vector and its child and take the pointers of both.
fn list<T: Item>(
    chunk: &mut DataChunkRef<'_>,
    index: usize,
    rows: usize,
) -> Result<(NonNull<u64>, Data)> {
    // Room for one item per row to start with; DuckDB allocates a child of a full chunk's size
    // anyway.
    let reserved = rows;
    let pointers = list_pointers::<T>(chunk, index, Some(rows), reserved)?;
    let column = ListColumn {
        vector: index,
        entries: pointers.entries,
        items: pointers.items,
        item_validity: pointers.item_validity,
        reserved,
        used: 0,
    };
    Ok((pointers.validity, Data::List(column)))
}

impl ListColumn {
    /// Grow the child to hold at least `needed` items. Returns the vector's validity mask,
    /// fetched again with everything else.
    #[cold]
    fn reserve(&mut self, chunk: &mut DataChunkRef<'_>, needed: usize) -> Result<NonNull<u64>> {
        let size = needed.max(self.reserved.saturating_mul(2));
        // A failed resize may have replaced the child's buffers all the same: until new
        // pointers are in place, no item can be written (invariant 2).
        self.reserved = 0;
        let pointers = match self.items {
            Items::U16(_) => list_pointers::<u16>(chunk, self.vector, None, size),
            Items::U32(_) => list_pointers::<u32>(chunk, self.vector, None, size),
            Items::Str(_) => list_pointers::<String>(chunk, self.vector, None, size),
            Items::Blob(_) => list_pointers::<BlobValue>(chunk, self.vector, None, size),
        }?;
        self.entries = pointers.entries;
        self.items = pointers.items;
        self.item_validity = pointers.item_validity;
        self.reserved = size;
        Ok(pointers.validity)
    }
}

/// A fixed-width `RowSink` method: check the row and the column's type, then store.
macro_rules! store {
    ($(#[$doc:meta])* $method:ident, $type:ty, $variant:ident) => {
        $(#[$doc])*
        #[inline]
        fn $method(&mut self, col: OutCol, v: $type) {
            let (row, column) = self.cell(col);
            let Data::$variant(data) = column.data else {
                mismatch(col, stringify!($method))
            };
            // SAFETY: `cell` checked `row < limit`, the size of this vector (invariant 2);
            // `data` and `validity` are its current pointers (invariant 3), and the variant
            // says its slots hold this type (invariant 1).
            unsafe { put(data, column.validity, row, v) }
        }
    };
}

impl<'chunk> RowSink for ChunkWriter<'chunk> {
    #[inline]
    fn null(&mut self, col: OutCol) {
        let (row, column) = self.cell(col);
        // SAFETY: `cell` checked `row < limit`, the size of this vector (invariant 2), whose
        // mask `validity` is (invariant 3). The slot keeps an initialised value (invariant 4).
        unsafe { mark_null(column.validity, row) }
    }

    store!(bool, bool, Bool);
    store!(u8, u8, U8);
    store!(u16, u16, U16);
    store!(u32, u32, U32);
    store!(u64, u64, U64);
    store!(i8, i8, I8);
    store!(i64, i64, I64);
    store!(f64, f64, F64);
    store!(
        /// Microseconds for a TIMESTAMP column, nanoseconds for a TIMESTAMP_NS one: the unit
        /// of the column's kind, which is the unit of the vector.
        timestamp,
        i64,
        Timestamp
    );

    #[inline]
    fn str(&mut self, col: OutCol, v: &str) {
        let (row, column) = self.cell(col);
        let Data::Str(bytes) = &column.data else {
            mismatch(col, "str")
        };
        // SAFETY: `cell` checked `row < limit`, the size of this vector (invariant 2), whose
        // current storage `bytes` and `validity` are (invariant 3); `v` is UTF-8.
        if let Err(error) = unsafe { bytes.put(column.validity, row, v.as_bytes()) } {
            self.fail(error);
        }
    }

    /// Also stores `Fixed(n)` values (the trait's `fixed` forwards here): both are BLOBs.
    #[inline]
    fn bytes(&mut self, col: OutCol, v: &[u8]) {
        let (row, column) = self.cell(col);
        let Data::Blob(bytes) = &column.data else {
            mismatch(col, "bytes")
        };
        // SAFETY: as for `str`; a BLOB holds any bytes.
        if let Err(error) = unsafe { bytes.put(column.validity, row, v) } {
            self.fail(error);
        }
    }

    type List<'s>
        = ChunkList<'s, 'chunk>
    where
        Self: 's;

    #[inline]
    fn list(&mut self, col: OutCol) -> ChunkList<'_, 'chunk> {
        let (row, column) = self.cell(col);
        let Data::List(list) = &column.data else {
            mismatch(col, "list")
        };
        let start = list.used;
        ChunkList {
            writer: self,
            column: usize::from(col.0),
            row,
            start,
            len: 0,
            failed: false,
        }
    }

    #[inline]
    fn end_row(&mut self) -> ControlFlow<Full> {
        if self.row >= self.limit {
            full();
        }
        self.row += 1;
        if self.row == self.limit {
            ControlFlow::Break(Full)
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// The writer of one list cell of a [`ChunkWriter`].
///
/// The items go to the child of the column's LIST vector, after the items of the cells before
/// it. A writer dropped without [`finish`](ListSink::finish) leaves the cell as it was and its
/// items unused.
#[derive(Debug)]
pub struct ChunkList<'s, 'chunk> {
    writer: &'s mut ChunkWriter<'chunk>,
    column: usize,
    /// The row of the cell, checked against the writer's limit by `list()`.
    row: usize,
    /// The index of the cell's first item in the child.
    start: usize,
    len: usize,
    /// The child could not grow: the cell becomes NULL.
    failed: bool,
}

impl ChunkList<'_, '_> {
    /// The index of the next item in the child, and the column's storage with room for it.
    /// `None` when the child cannot grow.
    #[inline(always)]
    fn item(&mut self) -> Option<(usize, &mut ListColumn)> {
        if self.failed {
            return None;
        }
        let writer = &mut *self.writer;
        let column = &mut writer.columns[self.column];
        let Data::List(list) = &mut column.data else {
            unreachable!("list() checked that the column is a list")
        };
        let at = self.start + self.len;
        if at >= list.reserved {
            match list.reserve(&mut writer.chunk, at + 1) {
                Ok(validity) => column.validity = validity,
                Err(error) => {
                    writer.error.get_or_insert(error);
                    self.failed = true;
                    return None;
                }
            }
        }
        self.len += 1;
        Some((at, list))
    }

    /// Store a VARCHAR or BLOB item; `text` says which the caller has.
    #[inline(always)]
    fn bytes_item(&mut self, value: &[u8], text: bool) {
        let column = self.column;
        let Some((at, list)) = self.item() else {
            return;
        };
        let bytes = match (&list.items, text) {
            (Items::Str(bytes), true) | (Items::Blob(bytes), false) => bytes,
            _ => item_mismatch(column, if text { "str" } else { "bytes" }),
        };
        // SAFETY: `item` made `at < reserved`, the size of the child (invariant 2), whose
        // current storage `bytes` and `item_validity` are (invariant 3); the value is UTF-8
        // when the child is a VARCHAR, since `text` is only set by `str`.
        if let Err(error) = unsafe { bytes.put(list.item_validity, at, value) } {
            self.writer.error.get_or_insert(error);
        }
    }
}

impl ListSink for ChunkList<'_, '_> {
    #[inline]
    fn null(&mut self) {
        if let Some((at, list)) = self.item() {
            // SAFETY: `item` made `at < reserved`, the size of the child (invariant 2), whose
            // mask `item_validity` is (invariant 3); the slot is initialised (invariant 4).
            unsafe { mark_null(list.item_validity, at) }
        }
    }

    #[inline]
    fn u16(&mut self, v: u16) {
        let column = self.column;
        let Some((at, list)) = self.item() else {
            return;
        };
        let Items::U16(data) = list.items else {
            item_mismatch(column, "u16")
        };
        // SAFETY: `item` made `at < reserved`, the size of the child (invariant 2); `data` and
        // `item_validity` are its current pointers (invariant 3) and it stores `u16`
        // (invariant 1).
        unsafe { put(data, list.item_validity, at, v) }
    }

    #[inline]
    fn u32(&mut self, v: u32) {
        let column = self.column;
        let Some((at, list)) = self.item() else {
            return;
        };
        let Items::U32(data) = list.items else {
            item_mismatch(column, "u32")
        };
        // SAFETY: as for `u16`, for a child that stores `u32`.
        unsafe { put(data, list.item_validity, at, v) }
    }

    #[inline]
    fn str(&mut self, v: &str) {
        self.bytes_item(v.as_bytes(), true);
    }

    #[inline]
    fn bytes(&mut self, v: &[u8]) {
        self.bytes_item(v, false);
    }

    #[inline]
    fn finish(self) {
        let column = &mut self.writer.columns[self.column];
        let Data::List(list) = &mut column.data else {
            unreachable!("list() checked that the column is a list")
        };
        if self.failed {
            // SAFETY: `list()` checked `row < limit`, the size of this vector (invariant 2),
            // whose mask `validity` is (invariant 3).
            unsafe { mark_null(column.validity, self.row) };
            return;
        }
        let entry = ListIndex::new(self.start as u64, self.len as u64);
        // SAFETY: `list()` checked `row < limit`, the size of this vector (invariant 2);
        // `entries` and `validity` are its current pointers (invariant 3) and a LIST vector
        // stores a `ListIndex` per row (invariant 1). The entry covers items below `reserved`,
        // each written or zero-filled (invariant 4).
        unsafe { put(list.entries, column.validity, self.row, entry) };
        list.used = self.start + self.len;
    }
}
