//! The Arrow row sink: stores the rows of one output of a scan in Arrow
//! builders and hands them on as record batches.
//!
//! What a cell holds is decided in `pcapsql_core::scan` (`write_value` and
//! the row writers), which is shared with every other frontend; this file
//! only stores values that already have their column's kind.

use std::ops::ControlFlow;
use std::sync::Arc;

use arrow::array::{
    Array, ArrayRef, AsArray, BinaryBuilder, BooleanBuilder, FixedSizeBinaryBuilder,
    Float64Builder, Int64Builder, Int8Builder, ListBuilder, StringBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow::datatypes::{SchemaRef, TimestampMicrosecondType, TimestampNanosecondType};
use arrow::record_batch::{RecordBatch, RecordBatchOptions};

use crate::error::{Error, QueryError};
use crate::query::arrow_schema::{col_kind_to_arrow_type, out_columns_to_arrow_schema};
use pcapsql_core::scan::{ColKind, Full, ListSink, OutCol, OutColumn, RowSink};

/// Which of the sink's builder vectors holds a column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Store {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I64,
    F64,
    Str,
    Bin,
    Fixed,
    TsMicros,
    TsNanos,
    List,
}

/// Where a column's builder is: the vector of its type, and its index
/// there.
#[derive(Clone, Copy, Debug)]
struct Slot {
    store: Store,
    index: u16,
}

/// The builder of a list column.
#[derive(Debug)]
enum ListColumn {
    U16(ListBuilder<UInt16Builder>),
    U32(ListBuilder<UInt32Builder>),
    Str(ListBuilder<StringBuilder>),
    Fixed(ListBuilder<FixedSizeBinaryBuilder>),
}

/// A [`RowSink`] over Arrow builders: the rows of one output of a scan,
/// taken out as [`RecordBatch`]es of at most `capacity` rows.
///
/// The builders are kept in one vector per Arrow type, with a map from the
/// output column to its place there, so that storing a value is an indexed
/// append with no dispatch on the column's type.
///
/// A builder gives its buffers away with its batch (Arrow's `finish` leaves
/// it empty, without capacity). After a full batch each builder is therefore
/// replaced by one with room for the next: `capacity` rows, and for the
/// bytes of text and binary values and the items of lists what the batch
/// just taken held plus an eighth (see [`next_capacity`]), so that a batch
/// like the last one is built without growing a buffer. After a batch that
/// is not full (the last of a scan, a row cap, a timed flush) nothing is
/// allocated ahead.
///
/// `end_row` reports [`Full`] when the sink holds `capacity` rows;
/// [`take_batch`](Self::take_batch) empties it.
#[derive(Debug)]
pub struct ArrowSink {
    schema: SchemaRef,
    capacity: usize,
    rows: usize,
    slots: Box<[Slot]>,
    bools: Vec<BooleanBuilder>,
    u8s: Vec<UInt8Builder>,
    u16s: Vec<UInt16Builder>,
    u32s: Vec<UInt32Builder>,
    u64s: Vec<UInt64Builder>,
    i8s: Vec<Int8Builder>,
    i64s: Vec<Int64Builder>,
    f64s: Vec<Float64Builder>,
    strs: Vec<StringBuilder>,
    bins: Vec<BinaryBuilder>,
    fixed: Vec<FixedSizeBinaryBuilder>,
    /// Timestamps of either unit, as their integer.
    timestamps: Vec<Int64Builder>,
    lists: Vec<ListColumn>,
}

/// The capacity, in value bytes or list items, of the builder that follows
/// one whose batch held `used`: an eighth more, so that the usual variation
/// between batches does not double the buffer, and little enough that a
/// batch kept in memory is not much larger than its values.
fn next_capacity(used: usize) -> usize {
    used + used / 8
}

fn push<B>(builders: &mut Vec<B>, builder: B) -> u16 {
    builders.push(builder);
    (builders.len() - 1) as u16
}

impl ArrowSink {
    /// A sink for an output with these columns
    /// (`OutputPlan::columns`), full at `capacity` rows (at least one). Its
    /// batches have the schema
    /// [`out_columns_to_arrow_schema`] derives from the columns.
    pub fn new(columns: &[OutColumn], capacity: usize) -> Self {
        Self::with_schema(
            Arc::new(out_columns_to_arrow_schema(columns)),
            columns,
            capacity,
        )
    }

    /// [`new`](Self::new) with the schema the batches carry, which must be
    /// the one [`out_columns_to_arrow_schema`] derives from `columns` (the
    /// same `Arc` can then be shared by every partition's batches).
    pub fn with_schema(schema: SchemaRef, columns: &[OutColumn], capacity: usize) -> Self {
        debug_assert_eq!(schema.fields().len(), columns.len());
        debug_assert!(schema
            .fields()
            .iter()
            .zip(columns)
            .all(|(field, column)| *field.data_type() == col_kind_to_arrow_type(column.kind)));
        let capacity = capacity.max(1);
        let mut sink = Self {
            schema,
            capacity,
            rows: 0,
            slots: Box::default(),
            bools: Vec::new(),
            u8s: Vec::new(),
            u16s: Vec::new(),
            u32s: Vec::new(),
            u64s: Vec::new(),
            i8s: Vec::new(),
            i64s: Vec::new(),
            f64s: Vec::new(),
            strs: Vec::new(),
            bins: Vec::new(),
            fixed: Vec::new(),
            timestamps: Vec::new(),
            lists: Vec::new(),
        };
        let n = capacity;
        let fixed = |width: u16| FixedSizeBinaryBuilder::with_capacity(n, i32::from(width));
        sink.slots = columns
            .iter()
            .map(|column| {
                let (store, index) = match column.kind {
                    ColKind::Bool => (
                        Store::Bool,
                        push(&mut sink.bools, BooleanBuilder::with_capacity(n)),
                    ),
                    ColKind::U8 => (
                        Store::U8,
                        push(&mut sink.u8s, UInt8Builder::with_capacity(n)),
                    ),
                    ColKind::U16 => (
                        Store::U16,
                        push(&mut sink.u16s, UInt16Builder::with_capacity(n)),
                    ),
                    ColKind::U32 => (
                        Store::U32,
                        push(&mut sink.u32s, UInt32Builder::with_capacity(n)),
                    ),
                    ColKind::U64 => (
                        Store::U64,
                        push(&mut sink.u64s, UInt64Builder::with_capacity(n)),
                    ),
                    ColKind::I8 => (
                        Store::I8,
                        push(&mut sink.i8s, Int8Builder::with_capacity(n)),
                    ),
                    ColKind::I64 => (
                        Store::I64,
                        push(&mut sink.i64s, Int64Builder::with_capacity(n)),
                    ),
                    ColKind::F64 => (
                        Store::F64,
                        push(&mut sink.f64s, Float64Builder::with_capacity(n)),
                    ),
                    ColKind::Str => (
                        Store::Str,
                        push(&mut sink.strs, StringBuilder::with_capacity(n, n * 32)),
                    ),
                    ColKind::Bin => (
                        Store::Bin,
                        push(&mut sink.bins, BinaryBuilder::with_capacity(n, n * 64)),
                    ),
                    ColKind::Fixed(width) => (Store::Fixed, push(&mut sink.fixed, fixed(width))),
                    ColKind::TsMicros => (
                        Store::TsMicros,
                        push(&mut sink.timestamps, Int64Builder::with_capacity(n)),
                    ),
                    ColKind::TsNanos => (
                        Store::TsNanos,
                        push(&mut sink.timestamps, Int64Builder::with_capacity(n)),
                    ),
                    ColKind::ListU16 => (
                        Store::List,
                        push(
                            &mut sink.lists,
                            ListColumn::U16(ListBuilder::with_capacity(
                                UInt16Builder::with_capacity(n),
                                n,
                            )),
                        ),
                    ),
                    ColKind::ListU32 => (
                        Store::List,
                        push(
                            &mut sink.lists,
                            ListColumn::U32(ListBuilder::with_capacity(
                                UInt32Builder::with_capacity(n),
                                n,
                            )),
                        ),
                    ),
                    ColKind::ListStr => (
                        Store::List,
                        push(
                            &mut sink.lists,
                            ListColumn::Str(ListBuilder::with_capacity(
                                StringBuilder::with_capacity(n, n * 32),
                                n,
                            )),
                        ),
                    ),
                    ColKind::ListFixed(width) => (
                        Store::List,
                        push(
                            &mut sink.lists,
                            ListColumn::Fixed(ListBuilder::with_capacity(fixed(width), n)),
                        ),
                    ),
                };
                Slot { store, index }
            })
            .collect();
        sink
    }

    /// The schema of the batches.
    pub fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    /// The number of complete rows held.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// True when the sink holds as many rows as a batch takes.
    pub fn is_full(&self) -> bool {
        self.rows >= self.capacity
    }

    /// Take the rows held as a batch, leaving the sink empty; `None` when it
    /// holds none. A sink without columns (`SELECT count(*)`) gives a batch
    /// that carries only its row count.
    ///
    /// After a full batch the builders have room for the next; after any
    /// other they hold no memory.
    pub fn take_batch(&mut self) -> Result<Option<RecordBatch>, Error> {
        if self.rows == 0 {
            return Ok(None);
        }
        let options = RecordBatchOptions::new().with_row_count(Some(self.rows));
        // A batch that is not full is the last of its scan, or one of a feed
        // slow enough to be flushed by time: no next batch to prepare for.
        let refill = self.rows >= self.capacity;
        self.rows = 0;
        let arrays = self.finish_arrays(refill);
        RecordBatch::try_new_with_options(Arc::clone(&self.schema), arrays, &options)
            .map(Some)
            .map_err(|e| Error::Query(QueryError::Arrow(e.to_string())))
    }

    /// The columns' values so far as arrays, in column order, leaving every
    /// builder empty: with room for a batch like this one with `refill`,
    /// without capacity otherwise.
    pub(crate) fn finish_arrays(&mut self, refill: bool) -> Vec<ArrayRef> {
        let n = self.capacity;
        let mut arrays = Vec::with_capacity(self.slots.len());
        // Finish a builder whose only capacity is its rows.
        macro_rules! finish {
            ($builders:expr, $i:expr, $new:expr) => {{
                let array = $builders[$i].finish();
                if refill {
                    $builders[$i] = $new;
                }
                array
            }};
        }
        for slot in self.slots.iter() {
            let i = usize::from(slot.index);
            let array: ArrayRef = match slot.store {
                Store::Bool => Arc::new(finish!(self.bools, i, BooleanBuilder::with_capacity(n))),
                Store::U8 => Arc::new(finish!(self.u8s, i, UInt8Builder::with_capacity(n))),
                Store::U16 => Arc::new(finish!(self.u16s, i, UInt16Builder::with_capacity(n))),
                Store::U32 => Arc::new(finish!(self.u32s, i, UInt32Builder::with_capacity(n))),
                Store::U64 => Arc::new(finish!(self.u64s, i, UInt64Builder::with_capacity(n))),
                Store::I8 => Arc::new(finish!(self.i8s, i, Int8Builder::with_capacity(n))),
                Store::I64 => Arc::new(finish!(self.i64s, i, Int64Builder::with_capacity(n))),
                Store::F64 => Arc::new(finish!(self.f64s, i, Float64Builder::with_capacity(n))),
                Store::Str => {
                    let array = self.strs[i].finish();
                    if refill {
                        let bytes = next_capacity(array.value_data().len());
                        self.strs[i] = StringBuilder::with_capacity(n, bytes);
                    }
                    Arc::new(array)
                }
                Store::Bin => {
                    let array = self.bins[i].finish();
                    if refill {
                        let bytes = next_capacity(array.value_data().len());
                        self.bins[i] = BinaryBuilder::with_capacity(n, bytes);
                    }
                    Arc::new(array)
                }
                Store::Fixed => {
                    let array = self.fixed[i].finish();
                    if refill {
                        self.fixed[i] =
                            FixedSizeBinaryBuilder::with_capacity(n, array.value_length());
                    }
                    Arc::new(array)
                }
                Store::TsMicros => Arc::new(
                    finish!(self.timestamps, i, Int64Builder::with_capacity(n))
                        .reinterpret_cast::<TimestampMicrosecondType>(),
                ),
                Store::TsNanos => Arc::new(
                    finish!(self.timestamps, i, Int64Builder::with_capacity(n))
                        .reinterpret_cast::<TimestampNanosecondType>(),
                ),
                Store::List => {
                    let column = &mut self.lists[i];
                    let array = match column {
                        ListColumn::U16(b) => b.finish(),
                        ListColumn::U32(b) => b.finish(),
                        ListColumn::Str(b) => b.finish(),
                        ListColumn::Fixed(b) => b.finish(),
                    };
                    if refill {
                        // The items of the batch's lists, and so of the
                        // next one's.
                        let items = next_capacity(array.values().len());
                        *column = match column {
                            ListColumn::U16(_) => ListColumn::U16(ListBuilder::with_capacity(
                                UInt16Builder::with_capacity(items),
                                n,
                            )),
                            ListColumn::U32(_) => ListColumn::U32(ListBuilder::with_capacity(
                                UInt32Builder::with_capacity(items),
                                n,
                            )),
                            ListColumn::Str(_) => {
                                let bytes = next_capacity(
                                    array.values().as_string::<i32>().value_data().len(),
                                );
                                ListColumn::Str(ListBuilder::with_capacity(
                                    StringBuilder::with_capacity(items, bytes),
                                    n,
                                ))
                            }
                            ListColumn::Fixed(_) => {
                                let width = array.values().as_fixed_size_binary().value_length();
                                ListColumn::Fixed(ListBuilder::with_capacity(
                                    FixedSizeBinaryBuilder::with_capacity(items, width),
                                    n,
                                ))
                            }
                        };
                    }
                    Arc::new(array)
                }
            };
            arrays.push(array);
        }
        arrays
    }

    /// The index of `col`'s builder in the vector of its type.
    #[inline]
    fn at(&self, col: OutCol) -> usize {
        usize::from(self.slots[usize::from(col.0)].index)
    }
}

impl RowSink for ArrowSink {
    #[inline]
    fn null(&mut self, col: OutCol) {
        let slot = self.slots[usize::from(col.0)];
        let i = usize::from(slot.index);
        match slot.store {
            Store::Bool => self.bools[i].append_null(),
            Store::U8 => self.u8s[i].append_null(),
            Store::U16 => self.u16s[i].append_null(),
            Store::U32 => self.u32s[i].append_null(),
            Store::U64 => self.u64s[i].append_null(),
            Store::I8 => self.i8s[i].append_null(),
            Store::I64 => self.i64s[i].append_null(),
            Store::F64 => self.f64s[i].append_null(),
            Store::Str => self.strs[i].append_null(),
            Store::Bin => self.bins[i].append_null(),
            Store::Fixed => self.fixed[i].append_null(),
            Store::TsMicros | Store::TsNanos => self.timestamps[i].append_null(),
            Store::List => match &mut self.lists[i] {
                ListColumn::U16(b) => b.append_null(),
                ListColumn::U32(b) => b.append_null(),
                ListColumn::Str(b) => b.append_null(),
                ListColumn::Fixed(b) => b.append_null(),
            },
        }
    }

    #[inline]
    fn bool(&mut self, col: OutCol, v: bool) {
        let i = self.at(col);
        self.bools[i].append_value(v);
    }

    #[inline]
    fn u8(&mut self, col: OutCol, v: u8) {
        let i = self.at(col);
        self.u8s[i].append_value(v);
    }

    #[inline]
    fn u16(&mut self, col: OutCol, v: u16) {
        let i = self.at(col);
        self.u16s[i].append_value(v);
    }

    #[inline]
    fn u32(&mut self, col: OutCol, v: u32) {
        let i = self.at(col);
        self.u32s[i].append_value(v);
    }

    #[inline]
    fn u64(&mut self, col: OutCol, v: u64) {
        let i = self.at(col);
        self.u64s[i].append_value(v);
    }

    #[inline]
    fn i8(&mut self, col: OutCol, v: i8) {
        let i = self.at(col);
        self.i8s[i].append_value(v);
    }

    #[inline]
    fn i64(&mut self, col: OutCol, v: i64) {
        let i = self.at(col);
        self.i64s[i].append_value(v);
    }

    #[inline]
    fn f64(&mut self, col: OutCol, v: f64) {
        let i = self.at(col);
        self.f64s[i].append_value(v);
    }

    #[inline]
    fn str(&mut self, col: OutCol, v: &str) {
        let i = self.at(col);
        self.strs[i].append_value(v);
    }

    #[inline]
    fn bytes(&mut self, col: OutCol, v: &[u8]) {
        let i = self.at(col);
        self.bins[i].append_value(v);
    }

    #[inline]
    fn fixed(&mut self, col: OutCol, v: &[u8]) {
        let i = self.at(col);
        // The length was checked by the caller; should it be wrong all the
        // same, the cell is NULL rather than missing.
        if self.fixed[i].append_value(v).is_err() {
            self.fixed[i].append_null();
        }
    }

    #[inline]
    fn timestamp(&mut self, col: OutCol, v: i64) {
        let i = self.at(col);
        self.timestamps[i].append_value(v);
    }

    type List<'s> = ArrowList<'s>;

    #[inline]
    fn list(&mut self, col: OutCol) -> ArrowList<'_> {
        let i = self.at(col);
        match &mut self.lists[i] {
            ListColumn::U16(b) => ArrowList::U16(b),
            ListColumn::U32(b) => ArrowList::U32(b),
            ListColumn::Str(b) => ArrowList::Str(b),
            ListColumn::Fixed(b) => ArrowList::Fixed(b),
        }
    }

    #[inline]
    fn end_row(&mut self) -> ControlFlow<Full> {
        self.rows += 1;
        if self.rows >= self.capacity {
            ControlFlow::Break(Full)
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// The writer of one list cell of an [`ArrowSink`]. An item of another type
/// than the list's is stored as a NULL item.
#[derive(Debug)]
pub enum ArrowList<'s> {
    #[doc(hidden)]
    U16(&'s mut ListBuilder<UInt16Builder>),
    #[doc(hidden)]
    U32(&'s mut ListBuilder<UInt32Builder>),
    #[doc(hidden)]
    Str(&'s mut ListBuilder<StringBuilder>),
    #[doc(hidden)]
    Fixed(&'s mut ListBuilder<FixedSizeBinaryBuilder>),
}

impl ListSink for ArrowList<'_> {
    #[inline]
    fn null(&mut self) {
        match self {
            ArrowList::U16(b) => b.values().append_null(),
            ArrowList::U32(b) => b.values().append_null(),
            ArrowList::Str(b) => b.values().append_null(),
            ArrowList::Fixed(b) => b.values().append_null(),
        }
    }

    #[inline]
    fn u16(&mut self, v: u16) {
        match self {
            ArrowList::U16(b) => b.values().append_value(v),
            _ => self.null(),
        }
    }

    #[inline]
    fn u32(&mut self, v: u32) {
        match self {
            ArrowList::U32(b) => b.values().append_value(v),
            _ => self.null(),
        }
    }

    #[inline]
    fn str(&mut self, v: &str) {
        match self {
            ArrowList::Str(b) => b.values().append_value(v),
            _ => self.null(),
        }
    }

    #[inline]
    fn bytes(&mut self, v: &[u8]) {
        match self {
            ArrowList::Fixed(b) => {
                if b.values().append_value(v).is_err() {
                    b.values().append_null();
                }
            }
            _ => self.null(),
        }
    }

    #[inline]
    fn finish(self) {
        match self {
            ArrowList::U16(b) => b.append(true),
            ArrowList::U32(b) => b.append(true),
            ArrowList::Str(b) => b.append(true),
            ArrowList::Fixed(b) => b.append(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{
        Array, AsArray, BinaryArray, BooleanArray, FixedSizeBinaryArray, Float64Array, Int64Array,
        Int8Array, ListArray, StringArray, TimestampMicrosecondArray, TimestampNanosecondArray,
        UInt16Array, UInt32Array, UInt64Array, UInt8Array,
    };
    use arrow::datatypes::{DataType, UInt64Type};
    use pcapsql_core::io::PacketRef;
    use pcapsql_core::scan::testing::{run_conformance, Cell, SinkHarness};
    use pcapsql_core::scan::{
        write_frame_row, write_layer_row, write_value, Catalog, ColumnSource, FieldResolver,
        ScanPlan, TableScan,
    };
    use pcapsql_core::{FieldValue, ParseResult, TunnelType};
    use smallvec::SmallVec;

    const COL: OutCol = OutCol(0);

    fn column(kind: ColKind) -> OutColumn {
        OutColumn {
            name: "c",
            kind,
            nullable: true,
            source: ColumnSource::Field("c"),
        }
    }

    /// A sink of one nullable column of `kind`.
    fn one_column(kind: ColKind, capacity: usize) -> ArrowSink {
        ArrowSink::new(&[column(kind)], capacity)
    }

    /// The output columns of `table` as a compiled plan resolves them:
    /// `columns` by name, or every default column.
    fn table_columns(table: &str, columns: Option<&[&str]>) -> Vec<OutColumn> {
        let catalog = Catalog::builtin();
        let (id, def) = catalog.table(table).unwrap();
        let ids = match columns {
            Some(names) => names.iter().map(|n| def.column(n).unwrap().0).collect(),
            None => def.default_columns().map(|(id, _)| id).collect(),
        };
        let plan = ScanPlan {
            tables: vec![TableScan::new(id, ids)],
            ..Default::default()
        };
        let compiled = plan
            .compile(catalog, &pcapsql_core::default_registry())
            .unwrap();
        compiled.outputs()[0].columns.to_vec()
    }

    /// The cell at `row` of `array`, a column of kind `kind`.
    fn cell(array: &dyn Array, kind: ColKind, row: usize) -> Cell {
        if array.is_null(row) {
            return Cell::Null;
        }
        macro_rules! value {
            ($array:ty) => {
                array.as_any().downcast_ref::<$array>().unwrap().value(row)
            };
        }
        let item_kind = match kind {
            ColKind::ListU16 => ColKind::U16,
            ColKind::ListU32 => ColKind::U32,
            ColKind::ListStr => ColKind::Str,
            ColKind::ListFixed(n) => ColKind::Fixed(n),
            ColKind::Bool => return Cell::Bool(value!(BooleanArray)),
            ColKind::U8 => return Cell::U8(value!(UInt8Array)),
            ColKind::U16 => return Cell::U16(value!(UInt16Array)),
            ColKind::U32 => return Cell::U32(value!(UInt32Array)),
            ColKind::U64 => return Cell::U64(value!(UInt64Array)),
            ColKind::I8 => return Cell::I8(value!(Int8Array)),
            ColKind::I64 => return Cell::I64(value!(Int64Array)),
            ColKind::F64 => return Cell::F64(value!(Float64Array)),
            ColKind::Str => return Cell::Str(value!(StringArray).to_string()),
            ColKind::Bin => return Cell::Bytes(value!(BinaryArray).to_vec()),
            ColKind::Fixed(_) => return Cell::Bytes(value!(FixedSizeBinaryArray).to_vec()),
            ColKind::TsMicros => return Cell::Timestamp(value!(TimestampMicrosecondArray)),
            ColKind::TsNanos => return Cell::Timestamp(value!(TimestampNanosecondArray)),
        };
        let items = value!(ListArray);
        Cell::List(
            (0..items.len())
                .map(|i| cell(items.as_ref(), item_kind, i))
                .collect(),
        )
    }

    /// A batch as engine-neutral cells, checking it against its columns.
    fn batch_cells(batch: &RecordBatch, columns: &[OutColumn]) -> Vec<Vec<Cell>> {
        assert_eq!(batch.num_columns(), columns.len());
        for (array, column) in batch.columns().iter().zip(columns) {
            assert_eq!(*array.data_type(), col_kind_to_arrow_type(column.kind));
        }
        (0..batch.num_rows())
            .map(|row| {
                batch
                    .columns()
                    .iter()
                    .zip(columns)
                    .map(|(array, column)| cell(array.as_ref(), column.kind, row))
                    .collect()
            })
            .collect()
    }

    struct ArrowHarness {
        /// The columns of the sink under test (one sink at a time).
        columns: Vec<OutColumn>,
        capacity: usize,
    }

    impl SinkHarness for ArrowHarness {
        type Sink = ArrowSink;

        fn new_sink(&mut self, columns: &[OutColumn], capacity: usize) -> ArrowSink {
            self.columns = columns.to_vec();
            self.capacity = capacity;
            ArrowSink::new(columns, capacity)
        }

        fn drain(&mut self, sink: &mut ArrowSink) -> Vec<Vec<Cell>> {
            let held = sink.rows();
            assert!(held <= self.capacity, "the sink holds more than a batch");
            assert_eq!(sink.is_full(), held == self.capacity);
            let cells = match sink.take_batch().expect("the batch builds") {
                Some(batch) => {
                    assert_eq!(batch.schema(), *sink.schema());
                    batch_cells(&batch, &self.columns)
                }
                None => Vec::new(),
            };
            assert_eq!(cells.len(), held);
            assert_eq!(sink.rows(), 0);
            cells
        }
    }

    #[test]
    fn arrow_sink_conforms() {
        run_conformance(&mut ArrowHarness {
            columns: Vec::new(),
            capacity: 0,
        });
    }

    /// Every column of every table is stored in the Arrow type its schema
    /// declares.
    #[test]
    fn every_table_column_is_built_in_its_schema_type() {
        for name in crate::query::tables::all_table_names() {
            let schema = crate::query::tables::get_table_schema(name).expect("schema");
            let (_, table) = Catalog::builtin().table(name).unwrap();
            let columns: Vec<OutColumn> = table
                .default_columns()
                .map(|(_, def)| OutColumn {
                    name: def.name,
                    kind: def.kind,
                    nullable: def.nullable,
                    source: def.source,
                })
                .collect();
            let mut sink = ArrowSink::new(&columns, 1);
            assert_eq!(sink.schema().as_ref(), &schema, "{name}");
            // The builders the sink starts with, and the ones that replace
            // them after a full batch.
            for refill in [true, false] {
                let arrays = sink.finish_arrays(refill);
                assert_eq!(arrays.len(), schema.fields().len(), "{name}");
                for (array, field) in arrays.iter().zip(schema.fields()) {
                    assert_eq!(
                        array.data_type(),
                        field.data_type(),
                        "{name}.{}",
                        field.name()
                    );
                }
            }
        }
    }

    /// The builders that replace the ones a full batch took hold the same
    /// cells: rows written through a sink of two rows a batch are the rows
    /// of a sink that holds them all, for every kind of column.
    #[test]
    fn batches_after_the_first_hold_the_same_cells() {
        let kinds = [
            ColKind::Bool,
            ColKind::U8,
            ColKind::U16,
            ColKind::U32,
            ColKind::U64,
            ColKind::I8,
            ColKind::I64,
            ColKind::F64,
            ColKind::Str,
            ColKind::Bin,
            ColKind::Fixed(6),
            ColKind::TsMicros,
            ColKind::TsNanos,
            ColKind::ListU16,
            ColKind::ListU32,
            ColKind::ListStr,
            ColKind::ListFixed(4),
        ];
        let columns: Vec<OutColumn> = kinds.iter().map(|kind| column(*kind)).collect();
        // Row `row` of every column; every third row of a column is NULL,
        // and text, bytes and lists grow with the row.
        fn write_row(sink: &mut ArrowSink, kinds: &[ColKind], row: usize) -> ControlFlow<Full> {
            for (index, kind) in kinds.iter().enumerate() {
                let col = OutCol(index as u16);
                if (row + index).is_multiple_of(3) {
                    sink.null(col);
                    continue;
                }
                let text = "x".repeat(row * 7);
                let bytes = vec![row as u8; row * 5];
                match *kind {
                    ColKind::Bool => sink.bool(col, row.is_multiple_of(2)),
                    ColKind::U8 => sink.u8(col, row as u8),
                    ColKind::U16 => sink.u16(col, row as u16),
                    ColKind::U32 => sink.u32(col, row as u32),
                    ColKind::U64 => sink.u64(col, row as u64),
                    ColKind::I8 => sink.i8(col, -(row as i8)),
                    ColKind::I64 => sink.i64(col, -(row as i64)),
                    ColKind::F64 => sink.f64(col, row as f64 / 2.0),
                    ColKind::Str => sink.str(col, &text),
                    ColKind::Bin => sink.bytes(col, &bytes),
                    ColKind::Fixed(width) => sink.fixed(col, &vec![row as u8; usize::from(width)]),
                    ColKind::TsMicros | ColKind::TsNanos => sink.timestamp(col, row as i64),
                    ColKind::ListU16
                    | ColKind::ListU32
                    | ColKind::ListStr
                    | ColKind::ListFixed(_) => {
                        let mut list = sink.list(col);
                        for item in 0..row {
                            match *kind {
                                ColKind::ListU16 => list.u16(item as u16),
                                ColKind::ListU32 => list.u32(item as u32),
                                ColKind::ListStr => list.str(&text[..item]),
                                _ => list.bytes(&[item as u8; 4]),
                            }
                        }
                        list.finish();
                    }
                }
            }
            sink.end_row()
        }

        const ROWS: usize = 9;
        let mut whole = ArrowSink::new(&columns, ROWS + 1);
        let mut paged = ArrowSink::new(&columns, 2);
        let mut batches = Vec::new();
        for row in 0..ROWS {
            assert!(write_row(&mut whole, &kinds, row).is_continue());
            if write_row(&mut paged, &kinds, row).is_break() {
                batches.push(paged.take_batch().unwrap().unwrap());
            }
        }
        batches.extend(paged.take_batch().unwrap());
        assert_eq!(
            batches.iter().map(|b| b.num_rows()).collect::<Vec<_>>(),
            [2, 2, 2, 2, 1]
        );
        let whole = whole.take_batch().unwrap().unwrap();
        let paged = arrow::compute::concat_batches(paged.schema(), &batches).unwrap();
        assert_eq!(paged, whole);
        assert_eq!(batch_cells(&paged, &columns), batch_cells(&whole, &columns));
    }

    /// After a full batch the builders have room for a batch like it, so
    /// the next one's buffers are the ones allocated then; after a batch
    /// that is not full nothing is held.
    #[test]
    fn builders_are_sized_from_the_batch_taken() {
        let mut sink = one_column(ColKind::Bin, 4);
        let value = [0xABu8; 1000];
        for _ in 0..4 {
            let _ = {
                sink.bytes(COL, &value);
                sink.end_row()
            };
        }
        sink.take_batch().unwrap().unwrap();
        // 4000 bytes held, so room for 4500: more than the 4 * 64 a new
        // sink guesses.
        for _ in 0..4 {
            sink.bytes(COL, &value);
            let _ = sink.end_row();
        }
        let batch = sink.take_batch().unwrap().unwrap();
        let held = batch.column(0).as_binary::<i32>().values().capacity();
        assert!((4500..5000).contains(&held), "{held}");

        // A batch that is not full: no room is kept for another.
        sink.bytes(COL, &value);
        let _ = sink.end_row();
        sink.take_batch().unwrap().unwrap();
        sink.bytes(COL, &[1]);
        let _ = sink.end_row();
        let batch = sink.take_batch().unwrap().unwrap();
        let held = batch.column(0).as_binary::<i32>().values().capacity();
        assert!(held <= 1024, "{held}");
    }

    /// What each column type stores for each kind of `FieldValue`, one line
    /// per pair.
    fn coercion_table() -> String {
        use arrow::util::display::{ArrayFormatter, FormatOptions};
        use std::net::IpAddr;

        let columns = [
            ("UInt8", ColKind::U8),
            ("UInt16", ColKind::U16),
            ("UInt32", ColKind::U32),
            ("UInt64", ColKind::U64),
            ("Int8", ColKind::I8),
            ("Int64", ColKind::I64),
            ("Float64", ColKind::F64),
            ("Boolean", ColKind::Bool),
            ("Utf8", ColKind::Str),
            ("Binary", ColKind::Bin),
            ("FixedSizeBinary(6)", ColKind::Fixed(6)),
            ("FixedSizeBinary(16)", ColKind::Fixed(16)),
            ("Timestamp(us)", ColKind::TsMicros),
            ("List<UInt16>", ColKind::ListU16),
            ("List<UInt32>", ColKind::ListU32),
            ("List<Utf8>", ColKind::ListStr),
            ("List<FixedSizeBinary(16)>", ColKind::ListFixed(16)),
        ];

        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        let b3: &[u8] = &[1, 2, 3];
        let b6: &[u8] = &[1, 2, 3, 4, 5, 6];
        let b16: &[u8] = &[0xAA; 16];
        let values = [
            ("Null", FieldValue::Null),
            ("Bool(true)", FieldValue::Bool(true)),
            ("UInt8(7)", FieldValue::UInt8(7)),
            ("UInt16(7)", FieldValue::UInt16(7)),
            ("UInt16(300)", FieldValue::UInt16(300)),
            ("UInt32(7)", FieldValue::UInt32(7)),
            ("UInt32(70000)", FieldValue::UInt32(70_000)),
            ("UInt32(3000000000)", FieldValue::UInt32(3_000_000_000)),
            ("UInt64(7)", FieldValue::UInt64(7)),
            ("UInt64(5000000000)", FieldValue::UInt64(5_000_000_000)),
            ("UInt64(MAX)", FieldValue::UInt64(u64::MAX)),
            ("Int8(-3)", FieldValue::Int8(-3)),
            ("Int64(7)", FieldValue::Int64(7)),
            ("Int64(-5)", FieldValue::Int64(-5)),
            ("Int64(5000000000)", FieldValue::Int64(5_000_000_000)),
            ("Float64(1.5)", FieldValue::Float64(1.5)),
            ("Str(abc)", FieldValue::Str("abc")),
            ("OwnedString(xyz)", FieldValue::OwnedString("xyz".into())),
            ("Bytes(3)", FieldValue::Bytes(b3)),
            ("Bytes(6)", FieldValue::Bytes(b6)),
            ("Bytes(16)", FieldValue::Bytes(b16)),
            ("OwnedBytes(6)", FieldValue::OwnedBytes(b6.to_vec())),
            ("IpAddr(v4)", FieldValue::IpAddr(v4)),
            ("IpAddr(v6)", FieldValue::IpAddr(v6)),
            ("MacAddr", FieldValue::MacAddr(mac)),
            ("List[]", FieldValue::List(vec![])),
            ("List[Null]", FieldValue::List(vec![FieldValue::Null])),
            (
                "List[UInt8(1), UInt16(2), UInt32(3), UInt64(4)]",
                FieldValue::List(vec![
                    FieldValue::UInt8(1),
                    FieldValue::UInt16(2),
                    FieldValue::UInt32(3),
                    FieldValue::UInt64(4),
                ]),
            ),
            (
                "List[Str(a), OwnedString(b), UInt16(5)]",
                FieldValue::List(vec![
                    FieldValue::Str("a"),
                    FieldValue::OwnedString("b".into()),
                    FieldValue::UInt16(5),
                ]),
            ),
            (
                "List[Bytes(3), Bytes(16), OwnedBytes(6)]",
                FieldValue::List(vec![
                    FieldValue::Bytes(b3),
                    FieldValue::Bytes(b16),
                    FieldValue::OwnedBytes(b6.to_vec()),
                ]),
            ),
            (
                "List[IpAddr(v4), IpAddr(v6), MacAddr]",
                FieldValue::List(vec![
                    FieldValue::IpAddr(v4),
                    FieldValue::IpAddr(v6),
                    FieldValue::MacAddr(mac),
                ]),
            ),
        ];

        let options = FormatOptions::default().with_null("NULL");
        let mut out = String::new();
        for (label, kind) in &columns {
            for (value_label, value) in &values {
                let mut sink = one_column(*kind, 1);
                write_value(&mut sink, COL, *kind, value);
                assert!(sink.end_row().is_break());
                // The batch builds: every value leaves exactly one cell.
                let batch = sink.take_batch().unwrap().unwrap();
                assert_eq!(batch.num_rows(), 1);
                let cell = ArrayFormatter::try_new(batch.column(0).as_ref(), &options)
                    .unwrap()
                    .value(0)
                    .to_string();
                out.push_str(&format!("{label} <- {value_label} = {cell}\n"));
            }
        }
        out
    }

    /// The value each column type stores for each kind of `FieldValue` is
    /// part of the tables' contract. The rules are `pcapsql_core`'s
    /// (`scan::write_value`), shared by every frontend; this pins what they
    /// give in Arrow, in `coercion.snap`. Regenerate after an intentional
    /// change with
    /// `PCAPSQL_GOLDEN_UPDATE=1 cargo test -p pcapsql-datafusion --lib coercion_matches_snapshot`
    /// and review the diff.
    #[test]
    fn coercion_matches_snapshot() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/query/builders/coercion.snap"
        );
        let actual = coercion_table();
        if std::env::var("PCAPSQL_GOLDEN_UPDATE").is_ok() {
            std::fs::write(path, &actual).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(path).expect("coercion.snap is missing");
        for (n, (want, got)) in expected.lines().zip(actual.lines()).enumerate() {
            assert_eq!(got, want, "coercion.snap line {}", n + 1);
        }
        assert_eq!(
            actual.lines().count(),
            expected.lines().count(),
            "coercion.snap has a different number of lines"
        );
    }

    /// The batch of one column of `kind` holding `values`, one per row.
    fn column_of(kind: ColKind, values: &[FieldValue<'_>]) -> ArrayRef {
        let mut sink = one_column(kind, values.len() + 1);
        for value in values {
            write_value(&mut sink, COL, kind, value);
            assert!(sink.end_row().is_continue());
        }
        let batch = sink.take_batch().expect("the batch builds").unwrap();
        assert_eq!(batch.num_rows(), values.len());
        Arc::clone(batch.column(0))
    }

    /// An integer wider than its column is NULL, not a wrapped value.
    #[test]
    fn out_of_range_integers_become_null_not_wrapped() {
        let a = column_of(
            ColKind::U8,
            &[
                FieldValue::UInt16(255),
                FieldValue::UInt16(256),
                FieldValue::UInt32(0x1_0005),
            ],
        );
        let a = a.as_any().downcast_ref::<UInt8Array>().unwrap();
        assert_eq!(a.value(0), 255);
        assert!(a.is_null(1), "256 does not fit u8");
        assert!(a.is_null(2), "0x10005 must not wrap to 5");

        let a = column_of(
            ColKind::U16,
            &[FieldValue::UInt32(65_535), FieldValue::UInt32(65_536)],
        );
        let a = a.as_any().downcast_ref::<UInt16Array>().unwrap();
        assert_eq!(a.value(0), 65_535);
        assert!(a.is_null(1));
    }

    /// D7: a value of the wrong length for a fixed-size binary column is
    /// NULL. Its append used to fail unnoticed, which left the column one
    /// row short and failed the whole batch.
    #[test]
    fn wrong_length_fixed_binary_is_null() {
        let a = column_of(
            ColKind::Fixed(6),
            &[
                FieldValue::Bytes(&[1, 2, 3]),
                FieldValue::MacAddr([1, 2, 3, 4, 5, 6]),
                FieldValue::Bytes(&[0xAA; 16]),
                FieldValue::IpAddr("2001:db8::1".parse().unwrap()),
                FieldValue::OwnedBytes(vec![9; 6]),
            ],
        );
        let a = a.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
        assert_eq!(a.len(), 5);
        let nulls: Vec<bool> = (0..5).map(|i| a.is_null(i)).collect();
        assert_eq!(nulls, [true, false, true, true, false]);
        assert_eq!(a.value(1), [1, 2, 3, 4, 5, 6]);
        assert_eq!(a.value(4), [9; 6]);

        let a = column_of(
            ColKind::Fixed(16),
            &[
                FieldValue::MacAddr([1, 2, 3, 4, 5, 6]),
                FieldValue::Bytes(&[0xAA; 16]),
                FieldValue::OwnedBytes(vec![1, 2, 3]),
            ],
        );
        let a = a.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
        let nulls: Vec<bool> = (0..3).map(|i| a.is_null(i)).collect();
        assert_eq!(nulls, [true, false, true]);
    }

    /// D7: a wrong-length item of a fixed-size binary list is a NULL item.
    /// It used to disappear, shortening the list and shifting what followed.
    #[test]
    fn wrong_length_fixed_binary_list_item_is_a_null_item() {
        let a = column_of(
            ColKind::ListFixed(16),
            &[FieldValue::List(vec![
                FieldValue::Bytes(&[1, 2, 3]),
                FieldValue::Bytes(&[0xAA; 16]),
                FieldValue::MacAddr([1, 2, 3, 4, 5, 6]),
                FieldValue::IpAddr("2001:db8::1".parse().unwrap()),
                FieldValue::OwnedBytes(vec![7; 15]),
            ])],
        );
        let list = a.as_any().downcast_ref::<ListArray>().unwrap();
        let items = list.value(0);
        let items = items
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .unwrap();
        assert_eq!(items.len(), 5, "every item keeps its position");
        let nulls: Vec<bool> = (0..5).map(|i| items.is_null(i)).collect();
        assert_eq!(nulls, [true, false, true, false, true]);
        assert_eq!(items.value(1), [0xAA; 16]);
    }

    /// D8: an unsigned value above `i64::MAX` is NULL in a timestamp
    /// column. It used to wrap to a negative timestamp.
    #[test]
    fn oversized_unsigned_timestamp_is_null() {
        let a = column_of(
            ColKind::TsMicros,
            &[
                FieldValue::UInt64(i64::MAX as u64),
                FieldValue::UInt64(i64::MAX as u64 + 1),
                FieldValue::UInt64(u64::MAX),
                FieldValue::Int64(-1),
            ],
        );
        let a = a
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(a.value(0), i64::MAX);
        assert!(a.is_null(1));
        assert!(a.is_null(2), "u64::MAX must not wrap to -1");
        assert_eq!(a.value(3), -1);
    }

    /// List cells: each item converted (or NULL when it has the wrong
    /// type), a NULL cell for a non-list value, and an empty list for an
    /// empty one.
    #[test]
    fn list_cells_keep_items_and_nulls() {
        let cells = [
            FieldValue::List(vec![
                FieldValue::UInt16(7),
                FieldValue::UInt8(3),
                FieldValue::Str("a.example"),
                FieldValue::OwnedString("b".into()),
                FieldValue::Bytes(b"xy"),
                FieldValue::OwnedBytes(vec![1, 2]),
                FieldValue::IpAddr("10.0.0.1".parse().unwrap()),
                FieldValue::Bool(true),
            ]),
            FieldValue::Null,
            FieldValue::List(vec![]),
            FieldValue::UInt16(1),
        ];
        let render = |kind: ColKind| -> Vec<String> {
            let array = column_of(kind, &cells);
            let array = array.as_any().downcast_ref::<ListArray>().unwrap();
            (0..array.len())
                .map(|i| {
                    if array.is_null(i) {
                        return "NULL".to_string();
                    }
                    let options = arrow::util::display::FormatOptions::default().with_null("∅");
                    let values = array.value(i);
                    let f =
                        arrow::util::display::ArrayFormatter::try_new(&values, &options).unwrap();
                    (0..values.len())
                        .map(|j| f.value(j).to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .collect()
        };
        assert_eq!(
            render(ColKind::ListU16),
            ["7,3,∅,∅,∅,∅,∅,∅", "NULL", "", "NULL"]
        );
        assert_eq!(
            render(ColKind::ListU32),
            ["7,3,∅,∅,∅,∅,167772161,∅", "NULL", "", "NULL"]
        );
        assert_eq!(
            render(ColKind::ListStr),
            ["7,3,a.example,b,∅,∅,10.0.0.1,true", "NULL", "", "NULL"]
        );
        assert_eq!(
            render(ColKind::ListFixed(2)),
            ["∅,∅,∅,∅,7879,0102,∅,∅", "NULL", "", "NULL"]
        );
    }

    fn tcp_layer<'a>() -> ParseResult<'a> {
        let mut fields = SmallVec::new();
        fields.push(("src_port", FieldValue::UInt16(12345)));
        fields.push(("dst_port", FieldValue::UInt16(80)));
        fields.push(("seq", FieldValue::UInt32(100)));
        fields.push(("ack", FieldValue::UInt32(0)));
        fields.push(("flags", FieldValue::UInt16(0x02)));
        ParseResult {
            fields,
            remaining: &[],
            child_hints: SmallVec::new(),
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    fn packet(frame_number: u64) -> PacketRef<'static> {
        PacketRef {
            frame_number,
            timestamp_ns: 1_000_000_000,
            captured_len: 4,
            original_len: 100,
            link_type: 1,
            data: &[1, 2, 3, 4],
        }
    }

    #[test]
    fn frame_rows_build_a_frames_batch() {
        let columns = table_columns("frames", None);
        let mut resolver = FieldResolver::new(&columns);
        let mut sink = ArrowSink::new(&columns, 10);
        assert!(write_frame_row(&mut sink, &mut resolver, &packet(1)).is_continue());
        assert_eq!(sink.rows(), 1);

        let batch = sink.take_batch().unwrap().unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(
            batch.schema().as_ref(),
            &crate::query::tables::get_table_schema("frames").unwrap()
        );
        let timestamp = batch.column_by_name("timestamp").unwrap();
        let timestamp = timestamp
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(timestamp.value(0), 1_000_000);
        let raw = batch.column_by_name("raw_data").unwrap();
        assert_eq!(raw.as_binary::<i32>().value(0), [1, 2, 3, 4]);
    }

    #[test]
    fn layer_rows_build_a_protocol_batch() {
        let columns = table_columns("tcp", None);
        let mut resolver = FieldResolver::new(&columns);
        let mut sink = ArrowSink::new(&columns, 10);
        let _ = write_layer_row(&mut sink, &mut resolver, &packet(1), &tcp_layer());
        assert_eq!(sink.rows(), 1);

        let batch = sink.take_batch().unwrap().unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(
            batch.schema().as_ref(),
            &crate::query::tables::get_table_schema("tcp").unwrap()
        );
        let frame = batch.column_by_name("frame_number").unwrap();
        assert_eq!(frame.as_primitive::<UInt64Type>().value(0), 1);
        let port = batch.column_by_name("src_port").unwrap();
        let port = port.as_any().downcast_ref::<UInt16Array>().unwrap();
        assert_eq!(port.value(0), 12345);
        // A field the layer does not have is NULL.
        assert_eq!(batch.column_by_name("mss").unwrap().null_count(), 1);
    }

    #[test]
    fn sink_is_full_at_its_capacity_and_reusable() {
        let columns = table_columns("tcp", Some(&["frame_number", "dst_port"]));
        let mut resolver = FieldResolver::new(&columns);
        let mut sink = ArrowSink::new(&columns, 5);
        assert!(sink.take_batch().unwrap().is_none());
        for round in 0..2 {
            for i in 1..=5 {
                let flow = write_layer_row(&mut sink, &mut resolver, &packet(i), &tcp_layer());
                assert_eq!(flow.is_break(), i == 5, "round {round} row {i}");
                assert_eq!(sink.is_full(), i == 5);
            }
            let batch = sink.take_batch().unwrap().unwrap();
            assert_eq!(batch.num_rows(), 5);
            assert_eq!(sink.rows(), 0);
            let frames = batch.column(0).as_primitive::<UInt64Type>();
            assert_eq!(frames.values(), &[1, 2, 3, 4, 5]);
        }
    }

    /// A fully projected-away output (`SELECT count(*)`) still carries its
    /// row count.
    #[test]
    fn a_sink_without_columns_counts_rows() {
        let mut resolver = FieldResolver::new(&[]);
        let mut sink = ArrowSink::new(&[], 3);
        for _ in 0..2 {
            assert!(write_frame_row(&mut sink, &mut resolver, &packet(1)).is_continue());
        }
        let batch = sink.take_batch().unwrap().unwrap();
        assert_eq!(batch.num_columns(), 0);
        assert_eq!(batch.num_rows(), 2);
        assert!(sink.take_batch().unwrap().is_none());
    }

    #[test]
    fn nanosecond_timestamps_are_stored_as_such() {
        let mut sink = one_column(ColKind::TsNanos, 2);
        sink.timestamp(COL, 1_700_000_000_123_456_789);
        let _ = sink.end_row();
        let batch = sink.take_batch().unwrap().unwrap();
        assert_eq!(
            *batch.column(0).data_type(),
            DataType::Timestamp(arrow::datatypes::TimeUnit::Nanosecond, None)
        );
        let a = batch
            .column(0)
            .as_any()
            .downcast_ref::<TimestampNanosecondArray>()
            .unwrap();
        assert_eq!(a.value(0), 1_700_000_000_123_456_789);
    }
}
