//! The fixed-width columns of the Arrow sink: a vector of values, and a
//! validity bitmap that does not exist until the column's first NULL of a
//! batch.
//!
//! Storing a value is a push onto the vector and nothing else, whether the
//! batch has NULLs or not: the bitmap, once it exists, is all ones for the
//! whole batch and only a NULL changes it. The array of a batch is built
//! over the vector and the bitmap as they are, without a copy.

use std::sync::Arc;

use arrow::array::{
    make_array, ArrayData, ArrayRef, ArrowPrimitiveType, BooleanArray, PrimitiveArray,
};
use arrow::buffer::{BooleanBuffer, Buffer, NullBuffer, ScalarBuffer};
use arrow::datatypes::{ArrowNativeType, DataType};
use arrow::error::ArrowError;

/// The bytes of a bitmap of `bits` bits.
fn bitmap_bytes(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Which rows of a column are NULL: no bitmap while none is, then one bit
/// per row, set for a value.
#[derive(Debug, Default)]
struct Validity {
    /// Empty until the first NULL. Then every bit is set but those of the
    /// NULL rows, the bits of rows not yet written included.
    bits: Vec<u8>,
}

impl Validity {
    /// Row `row` is NULL. `capacity` is the number of rows the batch is
    /// expected to reach, which sizes the bitmap when this is its first
    /// NULL.
    #[inline]
    fn set_null(&mut self, row: usize, capacity: usize) {
        match self.bits.get_mut(row / 8) {
            Some(byte) => *byte &= !(1 << (row % 8)),
            None => self.grow_for_null(row, capacity),
        }
    }

    /// [`set_null`](Self::set_null) for a row the bitmap does not reach:
    /// the first NULL of a batch, or a row past the expected capacity.
    #[cold]
    fn grow_for_null(&mut self, row: usize, capacity: usize) {
        self.bits
            .resize(bitmap_bytes(capacity.max(row + 1)), u8::MAX);
        self.bits[row / 8] &= !(1 << (row % 8));
    }

    /// The null buffer of a batch of `len` rows, `None` when it has no
    /// NULL; no bitmap is left.
    fn finish(&mut self, len: usize) -> Option<NullBuffer> {
        if self.bits.is_empty() {
            return None;
        }
        let mut bits = std::mem::take(&mut self.bits);
        // Exactly the rows written (rows past a bitmap they outgrew were
        // values), and no bit set after them.
        bits.resize(bitmap_bytes(len), u8::MAX);
        if let (Some(last), tail @ 1..) = (bits.last_mut(), len % 8) {
            *last &= (1 << tail) - 1;
        }
        Some(NullBuffer::new(BooleanBuffer::new(
            Buffer::from_vec(bits),
            0,
            len,
        )))
    }
}

/// A column of integers, floats or timestamps.
#[derive(Debug)]
pub(super) struct Values<T> {
    values: Vec<T>,
    validity: Validity,
}

impl<T: ArrowNativeType> Values<T> {
    /// A column with room for `capacity` rows.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            validity: Validity::default(),
        }
    }

    #[inline]
    pub(super) fn push(&mut self, value: T) {
        self.values.push(value);
    }

    /// A NULL row, in a batch expected to reach `capacity` rows.
    #[inline]
    pub(super) fn push_null(&mut self, capacity: usize) {
        let row = self.values.len();
        self.values.push(T::default());
        self.validity.set_null(row, capacity);
    }

    /// The rows so far as an array of type `P`, leaving the column empty:
    /// with room for `refill` rows, or without capacity.
    pub(super) fn finish<P>(&mut self, refill: Option<usize>) -> ArrayRef
    where
        P: ArrowPrimitiveType<Native = T>,
    {
        let next = refill.map_or_else(Vec::new, Vec::with_capacity);
        let values = std::mem::replace(&mut self.values, next);
        let nulls = self.validity.finish(values.len());
        Arc::new(PrimitiveArray::<P>::new(ScalarBuffer::from(values), nulls))
    }
}

/// A boolean column: its values are a bitmap too.
#[derive(Debug)]
pub(super) struct Bits {
    /// One bit per row written, and zeroes for the rest of the batch.
    bits: Vec<u8>,
    rows: usize,
    validity: Validity,
}

impl Bits {
    /// A column with room for `capacity` rows.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            bits: vec![0; bitmap_bytes(capacity)],
            rows: 0,
            validity: Validity::default(),
        }
    }

    #[inline]
    pub(super) fn push(&mut self, value: bool) {
        let row = self.rows;
        match self.bits.get_mut(row / 8) {
            Some(byte) => *byte |= u8::from(value) << (row % 8),
            // Rows come one at a time, so this is the next byte.
            None => self.bits.push(u8::from(value)),
        }
        self.rows = row + 1;
    }

    /// A NULL row, in a batch expected to reach `capacity` rows.
    #[inline]
    pub(super) fn push_null(&mut self, capacity: usize) {
        self.validity.set_null(self.rows, capacity);
        self.push(false);
    }

    /// The rows so far as an array, leaving the column empty: with room
    /// for `refill` rows, or without capacity.
    pub(super) fn finish(&mut self, refill: Option<usize>) -> ArrayRef {
        let next = refill.map_or_else(Vec::new, |rows| vec![0; bitmap_bytes(rows)]);
        let mut bits = std::mem::replace(&mut self.bits, next);
        let rows = std::mem::take(&mut self.rows);
        bits.truncate(bitmap_bytes(rows));
        let values = BooleanBuffer::new(Buffer::from_vec(bits), 0, rows);
        Arc::new(BooleanArray::new(values, self.validity.finish(rows)))
    }
}

/// A column of byte strings of one length (a MAC or IPv6 address).
#[derive(Debug)]
pub(super) struct FixedBytes {
    values: Vec<u8>,
    width: usize,
    rows: usize,
    validity: Validity,
}

impl FixedBytes {
    /// A column of values of `width` bytes with room for `capacity` rows.
    pub(super) fn with_capacity(capacity: usize, width: u16) -> Self {
        let width = usize::from(width);
        Self {
            values: Vec::with_capacity(capacity * width),
            width,
            rows: 0,
            validity: Validity::default(),
        }
    }

    /// A value, in a batch expected to reach `capacity` rows. One of
    /// another length than the column's is stored as NULL rather than
    /// left out.
    #[inline]
    pub(super) fn push(&mut self, value: &[u8], capacity: usize) {
        if value.len() == self.width {
            self.values.extend_from_slice(value);
            self.rows += 1;
        } else {
            self.push_null(capacity);
        }
    }

    /// A NULL row, in a batch expected to reach `capacity` rows.
    pub(super) fn push_null(&mut self, capacity: usize) {
        self.values.resize(self.values.len() + self.width, 0);
        self.validity.set_null(self.rows, capacity);
        self.rows += 1;
    }

    /// The rows so far as an array, leaving the column empty: with room
    /// for `refill` rows, or without capacity.
    pub(super) fn finish(&mut self, refill: Option<usize>) -> Result<ArrayRef, ArrowError> {
        let next = refill.map_or_else(Vec::new, |rows| Vec::with_capacity(rows * self.width));
        let values = std::mem::replace(&mut self.values, next);
        let rows = std::mem::take(&mut self.rows);
        // Through `ArrayData` and not `FixedSizeBinaryArray::try_new`,
        // which takes the row count from the bytes and so finds none in a
        // column of empty values.
        let data = ArrayData::builder(DataType::FixedSizeBinary(self.width as i32))
            .len(rows)
            .add_buffer(Buffer::from_vec(values))
            .nulls(self.validity.finish(rows))
            .build()?;
        Ok(make_array(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::Array;

    /// The bitmap `Validity` gives for `len` rows of which `nulls` are
    /// NULL, written in a batch expected to reach `capacity` rows.
    fn validity(len: usize, nulls: &[usize], capacity: usize) -> Option<NullBuffer> {
        let mut validity = Validity::default();
        for row in nulls {
            validity.set_null(*row, capacity);
        }
        validity.finish(len)
    }

    #[test]
    fn no_null_is_no_bitmap() {
        assert!(validity(0, &[], 8).is_none());
        assert!(validity(100, &[], 8).is_none());
    }

    /// The bitmap is the bytes of the rows written and no more, whatever
    /// the capacity it was sized for, with no bit set past the last row.
    #[test]
    fn the_bitmap_covers_exactly_the_rows_written() {
        for (len, nulls, capacity, bytes) in [
            (1, &[0][..], 1024, &[0b0][..]),
            (3, &[1], 1024, &[0b101]),
            (8, &[7], 8, &[0x7F]),
            (9, &[8], 8, &[0xFF, 0b0]),
            (12, &[0, 11], 4, &[0xFE, 0b0111]),
            // A NULL after rows that outgrew the capacity, and values
            // after the bitmap's end.
            (20, &[2], 1, &[0xFB, 0xFF, 0x0F]),
        ] {
            let buffer = validity(len, nulls, capacity).expect("a bitmap");
            assert_eq!(buffer.len(), len);
            assert_eq!(buffer.null_count(), nulls.len());
            assert_eq!(buffer.buffer().as_slice(), bytes, "{len} rows");
            for row in 0..len {
                assert_eq!(buffer.is_null(row), nulls.contains(&row), "row {row}");
            }
        }
    }

    /// A column gives its buffers away and starts the next batch without
    /// NULLs, with the room asked for.
    #[test]
    fn a_finished_column_starts_again() {
        let mut column = Values::<u16>::with_capacity(2);
        column.push(1);
        column.push_null(2);
        let first = column.finish::<arrow::datatypes::UInt16Type>(Some(4));
        assert_eq!((first.len(), first.null_count()), (2, 1));
        assert_eq!(column.values.capacity(), 4);
        column.push(3);
        let second = column.finish::<arrow::datatypes::UInt16Type>(None);
        assert_eq!((second.len(), second.null_count()), (1, 0));
        assert!(second.nulls().is_none());
        assert_eq!(column.values.capacity(), 0);

        let mut bits = Bits::with_capacity(3);
        bits.push(true);
        bits.push_null(3);
        assert_eq!(bits.finish(None).null_count(), 1);
        // Without room: the bitmap grows a byte at a time.
        for row in 0..20u32 {
            bits.push(row.is_multiple_of(3));
        }
        let array = bits.finish(Some(16));
        assert!(array.nulls().is_none());
        assert_eq!(array.to_data().buffers()[0].as_slice(), [0x49, 0x92, 0x04]);
        assert_eq!(bits.bits, [0, 0]);
    }

    /// A column of empty values still has its rows.
    #[test]
    fn fixed_bytes_of_no_width_count_their_rows() {
        let mut column = FixedBytes::with_capacity(4, 0);
        column.push(&[], 4);
        column.push(&[1], 4);
        column.push(&[], 4);
        let array = column.finish(Some(4)).unwrap();
        assert_eq!(*array.data_type(), DataType::FixedSizeBinary(0));
        assert_eq!((array.len(), array.null_count()), (3, 1));
        assert!(array.is_null(1));
    }
}
