//! A single column built value by value: the legacy builder of the fused
//! joins.
//!
//! [`DynamicBuilder`] is what is left of the per-column builder the
//! protocol tables used before [`ArrowSink`]. `FusedBatchBuilder` still
//! builds its columns one by one through it; it goes away when fused joins
//! move to the shared scan layer. It holds no logic of its own: it is a
//! one-column [`ArrowSink`], and a field value is converted by
//! `pcapsql_core::scan::write_value` like everywhere else.

use arrow::array::ArrayRef;
use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

use super::sink::ArrowSink;
use crate::query::arrow_schema::{arrow_type_to_col_kind, col_kind_to_arrow_type};
use pcapsql_core::scan::{write_value, ColKind, ColumnSource, OutCol, OutColumn, RowSink};
use pcapsql_core::FieldValue;

const COL: OutCol = OutCol(0);

/// Builds one column of a given Arrow type.
pub(crate) struct DynamicBuilder {
    kind: ColKind,
    sink: ArrowSink,
}

impl DynamicBuilder {
    /// A builder for a column of `data_type`. A type no table column has
    /// (see `ColKind`) is built as a string column, which the batch then
    /// rejects.
    pub(crate) fn new(data_type: &DataType, capacity: usize) -> Self {
        let kind = arrow_type_to_col_kind(data_type).unwrap_or(ColKind::Str);
        let column = OutColumn {
            name: "",
            kind,
            nullable: true,
            source: ColumnSource::Field(""),
        };
        let schema = Schema::new(vec![Field::new("", col_kind_to_arrow_type(kind), true)]);
        Self {
            kind,
            sink: ArrowSink::with_schema(Arc::new(schema), &[column], capacity),
        }
    }

    /// Append a null value.
    pub(crate) fn append_null(&mut self) {
        self.sink.null(COL);
    }

    /// Append a field value, converted to the column's type or NULL
    /// (`pcapsql_core::scan::write_value`).
    pub(crate) fn append_field_value(&mut self, value: &FieldValue) {
        write_value(&mut self.sink, COL, self.kind, value);
    }

    /// Append a u64 value (frame_number, tunnel_id). Like the other typed
    /// appends, it does nothing on a column of another type.
    pub(crate) fn append_u64(&mut self, value: u64) {
        if self.kind == ColKind::U64 {
            self.sink.u64(COL, value);
        }
    }

    /// Append a u32 value (frame lengths).
    pub(crate) fn append_u32(&mut self, value: u32) {
        if self.kind == ColKind::U32 {
            self.sink.u32(COL, value);
        }
    }

    /// Append a u16 value (link type).
    pub(crate) fn append_u16(&mut self, value: u16) {
        if self.kind == ColKind::U16 {
            self.sink.u16(COL, value);
        }
    }

    /// Append a u8 value (encap_depth).
    pub(crate) fn append_u8(&mut self, value: u8) {
        if self.kind == ColKind::U8 {
            self.sink.u8(COL, value);
        }
    }

    /// Append a string (tunnel_type).
    pub(crate) fn append_str(&mut self, value: &str) {
        if self.kind == ColKind::Str {
            self.sink.str(COL, value);
        }
    }

    /// Append a timestamp value, in microseconds.
    pub(crate) fn append_timestamp(&mut self, value: i64) {
        if self.kind == ColKind::TsMicros {
            self.sink.timestamp(COL, value);
        }
    }

    /// Append raw binary data.
    pub(crate) fn append_binary(&mut self, value: &[u8]) {
        if self.kind == ColKind::Bin {
            self.sink.bytes(COL, value);
        }
    }

    /// Finish building and return the array, leaving the builder empty.
    pub(crate) fn finish(&mut self) -> ArrayRef {
        self.sink
            .finish_arrays()
            .pop()
            .expect("the sink has one column")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Array, FixedSizeBinaryArray, UInt16Array};

    /// The legacy builder converts values as the protocol tables do.
    #[test]
    fn appends_go_through_the_shared_coercion() {
        let mut b = DynamicBuilder::new(&DataType::UInt16, 4);
        b.append_field_value(&FieldValue::UInt8(7));
        b.append_field_value(&FieldValue::UInt32(70_000));
        b.append_u16(9);
        b.append_null();
        // Not a u16 column's value: ignored, as before.
        b.append_u64(1);
        let a = b.finish();
        let a = a.as_any().downcast_ref::<UInt16Array>().unwrap();
        assert_eq!(a.len(), 4);
        assert_eq!((a.value(0), a.is_null(1), a.value(2)), (7, true, 9));
        assert!(a.is_null(3));
        // Reusable after `finish`.
        b.append_u16(1);
        assert_eq!(b.finish().len(), 1);

        // D7 holds for a fused join's columns too.
        let mut b = DynamicBuilder::new(&DataType::FixedSizeBinary(6), 2);
        b.append_field_value(&FieldValue::Bytes(&[1, 2, 3]));
        b.append_field_value(&FieldValue::MacAddr([1; 6]));
        let a = b.finish();
        let a = a.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
        assert_eq!((a.len(), a.is_null(0), a.is_null(1)), (2, true, false));
    }
}
