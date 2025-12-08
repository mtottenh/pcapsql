//! Build DuckDB DataChunks from parsed packet data.
//!
//! This is the DuckDB equivalent of `pcapsql-datafusion`'s `ProtocolBatchBuilder`.

use std::ffi::CString;

use duckdb::core::{FlatVector, Inserter};
use pcapsql_core::FieldValue;

/// Insert a FieldValue into a DuckDB vector at the given row index.
///
/// This function handles the type conversion from pcapsql FieldValue to DuckDB types.
#[allow(dead_code)]
pub fn insert_field_value(vector: &mut FlatVector, row_idx: usize, value: &FieldValue) {
    match value {
        FieldValue::Null => {
            vector.set_null(row_idx);
        }
        FieldValue::Bool(v) => {
            let slice = vector.as_mut_slice::<bool>();
            slice[row_idx] = *v;
        }
        FieldValue::UInt8(v) => {
            let slice = vector.as_mut_slice::<u8>();
            slice[row_idx] = *v;
        }
        FieldValue::UInt16(v) => {
            let slice = vector.as_mut_slice::<u16>();
            slice[row_idx] = *v;
        }
        FieldValue::UInt32(v) => {
            let slice = vector.as_mut_slice::<u32>();
            slice[row_idx] = *v;
        }
        FieldValue::UInt64(v) => {
            let slice = vector.as_mut_slice::<u64>();
            slice[row_idx] = *v;
        }
        FieldValue::Int64(v) => {
            let slice = vector.as_mut_slice::<i64>();
            slice[row_idx] = *v;
        }
        FieldValue::Str(v) => {
            // Use Inserter trait for strings
            if let Ok(cstr) = CString::new(*v) {
                vector.insert(row_idx, cstr);
            } else {
                // String contains null byte, set as null
                vector.set_null(row_idx);
            }
        }
        FieldValue::OwnedString(v) => {
            // Use Inserter trait for strings
            if let Ok(cstr) = CString::new(v.as_str()) {
                vector.insert(row_idx, cstr);
            } else {
                // String contains null byte, set as null
                vector.set_null(row_idx);
            }
        }
        FieldValue::Bytes(v) => {
            // Use Inserter trait for binary data (borrowed slice)
            vector.insert(row_idx, *v);
        }
        FieldValue::OwnedBytes(v) => {
            // Use Inserter trait for binary data (owned vec)
            vector.insert(row_idx, v.as_slice());
        }
        FieldValue::MacAddr(v) => {
            // Store MAC address as 6-byte binary blob
            vector.insert(row_idx, v.as_slice());
        }
        FieldValue::IpAddr(addr) => {
            // Store as string for now (DuckDB INET type requires extension)
            if let Ok(cstr) = CString::new(addr.to_string()) {
                vector.insert(row_idx, cstr);
            } else {
                vector.set_null(row_idx);
            }
        }
    }
}

/// Insert a null value at the given row index.
#[inline]
#[allow(dead_code)]
pub fn insert_null(vector: &mut FlatVector, row_idx: usize) {
    vector.set_null(row_idx);
}

/// Insert a u64 value (for frame_number column).
#[inline]
pub fn insert_u64(vector: &mut FlatVector, row_idx: usize, value: u64) {
    let slice = vector.as_mut_slice::<u64>();
    slice[row_idx] = value;
}

/// Insert a u32 value.
#[inline]
pub fn insert_u32(vector: &mut FlatVector, row_idx: usize, value: u32) {
    let slice = vector.as_mut_slice::<u32>();
    slice[row_idx] = value;
}

/// Insert a u16 value.
#[inline]
pub fn insert_u16(vector: &mut FlatVector, row_idx: usize, value: u16) {
    let slice = vector.as_mut_slice::<u16>();
    slice[row_idx] = value;
}

/// Insert an i64 value (for timestamps).
#[inline]
pub fn insert_i64(vector: &mut FlatVector, row_idx: usize, value: i64) {
    let slice = vector.as_mut_slice::<i64>();
    slice[row_idx] = value;
}

/// Insert a string value.
#[inline]
#[allow(dead_code)]
pub fn insert_string(vector: &mut FlatVector, row_idx: usize, value: &str) {
    if let Ok(cstr) = CString::new(value) {
        vector.insert(row_idx, cstr);
    } else {
        vector.set_null(row_idx);
    }
}

/// Insert binary data.
#[inline]
#[allow(dead_code)]
pub fn insert_bytes(vector: &mut FlatVector, row_idx: usize, value: &[u8]) {
    vector.insert(row_idx, value);
}
