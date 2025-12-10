//! Build DuckDB DataChunks from parsed packet data.
//!
//! This is the DuckDB equivalent of `pcapsql-datafusion`'s `ProtocolBatchBuilder`.

use std::ffi::CString;

use duckdb::core::{FlatVector, Inserter, ListVector};
use pcapsql_core::FieldValue;

/// Builder for accumulating list column data.
///
/// DuckDB's ListVector requires all elements to be written to the child vector first,
/// then entries (offset, length) are set for each row. This builder accumulates data
/// during row-by-row processing, then writes everything at the end.
#[derive(Debug, Default)]
pub struct ListColumnBuilder {
    /// Entries: (offset, length) for each row
    entries: Vec<(usize, usize)>,
    /// Accumulated UInt16 values (for answer_types)
    uint16_values: Vec<u16>,
    /// Accumulated UInt32 values (for answer_ip4s, answer_ttls)
    uint32_values: Vec<u32>,
    /// Accumulated String values (for answer_cnames)
    string_values: Vec<String>,
    /// Accumulated binary values (for answer_ip6s - 16 bytes each)
    binary_values: Vec<Vec<u8>>,
    /// Track which type this builder is for
    value_type: ListValueType,
}

/// The type of values stored in this list column.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum ListValueType {
    #[default]
    Unknown,
    UInt16,
    UInt32,
    String,
    Binary,
}

impl ListColumnBuilder {
    /// Create a new list column builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a null list for this row.
    pub fn push_null(&mut self) {
        // A null list is represented by an entry with length 0 at current offset
        // The validity mask will mark it as null
        let offset = self.current_offset();
        self.entries.push((offset, 0));
    }

    /// Add an empty list for this row.
    pub fn push_empty(&mut self) {
        let offset = self.current_offset();
        self.entries.push((offset, 0));
    }

    /// Add a list of UInt16 values.
    pub fn push_uint16_list(&mut self, values: &[u16]) {
        self.value_type = ListValueType::UInt16;
        let offset = self.uint16_values.len();
        self.uint16_values.extend_from_slice(values);
        self.entries.push((offset, values.len()));
    }

    /// Add a list of UInt32 values.
    pub fn push_uint32_list(&mut self, values: &[u32]) {
        self.value_type = ListValueType::UInt32;
        let offset = self.uint32_values.len();
        self.uint32_values.extend_from_slice(values);
        self.entries.push((offset, values.len()));
    }

    /// Add a list of String values.
    pub fn push_string_list(&mut self, values: &[String]) {
        self.value_type = ListValueType::String;
        let offset = self.string_values.len();
        self.string_values.extend(values.iter().cloned());
        self.entries.push((offset, values.len()));
    }

    /// Add a list of binary values (for IPv6 addresses).
    pub fn push_binary_list(&mut self, values: &[Vec<u8>]) {
        self.value_type = ListValueType::Binary;
        let offset = self.binary_values.len();
        self.binary_values.extend(values.iter().cloned());
        self.entries.push((offset, values.len()));
    }

    /// Get the current offset based on value type.
    fn current_offset(&self) -> usize {
        match self.value_type {
            ListValueType::Unknown => 0,
            ListValueType::UInt16 => self.uint16_values.len(),
            ListValueType::UInt32 => self.uint32_values.len(),
            ListValueType::String => self.string_values.len(),
            ListValueType::Binary => self.binary_values.len(),
        }
    }

    /// Write accumulated list data to a DuckDB ListVector.
    pub fn write_to_list_vector(&self, list_vector: &mut ListVector, null_rows: &[usize]) {
        let total_elements = match self.value_type {
            ListValueType::Unknown => 0,
            ListValueType::UInt16 => self.uint16_values.len(),
            ListValueType::UInt32 => self.uint32_values.len(),
            ListValueType::String => self.string_values.len(),
            ListValueType::Binary => self.binary_values.len(),
        };

        if total_elements == 0 && self.entries.is_empty() {
            return;
        }

        // Write child data
        match self.value_type {
            ListValueType::UInt16 => {
                let mut child = list_vector.child(total_elements);
                child.copy(&self.uint16_values);
                list_vector.set_len(total_elements);
            }
            ListValueType::UInt32 => {
                let mut child = list_vector.child(total_elements);
                child.copy(&self.uint32_values);
                list_vector.set_len(total_elements);
            }
            ListValueType::String => {
                let child = list_vector.child(total_elements);
                for (i, s) in self.string_values.iter().enumerate() {
                    if let Ok(cstr) = CString::new(s.as_str()) {
                        child.insert(i, cstr);
                    }
                }
                list_vector.set_len(total_elements);
            }
            ListValueType::Binary => {
                let child = list_vector.child(total_elements);
                for (i, b) in self.binary_values.iter().enumerate() {
                    child.insert(i, b.as_slice());
                }
                list_vector.set_len(total_elements);
            }
            ListValueType::Unknown => {}
        }

        // Set entries for each row
        for (row_idx, (offset, length)) in self.entries.iter().enumerate() {
            list_vector.set_entry(row_idx, *offset, *length);
        }

        // Mark null rows
        for &row_idx in null_rows {
            list_vector.set_null(row_idx);
        }
    }

    /// Get the number of rows added.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Extract list values from a FieldValue::List into typed vectors.
pub fn extract_list_values(list: &[FieldValue]) -> ListExtract {
    if list.is_empty() {
        return ListExtract::Empty;
    }

    // Determine type from first non-null element
    for item in list {
        match item {
            FieldValue::UInt16(_) => {
                let values: Vec<u16> = list
                    .iter()
                    .filter_map(|v| match v {
                        FieldValue::UInt16(x) => Some(*x),
                        _ => None,
                    })
                    .collect();
                return ListExtract::UInt16(values);
            }
            FieldValue::UInt32(_) => {
                let values: Vec<u32> = list
                    .iter()
                    .filter_map(|v| match v {
                        FieldValue::UInt32(x) => Some(*x),
                        _ => None,
                    })
                    .collect();
                return ListExtract::UInt32(values);
            }
            FieldValue::Str(_) => {
                let values: Vec<String> = list
                    .iter()
                    .filter_map(|v| match v {
                        FieldValue::Str(x) => Some(x.to_string()),
                        FieldValue::OwnedString(x) => Some(x.to_string()),
                        _ => None,
                    })
                    .collect();
                return ListExtract::String(values);
            }
            FieldValue::OwnedString(_) => {
                let values: Vec<String> = list
                    .iter()
                    .filter_map(|v| match v {
                        FieldValue::Str(x) => Some(x.to_string()),
                        FieldValue::OwnedString(x) => Some(x.to_string()),
                        _ => None,
                    })
                    .collect();
                return ListExtract::String(values);
            }
            FieldValue::Bytes(_) => {
                let values: Vec<Vec<u8>> = list
                    .iter()
                    .filter_map(|v| match v {
                        FieldValue::Bytes(x) => Some(x.to_vec()),
                        FieldValue::OwnedBytes(x) => Some(x.clone()),
                        _ => None,
                    })
                    .collect();
                return ListExtract::Binary(values);
            }
            FieldValue::OwnedBytes(_) => {
                let values: Vec<Vec<u8>> = list
                    .iter()
                    .filter_map(|v| match v {
                        FieldValue::Bytes(x) => Some(x.to_vec()),
                        FieldValue::OwnedBytes(x) => Some(x.clone()),
                        _ => None,
                    })
                    .collect();
                return ListExtract::Binary(values);
            }
            FieldValue::Null => continue,
            _ => return ListExtract::Unsupported,
        }
    }

    ListExtract::Empty
}

/// Result of extracting list values.
pub enum ListExtract {
    Empty,
    UInt16(Vec<u16>),
    UInt32(Vec<u32>),
    String(Vec<String>),
    Binary(Vec<Vec<u8>>),
    Unsupported,
}

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
        FieldValue::List(_) => {
            // List values require special handling via insert_list_value
            // For FlatVector, we just set null as placeholder
            vector.set_null(row_idx);
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
