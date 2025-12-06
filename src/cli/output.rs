//! Output formatting for query results.
//!
//! This module provides type-aware formatting for query results, automatically
//! converting network addresses (IPv4, IPv6, MAC) to human-readable strings
//! while displaying in table, CSV, or JSON format.

use std::io::Write;
use std::sync::Arc;

use arrow::array::{Array, FixedSizeBinaryArray, RecordBatch, UInt32Array};
use arrow::datatypes::Schema;
use clap::ValueEnum;

use crate::format::{detect_address_column, format_ipv4, format_ipv6, format_mac, AddressKind};

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Pretty-printed table (default)
    Table,
    /// Comma-separated values
    Csv,
    /// JSON Lines (one JSON object per row)
    Json,
}

/// Formats query results for output.
pub struct OutputFormatter {
    format: OutputFormat,
}

impl OutputFormatter {
    /// Create a new formatter with the specified format.
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// Format a RecordBatch and write to the given writer.
    pub fn write<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Table => self.write_table(batch, writer),
            OutputFormat::Csv => self.write_csv(batch, writer),
            OutputFormat::Json => self.write_json(batch, writer),
        }
    }

    /// Detect address columns and cache their types for efficient formatting.
    fn detect_address_columns(schema: &Schema) -> Vec<Option<AddressKind>> {
        schema
            .fields()
            .iter()
            .map(|field| detect_address_column(field))
            .collect()
    }

    /// Format a single cell value, applying address formatting if applicable.
    fn format_value(
        col: &Arc<dyn Array>,
        row_idx: usize,
        address_kind: Option<AddressKind>,
    ) -> String {
        if col.is_null(row_idx) {
            return String::new();
        }

        match address_kind {
            Some(AddressKind::Ipv4) => {
                if let Some(arr) = col.as_any().downcast_ref::<UInt32Array>() {
                    return format_ipv4(arr.value(row_idx));
                }
            }
            Some(AddressKind::Ipv6) => {
                if let Some(arr) = col.as_any().downcast_ref::<FixedSizeBinaryArray>() {
                    if let Some(s) = format_ipv6(arr.value(row_idx)) {
                        return s;
                    }
                }
            }
            Some(AddressKind::Mac) => {
                if let Some(arr) = col.as_any().downcast_ref::<FixedSizeBinaryArray>() {
                    if let Some(s) = format_mac(arr.value(row_idx)) {
                        return s;
                    }
                }
            }
            None => {}
        }

        // Fallback to default Arrow formatting
        arrow::util::display::array_value_to_string(col, row_idx)
            .unwrap_or_else(|_| "?".to_string())
    }

    fn write_table<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        use comfy_table::{Cell, Table};

        let address_kinds = Self::detect_address_columns(batch.schema().as_ref());

        let mut table = Table::new();

        // Add header row
        let headers: Vec<Cell> = batch
            .schema()
            .fields()
            .iter()
            .map(|f| Cell::new(f.name()))
            .collect();
        table.set_header(headers);

        // Add data rows
        for row_idx in 0..batch.num_rows() {
            let mut row = Vec::with_capacity(batch.num_columns());
            for (col_idx, col) in batch.columns().iter().enumerate() {
                let value = Self::format_value(col, row_idx, address_kinds[col_idx]);
                row.push(Cell::new(value));
            }
            table.add_row(row);
        }

        writeln!(writer, "{table}")
    }

    fn write_csv<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        let address_kinds = Self::detect_address_columns(batch.schema().as_ref());

        // Write header
        let schema = batch.schema();
        let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        writeln!(writer, "{}", headers.join(","))?;

        // Write rows
        for row_idx in 0..batch.num_rows() {
            let mut values = Vec::with_capacity(batch.num_columns());
            for (col_idx, col) in batch.columns().iter().enumerate() {
                let value = Self::format_value(col, row_idx, address_kinds[col_idx]);
                // Escape commas and quotes
                if value.contains(',') || value.contains('"') || value.contains('\n') {
                    values.push(format!("\"{}\"", value.replace('"', "\"\"")));
                } else {
                    values.push(value);
                }
            }
            writeln!(writer, "{}", values.join(","))?;
        }

        Ok(())
    }

    fn write_json<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        let schema = batch.schema();
        let address_kinds = Self::detect_address_columns(schema.as_ref());

        for row_idx in 0..batch.num_rows() {
            let mut obj = serde_json::Map::new();
            for (col_idx, field) in schema.fields().iter().enumerate() {
                let col = batch.column(col_idx);

                let json_value = if col.is_null(row_idx) {
                    serde_json::Value::Null
                } else if address_kinds[col_idx].is_some() {
                    // Formatted addresses are always strings
                    let value = Self::format_value(col, row_idx, address_kinds[col_idx]);
                    serde_json::Value::String(value)
                } else {
                    // Non-address values: try to preserve type
                    let value = arrow::util::display::array_value_to_string(col, row_idx)
                        .unwrap_or_else(|_| "null".to_string());

                    if value == "null" {
                        serde_json::Value::Null
                    } else if let Ok(n) = value.parse::<i64>() {
                        serde_json::Value::Number(n.into())
                    } else if let Ok(n) = value.parse::<f64>() {
                        serde_json::json!(n)
                    } else if value == "true" {
                        serde_json::Value::Bool(true)
                    } else if value == "false" {
                        serde_json::Value::Bool(false)
                    } else {
                        serde_json::Value::String(value)
                    }
                };

                obj.insert(field.name().clone(), json_value);
            }

            writeln!(writer, "{}", serde_json::Value::Object(obj))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::UInt16Array;
    use arrow::datatypes::{DataType, Field};

    fn create_test_batch() -> RecordBatch {
        let schema = Schema::new(vec![
            Field::new("src_ip", DataType::UInt32, true),
            Field::new("dst_ip", DataType::UInt32, true),
            Field::new("count", DataType::UInt32, true), // Not an IP column
            Field::new("src_port", DataType::UInt16, true),
        ]);

        // 192.168.1.1 = 0xC0A80101 = 3232235777
        // 10.0.0.1 = 0x0A000001 = 167772161
        let src_ip = UInt32Array::from(vec![Some(0xC0A80101), Some(0x0A000001)]);
        let dst_ip = UInt32Array::from(vec![Some(0x08080808), Some(0x08080404)]); // 8.8.8.8, 8.8.4.4
        let count = UInt32Array::from(vec![Some(42), Some(100)]);
        let src_port = UInt16Array::from(vec![Some(443), Some(80)]);

        RecordBatch::try_new(
            Arc::new(schema),
            vec![
                Arc::new(src_ip),
                Arc::new(dst_ip),
                Arc::new(count),
                Arc::new(src_port),
            ],
        )
        .unwrap()
    }

    #[test]
    fn test_table_output_formats_ips() {
        let batch = create_test_batch();
        let formatter = OutputFormatter::new(OutputFormat::Table);

        let mut output = Vec::new();
        formatter.write(&batch, &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();

        // IPs should be formatted
        assert!(output_str.contains("192.168.1.1"), "Should contain formatted IP");
        assert!(output_str.contains("10.0.0.1"), "Should contain formatted IP");
        assert!(output_str.contains("8.8.8.8"), "Should contain formatted IP");

        // Count should still be a number (not formatted as IP)
        assert!(output_str.contains("42"), "Count should be preserved");
        assert!(output_str.contains("100"), "Count should be preserved");
    }

    #[test]
    fn test_csv_output_formats_ips() {
        let batch = create_test_batch();
        let formatter = OutputFormatter::new(OutputFormat::Csv);

        let mut output = Vec::new();
        formatter.write(&batch, &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("192.168.1.1"));
        assert!(output_str.contains("8.8.8.8"));
        // Non-IP UInt32 should remain as number
        assert!(output_str.contains(",42,"));
    }

    #[test]
    fn test_json_output_formats_ips() {
        let batch = create_test_batch();
        let formatter = OutputFormatter::new(OutputFormat::Json);

        let mut output = Vec::new();
        formatter.write(&batch, &mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();

        // IPs should be string values in JSON
        assert!(output_str.contains("\"src_ip\":\"192.168.1.1\""));
        assert!(output_str.contains("\"dst_ip\":\"8.8.8.8\""));

        // Count should be a number in JSON
        assert!(output_str.contains("\"count\":42"));
    }

    #[test]
    fn test_detect_address_columns() {
        let schema = Schema::new(vec![
            Field::new("src_ip", DataType::UInt32, true),
            Field::new("count", DataType::UInt32, true),
            Field::new("src_mac", DataType::FixedSizeBinary(6), true),
        ]);

        let kinds = OutputFormatter::detect_address_columns(&schema);

        assert_eq!(kinds.len(), 3);
        assert_eq!(kinds[0], Some(AddressKind::Ipv4));
        assert_eq!(kinds[1], None); // count is not an address
        assert_eq!(kinds[2], Some(AddressKind::Mac));
    }
}
