//! Output formatting for query results.
//!
//! This module provides type-aware formatting for query results, automatically
//! converting network addresses (IPv4, IPv6, MAC) to human-readable strings
//! while displaying in table, CSV, JSON or raw format.

use std::io::Write;
use std::sync::Arc;

use arrow::array::{Array, FixedSizeBinaryArray, RecordBatch, UInt32Array};
use arrow::datatypes::Schema;

use crate::query::arrow_schema::detect_arrow_address_column;
use pcapsql_core::{format_ipv4, format_ipv6, format_mac, AddressKind};

// Re-export OutputFormat from args (where it's defined for build.rs compatibility)
pub use super::args::OutputFormat;

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
            OutputFormat::Raw => self.write_raw(batch, writer),
        }
    }

    /// Append one batch of a continuous result: CSV writes its header before
    /// the first non-empty batch only, JSON lines and raw need none, and the
    /// table format renders one table per batch (each closed window).
    pub fn write_incremental<W: Write>(
        &self,
        batch: &RecordBatch,
        writer: &mut W,
        header_written: &mut bool,
    ) -> std::io::Result<()> {
        if batch.num_rows() == 0 {
            return Ok(());
        }
        match self.format {
            OutputFormat::Table | OutputFormat::Json | OutputFormat::Raw => {
                self.write(batch, writer)
            }
            OutputFormat::Csv => {
                if *header_written {
                    self.write_csv_rows(batch, writer)
                } else {
                    *header_written = true;
                    self.write_csv(batch, writer)
                }
            }
        }
    }

    /// Format multiple RecordBatches and write to the given writer as a single combined result.
    pub fn write_batches<W: Write>(
        &self,
        batches: &[RecordBatch],
        writer: &mut W,
    ) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Table => self.write_table_batches(batches, writer),
            OutputFormat::Csv => self.write_csv_batches(batches, writer),
            OutputFormat::Json => self.write_json_batches(batches, writer),
            OutputFormat::Raw => batches.iter().try_for_each(|b| self.write_raw(b, writer)),
        }
    }

    /// Detect address columns and cache their types for efficient formatting.
    fn detect_address_columns(schema: &Schema) -> Vec<Option<AddressKind>> {
        schema
            .fields()
            .iter()
            .map(|field| detect_arrow_address_column(field))
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
        // Write header
        let schema = batch.schema();
        let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        writeln!(writer, "{}", headers.join(","))?;
        self.write_csv_rows(batch, writer)
    }

    /// The rows of one batch as CSV, without a header.
    fn write_csv_rows<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        let address_kinds = Self::detect_address_columns(batch.schema().as_ref());
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

    /// Write each row's values tab-separated, with no header and no quoting,
    /// so a text value (such as `hdr_ascii` output) prints exactly as it is.
    /// A row that already ends in a newline gets no second one.
    fn write_raw<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        let address_kinds = Self::detect_address_columns(batch.schema().as_ref());
        for row_idx in 0..batch.num_rows() {
            let line = batch
                .columns()
                .iter()
                .enumerate()
                .map(|(col_idx, col)| Self::format_value(col, row_idx, address_kinds[col_idx]))
                .collect::<Vec<_>>()
                .join("\t");
            if line.ends_with('\n') {
                write!(writer, "{line}")?;
            } else {
                writeln!(writer, "{line}")?;
            }
        }
        Ok(())
    }

    /// Write multiple batches as a single combined table.
    fn write_table_batches<W: Write>(
        &self,
        batches: &[RecordBatch],
        writer: &mut W,
    ) -> std::io::Result<()> {
        use comfy_table::{Cell, Table};

        // Handle empty batches
        if batches.is_empty() {
            return Ok(());
        }

        // Get schema from first non-empty batch
        let first_batch = batches.iter().find(|b| b.num_rows() > 0);
        let schema = match first_batch {
            Some(batch) => batch.schema(),
            None => return Ok(()), // All batches are empty
        };

        let address_kinds = Self::detect_address_columns(schema.as_ref());

        let mut table = Table::new();

        // Add header row (once)
        let headers: Vec<Cell> = schema
            .fields()
            .iter()
            .map(|f| Cell::new(f.name()))
            .collect();
        table.set_header(headers);

        // Add data rows from all batches
        for batch in batches {
            for row_idx in 0..batch.num_rows() {
                let mut row = Vec::with_capacity(batch.num_columns());
                for (col_idx, col) in batch.columns().iter().enumerate() {
                    let value = Self::format_value(col, row_idx, address_kinds[col_idx]);
                    row.push(Cell::new(value));
                }
                table.add_row(row);
            }
        }

        writeln!(writer, "{table}")
    }

    /// Write multiple batches as CSV with a single header.
    fn write_csv_batches<W: Write>(
        &self,
        batches: &[RecordBatch],
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Handle empty batches
        if batches.is_empty() {
            return Ok(());
        }

        // Get schema from first non-empty batch
        let first_batch = batches.iter().find(|b| b.num_rows() > 0);
        let schema = match first_batch {
            Some(batch) => batch.schema(),
            None => return Ok(()), // All batches are empty
        };

        let address_kinds = Self::detect_address_columns(schema.as_ref());

        // Write header (once)
        let headers: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        writeln!(writer, "{}", headers.join(","))?;

        // Write rows from all batches
        for batch in batches {
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
        }

        Ok(())
    }

    /// Write multiple batches as JSON lines.
    fn write_json_batches<W: Write>(
        &self,
        batches: &[RecordBatch],
        writer: &mut W,
    ) -> std::io::Result<()> {
        // JSON lines format doesn't have headers, so just iterate through all batches
        for batch in batches {
            self.write_json(batch, writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{StringArray, UInt16Array};
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
        assert!(
            output_str.contains("192.168.1.1"),
            "Should contain formatted IP"
        );
        assert!(
            output_str.contains("10.0.0.1"),
            "Should contain formatted IP"
        );
        assert!(
            output_str.contains("8.8.8.8"),
            "Should contain formatted IP"
        );

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
    fn test_raw_output_formats_ips() {
        let batch = create_test_batch();
        let formatter = OutputFormatter::new(OutputFormat::Raw);

        let mut output = Vec::new();
        formatter.write(&batch, &mut output).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "192.168.1.1\t8.8.8.8\t42\t443\n10.0.0.1\t8.8.4.4\t100\t80\n"
        );
    }

    #[test]
    fn test_raw_output_keeps_text_verbatim() {
        let schema = Schema::new(vec![Field::new("h", DataType::Utf8, true)]);
        let text = StringArray::from(vec![Some("a, \"b\"\n  c\n"), None, Some("d")]);
        let batch = RecordBatch::try_new(Arc::new(schema), vec![Arc::new(text)]).unwrap();
        let formatter = OutputFormatter::new(OutputFormat::Raw);

        let mut output = Vec::new();
        formatter
            .write_batches(&[batch.clone(), batch], &mut output)
            .unwrap();

        // No quoting, no extra newline after a value that ends in one, and a
        // null prints as an empty line.
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "a, \"b\"\n  c\n\nd\na, \"b\"\n  c\n\nd\n"
        );
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
