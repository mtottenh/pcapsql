//! Output formatting for query results.

use arrow::array::RecordBatch;
use clap::ValueEnum;
use std::io::Write;

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

    fn write_table<W: Write>(&self, batch: &RecordBatch, writer: &mut W) -> std::io::Result<()> {
        use comfy_table::{Cell, Table};

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
            for col_idx in 0..batch.num_columns() {
                let col = batch.column(col_idx);
                let value = arrow::util::display::array_value_to_string(col, row_idx)
                    .unwrap_or_else(|_| "?".to_string());
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

        // Write rows
        for row_idx in 0..batch.num_rows() {
            let mut values = Vec::with_capacity(batch.num_columns());
            for col_idx in 0..batch.num_columns() {
                let col = batch.column(col_idx);
                let value = arrow::util::display::array_value_to_string(col, row_idx)
                    .unwrap_or_else(|_| "".to_string());
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

        for row_idx in 0..batch.num_rows() {
            let mut obj = serde_json::Map::new();
            for (col_idx, field) in schema.fields().iter().enumerate() {
                let col = batch.column(col_idx);
                let value = arrow::util::display::array_value_to_string(col, row_idx)
                    .unwrap_or_else(|_| "null".to_string());

                // Try to parse as number or boolean, otherwise use string
                let json_value = if value == "null" {
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
                };

                obj.insert(field.name().clone(), json_value);
            }

            writeln!(writer, "{}", serde_json::Value::Object(obj))?;
        }

        Ok(())
    }
}
