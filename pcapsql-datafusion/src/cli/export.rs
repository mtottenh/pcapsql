//! Export functionality for query results.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

use arrow::array::RecordBatch;
use arrow::datatypes::Schema;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use super::ExportFormat;

/// Exports query results to various file formats.
pub struct Exporter;

impl Exporter {
    /// Export RecordBatches to a file.
    pub fn export<P: AsRef<Path>>(
        path: P,
        format: ExportFormat,
        batches: &[RecordBatch],
    ) -> std::io::Result<usize> {
        if batches.is_empty() {
            return Ok(0);
        }

        let schema = batches[0].schema();
        let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();

        match format {
            ExportFormat::Parquet => Self::export_parquet(path.as_ref(), schema, batches)?,
            ExportFormat::Json => Self::export_json(path.as_ref(), batches)?,
            ExportFormat::Csv => Self::export_csv(path.as_ref(), batches)?,
        }

        Ok(total_rows)
    }

    /// Export to Parquet format.
    fn export_parquet(
        path: &Path,
        schema: Arc<Schema>,
        batches: &[RecordBatch],
    ) -> std::io::Result<()> {
        let file = File::create(path)?;

        // Configure Parquet writer with Snappy compression
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();

        let mut writer = ArrowWriter::try_new(file, schema, Some(props))
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        for batch in batches {
            writer
                .write(batch)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }

        writer
            .close()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        Ok(())
    }

    /// Export to JSON Lines format.
    fn export_json(path: &Path, batches: &[RecordBatch]) -> std::io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        for batch in batches {
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
        }

        writer.flush()?;
        Ok(())
    }

    /// Export to CSV format.
    fn export_csv(path: &Path, batches: &[RecordBatch]) -> std::io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        let mut header_written = false;

        for batch in batches {
            let schema = batch.schema();

            // Write header once
            if !header_written {
                let headers: Vec<&str> =
                    schema.fields().iter().map(|f| f.name().as_str()).collect();
                writeln!(writer, "{}", headers.join(","))?;
                header_written = true;
            }

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
        }

        writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int32Array, StringArray};
    use arrow::datatypes::{DataType, Field};
    use tempfile::tempdir;

    fn create_test_batch() -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
        ]));

        let id_array = Int32Array::from(vec![1, 2, 3]);
        let name_array = StringArray::from(vec![Some("Alice"), Some("Bob"), None]);

        RecordBatch::try_new(
            schema,
            vec![Arc::new(id_array), Arc::new(name_array)],
        )
        .unwrap()
    }

    #[test]
    fn test_export_csv() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.csv");

        let batch = create_test_batch();
        let result = Exporter::export(&path, ExportFormat::Csv, &[batch]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("id,name"));
        assert!(content.contains("1,Alice"));
        assert!(content.contains("2,Bob"));
    }

    #[test]
    fn test_export_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let batch = create_test_batch();
        let result = Exporter::export(&path, ExportFormat::Json, &[batch]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"id\":1"));
        assert!(content.contains("\"name\":\"Alice\""));
    }

    #[test]
    fn test_export_parquet() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.parquet");

        let batch = create_test_batch();
        let result = Exporter::export(&path, ExportFormat::Parquet, &[batch]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        // Verify file was created
        assert!(path.exists());
        assert!(path.metadata().unwrap().len() > 0);
    }

    #[test]
    fn test_export_empty_batches() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.csv");

        let result = Exporter::export(&path, ExportFormat::Csv, &[]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_export_format_from_extension() {
        assert_eq!(
            ExportFormat::from_extension(&std::path::PathBuf::from("test.parquet")),
            Some(ExportFormat::Parquet)
        );
        assert_eq!(
            ExportFormat::from_extension(&std::path::PathBuf::from("test.pq")),
            Some(ExportFormat::Parquet)
        );
        assert_eq!(
            ExportFormat::from_extension(&std::path::PathBuf::from("test.json")),
            Some(ExportFormat::Json)
        );
        assert_eq!(
            ExportFormat::from_extension(&std::path::PathBuf::from("test.jsonl")),
            Some(ExportFormat::Json)
        );
        assert_eq!(
            ExportFormat::from_extension(&std::path::PathBuf::from("test.csv")),
            Some(ExportFormat::Csv)
        );
        assert_eq!(
            ExportFormat::from_extension(&std::path::PathBuf::from("test.txt")),
            None
        );
    }

    #[test]
    fn test_csv_escaping() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.csv");

        let schema = Arc::new(Schema::new(vec![
            Field::new("text", DataType::Utf8, true),
        ]));

        let text_array = StringArray::from(vec![
            Some("hello, world"),
            Some("quote \"test\""),
            Some("normal"),
        ]);

        let batch = RecordBatch::try_new(schema, vec![Arc::new(text_array)]).unwrap();
        Exporter::export(&path, ExportFormat::Csv, &[batch]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        // Commas should be quoted
        assert!(content.contains("\"hello, world\""));
        // Quotes should be escaped
        assert!(content.contains("\"quote \"\"test\"\"\""));
    }
}
