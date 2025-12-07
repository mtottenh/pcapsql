//! NTP table schema definition.
//!
//! The `ntp` table contains NTP (Network Time Protocol) fields.

use arrow::datatypes::{DataType, Field, Schema};

/// Build the schema for the `ntp` table.
///
/// Fields:
/// - `frame_number`: Reference to frames table
/// - `version`: NTP version (3 or 4)
/// - `mode`: Mode (1-7: symmetric, client, server, broadcast, etc.)
/// - `leap_indicator`: Leap indicator (0-3)
/// - `stratum`: Stratum level (0-15)
/// - `poll`: Poll interval exponent
/// - `precision`: Clock precision exponent
/// - `root_delay`: Root delay (seconds as f64)
/// - `root_dispersion`: Root dispersion (seconds as f64)
/// - `reference_id`: Reference identifier
/// - `reference_ts`: Reference timestamp
/// - `origin_ts`: Origin timestamp
/// - `receive_ts`: Receive timestamp
/// - `transmit_ts`: Transmit timestamp
pub fn ntp_table_schema() -> Schema {
    Schema::new(vec![
        Field::new("frame_number", DataType::UInt64, false),
        Field::new("version", DataType::UInt8, true),
        Field::new("mode", DataType::UInt8, true),
        Field::new("leap_indicator", DataType::UInt8, true),
        Field::new("stratum", DataType::UInt8, true),
        Field::new("poll", DataType::Int8, true),
        Field::new("precision", DataType::Int8, true),
        Field::new("root_delay", DataType::Float64, true),
        Field::new("root_dispersion", DataType::Float64, true),
        Field::new("reference_id", DataType::Utf8, true),
        Field::new("reference_ts", DataType::Float64, true),
        Field::new("origin_ts", DataType::Float64, true),
        Field::new("receive_ts", DataType::Float64, true),
        Field::new("transmit_ts", DataType::Float64, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_schema() {
        let schema = ntp_table_schema();

        assert_eq!(schema.fields().len(), 14);
        assert!(schema.field_with_name("frame_number").is_ok());
        assert!(schema.field_with_name("version").is_ok());
        assert!(schema.field_with_name("mode").is_ok());
        assert!(schema.field_with_name("transmit_ts").is_ok());
    }

    #[test]
    fn test_no_protocol_prefix() {
        let schema = ntp_table_schema();
        for field in schema.fields() {
            assert!(
                !field.name().starts_with("ntp."),
                "Field '{}' should not have protocol prefix",
                field.name()
            );
        }
    }
}
