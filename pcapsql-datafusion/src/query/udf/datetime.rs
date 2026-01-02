//! DateTime formatting and conversion UDFs.
//!
//! Provides functions for formatting and manipulating packet timestamps:
//!
//! - `strftime(format, timestamp)` - Format timestamp using strftime codes
//! - `datetime(timestamp)` - Convert to ISO 8601 datetime string
//! - `date(timestamp)` - Extract date (YYYY-MM-DD)
//! - `time(timestamp)` - Extract time (HH:MM:SS.ffffff)
//! - `epoch(timestamp)` - Convert to Unix epoch seconds (Float64)
//! - `epoch_ms(timestamp)` - Convert to Unix epoch milliseconds (Int64)
//!
//! ## Example Queries
//!
//! ```sql
//! -- Format with strftime
//! SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp) FROM frames;
//!
//! -- Get ISO 8601 datetime
//! SELECT datetime(timestamp) FROM frames;
//!
//! -- Extract date and time parts
//! SELECT date(timestamp), time(timestamp) FROM frames;
//!
//! -- Convert to epoch for calculations
//! SELECT epoch(timestamp) AS unix_ts FROM frames;
//! ```

use std::any::Any;
use std::sync::Arc;

use arrow::array::{Array, Float64Array, Int64Array, StringArray, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, TimeUnit};
use chrono::{TimeZone, Utc};
use datafusion::common::Result as DFResult;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};

// ============================================================================
// strftime(format, timestamp) UDF - Format timestamp using strftime codes
// ============================================================================

/// Create the `strftime(format, timestamp)` UDF.
///
/// # Example
/// ```sql
/// SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp) FROM frames;
/// SELECT strftime('%H:%M', timestamp) AS hour_minute FROM frames;
/// ```
pub fn create_strftime_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(StrftimeUdf::new())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct StrftimeUdf {
    signature: Signature,
}

impl StrftimeUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![
                    DataType::Utf8,
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                ],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for StrftimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "strftime"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;

        let format_array = args[0]
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("strftime: expected string format");

        let timestamps = args[1]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("strftime: expected timestamp array");

        let result: StringArray = format_array
            .iter()
            .zip(timestamps.iter())
            .map(|(format_opt, ts_opt)| match (format_opt, ts_opt) {
                (Some(format), Some(ts_us)) => {
                    let dt = Utc.timestamp_micros(ts_us).single();
                    dt.map(|d| d.format(format).to_string())
                }
                _ => None,
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// datetime(timestamp) UDF - ISO 8601 datetime string
// ============================================================================

/// Create the `datetime(timestamp)` UDF.
///
/// Returns ISO 8601 format: YYYY-MM-DDTHH:MM:SS.ffffff
///
/// # Example
/// ```sql
/// SELECT datetime(timestamp) FROM frames;
/// ```
pub fn create_datetime_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(DatetimeUdf::new())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct DatetimeUdf {
    signature: Signature,
}

impl DatetimeUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for DatetimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "datetime"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;

        let timestamps = args[0]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("datetime: expected timestamp array");

        let result: StringArray = timestamps
            .iter()
            .map(|ts_opt| {
                ts_opt.and_then(|ts_us| {
                    Utc.timestamp_micros(ts_us)
                        .single()
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.6f").to_string())
                })
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// date(timestamp) UDF - Extract date part
// ============================================================================

/// Create the `date(timestamp)` UDF.
///
/// Returns date in YYYY-MM-DD format.
///
/// # Example
/// ```sql
/// SELECT date(timestamp), COUNT(*) FROM frames GROUP BY date(timestamp);
/// ```
pub fn create_date_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(DateUdf::new())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct DateUdf {
    signature: Signature,
}

impl DateUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for DateUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "date"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;

        let timestamps = args[0]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("date: expected timestamp array");

        let result: StringArray = timestamps
            .iter()
            .map(|ts_opt| {
                ts_opt.and_then(|ts_us| {
                    Utc.timestamp_micros(ts_us)
                        .single()
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                })
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// time(timestamp) UDF - Extract time part
// ============================================================================

/// Create the `time(timestamp)` UDF.
///
/// Returns time in HH:MM:SS.ffffff format.
///
/// # Example
/// ```sql
/// SELECT time(timestamp) FROM frames;
/// ```
pub fn create_time_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(TimeUdf::new())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct TimeUdf {
    signature: Signature,
}

impl TimeUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for TimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "time"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;

        let timestamps = args[0]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("time: expected timestamp array");

        let result: StringArray = timestamps
            .iter()
            .map(|ts_opt| {
                ts_opt.and_then(|ts_us| {
                    Utc.timestamp_micros(ts_us)
                        .single()
                        .map(|dt| dt.format("%H:%M:%S%.6f").to_string())
                })
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// epoch(timestamp) UDF - Unix epoch seconds
// ============================================================================

/// Create the `epoch(timestamp)` UDF.
///
/// Returns Unix epoch seconds as Float64 (with microsecond precision).
///
/// # Example
/// ```sql
/// SELECT epoch(timestamp) FROM frames;
/// SELECT * FROM frames WHERE epoch(timestamp) > 1704067200;
/// ```
pub fn create_epoch_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(EpochUdf::new())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct EpochUdf {
    signature: Signature,
}

impl EpochUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for EpochUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "epoch"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Float64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;

        let timestamps = args[0]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("epoch: expected timestamp array");

        let result: Float64Array = timestamps
            .iter()
            .map(|ts_opt| ts_opt.map(|ts_us| ts_us as f64 / 1_000_000.0))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ============================================================================
// epoch_ms(timestamp) UDF - Unix epoch milliseconds
// ============================================================================

/// Create the `epoch_ms(timestamp)` UDF.
///
/// Returns Unix epoch milliseconds as Int64.
///
/// # Example
/// ```sql
/// SELECT epoch_ms(timestamp) FROM frames;
/// ```
pub fn create_epoch_ms_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(EpochMsUdf::new())
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct EpochMsUdf {
    signature: Signature,
}

impl EpochMsUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for EpochMsUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "epoch_ms"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Int64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;

        let timestamps = args[0]
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .expect("epoch_ms: expected timestamp array");

        let result: Int64Array = timestamps
            .iter()
            .map(|ts_opt| ts_opt.map(|ts_us| ts_us / 1_000))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::TimestampMicrosecondArray;
    use datafusion::prelude::*;

    // 2024-01-01 12:34:56.789012 UTC
    const TEST_TIMESTAMP_US: i64 = 1_704_112_496_789_012;

    fn create_test_context() -> (SessionContext, i64) {
        let ctx = SessionContext::new();
        (ctx, TEST_TIMESTAMP_US)
    }

    async fn setup_test_table(ctx: &SessionContext, ts_us: i64) {
        let timestamps = TimestampMicrosecondArray::from(vec![
            ts_us,
            ts_us + 1_000_000,  // +1 second
            ts_us + 60_000_000, // +1 minute
        ]);

        let batch = arrow::array::RecordBatch::try_new(
            Arc::new(arrow::datatypes::Schema::new(vec![
                arrow::datatypes::Field::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    false,
                ),
            ])),
            vec![Arc::new(timestamps)],
        )
        .unwrap();

        ctx.register_batch("test_data", batch).unwrap();
    }

    #[tokio::test]
    async fn test_strftime_udf() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_strftime_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT strftime('%Y-%m-%d', ts) AS formatted FROM test_data")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let formatted = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        assert_eq!(formatted.value(0), "2024-01-01");
    }

    #[tokio::test]
    async fn test_strftime_time_format() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_strftime_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT strftime('%H:%M:%S', ts) AS time_str FROM test_data LIMIT 1")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let time_str = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        assert_eq!(time_str.value(0), "12:34:56");
    }

    #[tokio::test]
    async fn test_datetime_udf() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_datetime_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT datetime(ts) AS dt FROM test_data LIMIT 1")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let dt = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        assert_eq!(dt.value(0), "2024-01-01T12:34:56.789012");
    }

    #[tokio::test]
    async fn test_date_udf() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_date_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT date(ts) AS d FROM test_data LIMIT 1")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let d = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        assert_eq!(d.value(0), "2024-01-01");
    }

    #[tokio::test]
    async fn test_time_udf() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_time_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT time(ts) AS t FROM test_data LIMIT 1")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let t = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        assert_eq!(t.value(0), "12:34:56.789012");
    }

    #[tokio::test]
    async fn test_epoch_udf() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_epoch_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT epoch(ts) AS e FROM test_data LIMIT 1")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let e = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();

        // Should be ts_us / 1_000_000.0
        let expected = ts_us as f64 / 1_000_000.0;
        assert!((e.value(0) - expected).abs() < 0.000001);
    }

    #[tokio::test]
    async fn test_epoch_ms_udf() {
        let (ctx, ts_us) = create_test_context();
        ctx.register_udf(create_epoch_ms_udf());
        setup_test_table(&ctx, ts_us).await;

        let result = ctx
            .sql("SELECT epoch_ms(ts) AS ms FROM test_data LIMIT 1")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let ms = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();

        // Should be ts_us / 1_000
        assert_eq!(ms.value(0), ts_us / 1_000);
    }

    #[tokio::test]
    async fn test_null_handling() {
        let ctx = SessionContext::new();
        ctx.register_udf(create_datetime_udf());

        let timestamps = TimestampMicrosecondArray::from(vec![
            Some(TEST_TIMESTAMP_US),
            None,
            Some(TEST_TIMESTAMP_US + 1_000_000),
        ]);

        let batch = arrow::array::RecordBatch::try_new(
            Arc::new(arrow::datatypes::Schema::new(vec![
                arrow::datatypes::Field::new(
                    "ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    true,
                ),
            ])),
            vec![Arc::new(timestamps)],
        )
        .unwrap();

        ctx.register_batch("test_data", batch).unwrap();

        let result = ctx
            .sql("SELECT datetime(ts) AS dt FROM test_data")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let dt = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        assert!(!dt.is_null(0));
        assert!(dt.is_null(1));
        assert!(!dt.is_null(2));
    }
}
