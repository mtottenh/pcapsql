//! Time-related UDFs for capture time analysis.
//!
//! Provides functions for working with packet timestamps relative to capture timing:
//!
//! - `start_time()` - Returns the capture start timestamp
//! - `end_time()` - Returns the capture end timestamp
//! - `relative_time(timestamp)` - Returns seconds from capture start as Float64
//!
//! ## Example Queries
//!
//! ```sql
//! -- Get capture time range
//! SELECT start_time(), end_time();
//!
//! -- Filter to first 10 seconds of capture
//! SELECT * FROM tcp WHERE relative_time(timestamp) < 10.0;
//!
//! -- Show relative timestamps
//! SELECT frame_number, relative_time(timestamp) AS rel_time FROM frames;
//! ```

use std::any::Any;
use std::fmt::Debug;
use std::sync::{Arc, OnceLock};

use arrow::array::{Array, Float64Array, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, TimeUnit};
use datafusion::common::{Result as DFResult, ScalarValue};
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, TypeSignature,
    Volatility,
};

// ============================================================================
// start_time() UDF - Returns capture start timestamp
// ============================================================================

/// Create the `start_time()` UDF that returns the capture start timestamp.
///
/// # Example
/// ```sql
/// SELECT start_time();
/// ```
pub fn create_start_time_udf(start_us: i64) -> ScalarUDF {
    ScalarUDF::new_from_impl(StartTimeUdf::new(start_us))
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct StartTimeUdf {
    signature: Signature,
    start_timestamp_us: i64,
}

impl StartTimeUdf {
    fn new(start_us: i64) -> Self {
        Self {
            signature: Signature::new(TypeSignature::Nullary, Volatility::Stable),
            start_timestamp_us: start_us,
        }
    }
}

impl ScalarUDFImpl for StartTimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "start_time"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Timestamp(TimeUnit::Microsecond, None))
    }

    fn invoke_with_args(&self, _args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        Ok(ColumnarValue::Scalar(ScalarValue::TimestampMicrosecond(
            Some(self.start_timestamp_us),
            None,
        )))
    }
}

// ============================================================================
// end_time() UDF - Eager version (timestamp known at registration)
// ============================================================================

/// Create the `end_time()` UDF with a known end timestamp (eager mode).
///
/// Used in in-memory mode where all packets have been loaded.
pub fn create_end_time_udf_eager(end_us: i64) -> ScalarUDF {
    ScalarUDF::new_from_impl(EagerEndTimeUdf::new(end_us))
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct EagerEndTimeUdf {
    signature: Signature,
    end_timestamp_us: i64,
}

impl EagerEndTimeUdf {
    fn new(end_us: i64) -> Self {
        Self {
            signature: Signature::new(TypeSignature::Nullary, Volatility::Stable),
            end_timestamp_us: end_us,
        }
    }
}

impl ScalarUDFImpl for EagerEndTimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "end_time"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Timestamp(TimeUnit::Microsecond, None))
    }

    fn invoke_with_args(&self, _args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        Ok(ColumnarValue::Scalar(ScalarValue::TimestampMicrosecond(
            Some(self.end_timestamp_us),
            None,
        )))
    }
}

// ============================================================================
// end_time() UDF - Lazy version (scans on first call)
// ============================================================================

/// Create the `end_time()` UDF with lazy evaluation (streaming mode).
///
/// The scan function is called on the first invocation and cached.
/// This avoids scanning the entire file if end_time() is never called.
pub fn create_end_time_udf_lazy<F>(scan_fn: F) -> ScalarUDF
where
    F: Fn() -> i64 + Send + Sync + 'static,
{
    ScalarUDF::new_from_impl(LazyEndTimeUdf::new(scan_fn))
}

struct LazyEndTimeUdf {
    signature: Signature,
    /// Closure that scans for last timestamp (captures Arc<Source>)
    scan_fn: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Cached result (computed on first call)
    end_ts: OnceLock<i64>,
}

impl LazyEndTimeUdf {
    fn new<F>(scan_fn: F) -> Self
    where
        F: Fn() -> i64 + Send + Sync + 'static,
    {
        Self {
            signature: Signature::new(TypeSignature::Nullary, Volatility::Stable),
            scan_fn: Arc::new(scan_fn),
            end_ts: OnceLock::new(),
        }
    }

    fn get_end_timestamp(&self) -> i64 {
        *self.end_ts.get_or_init(|| (self.scan_fn)())
    }
}

impl Debug for LazyEndTimeUdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyEndTimeUdf")
            .field("end_ts", &self.end_ts)
            .finish()
    }
}

// Manual implementations since closures can't be derived
impl PartialEq for LazyEndTimeUdf {
    fn eq(&self, other: &Self) -> bool {
        // Two LazyEndTimeUdfs are equal if they have the same cached value
        // (or both are uncached). The closures are considered equivalent.
        self.end_ts.get() == other.end_ts.get()
    }
}

impl Eq for LazyEndTimeUdf {}

impl std::hash::Hash for LazyEndTimeUdf {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash based on the name and any cached value
        "LazyEndTimeUdf".hash(state);
        self.end_ts.get().hash(state);
    }
}

impl ScalarUDFImpl for LazyEndTimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "end_time"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Timestamp(TimeUnit::Microsecond, None))
    }

    fn invoke_with_args(&self, _args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let end_us = self.get_end_timestamp();
        Ok(ColumnarValue::Scalar(ScalarValue::TimestampMicrosecond(
            Some(end_us),
            None,
        )))
    }
}

// ============================================================================
// relative_time(timestamp) UDF - Returns seconds from capture start
// ============================================================================

/// Create the `relative_time(timestamp)` UDF that returns seconds from capture start.
///
/// # Example
/// ```sql
/// SELECT frame_number, relative_time(timestamp) AS rel_time FROM frames;
/// SELECT * FROM tcp WHERE relative_time(timestamp) < 10.0;
/// ```
pub fn create_relative_time_udf(start_us: i64) -> ScalarUDF {
    ScalarUDF::new_from_impl(RelativeTimeUdf::new(start_us))
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct RelativeTimeUdf {
    signature: Signature,
    start_timestamp_us: i64,
}

impl RelativeTimeUdf {
    fn new(start_us: i64) -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Stable,
            ),
            start_timestamp_us: start_us,
        }
    }
}

impl ScalarUDFImpl for RelativeTimeUdf {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "relative_time"
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
            .expect("relative_time: expected timestamp array");

        let start_us = self.start_timestamp_us;
        let result: Float64Array = timestamps
            .iter()
            .map(|opt| opt.map(|ts| (ts - start_us) as f64 / 1_000_000.0))
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::TimestampMicrosecondArray;
    use datafusion::prelude::*;

    #[tokio::test]
    async fn test_start_time_udf() {
        let ctx = SessionContext::new();
        let start_us: i64 = 1_704_067_200_000_000; // 2024-01-01 00:00:00 UTC
        ctx.register_udf(create_start_time_udf(start_us));

        let result = ctx
            .sql("SELECT start_time()")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        let batch = &result[0];
        assert_eq!(batch.num_rows(), 1);

        let ts_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts_array.value(0), start_us);
    }

    #[tokio::test]
    async fn test_end_time_udf_eager() {
        let ctx = SessionContext::new();
        let end_us: i64 = 1_704_153_600_000_000; // 2024-01-02 00:00:00 UTC
        ctx.register_udf(create_end_time_udf_eager(end_us));

        let result = ctx
            .sql("SELECT end_time()")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        let batch = &result[0];
        let ts_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts_array.value(0), end_us);
    }

    #[tokio::test]
    async fn test_end_time_udf_lazy() {
        let ctx = SessionContext::new();
        let end_us: i64 = 1_704_153_600_000_000;

        // Lazy version with closure
        let scan_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let scan_called_clone = scan_called.clone();
        ctx.register_udf(create_end_time_udf_lazy(move || {
            scan_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            end_us
        }));

        // Scan should not be called until we query
        assert!(!scan_called.load(std::sync::atomic::Ordering::SeqCst));

        let result = ctx
            .sql("SELECT end_time()")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        // Now scan should have been called
        assert!(scan_called.load(std::sync::atomic::Ordering::SeqCst));

        let batch = &result[0];
        let ts_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts_array.value(0), end_us);
    }

    #[tokio::test]
    async fn test_relative_time_udf() {
        let ctx = SessionContext::new();
        let start_us: i64 = 1_704_067_200_000_000; // 2024-01-01 00:00:00 UTC
        ctx.register_udf(create_relative_time_udf(start_us));

        // Create a test table with timestamps
        let timestamps = TimestampMicrosecondArray::from(vec![
            start_us,              // 0.0 seconds
            start_us + 1_000_000,  // 1.0 seconds
            start_us + 5_500_000,  // 5.5 seconds
            start_us + 10_000_000, // 10.0 seconds
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

        let result = ctx
            .sql("SELECT relative_time(ts) AS rel FROM test_data")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let batch = &result[0];
        let rel_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();

        assert!((rel_array.value(0) - 0.0).abs() < 0.001);
        assert!((rel_array.value(1) - 1.0).abs() < 0.001);
        assert!((rel_array.value(2) - 5.5).abs() < 0.001);
        assert!((rel_array.value(3) - 10.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_relative_time_filter() {
        let ctx = SessionContext::new();
        let start_us: i64 = 1_704_067_200_000_000;
        ctx.register_udf(create_relative_time_udf(start_us));

        let timestamps = TimestampMicrosecondArray::from(vec![
            start_us,              // 0.0 seconds
            start_us + 3_000_000,  // 3.0 seconds
            start_us + 7_000_000,  // 7.0 seconds
            start_us + 12_000_000, // 12.0 seconds
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

        // Filter to first 5 seconds
        let result = ctx
            .sql("SELECT * FROM test_data WHERE relative_time(ts) < 5.0")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        // Should get 2 rows (0.0 and 3.0 seconds)
        let total_rows: usize = result.iter().map(|b| b.num_rows()).sum();
        assert_eq!(total_rows, 2);
    }
}
