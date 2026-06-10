//! Time UDFs bound to the capture's observed time range.
//!
//! `start_time()`, `end_time()` and `relative_time(ts)` read a shared
//! [`CaptureTimeRange`] at invocation time. The engine widens the range as
//! parse passes observe packets, so the UDFs return correct values for any
//! query whose execution follows a parse of the frames it touches — without
//! requiring an up-front full scan at engine open.
//!
//! Until the first parse pass completes, the range is unknown and the UDFs
//! return the Unix epoch / 0. The boundary-index integration (migration
//! phase P6) will pre-populate the range at open for indexed sources.

use std::any::Any;
use std::fmt::Debug;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use arrow::array::{Array, Float64Array, TimestampMicrosecondArray};
use arrow::datatypes::{DataType, TimeUnit};
use datafusion::common::{Result as DFResult, ScalarValue};
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, TypeSignature,
    Volatility,
};

/// The capture's observed `[start, end]` timestamp range (microseconds since
/// the Unix epoch), widened monotonically as parse passes observe packets.
#[derive(Debug)]
pub struct CaptureTimeRange {
    /// `i64::MAX` sentinel = no packet observed yet.
    start_us: AtomicI64,
    /// `i64::MIN` sentinel = no packet observed yet.
    end_us: AtomicI64,
}

impl Default for CaptureTimeRange {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureTimeRange {
    pub fn new() -> Self {
        Self {
            start_us: AtomicI64::new(i64::MAX),
            end_us: AtomicI64::new(i64::MIN),
        }
    }

    /// Widen the range with an observed `[start, end]` (microseconds).
    pub fn record(&self, start_us: i64, end_us: i64) {
        self.start_us.fetch_min(start_us, Ordering::Relaxed);
        self.end_us.fetch_max(end_us, Ordering::Relaxed);
    }

    /// Observed capture start (0 until any packet has been seen).
    pub fn start_us(&self) -> i64 {
        match self.start_us.load(Ordering::Relaxed) {
            i64::MAX => 0,
            v => v,
        }
    }

    /// Observed capture end (0 until any packet has been seen).
    pub fn end_us(&self) -> i64 {
        match self.end_us.load(Ordering::Relaxed) {
            i64::MIN => 0,
            v => v,
        }
    }
}

// ============================================================================
// start_time() UDF - Returns capture start timestamp
// ============================================================================

/// Create the `start_time()` UDF returning the capture start timestamp.
///
/// # Example
/// ```sql
/// SELECT start_time();
/// ```
pub fn create_start_time_udf(range: Arc<CaptureTimeRange>) -> ScalarUDF {
    ScalarUDF::new_from_impl(StartTimeUdf::new(range))
}

#[derive(Debug)]
struct StartTimeUdf {
    signature: Signature,
    range: Arc<CaptureTimeRange>,
}

impl StartTimeUdf {
    fn new(range: Arc<CaptureTimeRange>) -> Self {
        Self {
            signature: Signature::new(TypeSignature::Nullary, Volatility::Stable),
            range,
        }
    }
}

// ScalarUDFImpl requires Eq + Hash; identity is the shared range pointer.
impl PartialEq for StartTimeUdf {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.range, &other.range)
    }
}

impl Eq for StartTimeUdf {}

impl std::hash::Hash for StartTimeUdf {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "StartTimeUdf".hash(state);
        Arc::as_ptr(&self.range).hash(state);
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
            Some(self.range.start_us()),
            None,
        )))
    }
}

// ============================================================================
// end_time() UDF - Returns capture end timestamp
// ============================================================================

/// Create the `end_time()` UDF returning the capture end timestamp.
///
/// # Example
/// ```sql
/// SELECT end_time();
/// ```
pub fn create_end_time_udf(range: Arc<CaptureTimeRange>) -> ScalarUDF {
    ScalarUDF::new_from_impl(EndTimeUdf::new(range))
}

#[derive(Debug)]
struct EndTimeUdf {
    signature: Signature,
    range: Arc<CaptureTimeRange>,
}

impl EndTimeUdf {
    fn new(range: Arc<CaptureTimeRange>) -> Self {
        Self {
            signature: Signature::new(TypeSignature::Nullary, Volatility::Stable),
            range,
        }
    }
}

// ScalarUDFImpl requires Eq + Hash; identity is the shared range pointer.
impl PartialEq for EndTimeUdf {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.range, &other.range)
    }
}

impl Eq for EndTimeUdf {}

impl std::hash::Hash for EndTimeUdf {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "EndTimeUdf".hash(state);
        Arc::as_ptr(&self.range).hash(state);
    }
}

impl ScalarUDFImpl for EndTimeUdf {
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
            Some(self.range.end_us()),
            None,
        )))
    }
}

// ============================================================================
// relative_time(timestamp) UDF - Returns seconds from capture start
// ============================================================================

/// Create the `relative_time(timestamp)` UDF returning seconds from capture
/// start.
///
/// # Example
/// ```sql
/// SELECT frame_number, relative_time(timestamp) AS rel_time FROM frames;
/// SELECT * FROM tcp WHERE relative_time(timestamp) < 10.0;
/// ```
pub fn create_relative_time_udf(range: Arc<CaptureTimeRange>) -> ScalarUDF {
    ScalarUDF::new_from_impl(RelativeTimeUdf::new(range))
}

#[derive(Debug)]
struct RelativeTimeUdf {
    signature: Signature,
    range: Arc<CaptureTimeRange>,
}

impl RelativeTimeUdf {
    fn new(range: Arc<CaptureTimeRange>) -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Timestamp(TimeUnit::Microsecond, None)],
                Volatility::Stable,
            ),
            range,
        }
    }
}

// ScalarUDFImpl requires Eq + Hash; identity is the shared range pointer.
impl PartialEq for RelativeTimeUdf {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.range, &other.range)
    }
}

impl Eq for RelativeTimeUdf {}

impl std::hash::Hash for RelativeTimeUdf {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "RelativeTimeUdf".hash(state);
        Arc::as_ptr(&self.range).hash(state);
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

        let start_us = self.range.start_us();
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

    fn range_with(start_us: i64, end_us: i64) -> Arc<CaptureTimeRange> {
        let range = Arc::new(CaptureTimeRange::new());
        range.record(start_us, end_us);
        range
    }

    #[test]
    fn test_range_unknown_defaults_to_epoch() {
        let range = CaptureTimeRange::new();
        assert_eq!(range.start_us(), 0);
        assert_eq!(range.end_us(), 0);
    }

    #[test]
    fn test_range_widens_monotonically() {
        let range = CaptureTimeRange::new();
        range.record(100, 200);
        range.record(150, 300);
        range.record(50, 180);
        assert_eq!(range.start_us(), 50);
        assert_eq!(range.end_us(), 300);
    }

    #[tokio::test]
    async fn test_start_time_udf() {
        let ctx = SessionContext::new();
        let start_us: i64 = 1_704_067_200_000_000; // 2024-01-01 00:00:00 UTC
        ctx.register_udf(create_start_time_udf(range_with(
            start_us,
            start_us + 1_000_000,
        )));

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
    async fn test_end_time_udf() {
        let ctx = SessionContext::new();
        let end_us: i64 = 1_704_153_600_000_000; // 2024-01-02 00:00:00 UTC
        ctx.register_udf(create_end_time_udf(range_with(end_us - 1_000_000, end_us)));

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
    async fn test_end_time_udf_sees_late_updates() {
        // The range can be populated AFTER registration (a parse pass that
        // runs between planning and execution) — the UDF must see it.
        let ctx = SessionContext::new();
        let range = Arc::new(CaptureTimeRange::new());
        ctx.register_udf(create_end_time_udf(range.clone()));

        let end_us: i64 = 1_704_153_600_000_000;
        range.record(end_us - 5_000_000, end_us);

        let result = ctx
            .sql("SELECT end_time()")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let ts_array = result[0]
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
        ctx.register_udf(create_relative_time_udf(range_with(
            start_us,
            start_us + 10_000_000,
        )));

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
        ctx.register_udf(create_relative_time_udf(range_with(
            start_us,
            start_us + 12_000_000,
        )));

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
