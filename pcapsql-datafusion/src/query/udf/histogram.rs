//! HdrHistogram UDAFs for streaming latency analysis.
//!
//! This module provides User Defined Aggregate Functions (UDAFs) built on
//! HdrHistogram for high-fidelity latency measurement with:
//!
//! - **Constant memory**: Fixed footprint regardless of data size
//! - **Streaming**: Values accumulated incrementally via `update_batch`
//! - **Mergeable**: Supports parallel execution via `merge_batch`
//! - **High precision**: Configurable significant figures (1-5)
//!
//! ## Aggregate Function
//!
//! - `hdr_histogram(value, [sigfigs])` - Build histogram, returns serialized bytes
//!
//! ## Scalar Extraction Functions
//!
//! - `hdr_percentile(hist, p)` - Extract percentile (0.0-1.0 or 0-100)
//! - `hdr_value_at_quantile(hist, q)` - Alias for hdr_percentile
//! - `hdr_count(hist)` - Total sample count
//! - `hdr_min(hist)` - Minimum recorded value
//! - `hdr_max(hist)` - Maximum recorded value
//! - `hdr_mean(hist)` - Mean of recorded values
//! - `hdr_stdev(hist)` - Standard deviation
//!
//! ## Distribution Functions
//!
//! - `hdr_buckets(hist)` - Log-scale bucket rows as `List<Struct<lo,hi,count>>`,
//!   to be exploded with `UNNEST` for machine-readable distribution tables
//! - `hdr_ascii(hist)` - Rendered ASCII histogram with cumulative % (CDF),
//!   for interactive inspection of the distribution shape
//!
//! ## Example Usage
//!
//! ```sql
//! -- Build histogram and extract multiple percentiles
//! WITH h AS (
//!     SELECT hdr_histogram(rtt_ms) as hist
//!     FROM tcp_rtt
//! )
//! SELECT
//!     hdr_percentile(hist, 0.50) as p50,
//!     hdr_percentile(hist, 0.99) as p99,
//!     hdr_percentile(hist, 0.999) as p999,
//!     hdr_count(hist) as samples,
//!     hdr_min(hist) as min_rtt,
//!     hdr_max(hist) as max_rtt
//! FROM h;
//!
//! -- With custom precision (3 significant figures)
//! SELECT hdr_histogram(latency_us, 3) as hist FROM measurements;
//! ```
//!
//! ## Serialization
//!
//! The histogram is serialized using HdrHistogram's V2 compressed format,
//! which is compact and suitable for storage or network transfer.
//!
//! ## Kernels
//!
//! What a histogram records, how it is merged and serialized, its
//! statistics, its buckets and its rendering are
//! `pcapsql_core::format::histogram`, which the DuckDB extension's
//! functions of the same names call too. What is here is the DataFusion
//! side: the accumulator, the arrays and the signatures.

use std::fmt::Debug;
use std::sync::Arc;

use arrow::array::{
    Array, ArrayBuilder, ArrayRef, BinaryArray, Float32Array, Float64Array, Int16Array, Int32Array,
    Int64Array, Int8Array, ListArray, StringArray, StructArray, UInt16Array, UInt32Array,
    UInt64Array, UInt64Builder, UInt8Array,
};
use arrow::buffer::{BooleanBuffer, NullBuffer, OffsetBuffer, ScalarBuffer};
use arrow::datatypes::{DataType, Field, Fields};
use datafusion::common::{Result as DFResult, ScalarValue};
use datafusion::logical_expr::{
    Accumulator, AggregateUDF, AggregateUDFImpl, ColumnarValue, ScalarFunctionArgs, ScalarUDF,
    ScalarUDFImpl, Signature, Volatility,
};
use pcapsql_core::format::histogram::{
    log_buckets, render_ascii, HdrHistogram, DEFAULT_SIGFIGS, MAX_BUCKETS,
};

// ============================================================================
// hdr_histogram() UDAF - Streaming Histogram Builder
// ============================================================================

/// Create the `hdr_histogram()` UDAF.
pub fn create_hdr_histogram_udaf() -> AggregateUDF {
    AggregateUDF::new_from_impl(HdrHistogramUdaf::new())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrHistogramUdaf {
    signature: Signature,
}

impl HdrHistogramUdaf {
    fn new() -> Self {
        Self {
            // Accept Float64 value, optional UInt8 sigfigs
            signature: Signature::variadic_any(Volatility::Immutable),
        }
    }
}

impl AggregateUDFImpl for HdrHistogramUdaf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_histogram"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        // Return serialized histogram as binary
        Ok(DataType::Binary)
    }

    fn accumulator(
        &self,
        _acc_args: datafusion::logical_expr::function::AccumulatorArgs,
    ) -> DFResult<Box<dyn Accumulator>> {
        Ok(Box::new(HdrHistogramAccumulator::new(DEFAULT_SIGFIGS)))
    }

    fn state_fields(
        &self,
        _args: datafusion::logical_expr::function::StateFieldsArgs,
    ) -> DFResult<Vec<Arc<Field>>> {
        // State is the serialized histogram
        Ok(vec![Arc::new(Field::new(
            "histogram_state",
            DataType::Binary,
            true,
        ))])
    }
}

/// Accumulator that streams values into an HdrHistogram.
///
/// This is the core of the streaming implementation:
/// - `update_batch`: Called incrementally with batches of values
/// - `state`: Serializes histogram for distributed merge
/// - `merge_batch`: Merges histograms from parallel workers
/// - `evaluate`: Returns final serialized histogram
#[derive(Debug)]
struct HdrHistogramAccumulator {
    histogram: HdrHistogram,
}

impl HdrHistogramAccumulator {
    fn new(sigfigs: u8) -> Self {
        // An auto-resizing histogram: any value can be recorded without
        // pre-specifying a maximum.
        let histogram = HdrHistogram::with_sigfigs(sigfigs).expect("valid sigfigs");
        Self { histogram }
    }

    fn serialize(&self) -> Vec<u8> {
        self.histogram.serialize().expect("histogram serialization")
    }

    fn deserialize(bytes: &[u8]) -> DFResult<HdrHistogram> {
        HdrHistogram::deserialize(bytes)
            .map_err(|e| datafusion::error::DataFusionError::Execution(e.to_string()))
    }
}

impl Accumulator for HdrHistogramAccumulator {
    /// Stream values into the histogram - called incrementally per batch.
    fn update_batch(&mut self, values: &[ArrayRef]) -> DFResult<()> {
        if values.is_empty() {
            return Ok(());
        }

        let values_array = &values[0];

        // Handle every numeric array type; anything else is ignored.
        // Note: floats are truncated and negative values are skipped (the
        // core kernels), so callers wanting sub-unit precision should
        // scale values before recording.
        macro_rules! record {
            ($array_ty:ty, $record:ident, $wide:ty) => {
                if let Some(a) = values_array.as_any().downcast_ref::<$array_ty>() {
                    for i in 0..a.len() {
                        if !a.is_null(i) {
                            self.histogram.$record(<$wide>::from(a.value(i)));
                        }
                    }
                    return Ok(());
                }
            };
        }

        record!(Float64Array, record_float, f64);
        record!(Float32Array, record_float, f64);
        record!(Int64Array, record_signed, i64);
        record!(Int32Array, record_signed, i64);
        record!(Int16Array, record_signed, i64);
        record!(Int8Array, record_signed, i64);
        record!(UInt64Array, record, u64);
        record!(UInt32Array, record, u64);
        record!(UInt16Array, record, u64);
        record!(UInt8Array, record, u64);
        // Silently ignore non-numeric types

        Ok(())
    }

    /// Merge histograms from parallel workers.
    fn merge_batch(&mut self, states: &[ArrayRef]) -> DFResult<()> {
        if states.is_empty() {
            return Ok(());
        }

        let state_array = states[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .ok_or_else(|| {
                datafusion::error::DataFusionError::Execution(
                    "Expected binary array for histogram state".to_string(),
                )
            })?;

        for i in 0..state_array.len() {
            if !state_array.is_null(i) {
                let bytes = state_array.value(i);
                if !bytes.is_empty() {
                    let other = Self::deserialize(bytes)?;
                    self.histogram.merge(&other).map_err(|e| {
                        datafusion::error::DataFusionError::Execution(e.to_string())
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Return intermediate state for distributed aggregation.
    fn state(&mut self) -> DFResult<Vec<ScalarValue>> {
        let bytes = self.serialize();
        Ok(vec![ScalarValue::Binary(Some(bytes))])
    }

    /// Return final serialized histogram.
    fn evaluate(&mut self) -> DFResult<ScalarValue> {
        let bytes = self.serialize();
        Ok(ScalarValue::Binary(Some(bytes)))
    }

    fn size(&self) -> usize {
        // Approximate memory size
        std::mem::size_of::<Self>() + (self.histogram.len() as usize) * 8
    }
}

// ============================================================================
// Scalar UDFs for extracting values from serialized histograms
// ============================================================================

/// Create the `hdr_percentile()` UDF.
pub fn create_hdr_percentile_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrPercentileUdf::new())
}

/// Create the `hdr_count()` UDF.
pub fn create_hdr_count_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrCountUdf::new())
}

/// Create the `hdr_min()` UDF.
pub fn create_hdr_min_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrMinUdf::new())
}

/// Create the `hdr_max()` UDF.
pub fn create_hdr_max_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrMaxUdf::new())
}

/// Create the `hdr_mean()` UDF.
pub fn create_hdr_mean_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrMeanUdf::new())
}

/// Create the `hdr_stdev()` UDF.
pub fn create_hdr_stdev_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrStdevUdf::new())
}

/// Create the `hdr_buckets()` UDF.
pub fn create_hdr_buckets_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrBucketsUdf::new())
}

/// Create the `hdr_ascii()` UDF.
pub fn create_hdr_ascii_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(HdrAsciiUdf::new())
}

// Helper to deserialize histogram from binary
fn deserialize_histogram(bytes: &[u8]) -> Option<HdrHistogram> {
    HdrHistogram::deserialize(bytes).ok()
}

/// Struct fields for a single bucket row.
fn bucket_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("lo", DataType::UInt64, false),
        Field::new("hi", DataType::UInt64, false),
        Field::new("count", DataType::UInt64, false),
    ])
}

/// Arrow type returned by `hdr_buckets`: list of (lo, hi, count) structs.
fn bucket_list_type() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(bucket_struct_fields()),
        true,
    )))
}

// ----------------------------------------------------------------------------
// hdr_percentile(hist, percentile) -> Float64
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrPercentileUdf {
    signature: Signature,
}

impl HdrPercentileUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(
                vec![DataType::Binary, DataType::Float64],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for HdrPercentileUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_percentile"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Float64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_percentile: expected binary array for histogram");
        let percentile_array = args[1]
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("hdr_percentile: expected float64 array for percentile");

        let result: Float64Array = hist_array
            .iter()
            .zip(percentile_array.iter())
            .map(|(hist_opt, p_opt)| {
                match (hist_opt, p_opt) {
                    (Some(bytes), Some(p)) => {
                        // Both the 0-1 and the 0-100 range are supported.
                        deserialize_histogram(bytes).map(|hist| hist.percentile(p))
                    }
                    _ => None,
                }
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_count(hist) -> UInt64
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrCountUdf {
    signature: Signature,
}

impl HdrCountUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrCountUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_count"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::UInt64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_count: expected binary array");

        let result: UInt64Array = hist_array
            .iter()
            .map(|hist_opt| {
                hist_opt.and_then(|bytes| deserialize_histogram(bytes).map(|h| h.len()))
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_min(hist) -> UInt64
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrMinUdf {
    signature: Signature,
}

impl HdrMinUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrMinUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_min"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::UInt64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_min: expected binary array");

        let result: UInt64Array = hist_array
            .iter()
            .map(|hist_opt| {
                hist_opt.and_then(|bytes| deserialize_histogram(bytes).map(|h| h.min()))
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_max(hist) -> UInt64
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrMaxUdf {
    signature: Signature,
}

impl HdrMaxUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrMaxUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_max"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::UInt64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_max: expected binary array");

        let result: UInt64Array = hist_array
            .iter()
            .map(|hist_opt| {
                hist_opt.and_then(|bytes| deserialize_histogram(bytes).map(|h| h.max()))
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_mean(hist) -> Float64
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrMeanUdf {
    signature: Signature,
}

impl HdrMeanUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrMeanUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_mean"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Float64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_mean: expected binary array");

        let result: Float64Array = hist_array
            .iter()
            .map(|hist_opt| {
                hist_opt.and_then(|bytes| deserialize_histogram(bytes).map(|h| h.mean()))
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_stdev(hist) -> Float64
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrStdevUdf {
    signature: Signature,
}

impl HdrStdevUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrStdevUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_stdev"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Float64)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_stdev: expected binary array");

        let result: Float64Array = hist_array
            .iter()
            .map(|hist_opt| {
                hist_opt.and_then(|bytes| deserialize_histogram(bytes).map(|h| h.stdev()))
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_buckets(hist) -> List<Struct<lo, hi, count>>
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrBucketsUdf {
    signature: Signature,
}

impl HdrBucketsUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrBucketsUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_buckets"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(bucket_list_type())
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_buckets: expected binary array");

        let mut lo_builder = UInt64Builder::new();
        let mut hi_builder = UInt64Builder::new();
        let mut count_builder = UInt64Builder::new();
        let mut offsets: Vec<i32> = Vec::with_capacity(hist_array.len() + 1);
        let mut validity: Vec<bool> = Vec::with_capacity(hist_array.len());
        offsets.push(0);

        for hist_opt in hist_array.iter() {
            match hist_opt.and_then(deserialize_histogram) {
                Some(hist) => {
                    for (lo, hi, count) in log_buckets(&hist, MAX_BUCKETS) {
                        lo_builder.append_value(lo);
                        hi_builder.append_value(hi);
                        count_builder.append_value(count);
                    }
                    validity.push(true);
                }
                None => validity.push(false),
            }
            offsets.push(lo_builder.len() as i32);
        }

        let values = Arc::new(StructArray::new(
            bucket_struct_fields(),
            vec![
                Arc::new(lo_builder.finish()) as ArrayRef,
                Arc::new(hi_builder.finish()) as ArrayRef,
                Arc::new(count_builder.finish()) as ArrayRef,
            ],
            None,
        )) as ArrayRef;

        let result = ListArray::new(
            Arc::new(Field::new(
                "item",
                DataType::Struct(bucket_struct_fields()),
                true,
            )),
            OffsetBuffer::new(ScalarBuffer::from(offsets)),
            values,
            Some(NullBuffer::new(BooleanBuffer::from(validity))),
        );

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

// ----------------------------------------------------------------------------
// hdr_ascii(hist) -> Utf8 (rendered histogram with cumulative percent)
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HdrAsciiUdf {
    signature: Signature,
}

impl HdrAsciiUdf {
    fn new() -> Self {
        Self {
            signature: Signature::exact(vec![DataType::Binary], Volatility::Immutable),
        }
    }
}

impl ScalarUDFImpl for HdrAsciiUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "hdr_ascii"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DFResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DFResult<ColumnarValue> {
        let args = ColumnarValue::values_to_arrays(&args.args)?;
        let hist_array = args[0]
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("hdr_ascii: expected binary array");

        let result: StringArray = hist_array
            .iter()
            .map(|hist_opt| {
                hist_opt
                    .and_then(deserialize_histogram)
                    .map(|hist| render_ascii(&hist))
            })
            .collect();

        Ok(ColumnarValue::Array(Arc::new(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram_accumulator_basic() {
        let mut acc = HdrHistogramAccumulator::new(2);

        // Simulate streaming batches
        let batch1 = Arc::new(Float64Array::from(vec![1.0, 2.0, 3.0, 4.0, 5.0])) as ArrayRef;
        acc.update_batch(&[batch1]).unwrap();

        let batch2 = Arc::new(Float64Array::from(vec![6.0, 7.0, 8.0, 9.0, 10.0])) as ArrayRef;
        acc.update_batch(&[batch2]).unwrap();

        assert_eq!(acc.histogram.len(), 10);
        assert_eq!(acc.histogram.min(), 1);
        assert_eq!(acc.histogram.max(), 10);
    }

    #[test]
    fn test_histogram_serialization_roundtrip() {
        // Use 3 significant figures for better precision in tests
        let mut acc = HdrHistogramAccumulator::new(3);
        let batch = Arc::new(Float64Array::from(vec![100.0, 200.0, 300.0])) as ArrayRef;
        acc.update_batch(&[batch]).unwrap();

        let bytes = acc.serialize();
        let restored = HdrHistogramAccumulator::deserialize(&bytes).unwrap();

        assert_eq!(restored.len(), 3);
        assert_eq!(restored.min(), 100);
        assert_eq!(restored.max(), 300);
    }

    #[test]
    fn test_histogram_merge() {
        let mut acc1 = HdrHistogramAccumulator::new(2);
        let batch1 = Arc::new(Float64Array::from(vec![1.0, 2.0, 3.0])) as ArrayRef;
        acc1.update_batch(&[batch1]).unwrap();

        let mut acc2 = HdrHistogramAccumulator::new(2);
        let batch2 = Arc::new(Float64Array::from(vec![4.0, 5.0, 6.0])) as ArrayRef;
        acc2.update_batch(&[batch2]).unwrap();

        // Serialize acc2's state
        let state = acc2.serialize();
        let state_array = Arc::new(BinaryArray::from(vec![state.as_slice()])) as ArrayRef;

        // Merge into acc1
        acc1.merge_batch(&[state_array]).unwrap();

        assert_eq!(acc1.histogram.len(), 6);
        assert_eq!(acc1.histogram.min(), 1);
        assert_eq!(acc1.histogram.max(), 6);
    }

    #[test]
    fn test_log_buckets_powers_of_two_with_gaps() {
        let mut acc = HdrHistogramAccumulator::new(2);
        let batch = Arc::new(Float64Array::from(vec![1.0, 2.0, 100.0, 1024.0])) as ArrayRef;
        acc.update_batch(&[batch]).unwrap();

        let rows = log_buckets(&acc.histogram, 48);

        // Buckets [1,1], [2,3], [4,7], ..., [1024,2047]
        assert_eq!(rows.len(), 11);
        assert_eq!(rows[0], (1, 1, 1));
        assert_eq!(rows[1], (2, 3, 1));
        // The gap is visible: intermediate buckets exist with zero counts
        assert_eq!(rows[2], (4, 7, 0));
        let b = rows.iter().find(|r| r.0 == 64).unwrap();
        assert_eq!(*b, (64, 127, 1)); // 100 recorded here
        assert_eq!(rows.last().unwrap().0, 1024);
        assert_eq!(rows.last().unwrap().2, 1);
        // Counts sum back to the total
        assert_eq!(rows.iter().map(|r| r.2).sum::<u64>(), 4);
    }

    #[test]
    fn test_log_buckets_coarsens_to_powers_of_ten() {
        let mut acc = HdrHistogramAccumulator::new(2);
        let batch = Arc::new(Float64Array::from(vec![1.0, 500.0, 5000.0])) as ArrayRef;
        acc.update_batch(&[batch]).unwrap();

        // 14 binary buckets don't fit in 8 rows -> decades
        let rows = log_buckets(&acc.histogram, 8);
        assert!(rows.len() <= 8);
        assert_eq!(rows.first().unwrap().0, 1);
        let last = rows.last().unwrap();
        assert!(last.1 >= 5000);
        // Aligned to the histogram's internal grid, so no double counting
        assert_eq!(rows.iter().map(|r| r.2).sum::<u64>(), 3);
    }

    #[test]
    fn test_log_buckets_empty_histogram() {
        let acc = HdrHistogramAccumulator::new(2);
        assert!(log_buckets(&acc.histogram, 48).is_empty());
        assert_eq!(render_ascii(&acc.histogram), "(empty histogram)");
    }

    #[test]
    fn test_render_ascii_shape() {
        let mut acc = HdrHistogramAccumulator::new(2);
        let batch = Arc::new(Float64Array::from(vec![2.0, 2.0, 2.0, 100.0, 4000.0])) as ArrayRef;
        acc.update_batch(&[batch]).unwrap();

        let out = render_ascii(&acc.histogram);
        let lines: Vec<&str> = out.lines().collect();

        assert!(lines[0].contains("5 samples"));
        assert!(lines[1].contains("cum"));
        // Header + 5 buckets: [2,3], [4,7], ..., [4096,8191]
        assert_eq!(lines.len(), 2 + log_buckets(&acc.histogram, 64).len());
        // The dominant bucket bar is at full width, empties have none
        let dominant = lines.iter().find(|l| l.contains("2-3")).unwrap();
        assert!(dominant.contains("####"));
        let empty = lines.iter().find(|l| l.contains("4-7")).unwrap();
        assert!(!empty.contains('#'));
        // Cumulative percent reaches 100 on the last bucket
        assert!(lines.last().unwrap().contains("100.0%"));
    }

    #[test]
    fn test_uint32_values_are_recorded() {
        // frames.length is UInt32; it used to be silently dropped
        let mut acc = HdrHistogramAccumulator::new(2);
        let batch = Arc::new(UInt32Array::from(vec![136_u32, 583, 65080])) as ArrayRef;
        acc.update_batch(&[batch]).unwrap();

        assert_eq!(acc.histogram.len(), 3);
        assert_eq!(acc.histogram.min(), 136);
        // max() is the highest *equivalent* value at the histogram's
        // significant-figure precision, so 65080 may quantize upward.
        assert!(acc.histogram.max() >= 65080);
    }

    // ------------------------------------------------------------------
    // The SQL functions against the kernels they wrap. The DuckDB
    // extension's functions are compared with the same kernels the same
    // way (pcapsql-duckdb/itest/tests/histogram.rs), which is what makes
    // the two engines answer alike.
    // ------------------------------------------------------------------

    use datafusion::prelude::SessionContext;

    const PERCENTILES: [f64; 7] = [0.0, 0.25, 0.5, 0.9, 99.0, 99.9, 1.0];

    /// Everything the scalar functions say of a histogram.
    #[derive(Debug, PartialEq)]
    struct Answers {
        count: u64,
        min: u64,
        max: u64,
        mean: f64,
        stdev: f64,
        percentiles: Vec<f64>,
        buckets: Vec<(u64, u64, u64)>,
        ascii: String,
    }

    /// What the kernel says of the histogram that recorded `values`, read
    /// back from its serialized form as the SQL functions read it.
    fn kernel_answers(values: &[u64]) -> Answers {
        let mut recorded = HdrHistogram::default();
        for &value in values {
            recorded.record(value);
        }
        let hist = HdrHistogram::deserialize(&recorded.serialize().unwrap()).unwrap();
        Answers {
            count: hist.len(),
            min: hist.min(),
            max: hist.max(),
            mean: hist.mean(),
            stdev: hist.stdev(),
            percentiles: PERCENTILES.iter().map(|&p| hist.percentile(p)).collect(),
            buckets: log_buckets(&hist, MAX_BUCKETS),
            ascii: render_ascii(&hist),
        }
    }

    /// What the SQL functions say of the one histogram `sql` returns as `h`.
    async fn sql_answers(ctx: &SessionContext, sql: &str) -> Answers {
        let percentiles: Vec<String> = PERCENTILES
            .iter()
            .map(|p| format!("hdr_percentile(h, {p:?})"))
            .collect();
        let query = format!(
            "SELECT hdr_count(h), hdr_min(h), hdr_max(h), hdr_mean(h), hdr_stdev(h), {}, \
             hdr_buckets(h), hdr_ascii(h) FROM ({sql}) q",
            percentiles.join(", ")
        );
        let batches = ctx.sql(&query).await.unwrap().collect().await.unwrap();
        let batch = &batches[0];
        assert_eq!(batch.num_rows(), 1, "{query}");
        let unsigned = |column: usize| {
            let array = batch.column(column);
            array
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap()
                .value(0)
        };
        let float = |column: usize| {
            let array = batch.column(column);
            array
                .as_any()
                .downcast_ref::<Float64Array>()
                .unwrap()
                .value(0)
        };
        let lists = batch.column(5 + PERCENTILES.len());
        let lists = lists.as_any().downcast_ref::<ListArray>().unwrap();
        assert!(lists.is_valid(0));
        let structs = lists.value(0);
        let structs = structs.as_any().downcast_ref::<StructArray>().unwrap();
        let field = |index: usize| {
            structs
                .column(index)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap()
                .clone()
        };
        let (lo, hi, count) = (field(0), field(1), field(2));
        let ascii = batch.column(6 + PERCENTILES.len());
        Answers {
            count: unsigned(0),
            min: unsigned(1),
            max: unsigned(2),
            mean: float(3),
            stdev: float(4),
            percentiles: (0..PERCENTILES.len()).map(|i| float(5 + i)).collect(),
            buckets: (0..structs.len())
                .map(|i| (lo.value(i), hi.value(i), count.value(i)))
                .collect(),
            ascii: ascii
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(0)
                .to_owned(),
        }
    }

    #[tokio::test]
    async fn test_sql_functions_answer_as_the_kernels_do() {
        let ctx = SessionContext::new();
        crate::query::udf::register_histogram_udfs(&ctx).unwrap();
        let cases: [(&str, &str, &[u64]); 10] = [
            (
                "integers, some NULL",
                "SELECT hdr_histogram(v) AS h FROM (VALUES (1), (NULL), (5), (5), (1000)) t(v)",
                &[1, 5, 5, 1000],
            ),
            (
                "one row",
                "SELECT hdr_histogram(v) AS h FROM (VALUES (42)) t(v)",
                &[42],
            ),
            (
                "no rows",
                "SELECT hdr_histogram(v) AS h FROM (VALUES (1), (2)) t(v) WHERE v > 5",
                &[],
            ),
            (
                "every row NULL",
                "SELECT hdr_histogram(CAST(NULL AS BIGINT)) AS h FROM (VALUES (1), (2)) t(v)",
                &[],
            ),
            (
                "the largest values",
                "SELECT hdr_histogram(arrow_cast(v, 'UInt64')) AS h FROM \
                 (VALUES (18446744073709551615), (9223372036854775808), (1)) t(v)",
                &[u64::MAX, 1 << 63, 1],
            ),
            (
                "negative values are not recorded",
                "SELECT hdr_histogram(v) AS h FROM \
                 (VALUES (-1), (-9223372036854775808), (0), (7), (9223372036854775807)) t(v)",
                &[0, 7, i64::MAX as u64],
            ),
            (
                "fractions are cut off, NaN and negative numbers left out",
                "SELECT hdr_histogram(v) AS h FROM (VALUES (1.5), (2.99), (-3.0), (1e30), \
                 (CAST('NaN' AS DOUBLE)), (CAST('inf' AS DOUBLE)), (CAST('-inf' AS DOUBLE)), \
                 (0.0), (0.99)) t(v)",
                &[1, 2, u64::MAX, u64::MAX, 0, 0],
            ),
            (
                "32-bit unsigned",
                "SELECT hdr_histogram(arrow_cast(v, 'UInt32')) AS h FROM \
                 (VALUES (4294967295), (136), (583), (65080)) t(v)",
                &[4294967295, 136, 583, 65080],
            ),
            (
                // Unlike in the DuckDB extension, which records the integer part.
                "a DECIMAL column is not recorded",
                "SELECT hdr_histogram(CAST(v AS DECIMAL(10, 2))) AS h FROM (VALUES (1.5), (20)) t(v)",
                &[],
            ),
            (
                "a column that is not a number is not recorded",
                "SELECT hdr_histogram(v) AS h FROM (VALUES ('a'), ('b')) t(v)",
                &[],
            ),
        ];
        for (what, sql, recorded) in cases {
            assert_eq!(
                sql_answers(&ctx, sql).await,
                kernel_answers(recorded),
                "{what}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_blob_that_is_no_histogram_is_null() {
        let ctx = SessionContext::new();
        crate::query::udf::register_histogram_udfs(&ctx).unwrap();
        for blob in ["X'00ff'", "X''", "CAST(NULL AS BYTEA)", "X'1c849313'"] {
            let query = format!(
                "SELECT hdr_count(h), hdr_min(h), hdr_max(h), hdr_mean(h), hdr_stdev(h), \
                 hdr_percentile(h, 0.5), hdr_buckets(h), hdr_ascii(h) FROM (SELECT {blob} AS h) q"
            );
            let batches = ctx.sql(&query).await.unwrap().collect().await.unwrap();
            let batch = &batches[0];
            assert_eq!(batch.num_rows(), 1);
            for column in batch.columns() {
                assert!(column.is_null(0), "{blob}: {column:?}");
            }
        }
    }
}
