//! The kernels behind the `hdr_*` SQL functions: a histogram of unsigned
//! values that is built from a column, merged, serialized, and asked for
//! its statistics, its buckets and a picture of itself.
//!
//! The histogram is an [HdrHistogram](https://hdrhistogram.org): its memory
//! does not grow with the number of values, only (in steps) with the
//! largest, and a value is kept to a number of significant decimal digits
//! ([`DEFAULT_SIGFIGS`]: within 1 %). It lives behind the `histogram`
//! feature of this crate, which is off by default: the `hdrhistogram` crate
//! needs a newer compiler than the rest of the library.
//!
//! As for the other kernels of [`format`](super), nothing here knows a
//! column or NULL. The engines' wrappers own that, and both give the same
//! answers because both call these:
//!
//! | SQL | Kernel |
//! |---|---|
//! | `hdr_histogram(value)` (aggregate) | [`HdrHistogram::record`], [`record_signed`](HdrHistogram::record_signed), [`record_wide`](HdrHistogram::record_wide), [`record_float`](HdrHistogram::record_float); [`merge`](HdrHistogram::merge) for partial states; [`serialize`](HdrHistogram::serialize) for the result |
//! | `hdr_count`, `hdr_min`, `hdr_max`, `hdr_mean`, `hdr_stdev` | [`HdrHistogram::deserialize`], then [`len`](HdrHistogram::len), [`min`](HdrHistogram::min), [`max`](HdrHistogram::max), [`mean`](HdrHistogram::mean), [`stdev`](HdrHistogram::stdev) |
//! | `hdr_percentile(hist, p)` | [`HdrHistogram::percentile`] |
//! | `hdr_buckets(hist)` | [`HdrHistogram::buckets`] |
//! | `hdr_ascii(hist)` | [`HdrHistogram::write_ascii`] |
//!
//! # What is recorded
//!
//! A value is an unsigned 64-bit integer. A negative number is not
//! recorded, a number with a fraction is cut to its integer part (a column
//! of fractions of a unit is scaled before it is recorded), and NaN is not
//! recorded. There is no value outside the range of a histogram: it grows
//! to hold the largest it is given, up to `u64::MAX`.
//!
//! # The serialized form
//!
//! [`HdrHistogram::serialize`] writes HdrHistogram's V2 encoding, which
//! every implementation of HdrHistogram reads. It is the value of the
//! histogram in SQL (a binary column), in both engines.
//!
//! Two histograms of the same values have the same counts and give the same
//! answers. Their bytes are equal when each was built by recording alone,
//! in whatever order. A histogram that was merged can differ from them in
//! one field of the header: the encoding stores the highest value the
//! histogram has room for, and where recording a value that does not fit
//! makes room for a whole power of two, merging a histogram that does not
//! fit makes room for exactly its largest value. So the field depends on
//! how the values were split into partial histograms and in which order
//! those were merged, which an engine that aggregates in parallel does not
//! fix. Compare histograms by what they answer, not by their bytes.

use std::fmt;
use std::io::Cursor;

use hdrhistogram::serialization::{Deserializer, Serializer, V2Serializer};
use hdrhistogram::Histogram;
use thiserror::Error;

/// The significant decimal digits a histogram of the SQL functions keeps
/// of a value: 2, so a value is reported within 1 %.
pub const DEFAULT_SIGFIGS: u8 = 2;

/// The most buckets [`HdrHistogram::buckets`] and
/// [`HdrHistogram::write_ascii`] produce.
pub const MAX_BUCKETS: usize = 64;

/// Why a histogram could not be merged, written or read.
#[derive(Debug, Error)]
pub enum HistogramError {
    /// The bytes are not a serialized histogram.
    #[error("histogram deserialize error: {0}")]
    Deserialize(String),
    /// The other histogram's values do not fit this one.
    #[error("histogram merge error: {0}")]
    Merge(String),
    /// A count of the histogram cannot be encoded.
    #[error("histogram serialize error: {0}")]
    Serialize(String),
}

/// One row of [`HdrHistogram::buckets`]: the values from `lo` to `hi`, both
/// included, and how many were recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    /// The smallest value of the bucket.
    pub lo: u64,
    /// The largest value of the bucket.
    pub hi: u64,
    /// The number of recorded values in the bucket.
    pub count: u64,
}

/// A histogram of unsigned values (see the module documentation).
#[derive(Debug, Clone, PartialEq)]
pub struct HdrHistogram {
    inner: Histogram<u64>,
}

impl Default for HdrHistogram {
    /// An empty histogram that keeps [`DEFAULT_SIGFIGS`] digits of a value.
    fn default() -> Self {
        Self::with_sigfigs(DEFAULT_SIGFIGS).expect("the default precision is valid")
    }
}

impl HdrHistogram {
    /// An empty histogram that keeps `sigfigs` significant decimal digits of
    /// a value and grows to hold whatever is recorded. `None` for more
    /// than five digits, which HdrHistogram does not offer.
    pub fn with_sigfigs(sigfigs: u8) -> Option<Self> {
        Histogram::new(sigfigs).ok().map(|inner| Self { inner })
    }

    /// Record a value.
    #[inline]
    pub fn record(&mut self, value: u64) {
        // A histogram that grows refuses nothing a `u64` can hold.
        let _ = self.inner.record(value);
    }

    /// Record a signed value; a negative one is not recorded.
    #[inline]
    pub fn record_signed(&mut self, value: i64) {
        if let Ok(value) = u64::try_from(value) {
            self.record(value);
        }
    }

    /// Record an integer of more than 64 bits: a negative one is not
    /// recorded, and one past `u64::MAX` is recorded as `u64::MAX`.
    #[inline]
    pub fn record_wide(&mut self, value: i128) {
        if value >= 0 {
            self.record(u64::try_from(value).unwrap_or(u64::MAX));
        }
    }

    /// Record the integer part of a floating-point value. A negative value
    /// and NaN are not recorded; a value past `u64::MAX`, infinity
    /// included, is recorded as `u64::MAX`.
    #[inline]
    pub fn record_float(&mut self, value: f64) {
        if value >= 0.0 {
            // Truncating and saturating: what `as` does.
            self.record(value as u64);
        }
    }

    /// Add the values of `other` to this histogram.
    pub fn merge(&mut self, other: &HdrHistogram) -> Result<(), HistogramError> {
        self.inner
            .add(&other.inner)
            .map_err(|error| HistogramError::Merge(error.to_string()))
    }

    /// The number of recorded values.
    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    /// Whether no value was recorded.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The smallest recorded value, at the histogram's precision; 0 for an
    /// empty histogram.
    pub fn min(&self) -> u64 {
        self.inner.min()
    }

    /// The largest recorded value, at the histogram's precision: the
    /// highest value the histogram cannot tell from it, which is at least
    /// the value itself. 0 for an empty histogram.
    pub fn max(&self) -> u64 {
        self.inner.max()
    }

    /// The mean of the recorded values; 0 for an empty histogram.
    pub fn mean(&self) -> f64 {
        self.inner.mean()
    }

    /// The standard deviation of the recorded values; 0 for an empty
    /// histogram.
    pub fn stdev(&self) -> f64 {
        self.inner.stdev()
    }

    /// The value at a percentile: the smallest value that `p` of the
    /// recorded values are at or below. `p` is a fraction from 0 to 1, or,
    /// above 1, a percentage (`0.99` and `99` are the same percentile).
    pub fn percentile(&self, p: f64) -> f64 {
        let quantile = if p > 1.0 { p / 100.0 } else { p };
        self.inner.value_at_quantile(quantile) as f64
    }

    /// The histogram in HdrHistogram's V2 encoding.
    pub fn serialize(&self) -> Result<Vec<u8>, HistogramError> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Append the histogram in HdrHistogram's V2 encoding to `bytes`.
    pub fn serialize_into(&self, bytes: &mut Vec<u8>) -> Result<(), HistogramError> {
        V2Serializer::new()
            .serialize(&self.inner, bytes)
            .map(|_written| ())
            .map_err(|error| HistogramError::Serialize(error.to_string()))
    }

    /// The histogram `bytes` encode: what [`serialize`](Self::serialize)
    /// wrote, or any other HdrHistogram V2 encoding (compressed or not).
    /// Bytes after the encoding are not looked at.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, HistogramError> {
        Deserializer::new()
            .deserialize(&mut Cursor::new(bytes))
            .map(|inner| Self { inner })
            .map_err(|error| HistogramError::Deserialize(error.to_string()))
    }

    /// The recorded range in at most [`MAX_BUCKETS`] buckets on a
    /// logarithmic scale: [`log_buckets`] as rows.
    pub fn buckets(&self) -> impl Iterator<Item = Bucket> {
        log_buckets(self, MAX_BUCKETS)
            .into_iter()
            .map(|(lo, hi, count)| Bucket { lo, hi, count })
    }

    /// Draw the histogram as text: a line of statistics, a header, and a
    /// line per bucket of [`buckets`](Self::buckets) with its count, its
    /// share, the cumulative share and a bar. `(empty histogram)` when no
    /// value was recorded.
    pub fn write_ascii<W: fmt::Write>(&self, out: &mut W) -> fmt::Result {
        const BAR_WIDTH: usize = 40;

        let total = self.len();
        if total == 0 {
            return out.write_str("(empty histogram)");
        }
        let rows = log_buckets(self, MAX_BUCKETS);
        let max_count = rows.iter().map(|r| r.2).max().unwrap_or(0).max(1);

        writeln!(
            out,
            "{} samples | min {} | max {} | mean {:.1} | stdev {:.1}",
            total,
            self.min(),
            self.max(),
            self.mean(),
            self.stdev()
        )?;

        let bucket_width = rows
            .iter()
            .map(|(lo, hi, _)| format!("{lo}-{hi}").len())
            .max()
            .unwrap_or(6)
            .max(6);
        writeln!(
            out,
            "{:>bw$} {:>12} {:>7} {:>7} bar",
            "bucket",
            "count",
            "pct",
            "cum",
            bw = bucket_width
        )?;

        let mut cum = 0_u64;
        for (lo, hi, count) in rows {
            cum += count;
            let bar_len = ((BAR_WIDTH as f64 * count as f64) / max_count as f64).round() as usize;
            writeln!(
                out,
                "{:>bw$} {:>12} {:>6.1}% {:>6.1}% {}",
                format!("{lo}-{hi}"),
                count,
                100.0 * count as f64 / total as f64,
                100.0 * cum as f64 / total as f64,
                "#".repeat(bar_len),
                bw = bucket_width
            )?;
        }
        Ok(())
    }
}

/// Split the recorded value range into log-scale buckets.
///
/// Returns inclusive `(lo, hi, count)` rows covering the recorded range,
/// including empty buckets so gaps in the distribution stay visible. Bucket
/// edges are powers of two, aligned with the histogram's internal grid so
/// every recorded value lands in exactly one bucket (bucket counts always sum
/// back to the total). Falls back to powers of ten when the value range is
/// too wide for `max_rows` binary buckets.
pub fn log_buckets(hist: &HdrHistogram, max_rows: usize) -> Vec<(u64, u64, u64)> {
    if hist.is_empty() {
        return Vec::new();
    }

    let mut rows = Vec::new();
    for base in [2.0_f64, 10.0] {
        rows.clear();
        let mut lo = 0_u64;
        for iv in hist.inner.iter_log(1, base) {
            let hi = iv.value_iterated_to();
            rows.push((lo, hi, iv.count_since_last_iteration()));
            lo = hi.saturating_add(1);
        }
        // iter_log always leads with a [0,0] step and visits every bucket
        // from 1 up; trim the empty run below the recorded minimum so the
        // output starts at the real value range.
        let first_nonzero = rows.iter().position(|r| r.2 > 0).unwrap_or(0);
        rows.drain(0..first_nonzero);

        if rows.len() <= max_rows {
            break;
        }
    }
    // Decades are the coarsest scale there is: what they give is returned
    // even when it is more than `max_rows`.
    rows
}

/// [`HdrHistogram::write_ascii`] as a `String`.
pub fn render_ascii(hist: &HdrHistogram) -> String {
    let mut out = String::new();
    hist.write_ascii(&mut out)
        .expect("writing to a String does not fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(values: &[u64]) -> HdrHistogram {
        let mut hist = HdrHistogram::default();
        for &value in values {
            hist.record(value);
        }
        hist
    }

    #[test]
    fn statistics_of_recorded_values() {
        let hist = of(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(hist.len(), 10);
        assert!(!hist.is_empty());
        assert_eq!(hist.min(), 1);
        assert_eq!(hist.max(), 10);
        assert_eq!(hist.mean(), 5.5);
        assert!((hist.stdev() - 2.8722813232690143).abs() < 1e-12);
        // A fraction and a percentage name the same percentile.
        assert_eq!(hist.percentile(0.5), 5.0);
        assert_eq!(hist.percentile(50.0), 5.0);
        assert_eq!(hist.percentile(0.0), 1.0);
        assert_eq!(hist.percentile(1.0), 10.0);
        assert_eq!(hist.percentile(100.0), 10.0);
        assert_eq!(hist.percentile(99.0), hist.percentile(0.99));
    }

    #[test]
    fn an_empty_histogram_answers_zero() {
        let hist = HdrHistogram::default();
        assert!(hist.is_empty());
        assert_eq!(
            (
                hist.len(),
                hist.min(),
                hist.max(),
                hist.mean(),
                hist.stdev()
            ),
            (0, 0, 0, 0.0, 0.0)
        );
        assert_eq!(hist.percentile(0.5), 0.0);
        assert_eq!(hist.buckets().count(), 0);
        assert_eq!(render_ascii(&hist), "(empty histogram)");
        // And survives the encoding as what it is.
        let restored = HdrHistogram::deserialize(&hist.serialize().unwrap()).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn values_are_kept_to_two_digits() {
        let hist = of(&[136, 583, 65080]);
        assert_eq!(hist.len(), 3);
        assert_eq!(hist.min(), 136);
        // The highest value the histogram cannot tell from 65080.
        assert!(hist.max() >= 65080);
        assert!(hist.max() < 65080 + 65080 / 100);
    }

    #[test]
    fn signed_and_float_values_are_cut_to_what_a_histogram_holds() {
        let mut hist = HdrHistogram::default();
        for value in [-1, i64::MIN, 0, 7] {
            hist.record_signed(value);
        }
        assert_eq!(hist.len(), 2);
        assert_eq!((hist.min(), hist.max()), (0, 7));

        let mut hist = HdrHistogram::default();
        for value in [-1, i128::MIN, 0, 9, i128::from(u64::MAX) + 1, i128::MAX] {
            hist.record_wide(value);
        }
        assert_eq!(hist.len(), 4);
        assert_eq!((hist.min(), hist.max()), (0, u64::MAX));

        let mut hist = HdrHistogram::default();
        for value in [
            -0.5,
            -1e300,
            f64::NEG_INFINITY,
            f64::NAN,
            0.0,
            -0.0,
            0.99,
            3.99,
        ] {
            hist.record_float(value);
        }
        // 0.0, -0.0 and 0.99 are 0; 3.99 is 3; the rest is not recorded.
        assert_eq!(hist.len(), 4);
        assert_eq!((hist.min(), hist.max()), (0, 3));
    }

    #[test]
    fn no_value_is_out_of_range() {
        let mut hist = HdrHistogram::default();
        hist.record(u64::MAX);
        hist.record_float(f64::INFINITY);
        hist.record_float(1e300);
        hist.record(1);
        assert_eq!(hist.len(), 4);
        assert_eq!(hist.min(), 1);
        assert_eq!(hist.max(), u64::MAX);
        let restored = HdrHistogram::deserialize(&hist.serialize().unwrap()).unwrap();
        assert_eq!(restored.len(), 4);
        // What the SQL functions see: HdrHistogram reads the largest value
        // back as the top of its last bucket, which is one below.
        assert_eq!(restored.max(), u64::MAX - 1);
    }

    #[test]
    fn the_encoding_round_trips() {
        let mut hist = HdrHistogram::with_sigfigs(3).unwrap();
        for value in [100, 200, 300] {
            hist.record(value);
        }
        let bytes = hist.serialize().unwrap();
        let restored = HdrHistogram::deserialize(&bytes).unwrap();
        assert_eq!(restored.len(), 3);
        assert_eq!(restored.min(), 100);
        assert_eq!(restored.max(), 300);
        assert_eq!(restored.serialize().unwrap(), bytes);
        // `serialize_into` appends.
        let mut twice = bytes.clone();
        hist.serialize_into(&mut twice).unwrap();
        assert_eq!(twice, [bytes.clone(), bytes.clone()].concat());
        // What follows the encoding is not read.
        assert_eq!(
            HdrHistogram::deserialize(&twice).unwrap().len(),
            restored.len()
        );
    }

    #[test]
    fn six_digits_are_not_offered() {
        for sigfigs in 0..=5 {
            assert!(HdrHistogram::with_sigfigs(sigfigs).is_some(), "{sigfigs}");
        }
        assert!(HdrHistogram::with_sigfigs(6).is_none());
    }

    #[test]
    fn merging_adds_the_values() {
        let mut left = of(&[1, 2, 3]);
        let right = of(&[4, 5, 6, 1_000_000]);
        left.merge(&right).unwrap();
        assert_eq!(left.len(), 7);
        assert_eq!(left.min(), 1);
        assert!(left.max() >= 1_000_000);
        // The same as recording all of them.
        let all = of(&[1, 2, 3, 4, 5, 6, 1_000_000]);
        assert_eq!(
            left.buckets().collect::<Vec<_>>(),
            all.buckets().collect::<Vec<_>>()
        );
        assert_eq!(left.mean(), all.mean());
        // Merging an empty histogram, and into one, changes nothing.
        left.merge(&HdrHistogram::default()).unwrap();
        assert_eq!(left.len(), 7);
        let mut empty = HdrHistogram::default();
        empty.merge(&all).unwrap();
        assert_eq!(render_ascii(&empty), render_ascii(&all));
    }

    #[test]
    fn a_histogram_that_was_read_does_not_grow() {
        // HdrHistogram reads an encoding into a histogram of the encoded
        // range. Merging a wider one into it is an error, not a panic.
        let mut read = HdrHistogram::deserialize(&of(&[1, 2]).serialize().unwrap()).unwrap();
        let error = read.merge(&of(&[1 << 40])).unwrap_err();
        assert!(
            error.to_string().starts_with("histogram merge error: "),
            "{error}"
        );
        read.merge(&of(&[2])).unwrap();
        assert_eq!(read.len(), 3);
    }

    #[test]
    fn recording_in_any_order_gives_the_same_bytes() {
        let values = [3, 1100, 1900, 0, 70_000, 1 << 40, 17, 1900, 65_535, 65_536];
        let bytes = of(&values).serialize().unwrap();
        let mut order = values;
        for _ in 0..values.len() {
            order.rotate_left(1);
            assert_eq!(of(&order).serialize().unwrap(), bytes, "{order:?}");
            let mut reversed = order;
            reversed.reverse();
            assert_eq!(of(&reversed).serialize().unwrap(), bytes, "{reversed:?}");
        }
    }

    #[test]
    fn a_merged_histogram_can_differ_in_its_bytes_and_in_nothing_else() {
        // The same four values: recorded, and merged from two halves in
        // either order. 1100 and 1900 are in the same power of two.
        let recorded = of(&[5, 1100, 9, 1900]);
        let (low, high) = (of(&[5, 1100]), of(&[9, 1900]));
        let mut low_first = HdrHistogram::default();
        low_first.merge(&low).unwrap();
        low_first.merge(&high).unwrap();
        let mut high_first = HdrHistogram::default();
        high_first.merge(&high).unwrap();
        high_first.merge(&low).unwrap();

        let bytes = |hist: &HdrHistogram| hist.serialize().unwrap();
        assert_ne!(bytes(&low_first), bytes(&high_first));
        assert_ne!(bytes(&low_first), bytes(&recorded));
        for hist in [&low_first, &high_first] {
            let read = HdrHistogram::deserialize(&bytes(hist)).unwrap();
            assert_eq!((read.len(), read.min()), (4, 5));
            assert_eq!(read.max(), recorded.max());
            assert_eq!(read.mean(), recorded.mean());
            assert_eq!(read.stdev(), recorded.stdev());
            for p in [0.0, 0.25, 0.5, 0.75, 0.99, 1.0] {
                assert_eq!(read.percentile(p), recorded.percentile(p), "{p}");
            }
            assert_eq!(
                read.buckets().collect::<Vec<_>>(),
                recorded.buckets().collect::<Vec<_>>()
            );
            assert_eq!(render_ascii(&read), render_ascii(&recorded));
        }
    }

    #[test]
    fn bytes_that_are_no_histogram_are_an_error() {
        let valid = of(&[5, 50, 500, 5000]).serialize().unwrap();
        for bytes in [
            &b""[..],
            b"\x00",
            b"not a histogram",
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            &valid[..valid.len() - 1],
            &valid[..8],
            &valid[1..],
        ] {
            let error = HdrHistogram::deserialize(bytes).unwrap_err();
            assert!(
                error
                    .to_string()
                    .starts_with("histogram deserialize error: "),
                "{bytes:?}: {error}"
            );
        }
    }

    #[test]
    fn damaged_encodings_are_read_or_refused_never_a_panic() {
        // Every single-bit change of an encoding, and every cut of it.
        let valid = of(&[0, 1, 2, 300, 70_000, u64::MAX / 3])
            .serialize()
            .unwrap();
        let mut read = 0;
        for index in 0..valid.len() {
            for bit in 0..8 {
                let mut damaged = valid.clone();
                damaged[index] ^= 1 << bit;
                if let Ok(hist) = HdrHistogram::deserialize(&damaged) {
                    // Whatever it now holds, it answers.
                    let _ = (
                        hist.len(),
                        hist.min(),
                        hist.max(),
                        hist.mean(),
                        hist.stdev(),
                    );
                    let _ = hist.percentile(0.99);
                    let _ = hist.buckets().count();
                    let _ = render_ascii(&hist);
                    read += 1;
                }
            }
            assert!(HdrHistogram::deserialize(&valid[..index]).is_err());
        }
        // Some changes are another histogram (a count, a bound): the test
        // was of both outcomes.
        assert!(read > 0 && read < valid.len() * 8, "{read}");
    }

    #[test]
    fn buckets_are_powers_of_two_with_the_gaps() {
        let rows = log_buckets(&of(&[1, 2, 100, 1024]), 48);
        // [1,1], [2,3], [4,7], ..., [1024,2047]
        assert_eq!(rows.len(), 11);
        assert_eq!(rows[0], (1, 1, 1));
        assert_eq!(rows[1], (2, 3, 1));
        assert_eq!(rows[2], (4, 7, 0));
        assert_eq!(rows[6], (64, 127, 1));
        assert_eq!(rows[10].0, 1024);
        assert_eq!(rows.iter().map(|r| r.2).sum::<u64>(), 4);
        // The rows of `buckets` are these.
        let buckets: Vec<Bucket> = of(&[1, 2, 100, 1024]).buckets().collect();
        assert_eq!(buckets.len(), 11);
        assert_eq!(
            buckets[6],
            Bucket {
                lo: 64,
                hi: 127,
                count: 1
            }
        );
    }

    #[test]
    fn buckets_become_decades_when_powers_of_two_are_too_many() {
        let hist = of(&[1, 500, 5000]);
        let rows = log_buckets(&hist, 8);
        assert!(rows.len() <= 8);
        assert_eq!(rows.first().unwrap().0, 1);
        assert!(rows.last().unwrap().1 >= 5000);
        assert_eq!(rows.iter().map(|r| r.2).sum::<u64>(), 3);
        // The whole range of a u64 is 64 binary buckets: within the limit
        // of the SQL functions.
        let wide = of(&[1, u64::MAX]);
        let buckets: Vec<Bucket> = wide.buckets().collect();
        assert_eq!(buckets.len(), MAX_BUCKETS);
        assert_eq!(buckets.iter().map(|bucket| bucket.count).sum::<u64>(), 2);
        // From zero it is one more, and decades it is.
        let from_zero = of(&[0, u64::MAX]);
        let buckets: Vec<Bucket> = from_zero.buckets().collect();
        assert!(buckets.len() <= MAX_BUCKETS, "{}", buckets.len());
        assert_eq!(buckets.iter().map(|bucket| bucket.count).sum::<u64>(), 2);
    }

    #[test]
    fn the_picture_has_a_line_per_bucket() {
        let hist = of(&[2, 2, 2, 100, 4000]);
        let out = render_ascii(&hist);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            format!(
                "5 samples | min 2 | max {} | mean {:.1} | stdev {:.1}",
                hist.max(),
                hist.mean(),
                hist.stdev()
            )
        );
        assert!(
            lines[1].ends_with("count     pct     cum bar"),
            "{}",
            lines[1]
        );
        assert_eq!(lines.len(), 2 + hist.buckets().count());
        let dominant = lines.iter().find(|l| l.contains("2-3")).unwrap();
        assert!(dominant.ends_with(&"#".repeat(40)), "{dominant}");
        assert!(dominant.contains(" 60.0%"), "{dominant}");
        let empty = lines.iter().find(|l| l.contains("4-7")).unwrap();
        assert!(!empty.contains('#'));
        assert!(lines.last().unwrap().contains("100.0%"));
        assert!(out.ends_with('\n'));
    }
}
