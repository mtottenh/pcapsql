//! Tumbling window assignment.
//!
//! Tumbling windows are fixed-size, non-overlapping and aligned to the Unix
//! epoch; every event belongs to exactly one window.
//!
//! ```text
//! Timeline:    0    1    2    3    4    5    6    7    8    9    10
//!              |    |    |    |    |    |    |    |    |    |    |
//! TUMBLE(2):   [----)    [----)    [----)    [----)    [----)
//!              w0        w1        w2        w3        w4
//! ```

use std::time::Duration;

use super::watermark::Watermark;
use super::window::WindowBounds;

/// Assigns timestamps to epoch-aligned tumbling windows.
///
/// Assignment is a floor division and a multiplication, so a window start is
/// always the largest multiple of the size that is `<=` the timestamp —
/// including for timestamps before the epoch (`-1` with a 10 µs window is in
/// `[-10, 0)`, not `[0, 10)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TumblingWindowAssigner {
    /// Window size in microseconds.
    size_us: i64,
}

impl TumblingWindowAssigner {
    /// Create an assigner with the given window size.
    ///
    /// # Panics
    ///
    /// Panics if `window_size` is zero or does not fit in `i64` microseconds.
    pub fn new(window_size: Duration) -> Self {
        Self::from_micros(duration_to_micros(window_size, "window size"))
    }

    /// Create an assigner from a window size in microseconds.
    ///
    /// # Panics
    ///
    /// Panics if `size_us` is not positive.
    pub fn from_micros(size_us: i64) -> Self {
        assert!(size_us > 0, "window size must be positive");
        Self { size_us }
    }

    /// The window containing `timestamp`.
    #[inline]
    pub fn assign(&self, timestamp: i64) -> WindowBounds {
        let start = floor_to_multiple(timestamp, self.size_us);
        WindowBounds::new(start, start + self.size_us)
    }

    /// Window size in microseconds.
    pub fn size_us(&self) -> i64 {
        self.size_us
    }

    /// Window size as a `Duration`.
    pub fn window_size(&self) -> Duration {
        Duration::from_micros(self.size_us as u64)
    }

    /// The windows that a watermark advance from `prev` to `new` closes:
    /// those with `prev < end <= new`, oldest first.
    ///
    /// Windows are enumerated from the one containing `earliest_event` (the
    /// smallest timestamp observed so far) — a stream's first watermark
    /// advances from [`Watermark::INITIAL`], and without that lower bound the
    /// enumeration would start at `i64::MIN`. Windows ending before the
    /// earliest event cannot hold data, so nothing is lost by skipping them.
    pub fn closed_windows(
        &self,
        prev: Watermark,
        new: Watermark,
        earliest_event: i64,
    ) -> Vec<WindowBounds> {
        if new <= prev {
            return Vec::new();
        }
        // Smallest window end strictly greater than `prev` (a window ending
        // exactly at `prev` was closed by `prev`).
        let first_end_after_prev = if prev == Watermark::INITIAL {
            // Nothing was closed before: the earliest event alone bounds the
            // enumeration below (there is no window floor below i64::MIN).
            i64::MIN
        } else {
            floor_to_multiple(prev.as_micros(), self.size_us)
                .checked_add(self.size_us)
                .unwrap_or(i64::MAX)
        };
        let earliest_end = self.assign(earliest_event).end;
        let mut end = first_end_after_prev.max(earliest_end);
        let mut windows = Vec::new();
        while end <= new.as_micros() {
            windows.push(WindowBounds::new(end - self.size_us, end));
            match end.checked_add(self.size_us) {
                Some(next) => end = next,
                None => break,
            }
        }
        windows
    }
}

/// Largest multiple of `step` (positive) that is `<= value`.
///
/// `value` must be at least `i64::MIN + step` (no such multiple exists
/// below that); timestamps near `i64::MIN` are not meaningful event times.
#[inline]
pub(crate) fn floor_to_multiple(value: i64, step: i64) -> i64 {
    value - value.rem_euclid(step)
}

/// A positive `Duration` as `i64` microseconds.
///
/// # Panics
///
/// Panics (with `what` in the message) when the duration is zero or exceeds
/// `i64::MAX` microseconds.
pub(crate) fn duration_to_micros(duration: Duration, what: &str) -> i64 {
    let micros = duration.as_micros();
    assert!(micros > 0, "{what} must be positive");
    assert!(
        micros <= i64::MAX as u128,
        "{what} exceeds i64 microseconds"
    );
    micros as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000;

    #[test]
    fn assignment_basic() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(60));
        assert_eq!(a.assign(30 * S), WindowBounds::new(0, 60 * S));
        assert_eq!(a.assign(60 * S), WindowBounds::new(60 * S, 120 * S));
        assert_eq!(a.assign(90 * S), WindowBounds::new(60 * S, 120 * S));
    }

    #[test]
    fn assignment_boundaries() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(10));
        // A timestamp on the boundary opens the next window.
        assert_eq!(a.assign(10 * S), WindowBounds::new(10 * S, 20 * S));
        assert_eq!(a.assign(10 * S - 1), WindowBounds::new(0, 10 * S));
        assert_eq!(a.assign(0), WindowBounds::new(0, 10 * S));
    }

    #[test]
    fn assignment_before_epoch_floors() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(10));
        assert_eq!(a.assign(-1), WindowBounds::new(-10 * S, 0));
        assert_eq!(a.assign(-10 * S), WindowBounds::new(-10 * S, 0));
        assert_eq!(a.assign(-10 * S - 1), WindowBounds::new(-20 * S, -10 * S));
        for ts in [-25 * S, -10 * S, -1, 0, 1, 7 * S] {
            assert!(a.assign(ts).contains(ts), "{ts} must be in its window");
        }
    }

    #[test]
    fn assignment_real_epoch_timestamps() {
        let midnight = 1_704_067_200 * S; // 2024-01-01T00:00:00Z
        let a = TumblingWindowAssigner::new(Duration::from_secs(60));
        assert_eq!(
            a.assign(midnight + 30 * S),
            WindowBounds::new(midnight, midnight + 60 * S)
        );
        assert_eq!(a.assign(midnight + 90 * S).start, midnight + 60 * S);
    }

    #[test]
    fn one_microsecond_windows() {
        let a = TumblingWindowAssigner::from_micros(1);
        assert_eq!(a.assign(42), WindowBounds::new(42, 43));
        assert_eq!(a.window_size(), Duration::from_micros(1));
        assert_eq!(a.size_us(), 1);
    }

    #[test]
    fn closed_windows_from_prior_watermark() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(60));
        let closed = a.closed_windows(
            Watermark::from_micros(30 * S),
            Watermark::from_micros(130 * S),
            5 * S,
        );
        assert_eq!(
            closed,
            vec![
                WindowBounds::new(0, 60 * S),
                WindowBounds::new(60 * S, 120 * S)
            ]
        );
        // A watermark exactly on a window end closes that window.
        let closed = a.closed_windows(
            Watermark::from_micros(59 * S),
            Watermark::from_micros(60 * S),
            0,
        );
        assert_eq!(closed, vec![WindowBounds::new(0, 60 * S)]);
        // A previous watermark exactly on a window end has already closed it.
        let closed = a.closed_windows(
            Watermark::from_micros(60 * S),
            Watermark::from_micros(119 * S),
            0,
        );
        assert!(closed.is_empty());
    }

    #[test]
    fn closed_windows_from_initial_starts_at_earliest_event() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(60));
        let earliest = 1_704_067_200 * S + 15 * S;
        let closed = a.closed_windows(
            Watermark::INITIAL,
            Watermark::from_micros(earliest + 200 * S),
            earliest,
        );
        let first = a.assign(earliest);
        assert_eq!(
            closed,
            vec![
                first,
                WindowBounds::new(first.end, first.end + 60 * S),
                WindowBounds::new(first.end + 60 * S, first.end + 120 * S),
            ]
        );
        // Nothing closed yet when the watermark is still inside the first window.
        assert!(a
            .closed_windows(
                Watermark::INITIAL,
                Watermark::from_micros(earliest + 10 * S),
                earliest
            )
            .is_empty());
    }

    #[test]
    fn closed_windows_ignores_windows_before_earliest_event() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(10));
        // The previous watermark is far behind the first event: windows between
        // them never held data and are not enumerated.
        let closed = a.closed_windows(
            Watermark::from_micros(0),
            Watermark::from_micros(1_000 * S),
            975 * S,
        );
        assert_eq!(
            closed,
            vec![
                WindowBounds::new(970 * S, 980 * S),
                WindowBounds::new(980 * S, 990 * S),
                WindowBounds::new(990 * S, 1_000 * S),
            ]
        );
    }

    #[test]
    fn closed_windows_no_advance() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(60));
        let wm = Watermark::from_micros(30 * S);
        assert!(a.closed_windows(wm, wm, 0).is_empty());
        assert!(a
            .closed_windows(wm, Watermark::from_micros(20 * S), 0)
            .is_empty());
        assert!(a
            .closed_windows(Watermark::INITIAL, Watermark::INITIAL, 0)
            .is_empty());
    }

    #[test]
    fn closed_windows_before_epoch() {
        let a = TumblingWindowAssigner::new(Duration::from_secs(10));
        let closed = a.closed_windows(Watermark::INITIAL, Watermark::from_micros(5 * S), -15 * S);
        assert_eq!(
            closed,
            vec![
                WindowBounds::new(-20 * S, -10 * S),
                WindowBounds::new(-10 * S, 0),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "window size must be positive")]
    fn zero_size_panics() {
        TumblingWindowAssigner::new(Duration::from_secs(0));
    }
}
