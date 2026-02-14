//! Tumbling window assignment.
//!
//! Tumbling windows are fixed-size, non-overlapping, epoch-aligned windows.
//! Each event belongs to exactly one window.
//!
//! ```text
//! Timeline:    0    1    2    3    4    5    6    7    8    9    10
//!              |    |    |    |    |    |    |    |    |    |    |
//! TUMBLE(2):   [----]    [----]    [----]    [----]    [----]
//!              w0        w1        w2        w3        w4
//! ```

use std::time::Duration;

use super::watermark::Watermark;
use super::window::WindowBounds;

/// Tumbling window assigner.
///
/// Assigns each event to exactly one non-overlapping, epoch-aligned window.
/// Assignment is O(1) — a single integer division and multiplication.
#[derive(Debug, Clone)]
pub struct TumblingWindowAssigner {
    /// Window size in microseconds.
    size_us: i64,
}

impl TumblingWindowAssigner {
    /// Create a new tumbling window assigner.
    ///
    /// # Panics
    ///
    /// Panics if `window_size` is zero.
    pub fn new(window_size: Duration) -> Self {
        let size_us = window_size.as_micros() as i64;
        assert!(size_us > 0, "Window size must be positive");
        Self { size_us }
    }

    /// Create from a size in microseconds.
    pub fn from_micros(size_us: i64) -> Self {
        assert!(size_us > 0, "Window size must be positive");
        Self { size_us }
    }

    /// Assign a timestamp to its tumbling window.
    ///
    /// Each timestamp belongs to exactly one window.
    #[inline]
    pub fn assign(&self, timestamp: i64) -> WindowBounds {
        // Use floor division for epoch-aligned windows.
        // Rust's integer division truncates toward zero, which works correctly
        // for non-negative timestamps (which pcap timestamps always are).
        let window_start = (timestamp / self.size_us) * self.size_us;
        WindowBounds::new(window_start, window_start + self.size_us)
    }

    /// Get the window size in microseconds.
    pub fn size_us(&self) -> i64 {
        self.size_us
    }

    /// Get the window size as a Duration.
    pub fn window_size(&self) -> Duration {
        Duration::from_micros(self.size_us as u64)
    }

    /// Get the next window after the given one.
    pub fn next_window(&self, window: &WindowBounds) -> WindowBounds {
        WindowBounds::new(window.end, window.end + self.size_us)
    }

    /// Get all windows that are newly closed between two watermarks.
    ///
    /// Returns windows with `end > prev_watermark` and `end <= new_watermark`.
    pub fn closed_windows(
        &self,
        prev_watermark: Watermark,
        new_watermark: Watermark,
    ) -> Vec<WindowBounds> {
        let mut windows = Vec::new();

        if new_watermark <= prev_watermark {
            return windows;
        }

        // Find first window end that's after prev_watermark
        let first_end = ((prev_watermark.as_micros() / self.size_us) + 1) * self.size_us;

        // Iterate through windows that are now closed
        let mut end = first_end;
        while end <= new_watermark.as_micros() {
            windows.push(WindowBounds::new(end - self.size_us, end));
            end += self.size_us;
        }

        windows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tumble_assignment_basic() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));

        // t=30s should be in [0, 60s)
        let w = assigner.assign(30_000_000);
        assert_eq!(w.start, 0);
        assert_eq!(w.end, 60_000_000);

        // t=60s should be in [60s, 120s)
        let w = assigner.assign(60_000_000);
        assert_eq!(w.start, 60_000_000);
        assert_eq!(w.end, 120_000_000);

        // t=90s should be in [60s, 120s)
        let w = assigner.assign(90_000_000);
        assert_eq!(w.start, 60_000_000);
        assert_eq!(w.end, 120_000_000);
    }

    #[test]
    fn test_tumble_assignment_boundary() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(10));

        // Exact boundary: t=10s should be in [10s, 20s), not [0, 10s)
        let w = assigner.assign(10_000_000);
        assert_eq!(w.start, 10_000_000);
        assert_eq!(w.end, 20_000_000);

        // Just before boundary: t=9.999999s should be in [0, 10s)
        let w = assigner.assign(9_999_999);
        assert_eq!(w.start, 0);
        assert_eq!(w.end, 10_000_000);
    }

    #[test]
    fn test_tumble_window_contains() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));
        let window = assigner.assign(30_000_000);

        assert!(window.contains(0));
        assert!(window.contains(30_000_000));
        assert!(window.contains(59_999_999));
        assert!(!window.contains(60_000_000)); // Exclusive end
    }

    #[test]
    fn test_tumble_deterministic() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));

        // Same timestamp should always yield same window
        let w1 = assigner.assign(45_000_000);
        let w2 = assigner.assign(45_000_000);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_tumble_non_overlapping() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));

        // Adjacent windows should not overlap
        let w1 = assigner.assign(30_000_000); // [0, 60s)
        let w2 = assigner.assign(90_000_000); // [60s, 120s)

        assert_eq!(w1.end, w2.start);
        assert!(!w1.contains(w2.start));
    }

    #[test]
    fn test_tumble_next_window() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));
        let w = assigner.assign(30_000_000);
        let next = assigner.next_window(&w);

        assert_eq!(next.start, w.end);
        assert_eq!(next.end, w.end + 60_000_000);
    }

    #[test]
    fn test_tumble_closed_windows() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));

        let prev = Watermark::from_micros(30_000_000); // 30s
        let new = Watermark::from_micros(130_000_000); // 130s

        let closed = assigner.closed_windows(prev, new);

        // Windows closed: [0, 60s) and [60s, 120s)
        assert_eq!(closed.len(), 2);
        assert_eq!(closed[0], WindowBounds::new(0, 60_000_000));
        assert_eq!(closed[1], WindowBounds::new(60_000_000, 120_000_000));
    }

    #[test]
    fn test_tumble_closed_windows_no_advance() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));

        let wm = Watermark::from_micros(30_000_000);
        // Same or lower watermark
        assert!(assigner.closed_windows(wm, wm).is_empty());
        assert!(assigner
            .closed_windows(wm, Watermark::from_micros(20_000_000))
            .is_empty());
    }

    #[test]
    fn test_tumble_with_real_timestamps() {
        // Simulate real epoch timestamps (e.g., 2024-01-01 00:00:00 UTC)
        let epoch = 1_704_067_200_000_000i64; // 2024-01-01 00:00:00 UTC in microseconds
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));

        let w = assigner.assign(epoch + 30_000_000); // 30s after midnight
        assert_eq!(w.start, epoch);
        assert_eq!(w.end, epoch + 60_000_000);

        let w2 = assigner.assign(epoch + 90_000_000); // 90s after midnight
        assert_eq!(w2.start, epoch + 60_000_000);
    }

    #[test]
    fn test_tumble_small_window() {
        // 1 microsecond windows
        let assigner = TumblingWindowAssigner::from_micros(1);
        let w = assigner.assign(42);
        assert_eq!(w.start, 42);
        assert_eq!(w.end, 43);
    }

    #[test]
    fn test_tumble_window_size() {
        let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));
        assert_eq!(assigner.window_size(), Duration::from_secs(60));
        assert_eq!(assigner.size_us(), 60_000_000);
    }

    #[test]
    #[should_panic(expected = "Window size must be positive")]
    fn test_tumble_zero_size() {
        TumblingWindowAssigner::new(Duration::from_secs(0));
    }
}
