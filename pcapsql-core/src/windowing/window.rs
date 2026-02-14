//! Window bounds for time-based windowing.

use super::watermark::Watermark;

/// Bounds of a time window.
///
/// Windows use half-open intervals: `[start, end)` where start is inclusive
/// and end is exclusive. All timestamps are in microseconds since Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WindowBounds {
    /// Start of window (inclusive), microseconds since epoch.
    pub start: i64,
    /// End of window (exclusive), microseconds since epoch.
    pub end: i64,
}

impl WindowBounds {
    /// Create new window bounds.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `start < end`.
    pub fn new(start: i64, end: i64) -> Self {
        debug_assert!(start < end, "Window start must be before end");
        Self { start, end }
    }

    /// Check if a timestamp falls within this window.
    #[inline]
    pub fn contains(&self, timestamp: i64) -> bool {
        timestamp >= self.start && timestamp < self.end
    }

    /// Get window duration in microseconds.
    pub fn duration_us(&self) -> i64 {
        self.end - self.start
    }

    /// Check if this window is closed by a watermark.
    #[inline]
    pub fn is_closed_by(&self, watermark: Watermark) -> bool {
        watermark.as_micros() >= self.end
    }
}

impl std::fmt::Display for WindowBounds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_bounds_new() {
        let w = WindowBounds::new(0, 100);
        assert_eq!(w.start, 0);
        assert_eq!(w.end, 100);
    }

    #[test]
    fn test_window_bounds_contains() {
        let w = WindowBounds::new(100, 200);

        // Boundary tests
        assert!(w.contains(100)); // Inclusive start
        assert!(!w.contains(200)); // Exclusive end
        assert!(w.contains(150)); // Interior
        assert!(!w.contains(99)); // Before start
        assert!(!w.contains(201)); // After end
    }

    #[test]
    fn test_window_bounds_duration() {
        let w = WindowBounds::new(1_000_000, 61_000_000);
        assert_eq!(w.duration_us(), 60_000_000);
    }

    #[test]
    fn test_window_bounds_is_closed_by() {
        let w = WindowBounds::new(0, 60_000_000); // [0, 60s)

        // Watermark at 59s: window still open
        assert!(!w.is_closed_by(Watermark::from_micros(59_000_000)));

        // Watermark at exactly 60s: window closes
        assert!(w.is_closed_by(Watermark::from_micros(60_000_000)));

        // Watermark at 61s: window definitely closed
        assert!(w.is_closed_by(Watermark::from_micros(61_000_000)));
    }

    #[test]
    fn test_window_bounds_ordering() {
        let w1 = WindowBounds::new(0, 60_000_000);
        let w2 = WindowBounds::new(60_000_000, 120_000_000);
        let w3 = WindowBounds::new(0, 120_000_000);

        assert!(w1 < w2);
        assert!(w1 < w3); // Same start, smaller end
    }

    #[test]
    fn test_window_bounds_display() {
        let w = WindowBounds::new(1000, 2000);
        assert_eq!(format!("{w}"), "[1000, 2000)");
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn test_window_bounds_invalid() {
        WindowBounds::new(200, 100); // start > end
    }
}
