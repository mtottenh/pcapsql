//! Window bounds for time-based windowing.

use super::watermark::Watermark;

/// Bounds of a time window.
///
/// Windows are half-open intervals `[start, end)`: `start` is inclusive and
/// `end` exclusive. Both are microseconds since the Unix epoch, matching the
/// `frames.timestamp` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WindowBounds {
    /// Start of the window (inclusive), microseconds since the epoch.
    pub start: i64,
    /// End of the window (exclusive), microseconds since the epoch.
    pub end: i64,
}

impl WindowBounds {
    /// Create new window bounds.
    ///
    /// Debug-asserts `start < end`.
    pub fn new(start: i64, end: i64) -> Self {
        debug_assert!(start < end, "window start must be before its end");
        Self { start, end }
    }

    /// Whether `timestamp` falls within this window.
    #[inline]
    pub fn contains(&self, timestamp: i64) -> bool {
        timestamp >= self.start && timestamp < self.end
    }

    /// Window duration in microseconds.
    pub fn duration_us(&self) -> i64 {
        self.end - self.start
    }

    /// Whether a watermark closes this window: no event with a timestamp
    /// inside it can still arrive once the watermark reaches `end`.
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
    fn contains_is_half_open() {
        let w = WindowBounds::new(100, 200);
        assert!(w.contains(100));
        assert!(w.contains(150));
        assert!(w.contains(199));
        assert!(!w.contains(200));
        assert!(!w.contains(99));
    }

    #[test]
    fn duration() {
        assert_eq!(
            WindowBounds::new(1_000_000, 61_000_000).duration_us(),
            60_000_000
        );
    }

    #[test]
    fn closed_by_watermark_at_or_past_end() {
        let w = WindowBounds::new(0, 60_000_000);
        assert!(!w.is_closed_by(Watermark::from_micros(59_999_999)));
        assert!(w.is_closed_by(Watermark::from_micros(60_000_000)));
        assert!(w.is_closed_by(Watermark::from_micros(61_000_000)));
        assert!(!w.is_closed_by(Watermark::INITIAL));
    }

    #[test]
    fn ordering_and_display() {
        let w1 = WindowBounds::new(0, 60_000_000);
        let w2 = WindowBounds::new(60_000_000, 120_000_000);
        let w3 = WindowBounds::new(0, 120_000_000);
        assert!(w1 < w2);
        assert!(w1 < w3);
        assert_eq!(format!("{}", WindowBounds::new(1000, 2000)), "[1000, 2000)");
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn inverted_bounds_panic() {
        WindowBounds::new(200, 100);
    }
}
