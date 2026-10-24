//! Hopping (sliding) window assignment.
//!
//! Hopping windows have a fixed size and start every `slide`; when the slide
//! is shorter than the size they overlap and an event belongs to several
//! windows.
//!
//! ```text
//! Timeline:    0    1    2    3    4    5    6    7    8    9    10
//!              |    |    |    |    |    |    |    |    |    |    |
//! HOP(1, 3):   [--------------)
//!                   [--------------)
//!                        [--------------)
//!                             [--------------)
//! ```

use std::time::Duration;

use super::tumble::{duration_to_micros, floor_to_multiple};
use super::window::WindowBounds;

/// Assigns timestamps to epoch-aligned hopping windows.
///
/// Window starts are the multiples of `slide`; an event at `t` belongs to
/// every window `[s, s + size)` with `s <= t < s + size`. That is
/// `ceil(size / slide)` windows when `size` is a multiple of `slide`, and
/// either `floor(size / slide)` or `ceil(size / slide)` windows otherwise,
/// depending on where in its slide the event falls. Starts floor towards
/// negative infinity, so windows before the epoch are aligned like the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoppingWindowAssigner {
    /// Window size in microseconds.
    size_us: i64,
    /// Slide (hop) interval in microseconds.
    slide_us: i64,
}

impl HoppingWindowAssigner {
    /// Create an assigner: a new window starts every `slide` and lasts `size`.
    ///
    /// # Panics
    ///
    /// Panics if either duration is zero or `slide > size` (which would
    /// leave gaps between windows).
    pub fn new(slide: Duration, size: Duration) -> Self {
        Self::from_micros(
            duration_to_micros(slide, "slide"),
            duration_to_micros(size, "window size"),
        )
    }

    /// Create an assigner from microsecond values.
    ///
    /// # Panics
    ///
    /// Panics if either value is not positive or `slide_us > size_us`.
    pub fn from_micros(slide_us: i64, size_us: i64) -> Self {
        assert!(slide_us > 0, "slide must be positive");
        assert!(size_us > 0, "window size must be positive");
        assert!(
            slide_us <= size_us,
            "slide ({slide_us} us) must not exceed the window size ({size_us} us)"
        );
        Self { size_us, slide_us }
    }

    /// Every window containing `timestamp`, oldest first.
    pub fn assign(&self, timestamp: i64) -> Vec<WindowBounds> {
        let mut windows = Vec::with_capacity(self.max_windows_per_event());
        // The latest window that can contain the timestamp starts at the
        // slide boundary at or before it; walk back while windows still
        // reach the timestamp.
        let mut start = floor_to_multiple(timestamp, self.slide_us);
        while start + self.size_us > timestamp {
            windows.push(WindowBounds::new(start, start + self.size_us));
            start -= self.slide_us;
        }
        windows.reverse();
        windows
    }

    /// Window size in microseconds.
    pub fn size_us(&self) -> i64 {
        self.size_us
    }

    /// Slide interval in microseconds.
    pub fn slide_us(&self) -> i64 {
        self.slide_us
    }

    /// Window size as a `Duration`.
    pub fn window_size(&self) -> Duration {
        Duration::from_micros(self.size_us as u64)
    }

    /// Slide interval as a `Duration`.
    pub fn slide(&self) -> Duration {
        Duration::from_micros(self.slide_us as u64)
    }

    /// The most windows an event can belong to: `ceil(size / slide)`.
    pub fn max_windows_per_event(&self) -> usize {
        ((self.size_us + self.slide_us - 1) / self.slide_us) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windowing::tumble::TumblingWindowAssigner;

    const S: i64 = 1_000_000;

    fn check_all_contain(a: &HoppingWindowAssigner, ts: i64) -> Vec<WindowBounds> {
        let windows = a.assign(ts);
        assert!(!windows.is_empty());
        for w in &windows {
            assert!(w.contains(ts), "window {w} must contain {ts}");
            assert_eq!(w.duration_us(), a.size_us());
            assert_eq!(
                w.start.rem_euclid(a.slide_us()),
                0,
                "start aligned to slide"
            );
        }
        for pair in windows.windows(2) {
            assert_eq!(pair[1].start - pair[0].start, a.slide_us(), "oldest first");
        }
        windows
    }

    #[test]
    fn size_multiple_of_slide() {
        // 5-minute windows every minute: every event is in exactly 5 windows.
        let a = HoppingWindowAssigner::new(Duration::from_secs(60), Duration::from_secs(300));
        assert_eq!(a.max_windows_per_event(), 5);
        let windows = check_all_contain(&a, 600 * S);
        assert_eq!(
            windows,
            vec![
                WindowBounds::new(360 * S, 660 * S),
                WindowBounds::new(420 * S, 720 * S),
                WindowBounds::new(480 * S, 780 * S),
                WindowBounds::new(540 * S, 840 * S),
                WindowBounds::new(600 * S, 900 * S),
            ]
        );
        for ts in [0, 5 * S, 10 * S, 25 * S, 100 * S, 599 * S + 999_999] {
            assert_eq!(check_all_contain(&a, ts).len(), 5);
        }
    }

    #[test]
    fn size_not_multiple_of_slide() {
        // 25 s windows every 10 s, starting at multiples of 10 s. An event at
        // t = 31 s is in [10, 35), [20, 45) and [30, 55): 3 windows; at
        // t = 37 s only in [20, 45) and [30, 55): 2 windows.
        let a = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(25));
        assert_eq!(a.max_windows_per_event(), 3);
        assert_eq!(
            check_all_contain(&a, 31 * S),
            vec![
                WindowBounds::new(10 * S, 35 * S),
                WindowBounds::new(20 * S, 45 * S),
                WindowBounds::new(30 * S, 55 * S),
            ]
        );
        assert_eq!(
            check_all_contain(&a, 37 * S),
            vec![
                WindowBounds::new(20 * S, 45 * S),
                WindowBounds::new(30 * S, 55 * S),
            ]
        );
        // The exclusive end: t = 35 s is no longer in [10, 35).
        assert_eq!(
            check_all_contain(&a, 35 * S),
            vec![
                WindowBounds::new(20 * S, 45 * S),
                WindowBounds::new(30 * S, 55 * S),
            ]
        );
    }

    #[test]
    fn boundaries() {
        let a = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));
        // On a slide boundary the window ending there is excluded.
        assert_eq!(
            check_all_contain(&a, 30 * S),
            vec![
                WindowBounds::new(10 * S, 40 * S),
                WindowBounds::new(20 * S, 50 * S),
                WindowBounds::new(30 * S, 60 * S),
            ]
        );
        assert_eq!(
            check_all_contain(&a, 30 * S - 1),
            vec![
                WindowBounds::new(0, 30 * S),
                WindowBounds::new(10 * S, 40 * S),
                WindowBounds::new(20 * S, 50 * S),
            ]
        );
    }

    #[test]
    fn before_epoch_floors() {
        let a = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));
        assert_eq!(
            check_all_contain(&a, -1),
            vec![
                WindowBounds::new(-30 * S, 0),
                WindowBounds::new(-20 * S, 10 * S),
                WindowBounds::new(-10 * S, 20 * S),
            ]
        );
        assert_eq!(
            check_all_contain(&a, -10 * S),
            vec![
                WindowBounds::new(-30 * S, 0),
                WindowBounds::new(-20 * S, 10 * S),
                WindowBounds::new(-10 * S, 20 * S),
            ]
        );
        // Near the epoch, windows legitimately start before it.
        assert_eq!(
            check_all_contain(&a, 5 * S),
            vec![
                WindowBounds::new(-20 * S, 10 * S),
                WindowBounds::new(-10 * S, 20 * S),
                WindowBounds::new(0, 30 * S),
            ]
        );
    }

    #[test]
    fn slide_equal_to_size_is_tumble() {
        let hop = HoppingWindowAssigner::new(Duration::from_secs(60), Duration::from_secs(60));
        let tumble = TumblingWindowAssigner::new(Duration::from_secs(60));
        assert_eq!(hop.max_windows_per_event(), 1);
        for ts in [-90 * S, 0, 30 * S, 60 * S, 90 * S, 120 * S] {
            assert_eq!(hop.assign(ts), vec![tumble.assign(ts)]);
        }
    }

    #[test]
    fn real_epoch_timestamps() {
        let midnight = 1_704_067_200 * S;
        let a = HoppingWindowAssigner::new(Duration::from_secs(30), Duration::from_secs(60));
        let windows = check_all_contain(&a, midnight + 45 * S);
        assert_eq!(
            windows,
            vec![
                WindowBounds::new(midnight, midnight + 60 * S),
                WindowBounds::new(midnight + 30 * S, midnight + 90 * S),
            ]
        );
    }

    #[test]
    fn accessors() {
        let a = HoppingWindowAssigner::new(Duration::from_secs(30), Duration::from_secs(300));
        assert_eq!(a.window_size(), Duration::from_secs(300));
        assert_eq!(a.slide(), Duration::from_secs(30));
        assert_eq!(a.size_us(), 300 * S);
        assert_eq!(a.slide_us(), 30 * S);
    }

    #[test]
    #[should_panic(expected = "slide")]
    fn slide_greater_than_size_panics() {
        HoppingWindowAssigner::new(Duration::from_secs(60), Duration::from_secs(30));
    }

    #[test]
    #[should_panic(expected = "slide must be positive")]
    fn zero_slide_panics() {
        HoppingWindowAssigner::new(Duration::from_secs(0), Duration::from_secs(30));
    }

    #[test]
    #[should_panic(expected = "window size must be positive")]
    fn zero_size_panics() {
        HoppingWindowAssigner::from_micros(1, 0);
    }
}
