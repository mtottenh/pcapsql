//! Hopping (sliding) window assignment.
//!
//! Hopping windows have a fixed size and slide interval, allowing overlap.
//! Each event may belong to multiple windows.
//!
//! ```text
//! Timeline:    0    1    2    3    4    5    6    7    8    9    10
//!              |    |    |    |    |    |    |    |    |    |    |
//! HOP(1, 3):   [--------]
//!                 [--------]
//!                    [--------]
//!                       [--------]
//!                          [--------]
//! ```

use std::time::Duration;

use super::window::WindowBounds;

/// Hopping (sliding) window assigner.
///
/// Assigns each event to one or more overlapping windows.
/// The number of windows per event is `ceil(size / slide)`.
#[derive(Debug, Clone)]
pub struct HoppingWindowAssigner {
    /// Window size in microseconds.
    size_us: i64,
    /// Slide/hop interval in microseconds.
    slide_us: i64,
    /// Number of windows each event belongs to: ceil(size/slide).
    windows_per_event: usize,
}

impl HoppingWindowAssigner {
    /// Create a new hopping window assigner.
    ///
    /// # Arguments
    ///
    /// * `slide` - How often a new window starts
    /// * `size` - Duration of each window
    ///
    /// # Panics
    ///
    /// Panics if slide > size (would create gaps) or if either is zero.
    pub fn new(slide: Duration, size: Duration) -> Self {
        let slide_us = slide.as_micros() as i64;
        let size_us = size.as_micros() as i64;

        assert!(slide_us > 0, "Slide must be positive");
        assert!(size_us > 0, "Size must be positive");
        assert!(
            slide_us <= size_us,
            "Slide ({slide:?}) must be <= size ({size:?})"
        );

        let windows_per_event = ((size_us + slide_us - 1) / slide_us) as usize;

        Self {
            size_us,
            slide_us,
            windows_per_event,
        }
    }

    /// Create from microsecond values.
    pub fn from_micros(slide_us: i64, size_us: i64) -> Self {
        assert!(slide_us > 0, "Slide must be positive");
        assert!(size_us > 0, "Size must be positive");
        assert!(slide_us <= size_us, "Slide must be <= size");

        let windows_per_event = ((size_us + slide_us - 1) / slide_us) as usize;

        Self {
            size_us,
            slide_us,
            windows_per_event,
        }
    }

    /// Assign a timestamp to all its hopping windows.
    ///
    /// Returns multiple windows in chronological order (oldest first).
    pub fn assign(&self, timestamp: i64) -> Vec<WindowBounds> {
        let mut windows = Vec::with_capacity(self.windows_per_event);

        // Find the latest window start aligned to slide that could contain timestamp.
        let last_window_start = (timestamp / self.slide_us) * self.slide_us;

        // Work backwards to find all containing windows.
        let mut window_start = last_window_start;
        while window_start > timestamp - self.size_us {
            let window_end = window_start + self.size_us;
            if timestamp >= window_start && timestamp < window_end {
                windows.push(WindowBounds::new(window_start, window_end));
            }
            window_start -= self.slide_us;
        }

        // Reverse to get chronological order
        windows.reverse();
        windows
    }

    /// Get the window size in microseconds.
    pub fn size_us(&self) -> i64 {
        self.size_us
    }

    /// Get the slide interval in microseconds.
    pub fn slide_us(&self) -> i64 {
        self.slide_us
    }

    /// Get the window size as a Duration.
    pub fn window_size(&self) -> Duration {
        Duration::from_micros(self.size_us as u64)
    }

    /// Get the slide interval as a Duration.
    pub fn slide(&self) -> Duration {
        Duration::from_micros(self.slide_us as u64)
    }

    /// Get the number of windows each event belongs to.
    pub fn windows_per_event(&self) -> usize {
        self.windows_per_event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windowing::tumble::TumblingWindowAssigner;

    #[test]
    fn test_hop_assignment_basic() {
        // 5-minute windows, 1-minute slide
        let assigner = HoppingWindowAssigner::new(
            Duration::from_secs(60),  // 1 min slide
            Duration::from_secs(300), // 5 min size
        );

        // Each event belongs to 5 windows
        assert_eq!(assigner.windows_per_event(), 5);

        // Use a timestamp far enough from 0 so all 5 windows have positive starts.
        // t=600s (10 min) with 5-min window and 1-min slide:
        // Windows starting at 360, 420, 480, 540, 600
        let ts = 600_000_000;
        let windows = assigner.assign(ts);
        assert_eq!(windows.len(), 5);

        // All windows should contain the timestamp
        for w in &windows {
            assert!(w.contains(ts), "Window {w} should contain {ts}");
            assert_eq!(w.duration_us(), 300_000_000);
        }

        // Verify chronological order and specific bounds
        assert_eq!(windows[0], WindowBounds::new(360_000_000, 660_000_000));
        assert_eq!(windows[1], WindowBounds::new(420_000_000, 720_000_000));
        assert_eq!(windows[2], WindowBounds::new(480_000_000, 780_000_000));
        assert_eq!(windows[3], WindowBounds::new(540_000_000, 840_000_000));
        assert_eq!(windows[4], WindowBounds::new(600_000_000, 900_000_000));
    }

    #[test]
    fn test_hop_tumble_equivalence() {
        // Hop with slide == size is equivalent to tumble
        let hop = HoppingWindowAssigner::new(Duration::from_secs(60), Duration::from_secs(60));
        let tumble = TumblingWindowAssigner::new(Duration::from_secs(60));

        for ts in [0, 30_000_000, 60_000_000, 90_000_000, 120_000_000] {
            let hop_windows = hop.assign(ts);
            let tumble_window = tumble.assign(ts);

            assert_eq!(
                hop_windows.len(),
                1,
                "Hop with slide==size should produce exactly 1 window"
            );
            assert_eq!(hop_windows[0], tumble_window);
        }
    }

    #[test]
    fn test_hop_windows_per_event() {
        // 30s window, 10s slide → each event in 3 windows
        let assigner = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));
        assert_eq!(assigner.windows_per_event(), 3);

        let windows = assigner.assign(25_000_000); // t=25s
        assert_eq!(windows.len(), 3);
    }

    #[test]
    fn test_hop_chronological_order() {
        let assigner = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));
        let windows = assigner.assign(25_000_000);

        // Windows should be in chronological order
        for i in 1..windows.len() {
            assert!(
                windows[i].start > windows[i - 1].start,
                "Windows must be in chronological order"
            );
        }
    }

    #[test]
    fn test_hop_all_windows_contain_timestamp() {
        let assigner = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));

        for ts in [0, 5_000_000, 10_000_000, 25_000_000, 100_000_000] {
            let windows = assigner.assign(ts);
            for w in &windows {
                assert!(w.contains(ts), "Window {w} should contain timestamp {ts}");
            }
        }
    }

    #[test]
    fn test_hop_window_sizes_consistent() {
        let assigner = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));
        let windows = assigner.assign(50_000_000);

        for w in &windows {
            assert_eq!(
                w.duration_us(),
                30_000_000,
                "All windows should have size 30s"
            );
        }
    }

    #[test]
    fn test_hop_at_boundary() {
        let assigner = HoppingWindowAssigner::new(Duration::from_secs(10), Duration::from_secs(30));

        // At slide boundary t=10s
        let windows = assigner.assign(10_000_000);

        // Should be in [0, 30s), [10s, 40s)
        // NOT in [-20s, 10s) since t=10s is exclusive end
        assert!(!windows.is_empty());
        for w in &windows {
            assert!(w.contains(10_000_000));
        }
    }

    #[test]
    fn test_hop_window_size_and_slide() {
        let assigner =
            HoppingWindowAssigner::new(Duration::from_secs(30), Duration::from_secs(300));

        assert_eq!(assigner.window_size(), Duration::from_secs(300));
        assert_eq!(assigner.slide(), Duration::from_secs(30));
        assert_eq!(assigner.size_us(), 300_000_000);
        assert_eq!(assigner.slide_us(), 30_000_000);
    }

    #[test]
    fn test_hop_with_real_timestamps() {
        // Simulate real epoch timestamps
        let epoch = 1_704_067_200_000_000i64; // 2024-01-01 00:00:00 UTC

        let assigner = HoppingWindowAssigner::new(Duration::from_secs(30), Duration::from_secs(60));

        let windows = assigner.assign(epoch + 45_000_000); // 45s after epoch

        // All windows should contain the timestamp
        for w in &windows {
            assert!(w.contains(epoch + 45_000_000));
            assert_eq!(w.duration_us(), 60_000_000);
        }
    }

    #[test]
    #[should_panic(expected = "Slide")]
    fn test_hop_slide_greater_than_size() {
        HoppingWindowAssigner::new(Duration::from_secs(60), Duration::from_secs(30));
    }

    #[test]
    #[should_panic(expected = "Slide must be positive")]
    fn test_hop_zero_slide() {
        HoppingWindowAssigner::new(Duration::from_secs(0), Duration::from_secs(30));
    }

    #[test]
    #[should_panic(expected = "Size must be positive")]
    fn test_hop_zero_size() {
        HoppingWindowAssigner::new(Duration::from_secs(1), Duration::from_secs(0));
    }
}
