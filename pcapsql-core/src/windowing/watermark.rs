//! Watermark infrastructure for streaming windows.
//!
//! A watermark `W` asserts: "All events with timestamp <= W have been observed
//! (or will be considered late)." Watermarks are the fundamental mechanism for
//! tracking progress in event-time processing.
//!
//! pcapsql uses **bounded out-of-orderness** watermarking:
//! `watermark = max(observed_timestamp) - allowed_lateness`

use std::time::Duration;

/// Watermark value representing event time progress.
///
/// Stored as microseconds since Unix epoch to match packet timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Watermark(i64);

impl Watermark {
    /// Initial watermark (no events observed).
    pub const INITIAL: Watermark = Watermark(i64::MIN);

    /// Create a watermark from a timestamp in microseconds.
    pub fn from_micros(ts: i64) -> Self {
        Watermark(ts)
    }

    /// Get the timestamp in microseconds.
    pub fn as_micros(&self) -> i64 {
        self.0
    }

    /// Check if an event with given timestamp is late.
    pub fn is_late(&self, event_timestamp: i64) -> bool {
        event_timestamp <= self.0
    }
}

impl std::fmt::Display for Watermark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Watermark({}us)", self.0)
    }
}

/// Strategy for when to emit watermarks.
#[derive(Debug, Clone)]
pub enum WatermarkEmitStrategy {
    /// Emit watermark after every N events.
    EveryNEvents(usize),
    /// Emit watermark at least every N microseconds of event time.
    EveryNMicros(i64),
    /// Emit watermark after every event (expensive but precise).
    EveryEvent,
}

/// Configuration for watermark generation.
#[derive(Debug, Clone)]
pub struct WatermarkConfig {
    /// Maximum allowed out-of-orderness.
    /// Events arriving more than this duration after their timestamp
    /// may be dropped as late.
    pub allowed_lateness: Duration,
    /// How often to emit watermarks.
    pub emit_strategy: WatermarkEmitStrategy,
    /// Whether to track late events for metrics.
    pub track_late_events: bool,
}

impl Default for WatermarkConfig {
    fn default() -> Self {
        Self {
            // 1 second default lateness for pcap data
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryNEvents(1000),
            track_late_events: true,
        }
    }
}

impl WatermarkConfig {
    /// Configuration for file-based PCAP processing.
    ///
    /// Uses tight lateness bounds since file data is well-ordered.
    pub fn for_file() -> Self {
        Self {
            allowed_lateness: Duration::from_millis(100),
            emit_strategy: WatermarkEmitStrategy::EveryNEvents(1000),
            track_late_events: true,
        }
    }

    /// Configuration for live capture.
    ///
    /// Uses looser lateness bounds to handle capture jitter.
    pub fn for_live_capture() -> Self {
        Self {
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryNEvents(100),
            track_late_events: true,
        }
    }

    /// Configuration for distributed/merged captures.
    pub fn for_distributed() -> Self {
        Self {
            allowed_lateness: Duration::from_secs(5),
            emit_strategy: WatermarkEmitStrategy::EveryNMicros(1_000_000),
            track_late_events: true,
        }
    }
}

/// Statistics about watermark generation.
#[derive(Debug, Default, Clone)]
pub struct WatermarkStats {
    /// Total events processed.
    pub events_processed: u64,
    /// Events that arrived late (after their watermark).
    pub late_events: u64,
    /// Watermarks emitted.
    pub watermarks_emitted: u64,
    /// Maximum observed lateness in microseconds.
    pub max_lateness_us: i64,
}

/// Generates watermarks from observed event timestamps.
///
/// This is the core component that tracks event time progress
/// and emits watermarks based on the configured strategy.
///
/// # Example
///
/// ```
/// use pcapsql_core::windowing::{WatermarkGenerator, WatermarkConfig, WatermarkEmitStrategy};
/// use std::time::Duration;
///
/// let config = WatermarkConfig {
///     allowed_lateness: Duration::from_secs(1),
///     emit_strategy: WatermarkEmitStrategy::EveryEvent,
///     track_late_events: true,
/// };
/// let mut gen = WatermarkGenerator::new(config);
///
/// // Observe events and get watermarks
/// let wm = gen.observe(10_000_000); // t=10s
/// // Watermark = 10s - 1s = 9s
/// assert_eq!(wm.unwrap().as_micros(), 9_000_000);
/// ```
#[derive(Debug)]
pub struct WatermarkGenerator {
    config: WatermarkConfig,
    /// Maximum timestamp observed so far.
    max_timestamp: i64,
    /// Current watermark value.
    current_watermark: Watermark,
    /// Events processed since last watermark emission.
    events_since_emit: usize,
    /// Last watermark emission timestamp (event time).
    last_emit_timestamp: i64,
    /// Statistics.
    stats: WatermarkStats,
}

impl WatermarkGenerator {
    /// Create a new watermark generator with the given configuration.
    pub fn new(config: WatermarkConfig) -> Self {
        Self {
            config,
            max_timestamp: i64::MIN,
            current_watermark: Watermark::INITIAL,
            events_since_emit: 0,
            last_emit_timestamp: i64::MIN,
            stats: WatermarkStats::default(),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(WatermarkConfig::default())
    }

    /// Create with specific allowed lateness.
    pub fn with_lateness(allowed_lateness: Duration) -> Self {
        Self::new(WatermarkConfig {
            allowed_lateness,
            ..Default::default()
        })
    }

    /// Observe an event timestamp and optionally emit a new watermark.
    ///
    /// Returns `Some(watermark)` if a new watermark should be emitted,
    /// `None` otherwise.
    pub fn observe(&mut self, event_timestamp: i64) -> Option<Watermark> {
        self.stats.events_processed += 1;

        // Check if event is late
        if self.config.track_late_events && self.current_watermark.is_late(event_timestamp) {
            self.stats.late_events += 1;
            let lateness = self.current_watermark.as_micros() - event_timestamp;
            self.stats.max_lateness_us = self.stats.max_lateness_us.max(lateness);
        }

        // Update max timestamp
        if event_timestamp > self.max_timestamp {
            self.max_timestamp = event_timestamp;
        }

        self.events_since_emit += 1;

        // Check if we should emit a new watermark
        if self.should_emit(event_timestamp) {
            self.emit_watermark()
        } else {
            None
        }
    }

    /// Force emission of current watermark.
    ///
    /// Useful at end of stream or periodic flushing.
    pub fn flush(&mut self) -> Option<Watermark> {
        if self.max_timestamp > i64::MIN {
            self.emit_watermark()
        } else {
            None
        }
    }

    /// Get the current watermark without advancing.
    pub fn current(&self) -> Watermark {
        self.current_watermark
    }

    /// Get statistics about watermark generation.
    pub fn stats(&self) -> &WatermarkStats {
        &self.stats
    }

    /// Check if an event is late relative to current watermark.
    pub fn is_late(&self, event_timestamp: i64) -> bool {
        self.current_watermark.is_late(event_timestamp)
    }

    fn should_emit(&self, event_timestamp: i64) -> bool {
        match self.config.emit_strategy {
            WatermarkEmitStrategy::EveryEvent => true,
            WatermarkEmitStrategy::EveryNEvents(n) => self.events_since_emit >= n,
            WatermarkEmitStrategy::EveryNMicros(interval) => {
                // Handle initial state where last_emit_timestamp is i64::MIN
                if self.last_emit_timestamp == i64::MIN {
                    return true;
                }
                event_timestamp - self.last_emit_timestamp >= interval
            }
        }
    }

    fn emit_watermark(&mut self) -> Option<Watermark> {
        let lateness_us = self.config.allowed_lateness.as_micros() as i64;
        let new_watermark_ts = self.max_timestamp.saturating_sub(lateness_us);

        // Only emit if watermark advances
        if new_watermark_ts > self.current_watermark.as_micros() {
            let new_watermark = Watermark::from_micros(new_watermark_ts);
            self.current_watermark = new_watermark;
            self.events_since_emit = 0;
            self.last_emit_timestamp = self.max_timestamp;
            self.stats.watermarks_emitted += 1;
            Some(new_watermark)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watermark_initial() {
        assert_eq!(Watermark::INITIAL.as_micros(), i64::MIN);
    }

    #[test]
    fn test_watermark_from_micros() {
        let wm = Watermark::from_micros(1_000_000);
        assert_eq!(wm.as_micros(), 1_000_000);
    }

    #[test]
    fn test_watermark_ordering() {
        let wm1 = Watermark::from_micros(100);
        let wm2 = Watermark::from_micros(200);
        assert!(wm1 < wm2);
        assert!(wm2 > wm1);
        assert_eq!(wm1, Watermark::from_micros(100));
    }

    #[test]
    fn test_watermark_is_late() {
        let wm = Watermark::from_micros(1_000_000);
        assert!(wm.is_late(500_000)); // Before watermark
        assert!(wm.is_late(1_000_000)); // At watermark (late: <= comparison)
        assert!(!wm.is_late(1_500_000)); // After watermark
    }

    #[test]
    fn test_watermark_display() {
        let wm = Watermark::from_micros(1_000_000);
        assert_eq!(format!("{wm}"), "Watermark(1000000us)");
    }

    #[test]
    fn test_generator_with_every_event_strategy() {
        let config = WatermarkConfig {
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        };
        let mut gen = WatermarkGenerator::new(config);

        // First event at t=10s
        let wm = gen.observe(10_000_000);
        assert!(wm.is_some());
        // Watermark = 10s - 1s = 9s
        assert_eq!(wm.unwrap().as_micros(), 9_000_000);

        // Second event at t=12s
        let wm = gen.observe(12_000_000);
        assert!(wm.is_some());
        // Watermark = 12s - 1s = 11s
        assert_eq!(wm.unwrap().as_micros(), 11_000_000);
    }

    #[test]
    fn test_watermark_monotonic() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_millis(100),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        });

        // Process events with some out-of-order
        let timestamps = [1_000_000, 2_000_000, 1_500_000, 3_000_000, 2_500_000];
        let mut prev_watermark = Watermark::INITIAL;

        for ts in timestamps {
            if let Some(wm) = gen.observe(ts) {
                assert!(wm >= prev_watermark, "Watermark must be monotonic");
                prev_watermark = wm;
            }
        }
    }

    #[test]
    fn test_watermark_with_allowed_lateness() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        });

        // Observe event at t=10s
        gen.observe(10_000_000);

        // Watermark should be t=10s - 1s = t=9s
        assert_eq!(gen.current().as_micros(), 9_000_000);
    }

    #[test]
    fn test_generator_out_of_order_no_regression() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_secs(0),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        });

        gen.observe(5_000_000); // wm -> 5s
        assert_eq!(gen.current().as_micros(), 5_000_000);

        // Out-of-order event at t=3s should NOT regress watermark
        gen.observe(3_000_000);
        assert_eq!(gen.current().as_micros(), 5_000_000);
    }

    #[test]
    fn test_emit_strategy_every_n_events() {
        let config = WatermarkConfig {
            allowed_lateness: Duration::from_millis(0),
            emit_strategy: WatermarkEmitStrategy::EveryNEvents(5),
            track_late_events: false,
        };
        let mut gen = WatermarkGenerator::new(config);

        // First 4 events should not emit
        for i in 1..5 {
            assert!(gen.observe(i * 1000).is_none(), "Event {i} should not emit");
        }

        // 5th event should emit
        assert!(gen.observe(5000).is_some(), "5th event should emit");
    }

    #[test]
    fn test_emit_strategy_every_n_micros() {
        let config = WatermarkConfig {
            allowed_lateness: Duration::from_millis(0),
            emit_strategy: WatermarkEmitStrategy::EveryNMicros(1_000_000), // 1s
            track_late_events: false,
        };
        let mut gen = WatermarkGenerator::new(config);

        // First event always emits (initial state)
        assert!(gen.observe(1_000_000).is_some());

        // Events within 1s event-time interval should not emit
        assert!(gen.observe(1_500_000).is_none());
        assert!(gen.observe(1_800_000).is_none());

        // Event >= 1s event-time later should emit
        assert!(gen.observe(2_000_000).is_some());
    }

    #[test]
    fn test_flush() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryNEvents(1000), // Very high
            track_late_events: false,
        });

        // Observe events but don't hit emit threshold
        gen.observe(5_000_000);
        gen.observe(10_000_000);

        // Watermark hasn't been emitted yet via observe
        assert_eq!(gen.current(), Watermark::INITIAL);

        // Flush forces emission
        let wm = gen.flush();
        assert!(wm.is_some());
        assert_eq!(wm.unwrap().as_micros(), 9_000_000); // 10s - 1s
    }

    #[test]
    fn test_flush_no_events() {
        let mut gen = WatermarkGenerator::with_defaults();
        // Flush without any events should return None
        assert!(gen.flush().is_none());
    }

    #[test]
    fn test_late_event_tracking() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        });

        // Advance watermark: observe t=10s, watermark = 9s
        gen.observe(10_000_000);

        // Late event at t=5s (before watermark at 9s)
        gen.observe(5_000_000);

        assert_eq!(gen.stats().late_events, 1);
        assert_eq!(gen.stats().events_processed, 2);
        assert!(gen.stats().max_lateness_us > 0);
    }

    #[test]
    fn test_late_event_detection() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_millis(100),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        });

        // Advance watermark past t=1s
        gen.observe(2_000_000);
        gen.flush();

        // Event at t=0.5s should be late
        assert!(gen.is_late(500_000));

        // Event at t=3s should not be late
        assert!(!gen.is_late(3_000_000));
    }

    #[test]
    fn test_watermark_stats() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::from_secs(0),
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: true,
        });

        for i in 1..=10 {
            gen.observe(i * 1_000_000);
        }

        let stats = gen.stats();
        assert_eq!(stats.events_processed, 10);
        assert_eq!(stats.late_events, 0);
        assert!(stats.watermarks_emitted > 0);
    }

    #[test]
    fn test_config_presets() {
        let file = WatermarkConfig::for_file();
        assert_eq!(file.allowed_lateness, Duration::from_millis(100));

        let live = WatermarkConfig::for_live_capture();
        assert_eq!(live.allowed_lateness, Duration::from_secs(1));

        let dist = WatermarkConfig::for_distributed();
        assert_eq!(dist.allowed_lateness, Duration::from_secs(5));
    }
}
