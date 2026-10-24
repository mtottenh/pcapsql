//! Watermarks: event-time progress for streaming windows.
//!
//! A watermark `W` asserts "every event with a timestamp `<= W` has been
//! observed; anything older that still arrives is late". pcapsql uses
//! *bounded out-of-orderness* watermarking:
//! `watermark = max(observed timestamp) - allowed_lateness`.

use std::time::Duration;

/// Event-time progress, in microseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Watermark(i64);

impl Watermark {
    /// The watermark before any event was observed.
    pub const INITIAL: Watermark = Watermark(i64::MIN);

    /// A watermark at the given microsecond timestamp.
    pub fn from_micros(ts: i64) -> Self {
        Watermark(ts)
    }

    /// The watermark as a microsecond timestamp.
    pub fn as_micros(&self) -> i64 {
        self.0
    }

    /// Whether an event with this timestamp is late: at or before the
    /// watermark.
    pub fn is_late(&self, event_timestamp: i64) -> bool {
        event_timestamp <= self.0
    }
}

impl std::fmt::Display for Watermark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Watermark({}us)", self.0)
    }
}

/// When a [`WatermarkGenerator`] re-evaluates its watermark.
///
/// A re-evaluation emits a new watermark only when it advances; an event
/// that does not raise the maximum observed timestamp never emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkEmitStrategy {
    /// Re-evaluate after every event (precise; one comparison per event).
    EveryEvent,
    /// Re-evaluate every N observed events.
    EveryNEvents(usize),
    /// Re-evaluate once the maximum observed timestamp has advanced by at
    /// least this many microseconds since the last evaluation. A late event
    /// never postpones an evaluation, since it does not move the maximum.
    EveryNMicros(i64),
}

/// Configuration of a [`WatermarkGenerator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkConfig {
    /// How far behind the maximum observed timestamp the watermark trails,
    /// i.e. how much out-of-orderness is tolerated before an event is late.
    pub allowed_lateness: Duration,
    /// How often the watermark is re-evaluated.
    pub emit_strategy: WatermarkEmitStrategy,
    /// Whether to count late events in [`WatermarkStats`].
    pub track_late_events: bool,
}

impl Default for WatermarkConfig {
    /// One second of allowed lateness, re-evaluated every 1000 events, late
    /// events counted.
    fn default() -> Self {
        Self {
            allowed_lateness: Duration::from_secs(1),
            emit_strategy: WatermarkEmitStrategy::EveryNEvents(1000),
            track_late_events: true,
        }
    }
}

/// Counters kept by a [`WatermarkGenerator`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WatermarkStats {
    /// Events observed.
    pub events_processed: u64,
    /// Events observed at or before the watermark current at the time
    /// (only counted with `track_late_events`).
    pub late_events: u64,
    /// Watermarks emitted (advances only).
    pub watermarks_emitted: u64,
    /// Largest observed lateness in microseconds (watermark minus event
    /// timestamp).
    pub max_lateness_us: i64,
}

/// Derives watermarks from observed event timestamps.
///
/// # Example
///
/// ```
/// use pcapsql_core::windowing::{WatermarkConfig, WatermarkEmitStrategy, WatermarkGenerator};
/// use std::time::Duration;
///
/// let mut gen = WatermarkGenerator::new(WatermarkConfig {
///     allowed_lateness: Duration::from_secs(1),
///     emit_strategy: WatermarkEmitStrategy::EveryEvent,
///     track_late_events: true,
/// });
/// let wm = gen.observe(10_000_000).unwrap(); // t = 10 s
/// assert_eq!(wm.as_micros(), 9_000_000); // 10 s - 1 s
/// assert!(gen.is_late(8_500_000));
/// ```
#[derive(Debug)]
pub struct WatermarkGenerator {
    config: WatermarkConfig,
    /// Largest and smallest timestamps observed (`None` before the first).
    max_timestamp: Option<i64>,
    min_timestamp: Option<i64>,
    current: Watermark,
    /// Events since the last re-evaluation.
    events_since_eval: usize,
    /// `max_timestamp` at the last re-evaluation.
    max_at_last_eval: Option<i64>,
    stats: WatermarkStats,
}

impl WatermarkGenerator {
    /// A generator with the given configuration.
    pub fn new(config: WatermarkConfig) -> Self {
        Self {
            config,
            max_timestamp: None,
            min_timestamp: None,
            current: Watermark::INITIAL,
            events_since_eval: 0,
            max_at_last_eval: None,
            stats: WatermarkStats::default(),
        }
    }

    /// Observe an event; returns the new watermark when the strategy
    /// re-evaluates it and it advanced.
    pub fn observe(&mut self, event_timestamp: i64) -> Option<Watermark> {
        self.stats.events_processed += 1;
        if self.config.track_late_events && self.current.is_late(event_timestamp) {
            self.stats.late_events += 1;
            let lateness = self.current.as_micros() - event_timestamp;
            self.stats.max_lateness_us = self.stats.max_lateness_us.max(lateness);
        }
        self.max_timestamp = Some(
            self.max_timestamp
                .map_or(event_timestamp, |m| m.max(event_timestamp)),
        );
        self.min_timestamp = Some(
            self.min_timestamp
                .map_or(event_timestamp, |m| m.min(event_timestamp)),
        );
        self.events_since_eval += 1;

        if self.should_evaluate() {
            self.evaluate()
        } else {
            None
        }
    }

    /// Re-evaluate now, regardless of the strategy (end of stream, periodic
    /// flush); returns the watermark if it advanced.
    pub fn flush(&mut self) -> Option<Watermark> {
        self.max_timestamp?;
        self.evaluate()
    }

    /// The current watermark ([`Watermark::INITIAL`] until the first
    /// emission).
    pub fn current(&self) -> Watermark {
        self.current
    }

    /// The smallest timestamp observed so far (the lower bound for
    /// enumerating closed windows).
    pub fn earliest(&self) -> Option<i64> {
        self.min_timestamp
    }

    /// The largest timestamp observed so far.
    pub fn latest(&self) -> Option<i64> {
        self.max_timestamp
    }

    /// Counters.
    pub fn stats(&self) -> &WatermarkStats {
        &self.stats
    }

    /// Whether an event at this timestamp is late with respect to the
    /// current watermark.
    pub fn is_late(&self, event_timestamp: i64) -> bool {
        self.current.is_late(event_timestamp)
    }

    fn should_evaluate(&self) -> bool {
        match self.config.emit_strategy {
            WatermarkEmitStrategy::EveryEvent => true,
            WatermarkEmitStrategy::EveryNEvents(n) => self.events_since_eval >= n,
            WatermarkEmitStrategy::EveryNMicros(interval) => {
                match (self.max_at_last_eval, self.max_timestamp) {
                    (None, _) => true, // never evaluated
                    (Some(last), Some(max)) => max - last >= interval,
                    (Some(_), None) => false,
                }
            }
        }
    }

    /// Recompute the watermark from the maximum observed timestamp; emits
    /// only an advance. The strategy's counters restart here whether or not
    /// it advanced.
    fn evaluate(&mut self) -> Option<Watermark> {
        self.events_since_eval = 0;
        self.max_at_last_eval = self.max_timestamp;
        let max = self.max_timestamp?;
        let lateness_us = self
            .config
            .allowed_lateness
            .as_micros()
            .min(i64::MAX as u128) as i64;
        let candidate = max.saturating_sub(lateness_us);
        if candidate > self.current.as_micros() {
            self.current = Watermark::from_micros(candidate);
            self.stats.watermarks_emitted += 1;
            Some(self.current)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000;

    fn generator(lateness: Duration, strategy: WatermarkEmitStrategy) -> WatermarkGenerator {
        WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: lateness,
            emit_strategy: strategy,
            track_late_events: true,
        })
    }

    #[test]
    fn watermark_basics() {
        assert_eq!(Watermark::INITIAL.as_micros(), i64::MIN);
        let wm = Watermark::from_micros(S);
        assert!(wm.is_late(500_000));
        assert!(wm.is_late(S)); // at the watermark counts as late
        assert!(!wm.is_late(S + 1));
        assert!(Watermark::from_micros(100) < Watermark::from_micros(200));
        assert_eq!(format!("{wm}"), "Watermark(1000000us)");
        assert!(!Watermark::INITIAL.is_late(i64::MIN + 1));
    }

    #[test]
    fn every_event_trails_max_by_lateness() {
        let mut gen = generator(Duration::from_secs(1), WatermarkEmitStrategy::EveryEvent);
        assert_eq!(gen.observe(10 * S), Some(Watermark::from_micros(9 * S)));
        assert_eq!(gen.observe(12 * S), Some(Watermark::from_micros(11 * S)));
        assert_eq!(gen.current().as_micros(), 11 * S);
        assert_eq!(gen.earliest(), Some(10 * S));
        assert_eq!(gen.latest(), Some(12 * S));
    }

    #[test]
    fn watermark_never_regresses() {
        let mut gen = generator(
            Duration::from_millis(100),
            WatermarkEmitStrategy::EveryEvent,
        );
        let mut prev = Watermark::INITIAL;
        for ts in [S, 2 * S, 1_500_000, 3 * S, 2_500_000] {
            if let Some(wm) = gen.observe(ts) {
                assert!(wm > prev, "an emitted watermark advances");
                prev = wm;
            }
        }
        assert_eq!(gen.current().as_micros(), 3 * S - 100_000);
        // Out-of-order events emit nothing and do not move the watermark.
        let mut gen = generator(Duration::ZERO, WatermarkEmitStrategy::EveryEvent);
        assert_eq!(gen.observe(5 * S), Some(Watermark::from_micros(5 * S)));
        assert_eq!(gen.observe(3 * S), None);
        assert_eq!(gen.current().as_micros(), 5 * S);
        assert_eq!(gen.earliest(), Some(3 * S));
    }

    #[test]
    fn every_n_events_counts_evaluations_not_advances() {
        let mut gen = generator(Duration::ZERO, WatermarkEmitStrategy::EveryNEvents(3));
        assert_eq!(gen.observe(S), None);
        assert_eq!(gen.observe(2 * S), None);
        assert_eq!(gen.observe(3 * S), Some(Watermark::from_micros(3 * S)));
        // Three late events: the evaluation at the third does not advance,
        // and the counter restarts regardless — the next two events do not
        // trigger per-event evaluations.
        assert_eq!(gen.observe(S), None);
        assert_eq!(gen.observe(S), None);
        assert_eq!(gen.observe(S), None);
        assert_eq!(gen.observe(10 * S), None); // 1 of 3 since the last evaluation
        assert_eq!(gen.observe(11 * S), None);
        assert_eq!(gen.observe(S), Some(Watermark::from_micros(11 * S)));
    }

    #[test]
    fn every_n_micros_uses_max_observed_timestamp() {
        let mut gen = generator(Duration::ZERO, WatermarkEmitStrategy::EveryNMicros(S));
        // The first event always evaluates.
        assert_eq!(gen.observe(S), Some(Watermark::from_micros(S)));
        assert_eq!(gen.observe(1_500_000), None);
        assert_eq!(gen.observe(1_800_000), None);
        // A late event does not postpone the evaluation ...
        assert_eq!(gen.observe(1_900_000), None);
        assert_eq!(gen.observe(500_000), None);
        // ... which happens once the maximum has advanced by the interval.
        assert_eq!(gen.observe(2 * S), Some(Watermark::from_micros(2 * S)));
        // Late events after a boundary still do not evaluate (max unchanged).
        assert_eq!(gen.observe(2 * S + 999_999), None);
        assert_eq!(gen.observe(S), None);
        assert_eq!(gen.observe(3 * S), Some(Watermark::from_micros(3 * S)));
    }

    #[test]
    fn flush_forces_evaluation() {
        let mut gen = generator(
            Duration::from_secs(1),
            WatermarkEmitStrategy::EveryNEvents(1000),
        );
        assert!(gen.flush().is_none()); // nothing observed
        gen.observe(5 * S);
        gen.observe(10 * S);
        assert_eq!(gen.current(), Watermark::INITIAL);
        assert_eq!(gen.flush(), Some(Watermark::from_micros(9 * S)));
        assert_eq!(gen.flush(), None); // no advance
        assert_eq!(gen.stats().watermarks_emitted, 1);
    }

    #[test]
    fn late_events_are_counted_with_their_lateness() {
        let mut gen = generator(Duration::from_secs(1), WatermarkEmitStrategy::EveryEvent);
        gen.observe(10 * S); // watermark 9 s
        assert!(gen.is_late(5 * S));
        assert!(!gen.is_late(9 * S + 1));
        gen.observe(5 * S); // 4 s late
        gen.observe(9 * S); // exactly at the watermark: late by 0
        gen.observe(9 * S + 1); // not late
        let stats = gen.stats();
        assert_eq!(stats.events_processed, 4);
        assert_eq!(stats.late_events, 2);
        assert_eq!(stats.max_lateness_us, 4 * S);
        assert_eq!(stats.watermarks_emitted, 1);
    }

    #[test]
    fn late_tracking_can_be_disabled() {
        let mut gen = WatermarkGenerator::new(WatermarkConfig {
            allowed_lateness: Duration::ZERO,
            emit_strategy: WatermarkEmitStrategy::EveryEvent,
            track_late_events: false,
        });
        gen.observe(10 * S);
        gen.observe(S);
        assert_eq!(gen.stats().late_events, 0);
        assert_eq!(gen.stats().events_processed, 2);
    }

    #[test]
    fn default_config() {
        let config = WatermarkConfig::default();
        assert_eq!(config.allowed_lateness, Duration::from_secs(1));
        assert_eq!(
            config.emit_strategy,
            WatermarkEmitStrategy::EveryNEvents(1000)
        );
        assert!(config.track_late_events);
    }

    #[test]
    fn lateness_saturates_near_i64_min() {
        let mut gen = generator(Duration::from_secs(1), WatermarkEmitStrategy::EveryEvent);
        // Subtracting the lateness saturates at i64::MIN, which is INITIAL:
        // no advance, no emission, no overflow.
        assert_eq!(gen.observe(i64::MIN + 1), None);
        assert_eq!(gen.current(), Watermark::INITIAL);
        assert_eq!(gen.observe(0), Some(Watermark::from_micros(-S)));
    }
}
