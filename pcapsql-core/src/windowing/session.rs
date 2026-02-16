//! Session window assignment.
//!
//! Session windows group events by activity gaps per key. Events within
//! a gap duration of each other belong to the same session. Each key
//! has its own independent session timeline.
//!
//! ```text
//! Timeline:    0    1    2    3    4    5    6    7    8    9    10
//!              |    |    |    |    |    |    |    |    |    |    |
//! Key A:       A    A         A              A    A    A
//!              [----Session 1----]            [--Session 2--]
//!                   gap=2                         gap=2
//! Key B:            B         B    B
//!                   [------Session 1------]
//! ```
//!
//! Unlike tumble and hop windows, session boundaries depend on the data
//! (gap-based) rather than fixed intervals. This means session detection
//! requires seeing multiple events to determine boundaries.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use super::window::WindowBounds;

/// Session window assigner.
///
/// Holds the gap duration parameter. Actual session detection is done
/// by [`SessionTracker`] which maintains per-key state.
#[derive(Debug, Clone)]
pub struct SessionWindowAssigner {
    /// Gap duration in microseconds. If no event arrives within this
    /// duration after the last event for a key, the session closes.
    gap_us: i64,
}

impl SessionWindowAssigner {
    /// Create a new session window assigner.
    ///
    /// # Panics
    ///
    /// Panics if `gap` is zero.
    pub fn new(gap: Duration) -> Self {
        let gap_us = gap.as_micros() as i64;
        assert!(gap_us > 0, "Gap must be positive");
        Self { gap_us }
    }

    /// Create from a gap in microseconds.
    pub fn from_micros(gap_us: i64) -> Self {
        assert!(gap_us > 0, "Gap must be positive");
        Self { gap_us }
    }

    /// Get the gap in microseconds.
    pub fn gap_us(&self) -> i64 {
        self.gap_us
    }

    /// Get the gap as Duration.
    pub fn gap(&self) -> Duration {
        Duration::from_micros(self.gap_us as u64)
    }
}

/// An active session for a specific key.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    /// Session start (first event timestamp).
    pub start: i64,
    /// Last event timestamp in this session.
    pub last_event: i64,
}

impl ActiveSession {
    /// Get the window bounds for this session.
    ///
    /// The window end is `last_event + gap_us` to represent the session
    /// timeout boundary.
    pub fn bounds(&self, gap_us: i64) -> WindowBounds {
        WindowBounds::new(self.start, self.last_event + gap_us)
    }
}

/// Tracks active sessions per key.
///
/// Used for incremental session detection. As events arrive, the tracker
/// creates, extends, or closes sessions based on the gap threshold.
#[derive(Debug)]
pub struct SessionTracker<K: Eq + Hash + Clone> {
    /// Active sessions per key.
    sessions: HashMap<K, ActiveSession>,
    /// Gap duration in microseconds.
    gap_us: i64,
}

impl<K: Eq + Hash + Clone> SessionTracker<K> {
    /// Create a new session tracker.
    pub fn new(gap: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            gap_us: gap.as_micros() as i64,
        }
    }

    /// Create from gap in microseconds.
    pub fn from_micros(gap_us: i64) -> Self {
        Self {
            sessions: HashMap::new(),
            gap_us,
        }
    }

    /// Observe an event for a key at a given timestamp.
    ///
    /// Returns `Some(WindowBounds)` if a previous session was closed
    /// (gap exceeded), or `None` if the event was added to an existing
    /// session or a new session was created.
    pub fn observe(&mut self, key: K, timestamp: i64) -> Option<WindowBounds> {
        if let Some(session) = self.sessions.get_mut(&key) {
            if timestamp - session.last_event > self.gap_us {
                // Gap exceeded — close old session, start new
                let closed = session.bounds(self.gap_us);
                *session = ActiveSession {
                    start: timestamp,
                    last_event: timestamp,
                };
                Some(closed)
            } else {
                // Extend existing session
                session.last_event = timestamp.max(session.last_event);
                None
            }
        } else {
            // First event for this key
            self.sessions.insert(
                key,
                ActiveSession {
                    start: timestamp,
                    last_event: timestamp,
                },
            );
            None
        }
    }

    /// Close all sessions that have timed out based on watermark.
    ///
    /// A session is timed out when `last_event + gap <= watermark`.
    pub fn close_expired(&mut self, watermark_us: i64) -> Vec<(K, WindowBounds)> {
        let gap_us = self.gap_us;
        let mut closed = Vec::new();
        self.sessions.retain(|key, session| {
            if session.last_event + gap_us <= watermark_us {
                closed.push((key.clone(), session.bounds(gap_us)));
                false
            } else {
                true
            }
        });
        closed
    }

    /// Close all remaining sessions and return them.
    pub fn flush_all(&mut self) -> Vec<(K, WindowBounds)> {
        let gap_us = self.gap_us;
        self.sessions
            .drain()
            .map(|(key, session)| (key, session.bounds(gap_us)))
            .collect()
    }

    /// Get the number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get a session for a specific key.
    pub fn get_session(&self, key: &K) -> Option<&ActiveSession> {
        self.sessions.get(key)
    }
}

/// Detect sessions in a batch of events.
///
/// Processes events in order and assigns each to a session per key.
/// Events for the same key that are within `gap_us` of each other
/// are grouped into the same session.
///
/// # Arguments
/// * `keys` - Key values for each event (parallel to `timestamps`)
/// * `timestamps` - Timestamps for each event (parallel to `keys`)
/// * `gap_us` - Session gap in microseconds
///
/// # Returns
/// A vector of `WindowBounds`, one per input event. Note that the
/// bounds for events in the same session will be identical and reflect
/// the final session boundaries (start = first event, end = last event + gap).
pub fn detect_sessions<K: Eq + Hash + Clone>(
    keys: &[K],
    timestamps: &[i64],
    gap_us: i64,
) -> Vec<WindowBounds> {
    assert_eq!(keys.len(), timestamps.len());

    if keys.is_empty() {
        return Vec::new();
    }

    let len = keys.len();

    // Phase 1: Assign each event to a session group.
    // A session group is identified by an index into `session_groups`.
    let mut event_session_ids: Vec<usize> = Vec::with_capacity(len);
    let mut session_groups: Vec<(i64, i64)> = Vec::new(); // (start, last_event) per group
    let mut key_active_session: HashMap<K, usize> = HashMap::new(); // key -> group index

    for i in 0..len {
        let key = &keys[i];
        let ts = timestamps[i];

        if let Some(&session_idx) = key_active_session.get(key) {
            let (_, ref mut last_event) = session_groups[session_idx];
            if ts - *last_event > gap_us {
                // Gap exceeded, start new session group
                let new_idx = session_groups.len();
                session_groups.push((ts, ts));
                key_active_session.insert(key.clone(), new_idx);
                event_session_ids.push(new_idx);
            } else {
                // Extend session
                *last_event = ts.max(*last_event);
                event_session_ids.push(session_idx);
            }
        } else {
            // First event for this key
            let new_idx = session_groups.len();
            session_groups.push((ts, ts));
            key_active_session.insert(key.clone(), new_idx);
            event_session_ids.push(new_idx);
        }
    }

    // Phase 2: Convert session groups to WindowBounds and map each event.
    let session_bounds: Vec<WindowBounds> = session_groups
        .iter()
        .map(|(start, last_event)| WindowBounds::new(*start, *last_event + gap_us))
        .collect();

    event_session_ids
        .iter()
        .map(|&idx| session_bounds[idx])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_assigner_new() {
        let assigner = SessionWindowAssigner::new(Duration::from_secs(30));
        assert_eq!(assigner.gap_us(), 30_000_000);
        assert_eq!(assigner.gap(), Duration::from_secs(30));
    }

    #[test]
    fn test_session_assigner_from_micros() {
        let assigner = SessionWindowAssigner::from_micros(5_000_000);
        assert_eq!(assigner.gap_us(), 5_000_000);
    }

    #[test]
    #[should_panic(expected = "Gap must be positive")]
    fn test_session_assigner_zero_gap() {
        SessionWindowAssigner::new(Duration::from_secs(0));
    }

    #[test]
    fn test_tracker_single_key_single_session() {
        let mut tracker = SessionTracker::<&str>::new(Duration::from_secs(5));

        // Events within gap → same session
        assert!(tracker.observe("A", 1_000_000).is_none()); // t=1s, new session
        assert!(tracker.observe("A", 3_000_000).is_none()); // t=3s, extend
        assert!(tracker.observe("A", 4_000_000).is_none()); // t=4s, extend

        assert_eq!(tracker.active_count(), 1);

        let session = tracker.get_session(&"A").unwrap();
        assert_eq!(session.start, 1_000_000);
        assert_eq!(session.last_event, 4_000_000);
    }

    #[test]
    fn test_tracker_single_key_gap_closes_session() {
        let mut tracker = SessionTracker::<&str>::new(Duration::from_secs(5));

        assert!(tracker.observe("A", 1_000_000).is_none()); // t=1s
        assert!(tracker.observe("A", 3_000_000).is_none()); // t=3s

        // t=10s: gap from 3s is 7s > 5s → closes old session
        let closed = tracker.observe("A", 10_000_000);
        assert!(closed.is_some());
        let bounds = closed.unwrap();
        assert_eq!(bounds.start, 1_000_000); // Old session start
        assert_eq!(bounds.end, 8_000_000); // last_event(3s) + gap(5s)

        // New session started
        let session = tracker.get_session(&"A").unwrap();
        assert_eq!(session.start, 10_000_000);
    }

    #[test]
    fn test_tracker_multiple_keys() {
        let mut tracker = SessionTracker::<&str>::new(Duration::from_secs(5));

        assert!(tracker.observe("A", 1_000_000).is_none());
        assert!(tracker.observe("B", 2_000_000).is_none());
        assert!(tracker.observe("A", 3_000_000).is_none());
        assert!(tracker.observe("B", 4_000_000).is_none());

        assert_eq!(tracker.active_count(), 2);

        let session_a = tracker.get_session(&"A").unwrap();
        assert_eq!(session_a.start, 1_000_000);
        assert_eq!(session_a.last_event, 3_000_000);

        let session_b = tracker.get_session(&"B").unwrap();
        assert_eq!(session_b.start, 2_000_000);
        assert_eq!(session_b.last_event, 4_000_000);
    }

    #[test]
    fn test_tracker_close_expired() {
        let mut tracker = SessionTracker::<&str>::new(Duration::from_secs(5));

        tracker.observe("A", 1_000_000); // session A ends at 6s
        tracker.observe("B", 3_000_000); // session B ends at 8s

        // Watermark at 7s: only A's session expires (end=6s <= 7s)
        let closed = tracker.close_expired(7_000_000);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0, "A");
        assert_eq!(closed[0].1.start, 1_000_000);
        assert_eq!(closed[0].1.end, 6_000_000);

        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_tracker_flush_all() {
        let mut tracker = SessionTracker::<&str>::new(Duration::from_secs(5));

        tracker.observe("A", 1_000_000);
        tracker.observe("B", 2_000_000);

        let flushed = tracker.flush_all();
        assert_eq!(flushed.len(), 2);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_detect_sessions_single_key() {
        let keys = vec!["A", "A", "A", "A", "A"];
        let timestamps = vec![
            1_000_000,  // t=1s
            3_000_000,  // t=3s (gap=2s, within 5s)
            4_000_000,  // t=4s (gap=1s, within 5s)
            15_000_000, // t=15s (gap=11s, exceeds 5s → new session)
            17_000_000, // t=17s (gap=2s, within 5s)
        ];
        let gap_us = 5_000_000; // 5s

        let bounds = detect_sessions(&keys, &timestamps, gap_us);
        assert_eq!(bounds.len(), 5);

        // First 3 events: session [1s, 4s + 5s = 9s)
        assert_eq!(bounds[0], WindowBounds::new(1_000_000, 9_000_000));
        assert_eq!(bounds[1], WindowBounds::new(1_000_000, 9_000_000));
        assert_eq!(bounds[2], WindowBounds::new(1_000_000, 9_000_000));

        // Last 2 events: session [15s, 17s + 5s = 22s)
        assert_eq!(bounds[3], WindowBounds::new(15_000_000, 22_000_000));
        assert_eq!(bounds[4], WindowBounds::new(15_000_000, 22_000_000));
    }

    #[test]
    fn test_detect_sessions_multiple_keys() {
        let keys = vec!["A", "B", "A", "B", "A"];
        let timestamps = vec![
            1_000_000,  // A t=1s
            2_000_000,  // B t=2s
            3_000_000,  // A t=3s (gap=2s, within 5s)
            4_000_000,  // B t=4s (gap=2s, within 5s)
            15_000_000, // A t=15s (gap=12s, exceeds 5s → new session)
        ];
        let gap_us = 5_000_000;

        let bounds = detect_sessions(&keys, &timestamps, gap_us);
        assert_eq!(bounds.len(), 5);

        // A events: session 1 [1s, 8s), session 2 [15s, 20s)
        assert_eq!(bounds[0], WindowBounds::new(1_000_000, 8_000_000));
        assert_eq!(bounds[2], WindowBounds::new(1_000_000, 8_000_000));
        assert_eq!(bounds[4], WindowBounds::new(15_000_000, 20_000_000));

        // B events: session [2s, 9s)
        assert_eq!(bounds[1], WindowBounds::new(2_000_000, 9_000_000));
        assert_eq!(bounds[3], WindowBounds::new(2_000_000, 9_000_000));
    }

    #[test]
    fn test_detect_sessions_empty() {
        let keys: Vec<&str> = vec![];
        let timestamps: Vec<i64> = vec![];
        let bounds = detect_sessions(&keys, &timestamps, 5_000_000);
        assert!(bounds.is_empty());
    }

    #[test]
    fn test_detect_sessions_single_event() {
        let keys = vec!["A"];
        let timestamps = vec![1_000_000];
        let bounds = detect_sessions(&keys, &timestamps, 5_000_000);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0], WindowBounds::new(1_000_000, 6_000_000));
    }

    #[test]
    fn test_active_session_bounds() {
        let session = ActiveSession {
            start: 1_000_000,
            last_event: 4_000_000,
        };
        let bounds = session.bounds(5_000_000);
        assert_eq!(bounds.start, 1_000_000);
        assert_eq!(bounds.end, 9_000_000); // 4s + 5s
    }

    #[test]
    fn test_tracker_exact_gap_boundary() {
        let mut tracker = SessionTracker::<&str>::new(Duration::from_secs(5));

        tracker.observe("A", 1_000_000); // t=1s

        // t=6s: gap from 1s is exactly 5s. This is NOT within gap (> check).
        let closed = tracker.observe("A", 6_000_000);
        assert!(closed.is_none()); // 6 - 1 = 5, which is NOT > 5, so extends

        // t=11.000001s: gap from 6s is 5.000001s > 5s → new session
        let closed = tracker.observe("A", 11_000_001);
        assert!(closed.is_some());
    }
}
