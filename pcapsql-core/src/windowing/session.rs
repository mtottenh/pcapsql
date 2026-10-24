//! Session window detection.
//!
//! Session windows group the events of one key by activity: two consecutive
//! events of a key belong to the same session when they are at most `gap`
//! apart, and a session's window runs from its first event to its last event
//! plus the gap. Unlike tumbling and hopping windows the bounds depend on the
//! data, so a session is only known once every event of its key has been
//! seen.
//!
//! ```text
//! Timeline:    0    1    2    3    4    5    6    7    8    9    10
//!              |    |    |    |    |    |    |    |    |    |    |
//! Key A:       A    A         A              A    A    A
//!              [----session 1----)           [--session 2----)
//! Key B:            B         B    B
//!                   [------session 1------)
//! gap = 2
//! ```

use super::window::WindowBounds;

/// Assign every event to its session window.
///
/// `keys[i]` and `timestamps[i]` describe event `i`; the result holds event
/// `i`'s window at index `i`. Events of one key are grouped into sessions by
/// time: an event starts a new session when it is more than `gap_us` after
/// the previous event of the same key, and every event of a session is
/// assigned the final bounds `[first event, last event + gap_us)`.
///
/// The input may be in any order — the capture order of a join output or of
/// several parse partitions is not time-ordered per key — because detection
/// sorts the events by `(key, timestamp)` internally. The result is still
/// indexed by the input position.
///
/// # Panics
///
/// Panics if the slices differ in length or `gap_us` is not positive.
pub fn detect_sessions<K: Ord>(keys: &[K], timestamps: &[i64], gap_us: i64) -> Vec<WindowBounds> {
    assert_eq!(
        keys.len(),
        timestamps.len(),
        "keys and timestamps must be parallel"
    );
    assert!(gap_us > 0, "session gap must be positive");
    let len = keys.len();
    if len == 0 {
        return Vec::new();
    }

    // Visit the events key by key in time order.
    let mut order: Vec<usize> = (0..len).collect();
    order.sort_unstable_by(|&a, &b| {
        keys[a]
            .cmp(&keys[b])
            .then_with(|| timestamps[a].cmp(&timestamps[b]))
    });

    // Sweep: a run of the same key is cut into sessions wherever the gap to
    // the previous event exceeds `gap_us`; all events of a session receive
    // its final bounds.
    let mut bounds = vec![WindowBounds { start: 0, end: 0 }; len];
    let mut run_start = 0;
    while run_start < len {
        let mut run_end = run_start + 1;
        while run_end < len
            && keys[order[run_end]] == keys[order[run_start]]
            && timestamps[order[run_end]] - timestamps[order[run_end - 1]] <= gap_us
        {
            run_end += 1;
        }
        let session = WindowBounds::new(
            timestamps[order[run_start]],
            timestamps[order[run_end - 1]] + gap_us,
        );
        for &event in &order[run_start..run_end] {
            bounds[event] = session;
        }
        run_start = run_end;
    }
    bounds
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000;

    #[test]
    fn single_key_splits_on_gap() {
        let keys = ["A"; 5];
        let ts = [S, 3 * S, 4 * S, 15 * S, 17 * S];
        let bounds = detect_sessions(&keys, &ts, 5 * S);
        let first = WindowBounds::new(S, 9 * S); // last event 4 s + gap
        let second = WindowBounds::new(15 * S, 22 * S);
        assert_eq!(bounds, vec![first, first, first, second, second]);
    }

    #[test]
    fn keys_have_independent_sessions() {
        let keys = ["A", "B", "A", "B", "A"];
        let ts = [S, 2 * S, 3 * S, 4 * S, 15 * S];
        let bounds = detect_sessions(&keys, &ts, 5 * S);
        let a1 = WindowBounds::new(S, 8 * S);
        let a2 = WindowBounds::new(15 * S, 20 * S);
        let b = WindowBounds::new(2 * S, 9 * S);
        assert_eq!(bounds, vec![a1, b, a1, b, a2]);
    }

    #[test]
    fn out_of_order_input_is_sorted_first() {
        // Processed in input order with gap 5 s, the event at 2 s would be
        // judged against the one at 20 s and land in the second session.
        let keys = ["A", "A", "A"];
        let ts = [S, 20 * S, 2 * S];
        let bounds = detect_sessions(&keys, &ts, 5 * S);
        let first = WindowBounds::new(S, 7 * S);
        let second = WindowBounds::new(20 * S, 25 * S);
        assert_eq!(bounds, vec![first, second, first]);
        for (i, w) in bounds.iter().enumerate() {
            assert!(w.contains(ts[i]), "event {i} at {} not in {w}", ts[i]);
        }
    }

    #[test]
    fn out_of_order_input_lowers_session_start() {
        // The earliest event arrives last: the session must start at it.
        let keys = ["k", "k", "k"];
        let ts = [5 * S, 7 * S, 3 * S];
        let bounds = detect_sessions(&keys, &ts, 3 * S);
        let w = WindowBounds::new(3 * S, 10 * S);
        assert_eq!(bounds, vec![w, w, w]);
    }

    #[test]
    fn interleaved_keys_out_of_order() {
        let keys = ["B", "A", "B", "A", "A", "B"];
        let ts = [30 * S, 10 * S, 2 * S, S, 40 * S, 31 * S];
        let bounds = detect_sessions(&keys, &ts, 5 * S);
        // A: 1 s → 10 s is a 9 s gap > 5 s, so three sessions; B: 2 s, then
        // 30 s and 31 s.
        let a1 = WindowBounds::new(S, 6 * S);
        let a2 = WindowBounds::new(10 * S, 15 * S);
        let a3 = WindowBounds::new(40 * S, 45 * S);
        let b1 = WindowBounds::new(2 * S, 7 * S);
        let b2 = WindowBounds::new(30 * S, 36 * S);
        assert_eq!(bounds, vec![b2, a2, b1, a1, a3, b2]);
    }

    #[test]
    fn gap_boundary_is_inclusive() {
        // Exactly `gap` apart extends the session; one microsecond more splits.
        let keys = ["A", "A", "A"];
        let ts = [S, 6 * S, 11 * S + 1];
        let bounds = detect_sessions(&keys, &ts, 5 * S);
        let first = WindowBounds::new(S, 11 * S);
        let second = WindowBounds::new(11 * S + 1, 16 * S + 1);
        assert_eq!(bounds, vec![first, first, second]);
    }

    #[test]
    fn duplicate_timestamps_share_a_session() {
        let keys = [1u16, 1, 1];
        let ts = [5 * S, 5 * S, 5 * S];
        let w = WindowBounds::new(5 * S, 8 * S);
        assert_eq!(detect_sessions(&keys, &ts, 3 * S), vec![w, w, w]);
    }

    #[test]
    fn empty_and_single_event() {
        assert!(detect_sessions::<&str>(&[], &[], 5 * S).is_empty());
        assert_eq!(
            detect_sessions(&["A"], &[S], 5 * S),
            vec![WindowBounds::new(S, 6 * S)]
        );
    }

    #[test]
    fn works_before_epoch() {
        let keys = ["A", "A"];
        let ts = [-10 * S, -8 * S];
        let w = WindowBounds::new(-10 * S, -3 * S);
        assert_eq!(detect_sessions(&keys, &ts, 5 * S), vec![w, w]);
    }

    #[test]
    #[should_panic(expected = "session gap must be positive")]
    fn zero_gap_panics() {
        detect_sessions(&["A"], &[0], 0);
    }

    #[test]
    #[should_panic(expected = "parallel")]
    fn mismatched_lengths_panic() {
        detect_sessions(&["A", "A"], &[0], 1);
    }
}
