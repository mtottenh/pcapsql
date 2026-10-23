//! Time-window primitives for packet streams.
//!
//! Engine-agnostic building blocks (no DataFusion dependency) for windowing
//! events by their timestamp. All timestamps are microseconds since the Unix
//! epoch, the unit of the `frames.timestamp` Arrow column.
//!
//! - [`WindowBounds`] — a half-open `[start, end)` interval.
//! - [`TumblingWindowAssigner`] — fixed-size, non-overlapping, epoch-aligned
//!   windows; one per event.
//! - [`HoppingWindowAssigner`] — fixed-size windows starting every `slide`;
//!   an event belongs to every window that covers it.
//! - [`detect_sessions`] — gap-based, per-key session windows over a batch of
//!   events in any order.
//! - [`Watermark`] / [`WatermarkGenerator`] — event-time progress with bounded
//!   out-of-orderness, for deciding when a window is complete.
//! - [`WindowType`] — a window specification (the SQL-facing shape).
//!
//! Window starts floor towards negative infinity, so events before the epoch
//! are assigned like any other.
//!
//! # Example
//!
//! ```
//! use pcapsql_core::windowing::*;
//! use std::time::Duration;
//!
//! let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));
//! let window = assigner.assign(90_000_000); // t = 90 s
//! assert_eq!((window.start, window.end), (60_000_000, 120_000_000));
//!
//! let mut watermarks = WatermarkGenerator::new(WatermarkConfig {
//!     allowed_lateness: Duration::from_secs(1),
//!     emit_strategy: WatermarkEmitStrategy::EveryEvent,
//!     track_late_events: true,
//! });
//! let wm = watermarks.observe(90_000_000).unwrap(); // watermark 89 s: window open
//! assert!(!window.is_closed_by(wm));
//! let wm = watermarks.observe(130_000_000).unwrap(); // watermark 129 s: window closed
//! assert!(window.is_closed_by(wm));
//! assert_eq!(
//!     assigner.closed_windows(Watermark::INITIAL, wm, watermarks.earliest().unwrap()),
//!     vec![window],
//! );
//! ```

pub mod hop;
pub mod session;
pub mod tumble;
pub mod watermark;
pub mod window;

pub use hop::HoppingWindowAssigner;
pub use session::detect_sessions;
pub use tumble::TumblingWindowAssigner;
pub use watermark::{
    Watermark, WatermarkConfig, WatermarkEmitStrategy, WatermarkGenerator, WatermarkStats,
};
pub use window::WindowBounds;

use std::time::Duration;

/// A window specification: the kind of window and its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WindowType {
    /// Fixed-size, non-overlapping windows.
    Tumble {
        /// Window size.
        size: Duration,
    },
    /// Fixed-size windows starting every `slide`.
    Hop {
        /// How often a new window starts.
        slide: Duration,
        /// Duration of each window.
        size: Duration,
    },
    /// Per-key sessions: a session ends when no event of its key arrives for
    /// `gap`.
    Session {
        /// The inactivity gap that ends a session.
        gap: Duration,
    },
}

impl std::fmt::Display for WindowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowType::Tumble { size } => write!(f, "TUMBLE({size:?})"),
            WindowType::Hop { slide, size } => write!(f, "HOP(slide={slide:?}, size={size:?})"),
            WindowType::Session { gap } => write!(f, "SESSION(gap={gap:?})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_type_display() {
        assert_eq!(
            WindowType::Tumble {
                size: Duration::from_secs(10)
            }
            .to_string(),
            "TUMBLE(10s)"
        );
        assert_eq!(
            WindowType::Hop {
                slide: Duration::from_millis(500),
                size: Duration::from_secs(2)
            }
            .to_string(),
            "HOP(slide=500ms, size=2s)"
        );
        assert_eq!(
            WindowType::Session {
                gap: Duration::from_secs(30)
            }
            .to_string(),
            "SESSION(gap=30s)"
        );
    }
}
