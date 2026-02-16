//! Streaming window primitives.
//!
//! This module provides the core building blocks for time-based windowing
//! over packet streams. All types are engine-agnostic (no DataFusion dependency)
//! and operate on microsecond timestamps matching pcap packet timestamps.
//!
//! ## Components
//!
//! - [`Watermark`] / [`WatermarkGenerator`] — Track event-time progress using
//!   bounded out-of-orderness watermarking.
//! - [`WindowBounds`] — Half-open `[start, end)` time interval in microseconds.
//! - [`TumblingWindowAssigner`] — Fixed-size, non-overlapping, epoch-aligned windows.
//! - [`HoppingWindowAssigner`] — Fixed-size windows with a slide interval (overlap).
//! - [`SessionWindowAssigner`] / [`SessionTracker`] — Variable-length windows based on activity gaps.
//!
//! ## Example
//!
//! ```
//! use pcapsql_core::windowing::*;
//! use std::time::Duration;
//!
//! // Create a tumbling window assigner with 1-minute windows
//! let assigner = TumblingWindowAssigner::new(Duration::from_secs(60));
//!
//! // Assign a timestamp to its window
//! let window = assigner.assign(90_000_000); // t = 90s
//! assert_eq!(window.start, 60_000_000);     // Window [60s, 120s)
//! assert_eq!(window.end, 120_000_000);
//!
//! // Create a watermark generator
//! let mut gen = WatermarkGenerator::new(WatermarkConfig {
//!     allowed_lateness: Duration::from_secs(1),
//!     emit_strategy: WatermarkEmitStrategy::EveryEvent,
//!     track_late_events: true,
//! });
//!
//! // Check if watermark closes the window
//! let wm = gen.observe(130_000_000).unwrap(); // t = 130s, wm = 129s
//! assert!(window.is_closed_by(wm));
//! ```

pub mod hop;
pub mod session;
pub mod tumble;
pub mod watermark;
pub mod window;

pub use hop::HoppingWindowAssigner;
pub use session::{SessionTracker, SessionWindowAssigner};
pub use tumble::TumblingWindowAssigner;
pub use watermark::{
    Watermark, WatermarkConfig, WatermarkEmitStrategy, WatermarkGenerator, WatermarkStats,
};
pub use window::WindowBounds;

/// Window type specification.
///
/// Describes the type and parameters of a window, used to configure
/// window TVFs and streaming aggregation.
#[derive(Debug, Clone)]
pub enum WindowType {
    /// Fixed-size, non-overlapping windows.
    Tumble {
        /// Window size.
        size: std::time::Duration,
    },
    /// Fixed-size windows with a slide interval.
    Hop {
        /// How often a new window starts.
        slide: std::time::Duration,
        /// Duration of each window.
        size: std::time::Duration,
    },
    /// Variable-length windows based on activity gaps per key.
    Session {
        /// Gap duration. If no event arrives within this duration
        /// after the last event for a key, the session closes.
        gap: std::time::Duration,
    },
}

impl WindowType {
    /// Create a tumbling window specification.
    pub fn tumble(size: std::time::Duration) -> Self {
        WindowType::Tumble { size }
    }

    /// Create a hopping window specification.
    pub fn hop(slide: std::time::Duration, size: std::time::Duration) -> Self {
        WindowType::Hop { slide, size }
    }

    /// Create a session window specification.
    pub fn session(gap: std::time::Duration) -> Self {
        WindowType::Session { gap }
    }
}

impl std::fmt::Display for WindowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowType::Tumble { size } => write!(f, "TUMBLE({}s)", size.as_secs()),
            WindowType::Hop { slide, size } => {
                write!(f, "HOP({}s, {}s)", slide.as_secs(), size.as_secs())
            }
            WindowType::Session { gap } => write!(f, "SESSION({}s)", gap.as_secs()),
        }
    }
}
