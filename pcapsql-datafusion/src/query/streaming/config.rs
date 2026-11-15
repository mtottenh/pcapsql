//! What a continuous engine configures, and the window a fused aggregate runs over.

use std::time::Duration;

use pcapsql_core::windowing::WindowType;

/// What a continuous engine tells the fused aggregate.
#[derive(Clone, Debug)]
pub struct ContinuousConfig {
    /// How far the watermark trails the largest timestamp seen: how late a
    /// row may be and still be aggregated.
    pub allowed_lateness: Duration,
    /// Close every open window after this long without input (`None`:
    /// windows close on event time only).
    pub idle_timeout: Option<Duration>,
    /// What to do when the window state does not fit the memory pool.
    pub on_memory_limit: MemoryLimitPolicy,
}

/// What the streaming window aggregate does when its state (open windows ×
/// groups × accumulators, accounted to DataFusion's memory pool) exceeds
/// the engine's memory limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MemoryLimitPolicy {
    /// Fail the query, naming the open windows and groups (the default:
    /// nothing is silently approximated).
    #[default]
    Error,
    /// Emit the oldest open windows before their time until the state fits
    /// again. Each is counted in `windows_forced`; a row arriving for one of
    /// them later is late. If the newest window alone does not fit, fail.
    CloseOldest,
}

impl std::str::FromStr for MemoryLimitPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "close-oldest" => Ok(Self::CloseOldest),
            other => Err(format!(
                "unknown memory-limit policy '{other}': use 'error' or 'close-oldest'"
            )),
        }
    }
}

/// The window a fused aggregate groups by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowSpec {
    Tumble {
        size_us: i64,
    },
    Hop {
        slide_us: i64,
        size_us: i64,
        /// Aggregated per slice (see [`WindowSpec::sliced`]); decided by the
        /// rule, which knows what else reads the window columns.
        sliced: bool,
    },
}

impl WindowSpec {
    pub(super) fn size_us(&self) -> i64 {
        match self {
            WindowSpec::Tumble { size_us } | WindowSpec::Hop { size_us, .. } => *size_us,
        }
    }

    /// Whether the window may be sliced: a hop whose size is a multiple of
    /// its slide.
    pub(super) fn slice_candidate(&self) -> bool {
        matches!(self, WindowSpec::Hop { slide_us, size_us, .. } if size_us % slide_us == 0 && size_us > slide_us)
    }

    pub(super) fn with_slicing(self, sliced: bool) -> Self {
        match self {
            WindowSpec::Hop {
                slide_us, size_us, ..
            } => WindowSpec::Hop {
                slide_us,
                size_us,
                sliced,
            },
            tumble => tumble,
        }
    }

    /// A sliced hop is aggregated per **slice** (one slide's worth of rows)
    /// and the slices merged into each window when it closes: every row
    /// updates one accumulator instead of `size / slide`. The rows carry the
    /// slice's bounds in the window columns, so slicing is only used when
    /// nothing but the aggregate's `GROUP BY window_start` / `window_end`
    /// reads them. Any other window is aggregated per window.
    pub(super) fn sliced(&self) -> bool {
        matches!(self, WindowSpec::Hop { sliced: true, .. })
    }

    /// The width of one state entry: the slide for a sliced hop, else the
    /// window size.
    pub(super) fn slice_us(&self) -> i64 {
        match self {
            WindowSpec::Hop { slide_us, .. } if self.sliced() => *slide_us,
            other => other.size_us(),
        }
    }

    pub(super) fn window_type(&self) -> WindowType {
        let micros = |us: i64| Duration::from_micros(us as u64);
        match self {
            WindowSpec::Tumble { size_us } => WindowType::Tumble {
                size: micros(*size_us),
            },
            WindowSpec::Hop {
                slide_us, size_us, ..
            } => WindowType::Hop {
                slide: micros(*slide_us),
                size: micros(*size_us),
            },
        }
    }
}
