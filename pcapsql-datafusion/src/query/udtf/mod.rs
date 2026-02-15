//! User-Defined Table Functions (UDTFs) for pcapsql.
//!
//! This module provides table-valued functions that can be used in SQL queries.
//!
//! ## Available Functions
//!
//! - `cache_stats()` - Returns cache statistics as a single-row table
//! - `tumble(table, interval)` - Tumbling window assignment
//! - `hop(table, slide, size)` - Hopping window assignment
//!
//! ## Example Usage
//!
//! ```sql
//! -- Cache statistics
//! SELECT * FROM cache_stats();
//!
//! -- Tumbling window: 1-minute windows over TCP packets
//! SELECT window_start, window_end, src_ip_v4, COUNT(*) as packets
//! FROM tumble(tcp_packets, INTERVAL '1' MINUTE)
//! GROUP BY window_start, window_end, src_ip_v4;
//!
//! -- Hopping window: 30s slide, 5-minute windows
//! SELECT window_start, window_end, src_ip_v4, SUM(length) as bytes
//! FROM hop(tcp_packets, INTERVAL '30' SECOND, INTERVAL '5' MINUTE)
//! GROUP BY window_start, window_end, src_ip_v4;
//! ```

mod cache_stats;
mod hop;
mod tumble;
mod window_args;
pub mod window_exec;
mod window_provider;

pub use cache_stats::{CacheStatsFunction, CacheStatsTable};
pub use hop::HopFunction;
pub use tumble::TumbleFunction;
