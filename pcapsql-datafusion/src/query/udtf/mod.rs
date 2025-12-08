//! User-Defined Table Functions (UDTFs) for pcapsql.
//!
//! This module provides table-valued functions that can be used in SQL queries.
//!
//! ## Available Functions
//!
//! - `cache_stats()` - Returns cache statistics as a single-row table
//!
//! ## Example Usage
//!
//! ```sql
//! -- Get all cache statistics
//! SELECT * FROM cache_stats();
//!
//! -- Get specific statistics
//! SELECT hit_ratio, utilization FROM cache_stats();
//!
//! -- Format as percentage
//! SELECT ROUND(hit_ratio * 100, 1) || '%' AS hit_rate FROM cache_stats();
//! ```

mod cache_stats;

pub use cache_stats::{CacheStatsFunction, CacheStatsTable};
