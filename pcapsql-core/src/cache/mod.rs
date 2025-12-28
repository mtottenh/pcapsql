//! Parse cache for avoiding redundant protocol parsing.
//!
//! In streaming mode with JOINs, multiple protocol readers traverse the same
//! PCAP file. Without caching, each reader parses every packet independently,
//! even though the parse result is the same.
//!
//! The cache stores parsed protocol data keyed by frame number, allowing
//! subsequent readers to reuse previous parse results.

mod lru;

pub use lru::LruParseCache;

use std::collections::HashMap;
use std::sync::Arc;

use crate::protocol::{FieldValue, OwnedFieldValue, TunnelType};

/// Owned parse result for a single protocol layer.
///
/// This is an owned version of `ParseResult<'a>` that can be stored in the cache.
/// All field values are owned (no borrowed references).
#[derive(Clone, Debug)]
pub struct OwnedParseResult {
    /// Extracted field values, keyed by field name.
    /// Field names are always static strings from protocol definitions.
    pub fields: HashMap<&'static str, OwnedFieldValue>,
    /// Parse error if partial parsing occurred.
    pub error: Option<String>,
    /// Encapsulation depth when this protocol was parsed (0 = outer layer).
    pub encap_depth: u8,
    /// Type of the innermost enclosing tunnel (if inside a tunnel).
    pub tunnel_type: TunnelType,
    /// Identifier of the innermost enclosing tunnel (VNI, GRE key, TEID, etc.).
    pub tunnel_id: Option<u64>,
}

impl OwnedParseResult {
    /// Create a new owned parse result from a borrowed one.
    /// Converts all borrowed field values to owned values.
    pub fn from_borrowed(
        fields: &smallvec::SmallVec<[(&'static str, FieldValue<'_>); 16]>,
        error: Option<&String>,
    ) -> Self {
        Self {
            fields: fields.iter().map(|(k, v)| (*k, v.to_owned())).collect(),
            error: error.cloned(),
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        }
    }

    /// Create a new owned parse result from a ParseResult with encap context.
    pub fn from_parse_result(result: &crate::protocol::ParseResult<'_>) -> Self {
        Self {
            fields: result
                .fields
                .iter()
                .map(|(k, v)| (*k, v.to_owned()))
                .collect(),
            error: result.error.clone(),
            encap_depth: result.encap_depth,
            tunnel_type: result.tunnel_type,
            tunnel_id: result.tunnel_id,
        }
    }

    /// Get a field value by name.
    pub fn get(&self, name: &str) -> Option<&OwnedFieldValue> {
        self.fields.get(name)
    }
}

/// Cached parse result for a single packet.
///
/// Contains the parsed protocol data for all protocols found in the packet.
/// Stored as Arc to enable zero-copy sharing between readers.
#[derive(Clone, Debug)]
pub struct CachedParse {
    /// Frame number this parse result belongs to
    pub frame_number: u64,
    /// Parsed protocol results (protocol_name -> OwnedParseResult)
    /// Protocol name is always a static string from the registry.
    pub protocols: Vec<(&'static str, OwnedParseResult)>,
}

impl CachedParse {
    /// Create a new cached parse from the parse_packet result.
    pub fn from_parse_results(
        frame_number: u64,
        results: &[(&'static str, crate::protocol::ParseResult<'_>)],
    ) -> Self {
        let protocols = results
            .iter()
            .map(|(name, result)| (*name, OwnedParseResult::from_parse_result(result)))
            .collect();

        Self {
            frame_number,
            protocols,
        }
    }

    /// Get the first parse result for a specific protocol.
    ///
    /// Note: For tunneled packets, the same protocol may appear multiple times
    /// at different encapsulation depths. Use `get_all_protocols()` to get all
    /// occurrences.
    pub fn get_protocol(&self, name: &str) -> Option<&OwnedParseResult> {
        self.protocols
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, r)| r)
    }

    /// Get ALL parse results for a specific protocol.
    ///
    /// For tunneled packets, the same protocol (e.g., IPv4) may appear at
    /// multiple encapsulation depths. This method returns all occurrences.
    pub fn get_all_protocols<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a OwnedParseResult> + 'a {
        self.protocols
            .iter()
            .filter(move |(n, _)| *n == name)
            .map(|(_, r)| r)
    }

    /// Count how many times a protocol appears in the packet.
    ///
    /// Returns 0 if the protocol is not present.
    pub fn count_protocol(&self, name: &str) -> usize {
        self.protocols.iter().filter(|(n, _)| *n == name).count()
    }

    /// Check if a specific protocol is present in the cached results.
    pub fn has_protocol(&self, name: &str) -> bool {
        self.protocols.iter().any(|(n, _)| *n == name)
    }

    /// Iterate over all protocol results.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &OwnedParseResult)> {
        self.protocols.iter().map(|(n, r)| (*n, r))
    }
}

/// Cache for parsed packet data.
///
/// Implementations must be thread-safe as multiple readers may access
/// the cache concurrently.
pub trait ParseCache: Send + Sync {
    /// Get cached parse result for a frame, if available.
    fn get(&self, frame_number: u64) -> Option<Arc<CachedParse>>;

    /// Store parse result for a frame.
    fn put(&self, frame_number: u64, parsed: Arc<CachedParse>);

    /// Get cached result or compute and cache it. Returns (result, was_hit).
    fn get_or_insert_with(
        &self,
        frame_number: u64,
        f: Box<dyn FnOnce() -> Arc<CachedParse> + '_>,
    ) -> (Arc<CachedParse>, bool) {
        // Default implementation: separate get/put (no coordination)
        if let Some(cached) = self.get(frame_number) {
            return (cached, true);
        }
        let result = f();
        self.put(frame_number, result.clone());
        (result, false)
    }

    /// Hint that a reader has finished with frames up to this number.
    ///
    /// Used for eviction decisions. When all active readers have passed
    /// a frame, it can be safely evicted.
    fn reader_passed(&self, reader_id: usize, frame_number: u64);

    /// Register a new reader and get its ID.
    fn register_reader(&self) -> usize;

    /// Unregister a reader (e.g., when stream completes).
    fn unregister_reader(&self, reader_id: usize);

    /// Get cache statistics (if available).
    fn stats(&self) -> Option<CacheStats> {
        None
    }

    /// Reset statistics counters. Default implementation does nothing.
    fn reset_stats(&self) {}
}

/// No-op cache implementation for when caching is disabled.
///
/// All operations are no-ops. This is the default for small files
/// where caching overhead exceeds benefit.
#[derive(Clone, Debug, Default)]
pub struct NoCache;

impl ParseCache for NoCache {
    fn get(&self, _frame_number: u64) -> Option<Arc<CachedParse>> {
        None
    }

    fn put(&self, _frame_number: u64, _parsed: Arc<CachedParse>) {
        // No-op
    }

    fn reader_passed(&self, _reader_id: usize, _frame_number: u64) {
        // No-op
    }

    fn register_reader(&self) -> usize {
        0
    }

    fn unregister_reader(&self, _reader_id: usize) {
        // No-op
    }
}

/// Cache statistics for monitoring.
#[derive(Clone, Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Current number of cached entries.
    pub entries: usize,
    /// Maximum number of entries allowed.
    pub max_entries: usize,

    /// Number of entries evicted due to LRU policy.
    pub evictions_lru: u64,
    /// Number of entries evicted because all readers passed them.
    pub evictions_reader: u64,
    /// Peak number of entries ever held (high watermark).
    pub peak_entries: usize,
    /// Number of currently active readers.
    pub active_readers: usize,
    /// Estimated memory usage in bytes.
    pub memory_bytes_estimate: usize,
}

impl CacheStats {
    /// Calculate the hit ratio (hits / total accesses).
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Calculate cache utilization (entries / max_entries).
    pub fn utilization(&self) -> f64 {
        if self.max_entries == 0 {
            0.0
        } else {
            self.entries as f64 / self.max_entries as f64
        }
    }

    /// Total evictions (LRU + reader-based).
    pub fn total_evictions(&self) -> u64 {
        self.evictions_lru + self.evictions_reader
    }

    /// Format statistics as a human-readable string.
    pub fn format_summary(&self) -> String {
        let hit_pct = self.hit_ratio() * 100.0;
        let miss_pct = 100.0 - hit_pct;
        let util_pct = self.utilization() * 100.0;

        format!(
            "Cache Statistics:\n\
             \x20 Hits:        {:>10} ({:.1}%)\n\
             \x20 Misses:      {:>10} ({:.1}%)\n\
             \x20 Entries:     {:>10} / {} ({:.1}%)\n\
             \x20 Peak:        {:>10}\n\
             \x20 Evictions:   {:>10} (LRU: {}, Reader: {})\n\
             \x20 Readers:     {:>10}\n\
             \x20 Memory:      {:>10}",
            self.hits,
            hit_pct,
            self.misses,
            miss_pct,
            self.entries,
            self.max_entries,
            util_pct,
            self.peak_entries,
            self.total_evictions(),
            self.evictions_lru,
            self.evictions_reader,
            self.active_readers,
            format_bytes(self.memory_bytes_estimate),
        )
    }
}

/// Format bytes as human-readable string.
fn format_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_cache() {
        let cache = NoCache;

        assert!(cache.get(1).is_none());

        let parsed = Arc::new(CachedParse {
            frame_number: 1,
            protocols: vec![],
        });
        cache.put(1, parsed);

        // Still returns None (no-op cache)
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_cached_parse_has_protocol() {
        let cached = CachedParse {
            frame_number: 1,
            protocols: vec![
                (
                    "ethernet",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "ipv4",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
            ],
        };

        assert!(cached.has_protocol("ethernet"));
        assert!(cached.has_protocol("ipv4"));
        assert!(!cached.has_protocol("tcp"));
    }

    #[test]
    fn test_cached_parse_get_all_protocols() {
        // Simulates a VXLAN packet with outer and inner IPv4
        let cached = CachedParse {
            frame_number: 1,
            protocols: vec![
                (
                    "ethernet",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "ipv4",
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert(
                                "src_ip",
                                OwnedFieldValue::OwnedString(compact_str::CompactString::new(
                                    "10.0.0.1",
                                )),
                            );
                            f
                        },
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "vxlan",
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert("vni", OwnedFieldValue::UInt32(100));
                            f
                        },
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "ethernet",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 1,
                        tunnel_type: TunnelType::Vxlan,
                        tunnel_id: Some(100),
                    },
                ),
                (
                    "ipv4",
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert(
                                "src_ip",
                                OwnedFieldValue::OwnedString(compact_str::CompactString::new(
                                    "192.168.1.1",
                                )),
                            );
                            f
                        },
                        error: None,
                        encap_depth: 1,
                        tunnel_type: TunnelType::Vxlan,
                        tunnel_id: Some(100),
                    },
                ),
            ],
        };

        // get_protocol returns first occurrence
        let first_ipv4 = cached.get_protocol("ipv4").unwrap();
        assert_eq!(first_ipv4.encap_depth, 0);

        // get_all_protocols returns all occurrences
        let all_ipv4: Vec<_> = cached.get_all_protocols("ipv4").collect();
        assert_eq!(all_ipv4.len(), 2);
        assert_eq!(all_ipv4[0].encap_depth, 0);
        assert_eq!(all_ipv4[1].encap_depth, 1);
        assert_eq!(all_ipv4[1].tunnel_type, TunnelType::Vxlan);
        assert_eq!(all_ipv4[1].tunnel_id, Some(100));

        // count_protocol
        assert_eq!(cached.count_protocol("ethernet"), 2);
        assert_eq!(cached.count_protocol("ipv4"), 2);
        assert_eq!(cached.count_protocol("vxlan"), 1);
        assert_eq!(cached.count_protocol("tcp"), 0);
    }

    #[test]
    fn test_cache_stats_hit_ratio() {
        let stats = CacheStats {
            hits: 75,
            misses: 25,
            entries: 100,
            max_entries: 1000,
            ..Default::default()
        };

        assert!((stats.hit_ratio() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_empty() {
        let stats = CacheStats::default();
        assert_eq!(stats.hit_ratio(), 0.0);
    }

    #[test]
    fn test_owned_parse_result_with_fields() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut fields = HashMap::new();
        fields.insert(
            "src_ip",
            OwnedFieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        );
        fields.insert("dst_port", OwnedFieldValue::UInt16(443));
        fields.insert(
            "payload",
            OwnedFieldValue::OwnedBytes(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]),
        );
        fields.insert("flags", OwnedFieldValue::UInt8(0x18));
        fields.insert("is_syn", OwnedFieldValue::Bool(false));

        let result = OwnedParseResult {
            fields,
            error: None,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        };

        // Test get method
        assert!(result.get("src_ip").is_some());
        assert!(result.get("dst_port").is_some());
        assert!(result.get("nonexistent").is_none());

        // Verify field values
        match result.get("dst_port") {
            Some(OwnedFieldValue::UInt16(port)) => assert_eq!(*port, 443),
            _ => panic!("Expected UInt16 for dst_port"),
        }
    }

    #[test]
    fn test_owned_parse_result_with_error() {
        let mut fields = HashMap::new();
        fields.insert("partial_field", OwnedFieldValue::UInt32(42));

        let result = OwnedParseResult {
            fields,
            error: Some("Truncated packet: expected 20 bytes, got 12".to_string()),
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
        };

        assert!(result.error.is_some());
        assert!(result.error.as_ref().unwrap().contains("Truncated"));
        // Partial fields should still be accessible
        assert!(result.get("partial_field").is_some());
    }

    #[test]
    fn test_owned_parse_result_from_borrowed() {
        use crate::protocol::FieldValue;
        use smallvec::SmallVec;

        let mut borrowed_fields: SmallVec<[(&'static str, FieldValue); 16]> = SmallVec::new();
        borrowed_fields.push((
            "src_mac",
            FieldValue::MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        ));
        borrowed_fields.push(("ethertype", FieldValue::UInt16(0x0800)));

        let error_msg = "Some error".to_string();
        let owned = OwnedParseResult::from_borrowed(&borrowed_fields, Some(&error_msg));

        // Keys should be converted to owned strings
        assert!(owned.get("src_mac").is_some());
        assert!(owned.get("ethertype").is_some());
        assert_eq!(owned.error, Some("Some error".to_string()));
    }

    #[test]
    fn test_cached_parse_get_protocol() {
        let cached = CachedParse {
            frame_number: 42,
            protocols: vec![
                (
                    "ethernet",
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert("src_mac", OwnedFieldValue::MacAddr([0x00; 6]));
                            f
                        },
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "ipv4",
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert("ttl", OwnedFieldValue::UInt8(64));
                            f
                        },
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
            ],
        };

        // Get existing protocol
        let eth = cached.get_protocol("ethernet");
        assert!(eth.is_some());
        assert!(eth.unwrap().get("src_mac").is_some());

        let ipv4 = cached.get_protocol("ipv4");
        assert!(ipv4.is_some());
        match ipv4.unwrap().get("ttl") {
            Some(OwnedFieldValue::UInt8(ttl)) => assert_eq!(*ttl, 64),
            _ => panic!("Expected TTL field"),
        }

        // Get non-existent protocol
        assert!(cached.get_protocol("tcp").is_none());
    }

    #[test]
    fn test_cached_parse_iter() {
        let cached = CachedParse {
            frame_number: 1,
            protocols: vec![
                (
                    "ethernet",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "ipv4",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
                (
                    "tcp",
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                        encap_depth: 0,
                        tunnel_type: TunnelType::None,
                        tunnel_id: None,
                    },
                ),
            ],
        };

        let protocol_names: Vec<&str> = cached.iter().map(|(name, _)| name).collect();
        assert_eq!(protocol_names, vec!["ethernet", "ipv4", "tcp"]);
    }

    #[test]
    fn test_cached_parse_empty_protocols() {
        let cached = CachedParse {
            frame_number: 100,
            protocols: vec![],
        };

        assert!(!cached.has_protocol("ethernet"));
        assert!(cached.get_protocol("anything").is_none());
        assert_eq!(cached.iter().count(), 0);
    }

    #[test]
    fn test_no_cache_register_reader() {
        let cache = NoCache;

        // All readers get ID 0 (no-op implementation)
        let r1 = cache.register_reader();
        let r2 = cache.register_reader();
        assert_eq!(r1, 0);
        assert_eq!(r2, 0);

        // Unregister is a no-op
        cache.unregister_reader(r1);
        cache.reader_passed(r1, 100);

        // Stats always None
        assert!(cache.stats().is_none());
    }

    #[test]
    fn test_cache_stats_various_ratios() {
        // 50% hit ratio
        let stats_50 = CacheStats {
            hits: 50,
            misses: 50,
            entries: 100,
            max_entries: 1000,
            ..Default::default()
        };
        assert!((stats_50.hit_ratio() - 0.5).abs() < 0.001);

        // 100% hit ratio
        let stats_100 = CacheStats {
            hits: 100,
            misses: 0,
            entries: 100,
            max_entries: 1000,
            ..Default::default()
        };
        assert!((stats_100.hit_ratio() - 1.0).abs() < 0.001);

        // 0% hit ratio (all misses)
        let stats_0 = CacheStats {
            hits: 0,
            misses: 100,
            entries: 0,
            max_entries: 1000,
            ..Default::default()
        };
        assert!((stats_0.hit_ratio() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_utilization() {
        // 0% utilization
        let stats_0 = CacheStats {
            entries: 0,
            max_entries: 100,
            ..Default::default()
        };
        assert!((stats_0.utilization() - 0.0).abs() < 0.001);

        // 50% utilization
        let stats_50 = CacheStats {
            entries: 50,
            max_entries: 100,
            ..Default::default()
        };
        assert!((stats_50.utilization() - 0.5).abs() < 0.001);

        // 100% utilization
        let stats_100 = CacheStats {
            entries: 100,
            max_entries: 100,
            ..Default::default()
        };
        assert!((stats_100.utilization() - 1.0).abs() < 0.001);

        // Edge case: max_entries = 0
        let stats_zero_max = CacheStats {
            entries: 0,
            max_entries: 0,
            ..Default::default()
        };
        assert!((stats_zero_max.utilization() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_total_evictions() {
        let stats = CacheStats {
            evictions_lru: 50,
            evictions_reader: 30,
            ..Default::default()
        };
        assert_eq!(stats.total_evictions(), 80);
    }

    #[test]
    fn test_cache_stats_format_summary() {
        let stats = CacheStats {
            hits: 75,
            misses: 25,
            entries: 500,
            max_entries: 1000,
            evictions_lru: 100,
            evictions_reader: 50,
            peak_entries: 750,
            active_readers: 3,
            memory_bytes_estimate: 512000, // 500 KB
        };

        let summary = stats.format_summary();

        // Check that key information is present
        assert!(summary.contains("Hits:"));
        assert!(summary.contains("75"));
        assert!(summary.contains("Misses:"));
        assert!(summary.contains("25"));
        assert!(summary.contains("Entries:"));
        assert!(summary.contains("500"));
        assert!(summary.contains("1000"));
        assert!(summary.contains("Peak:"));
        assert!(summary.contains("750"));
        assert!(summary.contains("Evictions:"));
        assert!(summary.contains("150")); // total evictions
        assert!(summary.contains("LRU: 100"));
        assert!(summary.contains("Reader: 50"));
        assert!(summary.contains("Readers:"));
        assert!(summary.contains("3"));
        assert!(summary.contains("Memory:"));
        assert!(summary.contains("KB"));
    }

    #[test]
    fn test_format_bytes() {
        // Bytes
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1023), "1023 B");

        // KB
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB"); // 1.5 KB
        assert_eq!(format_bytes(10240), "10.00 KB");

        // MB
        assert_eq!(format_bytes(1048576), "1.00 MB"); // 1 MB
        assert_eq!(format_bytes(5242880), "5.00 MB"); // 5 MB
        assert_eq!(format_bytes(10485760), "10.00 MB"); // 10 MB

        // GB
        assert_eq!(format_bytes(1073741824), "1.00 GB"); // 1 GB
        assert_eq!(format_bytes(2147483648), "2.00 GB"); // 2 GB
    }
}
