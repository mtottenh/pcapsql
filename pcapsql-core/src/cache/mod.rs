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

use crate::protocol::FieldValue;

/// Owned parse result for a single protocol layer.
///
/// This is an owned version of `ParseResult<'a>` that can be stored in the cache.
#[derive(Clone, Debug)]
pub struct OwnedParseResult {
    /// Extracted field values, keyed by field name.
    pub fields: HashMap<String, FieldValue>,
    /// Parse error if partial parsing occurred.
    pub error: Option<String>,
}

impl OwnedParseResult {
    /// Create a new owned parse result from a borrowed one.
    pub fn from_borrowed(fields: &HashMap<&'static str, FieldValue>, error: Option<&String>) -> Self {
        Self {
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            error: error.cloned(),
        }
    }

    /// Get a field value by name.
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
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
    pub protocols: Vec<(String, OwnedParseResult)>,
}

impl CachedParse {
    /// Create a new cached parse from the parse_packet result.
    pub fn from_parse_results(
        frame_number: u64,
        results: &[(&'static str, crate::protocol::ParseResult<'_>)],
    ) -> Self {
        let protocols = results
            .iter()
            .map(|(name, result)| {
                (
                    name.to_string(),
                    OwnedParseResult::from_borrowed(&result.fields, result.error.as_ref()),
                )
            })
            .collect();

        Self {
            frame_number,
            protocols,
        }
    }

    /// Get the parse result for a specific protocol.
    pub fn get_protocol(&self, name: &str) -> Option<&OwnedParseResult> {
        self.protocols
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, r)| r)
    }

    /// Check if a specific protocol is present in the cached results.
    pub fn has_protocol(&self, name: &str) -> bool {
        self.protocols.iter().any(|(n, _)| n == name)
    }

    /// Iterate over all protocol results.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &OwnedParseResult)> {
        self.protocols.iter().map(|(n, r)| (n.as_str(), r))
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
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
    pub max_entries: usize,
}

impl CacheStats {
    /// Cache hit ratio (0.0 to 1.0).
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
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
                    "ethernet".to_string(),
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                    },
                ),
                (
                    "ipv4".to_string(),
                    OwnedParseResult {
                        fields: HashMap::new(),
                        error: None,
                    },
                ),
            ],
        };

        assert!(cached.has_protocol("ethernet"));
        assert!(cached.has_protocol("ipv4"));
        assert!(!cached.has_protocol("tcp"));
    }

    #[test]
    fn test_cache_stats_hit_ratio() {
        let stats = CacheStats {
            hits: 75,
            misses: 25,
            entries: 100,
            max_entries: 1000,
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
        use crate::protocol::FieldValue;
        use std::net::{IpAddr, Ipv4Addr};

        let mut fields = HashMap::new();
        fields.insert("src_ip".to_string(), FieldValue::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        fields.insert("dst_port".to_string(), FieldValue::UInt16(443));
        fields.insert("payload".to_string(), FieldValue::Bytes(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]));
        fields.insert("flags".to_string(), FieldValue::UInt8(0x18));
        fields.insert("is_syn".to_string(), FieldValue::Bool(false));

        let result = OwnedParseResult {
            fields,
            error: None,
        };

        // Test get method
        assert!(result.get("src_ip").is_some());
        assert!(result.get("dst_port").is_some());
        assert!(result.get("nonexistent").is_none());

        // Verify field values
        match result.get("dst_port") {
            Some(FieldValue::UInt16(port)) => assert_eq!(*port, 443),
            _ => panic!("Expected UInt16 for dst_port"),
        }
    }

    #[test]
    fn test_owned_parse_result_with_error() {
        let mut fields = HashMap::new();
        fields.insert("partial_field".to_string(), crate::protocol::FieldValue::UInt32(42));

        let result = OwnedParseResult {
            fields,
            error: Some("Truncated packet: expected 20 bytes, got 12".to_string()),
        };

        assert!(result.error.is_some());
        assert!(result.error.as_ref().unwrap().contains("Truncated"));
        // Partial fields should still be accessible
        assert!(result.get("partial_field").is_some());
    }

    #[test]
    fn test_owned_parse_result_from_borrowed() {
        use crate::protocol::FieldValue;

        let mut borrowed_fields: HashMap<&'static str, FieldValue> = HashMap::new();
        borrowed_fields.insert("src_mac", FieldValue::MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        borrowed_fields.insert("ethertype", FieldValue::UInt16(0x0800));

        let error_msg = "Some error".to_string();
        let owned = OwnedParseResult::from_borrowed(&borrowed_fields, Some(&error_msg));

        // Keys should be converted to owned strings
        assert!(owned.get("src_mac").is_some());
        assert!(owned.get("ethertype").is_some());
        assert_eq!(owned.error, Some("Some error".to_string()));
    }

    #[test]
    fn test_cached_parse_get_protocol() {
        use crate::protocol::FieldValue;

        let cached = CachedParse {
            frame_number: 42,
            protocols: vec![
                (
                    "ethernet".to_string(),
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert("src_mac".to_string(), FieldValue::MacAddr([0x00; 6]));
                            f
                        },
                        error: None,
                    },
                ),
                (
                    "ipv4".to_string(),
                    OwnedParseResult {
                        fields: {
                            let mut f = HashMap::new();
                            f.insert("ttl".to_string(), FieldValue::UInt8(64));
                            f
                        },
                        error: None,
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
            Some(FieldValue::UInt8(ttl)) => assert_eq!(*ttl, 64),
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
                ("ethernet".to_string(), OwnedParseResult { fields: HashMap::new(), error: None }),
                ("ipv4".to_string(), OwnedParseResult { fields: HashMap::new(), error: None }),
                ("tcp".to_string(), OwnedParseResult { fields: HashMap::new(), error: None }),
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
        let stats_50 = CacheStats { hits: 50, misses: 50, entries: 100, max_entries: 1000 };
        assert!((stats_50.hit_ratio() - 0.5).abs() < 0.001);

        // 100% hit ratio
        let stats_100 = CacheStats { hits: 100, misses: 0, entries: 100, max_entries: 1000 };
        assert!((stats_100.hit_ratio() - 1.0).abs() < 0.001);

        // 0% hit ratio (all misses)
        let stats_0 = CacheStats { hits: 0, misses: 100, entries: 0, max_entries: 1000 };
        assert!((stats_0.hit_ratio() - 0.0).abs() < 0.001);
    }
}
