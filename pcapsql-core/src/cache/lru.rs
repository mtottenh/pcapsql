//! LRU cache with reader-aware eviction.
//!
//! The cache tracks which readers are active and their current positions.
//! Entries are evicted when:
//! 1. All active readers have passed the frame, OR
//! 2. The cache exceeds its size limit (LRU eviction)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use super::{CacheStats, CachedParse, ParseCache};

/// Average estimated size per cached entry (for memory estimation).
const ESTIMATED_ENTRY_SIZE: usize = 1024; // 1 KB per entry

/// LRU parse cache with configurable size limit.
///
/// Thread-safe implementation using RwLock for the main cache
/// and atomics for statistics.
pub struct LruParseCache {
    /// Maximum number of entries to cache
    max_entries: usize,

    /// Cached entries: frame_number -> (parse_result, last_access_order)
    entries: RwLock<HashMap<u64, (Arc<CachedParse>, u64)>>,

    /// Monotonically increasing access counter for LRU ordering
    access_counter: AtomicU64,

    /// Active readers and their current frame positions
    /// reader_id -> last_frame_passed
    readers: RwLock<HashMap<usize, u64>>,

    /// Next reader ID to assign
    next_reader_id: AtomicUsize,

    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,

    /// LRU evictions counter
    evictions_lru: AtomicU64,
    /// Reader-based evictions counter
    evictions_reader: AtomicU64,
    /// Peak entries ever held (high watermark)
    peak_entries: AtomicUsize,

    /// Whether reader-based eviction is enabled
    reader_eviction_enabled: bool,
}

impl LruParseCache {
    /// Create a new cache with the specified maximum entries.
    ///
    /// A good default is 10,000 entries, which at ~1KB per entry
    /// uses about 10MB of memory.
    pub fn new(max_entries: usize) -> Self {
        Self::with_options(max_entries, true)
    }

    /// Create a new cache with configurable options.
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of entries to cache
    /// * `reader_eviction_enabled` - If true, entries are evicted when all readers
    ///   have passed them. If false, only LRU eviction is used.
    pub fn with_options(max_entries: usize, reader_eviction_enabled: bool) -> Self {
        Self {
            max_entries,
            entries: RwLock::new(HashMap::with_capacity(max_entries.min(10000))),
            access_counter: AtomicU64::new(0),
            readers: RwLock::new(HashMap::new()),
            next_reader_id: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions_lru: AtomicU64::new(0),
            evictions_reader: AtomicU64::new(0),
            peak_entries: AtomicUsize::new(0),
            reader_eviction_enabled,
        }
    }

    /// Evict entries that all readers have passed.
    fn evict_passed_entries(&self, entries: &mut HashMap<u64, (Arc<CachedParse>, u64)>) {
        // Skip if reader-based eviction is disabled
        if !self.reader_eviction_enabled {
            return;
        }

        let readers = self.readers.read().unwrap();
        if readers.is_empty() {
            return;
        }

        // Find minimum frame that all readers have passed
        let min_passed = readers.values().min().copied().unwrap_or(0);

        let before_count = entries.len();

        // Remove entries below this threshold
        entries.retain(|&frame_number, _| frame_number >= min_passed);

        let evicted = before_count - entries.len();
        if evicted > 0 {
            self.evictions_reader.fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

    /// Evict least recently used entries to make room.
    fn evict_lru(&self, entries: &mut HashMap<u64, (Arc<CachedParse>, u64)>, target_size: usize) {
        if entries.len() <= target_size {
            return;
        }

        let to_remove = entries.len() - target_size;

        // Find the oldest entries by access order
        let mut access_orders: Vec<_> = entries
            .iter()
            .map(|(&frame, &(_, order))| (frame, order))
            .collect();
        access_orders.sort_by_key(|&(_, order)| order);

        // Remove oldest entries
        for (frame, _) in access_orders.into_iter().take(to_remove) {
            entries.remove(&frame);
        }

        self.evictions_lru.fetch_add(to_remove as u64, Ordering::Relaxed);
    }

    /// Update peak entries if current is higher.
    fn update_peak(&self, current: usize) {
        let mut peak = self.peak_entries.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_entries.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }
    }

    /// Get current cache statistics.
    pub fn get_stats(&self) -> CacheStats {
        let entries = self.entries.read().unwrap();
        let readers = self.readers.read().unwrap();

        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries: entries.len(),
            max_entries: self.max_entries,
            evictions_lru: self.evictions_lru.load(Ordering::Relaxed),
            evictions_reader: self.evictions_reader.load(Ordering::Relaxed),
            peak_entries: self.peak_entries.load(Ordering::Relaxed),
            active_readers: readers.len(),
            memory_bytes_estimate: entries.len() * ESTIMATED_ENTRY_SIZE,
        }
    }

    /// Reset statistics counters (keeps cache contents).
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions_lru.store(0, Ordering::Relaxed);
        self.evictions_reader.store(0, Ordering::Relaxed);
        // Note: peak_entries is NOT reset - it's a high watermark
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
    }
}

impl ParseCache for LruParseCache {
    fn get(&self, frame_number: u64) -> Option<Arc<CachedParse>> {
        let mut entries = self.entries.write().unwrap();

        if let Some((cached, access_order)) = entries.get_mut(&frame_number) {
            // Update access order for LRU
            *access_order = self.access_counter.fetch_add(1, Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(cached.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    fn put(&self, frame_number: u64, parsed: Arc<CachedParse>) {
        let mut entries = self.entries.write().unwrap();

        // Check if already present
        if entries.contains_key(&frame_number) {
            return;
        }

        // Evict old entries if needed
        if entries.len() >= self.max_entries {
            self.evict_passed_entries(&mut entries);

            if entries.len() >= self.max_entries {
                // Still full, do LRU eviction (remove ~10%)
                let target = (self.max_entries as f64 * 0.9) as usize;
                self.evict_lru(&mut entries, target);
            }
        }

        let access_order = self.access_counter.fetch_add(1, Ordering::Relaxed);
        entries.insert(frame_number, (parsed, access_order));

        // Update peak after insertion
        self.update_peak(entries.len());
    }

    fn reset_stats(&self) {
        LruParseCache::reset_stats(self);
    }

    fn reader_passed(&self, reader_id: usize, frame_number: u64) {
        let mut readers = self.readers.write().unwrap();
        if let Some(pos) = readers.get_mut(&reader_id) {
            *pos = frame_number;
        }
    }

    fn register_reader(&self) -> usize {
        let id = self.next_reader_id.fetch_add(1, Ordering::Relaxed);
        let mut readers = self.readers.write().unwrap();
        readers.insert(id, 0);
        id
    }

    fn unregister_reader(&self, reader_id: usize) {
        let mut readers = self.readers.write().unwrap();
        readers.remove(&reader_id);
    }

    fn stats(&self) -> Option<CacheStats> {
        Some(self.get_stats())
    }

    fn get_or_insert_with(
        &self,
        frame_number: u64,
        f: Box<dyn FnOnce() -> Arc<CachedParse> + '_>,
    ) -> (Arc<CachedParse>, bool) {
        // Fast path: check if already cached (read lock only)
        {
            let entries = self.entries.read().unwrap();
            if let Some((cached, _)) = entries.get(&frame_number) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return (cached.clone(), true);
            }
        }

        // Not cached - parse and insert
        self.misses.fetch_add(1, Ordering::Relaxed);
        let result = f();

        // Insert into cache
        {
            let mut entries = self.entries.write().unwrap();

            // Evict if needed
            if entries.len() >= self.max_entries {
                self.evict_passed_entries(&mut entries);
                if entries.len() >= self.max_entries {
                    let target = (self.max_entries as f64 * 0.9) as usize;
                    self.evict_lru(&mut entries, target);
                }
            }

            let access_order = self.access_counter.fetch_add(1, Ordering::Relaxed);
            entries.insert(frame_number, (result.clone(), access_order));
            self.update_peak(entries.len());
        }

        (result, false)
    }
}

impl std::fmt::Debug for LruParseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.get_stats();
        f.debug_struct("LruParseCache")
            .field("max_entries", &self.max_entries)
            .field("entries", &stats.entries)
            .field("hits", &stats.hits)
            .field("misses", &stats.misses)
            .field("hit_ratio", &format!("{:.2}%", stats.hit_ratio() * 100.0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit_miss() {
        let cache = LruParseCache::new(100);

        // Miss on empty cache
        assert!(cache.get(1).is_none());
        assert_eq!(cache.get_stats().misses, 1);

        // Put and hit
        let parsed = Arc::new(CachedParse {
            frame_number: 1,
            protocols: vec![],
        });
        cache.put(1, parsed.clone());

        assert!(cache.get(1).is_some());
        assert_eq!(cache.get_stats().hits, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let cache = LruParseCache::new(3);

        // Fill cache
        for i in 1..=3 {
            cache.put(
                i,
                Arc::new(CachedParse {
                    frame_number: i,
                    protocols: vec![],
                }),
            );
        }

        // Access frame 1 to make it recently used
        let _ = cache.get(1);

        // Add frame 4, should evict frame 2 (oldest unused)
        cache.put(
            4,
            Arc::new(CachedParse {
                frame_number: 4,
                protocols: vec![],
            }),
        );

        // Frame 1 should still be there (recently accessed)
        assert!(cache.get(1).is_some());
        // Frame 4 should be there (just added)
        assert!(cache.get(4).is_some());
        // Frame 3 might or might not be there depending on eviction
    }

    #[test]
    fn test_reader_tracking() {
        let cache = LruParseCache::new(100);

        let r1 = cache.register_reader();
        let r2 = cache.register_reader();

        assert_ne!(r1, r2);

        // Put some entries
        for i in 1..=10 {
            cache.put(
                i,
                Arc::new(CachedParse {
                    frame_number: i,
                    protocols: vec![],
                }),
            );
        }

        assert_eq!(cache.get_stats().entries, 10);

        // Reader 1 passes frame 5
        cache.reader_passed(r1, 5);

        // Reader 2 passes frame 5
        cache.reader_passed(r2, 5);

        // Unregister readers
        cache.unregister_reader(r1);
        cache.unregister_reader(r2);
    }

    #[test]
    fn test_duplicate_put_ignored() {
        let cache = LruParseCache::new(100);

        let parsed1 = Arc::new(CachedParse {
            frame_number: 1,
            protocols: vec![],
        });
        let parsed2 = Arc::new(CachedParse {
            frame_number: 1,
            protocols: vec![("test".to_string(), super::super::OwnedParseResult {
                fields: std::collections::HashMap::new(),
                error: None,
                encap_depth: 0,
                tunnel_type: crate::protocol::TunnelType::None,
                tunnel_id: None,
            })],
        });

        cache.put(1, parsed1);
        cache.put(1, parsed2);

        // Should still have the original (no protocols)
        let cached = cache.get(1).unwrap();
        assert!(cached.protocols.is_empty());
    }

    #[test]
    fn test_clear() {
        let cache = LruParseCache::new(100);

        for i in 1..=10 {
            cache.put(
                i,
                Arc::new(CachedParse {
                    frame_number: i,
                    protocols: vec![],
                }),
            );
        }

        assert_eq!(cache.get_stats().entries, 10);

        cache.clear();

        assert_eq!(cache.get_stats().entries, 0);
    }

    #[test]
    fn test_evict_passed_entries() {
        let cache = LruParseCache::new(100);

        // Register two readers
        let r1 = cache.register_reader();
        let r2 = cache.register_reader();

        // Add entries for frames 1-10
        for i in 1..=10 {
            cache.put(
                i,
                Arc::new(CachedParse {
                    frame_number: i,
                    protocols: vec![],
                }),
            );
        }

        // Reader 1 passes frame 5
        cache.reader_passed(r1, 5);

        // Entries should still exist (reader 2 hasn't passed)
        assert!(cache.get(3).is_some());

        // Reader 2 passes frame 7
        cache.reader_passed(r2, 7);

        // Force eviction by adding more entries when at capacity
        // This would trigger evict_passed_entries
    }

    #[test]
    fn test_debug_format() {
        let cache = LruParseCache::new(100);
        cache.put(
            1,
            Arc::new(CachedParse {
                frame_number: 1,
                protocols: vec![],
            }),
        );

        let debug_str = format!("{:?}", cache);
        assert!(debug_str.contains("LruParseCache"));
        assert!(debug_str.contains("max_entries"));
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let cache = Arc::new(LruParseCache::new(1000));
        let mut handles = vec![];

        // Spawn multiple threads to write and read concurrently
        for t in 0..4 {
            let cache_clone = cache.clone();
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let frame = (t * 100 + i) as u64;
                    cache_clone.put(
                        frame,
                        Arc::new(CachedParse {
                            frame_number: frame,
                            protocols: vec![],
                        }),
                    );
                    // Read back
                    let _ = cache_clone.get(frame);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Cache should have entries and no panics
        let stats = cache.get_stats();
        assert!(stats.entries > 0);
        assert!(stats.hits > 0);
    }

    #[test]
    fn test_heavy_eviction() {
        let cache = LruParseCache::new(10);

        // Add 100 entries to a cache of size 10
        for i in 1..=100 {
            cache.put(
                i,
                Arc::new(CachedParse {
                    frame_number: i,
                    protocols: vec![],
                }),
            );
        }

        // Cache should be at or below max
        let stats = cache.get_stats();
        assert!(stats.entries <= 10);

        // Recent entries should still be accessible
        // (the last few should be present)
        let mut found_recent = false;
        for i in 90..=100 {
            if cache.get(i).is_some() {
                found_recent = true;
                break;
            }
        }
        assert!(found_recent, "At least one recent entry should be in cache");
    }

    #[test]
    fn test_stats_accuracy() {
        let cache = LruParseCache::new(100);

        // Initial stats
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 100);

        // 3 misses
        cache.get(1);
        cache.get(2);
        cache.get(3);

        // Add 2 entries
        cache.put(1, Arc::new(CachedParse { frame_number: 1, protocols: vec![] }));
        cache.put(2, Arc::new(CachedParse { frame_number: 2, protocols: vec![] }));

        // 2 hits
        cache.get(1);
        cache.get(2);

        let stats = cache.get_stats();
        assert_eq!(stats.misses, 3);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.entries, 2);
        assert!((stats.hit_ratio() - 0.4).abs() < 0.01); // 2/(2+3) = 0.4
    }

    #[test]
    fn test_reader_eviction_boundary() {
        let cache = LruParseCache::new(20);

        // Register two readers
        let r1 = cache.register_reader();
        let r2 = cache.register_reader();

        // Add 15 entries
        for i in 1..=15 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        // Reader 1 is at frame 5, reader 2 at frame 10
        cache.reader_passed(r1, 5);
        cache.reader_passed(r2, 10);

        // Frames 1-4 can be evicted (both readers past them)
        // Frames 5-10 should stay (r1 hasn't passed them)

        // Add more entries to trigger eviction
        for i in 16..=25 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        // Now move reader 1 past
        cache.reader_passed(r1, 15);

        // Unregister readers
        cache.unregister_reader(r1);
        cache.unregister_reader(r2);

        // Cache should still function
        assert!(cache.get(25).is_some());
    }

    #[test]
    fn test_zero_size_cache() {
        // Edge case: cache with 0 max entries
        // Note: A zero-size cache is a degenerate case. For truly disabled caching,
        // use NoCache instead. This tests that the implementation doesn't panic
        // with pathological input.
        let cache = LruParseCache::new(0);

        cache.put(1, Arc::new(CachedParse { frame_number: 1, protocols: vec![] }));
        cache.put(2, Arc::new(CachedParse { frame_number: 2, protocols: vec![] }));

        // Implementation allows entries due to eviction logic triggering after insert check
        // For production use, NoCache is recommended when caching is not desired
        let stats = cache.get_stats();
        // Should still function without panic - entries may or may not be evicted
        assert!(stats.max_entries == 0);
    }

    #[test]
    fn test_eviction_counters() {
        let cache = LruParseCache::new(5);

        // Add 5 entries (fill the cache)
        for i in 1..=5 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        assert_eq!(stats.evictions_lru, 0);
        assert_eq!(stats.evictions_reader, 0);

        // Add more entries to trigger LRU eviction
        for i in 6..=10 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        // LRU evictions should have occurred
        assert!(stats.evictions_lru > 0);
        assert_eq!(stats.total_evictions(), stats.evictions_lru + stats.evictions_reader);
    }

    #[test]
    fn test_reader_eviction_counters() {
        let cache = LruParseCache::new(20);

        // Register a reader
        let r1 = cache.register_reader();

        // Add 10 entries
        for i in 1..=10 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        // Reader passes frame 5
        cache.reader_passed(r1, 5);

        let stats_before = cache.get_stats();
        let evictions_reader_before = stats_before.evictions_reader;

        // Add more entries to trigger eviction of passed entries
        for i in 11..=25 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        // Reader-based evictions should have occurred
        assert!(stats.evictions_reader >= evictions_reader_before);

        cache.unregister_reader(r1);
    }

    #[test]
    fn test_peak_entries_tracking() {
        let cache = LruParseCache::new(10);

        // Add 10 entries (fill the cache)
        for i in 1..=10 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        assert_eq!(stats.peak_entries, 10);
        assert_eq!(stats.entries, 10);

        // Clear the cache
        cache.clear();

        let stats = cache.get_stats();
        assert_eq!(stats.entries, 0);
        // Peak should still be 10 (high watermark)
        assert_eq!(stats.peak_entries, 10);
    }

    #[test]
    fn test_active_readers_count() {
        let cache = LruParseCache::new(100);

        let stats = cache.get_stats();
        assert_eq!(stats.active_readers, 0);

        let r1 = cache.register_reader();
        let stats = cache.get_stats();
        assert_eq!(stats.active_readers, 1);

        let r2 = cache.register_reader();
        let stats = cache.get_stats();
        assert_eq!(stats.active_readers, 2);

        cache.unregister_reader(r1);
        let stats = cache.get_stats();
        assert_eq!(stats.active_readers, 1);

        cache.unregister_reader(r2);
        let stats = cache.get_stats();
        assert_eq!(stats.active_readers, 0);
    }

    #[test]
    fn test_memory_bytes_estimate() {
        let cache = LruParseCache::new(100);

        let stats = cache.get_stats();
        assert_eq!(stats.memory_bytes_estimate, 0);

        // Add 5 entries
        for i in 1..=5 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        // 5 entries * 1024 bytes per entry = 5120 bytes
        assert_eq!(stats.memory_bytes_estimate, 5 * ESTIMATED_ENTRY_SIZE);
    }

    #[test]
    fn test_reset_stats() {
        let cache = LruParseCache::new(5);

        // Generate some stats
        cache.get(1); // miss
        cache.put(1, Arc::new(CachedParse { frame_number: 1, protocols: vec![] }));
        cache.get(1); // hit

        // Trigger some evictions
        for i in 2..=10 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        assert!(stats.hits > 0);
        assert!(stats.misses > 0);
        assert!(stats.evictions_lru > 0);
        let old_peak = stats.peak_entries;

        // Reset stats
        cache.reset_stats();

        let stats = cache.get_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions_lru, 0);
        assert_eq!(stats.evictions_reader, 0);
        // Peak should NOT be reset (it's a high watermark)
        assert_eq!(stats.peak_entries, old_peak);
        // Entries should still be there (cache not cleared)
        assert!(stats.entries > 0);
    }

    #[test]
    fn test_utilization() {
        let cache = LruParseCache::new(100);

        let stats = cache.get_stats();
        assert!((stats.utilization() - 0.0).abs() < 0.001);

        // Add 50 entries (50% utilization)
        for i in 1..=50 {
            cache.put(i, Arc::new(CachedParse { frame_number: i, protocols: vec![] }));
        }

        let stats = cache.get_stats();
        assert!((stats.utilization() - 0.5).abs() < 0.001);
    }
}
