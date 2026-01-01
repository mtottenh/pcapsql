//! Integration tests for cache statistics (M30).

use std::path::PathBuf;
use std::sync::Arc;

use pcapsql_core::cache::{CacheStats, CachedParse, LruParseCache, ParseCache};
use pcapsql_core::io::FilePacketSource;
use pcapsql_datafusion::query::QueryEngine;

fn test_pcap_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("testdata")
        .join("corpus")
        .join(name)
}

/// Helper to count result rows
#[allow(dead_code)]
async fn count_query_results(engine: &QueryEngine, query: &str) -> Option<i64> {
    let batches = engine.query(query).await.ok()?;
    let mut total = 0i64;
    for batch in &batches {
        if batch.num_columns() > 0 {
            let col = batch.column(0);
            if let Some(arr) = col.as_any().downcast_ref::<arrow::array::Int64Array>() {
                if !arr.is_empty() {
                    total += arr.value(0);
                }
            }
        }
    }
    Some(total)
}

// =============================================================================
// CacheStats Unit Tests
// =============================================================================

/// Test that extended CacheStats fields are populated.
#[tokio::test]
async fn test_extended_stats_fields() {
    let cache = LruParseCache::new(100);

    // Generate some activity
    for i in 0..50u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    // Some hits and misses
    for i in 0..30u64 {
        let _ = cache.get(i); // Hits
    }
    for i in 100..110u64 {
        let _ = cache.get(i); // Misses
    }

    let stats = cache.get_stats();

    assert_eq!(stats.hits, 30);
    assert_eq!(stats.misses, 10);
    assert_eq!(stats.entries, 50);
    assert_eq!(stats.max_entries, 100);
    assert!(stats.peak_entries >= 50);
    assert!(stats.memory_bytes_estimate > 0);
}

/// Test eviction counter tracking.
#[tokio::test]
async fn test_eviction_counters() {
    let cache = LruParseCache::new(10);

    // Fill beyond capacity to trigger evictions
    for i in 0..20u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    let stats = cache.get_stats();

    // Should have evicted some entries
    assert!(stats.evictions_lru > 0 || stats.evictions_reader > 0);
    assert!(stats.entries <= 10);
}

/// Test reader-based eviction tracking.
#[tokio::test]
async fn test_reader_eviction_tracking() {
    let cache = LruParseCache::new(100);

    // Register a reader
    let reader_id = cache.register_reader();

    // Add entries
    for i in 0..20u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    let stats_before = cache.get_stats();
    assert_eq!(stats_before.active_readers, 1);

    // Reader passes frame 15
    cache.reader_passed(reader_id, 15);

    // Force eviction by filling cache
    for i in 20..120u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    let stats_after = cache.get_stats();

    // Reader evictions should have occurred for frames 0-14
    assert!(stats_after.evictions_reader > 0);

    cache.unregister_reader(reader_id);
}

/// Test stats reset functionality.
#[tokio::test]
async fn test_stats_reset() {
    let cache = LruParseCache::new(100);

    // Generate activity
    for i in 0..10u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
        let _ = cache.get(i);
    }

    let stats_before = cache.get_stats();
    assert!(stats_before.hits > 0);
    assert!(stats_before.entries > 0);

    // Reset stats
    cache.reset_stats();

    let stats_after = cache.get_stats();

    // Counters should be zero
    assert_eq!(stats_after.hits, 0);
    assert_eq!(stats_after.misses, 0);
    assert_eq!(stats_after.evictions_lru, 0);
    assert_eq!(stats_after.evictions_reader, 0);

    // But entries should still be there
    assert_eq!(stats_after.entries, stats_before.entries);

    // And peak should be preserved
    assert_eq!(stats_after.peak_entries, stats_before.peak_entries);
}

/// Test hit ratio calculation.
#[tokio::test]
async fn test_hit_ratio() {
    // Zero total
    let stats = CacheStats {
        hits: 0,
        misses: 0,
        ..Default::default()
    };
    assert_eq!(stats.hit_ratio(), 0.0);

    // 80% hit rate
    let stats = CacheStats {
        hits: 80,
        misses: 20,
        ..Default::default()
    };
    assert!((stats.hit_ratio() - 0.8).abs() < 0.001);

    // 100% hit rate
    let stats = CacheStats {
        hits: 100,
        misses: 0,
        ..Default::default()
    };
    assert_eq!(stats.hit_ratio(), 1.0);
}

/// Test utilization calculation.
#[tokio::test]
async fn test_utilization() {
    // Zero max
    let stats = CacheStats {
        entries: 50,
        max_entries: 0,
        ..Default::default()
    };
    assert_eq!(stats.utilization(), 0.0);

    // Half full
    let stats = CacheStats {
        entries: 50,
        max_entries: 100,
        ..Default::default()
    };
    assert!((stats.utilization() - 0.5).abs() < 0.001);
}

/// Test format_summary output.
#[tokio::test]
async fn test_format_summary() {
    let stats = CacheStats {
        hits: 1000,
        misses: 200,
        entries: 500,
        max_entries: 1000,
        evictions_lru: 100,
        evictions_reader: 50,
        peak_entries: 750,
        active_readers: 2,
        memory_bytes_estimate: 512000,
    };

    let summary = stats.format_summary();

    assert!(summary.contains("1000")); // hits
    assert!(summary.contains("200")); // misses
    assert!(summary.contains("500")); // entries
    assert!(summary.contains("750")); // peak
    assert!(summary.contains("LRU: 100")); // lru evictions
    assert!(summary.contains("Reader: 50")); // reader evictions
    assert!(summary.contains("KB") || summary.contains("MB")); // memory
}

// =============================================================================
// cache_stats() Table Function Tests
// =============================================================================

/// Test cache_stats() table function returns data.
#[tokio::test]
async fn test_cache_stats_table_function() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    // Run a query first to populate cache
    let _ = engine.query("SELECT COUNT(*) FROM frames").await;

    // Query cache stats
    let batches = engine
        .query("SELECT * FROM cache_stats()")
        .await
        .expect("cache_stats() query failed");

    assert!(!batches.is_empty());
    assert_eq!(batches[0].num_rows(), 1);

    // Check column names
    let schema = batches[0].schema();
    assert!(schema.field_with_name("hits").is_ok());
    assert!(schema.field_with_name("misses").is_ok());
    assert!(schema.field_with_name("hit_ratio").is_ok());
    assert!(schema.field_with_name("entries").is_ok());
    assert!(schema.field_with_name("evictions_lru").is_ok());
    assert!(schema.field_with_name("evictions_reader").is_ok());
    assert!(schema.field_with_name("peak_entries").is_ok());
    assert!(schema.field_with_name("active_readers").is_ok());
    assert!(schema.field_with_name("memory_bytes").is_ok());
}

/// Test cache_stats() with projection.
#[tokio::test]
async fn test_cache_stats_projection() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    // Query just hit_ratio
    let batches = engine
        .query("SELECT hit_ratio FROM cache_stats()")
        .await
        .expect("cache_stats() query failed");

    assert!(!batches.is_empty());
    assert_eq!(batches[0].num_columns(), 1);

    let schema = batches[0].schema();
    assert_eq!(schema.fields().len(), 1);
    assert_eq!(schema.field(0).name(), "hit_ratio");
}

/// Test cache_stats() with multiple columns.
#[tokio::test]
async fn test_cache_stats_multi_column_projection() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    // Query multiple columns
    let batches = engine
        .query("SELECT hits, misses, hit_ratio, utilization FROM cache_stats()")
        .await
        .expect("cache_stats() query failed");

    assert!(!batches.is_empty());
    assert_eq!(batches[0].num_columns(), 4);
}

/// Test cache_stats() with no cache (in-memory mode).
#[tokio::test]
async fn test_cache_stats_no_cache() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // In-memory mode has no cache
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create engine");

    let batches = engine
        .query("SELECT * FROM cache_stats()")
        .await
        .expect("cache_stats() query failed");

    // Should return default/empty stats
    assert!(!batches.is_empty());
    assert_eq!(batches[0].num_rows(), 1);

    // max_entries should be 0 in non-cached mode
    let schema = batches[0].schema();
    let max_idx = schema
        .fields()
        .iter()
        .position(|f| f.name() == "max_entries")
        .unwrap();
    let col = batches[0]
        .column(max_idx)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap();
    assert_eq!(col.value(0), 0);
}

/// Test cache_stats() with SQL expressions.
#[tokio::test]
async fn test_cache_stats_with_expressions() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    // Test with SQL expressions
    let batches = engine
        .query("SELECT ROUND(hit_ratio * 100, 1) AS hit_pct FROM cache_stats()")
        .await
        .expect("cache_stats() with expression failed");

    assert!(!batches.is_empty());
    assert_eq!(batches[0].num_columns(), 1);
}

// =============================================================================
// Peak Entries Tests
// =============================================================================

/// Test peak entries tracking.
#[tokio::test]
async fn test_peak_entries_tracking() {
    let cache = LruParseCache::new(100);

    // Add 50 entries
    for i in 0..50u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    let stats1 = cache.get_stats();
    assert_eq!(stats1.peak_entries, 50);

    // Add 30 more
    for i in 50..80u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    let stats2 = cache.get_stats();
    assert_eq!(stats2.peak_entries, 80);

    // Clear cache
    cache.clear();

    let stats3 = cache.get_stats();

    // Peak should still be 80 (high watermark)
    assert_eq!(stats3.peak_entries, 80);
    assert_eq!(stats3.entries, 0);
}

// =============================================================================
// CLI Integration Tests
// =============================================================================

/// Test --stats CLI flag output format.
#[test]
fn test_stats_cli_output() {
    use std::process::Command;

    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_pcapsql"))
        .args([
            pcap.to_str().unwrap(),
            "--streaming",
            "--stats",
            "-e",
            "SELECT COUNT(*) FROM frames",
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain cache stats header
    assert!(
        stderr.contains("Cache Statistics") || stderr.contains("not available"),
        "Expected cache stats in stderr: {stderr}"
    );
}

/// Test stats are shown after query with --stats flag.
#[test]
fn test_stats_flag_shows_summary() {
    use std::process::Command;

    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_pcapsql"))
        .args([
            pcap.to_str().unwrap(),
            "--streaming",
            "--cache-size",
            "1000",
            "--stats",
            "-e",
            "SELECT COUNT(*) FROM frames",
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain cache stats components
    assert!(
        stderr.contains("Hits:") || stderr.contains("Cache Statistics"),
        "Expected cache stats in stderr: {stderr}"
    );
}

// =============================================================================
// QueryEngine Integration Tests
// =============================================================================

/// Test QueryEngine.cache_stats() method.
#[tokio::test]
async fn test_query_engine_cache_stats_method() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    // Run a query
    let _ = engine.query("SELECT COUNT(*) FROM frames").await;

    // Get stats via method
    let stats = engine.cache_stats();
    assert!(stats.is_some(), "Should have cache stats in streaming mode");

    let stats = stats.unwrap();
    assert_eq!(stats.max_entries, 1000);
}

/// Test QueryEngine.cache_stats() returns None for in-memory mode.
#[tokio::test]
async fn test_query_engine_cache_stats_none_for_inmemory() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create engine");

    // Should return None for in-memory mode
    let stats = engine.cache_stats();
    assert!(
        stats.is_none(),
        "In-memory mode should not have cache stats"
    );
}

/// Test cache() method access.
#[tokio::test]
async fn test_query_engine_cache_method() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    // Get cache reference
    let cache = engine.cache();
    assert!(cache.is_some(), "Should have cache in streaming mode");

    // Run query
    let _ = engine.query("SELECT COUNT(*) FROM frames").await;

    // Reset stats
    cache.unwrap().reset_stats();

    // Verify reset
    let stats = engine.cache_stats().unwrap();
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

/// Test stats with empty cache.
#[tokio::test]
async fn test_stats_empty_cache() {
    let cache = LruParseCache::new(100);
    let stats = cache.get_stats();

    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.evictions_lru, 0);
    assert_eq!(stats.evictions_reader, 0);
    assert_eq!(stats.peak_entries, 0);
    assert_eq!(stats.active_readers, 0);
    assert_eq!(stats.hit_ratio(), 0.0);
    assert_eq!(stats.utilization(), 0.0);
}

/// Test stats after cache is cleared.
#[tokio::test]
async fn test_stats_after_clear() {
    let cache = LruParseCache::new(100);

    // Add and access entries
    for i in 0..50u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
        let _ = cache.get(i);
    }

    let stats_before = cache.get_stats();
    assert_eq!(stats_before.entries, 50);
    assert_eq!(stats_before.hits, 50);

    // Clear
    cache.clear();

    let stats_after = cache.get_stats();
    assert_eq!(stats_after.entries, 0);
    // Hits should still be recorded
    assert_eq!(stats_after.hits, 50);
    // Peak should be preserved
    assert_eq!(stats_after.peak_entries, 50);
}

/// Test very high eviction rates.
#[tokio::test]
async fn test_high_eviction_rate() {
    let cache = LruParseCache::new(5);

    // Insert many more entries than capacity
    for i in 0..1000u64 {
        cache.put(
            i,
            Arc::new(CachedParse {
                frame_number: i,
                protocols: vec![],
            }),
        );
    }

    let stats = cache.get_stats();

    // Should have many evictions
    assert!(stats.evictions_lru >= 995, "Expected ~995 LRU evictions");
    assert!(stats.entries <= 5);
    assert_eq!(stats.peak_entries, 5);
}

/// Test concurrent stats access is safe.
#[tokio::test]
async fn test_concurrent_stats_access() {
    use std::sync::Arc;
    use tokio::task;

    let cache = Arc::new(LruParseCache::new(100));

    let mut handles = vec![];

    // Spawn multiple tasks that read/write cache and stats
    for i in 0..10 {
        let cache = Arc::clone(&cache);
        handles.push(task::spawn(async move {
            for j in 0..100u64 {
                let frame = i * 100 + j;
                cache.put(
                    frame,
                    Arc::new(CachedParse {
                        frame_number: frame,
                        protocols: vec![],
                    }),
                );
                let _ = cache.get(frame);
                let _ = cache.get_stats();
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Final stats should be consistent
    let stats = cache.get_stats();
    assert!(stats.hits > 0);
    assert!(stats.entries <= 100);
}

// =============================================================================
// Cache Stats SQL Schema Tests
// =============================================================================

/// Test that all expected columns exist in cache_stats().
#[tokio::test]
async fn test_cache_stats_schema_complete() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open PCAP"));
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine");

    let batches = engine
        .query("SELECT * FROM cache_stats()")
        .await
        .expect("Query failed");

    let schema = batches[0].schema();

    // Verify all 12 columns exist
    let expected_columns = [
        "hits",
        "misses",
        "hit_ratio",
        "entries",
        "max_entries",
        "utilization",
        "evictions_lru",
        "evictions_reader",
        "evictions_total",
        "peak_entries",
        "active_readers",
        "memory_bytes",
    ];

    for col in &expected_columns {
        assert!(schema.field_with_name(col).is_ok(), "Missing column: {col}");
    }

    assert_eq!(schema.fields().len(), 12);
}
