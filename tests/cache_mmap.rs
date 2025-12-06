//! Integration tests for cache and mmap features.

use std::path::PathBuf;
use std::sync::Arc;

use pcapsql::cache::{LruParseCache, ParseCache};
use pcapsql::io::{FilePacketSource, MmapPacketSource};
use pcapsql::query::QueryEngine;

fn test_pcap_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("corpus")
        .join(name)
}

/// Helper to count result rows
async fn count_query_results(engine: &QueryEngine, query: &str) -> Option<i64> {
    let batches = engine.query(query).await.ok()?;
    let mut total = 0i64;
    for batch in &batches {
        if batch.num_columns() > 0 {
            let col = batch.column(0);
            if let Some(arr) = col.as_any().downcast_ref::<arrow::array::Int64Array>() {
                if arr.len() > 0 {
                    total += arr.value(0);
                }
            }
        }
    }
    Some(total)
}

// =============================================================================
// Mmap Source Tests
// =============================================================================

#[tokio::test]
async fn test_mmap_source_opens() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = MmapPacketSource::open(&pcap);
    assert!(source.is_ok(), "Failed to open mmap source: {:?}", source.err());
}

#[tokio::test]
async fn test_mmap_source_queries_work() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(MmapPacketSource::open(&pcap).expect("Failed to open mmap source"));
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine");

    // Basic frame count query
    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok(), "Query failed: {:?}", result.err());
}

#[tokio::test]
async fn test_mmap_vs_file_consistency() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // File source
    let file_source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let file_engine = QueryEngine::with_streaming_source(file_source, 100)
        .await
        .unwrap();

    // Mmap source
    let mmap_source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let mmap_engine = QueryEngine::with_streaming_source(mmap_source, 100)
        .await
        .unwrap();

    // Compare ethernet counts
    let file_count = count_query_results(&file_engine, "SELECT COUNT(*) FROM ethernet").await;
    let mmap_count = count_query_results(&mmap_engine, "SELECT COUNT(*) FROM ethernet").await;

    assert_eq!(file_count, mmap_count, "Mmap and file source should return same counts");
}

#[tokio::test]
async fn test_mmap_dns_query() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .unwrap();

    // Query DNS data
    let result = engine.query("SELECT query_name FROM dns LIMIT 5").await;
    assert!(result.is_ok(), "DNS query failed: {:?}", result.err());
}

// =============================================================================
// Cache Tests
// =============================================================================

#[tokio::test]
async fn test_cache_basic_operations() {
    let cache = LruParseCache::new(100);

    // Initial stats
    let stats = cache.get_stats();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);

    // Miss
    let result = cache.get(1);
    assert!(result.is_none());
    assert_eq!(cache.get_stats().misses, 1);

    // Put
    use pcapsql::cache::CachedParse;
    let parsed = Arc::new(CachedParse {
        frame_number: 1,
        protocols: vec![],
    });
    cache.put(1, parsed.clone());

    // Hit
    let result = cache.get(1);
    assert!(result.is_some());
    assert_eq!(cache.get_stats().hits, 1);
}

#[tokio::test]
async fn test_streaming_with_cache() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine with cache");

    // Run a query
    let result = engine.query("SELECT COUNT(*) FROM dns").await;
    assert!(result.is_ok(), "Query with cache failed: {:?}", result.err());
}

#[tokio::test]
async fn test_cached_join_query() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine with cache");

    // JOIN query that would benefit from cache
    let result = engine
        .query(
            "SELECT e.src_mac, d.query_name
             FROM ethernet e
             JOIN dns d ON e.frame_number = d.frame_number
             LIMIT 5",
        )
        .await;

    assert!(result.is_ok(), "JOIN query failed: {:?}", result.err());
}

#[tokio::test]
async fn test_cache_disabled() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // cache_size = 0 should disable caching
    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 0)
        .await
        .expect("Failed to create engine without cache");

    // Should still work
    let result = engine.query("SELECT COUNT(*) FROM dns").await;
    assert!(result.is_ok(), "Query without cache failed: {:?}", result.err());
}

// =============================================================================
// Auto Mode Tests
// =============================================================================

#[tokio::test]
async fn test_auto_mode_small_file() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Small file should work in auto mode (uses in-memory)
    let engine = QueryEngine::auto(&pcap, 1000, 10000, false)
        .await
        .expect("Auto mode failed");

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_auto_mode_with_mmap() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Auto mode with mmap hint (small file may still use in-memory)
    let engine = QueryEngine::auto(&pcap, 1000, 10000, true)
        .await
        .expect("Auto mode with mmap hint failed");

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok());
}

// =============================================================================
// Mmap Edge Cases
// =============================================================================

#[tokio::test]
async fn test_mmap_supports_pcapng() {
    // PCAPNG files should now be supported by mmap source
    let pcap = test_pcap_path("dhcp.pcapng");
    if !pcap.exists() {
        return;
    }

    let result = MmapPacketSource::open(&pcap);
    assert!(result.is_ok(), "Mmap should support PCAPNG: {:?}", result.err());

    // Verify we can read packets
    let source = Arc::new(result.unwrap());
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine");

    let query_result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(query_result.is_ok(), "PCAPNG query failed: {:?}", query_result.err());
}

#[tokio::test]
async fn test_mmap_pcapng_vs_file_consistency() {
    let pcap = test_pcap_path("dhcp.pcapng");
    if !pcap.exists() {
        return;
    }

    // File source (reference)
    let file_source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let file_engine = QueryEngine::with_streaming_source(file_source, 100)
        .await
        .unwrap();

    // Mmap source
    let mmap_source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let mmap_engine = QueryEngine::with_streaming_source(mmap_source, 100)
        .await
        .unwrap();

    // Compare packet counts
    let file_count = count_query_results(&file_engine, "SELECT COUNT(*) FROM ethernet").await;
    let mmap_count = count_query_results(&mmap_engine, "SELECT COUNT(*) FROM ethernet").await;

    assert_eq!(file_count, mmap_count, "PCAPNG mmap vs file count mismatch");
}

#[tokio::test]
async fn test_mmap_pcapng_dhcp_parsing() {
    let pcap = test_pcap_path("dhcp.pcapng");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .unwrap();

    // Query DHCP-specific data
    let result = engine.query("SELECT COUNT(*) FROM dhcp").await;
    assert!(result.is_ok(), "DHCP query on PCAPNG failed: {:?}", result.err());
}

#[tokio::test]
async fn test_mmap_with_join() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .unwrap();

    // JOIN query using mmap source
    let result = engine
        .query(
            "SELECT i.src_ip, d.query_name
             FROM ipv4 i
             JOIN dns d ON i.frame_number = d.frame_number
             LIMIT 10",
        )
        .await;

    assert!(result.is_ok(), "Mmap JOIN query failed: {:?}", result.err());
}

// =============================================================================
// Performance Sanity Tests
// =============================================================================

#[tokio::test]
async fn test_cached_vs_uncached_same_results() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Without cache
    let source1 = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine1 = QueryEngine::with_streaming_source_cached(source1, 100, 0)
        .await
        .unwrap();

    // With cache
    let source2 = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine2 = QueryEngine::with_streaming_source_cached(source2, 100, 1000)
        .await
        .unwrap();

    // Both should return same count
    let count1 = count_query_results(&engine1, "SELECT COUNT(*) FROM dns").await;
    let count2 = count_query_results(&engine2, "SELECT COUNT(*) FROM dns").await;

    assert_eq!(count1, count2, "Cached and uncached should return same results");
}

// =============================================================================
// Combined Mmap + Cache Tests
// =============================================================================

#[tokio::test]
async fn test_mmap_with_cache_join_query() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Mmap source with cache
    let mmap_source = MmapPacketSource::open(&pcap);
    if mmap_source.is_err() {
        return; // Skip if mmap not supported
    }

    let source = Arc::new(mmap_source.unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine with mmap and cache");

    // Complex JOIN query that benefits from caching
    let result = engine
        .query(
            "SELECT e.src_mac, i.src_ip, d.query_name
             FROM ethernet e
             JOIN ipv4 i ON e.frame_number = i.frame_number
             JOIN dns d ON i.frame_number = d.frame_number
             LIMIT 5",
        )
        .await;

    assert!(result.is_ok(), "Mmap + cache JOIN failed: {:?}", result.err());
}

#[tokio::test]
async fn test_mmap_cache_repeated_queries() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let mmap_source = MmapPacketSource::open(&pcap);
    if mmap_source.is_err() {
        return;
    }

    let source = Arc::new(mmap_source.unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .unwrap();

    // Run the same query multiple times - cache should help
    for i in 0..3 {
        let result = engine.query("SELECT COUNT(*) FROM dns").await;
        assert!(result.is_ok(), "Query {} failed: {:?}", i, result.err());
    }
}

#[tokio::test]
async fn test_mmap_vs_file_vs_cached_consistency() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Method 1: Mmap source, no cache
    let mmap_source = MmapPacketSource::open(&pcap);
    if mmap_source.is_err() {
        return;
    }
    let engine_mmap = QueryEngine::with_streaming_source(Arc::new(mmap_source.unwrap()), 100)
        .await
        .unwrap();

    // Method 2: File source, no cache
    let file_source = FilePacketSource::open(&pcap).unwrap();
    let engine_file = QueryEngine::with_streaming_source_cached(Arc::new(file_source), 100, 0)
        .await
        .unwrap();

    // Method 3: File source with cache
    let file_source2 = FilePacketSource::open(&pcap).unwrap();
    let engine_cached = QueryEngine::with_streaming_source_cached(Arc::new(file_source2), 100, 1000)
        .await
        .unwrap();

    // Compare DNS counts
    let count_mmap = count_query_results(&engine_mmap, "SELECT COUNT(*) FROM dns").await;
    let count_file = count_query_results(&engine_file, "SELECT COUNT(*) FROM dns").await;
    let count_cached = count_query_results(&engine_cached, "SELECT COUNT(*) FROM dns").await;

    assert_eq!(count_mmap, count_file, "Mmap vs file count mismatch");
    assert_eq!(count_file, count_cached, "File vs cached count mismatch");
}

#[tokio::test]
async fn test_cache_effectiveness_with_aggregations() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .unwrap();

    // Query 1: Count all DNS
    let result1 = engine.query("SELECT COUNT(*) FROM dns").await;
    assert!(result1.is_ok());

    // Query 2: Count distinct query types - reads same packets again
    let result2 = engine.query("SELECT query_type, COUNT(*) FROM dns GROUP BY query_type").await;
    assert!(result2.is_ok());

    // Query 3: Join with IP - reads same packets again
    let result3 = engine
        .query(
            "SELECT d.query_name, i.src_ip
             FROM dns d
             JOIN ipv4 i ON d.frame_number = i.frame_number
             LIMIT 10",
        )
        .await;
    assert!(result3.is_ok());
}

#[tokio::test]
async fn test_small_cache_still_works() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Very small cache - should evict frequently but still work
    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 5)
        .await
        .unwrap();

    // Should still produce correct results
    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok(), "Small cache query failed: {:?}", result.err());
}

// =============================================================================
// Auto Mode Decision Tests
// =============================================================================

#[tokio::test]
async fn test_auto_mode_consistency() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Auto mode should produce same results regardless of how it chooses to load
    let engine1 = QueryEngine::auto(&pcap, 1000, 10000, false)
        .await
        .expect("Auto mode failed");

    let engine2 = QueryEngine::auto(&pcap, 1000, 10000, true)
        .await
        .expect("Auto mode with mmap hint failed");

    let count1 = count_query_results(&engine1, "SELECT COUNT(*) FROM ethernet").await;
    let count2 = count_query_results(&engine2, "SELECT COUNT(*) FROM ethernet").await;

    assert_eq!(count1, count2, "Auto mode should give consistent results");
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[tokio::test]
async fn test_empty_query_result_cached() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .unwrap();

    // Query that returns no results
    let result = engine
        .query("SELECT * FROM dns WHERE query_name = 'nonexistent.invalid'")
        .await;
    assert!(result.is_ok());
    let batches = result.unwrap();
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 0, "Should have no matching rows");
}

#[tokio::test]
async fn test_large_batch_size_with_cache() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    // Large batch size relative to cache
    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 10000, 100)
        .await
        .unwrap();

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_multiple_protocol_tables_same_query() {
    let pcap = test_pcap_path("dns.cap");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .unwrap();

    // Union of multiple protocol tables
    let result = engine
        .query(
            "SELECT frame_number FROM ethernet
             UNION ALL
             SELECT frame_number FROM ipv4
             ORDER BY frame_number
             LIMIT 20",
        )
        .await;
    assert!(result.is_ok(), "Multi-table union failed: {:?}", result.err());
}

// =============================================================================
// Compression Support Tests
// =============================================================================

#[tokio::test]
async fn test_mmap_gzip_compressed_pcap() {
    let pcap = test_pcap_path("dns.cap.gz");
    if !pcap.exists() {
        return; // Skip if compressed test file doesn't exist
    }

    let source = MmapPacketSource::open(&pcap);
    assert!(source.is_ok(), "Failed to open gzip-compressed PCAP: {:?}", source.err());

    let source = Arc::new(source.unwrap());

    // Verify it detects compression
    assert!(source.is_compressed(), "Should detect gzip compression");

    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine");

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok(), "Query on gzip PCAP failed: {:?}", result.err());
}

#[tokio::test]
async fn test_mmap_zstd_compressed_pcap() {
    let pcap = test_pcap_path("dns.cap.zst");
    if !pcap.exists() {
        return; // Skip if compressed test file doesn't exist
    }

    let source = MmapPacketSource::open(&pcap);
    assert!(source.is_ok(), "Failed to open zstd-compressed PCAP: {:?}", source.err());

    let source = Arc::new(source.unwrap());

    // Verify it detects compression
    assert!(source.is_compressed(), "Should detect zstd compression");

    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine");

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok(), "Query on zstd PCAP failed: {:?}", result.err());
}

#[tokio::test]
async fn test_compressed_vs_uncompressed_consistency() {
    let pcap_orig = test_pcap_path("dns.cap");
    let pcap_gz = test_pcap_path("dns.cap.gz");
    let pcap_zst = test_pcap_path("dns.cap.zst");

    if !pcap_orig.exists() {
        return;
    }

    // Original uncompressed file
    let source_orig = Arc::new(MmapPacketSource::open(&pcap_orig).unwrap());
    let engine_orig = QueryEngine::with_streaming_source(source_orig, 100)
        .await
        .unwrap();
    let count_orig = count_query_results(&engine_orig, "SELECT COUNT(*) FROM ethernet").await;

    // Gzip compressed file
    if pcap_gz.exists() {
        let source_gz = Arc::new(MmapPacketSource::open(&pcap_gz).unwrap());
        let engine_gz = QueryEngine::with_streaming_source(source_gz, 100)
            .await
            .unwrap();
        let count_gz = count_query_results(&engine_gz, "SELECT COUNT(*) FROM ethernet").await;

        assert_eq!(count_orig, count_gz, "Gzip compressed should match original");
    }

    // Zstd compressed file
    if pcap_zst.exists() {
        let source_zst = Arc::new(MmapPacketSource::open(&pcap_zst).unwrap());
        let engine_zst = QueryEngine::with_streaming_source(source_zst, 100)
            .await
            .unwrap();
        let count_zst = count_query_results(&engine_zst, "SELECT COUNT(*) FROM ethernet").await;

        assert_eq!(count_orig, count_zst, "Zstd compressed should match original");
    }
}

#[tokio::test]
async fn test_compressed_dns_query_results() {
    let pcap_orig = test_pcap_path("dns.cap");
    let pcap_gz = test_pcap_path("dns.cap.gz");

    if !pcap_orig.exists() || !pcap_gz.exists() {
        return;
    }

    // Query DNS on original
    let source_orig = Arc::new(MmapPacketSource::open(&pcap_orig).unwrap());
    let engine_orig = QueryEngine::with_streaming_source(source_orig, 100)
        .await
        .unwrap();
    let count_orig = count_query_results(&engine_orig, "SELECT COUNT(*) FROM dns").await;

    // Query DNS on gzip
    let source_gz = Arc::new(MmapPacketSource::open(&pcap_gz).unwrap());
    let engine_gz = QueryEngine::with_streaming_source(source_gz, 100)
        .await
        .unwrap();
    let count_gz = count_query_results(&engine_gz, "SELECT COUNT(*) FROM dns").await;

    assert_eq!(count_orig, count_gz, "DNS count should match between compressed and uncompressed");
}

#[tokio::test]
async fn test_compressed_with_cache() {
    let pcap = test_pcap_path("dns.cap.gz");
    if !pcap.exists() {
        return;
    }

    let source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let engine = QueryEngine::with_streaming_source_cached(source, 100, 1000)
        .await
        .expect("Failed to create engine with cache for compressed file");

    // Run multiple queries to exercise cache
    let result1 = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result1.is_ok(), "First query failed: {:?}", result1.err());

    let result2 = engine.query("SELECT COUNT(*) FROM dns").await;
    assert!(result2.is_ok(), "Second query failed: {:?}", result2.err());

    // Join query
    let result3 = engine
        .query(
            "SELECT e.src_mac, d.query_name
             FROM ethernet e
             JOIN dns d ON e.frame_number = d.frame_number
             LIMIT 5",
        )
        .await;
    assert!(result3.is_ok(), "Join query on compressed PCAP failed: {:?}", result3.err());
}

#[tokio::test]
async fn test_compression_detection() {
    use pcapsql::io::Compression;

    // Test magic byte detection
    let gzip_magic = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];
    assert_eq!(Compression::detect(&gzip_magic), Compression::Gzip);

    // PCAP magic (uncompressed)
    let pcap_magic = [0xd4, 0xc3, 0xb2, 0xa1, 0x00, 0x00];
    assert_eq!(Compression::detect(&pcap_magic), Compression::None);
}

// =============================================================================
// File Source Compression Tests
// =============================================================================

#[tokio::test]
async fn test_file_source_gzip_compressed() {
    let pcap = test_pcap_path("dns.cap.gz");
    if !pcap.exists() {
        return;
    }

    // FilePacketSource should handle gzip compression
    let source = FilePacketSource::open(&pcap);
    assert!(source.is_ok(), "Failed to open gzip PCAP with file source: {:?}", source.err());

    let source = Arc::new(source.unwrap());
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine");

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok(), "Query on file source gzip failed: {:?}", result.err());
}

#[tokio::test]
async fn test_file_source_zstd_compressed() {
    let pcap = test_pcap_path("dns.cap.zst");
    if !pcap.exists() {
        return;
    }

    // FilePacketSource should handle zstd compression
    let source = FilePacketSource::open(&pcap);
    assert!(source.is_ok(), "Failed to open zstd PCAP with file source: {:?}", source.err());

    let source = Arc::new(source.unwrap());
    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine");

    let result = engine.query("SELECT COUNT(*) FROM ethernet").await;
    assert!(result.is_ok(), "Query on file source zstd failed: {:?}", result.err());
}

#[tokio::test]
async fn test_file_vs_mmap_compressed_consistency() {
    let pcap = test_pcap_path("dns.cap.gz");
    if !pcap.exists() {
        return;
    }

    // FilePacketSource
    let file_source = Arc::new(FilePacketSource::open(&pcap).unwrap());
    let file_engine = QueryEngine::with_streaming_source(file_source, 100)
        .await
        .unwrap();
    let file_count = count_query_results(&file_engine, "SELECT COUNT(*) FROM ethernet").await;

    // MmapPacketSource
    let mmap_source = Arc::new(MmapPacketSource::open(&pcap).unwrap());
    let mmap_engine = QueryEngine::with_streaming_source(mmap_source, 100)
        .await
        .unwrap();
    let mmap_count = count_query_results(&mmap_engine, "SELECT COUNT(*) FROM ethernet").await;

    assert_eq!(file_count, mmap_count, "File and mmap sources should return same count for compressed files");
}
