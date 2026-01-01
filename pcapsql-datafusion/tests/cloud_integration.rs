//! Cloud storage integration tests.
//!
//! These tests require a running LocalStack or MinIO instance and are marked
//! with `#[ignore]` so they don't run in normal CI. To run them:
//!
//! ```bash
//! # Start LocalStack
//! docker compose -f testdata/cloud/docker-compose.yml up -d
//!
//! # Generate and upload test data
//! ./testdata/cloud/setup.sh
//!
//! # Run integration tests
//! cargo test -p pcapsql-datafusion --features s3,compress-zstd,compress-lz4 \
//!     --test cloud_integration -- --ignored
//! ```
//!
//! All test files are generated dynamically by gen_format_tests.py.

#[cfg(feature = "s3")]
mod cloud_tests {
    use pcapsql_core::io::{CloudLocation, CloudPacketSource, PacketReader, PacketSource};
    use pcapsql_datafusion::query::QueryEngine;

    /// LocalStack endpoint for S3-compatible testing.
    const TEST_ENDPOINT: &str = "http://localhost:4566";

    /// Test bucket name (created by setup.sh).
    const TEST_BUCKET: &str = "test-pcaps";

    // =========================================================================
    // Basic connectivity tests (using generated small_dns.pcap)
    // =========================================================================

    #[test]
    #[ignore]
    fn test_s3_read_uncompressed_pcap() {
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open cloud source");
        let meta = source.metadata();

        assert!(meta.size_bytes.is_some());
        assert!(meta.size_bytes.unwrap() > 0);
        assert!(!meta.seekable); // Cloud sources are non-seekable
        assert_eq!(meta.link_type, 1); // Ethernet
    }

    #[test]
    #[ignore]
    fn test_s3_not_found_returns_error() {
        let url = format!("s3://{}/nonexistent.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let result = CloudPacketSource::open(location);
        assert!(result.is_err());
    }

    // =========================================================================
    // Packet reading tests
    // =========================================================================

    #[test]
    #[ignore]
    fn test_s3_read_packets() {
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open cloud source");
        let mut reader = source.reader(None).expect("Failed to create reader");

        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_packet| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");

            if count == 0 {
                break;
            }
        }

        // small_dns.pcap has 200 packets (100 queries + 100 responses)
        assert_eq!(packet_count, 200, "Expected 200 DNS packets");
    }

    // =========================================================================
    // Query engine integration tests (async - use QueryEngine)
    // =========================================================================

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_s3_query_with_cache() {
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);

        let engine = QueryEngine::with_cloud_source(
            &url,
            1000,  // batch_size
            10000, // cache_size
            Some(TEST_ENDPOINT),
            true,            // anonymous
            8 * 1024 * 1024, // chunk_size
        )
        .await
        .expect("Failed to create QueryEngine");

        // Simple count query
        let result = engine
            .query("SELECT COUNT(*) as cnt FROM frames")
            .await
            .expect("Query failed");

        assert!(!result.is_empty());
        let count: i64 = result[0]
            .column(0)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap()
            .value(0);

        assert_eq!(count, 200, "Should have 200 frames");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_s3_streaming_join() {
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);

        let engine = QueryEngine::with_cloud_source(
            &url,
            1000,
            10000,
            Some(TEST_ENDPOINT),
            true,
            8 * 1024 * 1024,
        )
        .await
        .expect("Failed to create QueryEngine");

        // JOIN query across tables
        let result = engine
            .query(
                "SELECT f.frame_number, d.query_name
                 FROM frames f
                 JOIN dns d ON f.frame_number = d.frame_number
                 LIMIT 5",
            )
            .await
            .expect("JOIN query failed");

        assert!(!result.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_s3_dns_query() {
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);

        let engine = QueryEngine::with_cloud_source(
            &url,
            1000,
            10000,
            Some(TEST_ENDPOINT),
            true,
            8 * 1024 * 1024,
        )
        .await
        .expect("Failed to create QueryEngine");

        // Query DNS table
        let result = engine
            .query("SELECT query_name, is_query FROM dns LIMIT 10")
            .await
            .expect("DNS query failed");

        let total_rows: usize = result.iter().map(|b| b.num_rows()).sum();
        assert!(total_rows > 0, "DNS table should have rows");
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    #[ignore]
    fn test_s3_small_chunk_size() {
        // Test with very small chunk size to exercise buffering
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true)
            .with_chunk_size(1024); // 1KB chunks

        let source = CloudPacketSource::open(location).expect("Failed to open cloud source");
        let mut reader = source.reader(None).expect("Failed to create reader");

        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(10, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");

            if count == 0 {
                break;
            }
        }

        assert_eq!(
            packet_count, 200,
            "Should read all 200 packets with small chunks"
        );
    }

    #[test]
    #[ignore]
    fn test_s3_partitions_returns_single() {
        let url = format!("s3://{}/small_dns.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open cloud source");
        let partitions = source.partitions(4).expect("Failed to get partitions");

        // Cloud sources should return a single partition
        assert_eq!(partitions.len(), 1);
    }

    // =========================================================================
    // Large file tests (chunk boundary crossing)
    // =========================================================================

    #[test]
    #[ignore]
    fn test_s3_large_file_chunk_boundary() {
        // large_10mb.pcap is >8MB, default chunk is 8MB
        // This tests reading across multiple chunks
        let url = format!("s3://{}/large_10mb.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open cloud source");
        let meta = source.metadata();

        // Verify file size (large_10mb.pcap is ~6.3MB in practice)
        assert!(
            meta.size_bytes.unwrap() > 5 * 1024 * 1024,
            "Large file should be >5MB, got {} bytes",
            meta.size_bytes.unwrap()
        );

        let mut reader = source.reader(None).expect("Failed to create reader");

        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(1000, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");

            if count == 0 {
                break;
            }
        }

        // large_10mb.pcap has 65536 packets
        assert!(
            packet_count > 50000,
            "Expected many packets from large file, got {}",
            packet_count
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_s3_large_file_query() {
        let url = format!("s3://{}/large_10mb.pcap", TEST_BUCKET);

        let engine = QueryEngine::with_cloud_source(
            &url,
            1000,
            50000, // Larger cache for big file
            Some(TEST_ENDPOINT),
            true,
            8 * 1024 * 1024,
        )
        .await
        .expect("Failed to create QueryEngine");

        let result = engine
            .query("SELECT COUNT(*) FROM frames")
            .await
            .expect("Query failed");

        let count: i64 = result[0]
            .column(0)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap()
            .value(0);

        assert!(count > 50000, "Expected many frames from large file");
    }

    // =========================================================================
    // Format variant tests
    // =========================================================================

    #[test]
    #[ignore]
    fn test_s3_pcapng_format() {
        let url = format!("s3://{}/format_pcapng.pcapng", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open PCAPNG source");
        let meta = source.metadata();

        // Verify PCAPNG was detected and link type parsed
        assert_eq!(meta.link_type, 1, "PCAPNG should have Ethernet link type");

        // Read and count packets
        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(packet_count, 200, "PCAPNG should have 200 packets");
    }

    #[test]
    #[ignore]
    fn test_s3_legacy_be_micro_format() {
        let url = format!("s3://{}/format_be_micro.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open BE micro source");
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1, "BE micro should have Ethernet link type");

        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(packet_count, 200, "BE micro should have 200 packets");
    }

    #[test]
    #[ignore]
    fn test_s3_legacy_le_nano_format() {
        let url = format!("s3://{}/format_le_nano.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open LE nano source");
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1, "LE nano should have Ethernet link type");

        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(packet_count, 200, "LE nano should have 200 packets");
    }

    #[test]
    #[ignore]
    fn test_s3_legacy_be_nano_format() {
        let url = format!("s3://{}/format_be_nano.pcap", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open BE nano source");
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1, "BE nano should have Ethernet link type");

        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(packet_count, 200, "BE nano should have 200 packets");
    }

    // =========================================================================
    // Compression tests
    // =========================================================================

    #[test]
    #[ignore]
    fn test_s3_gzip_compression() {
        let url = format!("s3://{}/small_dns.pcap.gz", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open gzip source");
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1, "Gzip should detect Ethernet link type");

        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(
            packet_count, 200,
            "Gzip compressed file should have 200 packets"
        );
    }

    #[cfg(feature = "compress-zstd")]
    #[test]
    #[ignore]
    fn test_s3_zstd_compression() {
        let url = format!("s3://{}/small_dns.pcap.zst", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open zstd source");
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1, "Zstd should detect Ethernet link type");

        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(
            packet_count, 200,
            "Zstd compressed file should have 200 packets"
        );
    }

    #[cfg(feature = "compress-lz4")]
    #[test]
    #[ignore]
    fn test_s3_lz4_compression() {
        let url = format!("s3://{}/small_dns.pcap.lz4", TEST_BUCKET);
        let location = CloudLocation::parse(&url)
            .expect("Failed to parse URL")
            .with_endpoint(TEST_ENDPOINT)
            .with_anonymous(true);

        let source = CloudPacketSource::open(location).expect("Failed to open lz4 source");
        let meta = source.metadata();

        assert_eq!(meta.link_type, 1, "LZ4 should detect Ethernet link type");

        let mut reader = source.reader(None).expect("Failed to create reader");
        let mut packet_count = 0;
        loop {
            let count = reader
                .process_packets(100, |_| {
                    packet_count += 1;
                    Ok(())
                })
                .expect("Failed to process packets");
            if count == 0 {
                break;
            }
        }
        assert_eq!(
            packet_count, 200,
            "LZ4 compressed file should have 200 packets"
        );
    }
}
