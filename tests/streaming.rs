//! Integration tests for streaming mode with normalized tables.
//!
//! These tests verify that:
//! - All protocol tables exist and are accessible in streaming mode
//! - Cross-layer views work correctly
//! - JOINs work via sort-merge (frame_number is sorted)
//! - Query results match between in-memory and streaming modes

use std::path::PathBuf;
use std::sync::Arc;

use arrow::array::Array;
use pcapsql::io::FilePacketSource;
use pcapsql::query::QueryEngine;

/// Get the path to a test PCAP file.
fn test_pcap_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("corpus")
        .join(name)
}

#[tokio::test]
async fn test_streaming_tables_exist() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // All base tables should exist
    for table in [
        "frames", "ethernet", "ipv4", "ipv6", "tcp", "udp", "dns", "arp", "icmp", "dhcp", "ntp",
        "http", "tls", "vlan", "icmpv6",
    ] {
        let result = engine
            .query(&format!("SELECT COUNT(*) FROM {}", table))
            .await;
        assert!(
            result.is_ok(),
            "Table {} should exist in streaming mode: {:?}",
            table,
            result.err()
        );
    }
}

#[tokio::test]
async fn test_streaming_basic_query() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // Basic query on frames table
    let result = engine
        .query("SELECT COUNT(*) as cnt FROM frames")
        .await
        .expect("Basic frames query should work");

    assert!(!result.is_empty());
    assert!(result[0].num_rows() > 0);
}

#[tokio::test]
async fn test_streaming_dns_table() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // Query DNS-specific columns
    let result = engine
        .query("SELECT frame_number, query_name, is_query FROM dns LIMIT 5")
        .await
        .expect("DNS query should work");

    assert!(!result.is_empty());
    // dns.cap has DNS traffic
    let total_rows: usize = result.iter().map(|b| b.num_rows()).sum();
    assert!(total_rows > 0, "DNS table should have rows for dns.cap");
}

#[tokio::test]
async fn test_streaming_join_works() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // JOIN between frames and DNS
    let result = engine
        .query(
            "SELECT f.frame_number, d.query_name
             FROM frames f
             JOIN dns d ON f.frame_number = d.frame_number
             LIMIT 5",
        )
        .await;

    assert!(
        result.is_ok(),
        "JOIN should work in streaming mode: {:?}",
        result.err()
    );
    assert!(!result.unwrap().is_empty());
}

#[tokio::test]
async fn test_streaming_complex_join() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // Complex multi-table JOIN
    let result = engine
        .query(
            "SELECT
                f.frame_number,
                ip.src_ip,
                ip.dst_ip,
                u.src_port,
                u.dst_port,
                d.query_name
             FROM frames f
             JOIN ipv4 ip ON f.frame_number = ip.frame_number
             JOIN udp u ON f.frame_number = u.frame_number
             JOIN dns d ON f.frame_number = d.frame_number
             LIMIT 5",
        )
        .await;

    assert!(
        result.is_ok(),
        "Complex JOIN should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_streaming_vs_memory_frame_count() {
    let pcap = test_pcap_path("dns.cap");

    // In-memory mode
    let mem_engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create memory engine");

    // Streaming mode
    let stream_engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // Frame counts should match
    let mem_result = mem_engine
        .query("SELECT COUNT(*) as cnt FROM frames")
        .await
        .unwrap();
    let stream_result = stream_engine
        .query("SELECT COUNT(*) as cnt FROM frames")
        .await
        .unwrap();

    // Get the actual counts
    let mem_count: i64 = mem_result[0]
        .column(0)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap()
        .value(0);

    let stream_count: i64 = stream_result[0]
        .column(0)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap()
        .value(0);

    assert_eq!(
        mem_count, stream_count,
        "Frame counts should match between modes"
    );
}

#[tokio::test]
async fn test_streaming_vs_memory_dns_count() {
    let pcap = test_pcap_path("dns.cap");

    let mem_engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create memory engine");

    let stream_engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // DNS row counts should match
    let mem_result = mem_engine
        .query("SELECT COUNT(*) as cnt FROM dns")
        .await
        .unwrap();
    let stream_result = stream_engine
        .query("SELECT COUNT(*) as cnt FROM dns")
        .await
        .unwrap();

    let mem_count: i64 = mem_result[0]
        .column(0)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap()
        .value(0);

    let stream_count: i64 = stream_result[0]
        .column(0)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap()
        .value(0);

    assert_eq!(
        mem_count, stream_count,
        "DNS counts should match between modes"
    );
}

#[tokio::test]
async fn test_streaming_views_work() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // dns_packets view should work
    let result = engine.query("SELECT * FROM dns_packets LIMIT 5").await;
    assert!(
        result.is_ok(),
        "dns_packets view should work: {:?}",
        result.err()
    );

    // packets view (backward compatibility) should work
    let result = engine.query("SELECT * FROM packets LIMIT 5").await;
    assert!(
        result.is_ok(),
        "packets view should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_streaming_tcp_file() {
    let pcap = test_pcap_path("http-chunked-gzip.pcap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // TCP table should have data
    let result = engine
        .query("SELECT frame_number, src_port, dst_port, seq FROM tcp LIMIT 5")
        .await
        .expect("TCP query should work");

    let total_rows: usize = result.iter().map(|b| b.num_rows()).sum();
    assert!(total_rows > 0, "TCP table should have rows");
}

#[tokio::test]
async fn test_custom_source() {
    // Test that we can use the generic source interface
    let pcap = test_pcap_path("dns.cap");
    let source = Arc::new(FilePacketSource::open(&pcap).expect("Failed to open source"));

    let engine = QueryEngine::with_streaming_source(source, 100)
        .await
        .expect("Failed to create engine with custom source");

    let result = engine.query("SELECT COUNT(*) FROM dns").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_streaming_empty_protocol() {
    // dns.cap has no TCP traffic (it's UDP DNS)
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // TCP table should be empty but queryable
    let result = engine
        .query("SELECT COUNT(*) as cnt FROM tcp")
        .await
        .expect("Empty TCP table should be queryable");

    let count: i64 = result[0]
        .column(0)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap()
        .value(0);

    assert_eq!(count, 0, "TCP table should be empty for dns.cap");
}

#[tokio::test]
async fn test_streaming_arp() {
    let pcap = test_pcap_path("arp-storm.pcap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // ARP table should have data
    let result = engine
        .query("SELECT frame_number, sender_ip, target_ip FROM arp LIMIT 5")
        .await
        .expect("ARP query should work");

    let total_rows: usize = result.iter().map(|b| b.num_rows()).sum();
    assert!(total_rows > 0, "ARP table should have rows for arp-storm.pcap");
}

#[tokio::test]
async fn test_streaming_filter() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_streaming(&pcap, 100)
        .await
        .expect("Failed to create streaming engine");

    // Filter query should work
    let result = engine
        .query("SELECT * FROM udp WHERE dst_port = 53 LIMIT 10")
        .await
        .expect("Filter query should work");

    // All results should have dst_port = 53
    for batch in &result {
        if let Some(col) = batch.column_by_name("dst_port") {
            let arr = col
                .as_any()
                .downcast_ref::<arrow::array::UInt16Array>()
                .unwrap();
            for i in 0..arr.len() {
                if !arr.is_null(i) {
                    assert_eq!(arr.value(i), 53, "All results should have dst_port = 53");
                }
            }
        }
    }
}
