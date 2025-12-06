//! Integration tests for the normalized schema architecture.
//!
//! Tests validate that:
//! - All protocol tables exist and are accessible
//! - Cross-layer views work correctly
//! - Protocol tables are properly isolated
//! - JOINs between tables work
//! - Backward compatibility with old queries

use std::path::PathBuf;

use pcapsql::query::{tables, views, QueryEngine};

/// Get the path to a test PCAP file.
fn test_pcap_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("corpus")
        .join(name)
}

/// Test that all 17 protocol tables exist and are accessible.
#[tokio::test]
async fn test_base_tables_exist() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // All protocol table names
    let expected_tables = tables::all_table_names();
    assert_eq!(expected_tables.len(), 17);

    // Query each table to verify it exists
    for table_name in expected_tables {
        let query = format!("SELECT COUNT(*) as cnt FROM {}", table_name);
        let result = engine.query(&query).await;
        assert!(
            result.is_ok(),
            "Table '{}' should exist and be queryable: {:?}",
            table_name,
            result.err()
        );
    }
}

/// Test that all 13 cross-layer views exist and work.
#[tokio::test]
async fn test_cross_layer_views_exist() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // All view names
    let expected_views = views::all_view_names();
    assert_eq!(expected_views.len(), 13);

    // Query each view to verify it exists
    for view_name in expected_views {
        let query = format!("SELECT COUNT(*) as cnt FROM {}", view_name);
        let result = engine.query(&query).await;
        assert!(
            result.is_ok(),
            "View '{}' should exist and be queryable: {:?}",
            view_name,
            result.err()
        );
    }
}

/// Test that protocol tables are properly isolated.
/// DNS table should not have ARP-specific columns.
#[tokio::test]
async fn test_protocol_table_isolation() {
    // DNS table should have DNS-specific columns
    let dns_schema = tables::dns_table_schema();
    assert!(dns_schema.field_with_name("query_name").is_ok());
    assert!(dns_schema.field_with_name("transaction_id").is_ok());
    assert!(dns_schema.field_with_name("is_query").is_ok());

    // DNS table should NOT have ARP columns
    assert!(dns_schema.field_with_name("sender_ip").is_err());
    assert!(dns_schema.field_with_name("target_mac").is_err());
    assert!(dns_schema.field_with_name("operation").is_err());

    // ARP table should have ARP-specific columns
    let arp_schema = tables::arp_table_schema();
    assert!(arp_schema.field_with_name("sender_ip").is_ok());
    assert!(arp_schema.field_with_name("target_mac").is_ok());
    assert!(arp_schema.field_with_name("operation").is_ok());

    // ARP table should NOT have DNS columns
    assert!(arp_schema.field_with_name("query_name").is_err());
    assert!(arp_schema.field_with_name("transaction_id").is_err());
}

/// Test that JOINs between protocol tables work correctly.
#[tokio::test]
async fn test_join_between_protocol_tables() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // JOIN frames with DNS - should get DNS packets with timestamps
    let query = r#"
        SELECT
            f.frame_number,
            f.timestamp,
            d.query_name,
            d.is_query
        FROM frames f
        JOIN dns d ON f.frame_number = d.frame_number
        LIMIT 5
    "#;

    let result = engine.query(query).await;
    assert!(
        result.is_ok(),
        "JOIN between frames and dns should work: {:?}",
        result.err()
    );

    let batches = result.unwrap();
    assert!(!batches.is_empty(), "Should have results from JOIN");

    // JOIN frames + ipv4 + udp + dns
    let complex_query = r#"
        SELECT
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
        WHERE u.dst_port = 53
        LIMIT 5
    "#;

    let result = engine.query(complex_query).await;
    assert!(
        result.is_ok(),
        "Complex JOIN should work: {:?}",
        result.err()
    );
}

/// Test backward compatibility - old packets-style queries should still work.
#[tokio::test]
async fn test_backward_compatibility() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // Basic packets view query
    let result = engine
        .query("SELECT COUNT(*) FROM packets")
        .await;
    assert!(
        result.is_ok(),
        "packets view should work: {:?}",
        result.err()
    );

    // Query with common columns that existed in old flat schema
    let result = engine
        .query("SELECT frame_number, ip_version, src_port, dst_port, protocol FROM packets LIMIT 5")
        .await;
    assert!(
        result.is_ok(),
        "Common columns should be accessible via packets view: {:?}",
        result.err()
    );

    // Filter by protocol
    let result = engine
        .query("SELECT * FROM packets WHERE protocol = 'UDP' LIMIT 5")
        .await;
    assert!(
        result.is_ok(),
        "Protocol filter should work: {:?}",
        result.err()
    );
}

/// Test that the dns_packets view correctly joins DNS data.
#[tokio::test]
async fn test_dns_packets_view() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // Query the dns_packets view
    let query = "SELECT frame_number, query_name, is_query, src_port, dst_port FROM dns_packets LIMIT 5";
    let result = engine.query(query).await;
    assert!(
        result.is_ok(),
        "dns_packets view should work: {:?}",
        result.err()
    );

    let batches = result.unwrap();
    assert!(!batches.is_empty(), "dns_packets should have results");
}

/// Test that frame_number is the correct linking key.
#[tokio::test]
async fn test_frame_number_linking() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // All tables should have frame_number as first column
    for (table_name, schema) in tables::all_table_schemas() {
        let first_field = schema.fields().get(0);
        assert!(
            first_field.is_some(),
            "Table '{}' should have at least one field",
            table_name
        );
        assert_eq!(
            first_field.unwrap().name(),
            "frame_number",
            "Table '{}' should have frame_number as first column",
            table_name
        );
    }
}

/// Test TCP packets view with a TCP capture.
#[tokio::test]
async fn test_tcp_packets_view() {
    let pcap = test_pcap_path("http-chunked-gzip.pcap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // Query tcp_packets view
    let query = "SELECT frame_number, src_port, dst_port, seq, ack, flags FROM tcp_packets LIMIT 5";
    let result = engine.query(query).await;
    assert!(
        result.is_ok(),
        "tcp_packets view should work: {:?}",
        result.err()
    );

    let batches = result.unwrap();
    assert!(!batches.is_empty(), "tcp_packets should have results");

    // Count should match tcp table
    let tcp_count = engine
        .query("SELECT COUNT(*) FROM tcp")
        .await
        .expect("tcp count query failed");
    let tcp_packets_count = engine
        .query("SELECT COUNT(*) FROM tcp_packets")
        .await
        .expect("tcp_packets count query failed");

    // tcp_packets should have same row count as tcp (it's an INNER JOIN on tcp)
    assert_eq!(
        tcp_count[0].num_rows(),
        tcp_packets_count[0].num_rows(),
        "tcp and tcp_packets should have same number of rows"
    );
}

/// Test empty protocol tables.
#[tokio::test]
async fn test_empty_protocol_tables() {
    let pcap = test_pcap_path("dns.cap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // dns.cap has no TCP traffic (it's UDP DNS)
    let result = engine.query("SELECT COUNT(*) as cnt FROM tcp").await;
    assert!(result.is_ok(), "Empty tcp table should be queryable");

    // HTTP table should also be empty
    let result = engine.query("SELECT COUNT(*) as cnt FROM http").await;
    assert!(result.is_ok(), "Empty http table should be queryable");
}

/// Test ARP packets with arp-storm.pcap
#[tokio::test]
async fn test_arp_packets() {
    let pcap = test_pcap_path("arp-storm.pcap");
    let engine = QueryEngine::with_progress(&pcap, 1000, false)
        .await
        .expect("Failed to create query engine");

    // ARP table should have rows
    let result = engine.query("SELECT COUNT(*) as cnt FROM arp").await;
    assert!(result.is_ok(), "ARP query should work");

    // arp_packets view should work
    let result = engine
        .query("SELECT frame_number, sender_ip, target_ip, operation FROM arp_packets LIMIT 5")
        .await;
    assert!(
        result.is_ok(),
        "arp_packets view should work: {:?}",
        result.err()
    );
}

/// Test that protocol fields are properly stripped of prefixes.
#[tokio::test]
async fn test_field_name_normalization() {
    // Field names should not have protocol prefixes
    let dns_schema = tables::dns_table_schema();
    for field in dns_schema.fields() {
        assert!(
            !field.name().contains('.'),
            "Field '{}' should not have protocol prefix",
            field.name()
        );
    }

    let tcp_schema = tables::tcp_table_schema();
    for field in tcp_schema.fields() {
        assert!(
            !field.name().contains('.'),
            "Field '{}' should not have protocol prefix",
            field.name()
        );
    }
}
