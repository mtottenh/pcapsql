//! Integration tests for filter pushdown in streaming scans (issue #86).
//!
//! Selective WHERE queries on streaming tables must:
//! 1. Return exactly the same rows as the in-memory engine (correctness).
//! 2. Materialize fewer rows than a full scan, observable via the
//!    `pushdown_rows_pruned` metric on `ProtocolStreamExec` (effectiveness).

use std::io::Write;
use std::sync::Arc;

use arrow::array::UInt64Array;
use arrow::record_batch::RecordBatch;
use arrow::util::pretty::pretty_format_batches;
use datafusion::physical_plan::{collect, ExecutionPlan};
use tempfile::NamedTempFile;

use pcapsql_datafusion::query::QueryEngine;

// ============================================================================
// Test PCAP synthesis
// ============================================================================

fn ipv4_header(src: [u8; 4], dst: [u8; 4], protocol: u8, payload_len: u16) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut h = vec![
        0x45,
        0x00, // version/IHL, DSCP/ECN
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01, // identification
        0x40,
        0x00, // flags (DF), fragment offset
        64,
        protocol, // TTL, protocol
        0x00,
        0x00, // checksum (not validated by the parser)
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

fn tcp_segment(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&1000u32.to_be_bytes()); // seq
    s.extend_from_slice(&0u32.to_be_bytes()); // ack
    s.extend_from_slice(&[0x50, 0x02]); // data offset 5, SYN
    s.extend_from_slice(&[0xff, 0xff]); // window
    s.extend_from_slice(&[0x00, 0x00]); // checksum
    s.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    s
}

fn udp_datagram(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&8u16.to_be_bytes()); // length (header only)
    s.extend_from_slice(&[0x00, 0x00]); // checksum
    s
}

fn ethernet_frame(l3: &[u8]) -> Vec<u8> {
    let mut f = vec![
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
        0x08, 0x00, // ethertype IPv4
    ];
    f.extend_from_slice(l3);
    f
}

fn tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let l4 = tcp_segment(src_port, dst_port);
    let mut l3 = ipv4_header(src, dst, 6, l4.len() as u16);
    l3.extend_from_slice(&l4);
    ethernet_frame(&l3)
}

fn udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let l4 = udp_datagram(src_port, dst_port);
    let mut l3 = ipv4_header(src, dst, 17, l4.len() as u16);
    l3.extend_from_slice(&l4);
    ethernet_frame(&l3)
}

/// Write a legacy little-endian microsecond PCAP with the given frames.
fn write_pcap(frames: &[Vec<u8>]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp pcap");

    // Global header
    file.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap(); // magic
    file.write_all(&2u16.to_le_bytes()).unwrap(); // version major
    file.write_all(&4u16.to_le_bytes()).unwrap(); // version minor
    file.write_all(&0i32.to_le_bytes()).unwrap(); // thiszone
    file.write_all(&0u32.to_le_bytes()).unwrap(); // sigfigs
    file.write_all(&65535u32.to_le_bytes()).unwrap(); // snaplen
    file.write_all(&1u32.to_le_bytes()).unwrap(); // linktype: Ethernet

    for (i, frame) in frames.iter().enumerate() {
        file.write_all(&(1_700_000_000u32 + i as u32).to_le_bytes())
            .unwrap(); // ts_sec
        file.write_all(&0u32.to_le_bytes()).unwrap(); // ts_usec
        file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap(); // incl_len
        file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap(); // orig_len
        file.write_all(frame).unwrap();
    }

    file.flush().unwrap();
    file
}

/// Eight frames covering TCP/UDP, multiple ports and source addresses:
///
/// | frame | proto | src       | dst port |
/// |-------|-------|-----------|----------|
/// | 1     | tcp   | 10.0.0.1  | 443      |
/// | 2     | tcp   | 10.0.0.1  | 80       |
/// | 3     | tcp   | 10.0.0.3  | 443      |
/// | 4     | tcp   | 10.0.0.3  | 8080     |
/// | 5     | udp   | 10.0.0.1  | 53       |
/// | 6     | udp   | 10.0.0.5  | 53       |
/// | 7     | tcp   | 10.0.0.7  | 22       |
/// | 8     | tcp   | 10.0.0.1  | 443      |
fn test_capture() -> NamedTempFile {
    write_pcap(&[
        tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 40000, 443),
        tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 40001, 80),
        tcp_packet([10, 0, 0, 3], [10, 0, 0, 4], 40002, 443),
        tcp_packet([10, 0, 0, 3], [10, 0, 0, 4], 40003, 8080),
        udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53),
        udp_packet([10, 0, 0, 5], [10, 0, 0, 6], 1000, 53),
        tcp_packet([10, 0, 0, 7], [10, 0, 0, 8], 40004, 22),
        tcp_packet([10, 0, 0, 1], [10, 0, 0, 8], 40005, 443),
    ])
}

// ============================================================================
// Helpers
// ============================================================================

fn frame_numbers(batches: &[RecordBatch]) -> Vec<u64> {
    let mut out = Vec::new();
    for batch in batches {
        let col = batch
            .column_by_name("frame_number")
            .expect("frame_number column");
        let arr = col.as_any().downcast_ref::<UInt64Array>().unwrap();
        for i in 0..arr.len() {
            out.push(arr.value(i));
        }
    }
    out
}

/// Sum a named metric over an execution plan tree.
fn sum_metric(plan: &Arc<dyn ExecutionPlan>, name: &str) -> usize {
    let mut total = 0;
    if let Some(metrics) = plan.metrics() {
        if let Some(value) = metrics.sum_by_name(name) {
            total += value.as_usize();
        }
    }
    for child in plan.children() {
        total += sum_metric(child, name);
    }
    total
}

/// Run a query on both engines and assert identical frame_number results.
async fn assert_same_frames(
    in_memory: &QueryEngine,
    streaming: &QueryEngine,
    sql: &str,
    expected: &[u64],
) {
    let mem = frame_numbers(&in_memory.query(sql).await.unwrap());
    let stream = frame_numbers(&streaming.query(sql).await.unwrap());
    assert_eq!(mem, expected, "in-memory result mismatch for: {sql}");
    assert_eq!(stream, expected, "streaming result mismatch for: {sql}");
}

// ============================================================================
// Correctness: streaming + pushdown returns the same rows as in-memory
// ============================================================================

#[tokio::test]
async fn test_pushdown_matches_in_memory_results() {
    let pcap = test_capture();
    let in_memory = QueryEngine::new(pcap.path(), 1000).await.unwrap();
    // Small batch size to exercise multi-batch streaming.
    let streaming = QueryEngine::with_streaming(pcap.path(), 3).await.unwrap();

    let cases: &[(&str, &[u64])] = &[
        (
            "SELECT frame_number FROM tcp WHERE dst_port = 443 ORDER BY frame_number",
            &[1, 3, 8],
        ),
        (
            "SELECT frame_number FROM tcp WHERE dst_port <> 443 ORDER BY frame_number",
            &[2, 4, 7],
        ),
        (
            "SELECT frame_number FROM tcp WHERE dst_port IN (80, 8080) ORDER BY frame_number",
            &[2, 4],
        ),
        (
            "SELECT frame_number FROM tcp WHERE dst_port NOT IN (80, 8080) ORDER BY frame_number",
            &[1, 3, 7, 8],
        ),
        (
            "SELECT frame_number FROM tcp WHERE dst_port BETWEEN 100 AND 8000 ORDER BY frame_number",
            &[1, 3, 8],
        ),
        (
            "SELECT frame_number FROM tcp WHERE dst_port = 443 OR src_port = 40001 \
             ORDER BY frame_number",
            &[1, 2, 3, 8],
        ),
        (
            "SELECT frame_number FROM tcp WHERE src_port > 40000 AND dst_port < 100 \
             ORDER BY frame_number",
            &[2, 7],
        ),
        // mss comes from TCP options, absent in these packets: IS NULL keeps
        // all rows, equality against NULL keeps none.
        (
            "SELECT frame_number FROM tcp WHERE mss IS NULL ORDER BY frame_number",
            &[1, 2, 3, 4, 7, 8],
        ),
        ("SELECT frame_number FROM tcp WHERE mss = 1460", &[]),
        (
            "SELECT frame_number FROM tcp WHERE mss <> 1460",
            &[],
        ),
        // frame_number predicates (with ordered early-stop in streaming mode).
        (
            "SELECT frame_number FROM frames WHERE frame_number <= 2 ORDER BY frame_number",
            &[1, 2],
        ),
        (
            "SELECT frame_number FROM tcp WHERE frame_number BETWEEN 2 AND 7 \
             ORDER BY frame_number",
            &[2, 3, 4, 7],
        ),
        // IPv4 addresses are UInt32 columns; ip4() is const-folded into a
        // pushable integer literal.
        (
            "SELECT frame_number FROM ipv4 WHERE src_ip = ip4('10.0.0.1') ORDER BY frame_number",
            &[1, 2, 5, 8],
        ),
        // Mixed supported + unsupported conjuncts: the supported one is
        // pushed, DataFusion applies the rest.
        (
            "SELECT frame_number FROM tcp WHERE dst_port = 443 AND frame_number % 2 = 1 \
             ORDER BY frame_number",
            &[1, 3],
        ),
        // Pushdown through a join.
        (
            "SELECT t.frame_number FROM tcp t JOIN ipv4 i ON t.frame_number = i.frame_number \
             WHERE t.dst_port = 443 AND i.src_ip = ip4('10.0.0.1') ORDER BY t.frame_number",
            &[1, 8],
        ),
    ];

    for (sql, expected) in cases {
        assert_same_frames(&in_memory, &streaming, sql, expected).await;
    }
}

// ============================================================================
// Effectiveness: selective queries materialize fewer rows than a full scan
// ============================================================================

#[tokio::test]
async fn test_pushdown_prunes_rows() {
    let pcap = test_capture();
    let streaming = QueryEngine::with_streaming(pcap.path(), 1000)
        .await
        .unwrap();
    let ctx = streaming.context();

    let df = ctx
        .sql("SELECT frame_number FROM tcp WHERE dst_port = 443")
        .await
        .unwrap();
    let plan = df.create_physical_plan().await.unwrap();
    let batches = collect(plan.clone(), ctx.task_ctx()).await.unwrap();

    // 3 of 6 TCP rows match.
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 3);

    // The 3 non-matching TCP rows were pruned before Arrow materialization.
    let pruned = sum_metric(&plan, "pushdown_rows_pruned");
    assert_eq!(
        pruned, 3,
        "expected non-matching rows to be pruned in the scan"
    );
}

#[tokio::test]
async fn test_no_pushdown_without_filters() {
    let pcap = test_capture();
    let streaming = QueryEngine::with_streaming(pcap.path(), 1000)
        .await
        .unwrap();
    let ctx = streaming.context();

    let df = ctx.sql("SELECT frame_number FROM tcp").await.unwrap();
    let plan = df.create_physical_plan().await.unwrap();
    let batches = collect(plan.clone(), ctx.task_ctx()).await.unwrap();

    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 6);
    assert_eq!(sum_metric(&plan, "pushdown_rows_pruned"), 0);
}

#[tokio::test]
async fn test_explain_shows_pushdown() {
    let pcap = test_capture();
    let streaming = QueryEngine::with_streaming(pcap.path(), 1000)
        .await
        .unwrap();

    let batches = streaming
        .query("EXPLAIN SELECT frame_number FROM tcp WHERE dst_port = 443")
        .await
        .unwrap();
    let text = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        text.contains("pushdown=true"),
        "physical plan should mark the pushed-down predicate:\n{text}"
    );
    // The filter is Inexact, so it must still be re-applied above the scan.
    assert!(
        text.contains("FilterExec"),
        "inexact pushdown must keep the FilterExec:\n{text}"
    );
}

// ============================================================================
// Cached streaming mode (parse cache enabled)
// ============================================================================

#[tokio::test]
async fn test_pushdown_with_parse_cache() {
    let pcap = test_capture();
    let source = Arc::new(pcapsql_core::FilePacketSource::open(pcap.path()).unwrap());
    let in_memory = QueryEngine::new(pcap.path(), 1000).await.unwrap();
    let cached = QueryEngine::with_streaming_source_cached(source, 3, 100)
        .await
        .unwrap();

    assert_same_frames(
        &in_memory,
        &cached,
        "SELECT frame_number FROM tcp WHERE dst_port = 443 ORDER BY frame_number",
        &[1, 3, 8],
    )
    .await;
    assert_same_frames(
        &in_memory,
        &cached,
        "SELECT t.frame_number FROM tcp t JOIN udp u ON t.frame_number = u.frame_number + 1 \
         WHERE t.dst_port = 22 ORDER BY t.frame_number",
        &[7],
    )
    .await;
}
