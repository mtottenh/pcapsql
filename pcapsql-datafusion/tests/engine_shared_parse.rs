//! End-to-end tests for the shared single-parse-pass engine path: a query
//! touching N protocol tables parses the capture once, and produces exactly
//! the same results as the in-memory path.

use std::sync::Arc;

use arrow::util::pretty::pretty_format_batches;
use pcapsql_core::io::MmapPacketSource;
use pcapsql_datafusion::query::QueryEngine;
use pcapsql_testgen::{legacy_pcap, GenPacket, GeneratedCapture, LegacyVariant};
use tempfile::TempDir;

/// Build a minimal valid Ethernet/IPv4/UDP frame so the ethernet/ipv4/udp
/// tables actually populate.
fn udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    // Ethernet
    p.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst mac
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    p.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
                                        // IPv4
    let ip_total = (20 + 8 + payload_len) as u16;
    p.push(0x45); // version 4, IHL 5
    p.push(0x00); // DSCP/ECN
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // id
    p.extend_from_slice(&[0x40, 0x00]); // flags DF
    p.push(64); // ttl
    p.push(17); // protocol UDP
    p.extend_from_slice(&[0x00, 0x00]); // header checksum (0 = unchecked)
    p.extend_from_slice(&[192, 168, 0, 1]); // src ip
    p.extend_from_slice(&[192, 168, 0, 2]); // dst ip
                                            // UDP
    let udp_len = (8 + payload_len) as u16;
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // checksum 0
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

fn make_capture(n: usize) -> GeneratedCapture {
    let packets: Vec<GenPacket> = (0..n)
        .map(|i| {
            let data = udp_packet(10_000 + i as u16, 53, 8);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32 * 137) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets)
}

async fn engine(path: &std::path::Path) -> QueryEngine {
    let source = Arc::new(MmapPacketSource::open(path).expect("open mmap"));
    QueryEngine::with_streaming_source(source, 1000)
        .await
        .expect("build engine")
}

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine.query(sql).await.expect("query ok");
    pretty_format_batches(&batches).expect("format").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_parse_is_one_pass_and_matches_in_memory() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cap.pcap");
    std::fs::write(&path, make_capture(60).bytes).unwrap();

    let shared = engine(&path).await;

    // A view query touching multiple protocol tables performs exactly ONE
    // parse pass over the file, not one per table.
    let _ = run(
        &shared,
        "SELECT f.frame_number, u.dst_port \
         FROM frames f JOIN udp u USING (frame_number) \
         JOIN ipv4 v USING (frame_number)",
    )
    .await;
    assert_eq!(
        shared.parse_pass_count(),
        1,
        "shared parse must perform exactly one pass regardless of tables touched"
    );

    // Results are identical to the in-memory path on the same capture.
    let in_memory = QueryEngine::with_progress(&path, 1000, false)
        .await
        .expect("in-memory engine");
    let queries = [
        "SELECT count(*) AS c FROM frames",
        "SELECT count(*) AS c FROM udp",
        "SELECT count(*) AS c FROM ipv4",
        "SELECT frame_number, length FROM frames ORDER BY frame_number",
        "SELECT frame_number, src_port, dst_port FROM udp ORDER BY frame_number",
        "SELECT f.frame_number, u.src_port FROM frames f \
         JOIN udp u USING (frame_number) ORDER BY f.frame_number",
    ];
    for sql in queries {
        let a = run(&shared, sql).await;
        let b = run(&in_memory, sql).await;
        assert_eq!(a, b, "shared-parse vs in-memory mismatch for: {sql}");
    }

    // Sanity: the data actually populated the protocol tables.
    let frames = run(&shared, "SELECT count(*) AS c FROM frames").await;
    assert!(frames.contains("60"), "expected 60 frames:\n{frames}");
    let udp = run(&shared, "SELECT count(*) AS c FROM udp").await;
    assert!(udp.contains("60"), "expected 60 udp rows:\n{udp}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_capture_is_rejected() {
    // A header-only legacy capture with no packets.
    let gc = legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &[]);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.pcap");
    std::fs::write(&path, gc.bytes).unwrap();
    let source = Arc::new(MmapPacketSource::open(&path).unwrap());
    let result = QueryEngine::with_streaming_source(source, 1000).await;
    assert!(result.is_err(), "empty capture should be rejected");
}
