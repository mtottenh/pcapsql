//! Golden query corpus: cross-phase result-identity guard.
//!
//! A fixed, hand-crafted capture is queried with a corpus covering every
//! populated protocol table plus joins, aggregates, LIMIT, views, list
//! columns and `raw_data`. Results are compared byte-for-byte against
//! checked-in snapshots, so any refactor that changes query results — row
//! content, order, types, or formatting — fails loudly.
//!
//! Regenerate snapshots after an *intentional* change with:
//! ```text
//! PCAPSQL_GOLDEN_UPDATE=1 cargo test -p pcapsql-datafusion --test golden_corpus
//! ```
//! and review the diff like any other code change.

use std::path::{Path, PathBuf};

use arrow::util::pretty::pretty_format_batches;
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Packet crafting (deterministic, byte-exact)
// ---------------------------------------------------------------------------

const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const BCAST: [u8; 6] = [0xff; 6];

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&dst);
    p.extend_from_slice(&src);
    p.extend_from_slice(&ethertype.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45); // version 4, IHL 5
    p.push(0x00); // DSCP/ECN
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x40, 0x00]); // DF
    p.push(64); // ttl
    p.push(proto);
    p.extend_from_slice(&[0x00, 0x00]); // checksum (unverified)
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

fn tcp(sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.push(0x50); // data offset 5, no options
    p.push(flags);
    p.extend_from_slice(&65535u16.to_be_bytes()); // window
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum, urgent
    p.extend_from_slice(payload);
    p
}

fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(payload);
    p
}

/// DNS A query for example.com (id 0x1234, RD).
fn dns_query() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qd=1 an=0 ns=0 ar=0
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    p
}

/// DNS response with one A answer (93.184.216.34, ttl 300).
fn dns_response() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x1234u16.to_be_bytes());
    p.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA
    p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // qd=1 an=1
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0, 1, 0, 1]);
    p.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to offset 12
    p.extend_from_slice(&[0, 1, 0, 1]); // TYPE A, CLASS IN
    p.extend_from_slice(&300u32.to_be_bytes()); // TTL
    p.extend_from_slice(&[0, 4, 93, 184, 216, 34]); // RDLENGTH + RDATA
    p
}

/// ARP request: who-has 10.0.0.2 tell 10.0.0.1.
fn arp_request() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0, 1]); // htype ethernet
    p.extend_from_slice(&[0x08, 0x00]); // ptype IPv4
    p.push(6);
    p.push(4);
    p.extend_from_slice(&[0, 1]); // request
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&[10, 0, 0, 1]);
    p.extend_from_slice(&[0; 6]);
    p.extend_from_slice(&[10, 0, 0, 2]);
    p
}

/// ICMP echo request (id 1, seq 1).
fn icmp_echo() -> Vec<u8> {
    let mut p = vec![8, 0, 0, 0]; // type 8, code 0, checksum 0
    p.extend_from_slice(&[0, 1, 0, 1]); // id, seq
    p.extend_from_slice(&[0xAB; 8]);
    p
}

fn ipv6(src16: [u8; 16], dst16: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]); // version 6
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.push(next);
    p.push(64); // hop limit
    p.extend_from_slice(&src16);
    p.extend_from_slice(&dst16);
    p.extend_from_slice(payload);
    p
}

const IP6_A: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IP6_B: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

const ETH_IP4: u16 = 0x0800;
const ETH_IP6: u16 = 0x86DD;
const ETH_ARP: u16 = 0x0806;

/// The fixed corpus capture: 9 frames covering tcp/udp/dns/arp/icmp/ipv6.
fn corpus_capture() -> Vec<u8> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let frames: Vec<Vec<u8>> = vec![
        // 1: TCP SYN a:40000 -> b:80
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 1, &tcp(40000, 80, 1000, 0, 0x02, &[])),
        ),
        // 2: TCP SYN+ACK back
        eth(
            MAC_A,
            MAC_B,
            ETH_IP4,
            &ipv4(b, a, 6, 2, &tcp(80, 40000, 7000, 1001, 0x12, &[])),
        ),
        // 3: TCP PSH+ACK with payload
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                6,
                3,
                &tcp(40000, 80, 1001, 7001, 0x18, b"hello pcapsql"),
            ),
        ),
        // 4: DNS query a -> 8.8.8.8
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, [8, 8, 8, 8], 17, 4, &udp(33333, 53, &dns_query())),
        ),
        // 5: DNS response back
        eth(
            MAC_A,
            MAC_B,
            ETH_IP4,
            &ipv4([8, 8, 8, 8], a, 17, 5, &udp(53, 33333, &dns_response())),
        ),
        // 6: ARP request (broadcast)
        eth(BCAST, MAC_A, ETH_ARP, &arp_request()),
        // 7: ICMP echo request
        eth(MAC_B, MAC_A, ETH_IP4, &ipv4(a, b, 1, 6, &icmp_echo())),
        // 8: IPv6 UDP
        eth(
            MAC_B,
            MAC_A,
            ETH_IP6,
            &ipv6(IP6_A, IP6_B, 17, &udp(1024, 2048, &[0x11; 4])),
        ),
        // 9: TCP FIN+ACK
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 7, &tcp(40000, 80, 1014, 7001, 0x11, &[])),
        ),
    ];

    let packets: Vec<GenPacket> = frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + i as u32,
                ts_frac: (i as u32) * 1_000,
                data,
                origlen,
            }
        })
        .collect();

    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// (snapshot name, SQL). Every query is fully ordered so output is stable.
const CORPUS: &[(&str, &str)] = &[
    (
        "q01_frames",
        "SELECT frame_number, length, original_length, link_type \
         FROM frames ORDER BY frame_number",
    ),
    ("q02_count", "SELECT count(*) AS frames FROM frames"),
    (
        "q03_ethernet",
        "SELECT frame_number, ethertype FROM ethernet ORDER BY frame_number",
    ),
    (
        "q04_ipv4",
        "SELECT frame_number, src_ip, dst_ip, protocol, ttl \
         FROM ipv4 ORDER BY frame_number",
    ),
    (
        "q05_tcp",
        "SELECT frame_number, src_port, dst_port, flag_syn, flag_ack, flag_fin \
         FROM tcp ORDER BY frame_number",
    ),
    (
        "q06_udp",
        "SELECT frame_number, src_port, dst_port, length \
         FROM udp ORDER BY frame_number",
    ),
    (
        "q07_dns",
        "SELECT frame_number, query_name, is_query, answer_count \
         FROM dns ORDER BY frame_number",
    ),
    (
        "q08_arp",
        "SELECT frame_number, operation, sender_ip, target_ip \
         FROM arp ORDER BY frame_number",
    ),
    (
        "q09_icmp",
        "SELECT frame_number, \"type\", code FROM icmp ORDER BY frame_number",
    ),
    (
        "q10_ipv6",
        "SELECT frame_number, next_header, hop_limit FROM ipv6 ORDER BY frame_number",
    ),
    (
        "q11_join",
        "SELECT f.frame_number, t.src_port, t.dst_port \
         FROM frames f JOIN tcp t USING (frame_number) ORDER BY f.frame_number",
    ),
    (
        "q12_agg",
        "SELECT protocol, count(*) AS n FROM ipv4 GROUP BY protocol ORDER BY protocol",
    ),
    (
        "q13_limit",
        "SELECT frame_number FROM frames ORDER BY frame_number LIMIT 3",
    ),
    (
        "q14_raw_hex",
        "SELECT frame_number, length(hex(raw_data)) / 2 AS len, \
         substr(hex(raw_data), 1, 24) AS eth_header_prefix \
         FROM frames ORDER BY frame_number",
    ),
    (
        "q15_timestamp",
        "SELECT frame_number, timestamp FROM frames ORDER BY frame_number",
    ),
    (
        "q16_tcp_packets_view",
        "SELECT frame_number, src_ip_v4, dst_ip_v4, src_port, dst_port \
         FROM tcp_packets ORDER BY frame_number",
    ),
    (
        "q17_dns_answers",
        "SELECT frame_number, answer_ip4s, answer_ttls \
         FROM dns WHERE answer_count > 0 ORDER BY frame_number",
    ),
    (
        "q18_where",
        "SELECT frame_number FROM tcp WHERE dst_port = 80 ORDER BY frame_number",
    ),
];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

async fn engine(path: &Path, partitions: usize) -> QueryEngine {
    QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 1000,
            target_partitions: Some(partitions),
            index_stride: Some(4),
            ..Default::default()
        },
    )
    .await
    .expect("build engine")
}

async fn run(engine: &QueryEngine, sql: &str) -> String {
    let batches = engine.query(sql).await.unwrap_or_else(|e| {
        panic!("query failed: {sql}\n{e}");
    });
    pretty_format_batches(&batches).expect("format").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn golden_corpus_matches_snapshots() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("corpus.pcap");
    std::fs::write(&path, corpus_capture()).unwrap();

    let update = std::env::var("PCAPSQL_GOLDEN_UPDATE").is_ok();
    if update {
        std::fs::create_dir_all(golden_dir()).unwrap();
    }

    let e2 = engine(&path, 2).await;
    let e1 = engine(&path, 1).await;

    let mut failures = Vec::new();
    for (name, sql) in CORPUS {
        let got = run(&e2, sql).await;

        // Partition-count independence is part of the contract.
        let got_p1 = run(&e1, sql).await;
        assert_eq!(
            got, got_p1,
            "{name}: results differ between 1 and 2 partitions"
        );

        let snap_path = golden_dir().join(format!("{name}.snap"));
        if update {
            std::fs::write(&snap_path, &got).unwrap();
            continue;
        }
        let expected = std::fs::read_to_string(&snap_path).unwrap_or_else(|e| {
            panic!(
                "missing snapshot {} ({e}); run with PCAPSQL_GOLDEN_UPDATE=1 to create",
                snap_path.display()
            )
        });
        if got != expected {
            failures.push(format!(
                "=== {name} ===\n--- expected ---\n{expected}\n--- got ---\n{got}\n"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "golden corpus mismatches:\n{}",
        failures.join("\n")
    );
}
