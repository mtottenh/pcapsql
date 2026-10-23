//! Golden query corpus: cross-phase result-identity guard.
//!
//! Two fixed, hand-crafted captures are queried with a corpus covering every
//! populated protocol table plus joins, aggregates, LIMIT, views, list
//! columns, `raw_data`, VLAN and VXLAN encapsulation, the time UDFs, and
//! queries that reference the same table twice. The second capture uses the
//! Linux "cooked" (SLL) link type, as `tcpdump -i any` writes, so the
//! non-Ethernet link-layer path is guarded too. Results are compared
//! byte-for-byte against checked-in snapshots, so any refactor that changes
//! query results — row content, order, types, or formatting — fails loudly.
//!
//! Regenerate snapshots after an *intentional* change with:
//! ```text
//! PCAPSQL_GOLDEN_UPDATE=1 cargo test -p pcapsql-datafusion --test golden_corpus
//! ```
//! and review the diff like any other code change.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::util::pretty::pretty_format_batches;
use pcapsql_core::io::MmapPacketSource;
use pcapsql_datafusion::query::QueryEngine;
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
const ETH_VLAN: u16 = 0x8100;

/// 802.1Q tag: priority 3, DEI 0, VLAN id `vid`, followed by the inner
/// ethertype — inserted between the Ethernet header and its payload.
fn vlan_tagged(
    dst: [u8; 6],
    src: [u8; 6],
    vid: u16,
    inner_ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut tci = Vec::with_capacity(4 + payload.len());
    tci.extend_from_slice(&((3u16 << 13) | (vid & 0x0FFF)).to_be_bytes());
    tci.extend_from_slice(&inner_ethertype.to_be_bytes());
    tci.extend_from_slice(payload);
    eth(dst, src, ETH_VLAN, &tci)
}

/// VXLAN header (flags I, VNI `vni`) wrapping an inner Ethernet frame.
fn vxlan(vni: u32, inner: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + inner.len());
    p.extend_from_slice(&[0x08, 0, 0, 0]); // flags: VNI valid
    p.extend_from_slice(&vni.to_be_bytes()[1..]); // 24-bit VNI
    p.push(0); // reserved
    p.extend_from_slice(inner);
    p
}

/// Linux cooked capture (SLL, LINKTYPE 113) header in front of an L3 payload:
/// packet type, ARPHRD_ETHER, address length 6, 8-byte address, protocol.
fn sll(pkttype: u16, src: [u8; 6], protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(16 + payload.len());
    p.extend_from_slice(&pkttype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    p.extend_from_slice(&6u16.to_be_bytes());
    p.extend_from_slice(&src);
    p.extend_from_slice(&[0, 0]); // address padding to 8 bytes
    p.extend_from_slice(&protocol.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

const LINKTYPE_ETHERNET: u16 = 1;
const LINKTYPE_LINUX_SLL: u16 = 113;

fn to_capture(frames: Vec<Vec<u8>>, link_type: u16) -> Vec<u8> {
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
    legacy_pcap(LegacyVariant::LeMicro, link_type, 65535, &packets).bytes
}

/// The Linux SLL corpus capture: 3 frames (DNS query, TCP SYN, ICMP echo)
/// under a cooked-capture header instead of Ethernet.
fn sll_capture() -> Vec<u8> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let frames: Vec<Vec<u8>> = vec![
        // 1: DNS query a -> 8.8.8.8 (outgoing)
        sll(
            4,
            MAC_A,
            ETH_IP4,
            &ipv4(a, [8, 8, 8, 8], 17, 1, &udp(40000, 53, &dns_query())),
        ),
        // 2: TCP SYN a:40001 -> b:443 (outgoing)
        sll(
            4,
            MAC_A,
            ETH_IP4,
            &ipv4(a, b, 6, 2, &tcp(40001, 443, 5000, 0, 0x02, &[])),
        ),
        // 3: ICMP echo request, received (packet type 0 = to us)
        sll(0, MAC_B, ETH_IP4, &ipv4(b, a, 1, 3, &icmp_echo())),
    ];
    to_capture(frames, LINKTYPE_LINUX_SLL)
}

/// The fixed Ethernet corpus capture: 11 frames covering
/// tcp/udp/dns/arp/icmp/ipv6 plus one VLAN-tagged and one VXLAN-encapsulated
/// frame (the latter carries an inner Ethernet/IPv4/UDP frame).
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
        // 10: VLAN 100 tagged IPv4/UDP a:5000 -> b:6000
        vlan_tagged(
            MAC_B,
            MAC_A,
            100,
            ETH_IP4,
            &ipv4(a, b, 17, 8, &udp(5000, 6000, &[0x22; 6])),
        ),
        // 11: VXLAN (VNI 42) a:49152 -> b:4789 carrying inner Ethernet/IPv4/UDP
        //     192.168.1.1:7000 -> 192.168.1.2:8000
        eth(
            MAC_B,
            MAC_A,
            ETH_IP4,
            &ipv4(
                a,
                b,
                17,
                9,
                &udp(
                    49152,
                    4789,
                    &vxlan(
                        42,
                        &eth(
                            [0x02, 0, 0, 0, 0, 0x11],
                            [0x02, 0, 0, 0, 0, 0x22],
                            ETH_IP4,
                            &ipv4(
                                [192, 168, 1, 1],
                                [192, 168, 1, 2],
                                17,
                                1,
                                &udp(7000, 8000, &[0x33; 4]),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    ];
    to_capture(frames, LINKTYPE_ETHERNET)
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// Which corpus capture a query runs against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Capture {
    /// `corpus_capture()`: Ethernet link type.
    Eth,
    /// `sll_capture()`: Linux cooked (SLL) link type.
    Sll,
}

/// (capture, snapshot name, SQL). Every query is fully ordered so output is
/// stable.
const CORPUS: &[(Capture, &str, &str)] = &[
    (
        Capture::Eth,
        "q01_frames",
        "SELECT frame_number, length, original_length, link_type \
         FROM frames ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q02_count",
        "SELECT count(*) AS frames FROM frames",
    ),
    (
        Capture::Eth,
        "q03_ethernet",
        "SELECT frame_number, ethertype FROM ethernet ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q04_ipv4",
        "SELECT frame_number, src_ip, dst_ip, protocol, ttl \
         FROM ipv4 ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q05_tcp",
        "SELECT frame_number, src_port, dst_port, flag_syn, flag_ack, flag_fin \
         FROM tcp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q06_udp",
        "SELECT frame_number, src_port, dst_port, length \
         FROM udp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q07_dns",
        "SELECT frame_number, query_name, is_query, answer_count \
         FROM dns ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q08_arp",
        "SELECT frame_number, operation, sender_ip, target_ip \
         FROM arp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q09_icmp",
        "SELECT frame_number, \"type\", code FROM icmp ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q10_ipv6",
        "SELECT frame_number, next_header, hop_limit FROM ipv6 ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q11_join",
        "SELECT f.frame_number, t.src_port, t.dst_port \
         FROM frames f JOIN tcp t USING (frame_number) ORDER BY f.frame_number",
    ),
    (
        Capture::Eth,
        "q12_agg",
        "SELECT protocol, count(*) AS n FROM ipv4 GROUP BY protocol ORDER BY protocol",
    ),
    (
        Capture::Eth,
        "q13_limit",
        "SELECT frame_number FROM frames ORDER BY frame_number LIMIT 3",
    ),
    (
        Capture::Eth,
        "q14_raw_hex",
        "SELECT frame_number, length(hex(raw_data)) / 2 AS len, \
         substr(hex(raw_data), 1, 24) AS eth_header_prefix \
         FROM frames ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q15_timestamp",
        "SELECT frame_number, timestamp FROM frames ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q16_tcp_packets_view",
        "SELECT frame_number, src_ip_v4, dst_ip_v4, src_port, dst_port \
         FROM tcp_packets ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q17_dns_answers",
        "SELECT frame_number, answer_ip4s, answer_ttls \
         FROM dns WHERE answer_count > 0 ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q18_where",
        "SELECT frame_number FROM tcp WHERE dst_port = 80 ORDER BY frame_number",
    ),
    // --- encapsulation: a parse that prunes or stops early loses these rows ---
    (
        Capture::Eth,
        "q19_vlan",
        "SELECT frame_number, vlan_id, priority, inner_ethertype \
         FROM vlan ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q20_vxlan",
        "SELECT frame_number, vni FROM vxlan ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q21_ethernet_encap",
        "SELECT frame_number, src_mac, encap_depth, tunnel_type, tunnel_id \
         FROM ethernet WHERE frame_number >= 10 ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Eth,
        "q22_udp_inner",
        "SELECT frame_number, src_port, dst_port, encap_depth \
         FROM udp WHERE frame_number >= 10 ORDER BY frame_number, encap_depth",
    ),
    (
        Capture::Eth,
        "q23_ipv4_inner",
        "SELECT frame_number, src_ip, dst_ip, encap_depth, tunnel_type \
         FROM ipv4 WHERE encap_depth > 0 ORDER BY frame_number",
    ),
    // --- time UDFs depend on the capture's full time range; these run on a
    //     fresh engine (see FRESH_ENGINE_QUERIES) so an earlier query cannot
    //     have populated the range for them ---
    (
        Capture::Eth,
        "q24_time_udfs",
        "SELECT frame_number, relative_time(timestamp) AS rel, \
         start_time() AS t0, end_time() AS t1 \
         FROM frames ORDER BY frame_number LIMIT 2",
    ),
    (
        Capture::Eth,
        "q25_time_range_only",
        "SELECT start_time() AS t0, end_time() AS t1",
    ),
    // --- the same table referenced twice in one query ---
    (
        Capture::Eth,
        "q26_self_join",
        "SELECT a.frame_number, b.frame_number AS next_frame \
         FROM frames a JOIN frames b ON b.frame_number = a.frame_number + 1 \
         ORDER BY a.frame_number",
    ),
    (
        Capture::Eth,
        "q27_in_subquery",
        "SELECT frame_number FROM frames \
         WHERE frame_number IN (SELECT frame_number FROM tcp WHERE dst_port = 80) \
         ORDER BY frame_number",
    ),
    (
        Capture::Eth,
        "q28_view_plus_member",
        "SELECT t.frame_number, t.dst_port, u.flag_syn \
         FROM tcp_packets t JOIN tcp u USING (frame_number) ORDER BY t.frame_number",
    ),
    // --- Linux cooked capture: non-Ethernet link layer ---
    (
        Capture::Sll,
        "s01_sll",
        "SELECT frame_number, packet_type, protocol FROM linux_sll ORDER BY frame_number",
    ),
    (
        Capture::Sll,
        "s02_sll_ipv4",
        "SELECT frame_number, src_ip, dst_ip, protocol FROM ipv4 ORDER BY frame_number",
    ),
    (
        Capture::Sll,
        "s03_sll_udp_tcp_icmp",
        "SELECT (SELECT count(*) FROM udp) AS udp, (SELECT count(*) FROM tcp) AS tcp, \
         (SELECT count(*) FROM icmp) AS icmp",
    ),
    (
        Capture::Sll,
        "s04_sll_dns",
        "SELECT frame_number, query_name, is_query FROM dns ORDER BY frame_number",
    ),
    (
        Capture::Sll,
        "s05_sll_tcp_only",
        "SELECT frame_number, dst_port FROM tcp ORDER BY frame_number",
    ),
];

/// Queries that must be the *first* query a fresh engine runs: their result
/// depends on engine-wide state (the capture time range) that any earlier
/// query would otherwise establish as a side effect.
const FRESH_ENGINE_QUERIES: &[&str] = &["q24_time_udfs", "q25_time_range_only"];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

async fn engine(path: &Path, partitions: usize) -> QueryEngine {
    let source = Arc::new(
        MmapPacketSource::open(path)
            .expect("open mmap")
            .with_index_stride(4),
    );
    QueryEngine::with_streaming_source_partitions(source, 1000, partitions)
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
    let eth_path = dir.path().join("corpus.pcap");
    std::fs::write(&eth_path, corpus_capture()).unwrap();
    let sll_path = dir.path().join("corpus_sll.pcap");
    std::fs::write(&sll_path, sll_capture()).unwrap();

    let update = std::env::var("PCAPSQL_GOLDEN_UPDATE").is_ok();
    if update {
        std::fs::create_dir_all(golden_dir()).unwrap();
    }

    let eth = (engine(&eth_path, 2).await, engine(&eth_path, 1).await);
    let sll = (engine(&sll_path, 2).await, engine(&sll_path, 1).await);

    let mut failures = Vec::new();
    for (capture, name, sql) in CORPUS {
        let path = match capture {
            Capture::Eth => &eth_path,
            Capture::Sll => &sll_path,
        };
        let fresh = FRESH_ENGINE_QUERIES.contains(name);
        let fresh_engines = if fresh {
            Some((engine(path, 2).await, engine(path, 1).await))
        } else {
            None
        };
        let (e2, e1) = match (&fresh_engines, capture) {
            (Some(f), _) => (&f.0, &f.1),
            (None, Capture::Eth) => (&eth.0, &eth.1),
            (None, Capture::Sll) => (&sll.0, &sll.1),
        };
        let got = run(e2, sql).await;

        // Partition-count independence is part of the contract.
        let got_p1 = run(e1, sql).await;
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
