//! The golden corpus of the DataFusion frontend, and captures made with its frame builders.
//!
//! The frame builders, the capture builders and the query corpus are `pcapsql_testgen::corpus`,
//! the module `pcapsql-datafusion/tests/golden_corpus.rs` takes them from too. The functions
//! here are what the tests use:
//!
//! - [`capture`] and [`queries`]: the corpus captures and the queries whose results are the
//!   committed DataFusion snapshots ([`snapshot`]);
//! - [`udp_frame`], [`vxlan_frame`], [`nested_vxlan_frame`], [`dns_aaaa_frame`] and the capture
//!   writers [`legacy`], [`legacy_nanos`], [`pcapng`]: captures for the scan tests, built from
//!   the same byte-exact frame builders.

use std::path::PathBuf;

use pcapsql_testgen::corpus::{
    corpus_capture, dns_query, eth, http_capture, ipv4, routing_capture, sll2_capture, sll_capture,
    to_capture, tunnels_capture, udp, views_capture, vxlan, Capture, CORPUS, ETH_IP4,
    LINKTYPE_ETHERNET, MAC_A, MAC_B,
};
use pcapsql_testgen::{
    legacy_pcap, GenPacket, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};

/// The names of the corpus captures, as [`capture`] takes them.
pub const CAPTURES: [&str; 6] = ["eth", "sll", "sll2", "http", "routing", "tunnels"];

/// The corpus captures and `views`, the capture the DataFusion frontend compares its
/// `*_packets` views over besides them: the protocols no corpus capture has (ESP, MPLS, QUIC).
/// No corpus query reads it.
pub const VIEW_CAPTURES: [&str; 7] = ["eth", "sll", "sll2", "http", "routing", "tunnels", "views"];

fn capture_name(capture: Capture) -> &'static str {
    match capture {
        Capture::Eth => "eth",
        Capture::Sll => "sll",
        Capture::Sll2 => "sll2",
        Capture::Http => "http",
        Capture::Routing => "routing",
        Capture::Tunnels => "tunnels",
    }
}

/// The bytes of a corpus capture (a legacy pcap file).
pub fn capture(name: &str) -> Vec<u8> {
    match name {
        "eth" => corpus_capture(),
        "sll" => sll_capture(),
        "sll2" => sll2_capture(),
        "http" => http_capture(),
        "routing" => routing_capture(),
        "tunnels" => tunnels_capture(),
        "views" => views_capture(),
        other => panic!("there is no corpus capture '{other}'"),
    }
}

/// One query of the corpus.
#[derive(Debug, Clone, Copy)]
pub struct Query {
    /// The capture it runs against: one of [`CAPTURES`].
    pub capture: &'static str,
    /// The name of its snapshot.
    pub name: &'static str,
    /// The SQL, as the DataFusion frontend runs it.
    pub sql: &'static str,
}

/// Every query of the DataFusion golden corpus, in its order.
pub fn queries() -> Vec<Query> {
    CORPUS
        .iter()
        .map(|(capture, name, sql)| Query {
            capture: capture_name(*capture),
            name,
            sql,
        })
        .collect()
}

/// The committed DataFusion result of the corpus query `name`: Arrow's pretty-printed table.
pub fn snapshot(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../pcapsql-datafusion/tests/golden")
        .join(format!("{name}.snap"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

// ---------------------------------------------------------------------------------------------
// Frames and captures for the scan tests
// ---------------------------------------------------------------------------------------------

/// The addresses frame `i` is sent between: distinct per frame, so a row lost or doubled shows.
fn hosts(i: u32) -> ([u8; 4], [u8; 4]) {
    let [_, b, c, d] = i.to_be_bytes();
    ([10, b, c, d], [172, 16, c, d])
}

/// Ethernet/IPv4/UDP, source port `1024 + i % 60000`, destination port 9999, four payload bytes
/// that spell `i`. One row in `ethernet`, `ipv4` and `udp`.
pub fn udp_frame(i: u32) -> Vec<u8> {
    let (a, b) = hosts(i);
    let port = 1024 + (i % 60_000) as u16;
    eth(
        MAC_B,
        MAC_A,
        ETH_IP4,
        &ipv4(a, b, 17, i as u16, &udp(port, 9999, &i.to_be_bytes())),
    )
}

/// [`udp_frame`]`(i)` inside VXLAN (VNI `i % 2^24`): two rows in `ethernet`, `ipv4` and `udp`,
/// one in `vxlan`.
pub fn vxlan_frame(i: u32) -> Vec<u8> {
    let (a, b) = hosts(i);
    let outer = udp(49152, 4789, &vxlan(i & 0x00ff_ffff, &udp_frame(i)));
    eth(MAC_A, MAC_B, ETH_IP4, &ipv4(b, a, 17, i as u16, &outer))
}

/// [`vxlan_frame`]`(i)` inside another VXLAN: three rows in `ethernet`, `ipv4` and `udp`, two in
/// `vxlan`.
pub fn nested_vxlan_frame(i: u32) -> Vec<u8> {
    let (a, b) = hosts(i);
    let outer = udp(49153, 4789, &vxlan(0x00ab_cdef, &vxlan_frame(i)));
    eth(MAC_B, MAC_A, ETH_IP4, &ipv4(a, b, 17, i as u16, &outer))
}

/// The IPv6 addresses of the AAAA answers of [`dns_aaaa_frame`].
pub const AAAA_ANSWERS: [[u8; 16]; 2] = [
    [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ],
    [
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19,
        0x46,
    ],
];

/// The IPv4 address of the A answer of [`dns_aaaa_frame`].
pub const A_ANSWER: [u8; 4] = [93, 184, 216, 34];

/// A DNS response to an AAAA query for example.com with three answers: two AAAA records
/// ([`AAAA_ANSWERS`], TTL 60 and 61) and one A record ([`A_ANSWER`], TTL 62).
pub fn dns_aaaa_frame() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x4321u16.to_be_bytes());
    p.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA
    p.extend_from_slice(&[0, 1, 0, 3, 0, 0, 0, 0]); // qd=1 an=3
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0, 28, 0, 1]); // QTYPE AAAA, QCLASS IN
    for (ttl, address) in (60u32..).zip(AAAA_ANSWERS) {
        p.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to offset 12
        p.extend_from_slice(&[0, 28, 0, 1]); // TYPE AAAA, CLASS IN
        p.extend_from_slice(&ttl.to_be_bytes());
        p.extend_from_slice(&[0, 16]);
        p.extend_from_slice(&address);
    }
    p.extend_from_slice(&[0xC0, 0x0C]);
    p.extend_from_slice(&[0, 1, 0, 1]); // TYPE A, CLASS IN
    p.extend_from_slice(&62u32.to_be_bytes());
    p.extend_from_slice(&[0, 4]);
    p.extend_from_slice(&A_ANSWER);
    eth(
        MAC_A,
        MAC_B,
        ETH_IP4,
        &ipv4([8, 8, 8, 8], [10, 0, 0, 1], 17, 7, &udp(53, 40000, &p)),
    )
}

/// The DNS query of the corpus (an A query for example.com), in an Ethernet frame.
pub fn dns_query_frame() -> Vec<u8> {
    eth(
        MAC_B,
        MAC_A,
        ETH_IP4,
        &ipv4(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            17,
            6,
            &udp(40000, 53, &dns_query()),
        ),
    )
}

/// The second of the timestamp of the first frame of every capture written here:
/// 2023-11-14 22:13:20 UTC.
pub const FIRST_SECOND: u32 = 1_700_000_000;

/// A legacy pcap capture (little-endian, microseconds, Ethernet) of `frames`. Frame `i`
/// (counted from 0) has the timestamp [`FIRST_SECOND`]` + i` seconds and `i` milliseconds, as
/// in the corpus captures.
pub fn legacy(frames: Vec<Vec<u8>>) -> Vec<u8> {
    to_capture(frames, LINKTYPE_ETHERNET)
}

/// The nanoseconds within the second of frame `i` of [`legacy_nanos`] and [`pcapng`]: no two
/// frames of a capture agree, and nearly all have digits below the microsecond.
pub fn nanos_of(i: usize) -> u32 {
    (123_456_789 + 1_001 * i as u32) % 1_000_000_000
}

/// A legacy pcap capture with nanosecond timestamps (little-endian, Ethernet) of `frames`.
/// Frame `i` has the timestamp [`FIRST_SECOND`]` + i` seconds and [`nanos_of`]`(i)` nanoseconds.
pub fn legacy_nanos(frames: Vec<Vec<u8>>) -> Vec<u8> {
    let packets: Vec<GenPacket> = frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| GenPacket {
            ts_sec: FIRST_SECOND + i as u32,
            ts_frac: nanos_of(i),
            origlen: data.len() as u32,
            data,
        })
        .collect();
    legacy_pcap(LegacyVariant::LeNano, LINKTYPE_ETHERNET, 65535, &packets).bytes
}

/// A legacy pcap capture with nanosecond timestamps of `frames`, with frame `i` (counted from
/// 0) at `at(i)`: seconds since the epoch and nanoseconds within the second. The timestamps
/// need not ascend.
pub fn legacy_nanos_at(frames: Vec<Vec<u8>>, at: impl Fn(usize) -> (u32, u32)) -> Vec<u8> {
    let packets: Vec<GenPacket> = frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            let (ts_sec, ts_frac) = at(i);
            GenPacket {
                ts_sec,
                ts_frac,
                origlen: data.len() as u32,
                data,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeNano, LINKTYPE_ETHERNET, 65535, &packets).bytes
}

/// A pcapng capture of `frames` whose interface has the time offset `offset` seconds: frame
/// `i` has the timestamp `offset + i` seconds and [`nanos_of`]`(i)` nanoseconds, which is
/// before 1970 for a negative offset.
pub fn pcapng_from(frames: Vec<Vec<u8>>, offset: i64) -> Vec<u8> {
    let packets = frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| PcapngPacket {
            interface_id: 0,
            ts_sec: i as u64,
            ts_frac_units: u64::from(nanos_of(i)),
            origlen: data.len() as u32,
            data,
        })
        .collect();
    pcapsql_testgen::pcapng(&[PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: LINKTYPE_ETHERNET,
            tsresol: 9,
            snaplen: 65535,
            if_tsoffset: offset,
        }],
        packets,
    }])
    .bytes
}

/// A pcapng capture of `frames`: one section, one Ethernet interface with nanosecond
/// resolution, an Enhanced Packet Block per frame, with the timestamps of [`legacy_nanos`].
pub fn pcapng(frames: Vec<Vec<u8>>) -> Vec<u8> {
    let packets = frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| PcapngPacket {
            interface_id: 0,
            ts_sec: u64::from(FIRST_SECOND) + i as u64,
            ts_frac_units: u64::from(nanos_of(i)),
            origlen: data.len() as u32,
            data,
        })
        .collect();
    pcapsql_testgen::pcapng(&[PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: LINKTYPE_ETHERNET,
            tsresol: 9,
            snaplen: 65535,
            if_tsoffset: 0,
        }],
        packets,
    }])
    .bytes
}
