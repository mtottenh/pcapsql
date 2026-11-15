//! The registry's dispatch tables choose the parsers a scan of every
//! parser's `can_parse` chooses, over the fuzz corpus.
//!
//! `parse_packet` looks a layer's parser up in tables built from the
//! parsers' `Dispatch` rules; `common/full_scan.rs` walks a packet asking
//! every parser instead. Both must give every packet the same layers, in the
//! same tunnel context. The packets are
//!
//! - every capture of the reader's fuzz corpus (`fuzz/corpus/fuzz_pcap_reader`
//!   and the compressed ones of `fuzz_compression`): real traffic, tunnels
//!   and netlink included;
//! - every other corpus file, the way the fuzz targets use it: as a frame of
//!   each link type (`fuzz_protocol_chain`), and as the payload behind each
//!   of the targets' frame headers (`fuzz/src/frames.rs`) and three more
//!   (DHCP, NTP, MPLS), which puts it in front of every transport and
//!   application parser.
//!
//! Together they make every parser of the registry produce a layer.
//!
//! Debug builds also check every single choice inside `find_next`; this test
//! holds in release builds too and says which packet disagreed.

#[path = "common/full_scan.rs"]
mod full_scan;

#[allow(dead_code)]
mod frames {
    include!("../../fuzz/src/frames.rs");
}

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use full_scan::{assert_same_chain, assert_same_chains};
use pcapsql_core::io::{FilePacketReader, FilePacketSource, PacketReader, PacketSource};
use pcapsql_core::{default_registry, Protocol, ProtocolRegistry};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/corpus")
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files
}

/// The fuzz targets' frame headers: what a corpus file is appended to.
const HEADERS: &[(&str, &[u8])] = &[
    ("dns", frames::DNS_FRAME),
    ("icmp", frames::ICMP_FRAME),
    ("icmpv6", frames::ICMPV6_FRAME),
    ("tls", frames::TLS_FRAME),
    ("bgp", frames::BGP_FRAME),
    ("gtp-u", frames::GTP_U_FRAME),
    ("gtp-c", frames::GTP_C_FRAME),
    ("ospf", frames::OSPF_FRAME),
    ("gre", frames::GRE_FRAME),
    ("vxlan", frames::VXLAN_FRAME),
    ("quic", frames::QUIC_FRAME),
    ("ssh", frames::SSH_FRAME),
    ("tcp-options", frames::TCP_OPTIONS_FRAME),
    ("http", frames::HTTP_FRAME),
    ("http2", frames::HTTP2_FRAME),
    ("ipv4-options", frames::IPV4_OPTIONS_FRAME),
    ("ipv6-ext", frames::IPV6_EXT_FRAME),
    ("dhcp", DHCP_FRAME),
    ("ntp", NTP_FRAME),
    ("mpls", MPLS_FRAME),
];

/// Ethernet, IPv4 and UDP from port 68 to port 67.
const DHCP_FRAME: &[u8] = &udp_header(68, 67);
/// Ethernet, IPv4 and UDP from port 123 to port 123.
const NTP_FRAME: &[u8] = &udp_header(123, 123);
/// Ethernet and one MPLS label, the bottom of its stack.
const MPLS_FRAME: &[u8] = &[
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x88, 0x47, 0x00, 0x01, 0x01, 0x40,
];

/// The DNS header of the fuzz targets with other ports.
const fn udp_header(src: u16, dst: u16) -> [u8; 42] {
    let mut header = [0u8; 42];
    let mut i = 0;
    while i < 42 {
        header[i] = frames::DNS_FRAME[i];
        i += 1;
    }
    [header[34], header[35]] = src.to_be_bytes();
    [header[36], header[37]] = dst.to_be_bytes();
    header
}

/// `payload` behind `header`, with the lengths of the IPv4, IPv6 and UDP
/// headers that `header` has made to cover it, as the fuzz targets do.
fn wrap(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = header.to_vec();
    frame.extend_from_slice(payload);
    let ethertype = u16::from_be_bytes([header[12], header[13]]);
    let be = |n: usize| (n.min(usize::from(u16::MAX)) as u16).to_be_bytes();
    if ethertype == 0x0800 && header.len() >= 34 {
        let total = be(frame.len() - 14);
        frame[16..18].copy_from_slice(&total);
        if header[23] == 17 && header.len() >= 42 {
            let length = be(frame.len() - 34);
            frame[38..40].copy_from_slice(&length);
        }
    } else if ethertype == 0x86dd && header.len() >= 54 {
        let length = be(frame.len() - 54);
        frame[18..20].copy_from_slice(&length);
    }
    frame
}

/// The parsers of the layers a walk finds, added to `seen`.
fn note(
    seen: &mut BTreeSet<&'static str>,
    registry: &ProtocolRegistry,
    link_type: u16,
    data: &[u8],
) {
    seen.extend(
        full_scan::full_scan_chain(registry, link_type, data)
            .into_iter()
            .map(|(parser, ..)| parser),
    );
}

#[test]
fn dispatch_matches_a_full_scan_over_the_fuzz_corpus() {
    let registry = default_registry();
    let corpus = corpus();
    let mut seen = BTreeSet::new();

    // The captures.
    let mut captures = files(&corpus.join("fuzz_pcap_reader"));
    captures.extend(files(&corpus.join("fuzz_compression")));
    assert!(captures.len() >= 27, "{} captures", captures.len());
    let (mut packets, mut layers) = (0, 0);
    for path in &captures {
        let name = path.file_name().expect("a file").to_string_lossy();
        let open = || -> FilePacketReader {
            FilePacketSource::open(path)
                .and_then(|source| source.sequential_reader())
                .unwrap_or_else(|error| panic!("{name}: {error}"))
        };
        let (p, l) = assert_same_chains(&registry, open(), &name);
        assert!(p > 0, "{name} has no packets");
        packets += p;
        layers += l;
        let mut reader = open();
        while let Ok(1..) = reader.process_packets(1024, |packet| {
            note(&mut seen, &registry, packet.link_type, packet.data);
            Ok(())
        }) {}
    }
    println!(
        "{} captures: {packets} packets, {layers} layers",
        captures.len()
    );
    assert!(packets > 2_000 && layers > 2 * packets);

    // The inputs of the parser targets.
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .expect("the fuzz corpus")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert!(dirs.len() >= 14, "{} corpus directories", dirs.len());
    let (mut inputs, mut packets, mut layers) = (0, 0, 0);
    for dir in &dirs {
        for path in files(dir) {
            let data = std::fs::read(&path).expect("a corpus file");
            let name = path
                .strip_prefix(&corpus)
                .expect("under the corpus")
                .display()
                .to_string();
            inputs += 1;
            // As a frame of its own, of each kind of link.
            for link_type in [1u16, 101, 113, 253, 276] {
                layers += assert_same_chain(&registry, link_type, &data, &name);
                packets += 1;
                note(&mut seen, &registry, link_type, &data);
            }
            // As the payload behind each header.
            for (header_name, header) in HEADERS {
                let frame = wrap(header, &data);
                let what = format!("{name} behind the {header_name} header");
                layers += assert_same_chain(&registry, 1, &frame, &what);
                packets += 1;
                note(&mut seen, &registry, 1, &frame);
            }
        }
    }
    println!("{inputs} inputs: {packets} packets, {layers} layers");
    assert!(inputs > 2_000 && layers > 2 * packets);

    // The corpus reaches the parsers: every one of the registry gave a layer.
    let all: BTreeSet<&str> = registry.all_parsers().map(|p| p.name()).collect();
    assert_eq!(seen, all);
}
