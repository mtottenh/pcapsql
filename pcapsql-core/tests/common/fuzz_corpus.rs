//! The fuzz corpus (`fuzz/corpus`) as packets, the way the fuzz targets
//! use its files:
//!
//! - the captures of the reader's corpus (`fuzz_pcap_reader`, and the
//!   compressed ones of `fuzz_compression`): real traffic, tunnels and
//!   netlink included;
//! - every other file as a frame of its own, of each link type
//!   (`fuzz_protocol_chain`), and as the payload behind each of the targets'
//!   frame headers (`fuzz/src/frames.rs`) and three more (DHCP, NTP, MPLS),
//!   which puts it in front of every transport and application parser.
//!
//! A file of its own, without the rest of `common`, for the tests that walk
//! packets parser by parser.

mod frames {
    include!("../../../fuzz/src/frames.rs");
}

use std::path::{Path, PathBuf};

/// The corpus directory.
pub fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/corpus")
}

/// The files of `dir`, in name order.
pub fn files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files
}

/// The captures of the reader's corpus.
pub fn captures() -> Vec<PathBuf> {
    let corpus = corpus();
    let mut captures = files(&corpus.join("fuzz_pcap_reader"));
    captures.extend(files(&corpus.join("fuzz_compression")));
    captures
}

/// Every corpus file, by its path under the corpus, with its bytes: the
/// inputs of the parser targets (the captures among them too, which the
/// protocol chain target is also given).
pub fn inputs() -> Vec<(String, Vec<u8>)> {
    let corpus = corpus();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .expect("the fuzz corpus")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert!(dirs.len() >= 14, "{} corpus directories", dirs.len());
    let mut inputs = Vec::new();
    for dir in &dirs {
        for path in files(dir) {
            let data = std::fs::read(&path).expect("a corpus file");
            let name = path
                .strip_prefix(&corpus)
                .expect("under the corpus")
                .display()
                .to_string();
            inputs.push((name, data));
        }
    }
    inputs
}

/// The link types a corpus file is a frame of.
pub const LINK_TYPES: [u16; 5] = [1, 101, 113, 253, 276];

/// The fuzz targets' frame headers: what a corpus file is appended to.
pub const HEADERS: &[(&str, &[u8])] = &[
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
pub fn wrap(header: &[u8], payload: &[u8]) -> Vec<u8> {
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
