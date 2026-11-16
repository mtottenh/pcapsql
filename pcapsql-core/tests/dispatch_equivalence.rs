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

#[path = "common/fuzz_corpus.rs"]
mod fuzz_corpus;

use std::collections::BTreeSet;

use full_scan::{assert_same_chain, assert_same_chains};
use fuzz_corpus::{captures, inputs, wrap, HEADERS, LINK_TYPES};
use pcapsql_core::io::{FilePacketReader, FilePacketSource, PacketReader, PacketSource};
use pcapsql_core::{default_registry, Protocol, ProtocolRegistry};

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
    let mut seen = BTreeSet::new();

    // The captures.
    let captures = captures();
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
    let (mut inputs_seen, mut packets, mut layers) = (0, 0, 0);
    for (name, data) in inputs() {
        inputs_seen += 1;
        // As a frame of its own, of each kind of link.
        for link_type in LINK_TYPES {
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
    println!("{inputs_seen} inputs: {packets} packets, {layers} layers");
    assert!(inputs_seen > 2_000 && layers > 2 * packets);

    // The corpus reaches the parsers: every one of the registry gave a layer.
    let all: BTreeSet<&str> = registry.all_parsers().map(|p| p.name()).collect();
    assert_eq!(seen, all);
}
