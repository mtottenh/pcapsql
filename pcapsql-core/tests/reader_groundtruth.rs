//! Sequential ground-truth tests for the PCAP/PCAPNG reader.
//!
//! Every capture produced by `pcapsql-testgen` carries its expected frames
//! (numbers, nanosecond timestamps, lengths, link types, payload bytes). These
//! tests assert that a sequential read through the source layer reproduces that
//! ground truth exactly — across all four legacy magic variants, PCAPNG with
//! single/multiple interfaces (differing `if_tsresol`), multiple sections,
//! interfaces added midstream, oversized frames (larger than the read buffer),
//! and truncated captures.

use std::path::{Path, PathBuf};

use pcapsql_core::io::{FilePacketSource, MmapPacketSource, PacketReader, PacketSource};
use pcapsql_testgen::{
    generate, jumbo_straddle_capture, legacy_pcap, oversized_frame_capture, pcapng,
    truncated_capture, CaptureSpec, ExpectedFrame, Format, GenPacket, GeneratedCapture,
    LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};
use tempfile::TempDir;

/// A decoded frame in comparable form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    frame_number: u64,
    timestamp_ns: i64,
    caplen: u32,
    origlen: u32,
    link_type: u32,
    data: Vec<u8>,
}

fn expected_frames(gc: &GeneratedCapture) -> Vec<Frame> {
    gc.expected
        .iter()
        .map(|e: &ExpectedFrame| Frame {
            frame_number: e.frame_number,
            timestamp_ns: e.timestamp_ns,
            caplen: e.caplen,
            origlen: e.origlen,
            link_type: e.link_type,
            data: e.data.clone(),
        })
        .collect()
}

fn drain<R: PacketReader>(reader: &mut R) -> Vec<Frame> {
    let mut out = Vec::new();
    loop {
        let mut batch = Vec::new();
        let n = reader
            .process_packets(64, |p| {
                batch.push(Frame {
                    frame_number: p.frame_number,
                    timestamp_ns: p.timestamp_ns,
                    caplen: p.captured_len,
                    origlen: p.original_len,
                    link_type: p.link_type as u32,
                    data: p.data.to_vec(),
                });
                Ok(())
            })
            .expect("process_packets");
        out.extend(batch);
        if n == 0 {
            break;
        }
    }
    out
}

fn write_capture(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write capture");
    path
}

fn read_sequential_mmap(path: &Path) -> Vec<Frame> {
    let source = MmapPacketSource::open(path).expect("open mmap");
    let mut r = source.reader(None).expect("mmap reader");
    drain(&mut r)
}

fn read_sequential_file(path: &Path) -> Vec<Frame> {
    let source = FilePacketSource::open(path).expect("open file");
    let mut r = source.reader(None).expect("file reader");
    drain(&mut r)
}

/// Core assertion: a sequential read (mmap and file backends) equals the
/// generator's ground truth, frame for frame.
fn assert_equivalent(gc: &GeneratedCapture) {
    let dir = TempDir::new().expect("tempdir");
    let path = write_capture(dir.path(), "cap", &gc.bytes);
    let expected = expected_frames(gc);

    let mm = read_sequential_mmap(&path);
    assert_eq!(mm, expected, "sequential mmap read must equal ground truth");

    let fi = read_sequential_file(&path);
    assert_eq!(fi, expected, "sequential file read must equal ground truth");
}

// ----------------------------------------------------------------------------
// Explicit edge-case tests
// ----------------------------------------------------------------------------

#[test]
fn legacy_all_four_variants() {
    for variant in [
        LegacyVariant::LeMicro,
        LegacyVariant::BeMicro,
        LegacyVariant::LeNano,
        LegacyVariant::BeNano,
    ] {
        let packets: Vec<GenPacket> = (0..20)
            .map(|i| GenPacket {
                ts_sec: 1_700_000_000 + i,
                ts_frac: (i * 12345) % 1_000_000_000,
                data: vec![(i % 256) as u8; 14 + (i as usize % 50)],
                origlen: 14 + (i % 50),
            })
            .collect();
        let gc = legacy_pcap(variant, 1, 65535, &packets);
        assert_equivalent(&gc);
    }
}

#[test]
fn pcapng_single_interface() {
    let gc = pcapng(&[PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: 1,
            tsresol: 6,
            snaplen: 65535,
        }],
        packets: (0..25)
            .map(|i| PcapngPacket {
                interface_id: 0,
                ts_sec: 1_700_000_000 + i,
                ts_frac_units: (i * 7) % 1_000_000,
                data: vec![(i % 256) as u8; 20],
                origlen: 20,
            })
            .collect(),
    }]);
    assert_equivalent(&gc);
}

#[test]
fn pcapng_multi_interface_differing_tsresol() {
    // Interface 0 microsecond, interface 1 nanosecond. Both must decode to the
    // correct nanosecond wall-clock.
    let gc = pcapng(&[PcapngSection {
        interfaces: vec![
            PcapngInterface {
                link_type: 1,
                tsresol: 6,
                snaplen: 65535,
            },
            PcapngInterface {
                link_type: 1,
                tsresol: 9,
                snaplen: 262144,
            },
        ],
        packets: (0..40)
            .map(|i| PcapngPacket {
                interface_id: (i % 2) as u32,
                ts_sec: 1_700_000_000 + i,
                // ts_frac_units is in the interface's own units.
                ts_frac_units: if i % 2 == 0 {
                    (i * 11) % 1_000_000
                } else {
                    (i * 13) % 1_000_000_000
                },
                data: vec![(i % 256) as u8; 30],
                origlen: 30,
            })
            .collect(),
    }]);
    assert_equivalent(&gc);
}

#[test]
fn pcapng_multi_section() {
    let mk_section = |tsresol: u8, base: u64| PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: 1,
            tsresol,
            snaplen: 65535,
        }],
        packets: (0..15)
            .map(|i| PcapngPacket {
                interface_id: 0,
                ts_sec: base + i,
                ts_frac_units: i % 1_000,
                data: vec![(i % 256) as u8; 18],
                origlen: 18,
            })
            .collect(),
    };
    let gc = pcapng(&[
        mk_section(6, 1_700_000_000),
        mk_section(9, 1_700_001_000),
        mk_section(3, 1_700_002_000),
    ]);
    assert_equivalent(&gc);
}

#[test]
fn pcapng_interface_added_midstream() {
    let spec = CaptureSpec {
        format: Format::Pcapng,
        seed: 99,
        packet_count: 40,
        min_size: 16,
        max_size: 80,
        link_type: 1,
        interfaces: vec![6],
        sections: 1,
        add_interface_midstream: true,
    };
    let gc = generate(&spec);
    assert_equivalent(&gc);
}

#[test]
fn oversized_frame_exceeds_read_buffer() {
    // A single frame larger than the 256 KiB read buffer exercises the grow path.
    let gc = oversized_frame_capture(300_000);
    assert_equivalent(&gc);
}

#[test]
fn jumbo_frames_among_normal_frames() {
    let gc = jumbo_straddle_capture(7, 280_000, 30);
    assert_equivalent(&gc);
}

#[test]
fn truncated_capture_reads_complete_prefix() {
    // Declared length exceeds bytes present: the reader must stop gracefully
    // after the complete frames, matching the ground-truth prefix.
    let gc = truncated_capture(123);
    let dir = TempDir::new().unwrap();
    let path = write_capture(dir.path(), "trunc.pcap", &gc.bytes);
    let expected = expected_frames(&gc);
    assert_eq!(read_sequential_mmap(&path), expected);
    assert_eq!(read_sequential_file(&path), expected);
}

/// Deterministic sweep of the generator's edge-case space (seeds × formats ×
/// interface configurations), all checked against ground truth.
#[test]
fn generated_capture_sweep() {
    let formats = [
        Format::LegacyLeMicro,
        Format::LegacyBeMicro,
        Format::LegacyLeNano,
        Format::LegacyBeNano,
        Format::Pcapng,
    ];
    for seed in [1u64, 42, 0xDEAD_BEEF] {
        for format in formats {
            for (interfaces, sections, midstream) in [
                (vec![6u8], 1usize, false),
                (vec![6, 9], 1, false),
                (vec![9], 2, true),
            ] {
                let spec = CaptureSpec {
                    format,
                    seed,
                    packet_count: 30,
                    min_size: 14,
                    max_size: 120,
                    link_type: 1,
                    interfaces,
                    sections,
                    add_interface_midstream: midstream,
                };
                assert_equivalent(&generate(&spec));
            }
        }
    }
}
