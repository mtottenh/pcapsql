//! Partition-equivalence property tests for the source/reader layer.
//!
//! Centerpiece property: for any generated capture C (across formats,
//! endiannesses, resolutions, interface configurations and size distributions)
//! and any partition count N, parsing C at N partitions yields exactly the same
//! rows in the same order as parsing C at 1 partition — and both equal the
//! generator's ground truth (which validates timestamp/`if_tsresol` decoding too).

use std::path::{Path, PathBuf};

use pcapsql_core::io::{
    FilePacketSource, MmapPacketSource, PacketReader, PacketSource, SeekablePacketSource,
};
use pcapsql_testgen::{
    generate, jumbo_straddle_capture, legacy_pcap, oversized_frame_capture, pcapng,
    pcapng_with_byte_order, truncated_capture, CaptureSpec, ExpectedFrame, Format, GenPacket,
    GeneratedCapture, LegacyVariant, PcapngInterface, PcapngPacket, PcapngSection,
};
use proptest::prelude::*;
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

fn read_sequential_mmap(path: &Path, stride: u64) -> Vec<Frame> {
    let source = MmapPacketSource::open(path)
        .expect("open mmap")
        .with_index_stride(stride);
    let mut r = source.sequential_reader().expect("sequential reader");
    drain(&mut r)
}

fn read_partitioned_mmap(path: &Path, stride: u64, n: usize) -> Vec<Frame> {
    let source = MmapPacketSource::open(path)
        .expect("open mmap")
        .with_index_stride(stride);
    let ranges = source.partitions(n).expect("partitions");
    let mut frames = Vec::new();
    for range in &ranges {
        let mut r = source.reader_at(range).expect("reader_at");
        frames.extend(drain(&mut r));
    }
    frames
}

fn read_partitioned_file(path: &Path, stride: u64, n: usize) -> Vec<Frame> {
    let source = FilePacketSource::open(path)
        .expect("open file")
        .with_index_stride(stride);
    let ranges = source.partitions(n).expect("partitions");
    let mut frames = Vec::new();
    for range in &ranges {
        let mut r = source.reader_at(range).expect("reader_at");
        frames.extend(drain(&mut r));
    }
    frames
}

/// Core assertion: sequential == ground truth, and every partition count
/// reproduces the same frames in the same order (mmap and file backends).
fn assert_equivalent(gc: &GeneratedCapture, stride: u64) {
    let dir = TempDir::new().expect("tempdir");
    let path = write_capture(dir.path(), "cap", &gc.bytes);
    let expected = expected_frames(gc);

    let seq = read_sequential_mmap(&path, stride);
    assert_eq!(
        seq, expected,
        "sequential mmap read must equal ground truth"
    );

    for n in [1usize, 2, 3, 5, 8] {
        let mm = read_partitioned_mmap(&path, stride, n);
        assert_eq!(
            mm, expected,
            "mmap partitioned (n={n}) must equal ground truth"
        );
        let fi = read_partitioned_file(&path, stride, n);
        assert_eq!(
            fi, expected,
            "file partitioned (n={n}) must equal ground truth"
        );
    }
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
        assert_equivalent(&gc, 3);
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
    assert_equivalent(&gc, 4);
}

#[test]
fn pcapng_multi_interface_differing_tsresol() {
    // Interface 0 microsecond, interface 1 nanosecond. Both must decode to the
    // correct nanosecond wall-clock in every partition.
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
    assert_equivalent(&gc, 3);
}

#[test]
fn pcapng_binary_tsresol_power_of_two() {
    // `if_tsresol` with bit 7 set is a power-of-two resolution (here 2^-10 s per
    // tick, as some hardware timestampers write). pcap_parser's own decoder
    // rejects every binary exponent, so the reader must decode it itself; a
    // reader that silently fell back to microseconds would be off by ~1000x.
    // Partitions synthesize an IDB from the checkpoint's raw `if_tsresol`, so
    // the binary byte must survive that round trip too.
    let probe = pcapng(&[PcapngSection {
        interfaces: vec![PcapngInterface {
            link_type: 1,
            tsresol: 0x8A, // 2^10 = 1024 units per second
            snaplen: 65535,
        }],
        packets: vec![PcapngPacket {
            interface_id: 0,
            ts_sec: 10,
            ts_frac_units: 512,
            data: vec![0; 20],
            origlen: 20,
        }],
    }]);
    // Sanity-check the ground truth itself: tick 512 at 1024/s is exactly 0.5 s.
    assert_eq!(probe.expected[0].timestamp_ns, 10_500_000_000);
    assert_equivalent(&probe, 1);

    let gc = pcapng(&[PcapngSection {
        interfaces: vec![
            PcapngInterface {
                link_type: 1,
                tsresol: 0x8A,
                snaplen: 65535,
            },
            PcapngInterface {
                link_type: 1,
                tsresol: 6,
                snaplen: 65535,
            },
        ],
        packets: (0..24)
            .map(|i| PcapngPacket {
                interface_id: (i % 2) as u32,
                ts_sec: 1_700_000_000 + i,
                ts_frac_units: if i % 2 == 0 {
                    (i * 37) % 1024
                } else {
                    (i * 11) % 1_000_000
                },
                data: vec![(i % 256) as u8; 40],
                origlen: 40,
            })
            .collect(),
    }]);
    assert_equivalent(&gc, 3);
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
    assert_equivalent(&gc, 4);
}

/// True if the second Interface Description Block appears *after* the first
/// Enhanced Packet Block in `bytes` — i.e. an interface is declared mid-stream.
fn second_idb_after_first_epb(bytes: &[u8]) -> bool {
    const NG_IDB_TYPE: u32 = 0x0000_0001;
    const NG_EPB_TYPE: u32 = 0x0000_0006;
    let mut off = 0usize;
    let mut idb_seen = 0usize;
    let mut first_epb: Option<usize> = None;
    let mut second_idb: Option<usize> = None;
    while off + 8 <= bytes.len() {
        let bt = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let len = u32::from_le_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]) as usize;
        if len < 12 || off + len > bytes.len() {
            break;
        }
        if bt == NG_IDB_TYPE {
            idb_seen += 1;
            if idb_seen == 2 {
                second_idb = Some(off);
            }
        } else if bt == NG_EPB_TYPE && first_epb.is_none() {
            first_epb = Some(off);
        }
        off += len;
    }
    matches!((first_epb, second_idb), (Some(e), Some(i)) if e < i)
}

#[test]
fn pcapng_big_endian_sections() {
    // Big-endian PCAPNG is valid per spec. A mid-file partition starts with a
    // synthesized SHB + IDBs; those must be written in the section's byte
    // order or every block length that follows is misread.
    let gc = pcapng_with_byte_order(
        &[PcapngSection {
            interfaces: vec![
                PcapngInterface {
                    link_type: 1,
                    tsresol: 6,
                    snaplen: 65535,
                },
                PcapngInterface {
                    link_type: 113,
                    tsresol: 9,
                    snaplen: 262144,
                },
            ],
            packets: (0..40)
                .map(|i| PcapngPacket {
                    interface_id: (i % 2) as u32,
                    ts_sec: 1_700_000_000 + i,
                    ts_frac_units: if i % 2 == 0 {
                        (i * 11) % 1_000_000
                    } else {
                        (i * 13) % 1_000_000_000
                    },
                    data: vec![(i % 256) as u8; 30 + (i as usize % 7)],
                    origlen: 30 + (i as u32 % 7),
                })
                .collect(),
        }],
        true,
    );
    // On-disk byte-order magic is big-endian.
    assert_eq!(&gc.bytes[8..12], &[0x1A, 0x2B, 0x3C, 0x4D]);
    assert_equivalent(&gc, 3);

    // Generator path: multi-section, midstream IDB, big-endian throughout.
    let spec = CaptureSpec {
        format: Format::PcapngBe,
        seed: 7,
        packet_count: 36,
        min_size: 16,
        max_size: 90,
        link_type: 1,
        interfaces: vec![6, 3],
        sections: 2,
        add_interface_midstream: true,
    };
    assert_equivalent(&generate(&spec), 2);
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
    // The capture must use a *literal* mid-stream IDB: at least one packet block
    // precedes the second interface description block on disk. Partitions
    // therefore start before the second interface is declared, exercising the
    // reader's "pick up the IDB from the byte stream" path and the index's
    // per-checkpoint interface table.
    assert!(
        second_idb_after_first_epb(&gc.bytes),
        "midstream capture must place an EPB before the second IDB on disk"
    );
    assert_equivalent(&gc, 3);
}

#[test]
fn oversized_frame_exceeds_read_buffer() {
    // A single frame larger than the 256 KiB read buffer exercises the grow path.
    let gc = oversized_frame_capture(300_000);
    assert_equivalent(&gc, 2);
}

#[test]
fn jumbo_frame_straddles_partition_seam() {
    let gc = jumbo_straddle_capture(7, 280_000, 30);
    assert_equivalent(&gc, 2);
}

#[test]
fn truncated_capture_reads_complete_prefix() {
    // Declared length exceeds bytes present: reader must stop gracefully after
    // the complete frames, matching the ground-truth prefix.
    let gc = truncated_capture(123);
    let dir = TempDir::new().unwrap();
    let path = write_capture(dir.path(), "trunc.pcap", &gc.bytes);
    let expected = expected_frames(&gc);
    let seq = read_sequential_mmap(&path, 4);
    assert_eq!(seq, expected, "truncated capture: complete prefix only");
}

/// `reader_at(&PacketRange::whole())` on an uncompressed seekable source reads
/// from the file's own header: the same frames as the sequential reader, for
/// both backends, and an `end` on a byte-0 range is honoured.
#[test]
fn reader_at_whole_range_equals_sequential() {
    use pcapsql_core::io::{PacketPosition, PacketRange};
    for format in [Format::LegacyLeMicro, Format::Pcapng] {
        let gc = generate(&CaptureSpec {
            format,
            packet_count: 12,
            ..CaptureSpec::default()
        });
        let dir = TempDir::new().unwrap();
        let path = write_capture(dir.path(), "whole", &gc.bytes);
        let expected = expected_frames(&gc);

        let mmap = MmapPacketSource::open(&path).unwrap().with_index_stride(4);
        let mut r = mmap.reader_at(&PacketRange::whole()).unwrap();
        assert_eq!(drain(&mut r), expected, "mmap whole range ({format:?})");

        let file = FilePacketSource::open(&path).unwrap().with_index_stride(4);
        let mut r = file.reader_at(&PacketRange::whole()).unwrap();
        assert_eq!(drain(&mut r), expected, "file whole range ({format:?})");

        // A byte-0 range with an end: frames 1..5 only.
        let head = PacketRange {
            start: PacketPosition::START,
            end: Some(PacketPosition {
                byte_offset: 0,
                frame_number: 6,
            }),
        };
        let mut r = mmap.reader_at(&head).unwrap();
        assert_eq!(
            drain(&mut r),
            expected[..5].to_vec(),
            "mmap capped ({format:?})"
        );
        let mut r = file.reader_at(&head).unwrap();
        assert_eq!(
            drain(&mut r),
            expected[..5].to_vec(),
            "file capped ({format:?})"
        );
    }
}

/// Small captures are indexed in memory but no `.idx` sidecar is written
/// next to them; a capture past the threshold gets one.
#[test]
fn sidecar_is_only_persisted_for_large_captures() {
    use pcapsql_core::io::{sidecar_path, SIDECAR_MIN_SOURCE_BYTES};
    let dir = TempDir::new().unwrap();

    let small = generate(&CaptureSpec {
        packet_count: 20,
        ..CaptureSpec::default()
    });
    let path = write_capture(dir.path(), "small.pcap", &small.bytes);
    let source = MmapPacketSource::open(&path).unwrap().with_index_stride(4);
    assert_eq!(source.frame_count(), Some(20));
    assert!(source.partitions(3).unwrap().len() > 1);
    assert!(
        !sidecar_path(&path).exists(),
        "no sidecar for a small capture"
    );

    let large = generate(&CaptureSpec {
        packet_count: 4_200,
        min_size: 256,
        max_size: 256,
        ..CaptureSpec::default()
    });
    assert!(large.bytes.len() as u64 >= SIDECAR_MIN_SOURCE_BYTES);
    let path = write_capture(dir.path(), "large.pcap", &large.bytes);
    let source = FilePacketSource::open(&path).unwrap().with_index_stride(64);
    assert_eq!(source.frame_count(), Some(4_200));
    assert!(sidecar_path(&path).exists(), "sidecar for a large capture");
}

// ----------------------------------------------------------------------------
// Property: partition equivalence across the generated edge-case space
// ----------------------------------------------------------------------------

fn format_strategy() -> impl Strategy<Value = Format> {
    prop_oneof![
        Just(Format::LegacyLeMicro),
        Just(Format::LegacyBeMicro),
        Just(Format::LegacyLeNano),
        Just(Format::LegacyBeNano),
        Just(Format::Pcapng),
        Just(Format::PcapngBe),
    ]
}

prop_compose! {
    fn capture_spec_strategy()(
        format in format_strategy(),
        seed in any::<u64>(),
        packet_count in 1usize..40,
        min_size in 14usize..30,
        extra in 0usize..120,
        // Decimal exponents plus one binary (power-of-two) exponent, 2^-10 s.
        tsresols in proptest::collection::vec(prop_oneof![Just(3u8), Just(6u8), Just(9u8), Just(0x8Au8)], 1..3),
        sections in 1usize..3,
        midstream in any::<bool>(),
    ) -> CaptureSpec {
        CaptureSpec {
            format,
            seed,
            packet_count,
            min_size,
            max_size: min_size + extra,
            link_type: 1,
            interfaces: tsresols,
            sections,
            add_interface_midstream: midstream,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn prop_partition_equivalence(spec in capture_spec_strategy()) {
        let gc = generate(&spec);
        // Fine stride so even small captures split into several partitions.
        assert_equivalent(&gc, 2);
    }

    /// No frame dropped or duplicated across a seam: the multiset and the
    /// ordered set of frame numbers are exactly 1..=packet_count.
    #[test]
    fn prop_no_dropped_or_duplicated_frames(spec in capture_spec_strategy()) {
        let gc = generate(&spec);
        let dir = TempDir::new().unwrap();
        let path = write_capture(dir.path(), "cap", &gc.bytes);
        let total = gc.expected.len() as u64;
        for n in [1usize, 4, 7] {
            let frames = read_partitioned_mmap(&path, 2, n);
            let nums: Vec<u64> = frames.iter().map(|f| f.frame_number).collect();
            let want: Vec<u64> = (1..=total).collect();
            prop_assert_eq!(nums, want);
        }
    }
}
