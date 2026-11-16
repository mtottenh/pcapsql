//! Boundary index: the spine of random-access / parallel parsing.
//!
//! Random access to packets requires knowing where packet records start. No
//! backend knows this for free, so we build a sparse index of *checkpoints* by a
//! single header-only sequential scan, and persist it as a sidecar next to the
//! capture. Each checkpoint records:
//!
//! - the frame number and byte offset of a record boundary,
//! - for PCAPNG, the full interface table in effect at that point (link type and
//!   `if_tsresol` per interface) so a partition starting there can interpret its
//!   packets, and
//! - optional min/max timestamps over the window it begins (a zone map for
//!   partition pruning).
//!
//! Partitions are aligned to checkpoints, so a partition's start lands exactly on
//! a record boundary and its interface state is known precisely — no forward walk
//! is needed. The checkpoint stride therefore controls partition granularity; it
//! is configurable (small in tests, large in production).
//!
//! ## Sidecar format
//!
//! The sidecar is an explicit little-endian binary file: an 8-byte magic that
//! carries the format version, the index body, and a trailing 64-bit FNV-1a
//! checksum of everything before it. A sidecar with another version, a bad
//! checksum or a structurally invalid body (see `BoundaryIndex::validate`) is
//! rejected on read and the index is rebuilt — never misread. Version history:
//! v2 added the section byte order to PCAPNG checkpoints; v3 added the
//! checksum, `if_tsoffset` per interface and the object e-tag guard.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Error, PcapError};
use crate::io::pcap_stream::InterfaceState;
use crate::io::{PacketPosition, PacketRange, PcapFormat};

mod build;
mod codec;
mod synth;

pub use build::{build_boundary_index, build_boundary_index_to};
pub use synth::{synth_legacy_header, synth_pcapng_header};

/// Default checkpoint stride: one checkpoint every 65536 frames.
pub const DEFAULT_CHECKPOINT_STRIDE: u64 = 65536;

/// Sources smaller than this are not worth a sidecar: their index is rebuilt
/// from a header-only scan in well under a millisecond, and a `.idx` next to
/// every tiny fixture or sample is clutter. The index is still built and used
/// in memory; only the persistence is skipped (`write_sidecar` callers check
/// [`BoundaryIndex::worth_persisting`]).
pub const SIDECAR_MIN_SOURCE_BYTES: u64 = 1024 * 1024;

/// Longest e-tag a sidecar stores; a longer one is written as absent (and
/// the source drops it the same way, so the guard still agrees).
pub(crate) const MAX_ETAG_BYTES: usize = 4096;

/// A sparse checkpoint into the capture.
#[derive(Clone, Debug, PartialEq)]
pub struct Checkpoint {
    /// Frame number of the first packet at/after this checkpoint (1-indexed).
    pub frame_number: u64,
    /// Byte offset (in the uncompressed stream) of that packet's record start.
    pub byte_offset: u64,
    /// PCAPNG interface table in effect here (None for legacy PCAP).
    pub interface_state: Option<InterfaceState>,
    /// Minimum timestamp (ns) over the window beginning at this checkpoint.
    pub min_ts: Option<i64>,
    /// Maximum timestamp (ns) over the window beginning at this checkpoint.
    pub max_ts: Option<i64>,
}

/// A persisted index of record boundaries for a single capture.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundaryIndex {
    /// Length in bytes of the source this index was built from (validity guard).
    pub source_len: u64,
    /// Modification time of the source, if known (validity guard).
    pub source_mtime: Option<SystemTime>,
    /// Hash of the header region (validity guard).
    pub header_hash: u64,
    /// Entity tag of the source object (cloud sources; validity guard). Object
    /// stores report `last_modified` at one-second granularity, so the e-tag
    /// is what tells two uploads within the same second apart.
    pub source_etag: Option<String>,

    /// Capture format.
    pub format: PcapFormat,
    /// Link type of the first interface / legacy header.
    pub link_type: u32,
    /// Snapshot length.
    pub snaplen: u32,
    /// Total number of packets in the capture.
    pub packet_count: u64,
    /// Checkpoint stride used when building (frames between checkpoints).
    pub stride: u64,
    /// Sparse checkpoints, ascending by frame number. Always includes frame 1.
    pub checkpoints: Vec<Checkpoint>,
}

impl BoundaryIndex {
    /// Compute up to `max` non-overlapping ranges covering the whole capture,
    /// aligned to checkpoints so every partition starts on a record boundary
    /// with known interface state.
    pub fn partition_ranges(&self, max: usize) -> Vec<PacketRange> {
        if self.checkpoints.is_empty() || self.packet_count == 0 {
            return vec![PacketRange::whole()];
        }
        let max = max.max(1);
        let n = self.checkpoints.len().min(max);
        // Pick n checkpoints spread evenly across the available checkpoints.
        let mut chosen: Vec<&Checkpoint> = Vec::with_capacity(n);
        for i in 0..n {
            let idx = i * self.checkpoints.len() / n;
            // Avoid duplicates if the spacing collapses.
            if chosen
                .last()
                .is_none_or(|c| c.frame_number != self.checkpoints[idx].frame_number)
            {
                chosen.push(&self.checkpoints[idx]);
            }
        }
        let mut ranges = Vec::with_capacity(chosen.len());
        for (i, cp) in chosen.iter().enumerate() {
            let start = PacketPosition {
                byte_offset: cp.byte_offset,
                frame_number: cp.frame_number,
            };
            let end = chosen.get(i + 1).map(|next| PacketPosition {
                byte_offset: next.byte_offset,
                frame_number: next.frame_number,
            });
            ranges.push(PacketRange { start, end });
        }
        ranges
    }

    /// The capture's `[earliest, latest]` packet timestamp (nanoseconds), from
    /// the per-checkpoint window bounds. `None` when no packet carried a
    /// timestamp.
    pub fn time_range_ns(&self) -> Option<(i64, i64)> {
        let min = self.checkpoints.iter().filter_map(|c| c.min_ts).min()?;
        let max = self.checkpoints.iter().filter_map(|c| c.max_ts).max()?;
        Some((min, max))
    }

    /// Find the checkpoint whose frame number exactly matches `frame`.
    pub fn checkpoint_at(&self, frame: u64) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.frame_number == frame)
    }

    /// Validate this index against the current state of a local source.
    ///
    /// Length and header hash must match. The modification time must match
    /// when both sides know it; when only one side knows it the index is
    /// treated as stale (a sidecar written without an mtime must not pass on a
    /// source that has one, or vice versa). Only when neither side has an
    /// mtime does the check fall back to length + hash alone. An index that
    /// carries an object e-tag never validates a local file.
    pub fn is_valid_for(&self, len: u64, mtime: Option<SystemTime>, header_hash: u64) -> bool {
        self.matches_source(len, mtime, header_hash, None)
    }

    /// [`Self::is_valid_for`] for a source that also has an entity tag (a
    /// cloud object): the e-tag follows the same both-or-neither rule as the
    /// modification time.
    pub fn matches_source(
        &self,
        len: u64,
        mtime: Option<SystemTime>,
        header_hash: u64,
        e_tag: Option<&str>,
    ) -> bool {
        if self.source_len != len || self.header_hash != header_hash {
            return false;
        }
        let mtime_ok = match (self.source_mtime, mtime) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        };
        let etag_ok = match (self.source_etag.as_deref(), e_tag) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        };
        mtime_ok && etag_ok
    }

    /// Whether persisting this index as a sidecar pays off
    /// (see [`SIDECAR_MIN_SOURCE_BYTES`]).
    pub fn worth_persisting(&self) -> bool {
        self.source_len >= SIDECAR_MIN_SOURCE_BYTES
    }
}

/// The conventional sidecar path for a capture (`<capture>.idx`).
pub fn sidecar_path(capture: &Path) -> PathBuf {
    let mut s = capture.as_os_str().to_os_string();
    s.push(".idx");
    PathBuf::from(s)
}

/// Hash the header region of a capture (used as a validity guard).
///
/// FNV-1a 64-bit over the first 4 KiB of the file (covers the legacy global
/// header and a typical PCAPNG SHB + interface descriptions). A fixed,
/// documented algorithm: the value is persisted in the sidecar, so it must be
/// identical across Rust releases and platforms (`DefaultHasher` is not).
pub fn header_hash(header_bytes: &[u8]) -> u64 {
    let n = header_bytes.len().min(4096);
    let h = fnv1a_update(FNV_OFFSET, &header_bytes[..n]);
    // Fold in the hashed length so a short header is distinct from a
    // zero-padded one.
    fnv1a_update(h, &(n as u64).to_le_bytes())
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit over `bytes`, continuing from state `h`.
fn fnv1a_update(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// The sidecar's trailing checksum: plain FNV-1a 64-bit over the body. Not a
/// cryptographic hash; it catches torn writes, truncation and bit rot, and is
/// identical across Rust releases and platforms.
fn fnv1a(bytes: &[u8]) -> u64 {
    fnv1a_update(FNV_OFFSET, bytes)
}

fn invalid(reason: &str) -> Error {
    Error::Pcap(PcapError::InvalidFormat {
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::codec::{put_u32, put_u64, SIDECAR_MAGIC};
    use super::*;
    use crate::io::pcap_stream::InterfaceInfo;

    #[test]
    fn test_sidecar_roundtrip() {
        let idx = BoundaryIndex {
            source_len: 12345,
            source_mtime: Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(100, 500)),
            header_hash: 0xDEAD_BEEF,
            source_etag: Some("\"abc123\"".to_string()),
            format: PcapFormat::PcapNg,
            link_type: 1,
            snaplen: 65535,
            packet_count: 1000,
            stride: 4,
            checkpoints: vec![
                Checkpoint {
                    frame_number: 1,
                    byte_offset: 28,
                    interface_state: Some(InterfaceState {
                        interfaces: vec![
                            InterfaceInfo {
                                link_type: 1,
                                if_tsresol: 6,
                                snaplen: 65535,
                                if_tsoffset: 0,
                            },
                            InterfaceInfo {
                                link_type: 113,
                                if_tsresol: 9,
                                snaplen: 262144,
                                if_tsoffset: -3_600,
                            },
                        ],
                        big_endian: true,
                    }),
                    min_ts: Some(10),
                    max_ts: Some(20),
                },
                Checkpoint {
                    frame_number: 5,
                    byte_offset: 500,
                    interface_state: Some(InterfaceState::default()),
                    min_ts: None,
                    max_ts: None,
                },
            ],
        };
        let bytes = idx.to_bytes();
        let back = BoundaryIndex::from_bytes(&bytes).unwrap();
        assert_eq!(idx, back);
    }

    #[test]
    fn test_validity_guard() {
        let idx = BoundaryIndex {
            source_len: 100,
            source_mtime: None,
            header_hash: 42,
            source_etag: None,
            format: PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 0,
            packet_count: 0,
            stride: 4,
            checkpoints: vec![],
        };
        assert!(idx.is_valid_for(100, None, 42));
        assert!(!idx.is_valid_for(101, None, 42)); // size mismatch
        assert!(!idx.is_valid_for(100, None, 43)); // hash mismatch
                                                   // An mtime known on only one side is a mismatch, not a pass.
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5);
        assert!(!idx.is_valid_for(100, Some(t), 42));
        let with_mtime = BoundaryIndex {
            source_mtime: Some(t),
            ..idx.clone()
        };
        assert!(with_mtime.is_valid_for(100, Some(t), 42));
        assert!(!with_mtime.is_valid_for(100, None, 42));
        assert!(!with_mtime.is_valid_for(100, Some(t + std::time::Duration::from_secs(1)), 42));
    }

    #[test]
    fn header_hash_is_stable_fnv1a() {
        // Persisted in sidecars: the value must never change across releases.
        assert_eq!(header_hash(b""), 0xa8c7f832281a39c5);
        assert_eq!(header_hash(b"abc"), 0xe5f49fafdcdf1048);
        assert_ne!(header_hash(b"\0\0"), header_hash(b"\0\0\0"));
    }

    /// Append a valid checksum so the body itself is what gets exercised.
    fn with_checksum(mut body: Vec<u8>) -> Vec<u8> {
        let c = fnv1a(&body);
        put_u64(&mut body, c);
        body
    }

    #[test]
    fn hostile_sidecar_is_rejected_not_panicking() {
        // Valid prefix up to the mtime, then an mtime that would overflow
        // `SystemTime + Duration`.
        let mut w = Vec::new();
        w.extend_from_slice(SIDECAR_MAGIC);
        put_u64(&mut w, 10); // source_len
        w.push(1); // mtime present
        put_u64(&mut w, u64::MAX); // secs
        put_u32(&mut w, 0); // nanos
        assert!(BoundaryIndex::from_bytes(&with_checksum(w)).is_err());

        let mut w = Vec::new();
        w.extend_from_slice(SIDECAR_MAGIC);
        put_u64(&mut w, 10);
        w.push(1);
        put_u64(&mut w, 1);
        put_u32(&mut w, 2_000_000_000); // nanos >= 1e9
        assert!(BoundaryIndex::from_bytes(&with_checksum(w)).is_err());

        // Too short for even a checksum.
        assert!(BoundaryIndex::from_bytes(SIDECAR_MAGIC).is_err());
        assert!(BoundaryIndex::from_bytes(b"").is_err());
    }

    /// A flipped byte anywhere in the body, a truncated file, or a stale
    /// format version is rejected (and therefore rebuilt), never misread.
    #[test]
    fn sidecar_checksum_and_version_guard() {
        let idx = BoundaryIndex {
            source_len: 1000,
            source_mtime: None,
            header_hash: 1,
            source_etag: None,
            format: PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 65535,
            packet_count: 10,
            stride: 4,
            checkpoints: vec![Checkpoint {
                frame_number: 1,
                byte_offset: 24,
                interface_state: None,
                min_ts: Some(5),
                max_ts: Some(9),
            }],
        };
        let bytes = idx.to_bytes();
        assert_eq!(BoundaryIndex::from_bytes(&bytes).unwrap(), idx);

        for i in 8..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            assert!(
                BoundaryIndex::from_bytes(&bad).is_err(),
                "flipped byte {i} must be rejected"
            );
        }
        assert!(BoundaryIndex::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(BoundaryIndex::from_bytes(&extra).is_err());

        // A v2 sidecar (previous magic) is rejected by the version check.
        let mut v2 = bytes.clone();
        v2[7] = 0x02;
        assert!(BoundaryIndex::from_bytes(&v2).is_err());
    }

    /// `validate()` rejects interface state the synthesized header could not
    /// reproduce: link types wider than 16 bits and undecodable `if_tsresol`.
    #[test]
    fn sidecar_rejects_unrepresentable_interface_state() {
        let good = BoundaryIndex {
            source_len: 1000,
            source_mtime: None,
            header_hash: 1,
            source_etag: None,
            format: PcapFormat::PcapNg,
            link_type: 1,
            snaplen: 65535,
            packet_count: 10,
            stride: 4,
            checkpoints: vec![Checkpoint {
                frame_number: 1,
                byte_offset: 28,
                interface_state: Some(InterfaceState {
                    interfaces: vec![InterfaceInfo {
                        link_type: 1,
                        if_tsresol: 6,
                        snaplen: 65535,
                        if_tsoffset: 0,
                    }],
                    big_endian: false,
                }),
                min_ts: None,
                max_ts: None,
            }],
        };
        assert!(BoundaryIndex::from_bytes(&good.to_bytes()).is_ok());

        let mut bad = good.clone();
        bad.checkpoints[0]
            .interface_state
            .as_mut()
            .unwrap()
            .interfaces[0]
            .link_type = 0x1_0000;
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());

        let mut bad = good.clone();
        bad.checkpoints[0]
            .interface_state
            .as_mut()
            .unwrap()
            .interfaces[0]
            .if_tsresol = 20;
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());

        let mut bad = good;
        bad.link_type = 0x1_0000;
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());
    }

    /// The e-tag follows the same both-or-neither rule as the mtime.
    #[test]
    fn etag_guard() {
        let idx = BoundaryIndex {
            source_len: 100,
            source_mtime: None,
            header_hash: 42,
            source_etag: Some("v1".into()),
            format: PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 0,
            packet_count: 0,
            stride: 4,
            checkpoints: vec![],
        };
        assert!(idx.matches_source(100, None, 42, Some("v1")));
        assert!(!idx.matches_source(100, None, 42, Some("v2")));
        assert!(!idx.matches_source(100, None, 42, None));
        assert!(!idx.is_valid_for(100, None, 42)); // tagged index, untagged source
        assert!(!idx.worth_persisting());
    }

    /// A synthesized IDB carries the interface's `if_tsoffset`, so a mid-file
    /// partition decodes the same timestamps as a sequential read.
    #[test]
    fn synth_pcapng_header_carries_tsoffset() {
        let state = InterfaceState {
            interfaces: vec![InterfaceInfo {
                link_type: 1,
                if_tsresol: 6,
                snaplen: 65535,
                if_tsoffset: 1_000,
            }],
            big_endian: false,
        };
        let h = synth_pcapng_header(&state);
        assert_eq!(h.len(), 28 + 44);
        let mut reader =
            crate::io::GenericPcapReader::with_format(std::io::Cursor::new(h), PcapFormat::PcapNg)
                .unwrap();
        reader.process_packets(1, |_| Ok(())).unwrap();
        assert_eq!(reader.interface_state().interfaces[0].if_tsoffset, 1_000);
    }

    #[test]
    fn structurally_invalid_sidecar_is_rejected() {
        let base = BoundaryIndex {
            source_len: 1000,
            source_mtime: None,
            header_hash: 1,
            source_etag: None,
            format: PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 65535,
            packet_count: 10,
            stride: 4,
            checkpoints: vec![
                Checkpoint {
                    frame_number: 1,
                    byte_offset: 24,
                    interface_state: None,
                    min_ts: None,
                    max_ts: None,
                },
                Checkpoint {
                    frame_number: 5,
                    byte_offset: 400,
                    interface_state: None,
                    min_ts: None,
                    max_ts: None,
                },
            ],
        };
        assert!(BoundaryIndex::from_bytes(&base.to_bytes()).is_ok());

        let mut bad = base.clone();
        bad.checkpoints[1].byte_offset = 24; // not ascending
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());

        let mut bad = base.clone();
        bad.checkpoints[1].byte_offset = 5000; // beyond source_len
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());

        let mut bad = base.clone();
        bad.checkpoints[0].frame_number = 2; // must start at frame 1
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());

        let mut bad = base.clone();
        bad.stride = 0;
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());

        let mut bad = base;
        bad.checkpoints[1].interface_state = Some(InterfaceState::default()); // legacy w/ ifaces
        assert!(BoundaryIndex::from_bytes(&bad.to_bytes()).is_err());
    }

    #[test]
    fn test_partition_ranges_contiguous() {
        let cps: Vec<Checkpoint> = (0..8)
            .map(|i| Checkpoint {
                frame_number: 1 + i * 10,
                byte_offset: 24 + i * 1000,
                interface_state: None,
                min_ts: None,
                max_ts: None,
            })
            .collect();
        let idx = BoundaryIndex {
            source_len: 0,
            source_mtime: None,
            header_hash: 0,
            source_etag: None,
            format: PcapFormat::LegacyLeMicro,
            link_type: 1,
            snaplen: 0,
            packet_count: 80,
            stride: 10,
            checkpoints: cps,
        };
        let ranges = idx.partition_ranges(4);
        assert_eq!(ranges.len(), 4);
        // contiguous: each end == next start
        for w in ranges.windows(2) {
            let end = w[0].end.as_ref().unwrap();
            assert_eq!(end.frame_number, w[1].start.frame_number);
            assert_eq!(end.byte_offset, w[1].start.byte_offset);
        }
        // first starts at frame 1, last is open-ended
        assert_eq!(ranges[0].start.frame_number, 1);
        assert!(ranges.last().unwrap().end.is_none());
    }

    #[test]
    fn test_synth_legacy_header_len() {
        let h = synth_legacy_header(PcapFormat::LegacyLeMicro, 1, 65535);
        assert_eq!(h.len(), 24);
        // magic LE micro = D4 C3 B2 A1
        assert_eq!(&h[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    }

    #[test]
    fn test_synth_pcapng_header_len() {
        let state = InterfaceState {
            interfaces: vec![
                InterfaceInfo {
                    link_type: 1,
                    if_tsresol: 6,
                    snaplen: 65535,
                    if_tsoffset: 0,
                },
                InterfaceInfo {
                    link_type: 1,
                    if_tsresol: 9,
                    snaplen: 65535,
                    if_tsoffset: 0,
                },
            ],
            big_endian: false,
        };
        let h = synth_pcapng_header(&state);
        // SHB(28) + 2 * IDB(32)
        assert_eq!(h.len(), 28 + 64);
        // Little-endian byte-order magic on disk.
        assert_eq!(&h[8..12], &[0x4D, 0x3C, 0x2B, 0x1A]);

        let be = InterfaceState {
            big_endian: true,
            ..state
        };
        let h = synth_pcapng_header(&be);
        assert_eq!(h.len(), 28 + 64);
        assert_eq!(&h[8..12], &[0x1A, 0x2B, 0x3C, 0x4D]);
        // Block lengths are big-endian too, so a BE reader parses it.
        assert_eq!(&h[4..8], &[0, 0, 0, 28]);
        assert_eq!(&h[28 + 4..28 + 8], &[0, 0, 0, 32]);
    }
}

#[cfg(test)]
mod build_tests {
    use super::*;
    use pcapsql_testgen::{generate, CaptureSpec, Format};
    use std::io::Cursor;

    fn pcap_format(f: Format) -> PcapFormat {
        match f {
            Format::LegacyLeMicro => PcapFormat::LegacyLeMicro,
            Format::LegacyBeMicro => PcapFormat::LegacyBeMicro,
            Format::LegacyLeNano => PcapFormat::LegacyLeNano,
            Format::LegacyBeNano => PcapFormat::LegacyBeNano,
            Format::Pcapng | Format::PcapngBe => PcapFormat::PcapNg,
        }
    }

    fn build_for(spec: &CaptureSpec, stride: u64) -> (BoundaryIndex, usize, usize) {
        let gc = generate(spec);
        let len = gc.bytes.len();
        let expected = gc.expected.len();
        let idx = build_boundary_index(
            Cursor::new(gc.bytes),
            pcap_format(spec.format),
            stride,
            len as u64,
            None,
            0,
        )
        .expect("build index");
        (idx, expected, len)
    }

    #[test]
    fn checkpoints_align_and_cover_generated_captures() {
        for format in [
            Format::LegacyLeMicro,
            Format::LegacyBeMicro,
            Format::LegacyLeNano,
            Format::LegacyBeNano,
            Format::Pcapng,
        ] {
            let spec = CaptureSpec {
                format,
                seed: 7,
                packet_count: 23,
                min_size: 14,
                max_size: 90,
                link_type: 1,
                interfaces: vec![6],
                sections: 1,
                add_interface_midstream: false,
                if_tsoffset: 0,
            };
            let stride = 4u64;
            let (idx, expected_count, len) = build_for(&spec, stride);

            assert_eq!(idx.packet_count, expected_count as u64);
            assert_eq!(idx.stride, stride);

            // Checkpoints start at frame 1 and step by exactly `stride` frames.
            let frames: Vec<u64> = idx.checkpoints.iter().map(|c| c.frame_number).collect();
            let want: Vec<u64> = (0..)
                .map(|k| 1 + k * stride)
                .take_while(|f| *f <= expected_count as u64)
                .collect();
            assert_eq!(frames, want, "{format:?}");

            // Byte offsets are strictly increasing record starts within the file.
            let mut prev = 0u64;
            for cp in &idx.checkpoints {
                assert!(cp.byte_offset > prev || cp.frame_number == 1);
                assert!(cp.byte_offset < len as u64);
                prev = cp.byte_offset;
            }

            // Ranges built from the index are contiguous and cover everything.
            let ranges = idx.partition_ranges(4);
            assert_eq!(ranges[0].start.frame_number, 1);
            assert!(ranges.last().unwrap().end.is_none());
            for w in ranges.windows(2) {
                let end = w[0].end.as_ref().unwrap();
                assert_eq!(end.frame_number, w[1].start.frame_number);
                assert_eq!(end.byte_offset, w[1].start.byte_offset);
            }

            // Interface state is recorded for PCAPNG and absent for legacy.
            for cp in &idx.checkpoints {
                match format {
                    Format::Pcapng => {
                        let state = cp.interface_state.as_ref().expect("pcapng state");
                        assert_eq!(state.interfaces[0].if_tsresol, 6);
                    }
                    _ => assert!(cp.interface_state.is_none()),
                }
            }
        }
    }

    /// An index built up to a frame is the index of the capture cut after
    /// that frame, whatever comes after it in the source.
    #[test]
    fn an_index_built_to_a_frame_is_that_of_the_capture_cut_there() {
        for format in [Format::LegacyLeMicro, Format::LegacyBeNano, Format::Pcapng] {
            let spec = CaptureSpec {
                format,
                seed: 11,
                packet_count: 23,
                min_size: 14,
                max_size: 90,
                link_type: 1,
                interfaces: vec![6],
                sections: 1,
                add_interface_midstream: false,
                if_tsoffset: 0,
            };
            let capture = generate(&spec);
            let len = capture.bytes.len() as u64;
            let build_with = |bytes: &[u8], stride, last_frame| {
                build_boundary_index_to(
                    Cursor::new(bytes),
                    pcap_format(format),
                    stride,
                    len,
                    None,
                    0,
                    last_frame,
                )
                .expect("build index")
            };
            let build = |bytes: &[u8], last_frame| build_with(bytes, 4, last_frame);
            let whole = build(&capture.bytes, None);
            assert_eq!(whole.packet_count, 23);
            // Where every frame's record starts.
            let starts: Vec<usize> = build_with(&capture.bytes, 1, None)
                .checkpoints
                .iter()
                .map(|c| c.byte_offset as usize)
                .collect();
            assert_eq!(starts.len(), 23);
            for last in [1u64, 4, 5, 9, 22, 23, 24, 1000] {
                let to = build(&capture.bytes, Some(last));
                let frames = last.min(23);
                assert_eq!(to.packet_count, frames, "{format:?} {last}");
                // The checkpoints the whole index has up to that frame, and
                // nothing of the frames after it: not even their timestamps
                // in the last window.
                let kept: Vec<&Checkpoint> = whole
                    .checkpoints
                    .iter()
                    .filter(|c| c.frame_number <= frames)
                    .collect();
                assert_eq!(to.checkpoints.len(), kept.len(), "{format:?} {last}");
                for (a, b) in to.checkpoints.iter().zip(&kept) {
                    assert_eq!(a.frame_number, b.frame_number);
                    assert_eq!(a.byte_offset, b.byte_offset);
                    assert_eq!(a.interface_state, b.interface_state);
                }
                // The same index as that of the bytes up to the next frame.
                let cut = starts
                    .get(frames as usize)
                    .copied()
                    .unwrap_or(capture.bytes.len());
                let prefix = build(&capture.bytes[..cut], None);
                assert_eq!(to.packet_count, prefix.packet_count, "{format:?} {last}");
                assert_eq!(to.checkpoints, prefix.checkpoints, "{format:?} {last}");
                assert_eq!(to.link_type, whole.link_type);
                assert_eq!(to.source_len, len);
            }
            // Nothing after the frame is read: garbage there is not an error.
            let cut = starts[9];
            let mut damaged = capture.bytes[..cut].to_vec();
            damaged.extend_from_slice(&[0xFF; 64]);
            let to = build(&damaged, Some(9));
            assert_eq!(to.packet_count, 9, "{format:?}");
        }
    }

    #[test]
    fn pcapng_checkpoints_track_midstream_interface_growth() {
        // Two sections, each declaring a microsecond interface, then a second
        // nanosecond interface *mid-stream* (after half the section's packets).
        // A checkpoint records the interface table as of ITS byte offset, so
        // checkpoints before the mid-stream IDB carry only [6] and those at or
        // after it carry [6, 9]. A partition starting at an early checkpoint
        // still decodes the later interface because it re-reads the mid-stream
        // IDB from its byte range (see the partition-equivalence tests).
        let spec = CaptureSpec {
            format: Format::Pcapng,
            seed: 21,
            packet_count: 30,
            min_size: 16,
            max_size: 60,
            link_type: 1,
            interfaces: vec![6],
            sections: 2,
            add_interface_midstream: true,
            if_tsoffset: 0,
        };
        let (idx, expected_count, _) = build_for(&spec, 3);
        assert_eq!(idx.packet_count, expected_count as u64);

        let tables: Vec<Vec<u8>> = idx
            .checkpoints
            .iter()
            .map(|cp| {
                cp.interface_state
                    .as_ref()
                    .expect("pcapng state")
                    .interfaces
                    .iter()
                    .map(|i| i.if_tsresol)
                    .collect()
            })
            .collect();

        // Every checkpoint's table is a prefix of the section's full table:
        // either [6] (before the mid-stream IDB) or [6, 9] (at/after it).
        for (cp, resols) in idx.checkpoints.iter().zip(&tables) {
            assert!(
                resols.as_slice() == [6] || resols.as_slice() == [6, 9],
                "checkpoint at frame {} has unexpected interface table {:?}",
                cp.frame_number,
                resols
            );
        }
        // The first checkpoint (frame 1) precedes any mid-stream IDB, so it must
        // carry only the base interface. This is the property the old generator
        // could not produce — it declared both interfaces up front.
        assert_eq!(
            tables.first().map(Vec::as_slice),
            Some([6].as_slice()),
            "first checkpoint must precede the mid-stream IDB and carry only [6]"
        );
        // Both phases are present across the index.
        assert!(
            tables.iter().any(|r| r.as_slice() == [6]),
            "expected at least one pre-switch checkpoint with table [6]"
        );
        assert!(
            tables.iter().any(|r| r.as_slice() == [6, 9]),
            "expected at least one post-switch checkpoint with table [6, 9]"
        );
    }
}
