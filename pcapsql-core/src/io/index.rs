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

use std::hash::Hasher;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pcap_parser::pcapng::Block;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError as PcapParserError, PcapNGReader};

use crate::error::{Error, PcapError};
use crate::io::pcap_stream::{ns_from_legacy, ns_from_ticks, InterfaceInfo, InterfaceState};
use crate::io::{PacketPosition, PacketRange, PcapFormat};

/// Default checkpoint stride: one checkpoint every 65536 frames.
pub const DEFAULT_CHECKPOINT_STRIDE: u64 = 65536;

/// Sidecar file format magic + version.
const SIDECAR_MAGIC: &[u8; 8] = b"PCSQIDX\x01";

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

    /// Find the checkpoint whose frame number exactly matches `frame`.
    pub fn checkpoint_at(&self, frame: u64) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.frame_number == frame)
    }

    /// Validate this index against the current state of a source.
    pub fn is_valid_for(&self, len: u64, mtime: Option<SystemTime>, header_hash: u64) -> bool {
        if self.source_len != len || self.header_hash != header_hash {
            return false;
        }
        // mtime: if both known, require equality; if either unknown, don't fail on it.
        match (self.source_mtime, mtime) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }

    // ---- Sidecar (de)serialization: explicit little-endian binary format ----

    /// Serialize to the sidecar binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(SIDECAR_MAGIC);
        put_u64(&mut w, self.source_len);
        put_opt_systemtime(&mut w, self.source_mtime);
        put_u64(&mut w, self.header_hash);
        w.push(format_to_u8(self.format));
        put_u32(&mut w, self.link_type);
        put_u32(&mut w, self.snaplen);
        put_u64(&mut w, self.packet_count);
        put_u64(&mut w, self.stride);
        put_u64(&mut w, self.checkpoints.len() as u64);
        for cp in &self.checkpoints {
            put_u64(&mut w, cp.frame_number);
            put_u64(&mut w, cp.byte_offset);
            put_opt_i64(&mut w, cp.min_ts);
            put_opt_i64(&mut w, cp.max_ts);
            match &cp.interface_state {
                None => w.push(0),
                Some(state) => {
                    w.push(1);
                    put_u32(&mut w, state.interfaces.len() as u32);
                    for iface in &state.interfaces {
                        put_u32(&mut w, iface.link_type);
                        w.push(iface.if_tsresol);
                        put_u32(&mut w, iface.snaplen);
                    }
                }
            }
        }
        w
    }

    /// Parse from the sidecar binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor { data, pos: 0 };
        let magic = c.take(8)?;
        if magic != SIDECAR_MAGIC {
            return Err(invalid("bad sidecar magic/version"));
        }
        let source_len = c.u64()?;
        let source_mtime = c.opt_systemtime()?;
        let header_hash = c.u64()?;
        let format = u8_to_format(c.u8()?)?;
        let link_type = c.u32()?;
        let snaplen = c.u32()?;
        let packet_count = c.u64()?;
        let stride = c.u64()?;
        let cp_count = c.u64()? as usize;
        let mut checkpoints = Vec::with_capacity(cp_count.min(1 << 20));
        for _ in 0..cp_count {
            let frame_number = c.u64()?;
            let byte_offset = c.u64()?;
            let min_ts = c.opt_i64()?;
            let max_ts = c.opt_i64()?;
            let interface_state = match c.u8()? {
                0 => None,
                1 => {
                    let count = c.u32()? as usize;
                    let mut interfaces = Vec::with_capacity(count.min(1 << 16));
                    for _ in 0..count {
                        let link_type = c.u32()?;
                        let if_tsresol = c.u8()?;
                        let snaplen = c.u32()?;
                        interfaces.push(InterfaceInfo {
                            link_type,
                            if_tsresol,
                            snaplen,
                        });
                    }
                    Some(InterfaceState { interfaces })
                }
                _ => return Err(invalid("bad interface-state tag")),
            };
            checkpoints.push(Checkpoint {
                frame_number,
                byte_offset,
                interface_state,
                min_ts,
                max_ts,
            });
        }
        Ok(BoundaryIndex {
            source_len,
            source_mtime,
            header_hash,
            format,
            link_type,
            snaplen,
            packet_count,
            stride,
            checkpoints,
        })
    }

    /// Write the index to a sidecar path.
    pub fn write_sidecar(&self, path: &Path) -> Result<(), Error> {
        let mut f = std::fs::File::create(path).map_err(Error::Io)?;
        f.write_all(&self.to_bytes()).map_err(Error::Io)?;
        Ok(())
    }

    /// Read an index from a sidecar path.
    pub fn read_sidecar(path: &Path) -> Result<Self, Error> {
        let data = std::fs::read(path).map_err(Error::Io)?;
        Self::from_bytes(&data)
    }
}

/// The conventional sidecar path for a capture (`<capture>.idx`).
pub fn sidecar_path(capture: &Path) -> PathBuf {
    let mut s = capture.as_os_str().to_os_string();
    s.push(".idx");
    PathBuf::from(s)
}

/// Hash the header region of a capture (used as a validity guard).
pub fn header_hash(header_bytes: &[u8]) -> u64 {
    // FNV-1a 64-bit over the first chunk of the file (covers legacy global header
    // and a typical PCAPNG SHB + interface descriptions).
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let n = header_bytes.len().min(4096);
    h.write(&header_bytes[..n]);
    h.write_u64(0x9E37_79B9_7F4A_7C15); // salt to distinguish from raw bytes
    h.finish()
}

/// Build a boundary index by a single sequential scan over the (uncompressed)
/// capture bytes. Records a checkpoint every `stride` frames (and always at
/// frame 1), capturing PCAPNG interface state at each.
pub fn build_boundary_index<R: Read>(
    source: R,
    format: PcapFormat,
    stride: u64,
    source_len: u64,
    source_mtime: Option<SystemTime>,
    header_hash: u64,
) -> Result<BoundaryIndex, Error> {
    let stride = stride.max(1);
    let mut builder = IndexBuilder::new(stride);
    if format.is_pcapng() {
        let mut reader = PcapNGReader::new(262144, source)
            .map_err(|e| invalid(&format!("PCAPNG index init: {e:?}")))?;
        scan_pcapng(&mut reader, &mut builder)?;
    } else {
        let mut reader = LegacyPcapReader::new(262144, source)
            .map_err(|e| invalid(&format!("legacy index init: {e:?}")))?;
        scan_legacy(&mut reader, &mut builder, format.legacy_is_nano())?;
    }
    Ok(BoundaryIndex {
        source_len,
        source_mtime,
        header_hash,
        format,
        link_type: builder.link_type,
        snaplen: builder.snaplen,
        packet_count: builder.frame_number,
        stride,
        checkpoints: builder.checkpoints,
    })
}

/// Accumulates checkpoints during a scan.
struct IndexBuilder {
    stride: u64,
    frame_number: u64,
    link_type: u32,
    snaplen: u32,
    interfaces: Vec<InterfaceInfo>,
    checkpoints: Vec<Checkpoint>,
    cur: Option<usize>,
}

impl IndexBuilder {
    fn new(stride: u64) -> Self {
        Self {
            stride,
            frame_number: 0,
            link_type: 1,
            snaplen: 0,
            interfaces: Vec::new(),
            checkpoints: Vec::new(),
            cur: None,
        }
    }

    /// Record a packet at `byte_offset` with timestamp `ts_ns`, deciding whether
    /// it begins a new checkpoint window.
    fn observe_packet(&mut self, byte_offset: u64, ts_ns: i64, pcapng: bool) {
        self.frame_number += 1;
        let frame = self.frame_number;
        let starts_window = frame == 1 || (frame - 1).is_multiple_of(self.stride);
        if starts_window {
            let interface_state = if pcapng {
                Some(InterfaceState {
                    interfaces: self.interfaces.clone(),
                })
            } else {
                None
            };
            self.checkpoints.push(Checkpoint {
                frame_number: frame,
                byte_offset,
                interface_state,
                min_ts: Some(ts_ns),
                max_ts: Some(ts_ns),
            });
            self.cur = Some(self.checkpoints.len() - 1);
        } else if let Some(i) = self.cur {
            let cp = &mut self.checkpoints[i];
            cp.min_ts = Some(cp.min_ts.map_or(ts_ns, |m| m.min(ts_ns)));
            cp.max_ts = Some(cp.max_ts.map_or(ts_ns, |m| m.max(ts_ns)));
        }
    }
}

fn scan_legacy<S: Read>(
    reader: &mut LegacyPcapReader<S>,
    builder: &mut IndexBuilder,
    nano: bool,
) -> Result<(), Error> {
    let mut capacity = 262144usize;
    loop {
        // `consumed()` before `next()` is the byte offset of the block `next()`
        // is about to return (the start of its record).
        let block_start = reader.consumed() as u64;
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        builder.link_type = hdr.network.0 as u32;
                        builder.snaplen = hdr.snaplen;
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        let ts = ns_from_legacy(pkt.ts_sec, pkt.ts_usec, nano);
                        builder.observe_packet(block_start, ts, false);
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapParserError::Eof) | Err(PcapParserError::UnexpectedEof) => break,
            Err(PcapParserError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| invalid(&format!("legacy index refill: {e:?}")))?;
            }
            Err(PcapParserError::BufferTooSmall) => {
                capacity = grow(reader, capacity)?;
            }
            Err(e) => return Err(invalid(&format!("legacy index parse: {e:?}"))),
        }
    }
    Ok(())
}

fn scan_pcapng<S: Read>(
    reader: &mut PcapNGReader<S>,
    builder: &mut IndexBuilder,
) -> Result<(), Error> {
    let mut capacity = 262144usize;
    loop {
        // `consumed()` before `next()` is the byte offset of the block `next()`
        // is about to return (the start of its record).
        let block_start = reader.consumed() as u64;
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::NG(ng) = block {
                    match ng {
                        Block::SectionHeader(_) => {
                            builder.interfaces.clear();
                        }
                        Block::InterfaceDescription(idb) => {
                            let info = InterfaceInfo {
                                link_type: idb.linktype.0 as u32,
                                if_tsresol: idb.if_tsresol,
                                snaplen: idb.snaplen,
                            };
                            if builder.interfaces.is_empty() {
                                builder.link_type = info.link_type;
                                builder.snaplen = info.snaplen;
                            }
                            builder.interfaces.push(info);
                        }
                        Block::EnhancedPacket(epb) => {
                            let resolution = builder
                                .interfaces
                                .get(epb.if_id as usize)
                                .map(|i| i.resolution())
                                .unwrap_or(1_000_000);
                            let ts = ns_from_ticks(epb.ts_high, epb.ts_low, resolution);
                            builder.observe_packet(block_start, ts, true);
                        }
                        Block::SimplePacket(_) => {
                            builder.observe_packet(block_start, 0, true);
                        }
                        _ => {}
                    }
                }
                reader.consume(offset);
            }
            Err(PcapParserError::Eof) | Err(PcapParserError::UnexpectedEof) => break,
            Err(PcapParserError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| invalid(&format!("pcapng index refill: {e:?}")))?;
            }
            Err(PcapParserError::BufferTooSmall) => {
                capacity = grow(reader, capacity)?;
            }
            Err(e) => return Err(invalid(&format!("pcapng index parse: {e:?}"))),
        }
    }
    Ok(())
}

fn grow<I: PcapReaderIterator>(reader: &mut I, capacity: usize) -> Result<usize, Error> {
    let new_cap = capacity.saturating_mul(2);
    if new_cap == capacity || !reader.grow(new_cap) {
        return Err(invalid("index scan: frame exceeds maximum buffer size"));
    }
    reader
        .refill()
        .map_err(|e| invalid(&format!("index grow refill: {e:?}")))?;
    Ok(new_cap)
}

// ---- Header synthesis for mid-file (headerless) partition starts ----

/// Synthesize a 24-byte legacy global header for a mid-file partition.
pub fn synth_legacy_header(format: PcapFormat, link_type: u32, snaplen: u32) -> Vec<u8> {
    let be = format.is_big_endian();
    let mut v = Vec::with_capacity(24);
    put_u32_e(&mut v, format.legacy_magic_u32(), be);
    put_u16_e(&mut v, 2, be); // version major
    put_u16_e(&mut v, 4, be); // version minor
    put_u32_e(&mut v, 0, be); // thiszone
    put_u32_e(&mut v, 0, be); // sigfigs
    put_u32_e(&mut v, if snaplen == 0 { 65535 } else { snaplen }, be);
    put_u32_e(&mut v, link_type, be);
    v
}

/// Synthesize a PCAPNG section header + interface descriptions for a mid-file
/// partition, reconstructing the interface table (link type + `if_tsresol`).
pub fn synth_pcapng_header(state: &InterfaceState) -> Vec<u8> {
    let mut v = Vec::new();
    // Section Header Block (little-endian on disk), 28 bytes, no options.
    put_u32_le(&mut v, 0x0A0D_0D0A); // block type
    put_u32_le(&mut v, 28); // total length
    put_u32_le(&mut v, 0x1A2B_3C4D); // byte-order magic
    put_u16_le(&mut v, 1); // major
    put_u16_le(&mut v, 0); // minor
    put_u64_le(&mut v, u64::MAX); // section length: unknown
    put_u32_le(&mut v, 28); // total length (trailer)

    for iface in &state.interfaces {
        // Interface Description Block, 32 bytes with if_tsresol option.
        put_u32_le(&mut v, 0x0000_0001); // block type
        put_u32_le(&mut v, 32); // total length
        put_u16_le(&mut v, iface.link_type as u16); // linktype
        put_u16_le(&mut v, 0); // reserved
        put_u32_le(
            &mut v,
            if iface.snaplen == 0 {
                65535
            } else {
                iface.snaplen
            },
        );
        // Option: if_tsresol (code 9, len 1), value padded to 4 bytes.
        put_u16_le(&mut v, 9);
        put_u16_le(&mut v, 1);
        v.push(iface.if_tsresol);
        v.extend_from_slice(&[0, 0, 0]);
        // opt_endofopt
        put_u16_le(&mut v, 0);
        put_u16_le(&mut v, 0);
        put_u32_le(&mut v, 32); // total length (trailer)
    }
    v
}

// ---- little-endian / endian-aware encoding helpers ----

fn put_u16_le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u32_le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u64_le(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u16_e(v: &mut Vec<u8>, x: u16, be: bool) {
    if be {
        v.extend_from_slice(&x.to_be_bytes());
    } else {
        v.extend_from_slice(&x.to_le_bytes());
    }
}
fn put_u32_e(v: &mut Vec<u8>, x: u32, be: bool) {
    if be {
        v.extend_from_slice(&x.to_be_bytes());
    } else {
        v.extend_from_slice(&x.to_le_bytes());
    }
}

fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_opt_i64(v: &mut Vec<u8>, x: Option<i64>) {
    match x {
        None => v.push(0),
        Some(n) => {
            v.push(1);
            v.extend_from_slice(&n.to_le_bytes());
        }
    }
}
fn put_opt_systemtime(v: &mut Vec<u8>, t: Option<SystemTime>) {
    match t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
        None => v.push(0),
        Some(d) => {
            v.push(1);
            put_u64(v, d.as_secs());
            put_u32(v, d.subsec_nanos());
        }
    }
}

fn format_to_u8(f: PcapFormat) -> u8 {
    match f {
        PcapFormat::LegacyLeMicro => 0,
        PcapFormat::LegacyBeMicro => 1,
        PcapFormat::LegacyLeNano => 2,
        PcapFormat::LegacyBeNano => 3,
        PcapFormat::PcapNg => 4,
    }
}
fn u8_to_format(b: u8) -> Result<PcapFormat, Error> {
    Ok(match b {
        0 => PcapFormat::LegacyLeMicro,
        1 => PcapFormat::LegacyBeMicro,
        2 => PcapFormat::LegacyLeNano,
        3 => PcapFormat::LegacyBeNano,
        4 => PcapFormat::PcapNg,
        _ => return Err(invalid("bad format tag")),
    })
}

fn invalid(reason: &str) -> Error {
    Error::Pcap(PcapError::InvalidFormat {
        reason: reason.to_string(),
    })
}

/// Minimal little-endian cursor for sidecar parsing.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.data.len() {
            return Err(invalid("sidecar truncated"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn opt_i64(&mut self) -> Result<Option<i64>, Error> {
        Ok(match self.u8()? {
            0 => None,
            1 => {
                let b = self.take(8)?;
                Some(i64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            _ => return Err(invalid("bad opt tag")),
        })
    }
    fn opt_systemtime(&mut self) -> Result<Option<SystemTime>, Error> {
        Ok(match self.u8()? {
            0 => None,
            1 => {
                let secs = self.u64()?;
                let nanos = self.u32()?;
                Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
            }
            _ => return Err(invalid("bad opt tag")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sidecar_roundtrip() {
        let idx = BoundaryIndex {
            source_len: 12345,
            source_mtime: Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(100, 500)),
            header_hash: 0xDEAD_BEEF,
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
                            },
                            InterfaceInfo {
                                link_type: 1,
                                if_tsresol: 9,
                                snaplen: 262144,
                            },
                        ],
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
                },
                InterfaceInfo {
                    link_type: 1,
                    if_tsresol: 9,
                    snaplen: 65535,
                },
            ],
        };
        let h = synth_pcapng_header(&state);
        // SHB(28) + 2 * IDB(32)
        assert_eq!(h.len(), 28 + 64);
    }
}
