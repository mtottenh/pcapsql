//! The legacy pcap builder.

use crate::model::{ExpectedFrame, GeneratedCapture};

/// Legacy pcap on-disk variant (endianness + timestamp precision).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyVariant {
    /// Little-endian, microsecond timestamps (magic `0xa1b2c3d4`).
    LeMicro,
    /// Big-endian, microsecond timestamps.
    BeMicro,
    /// Little-endian, nanosecond timestamps (magic `0xa1b23c4d`).
    LeNano,
    /// Big-endian, nanosecond timestamps.
    BeNano,
}

impl LegacyVariant {
    #[inline]
    fn is_little_endian(self) -> bool {
        matches!(self, LegacyVariant::LeMicro | LegacyVariant::LeNano)
    }

    #[inline]
    pub(crate) fn is_nano(self) -> bool {
        matches!(self, LegacyVariant::LeNano | LegacyVariant::BeNano)
    }

    /// The 32-bit magic value (logical, host order). Byte order on disk is
    /// applied by the writer using the variant's endianness.
    #[inline]
    fn magic(self) -> u32 {
        if self.is_nano() {
            0xa1b2_3c4d
        } else {
            0xa1b2_c3d4
        }
    }
}

/// A single legacy packet to write.
///
/// `ts_frac` is microseconds for `*Micro` variants and nanoseconds for `*Nano`
/// variants. `data.len()` becomes the captured length; `origlen` is the on-wire
/// length (set equal to `data.len()` for an untruncated frame).
#[derive(Clone, Debug)]
pub struct GenPacket {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub data: Vec<u8>,
    pub origlen: u32,
}

/// Helper that accumulates bytes in a chosen endianness.
struct ByteWriter {
    little_endian: bool,
    buf: Vec<u8>,
}

impl ByteWriter {
    fn new(little_endian: bool) -> Self {
        Self {
            little_endian,
            buf: Vec::new(),
        }
    }

    #[inline]
    fn u16(&mut self, v: u16) {
        if self.little_endian {
            self.buf.extend_from_slice(&v.to_le_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    #[inline]
    fn u32(&mut self, v: u32) {
        if self.little_endian {
            self.buf.extend_from_slice(&v.to_le_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    #[inline]
    fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }

    #[inline]
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
}

/// Compute legacy timestamp in nanoseconds.
///
/// * micro: `ns = sec*1_000_000_000 + usec*1_000`
/// * nano:  `ns = sec*1_000_000_000 + nsec`
#[inline]
fn legacy_ts_ns(variant: LegacyVariant, ts_sec: u32, ts_frac: u32) -> i64 {
    let sec = ts_sec as i64;
    let frac = ts_frac as i64;
    if variant.is_nano() {
        sec * 1_000_000_000 + frac
    } else {
        sec * 1_000_000_000 + frac * 1_000
    }
}

/// Build a legacy pcap capture.
///
/// Layout (every multibyte field in the variant's endianness):
/// * Global header (24 bytes): magic(u32), version_major(u16)=2,
///   version_minor(u16)=4, thiszone(i32)=0, sigfigs(u32)=0, snaplen(u32),
///   network(u32)=link_type.
/// * Each record: ts_sec(u32), ts_frac(u32), caplen(u32)=data.len(),
///   origlen(u32), then the captured bytes (no padding in legacy pcap).
pub fn legacy_pcap(
    variant: LegacyVariant,
    link_type: u16,
    snaplen: u32,
    packets: &[GenPacket],
) -> GeneratedCapture {
    let le = variant.is_little_endian();
    let mut w = ByteWriter::new(le);

    // Global header. The magic is written as a whole u32 in the chosen
    // endianness so its byte order is consistent with every other field.
    w.u32(variant.magic());
    w.u16(2); // version_major
    w.u16(4); // version_minor
    w.i32(0); // thiszone
    w.u32(0); // sigfigs
    w.u32(snaplen);
    w.u32(link_type as u32); // network

    let mut expected = Vec::with_capacity(packets.len());
    for (idx, p) in packets.iter().enumerate() {
        let caplen = p.data.len() as u32;
        w.u32(p.ts_sec);
        w.u32(p.ts_frac);
        w.u32(caplen);
        w.u32(p.origlen);
        w.bytes(&p.data);

        expected.push(ExpectedFrame {
            frame_number: (idx + 1) as u64,
            timestamp_ns: legacy_ts_ns(variant, p.ts_sec, p.ts_frac),
            caplen,
            origlen: p.origlen,
            link_type: link_type as u32,
            data: p.data.clone(),
        });
    }

    GeneratedCapture {
        bytes: w.buf,
        expected,
    }
}
