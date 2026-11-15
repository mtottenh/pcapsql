//! The sidecar format of a [`BoundaryIndex`]: an explicit little-endian
//! binary file (see the module docs of [`super`]), and the checks a sidecar
//! must pass before its offsets are trusted.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{fnv1a, invalid, BoundaryIndex, Checkpoint, MAX_ETAG_BYTES};
use crate::error::Error;
use crate::io::pcap_stream::{tsresol_units, InterfaceInfo, InterfaceState};
use crate::io::PcapFormat;

/// Sidecar magic + format version (see the module docs). A sidecar of any
/// other version fails the magic check and is rebuilt.
pub(super) const SIDECAR_MAGIC: &[u8; 8] = b"PCSQIDX\x03";

impl BoundaryIndex {
    /// Structural sanity checks on a deserialized index.
    ///
    /// A sidecar is read before anything else and its offsets become partition
    /// starts, so a corrupt or hand-edited file must be rejected here rather
    /// than turn into mid-record reads later.
    fn validate(&self) -> Result<(), Error> {
        if self.stride == 0 {
            return Err(invalid("sidecar: stride must be >= 1"));
        }
        // The synthesized headers write link types as 16-bit fields.
        if self.link_type > u32::from(u16::MAX) {
            return Err(invalid("sidecar: link type does not fit 16 bits"));
        }
        if self.checkpoints.is_empty() {
            return Ok(());
        }
        if self.checkpoints[0].frame_number != 1 {
            return Err(invalid("sidecar: first checkpoint must be frame 1"));
        }
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if cp.frame_number > self.packet_count {
                return Err(invalid("sidecar: checkpoint frame beyond packet_count"));
            }
            if cp.byte_offset >= self.source_len {
                return Err(invalid("sidecar: checkpoint offset beyond source length"));
            }
            if self.format.is_pcapng() != cp.interface_state.is_some() {
                return Err(invalid(
                    "sidecar: interface state present iff the capture is PCAPNG",
                ));
            }
            for iface in cp.interface_state.iter().flat_map(|s| &s.interfaces) {
                if iface.link_type > u32::from(u16::MAX) {
                    return Err(invalid("sidecar: interface link type does not fit 16 bits"));
                }
                if tsresol_units(iface.if_tsresol).is_none() {
                    return Err(invalid("sidecar: interface if_tsresol is not decodable"));
                }
            }
            if i > 0 {
                let prev = &self.checkpoints[i - 1];
                if cp.frame_number <= prev.frame_number || cp.byte_offset <= prev.byte_offset {
                    return Err(invalid(
                        "sidecar: checkpoints must be strictly ascending by frame and offset",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Serialize to the sidecar binary format (body + trailing checksum).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(SIDECAR_MAGIC);
        put_u64(&mut w, self.source_len);
        put_opt_systemtime(&mut w, self.source_mtime);
        put_u64(&mut w, self.header_hash);
        put_opt_str(&mut w, self.source_etag.as_deref());
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
                    w.push(u8::from(state.big_endian));
                    put_u32(&mut w, state.interfaces.len() as u32);
                    for iface in &state.interfaces {
                        put_u32(&mut w, iface.link_type);
                        w.push(iface.if_tsresol);
                        put_u32(&mut w, iface.snaplen);
                        w.extend_from_slice(&iface.if_tsoffset.to_le_bytes());
                    }
                }
            }
        }
        let checksum = fnv1a(&w);
        put_u64(&mut w, checksum);
        w
    }

    /// Parse from the sidecar binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 8 || &data[..8] != SIDECAR_MAGIC {
            return Err(invalid("bad sidecar magic/version"));
        }
        if data.len() < 16 {
            return Err(invalid("sidecar truncated before checksum"));
        }
        let (body, trailer) = data.split_at(data.len() - 8);
        let stored = u64::from_le_bytes(trailer.try_into().expect("8-byte trailer"));
        if fnv1a(body) != stored {
            return Err(invalid("sidecar checksum mismatch"));
        }
        let mut c = Cursor { data: body, pos: 8 };
        let source_len = c.u64()?;
        let source_mtime = c.opt_systemtime()?;
        let header_hash = c.u64()?;
        let source_etag = c.opt_str()?;
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
                    let big_endian = match c.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(invalid("bad byte-order tag")),
                    };
                    let count = c.u32()? as usize;
                    let mut interfaces = Vec::with_capacity(count.min(1 << 16));
                    for _ in 0..count {
                        let link_type = c.u32()?;
                        let if_tsresol = c.u8()?;
                        let snaplen = c.u32()?;
                        let if_tsoffset = c.i64()?;
                        interfaces.push(InterfaceInfo {
                            link_type,
                            if_tsresol,
                            snaplen,
                            if_tsoffset,
                        });
                    }
                    Some(InterfaceState {
                        interfaces,
                        big_endian,
                    })
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
        if c.pos != body.len() {
            return Err(invalid("sidecar: trailing bytes after index body"));
        }
        let idx = BoundaryIndex {
            source_len,
            source_mtime,
            header_hash,
            source_etag,
            format,
            link_type,
            snaplen,
            packet_count,
            stride,
            checkpoints,
        };
        idx.validate()?;
        Ok(idx)
    }

    /// Write the index to a sidecar path.
    ///
    /// Written to a temporary file in the same directory and renamed into
    /// place, so a concurrent reader never observes a torn sidecar.
    pub fn write_sidecar(&self, path: &Path) -> Result<(), Error> {
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(format!(".tmp.{}", std::process::id()));
        let tmp = PathBuf::from(tmp);
        let result = (|| {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&self.to_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(Error::Io)
    }

    /// Read an index from a sidecar path.
    pub fn read_sidecar(path: &Path) -> Result<Self, Error> {
        let data = std::fs::read(path).map_err(Error::Io)?;
        Self::from_bytes(&data)
    }
}

pub(super) fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub(super) fn put_u64(v: &mut Vec<u8>, x: u64) {
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

fn put_opt_str(v: &mut Vec<u8>, s: Option<&str>) {
    match s.filter(|s| s.len() <= MAX_ETAG_BYTES) {
        None => v.push(0),
        Some(s) => {
            v.push(1);
            put_u32(v, s.len() as u32);
            v.extend_from_slice(s.as_bytes());
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
    fn i64(&mut self) -> Result<i64, Error> {
        Ok(self.u64()? as i64)
    }
    fn opt_i64(&mut self) -> Result<Option<i64>, Error> {
        Ok(match self.u8()? {
            0 => None,
            1 => Some(self.i64()?),
            _ => return Err(invalid("bad opt tag")),
        })
    }
    fn opt_str(&mut self) -> Result<Option<String>, Error> {
        Ok(match self.u8()? {
            0 => None,
            1 => {
                let len = self.u32()? as usize;
                if len > MAX_ETAG_BYTES {
                    return Err(invalid("sidecar: e-tag too long"));
                }
                let bytes = self.take(len)?;
                Some(
                    std::str::from_utf8(bytes)
                        .map_err(|_| invalid("sidecar: e-tag is not UTF-8"))?
                        .to_string(),
                )
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
                // Never panic on a hostile sidecar: `Duration::new` and
                // `SystemTime + Duration` both panic on overflow.
                if nanos >= 1_000_000_000 {
                    return Err(invalid("sidecar: mtime nanos out of range"));
                }
                let d = std::time::Duration::new(secs, nanos);
                Some(
                    SystemTime::UNIX_EPOCH
                        .checked_add(d)
                        .ok_or_else(|| invalid("sidecar: mtime out of range"))?,
                )
            }
            _ => return Err(invalid("bad opt tag")),
        })
    }
}
