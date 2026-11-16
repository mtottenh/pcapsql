//! The probe of a capture stream's head: compression, format, link type.
//!
//! Opening a stream **probes** its head: the compression magic, the capture
//! format (legacy pcap in either byte order and timestamp unit, or pcapng)
//! and the link type (the legacy global header, or the pcapng section header
//! plus the first interface description block). The probe reads exactly the
//! bytes those headers occupy and no more, so on a live feed the first packet
//! is never held back by a fixed-size pre-read. It returns the bytes it took,
//! for the caller to chain back in front of the rest of the stream.
//!
//! [`StreamHeader::probe`] is the public entry; the stdin source and
//! [`ReadPacketReader::sequential`](crate::io::ReadPacketReader::sequential)
//! are its users.

use std::io::{self, Read};

use crate::error::{Error, PcapError};
use crate::io::decompress::{decompress_header, Compression};
use crate::io::pcap_stream::{PcapFormat, BUFFER_SIZE};

/// Length of the legacy pcap global header.
pub(crate) const LEGACY_HEADER_LEN: usize = 24;
/// Smallest valid pcapng Section Header Block (no options).
const SHB_MIN_LEN: usize = 28;
/// Smallest valid pcapng Interface Description Block (no options).
const IDB_MIN_LEN: usize = 20;
/// pcapng block type of an Interface Description Block.
const IDB_BLOCK_TYPE: u32 = 1;
/// Sanity cap on the header blocks the probe is willing to pre-read: what
/// the reader itself accepts in one buffer. Real SHBs and IDBs are a few
/// hundred bytes; a larger length is a corrupt stream, which the reader
/// proper would report too.
const MAX_HEADER_BLOCK_LEN: usize = BUFFER_SIZE;
/// First request size when growing a *compressed* prefix whose decompressed
/// output does not yet hold the headers; doubles on each step up to
/// [`COMPRESSED_PROBE_MAX_STEP`]. One `read` per step, taking whatever it
/// returns, so a live feed is never waited on for more than it has sent.
const COMPRESSED_PROBE_STEP: usize = 512;
const COMPRESSED_PROBE_MAX_STEP: usize = 64 * 1024;

/// What the probe learned from the head of the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    /// Compression framing around the capture (`Compression::None` for raw).
    pub compression: Compression,
    /// Capture format.
    pub format: PcapFormat,
    /// Link type from the legacy header or the first pcapng IDB (1 when a
    /// pcapng stream declares no interface before its first other block).
    pub link_type: u32,
    /// Snapshot length from the same header (65535 when unknown).
    pub snaplen: u32,
    /// Bytes of (decompressed) stream the format's own header occupies: the
    /// legacy global header, or the pcapng SHB. The reader must see at least
    /// this much in its first read.
    pub header_len: usize,
}

impl StreamHeader {
    /// Read just enough of the head of `read` to learn the capture's
    /// compression, format, link type and snapshot length.
    ///
    /// Returns the header and the bytes taken from `read`, which
    /// [`ReadPacketReader::sequential`](crate::io::ReadPacketReader::sequential)
    /// puts back in front of the stream.
    pub fn probe<R: Read>(read: &mut R) -> Result<(StreamHeader, Vec<u8>), Error> {
        probe_stream(read, "the capture")
    }
}

/// What [`analyze_header`] still needs, in bytes of (decompressed) stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Need {
    /// Part of the capture's own header: end of input before this is an
    /// error.
    Required(usize),
    /// The first pcapng block after the SHB, hoped to be an IDB: end of
    /// input before this is a valid (empty) capture with the default link
    /// type.
    Optional(usize),
}

impl Need {
    fn target(self) -> usize {
        match self {
            Need::Required(n) | Need::Optional(n) => n,
        }
    }
}

/// Outcome of analyzing a (decompressed) stream prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Done {
        format: PcapFormat,
        link_type: u32,
        snaplen: u32,
        header_len: usize,
    },
    Need(Need),
}

/// Pure analysis of a decompressed stream prefix: the format and, when the
/// prefix holds them, the link type and snaplen from the legacy global
/// header or the pcapng SHB + first IDB. Reports exactly how many bytes it
/// needs to go further, so the caller reads no more than that.
fn analyze_header(bytes: &[u8]) -> Result<Probe, Error> {
    if bytes.len() < 4 {
        return Ok(Probe::Need(Need::Required(4)));
    }
    let format = PcapFormat::detect(bytes)?;
    if format.is_legacy() {
        if bytes.len() < LEGACY_HEADER_LEN {
            return Ok(Probe::Need(Need::Required(LEGACY_HEADER_LEN)));
        }
        let be = format.is_big_endian();
        return Ok(Probe::Done {
            format,
            snaplen: read_u32(&bytes[16..20], be),
            link_type: read_u32(&bytes[20..24], be),
            header_len: LEGACY_HEADER_LEN,
        });
    }

    // pcapng: block type (4), block total length (4), byte-order magic (4).
    if bytes.len() < 12 {
        return Ok(Probe::Need(Need::Required(12)));
    }
    let be = match &bytes[8..12] {
        [0x4d, 0x3c, 0x2b, 0x1a] => false,
        [0x1a, 0x2b, 0x3c, 0x4d] => true,
        other => {
            return Err(Error::Pcap(PcapError::InvalidFormat {
                reason: format!(
                    "PCAPNG section header has an invalid byte-order magic {other:02x?}"
                ),
            }))
        }
    };
    let shb_len = read_u32(&bytes[4..8], be) as usize;
    if shb_len < SHB_MIN_LEN || !shb_len.is_multiple_of(4) || shb_len > MAX_HEADER_BLOCK_LEN {
        return Err(Error::Pcap(PcapError::InvalidFormat {
            reason: format!(
                "PCAPNG section header block declares an invalid length ({shb_len} bytes)"
            ),
        }));
    }
    if bytes.len() < shb_len {
        return Ok(Probe::Need(Need::Required(shb_len)));
    }
    let done_without_idb = Probe::Done {
        format,
        link_type: 1,
        snaplen: 65535,
        header_len: shb_len,
    };

    // The first block after the SHB is normally the IDB that gives the link
    // type. Anything else is left to the reader.
    let idb = shb_len;
    if bytes.len() < idb + 8 {
        return Ok(Probe::Need(Need::Optional(idb + 8)));
    }
    let block_type = read_u32(&bytes[idb..idb + 4], be);
    let block_len = read_u32(&bytes[idb + 4..idb + 8], be) as usize;
    if block_type != IDB_BLOCK_TYPE
        || block_len < IDB_MIN_LEN
        || !block_len.is_multiple_of(4)
        || block_len > MAX_HEADER_BLOCK_LEN
    {
        return Ok(done_without_idb);
    }
    if bytes.len() < idb + block_len {
        return Ok(Probe::Need(Need::Optional(idb + block_len)));
    }
    Ok(Probe::Done {
        format,
        link_type: read_u16(&bytes[idb + 8..idb + 10], be) as u32,
        snaplen: read_u32(&bytes[idb + 12..idb + 16], be),
        header_len: shb_len,
    })
}

/// Read the head of the stream: compression, format, link type. Returns the
/// header and the raw bytes consumed from the stream, which the caller
/// chains back in front of it.
pub(crate) fn probe_stream<R: Read>(
    reader: &mut R,
    origin: &str,
) -> Result<(StreamHeader, Vec<u8>), Error> {
    let mut raw = Vec::with_capacity(64);
    // The compression magics need 6 bytes; every capture header is longer.
    read_up_to(reader, &mut raw, 6)?;
    if raw.is_empty() {
        return Err(Error::Pcap(PcapError::InvalidFormat {
            reason: format!("{origin} is empty: no capture header was read"),
        }));
    }
    let compression = Compression::detect(&raw);
    let finish = |probe: Probe, raw: Vec<u8>| -> Result<(StreamHeader, Vec<u8>), Error> {
        match probe {
            Probe::Done {
                format,
                link_type,
                snaplen,
                header_len,
            } => Ok((
                StreamHeader {
                    compression,
                    format,
                    link_type,
                    snaplen,
                    header_len,
                },
                raw,
            )),
            Probe::Need(_) => unreachable!("finish is only called on a complete probe"),
        }
    };

    if !compression.is_compressed() {
        loop {
            match analyze_header(&raw)? {
                done @ Probe::Done { .. } => return finish(done, raw),
                Probe::Need(need) => {
                    read_up_to(reader, &mut raw, need.target())?;
                    if raw.len() < need.target() {
                        return match need {
                            Need::Required(n) => Err(truncated_header(raw.len(), n)),
                            // SHB alone (or ending inside the block after
                            // it): a capture with no interface declared yet.
                            Need::Optional(_) => finish(analyze_shb_only(&raw)?, raw),
                        };
                    }
                }
            }
        }
    }

    // Compressed: grow the compressed prefix until it decompresses to what
    // the header analysis needs. A prefix cut inside the compressed stream
    // decompresses to an error once the decoder runs out of input ("read
    // more"); a prefix that decompresses to fewer bytes than asked for was a
    // complete stream, and what it holds is final. Each step is one `read`
    // of a doubling size, so a decoder that emits nothing until a whole
    // block is present costs O(log n) re-decodes, not O(n / step).
    let mut want = LEGACY_HEADER_LEN;
    let mut step = COMPRESSED_PROBE_STEP;
    let mut eof = false;
    loop {
        match decompress_header(&raw, compression, want) {
            Ok(decompressed) => match analyze_header(&decompressed)? {
                done @ Probe::Done { .. } => return finish(done, raw),
                Probe::Need(need) if decompressed.len() >= want => {
                    // The prefix may decompress further: ask for more output
                    // before reading more input.
                    want = need.target();
                    continue;
                }
                Probe::Need(Need::Required(n)) => {
                    return Err(truncated_header(decompressed.len(), n));
                }
                Probe::Need(Need::Optional(_)) => {
                    return finish(analyze_shb_only(&decompressed)?, raw);
                }
            },
            Err(e) if eof => {
                return Err(Error::Pcap(PcapError::InvalidFormat {
                    reason: format!(
                        "failed to decompress the capture header from {origin} ({compression}): {e}"
                    ),
                }));
            }
            Err(_) => {}
        }
        let before = raw.len();
        read_once(reader, &mut raw, step)?;
        eof = raw.len() == before;
        step = (step * 2).min(COMPRESSED_PROBE_MAX_STEP);
    }
}

/// A pcapng prefix that holds a complete SHB but ended before a complete
/// IDB: a capture with the default link type.
fn analyze_shb_only(bytes: &[u8]) -> Result<Probe, Error> {
    let format = PcapFormat::detect(bytes)?;
    let be = bytes[8] == 0x1a;
    Ok(Probe::Done {
        format,
        link_type: 1,
        snaplen: 65535,
        header_len: read_u32(&bytes[4..8], be) as usize,
    })
}

fn truncated_header(have: usize, need: usize) -> Error {
    Error::Pcap(PcapError::InvalidFormat {
        reason: format!(
            "stdin ended after {have} bytes: too short for a capture header ({need} bytes needed)"
        ),
    })
}

/// Read from `reader` into `buf` until `buf.len() == target` or end of
/// input; never asks for more than `target` bytes.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut Vec<u8>, target: usize) -> Result<(), Error> {
    while buf.len() < target {
        let start = buf.len();
        buf.resize(target, 0);
        match reader.read(&mut buf[start..]) {
            Ok(0) => {
                buf.truncate(start);
                break;
            }
            Ok(n) => buf.truncate(start + n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => buf.truncate(start),
            Err(e) => {
                buf.truncate(start);
                return Err(Error::Io(e));
            }
        }
    }
    Ok(())
}

/// One `read` of up to `max` bytes appended to `buf`: whatever the stream
/// has (0 at end of input). Retries only on `Interrupted`.
fn read_once<R: Read>(reader: &mut R, buf: &mut Vec<u8>, max: usize) -> Result<(), Error> {
    let start = buf.len();
    buf.resize(start + max, 0);
    loop {
        match reader.read(&mut buf[start..]) {
            Ok(n) => {
                buf.truncate(start + n);
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                buf.truncate(start);
                return Err(Error::Io(e));
            }
        }
    }
}

fn read_u32(b: &[u8], be: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

fn read_u16(b: &[u8], be: bool) -> u16 {
    let a = [b[0], b[1]];
    if be {
        u16::from_be_bytes(a)
    } else {
        u16::from_le_bytes(a)
    }
}
