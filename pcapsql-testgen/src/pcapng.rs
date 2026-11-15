//! The PCAPNG builder.

use crate::model::{ExpectedFrame, GeneratedCapture};

/// Block type magics (little-endian on disk).
const SHB_TYPE: u32 = 0x0A0D_0D0A;
pub(crate) const IDB_TYPE: u32 = 0x0000_0001;
pub(crate) const EPB_TYPE: u32 = 0x0000_0006;
/// Byte-order magic stored in the SHB.
const BOM_MAGIC: u32 = 0x1A2B_3C4D;
/// Option code for `if_tsresol`.
const OPT_IF_TSRESOL: u16 = 9;
const OPT_IF_TSOFFSET: u16 = 14;
/// Option code for `opt_endofopt`.
const OPT_ENDOFOPT: u16 = 0;

/// One interface description within a section.
#[derive(Clone, Debug)]
pub struct PcapngInterface {
    pub link_type: u16,
    /// Raw `if_tsresol` byte. Bit 7 clear: decimal exponent (3/6/9 give an
    /// exact nanosecond conversion). Bit 7 set: binary exponent, e.g. `0x8A`
    /// = 2^-10 s per tick, which exercises the power-of-two branch readers
    /// must implement.
    pub tsresol: u8,
    pub snaplen: u32,
    /// `if_tsoffset` option (seconds added to every timestamp of this
    /// interface), written as option 14 when non-zero and absent otherwise.
    pub if_tsoffset: i64,
}

/// One packet (Enhanced Packet Block) within a section.
///
/// The on-disk 64-bit tick count is `ts_sec*resolution + ts_frac_units`, where
/// `resolution = tsresol_units(tsresol)` of the referenced interface. `interface_id` is the
/// index into the section's `interfaces` list.
#[derive(Clone, Debug)]
pub struct PcapngPacket {
    pub interface_id: u32,
    pub ts_sec: u64,
    pub ts_frac_units: u64,
    pub data: Vec<u8>,
    pub origlen: u32,
}

/// One section: a set of interfaces (IDBs) followed by packets (EPBs).
#[derive(Clone, Debug)]
pub struct PcapngSection {
    pub interfaces: Vec<PcapngInterface>,
    pub packets: Vec<PcapngPacket>,
}

/// One block within a section, in exact on-disk order: an interface declaration
/// (IDB) or a packet (EPB).
///
/// This is the general form used to express captures where an interface is
/// declared *mid-stream* — after one or more packets have already been written —
/// which [`PcapngSection`] (all IDBs, then all EPBs) cannot represent. Interface
/// IDs are assigned in IDB appearance order across the section, exactly as a
/// reader assigns them, so a [`PcapngBlock::Packet`]'s `interface_id` must refer
/// to an interface whose IDB appears earlier in the same section.
#[derive(Clone, Debug)]
pub enum PcapngBlock {
    Interface(PcapngInterface),
    Packet(PcapngPacket),
}

/// One section as an explicit, ordered list of blocks (IDBs and EPBs interleaved
/// exactly as they appear on disk). See [`pcapng_ordered`].
#[derive(Clone, Debug)]
pub struct PcapngOrderedSection {
    pub blocks: Vec<PcapngBlock>,
}

/// Decode a PCAPNG `if_tsresol` byte into units per second (decimal or binary).
///
/// Mirrors the pcapng specification: bit 7 clear ⇒ `10^low7`, bit 7 set ⇒
/// `2^low7`. This is the ground-truth definition the reader is checked against.
/// `None` for an exponent that does not fit a `u64` (decimal > 19, binary >
/// 63); such a byte cannot be written by the generator, since no tick count
/// could be computed for it.
pub fn try_tsresol_units(tsresol: u8) -> Option<u64> {
    let exp = u32::from(tsresol & 0x7F);
    if tsresol & 0x80 == 0 {
        10u64.checked_pow(exp)
    } else {
        1u64.checked_shl(exp).filter(|_| exp <= 63)
    }
}

/// [`try_tsresol_units`] for a resolution the generator is about to write.
///
/// # Panics
///
/// On an unrepresentable `if_tsresol` byte, with a message naming it: a test
/// spec asking for one is a bug in the test, not a capture to produce.
pub fn tsresol_units(tsresol: u8) -> u64 {
    try_tsresol_units(tsresol).unwrap_or_else(|| {
        panic!(
            "if_tsresol {tsresol:#04x} is not representable as units per second \
             (decimal exponent > 19 or binary exponent > 63)"
        )
    })
}

/// PCAPNG nanosecond formula for an interface.
///
/// `ticks = (ts_high<<32)|ts_low`; `ns = ticks * 1e9 / resolution +
/// if_tsoffset * 1e9`, saturating at the `i64` bounds like the reader does.
#[inline]
pub(crate) fn pcapng_ts_ns(ticks: u64, resolution: u64, if_tsoffset: i64) -> i64 {
    let ns = ((ticks as u128 * 1_000_000_000u128) / resolution as u128) as i128
        + i128::from(if_tsoffset) * 1_000_000_000;
    ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// PCAPNG byte sink with block helpers; writes every multi-byte field in the
/// section's byte order (little-endian unless `big_endian` is set).
struct NgWriter {
    buf: Vec<u8>,
    big_endian: bool,
}

impl NgWriter {
    fn new(big_endian: bool) -> Self {
        Self {
            buf: Vec::new(),
            big_endian,
        }
    }

    #[inline]
    fn u16(&mut self, v: u16) {
        if self.big_endian {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    #[inline]
    fn u32(&mut self, v: u32) {
        if self.big_endian {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    #[inline]
    fn i64(&mut self, v: i64) {
        if self.big_endian {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    #[inline]
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Write the Section Header Block (fixed 28 bytes, no options).
    fn shb(&mut self) {
        let total: u32 = 28;
        self.u32(SHB_TYPE);
        self.u32(total);
        self.u32(BOM_MAGIC);
        self.u16(1); // major
        self.u16(0); // minor
        self.i64(-1); // section_length = 0xFFFF...FFFF
        self.u32(total);
    }

    /// Write an Interface Description Block with the `if_tsresol` option.
    ///
    /// Total length = 4(type) + 4(len) + 8(body: linktype/reserved/snaplen)
    /// + 8(tsresol option, padded) + 4(endofopt) + 4(len) = 32 bytes.
    fn idb(&mut self, iface: &PcapngInterface) {
        // 32 bytes with the if_tsresol option; 12 more for if_tsoffset.
        let total: u32 = if iface.if_tsoffset != 0 { 44 } else { 32 };
        self.u32(IDB_TYPE);
        self.u32(total);
        self.u16(iface.link_type);
        self.u16(0); // reserved
        self.u32(iface.snaplen);
        // if_tsresol option: code=9, len=1, value byte, padded to 4 bytes.
        self.u16(OPT_IF_TSRESOL);
        self.u16(1);
        self.bytes(&[iface.tsresol, 0, 0, 0]);
        if iface.if_tsoffset != 0 {
            // if_tsoffset option: code=14, len=8, i64 seconds in the
            // section's byte order (like every other multi-byte field).
            self.u16(OPT_IF_TSOFFSET);
            self.u16(8);
            self.i64(iface.if_tsoffset);
        }
        // opt_endofopt: code=0, len=0.
        self.u16(OPT_ENDOFOPT);
        self.u16(0);
        self.u32(total);
    }

    /// Write an Enhanced Packet Block.
    ///
    /// Layout: type, total_len, interface_id, ts_high, ts_low, caplen, origlen,
    /// packet data (caplen bytes padded to a multiple of 4 with zeros),
    /// total_len. No options.
    fn epb(&mut self, interface_id: u32, ts_high: u32, ts_low: u32, data: &[u8], origlen: u32) {
        let caplen = data.len() as u32;
        let pad = (4 - (data.len() % 4)) % 4;
        // 4(type)+4(len)+4(if_id)+4(ts_high)+4(ts_low)+4(caplen)+4(origlen)
        // + data + pad + 4(len)
        let total = 32 + data.len() + pad;
        let total = total as u32;

        self.u32(EPB_TYPE);
        self.u32(total);
        self.u32(interface_id);
        self.u32(ts_high);
        self.u32(ts_low);
        self.u32(caplen);
        self.u32(origlen);
        self.bytes(data);
        for _ in 0..pad {
            self.buf.push(0);
        }
        self.u32(total);
    }
}

/// Build a PCAPNG capture from one or more sections.
///
/// All blocks are little-endian and padded so each block's total length is a
/// multiple of 4. `block_total_length` appears right after `block_type`, is
/// repeated at the end, and includes the 12 bytes of type + len + len.
///
/// Frame numbering for `expected` is global and increments for every EPB across
/// all sections, in file order. Interface IDs are per-section, 0-based in IDB
/// order; `PcapngPacket::interface_id` indexes its section's `interfaces`.
///
/// This is the common case where every IDB precedes every EPB. It is a thin
/// wrapper over [`pcapng_ordered`]: each section becomes "all interfaces, then
/// all packets", which is byte-identical to emitting them in that order.
pub fn pcapng(sections: &[PcapngSection]) -> GeneratedCapture {
    pcapng_with_byte_order(sections, false)
}

/// [`pcapng`] with an explicit section byte order (`true` = big-endian).
///
/// Big-endian PCAPNG is valid per the specification (the SHB byte-order magic
/// tells readers which it is) and is where header-synthesis code that assumes
/// little-endian breaks.
pub fn pcapng_with_byte_order(sections: &[PcapngSection], big_endian: bool) -> GeneratedCapture {
    let ordered: Vec<PcapngOrderedSection> = sections
        .iter()
        .map(|s| {
            let mut blocks = Vec::with_capacity(s.interfaces.len() + s.packets.len());
            blocks.extend(s.interfaces.iter().cloned().map(PcapngBlock::Interface));
            blocks.extend(s.packets.iter().cloned().map(PcapngBlock::Packet));
            PcapngOrderedSection { blocks }
        })
        .collect();
    pcapng_ordered_with_byte_order(&ordered, big_endian)
}

/// Build a PCAPNG capture from sections whose blocks are emitted in exactly the
/// given order, allowing an IDB to appear *mid-stream* (after one or more EPBs).
///
/// Within each section the interface table is built up as IDBs are encountered,
/// exactly as a reader does: the `interface_id` of each [`PcapngBlock::Packet`]
/// indexes the interfaces declared *so far* in that section. A new section
/// header resets the table. Timestamp and link-type ground truth are computed
/// against the referenced interface, identically to [`pcapng`].
pub fn pcapng_ordered(sections: &[PcapngOrderedSection]) -> GeneratedCapture {
    pcapng_ordered_with_byte_order(sections, false)
}

/// [`pcapng_ordered`] with an explicit section byte order (`true` = big-endian).
pub fn pcapng_ordered_with_byte_order(
    sections: &[PcapngOrderedSection],
    big_endian: bool,
) -> GeneratedCapture {
    let mut w = NgWriter::new(big_endian);
    let mut expected = Vec::new();
    let mut frame_number: u64 = 0;

    for section in sections {
        w.shb();
        // Interface table for THIS section, grown as IDBs appear in the stream.
        let mut interfaces: Vec<PcapngInterface> = Vec::new();
        for block in &section.blocks {
            match block {
                PcapngBlock::Interface(iface) => {
                    w.idb(iface);
                    interfaces.push(iface.clone());
                }
                PcapngBlock::Packet(p) => {
                    let iface = &interfaces[p.interface_id as usize];
                    let resolution = tsresol_units(iface.tsresol);
                    let ticks = p.ts_sec * resolution + p.ts_frac_units;
                    let ts_high = (ticks >> 32) as u32;
                    let ts_low = (ticks & 0xFFFF_FFFF) as u32;

                    w.epb(p.interface_id, ts_high, ts_low, &p.data, p.origlen);

                    frame_number += 1;
                    expected.push(ExpectedFrame {
                        frame_number,
                        timestamp_ns: pcapng_ts_ns(ticks, resolution, iface.if_tsoffset),
                        caplen: p.data.len() as u32,
                        origlen: p.origlen,
                        link_type: iface.link_type as u32,
                        data: p.data.clone(),
                    });
                }
            }
        }
    }

    GeneratedCapture {
        bytes: w.buf,
        expected,
    }
}
