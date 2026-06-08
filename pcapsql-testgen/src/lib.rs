//! Deterministic PCAP / PCAPNG test-data generator.
//!
//! This crate produces byte-exact `.pcap` and `.pcapng` files together with a
//! *ground-truth* model of every frame they contain. It is foundational test
//! infrastructure for the parallel-parsing refactor: given the same inputs the
//! output is byte-identical, and the bytes are guaranteed (by the crate's own
//! tests) to be parseable by `pcap_parser` 0.15 — the same crate the rest of
//! the project relies on.
//!
//! # Layout responsibilities
//!
//! The generator is the single source of truth for two things that the readers
//! must agree with:
//!
//! 1. **Byte layout** of every header / record / block (little- or big-endian as
//!    appropriate, padding rules, length fields).
//! 2. **Timestamp math** — the `timestamp_ns` value in [`ExpectedFrame`] is
//!    computed here with the exact formulas documented on the builder functions,
//!    so a reader written to those same formulas will match bit-for-bit.
//!
//! Nothing here depends on `pcapsql-core` (to avoid a dependency cycle) and the
//! library has no runtime dependencies at all: the PRNG is implemented inline.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Deterministic PRNG: SplitMix64
// ---------------------------------------------------------------------------

/// A tiny, fully-deterministic PRNG (SplitMix64).
///
/// SplitMix64 is the standard "seed expander" used to initialise other PRNGs;
/// it is more than good enough for generating reproducible test payloads and
/// sizes. Identical seeds produce identical streams on every platform, which is
/// what makes the generated captures byte-identical.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Create a new generator from a seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Return the next 64-bit value and advance the state.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        // Constants from the reference SplitMix64 implementation.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Return a value in `[low, high]` inclusive. If `low >= high`, returns `low`.
    #[inline]
    pub fn next_in_range(&mut self, low: usize, high: usize) -> usize {
        if low >= high {
            return low;
        }
        let span = (high - low + 1) as u64;
        low + (self.next_u64() % span) as usize
    }
}

// ---------------------------------------------------------------------------
// Ground-truth model
// ---------------------------------------------------------------------------

/// One captured frame, as the generator knows it to be.
///
/// Other crates compare their parsed output against this. Every field is the
/// authoritative value; in particular [`Self::data`] is exactly `caplen` bytes
/// (the captured bytes, without any on-disk padding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedFrame {
    /// 1-indexed frame number, global across all sections.
    pub frame_number: u64,
    /// Timestamp in nanoseconds, computed with the per-format formulas.
    pub timestamp_ns: i64,
    /// Captured length in bytes (== `data.len()`).
    pub caplen: u32,
    /// Original on-wire length in bytes (may exceed `caplen`).
    pub origlen: u32,
    /// Link-layer type (e.g. 1 = Ethernet).
    pub link_type: u32,
    /// Exactly `caplen` captured bytes.
    pub data: Vec<u8>,
}

/// A generated capture: the raw file bytes plus the ground-truth frames.
#[derive(Clone, Debug)]
pub struct GeneratedCapture {
    /// The full `.pcap` / `.pcapng` file content.
    pub bytes: Vec<u8>,
    /// Ground truth, in file order.
    pub expected: Vec<ExpectedFrame>,
}

// ---------------------------------------------------------------------------
// Legacy pcap builder
// ---------------------------------------------------------------------------

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
    fn is_nano(self) -> bool {
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

// ---------------------------------------------------------------------------
// PCAPNG builder
// ---------------------------------------------------------------------------

/// Block type magics (little-endian on disk).
const SHB_TYPE: u32 = 0x0A0D_0D0A;
const IDB_TYPE: u32 = 0x0000_0001;
const EPB_TYPE: u32 = 0x0000_0006;
/// Byte-order magic stored in the SHB.
const BOM_MAGIC: u32 = 0x1A2B_3C4D;
/// Option code for `if_tsresol`.
const OPT_IF_TSRESOL: u16 = 9;
/// Option code for `opt_endofopt`.
const OPT_ENDOFOPT: u16 = 0;

/// One interface description within a section.
#[derive(Clone, Debug)]
pub struct PcapngInterface {
    pub link_type: u16,
    /// Decimal timestamp resolution exponent; only {3,6,9} are used so the
    /// nanosecond conversion is exact.
    pub tsresol: u8,
    pub snaplen: u32,
}

/// One packet (Enhanced Packet Block) within a section.
///
/// The on-disk 64-bit tick count is `ts_sec*resolution + ts_frac_units`, where
/// `resolution = 10^tsresol` of the referenced interface. `interface_id` is the
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

/// `10^exp` as a u64 (exp expected to be one of {3,6,9}).
#[inline]
fn pow10(exp: u8) -> u64 {
    10u64.pow(exp as u32)
}

/// PCAPNG nanosecond formula for a decimal resolution.
///
/// `ticks = (ts_high<<32)|ts_low`; `ns = ticks * 1e9 / resolution`.
/// `ts_offset` is always 0.
#[inline]
fn pcapng_ts_ns(ticks: u64, resolution: u64) -> i64 {
    ((ticks as u128 * 1_000_000_000u128) / resolution as u128) as i64
}

/// Little-endian PCAPNG byte sink with block helpers.
struct NgWriter {
    buf: Vec<u8>,
}

impl NgWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    #[inline]
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
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
        let total: u32 = 32;
        self.u32(IDB_TYPE);
        self.u32(total);
        self.u16(iface.link_type);
        self.u16(0); // reserved
        self.u32(iface.snaplen);
        // if_tsresol option: code=9, len=1, value byte, padded to 4 bytes.
        self.u16(OPT_IF_TSRESOL);
        self.u16(1);
        self.bytes(&[iface.tsresol, 0, 0, 0]);
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
pub fn pcapng(sections: &[PcapngSection]) -> GeneratedCapture {
    let mut w = NgWriter::new();
    let mut expected = Vec::new();
    let mut frame_number: u64 = 0;

    for section in sections {
        w.shb();
        for iface in &section.interfaces {
            w.idb(iface);
        }

        for p in &section.packets {
            let iface = &section.interfaces[p.interface_id as usize];
            let resolution = pow10(iface.tsresol);
            let ticks = p.ts_sec * resolution + p.ts_frac_units;
            let ts_high = (ticks >> 32) as u32;
            let ts_low = (ticks & 0xFFFF_FFFF) as u32;

            w.epb(p.interface_id, ts_high, ts_low, &p.data, p.origlen);

            frame_number += 1;
            expected.push(ExpectedFrame {
                frame_number,
                timestamp_ns: pcapng_ts_ns(ticks, resolution),
                caplen: p.data.len() as u32,
                origlen: p.origlen,
                link_type: iface.link_type as u32,
                data: p.data.clone(),
            });
        }
    }

    GeneratedCapture {
        bytes: w.buf,
        expected,
    }
}

// ---------------------------------------------------------------------------
// High-level deterministic generator
// ---------------------------------------------------------------------------

/// Output format selector for [`generate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    LegacyLeMicro,
    LegacyBeMicro,
    LegacyLeNano,
    LegacyBeNano,
    Pcapng,
}

/// Full specification for a deterministic capture.
#[derive(Clone, Debug)]
pub struct CaptureSpec {
    pub format: Format,
    pub seed: u64,
    pub packet_count: usize,
    /// Captured data size lower bound (>= 14 for ethernet).
    pub min_size: usize,
    pub max_size: usize,
    /// Link type for legacy and single-interface pcapng (1 = Ethernet default).
    pub link_type: u16,
    /// pcapng-only: tsresol per interface for the FIRST section.
    pub interfaces: Vec<u8>,
    /// pcapng-only: number of SHB sections (>= 1); each copies `interfaces`.
    pub sections: usize,
    /// pcapng-only: if true, after half a section's packets add another IDB
    /// (tsresol 9) and route later packets to it.
    pub add_interface_midstream: bool,
}

impl Default for CaptureSpec {
    fn default() -> Self {
        Self {
            format: Format::LegacyLeMicro,
            seed: 0,
            packet_count: 8,
            min_size: 14,
            max_size: 256,
            link_type: 1,
            interfaces: vec![6],
            sections: 1,
            add_interface_midstream: false,
        }
    }
}

/// Generate deterministic captured bytes for one frame.
///
/// The payload is a byte pattern derived from `frame_number` and `seed`, so the
/// content is reproducible *and* verifiable. When `len >= 14` the first 14
/// bytes are shaped to look like a minimal Ethernet header (dst MAC, src MAC,
/// EtherType 0x0800); the remainder is the seeded pattern. Correctness only
/// requires determinism, but the ethernet-looking prefix keeps fixtures
/// realistic.
fn make_payload(seed: u64, frame_number: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    // Per-frame byte generator: a small SplitMix seeded from seed+frame.
    let mut rng = SplitMix64::new(seed ^ frame_number.wrapping_mul(0x100_0000_01b3));

    if len >= 14 {
        // Minimal ethernet-looking header. The MACs embed the frame number so
        // the bytes are still derived deterministically and are verifiable.
        let fb = frame_number.to_le_bytes();
        // dst MAC
        out.extend_from_slice(&[0x02, fb[0], fb[1], fb[2], fb[3], fb[4]]);
        // src MAC
        out.extend_from_slice(&[0x02, 0x00, fb[0], fb[1], fb[2], fb[3]]);
        // EtherType IPv4
        out.extend_from_slice(&[0x08, 0x00]);
    }

    while out.len() < len {
        out.push((rng.next_u64() & 0xFF) as u8);
    }
    out.truncate(len);
    out
}

/// Generate a deterministic capture from a [`CaptureSpec`].
///
/// Sizes and contents derive entirely from `seed`, so calling `generate` twice
/// with the same spec yields byte-identical output. Timestamps increase
/// monotonically across the whole capture.
pub fn generate(spec: &CaptureSpec) -> GeneratedCapture {
    match spec.format {
        Format::LegacyLeMicro => generate_legacy(spec, LegacyVariant::LeMicro),
        Format::LegacyBeMicro => generate_legacy(spec, LegacyVariant::BeMicro),
        Format::LegacyLeNano => generate_legacy(spec, LegacyVariant::LeNano),
        Format::LegacyBeNano => generate_legacy(spec, LegacyVariant::BeNano),
        Format::Pcapng => generate_pcapng(spec),
    }
}

/// Base epoch (2021-01-01T00:00:00Z-ish) so timestamps look plausible.
const BASE_SEC: u64 = 1_609_459_200;

fn generate_legacy(spec: &CaptureSpec, variant: LegacyVariant) -> GeneratedCapture {
    let mut size_rng = SplitMix64::new(spec.seed);
    let snaplen: u32 = 262_144;
    let mut packets = Vec::with_capacity(spec.packet_count);

    for i in 0..spec.packet_count {
        let frame_number = (i + 1) as u64;
        let len = size_rng.next_in_range(spec.min_size, spec.max_size);
        let data = make_payload(spec.seed, frame_number, len);

        // Monotonic timestamps: one packet per ~millisecond.
        let ts_sec = (BASE_SEC + (i as u64) / 1000) as u32;
        let within = (i as u64) % 1000; // 0..999 ms
        let ts_frac = if variant.is_nano() {
            (within * 1_000_000) as u32 // ns
        } else {
            (within * 1_000) as u32 // us
        };

        let origlen = data.len() as u32;
        packets.push(GenPacket {
            ts_sec,
            ts_frac,
            data,
            origlen,
        });
    }

    legacy_pcap(variant, spec.link_type, snaplen, &packets)
}

fn generate_pcapng(spec: &CaptureSpec) -> GeneratedCapture {
    assert!(spec.sections >= 1, "sections must be >= 1");
    assert!(
        !spec.interfaces.is_empty(),
        "pcapng requires at least one interface tsresol"
    );

    let mut size_rng = SplitMix64::new(spec.seed);
    let snaplen: u32 = 262_144;

    // Distribute packet_count across sections as evenly as possible, in order.
    let base = spec.packet_count / spec.sections;
    let extra = spec.packet_count % spec.sections;

    let mut sections = Vec::with_capacity(spec.sections);
    let mut global_frame: u64 = 0;

    for s in 0..spec.sections {
        // Interfaces: a copy of `spec.interfaces` for this section.
        let mut interfaces: Vec<PcapngInterface> = spec
            .interfaces
            .iter()
            .map(|&tsresol| PcapngInterface {
                link_type: spec.link_type,
                tsresol,
                snaplen,
            })
            .collect();

        let count = base + if s < extra { 1 } else { 0 };

        // Optionally add a second interface partway through this section.
        let midstream_iface_id = interfaces.len() as u32;
        let switch_at = if spec.add_interface_midstream {
            interfaces.push(PcapngInterface {
                link_type: spec.link_type,
                tsresol: 9,
                snaplen,
            });
            count / 2
        } else {
            usize::MAX
        };

        let mut packets = Vec::with_capacity(count);
        for j in 0..count {
            global_frame += 1;
            let len = size_rng.next_in_range(spec.min_size, spec.max_size);
            let data = make_payload(spec.seed, global_frame, len);

            // Route to the midstream interface for the second half.
            let interface_id = if spec.add_interface_midstream && j >= switch_at {
                midstream_iface_id
            } else {
                // Spread across the section's base interfaces deterministically.
                (j % spec.interfaces.len()) as u32
            };

            let tsresol = interfaces[interface_id as usize].tsresol;
            let resolution = pow10(tsresol);

            // Monotonic timestamps across the whole file: one frame per ~ms.
            let idx = global_frame - 1;
            let ts_sec = BASE_SEC + idx / 1000;
            let within_ms = idx % 1000;
            // fractional units = within_ms milliseconds expressed in this
            // interface's resolution: ms * (resolution / 1000).
            let ts_frac_units = within_ms * (resolution / 1000);

            let origlen = data.len() as u32;
            packets.push(PcapngPacket {
                interface_id,
                ts_sec,
                ts_frac_units,
                data,
                origlen,
            });
        }

        sections.push(PcapngSection {
            interfaces,
            packets,
        });
    }

    pcapng(&sections)
}

// ---------------------------------------------------------------------------
// Special-case captures
// ---------------------------------------------------------------------------

/// A single legacy (LeMicro) frame whose captured length is exactly `caplen`
/// bytes. Pass a value larger than the reader's buffer (e.g. > 262_144) to
/// exercise the oversized-frame path.
pub fn oversized_frame_capture(caplen: usize) -> GeneratedCapture {
    let data = make_payload(OVERSIZE_SEED, 1, caplen);
    let p = GenPacket {
        ts_sec: BASE_SEC as u32,
        ts_frac: 0,
        origlen: data.len() as u32,
        data,
    };
    // snaplen large enough to admit the frame.
    legacy_pcap(LegacyVariant::LeMicro, 1, (caplen as u32).max(262_144), &[p])
}

/// A jumbo frame sized to straddle an arbitrary partition seam, surrounded by
/// normal frames. Legacy LeMicro.
///
/// Produces `normal_count` small frames, then one frame of `jumbo_caplen`
/// captured bytes, then `normal_count` more small frames.
pub fn jumbo_straddle_capture(
    seed: u64,
    jumbo_caplen: usize,
    normal_count: usize,
) -> GeneratedCapture {
    let mut size_rng = SplitMix64::new(seed);
    let mut packets = Vec::with_capacity(normal_count * 2 + 1);
    let mut frame_number: u64 = 0;

    let push_normal = |packets: &mut Vec<GenPacket>, frame_number: &mut u64, rng: &mut SplitMix64| {
        *frame_number += 1;
        let len = rng.next_in_range(64, 256);
        let data = make_payload(seed, *frame_number, len);
        let ts_sec = (BASE_SEC + *frame_number) as u32;
        packets.push(GenPacket {
            ts_sec,
            ts_frac: 0,
            origlen: data.len() as u32,
            data,
        });
    };

    for _ in 0..normal_count {
        push_normal(&mut packets, &mut frame_number, &mut size_rng);
    }

    // The jumbo frame.
    frame_number += 1;
    let jumbo = make_payload(seed, frame_number, jumbo_caplen);
    packets.push(GenPacket {
        ts_sec: (BASE_SEC + frame_number) as u32,
        ts_frac: 0,
        origlen: jumbo.len() as u32,
        data: jumbo,
    });

    for _ in 0..normal_count {
        push_normal(&mut packets, &mut frame_number, &mut size_rng);
    }

    legacy_pcap(
        LegacyVariant::LeMicro,
        1,
        (jumbo_caplen as u32).max(262_144),
        &packets,
    )
}

/// A truncated capture: a valid legacy (LeMicro) capture with the final bytes
/// cut off the byte vector.
///
/// `expected` contains only the frames that remain fully present before the
/// truncation point. This simulates a file cut off mid-record.
pub fn truncated_capture(seed: u64) -> GeneratedCapture {
    // A modest capture with several frames.
    let spec = CaptureSpec {
        format: Format::LegacyLeMicro,
        seed,
        packet_count: 6,
        min_size: 40,
        max_size: 120,
        link_type: 1,
        ..Default::default()
    };
    let full = generate(&spec);

    // Drop the last frame entirely, then cut a few extra bytes so the new last
    // record is also incomplete on disk. Recompute which frames remain wholly
    // present so `expected` is exactly the complete prefix.
    //
    // We cut off everything belonging to the final expected frame plus 5 bytes
    // of the (now) last record's data, leaving its header parseable but its
    // data short — which `pcap_parser` reports as Incomplete.
    let last = full
        .expected
        .last()
        .expect("capture must have at least one frame");
    // Bytes consumed by the final frame's record = 16-byte record header + caplen.
    let final_record_bytes = 16 + last.caplen as usize;
    // Also nibble 5 bytes off the data of the new last record.
    let cut = final_record_bytes + 5;

    let mut bytes = full.bytes.clone();
    let keep = bytes.len().saturating_sub(cut);
    bytes.truncate(keep);

    // Expected = every frame except the final one (which we removed) and the
    // new-last frame (which is now incomplete on disk).
    let kept_frames = full.expected.len().saturating_sub(2);
    let expected = full.expected.into_iter().take(kept_frames).collect();

    GeneratedCapture { bytes, expected }
}

/// Seed used by [`oversized_frame_capture`].
const OVERSIZE_SEED: u64 = 0x0123_4567_89AB_CDEF;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
    use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError as PpError, PcapNGReader};
    use std::io::Cursor;

    /// Parse a capture's bytes with `pcap_parser` and return the parsed frames
    /// as `(caplen, origlen, link_type, ts_ns, data)` tuples, in file order.
    fn parse_with_pcap_parser(gc: &GeneratedCapture, is_pcapng: bool) -> Vec<ParsedFrame> {
        if is_pcapng {
            parse_ng(&gc.bytes)
        } else {
            parse_legacy(&gc.bytes)
        }
    }

    #[derive(Debug)]
    struct ParsedFrame {
        caplen: u32,
        origlen: u32,
        link_type: u32,
        ts_ns: i64,
        data: Vec<u8>,
    }

    fn parse_legacy(bytes: &[u8]) -> Vec<ParsedFrame> {
        let mut out = Vec::new();
        let mut reader = LegacyPcapReader::new(65536, Cursor::new(bytes)).expect("reader");
        let mut nano = false;
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            // Detect nanosecond precision via the parsed header
                            // (handles both LE and BE magic forms).
                            nano = hdr.is_nanosecond_precision();
                        }
                        PcapBlockOwned::Legacy(pkt) => {
                            let sec = pkt.ts_sec as i64;
                            let frac = pkt.ts_usec as i64; // field is "usec" but holds nsec for nano
                            let ts_ns = if nano {
                                sec * 1_000_000_000 + frac
                            } else {
                                sec * 1_000_000_000 + frac * 1_000
                            };
                            out.push(ParsedFrame {
                                caplen: pkt.caplen,
                                origlen: pkt.origlen,
                                link_type: 0, // filled by caller from header if needed
                                ts_ns,
                                data: pkt.data.to_vec(),
                            });
                        }
                        _ => {}
                    }
                    reader.consume(offset);
                }
                // Eof / UnexpectedEof: stop. UnexpectedEof occurs when a record
                // header promises more bytes than remain (e.g. a truncated
                // file); we return the complete frames read so far.
                Err(PpError::Eof) | Err(PpError::UnexpectedEof) => break,
                Err(PpError::Incomplete(_)) => {
                    if reader.refill().is_err() {
                        break;
                    }
                }
                Err(e) => panic!("legacy parse error: {e:?}"),
            }
        }
        out
    }

    /// Parse legacy, also capturing the link type from the global header.
    fn parse_legacy_with_linktype(bytes: &[u8]) -> (u32, Vec<ParsedFrame>) {
        let mut link_type = 0u32;
        let mut out = Vec::new();
        let mut reader = LegacyPcapReader::new(65536, Cursor::new(bytes)).expect("reader");
        let mut nano = false;
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            link_type = hdr.network.0 as u32;
                            nano = hdr.is_nanosecond_precision();
                        }
                        PcapBlockOwned::Legacy(pkt) => {
                            let sec = pkt.ts_sec as i64;
                            let frac = pkt.ts_usec as i64;
                            let ts_ns = if nano {
                                sec * 1_000_000_000 + frac
                            } else {
                                sec * 1_000_000_000 + frac * 1_000
                            };
                            out.push(ParsedFrame {
                                caplen: pkt.caplen,
                                origlen: pkt.origlen,
                                link_type,
                                ts_ns,
                                data: pkt.data.to_vec(),
                            });
                        }
                        _ => {}
                    }
                    reader.consume(offset);
                }
                Err(PpError::Eof) => break,
                Err(PpError::Incomplete(_)) => {
                    if reader.refill().is_err() {
                        break;
                    }
                }
                Err(e) => panic!("legacy parse error: {e:?}"),
            }
        }
        (link_type, out)
    }

    fn parse_ng(bytes: &[u8]) -> Vec<ParsedFrame> {
        use pcap_parser::pcapng::Block;
        let mut out = Vec::new();
        // Per-section interface table: (link_type, resolution).
        let mut ifaces: Vec<(u32, u64)> = Vec::new();
        let mut reader = PcapNGReader::new(65536, Cursor::new(bytes)).expect("reader");
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::NG(ng) = block {
                        match ng {
                            Block::SectionHeader(_) => {
                                ifaces.clear();
                            }
                            Block::InterfaceDescription(idb) => {
                                let res = idb.ts_resolution().expect("valid tsresol");
                                ifaces.push((idb.linktype.0 as u32, res));
                            }
                            Block::EnhancedPacket(epb) => {
                                let (lt, res) = ifaces[epb.if_id as usize];
                                let ticks =
                                    ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
                                let ts_ns = ((ticks as u128 * 1_000_000_000u128)
                                    / res as u128)
                                    as i64;
                                out.push(ParsedFrame {
                                    caplen: epb.caplen,
                                    origlen: epb.origlen,
                                    link_type: lt,
                                    ts_ns,
                                    // packet_data() strips the on-disk padding.
                                    data: epb.packet_data().to_vec(),
                                });
                            }
                            _ => {}
                        }
                    }
                    reader.consume(offset);
                }
                Err(PpError::Eof) => break,
                Err(PpError::Incomplete(_)) => {
                    if reader.refill().is_err() {
                        break;
                    }
                }
                Err(e) => panic!("pcapng parse error: {e:?}"),
            }
        }
        out
    }

    /// Assert that the ground truth matches what pcap_parser reads back.
    fn assert_roundtrip(gc: &GeneratedCapture, is_pcapng: bool) {
        let parsed = parse_with_pcap_parser(gc, is_pcapng);
        assert_eq!(
            parsed.len(),
            gc.expected.len(),
            "packet count mismatch (parsed {} vs expected {})",
            parsed.len(),
            gc.expected.len()
        );
        for (p, e) in parsed.iter().zip(gc.expected.iter()) {
            assert_eq!(p.caplen, e.caplen, "caplen mismatch frame {}", e.frame_number);
            assert_eq!(
                p.origlen, e.origlen,
                "origlen mismatch frame {}",
                e.frame_number
            );
            assert_eq!(
                p.data, e.data,
                "data mismatch frame {} (len {} vs {})",
                e.frame_number,
                p.data.len(),
                e.data.len()
            );
            assert_eq!(p.ts_ns, e.timestamp_ns, "ts mismatch frame {}", e.frame_number);
            if is_pcapng {
                assert_eq!(
                    p.link_type, e.link_type,
                    "link_type mismatch frame {}",
                    e.frame_number
                );
            }
        }
    }

    // --- Low-level legacy variants -------------------------------------------

    fn sample_legacy(variant: LegacyVariant) -> GeneratedCapture {
        let packets = vec![
            GenPacket {
                ts_sec: 1_600_000_000,
                ts_frac: 123_456,
                data: vec![0xaa; 20],
                origlen: 20,
            },
            GenPacket {
                ts_sec: 1_600_000_001,
                ts_frac: 999_999,
                data: vec![0xbb; 60],
                origlen: 60,
            },
            GenPacket {
                ts_sec: 1_600_000_002,
                ts_frac: 0,
                data: (0..30u8).collect(),
                origlen: 100, // truncated frame: origlen > caplen
            },
        ];
        legacy_pcap(variant, 1, 65535, &packets)
    }

    #[test]
    fn legacy_le_micro_roundtrip() {
        let gc = sample_legacy(LegacyVariant::LeMicro);
        let (lt, parsed) = parse_legacy_with_linktype(&gc.bytes);
        assert_eq!(lt, 1);
        assert_eq!(parsed.len(), gc.expected.len());
        assert_roundtrip(&gc, false);
    }

    #[test]
    fn legacy_be_micro_roundtrip() {
        assert_roundtrip(&sample_legacy(LegacyVariant::BeMicro), false);
    }

    #[test]
    fn legacy_le_nano_roundtrip() {
        assert_roundtrip(&sample_legacy(LegacyVariant::LeNano), false);
    }

    #[test]
    fn legacy_be_nano_roundtrip() {
        assert_roundtrip(&sample_legacy(LegacyVariant::BeNano), false);
    }

    #[test]
    fn legacy_linktype_preserved() {
        let packets = vec![GenPacket {
            ts_sec: 1,
            ts_frac: 0,
            data: vec![1, 2, 3, 4],
            origlen: 4,
        }];
        for lt in [1u16, 101, 113, 127] {
            let gc = legacy_pcap(LegacyVariant::LeMicro, lt, 65535, &packets);
            let (parsed_lt, _) = parse_legacy_with_linktype(&gc.bytes);
            assert_eq!(parsed_lt, lt as u32);
            assert_eq!(gc.expected[0].link_type, lt as u32);
        }
    }

    // --- Low-level pcapng ----------------------------------------------------

    #[test]
    fn pcapng_single_section_roundtrip() {
        let section = PcapngSection {
            interfaces: vec![PcapngInterface {
                link_type: 1,
                tsresol: 6,
                snaplen: 65535,
            }],
            packets: vec![
                PcapngPacket {
                    interface_id: 0,
                    ts_sec: 1_600_000_000,
                    ts_frac_units: 500_000,
                    data: vec![0x11; 14],
                    origlen: 14,
                },
                PcapngPacket {
                    interface_id: 0,
                    ts_sec: 1_600_000_001,
                    ts_frac_units: 1, // forces non-4-aligned data path too
                    data: vec![0x22; 17], // not a multiple of 4 -> padding exercised
                    origlen: 17,
                },
            ],
        };
        let gc = pcapng(&[section]);
        assert_roundtrip(&gc, true);
    }

    #[test]
    fn pcapng_multi_iface_differing_tsresol_roundtrip() {
        let section = PcapngSection {
            interfaces: vec![
                PcapngInterface {
                    link_type: 1,
                    tsresol: 6,
                    snaplen: 65535,
                },
                PcapngInterface {
                    link_type: 1,
                    tsresol: 9,
                    snaplen: 65535,
                },
            ],
            packets: vec![
                PcapngPacket {
                    interface_id: 0,
                    ts_sec: 10,
                    ts_frac_units: 250_000, // us-resolution
                    data: vec![1; 30],
                    origlen: 30,
                },
                PcapngPacket {
                    interface_id: 1,
                    ts_sec: 11,
                    ts_frac_units: 250_000_000, // ns-resolution
                    data: vec![2; 31],
                    origlen: 31,
                },
            ],
        };
        assert_roundtrip(&pcapng(&[section]), true);
    }

    #[test]
    fn pcapng_multi_section_roundtrip() {
        let mk = |lt: u16, tsresol: u8, n: u64| PcapngSection {
            interfaces: vec![PcapngInterface {
                link_type: lt,
                tsresol,
                snaplen: 65535,
            }],
            packets: (0..n)
                .map(|i| PcapngPacket {
                    interface_id: 0,
                    ts_sec: 100 + i,
                    ts_frac_units: (i + 1) * 3,
                    data: vec![(i as u8).wrapping_add(1); 16 + i as usize],
                    origlen: 16 + i as u32,
                })
                .collect(),
        };
        let gc = pcapng(&[mk(1, 6, 3), mk(113, 9, 2)]);
        // Global frame numbering across sections.
        assert_eq!(gc.expected.len(), 5);
        assert_eq!(gc.expected[0].frame_number, 1);
        assert_eq!(gc.expected[4].frame_number, 5);
        // Link type differs by section.
        assert_eq!(gc.expected[0].link_type, 1);
        assert_eq!(gc.expected[3].link_type, 113);
        assert_roundtrip(&gc, true);
    }

    // --- High-level generate() across seeds/configs --------------------------

    fn legacy_specs() -> Vec<CaptureSpec> {
        let mut v = Vec::new();
        for &fmt in &[
            Format::LegacyLeMicro,
            Format::LegacyBeMicro,
            Format::LegacyLeNano,
            Format::LegacyBeNano,
        ] {
            for &seed in &[1u64, 42, 999, 0xDEAD_BEEF] {
                v.push(CaptureSpec {
                    format: fmt,
                    seed,
                    packet_count: 17,
                    min_size: 14,
                    max_size: 300,
                    link_type: 1,
                    ..Default::default()
                });
            }
        }
        v
    }

    fn pcapng_specs() -> Vec<CaptureSpec> {
        let mut v = Vec::new();
        for &seed in &[1u64, 42, 999, 0xDEAD_BEEF] {
            // single interface
            v.push(CaptureSpec {
                format: Format::Pcapng,
                seed,
                packet_count: 13,
                min_size: 14,
                max_size: 200,
                link_type: 1,
                interfaces: vec![6],
                sections: 1,
                add_interface_midstream: false,
            });
            // multi-iface differing tsresol
            v.push(CaptureSpec {
                format: Format::Pcapng,
                seed,
                packet_count: 16,
                min_size: 20,
                max_size: 180,
                link_type: 1,
                interfaces: vec![6, 9],
                sections: 1,
                add_interface_midstream: false,
            });
            // multi-section
            v.push(CaptureSpec {
                format: Format::Pcapng,
                seed,
                packet_count: 15,
                min_size: 18,
                max_size: 220,
                link_type: 1,
                interfaces: vec![3],
                sections: 3,
                add_interface_midstream: false,
            });
            // midstream interface
            v.push(CaptureSpec {
                format: Format::Pcapng,
                seed,
                packet_count: 14,
                min_size: 16,
                max_size: 160,
                link_type: 1,
                interfaces: vec![6],
                sections: 1,
                add_interface_midstream: true,
            });
            // multi-section + midstream combined
            v.push(CaptureSpec {
                format: Format::Pcapng,
                seed,
                packet_count: 20,
                min_size: 14,
                max_size: 140,
                link_type: 1,
                interfaces: vec![6, 9],
                sections: 2,
                add_interface_midstream: true,
            });
        }
        v
    }

    #[test]
    fn generate_legacy_roundtrip_all() {
        for spec in legacy_specs() {
            let gc = generate(&spec);
            assert_eq!(gc.expected.len(), spec.packet_count, "{spec:?}");
            assert_roundtrip(&gc, false);
            // Frame numbers are 1..=N in order.
            for (i, f) in gc.expected.iter().enumerate() {
                assert_eq!(f.frame_number, (i + 1) as u64);
            }
        }
    }

    #[test]
    fn generate_pcapng_roundtrip_all() {
        for spec in pcapng_specs() {
            let gc = generate(&spec);
            assert_eq!(gc.expected.len(), spec.packet_count, "{spec:?}");
            assert_roundtrip(&gc, true);
            for (i, f) in gc.expected.iter().enumerate() {
                assert_eq!(f.frame_number, (i + 1) as u64);
            }
        }
    }

    #[test]
    fn generate_is_deterministic() {
        let mut specs = legacy_specs();
        specs.extend(pcapng_specs());
        for spec in specs {
            let a = generate(&spec);
            let b = generate(&spec);
            assert_eq!(a.bytes, b.bytes, "non-deterministic bytes for {spec:?}");
            assert_eq!(a.expected, b.expected, "non-deterministic model for {spec:?}");
        }
    }

    #[test]
    fn midstream_interface_routes_later_packets() {
        let spec = CaptureSpec {
            format: Format::Pcapng,
            seed: 7,
            packet_count: 10,
            min_size: 14,
            max_size: 64,
            link_type: 1,
            interfaces: vec![6],
            sections: 1,
            add_interface_midstream: true,
        };
        let gc = generate(&spec);
        assert_roundtrip(&gc, true);
        // The first half uses tsresol-6, the second half uses tsresol-9; both
        // have link_type 1, so the round-trip alone proves routing/ts work.
        // Additionally confirm two interfaces actually got written by checking
        // there are two IDBs in the byte stream.
        let idb_count = count_blocks(&gc.bytes, IDB_TYPE);
        assert_eq!(idb_count, 2, "expected two IDBs for midstream interface");
    }

    /// Count little-endian PCAPNG blocks of a given type by walking total-length
    /// fields. Used only to sanity check block structure in tests.
    fn count_blocks(bytes: &[u8], block_type: u32) -> usize {
        let mut off = 0usize;
        let mut count = 0usize;
        while off + 8 <= bytes.len() {
            let bt = u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]);
            let len = u32::from_le_bytes([
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]) as usize;
            if len < 12 || off + len > bytes.len() {
                break;
            }
            if bt == block_type {
                count += 1;
            }
            off += len;
        }
        count
    }

    // --- Special-case captures -----------------------------------------------

    #[test]
    fn oversized_frame_exceeds_buffer() {
        let caplen = 300_000; // > 262_144
        let gc = oversized_frame_capture(caplen);
        assert_eq!(gc.expected.len(), 1);
        assert_eq!(gc.expected[0].caplen, caplen as u32);
        // A single frame larger than the read buffer is parseable once the
        // buffer is grown to fit it.
        let caplens = parse_legacy_caplens_growing(&gc.bytes, caplen + 65536);
        assert_eq!(caplens, vec![caplen as u32]);
    }

    #[test]
    fn jumbo_straddle_structure() {
        let gc = jumbo_straddle_capture(123, 280_000, 4);
        assert_eq!(gc.expected.len(), 9); // 4 + 1 + 4
                                          // Middle frame is the jumbo one.
        assert_eq!(gc.expected[4].caplen, 280_000);
        // Parse it back (growing buffer as needed for the jumbo frame).
        let parsed = parse_legacy_caplens_growing(&gc.bytes, 400_000);
        assert_eq!(parsed.len(), 9);
        assert_eq!(parsed[4], 280_000);
        for (p, e) in parsed.iter().zip(gc.expected.iter()) {
            assert_eq!(*p, e.caplen);
        }
    }

    /// Parse a legacy capture, returning each packet's caplen. Grows the reader
    /// buffer to `max_buf` when it reports the current frame is too large to
    /// store, so oversized/jumbo frames can be read back.
    fn parse_legacy_caplens_growing(bytes: &[u8], max_buf: usize) -> Vec<u32> {
        let mut reader = LegacyPcapReader::new(65536, Cursor::new(bytes)).expect("reader");
        let mut out = Vec::new();
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::Legacy(pkt) = block {
                        out.push(pkt.caplen);
                    }
                    reader.consume(offset);
                }
                Err(PpError::Eof) => break,
                Err(PpError::Incomplete(_)) => {
                    if reader.refill().is_err() {
                        break;
                    }
                }
                // A single record bigger than the buffer: grow then retry.
                Err(PpError::BufferTooSmall) => {
                    assert!(reader.grow(max_buf), "failed to grow reader buffer");
                    if reader.refill().is_err() {
                        break;
                    }
                }
                Err(e) => panic!("legacy(growing) parse error: {e:?}"),
            }
        }
        out
    }

    #[test]
    fn truncated_capture_is_short_and_partial() {
        let seed = 555;
        let truncated = truncated_capture(seed);

        // Full capture for comparison: same spec used inside truncated_capture.
        let full = generate(&CaptureSpec {
            format: Format::LegacyLeMicro,
            seed,
            packet_count: 6,
            min_size: 40,
            max_size: 120,
            link_type: 1,
            ..Default::default()
        });

        assert!(
            truncated.bytes.len() < full.bytes.len(),
            "truncated bytes ({}) should be shorter than full ({})",
            truncated.bytes.len(),
            full.bytes.len()
        );
        assert!(
            truncated.expected.len() < full.expected.len(),
            "truncated should expose fewer complete frames"
        );

        // pcap_parser should read exactly expected.len() complete packets,
        // then hit Incomplete/Eof.
        let mut reader =
            LegacyPcapReader::new(65536, Cursor::new(&truncated.bytes)).expect("reader");
        let mut complete = 0usize;
        // The loop only ever exits via a terminal Eof/Incomplete branch (the
        // catch-all Err arm panics, and the Ok arm never breaks), so reaching
        // the assert below already proves we hit a terminal state.
        let hit_terminal = loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::Legacy(_) = block {
                        complete += 1;
                    }
                    reader.consume(offset);
                }
                // All terminal: the stream ended before the final record could
                // be completed. `UnexpectedEof` is what pcap_parser reports when
                // a record header promises more bytes than the file contains.
                Err(PpError::Eof) | Err(PpError::UnexpectedEof) => break true,
                Err(PpError::Incomplete(_)) => {
                    // No more data can satisfy the incomplete final record.
                    if reader.reader_exhausted() {
                        break true;
                    }
                    if reader.refill().is_err() {
                        break true;
                    }
                }
                Err(e) => panic!("truncated parse error: {e:?}"),
            }
        };
        assert!(hit_terminal, "should terminate on Incomplete/Eof");
        assert_eq!(
            complete,
            truncated.expected.len(),
            "pcap_parser read {} complete packets, expected {}",
            complete,
            truncated.expected.len()
        );

        // And the complete frames match ground truth.
        let parsed = parse_legacy(&truncated.bytes);
        assert_eq!(parsed.len(), truncated.expected.len());
        for (p, e) in parsed.iter().zip(truncated.expected.iter()) {
            assert_eq!(p.caplen, e.caplen);
            assert_eq!(p.data, e.data);
        }
    }

    #[test]
    fn prng_is_reproducible() {
        let mut a = SplitMix64::new(12345);
        let mut b = SplitMix64::new(12345);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
