//! The high-level deterministic generator.

use crate::legacy::{legacy_pcap, GenPacket, LegacyVariant};
use crate::model::GeneratedCapture;
use crate::pcapng::{
    pcapng_ordered_with_byte_order, tsresol_units, PcapngBlock, PcapngInterface,
    PcapngOrderedSection, PcapngPacket,
};
use crate::rng::SplitMix64;

/// Output format selector for [`generate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    LegacyLeMicro,
    LegacyBeMicro,
    LegacyLeNano,
    LegacyBeNano,
    Pcapng,
    /// PCAPNG with big-endian sections.
    PcapngBe,
}

impl Format {
    /// True for either PCAPNG byte order.
    pub fn is_pcapng(self) -> bool {
        matches!(self, Format::Pcapng | Format::PcapngBe)
    }
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
    /// pcapng-only: `if_tsoffset` (seconds) written on every interface,
    /// including the midstream one; 0 writes no option.
    pub if_tsoffset: i64,
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
            if_tsoffset: 0,
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
pub(crate) fn make_payload(seed: u64, frame_number: u64, len: usize) -> Vec<u8> {
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
        Format::Pcapng => generate_pcapng(spec, false),
        Format::PcapngBe => generate_pcapng(spec, true),
    }
}

/// Base epoch (2021-01-01T00:00:00Z-ish) so timestamps look plausible.
pub(crate) const BASE_SEC: u64 = 1_609_459_200;

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

fn generate_pcapng(spec: &CaptureSpec, big_endian: bool) -> GeneratedCapture {
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

    // Frame spacing: see the timestamp comment in the packet loop. The
    // midstream interface (tsresol 9) is never the coarsest.
    let min_resolution = spec
        .interfaces
        .iter()
        .map(|&t| tsresol_units(t))
        .min()
        .expect("at least one interface");
    let step_ns: u64 = 1_000_000u64.max(1_000_000_000u64.div_ceil(min_resolution));

    let mut sections = Vec::with_capacity(spec.sections);
    let mut global_frame: u64 = 0;

    for s in 0..spec.sections {
        let count = base + if s < extra { 1 } else { 0 };

        // Base interfaces (one per `spec.interfaces` tsresol), declared up front.
        let base_ifaces: Vec<PcapngInterface> = spec
            .interfaces
            .iter()
            .map(|&tsresol| PcapngInterface {
                link_type: spec.link_type,
                tsresol,
                snaplen,
                if_tsoffset: spec.if_tsoffset,
            })
            .collect();
        let base_len = base_ifaces.len();

        // A midstream interface (tsresol 9) is declared *after* `switch_at`
        // packets, so its IDB lands literally mid-stream in the byte layout
        // (preceded by EPBs). Its interface id is `base_len` — it is the next
        // IDB a reader encounters in this section.
        let midstream_iface_id = base_len as u32;
        let switch_at = if spec.add_interface_midstream {
            count / 2
        } else {
            usize::MAX
        };

        // Emit the base IDBs first, then walk the packets, inserting the
        // midstream IDB at the switch point so it sits between EPBs on disk.
        let mut blocks: Vec<PcapngBlock> = Vec::with_capacity(base_len + 1 + count);
        for iface in &base_ifaces {
            blocks.push(PcapngBlock::Interface(iface.clone()));
        }
        // tsresol by interface id, grown when the midstream IDB is declared.
        let mut tsresol_by_id: Vec<u8> = base_ifaces.iter().map(|i| i.tsresol).collect();
        let mut midstream_declared = false;

        for j in 0..count {
            global_frame += 1;

            // Declare the midstream interface right before the first packet that
            // routes to it, so the IDB is genuinely mid-stream.
            if spec.add_interface_midstream && j == switch_at && !midstream_declared {
                blocks.push(PcapngBlock::Interface(PcapngInterface {
                    link_type: spec.link_type,
                    tsresol: 9,
                    snaplen,
                    if_tsoffset: spec.if_tsoffset,
                }));
                tsresol_by_id.push(9);
                midstream_declared = true;
            }

            let len = size_rng.next_in_range(spec.min_size, spec.max_size);
            let data = make_payload(spec.seed, global_frame, len);

            // Route to the midstream interface for the second half.
            let interface_id = if spec.add_interface_midstream && j >= switch_at {
                midstream_iface_id
            } else {
                // Spread across the section's base interfaces deterministically.
                (j % base_len) as u32
            };

            let resolution = tsresol_units(tsresol_by_id[interface_id as usize]);

            // Monotonic timestamps across the whole file, also across
            // interfaces of different resolutions: frames are `step_ns`
            // apart, where the step is one millisecond or one tick of the
            // coarsest interface in the spec, whichever is longer. Each
            // interface then truncates the instant to its own resolution
            // (ticks = floor(t * resolution)), so a frame never decodes to an
            // earlier time than the frame before it, and consecutive frames
            // on the same interface differ by at least one tick. The ground
            // truth is computed from the ticks actually written, so it stays
            // exact for every resolution.
            let idx = global_frame - 1;
            let t_ns = u128::from(BASE_SEC) * 1_000_000_000 + u128::from(idx) * u128::from(step_ns);
            let ts_sec = (t_ns / 1_000_000_000) as u64;
            let frac_ns = t_ns % 1_000_000_000;
            let ts_frac_units = (frac_ns * u128::from(resolution) / 1_000_000_000) as u64;

            let origlen = data.len() as u32;
            blocks.push(PcapngBlock::Packet(PcapngPacket {
                interface_id,
                ts_sec,
                ts_frac_units,
                data,
                origlen,
            }));
        }

        sections.push(PcapngOrderedSection { blocks });
    }

    pcapng_ordered_with_byte_order(&sections, big_endian)
}
