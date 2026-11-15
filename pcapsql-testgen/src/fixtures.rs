//! Special-case captures.

use crate::legacy::{legacy_pcap, GenPacket, LegacyVariant};
use crate::model::GeneratedCapture;
use crate::rng::SplitMix64;
use crate::spec::{generate, make_payload, CaptureSpec, Format, BASE_SEC};

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
    legacy_pcap(
        LegacyVariant::LeMicro,
        1,
        (caplen as u32).max(262_144),
        &[p],
    )
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

    let push_normal =
        |packets: &mut Vec<GenPacket>, frame_number: &mut u64, rng: &mut SplitMix64| {
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
