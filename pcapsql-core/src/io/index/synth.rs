//! Header synthesis for mid-file (headerless) partition starts.

use crate::io::pcap_stream::InterfaceState;
use crate::io::PcapFormat;

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
/// partition, reconstructing the interface table (link type + `if_tsresol`)
/// in the byte order of the section the partition starts in.
pub fn synth_pcapng_header(state: &InterfaceState) -> Vec<u8> {
    let be = state.big_endian;
    let mut v = Vec::new();
    // Section Header Block, 28 bytes, no options. The byte-order magic is the
    // same 32-bit value written in the section's own byte order, which is how
    // readers detect it.
    put_u32_e(&mut v, 0x0A0D_0D0A, be); // block type
    put_u32_e(&mut v, 28, be); // total length
    put_u32_e(&mut v, 0x1A2B_3C4D, be); // byte-order magic
    put_u16_e(&mut v, 1, be); // major
    put_u16_e(&mut v, 0, be); // minor
    put_u64_e(&mut v, u64::MAX, be); // section length: unknown
    put_u32_e(&mut v, 28, be); // total length (trailer)

    for iface in &state.interfaces {
        // Interface Description Block: 32 bytes with the if_tsresol option,
        // plus 12 for an if_tsoffset option when the interface has one.
        let total: u32 = if iface.if_tsoffset != 0 { 44 } else { 32 };
        put_u32_e(&mut v, 0x0000_0001, be); // block type
        put_u32_e(&mut v, total, be); // total length
        put_u16_e(&mut v, iface.link_type as u16, be); // linktype
        put_u16_e(&mut v, 0, be); // reserved
        put_u32_e(
            &mut v,
            if iface.snaplen == 0 {
                65535
            } else {
                iface.snaplen
            },
            be,
        );
        // Option: if_tsresol (code 9, len 1), value padded to 4 bytes.
        put_u16_e(&mut v, 9, be);
        put_u16_e(&mut v, 1, be);
        v.push(iface.if_tsresol);
        v.extend_from_slice(&[0, 0, 0]);
        if iface.if_tsoffset != 0 {
            // Option: if_tsoffset (code 14, len 8), seconds.
            put_u16_e(&mut v, 14, be);
            put_u16_e(&mut v, 8, be);
            put_u64_e(&mut v, iface.if_tsoffset as u64, be);
        }
        // opt_endofopt
        put_u16_e(&mut v, 0, be);
        put_u16_e(&mut v, 0, be);
        put_u32_e(&mut v, total, be); // total length (trailer)
    }
    v
}

fn put_u64_e(v: &mut Vec<u8>, x: u64, be: bool) {
    if be {
        v.extend_from_slice(&x.to_be_bytes());
    } else {
        v.extend_from_slice(&x.to_le_bytes());
    }
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
