//! Fuzz target for VXLAN (Virtual Extensible LAN) parser.
//!
//! VXLAN parser (452 lines) handles:
//! - 8-byte VXLAN header with flags and VNI
//! - VNI (24-bit VXLAN Network Identifier) extraction
//! - Inner Ethernet frame parsing
//! - Tunnel boundary signaling

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let registry = default_registry();

    // Build frame: Ethernet (14) + IPv4 (20) + UDP (8) + VXLAN payload
    // Total header overhead: 42 bytes
    let mut frame = vec![
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst mac
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
        0x08, 0x00, // ethertype IPv4
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x00, // version=4, ihl=5, dscp=0, total_len (patched)
        0x00, 0x01, 0x00, 0x00, // id=1, flags=0, frag_offset=0
        0x40, 0x11, 0x00, 0x00, // ttl=64, protocol=UDP(17), checksum=0
        0x0a, 0x00, 0x00, 0x01, // src ip: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // dst ip: 10.0.0.2
        // UDP header (8 bytes)
        0xc0, 0x00, // src_port = 49152 (ephemeral)
        0x12, 0xb5, // dst_port = 4789 (VXLAN)
        0x00, 0x00, // length (patched)
        0x00, 0x00, // checksum = 0
    ];

    // Patch IPv4 total length
    let ip_total_len = (28 + data.len()) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Patch UDP length
    let udp_len = (8 + data.len()) as u16;
    frame[38] = (udp_len >> 8) as u8;
    frame[39] = (udp_len & 0xff) as u8;

    // Append VXLAN payload
    frame.extend_from_slice(data);

    // Parse - VXLAN parser triggered by dst_port=4789
    let _ = parse_packet(&registry, 1, &frame);
});
