//! Fuzz target for GRE (Generic Routing Encapsulation) parser.
//!
//! GRE parser (773 lines) handles:
//! - Standard GRE (RFC 2784, 2890)
//! - Optional checksum, key, and sequence number fields
//! - NVGRE variant (RFC 7637)
//! - Encapsulated protocol detection and tunnel tracking

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let registry = default_registry();

    // Build frame: Ethernet (14) + IPv4 (20) + GRE payload
    // GRE runs directly over IP (protocol 47), no TCP/UDP
    // Total header overhead: 34 bytes
    let mut frame = vec![
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst mac
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
        0x08, 0x00, // ethertype IPv4
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x00, // version=4, ihl=5, dscp=0, total_len (patched)
        0x00, 0x01, 0x00, 0x00, // id=1, flags=0, frag_offset=0
        0x40, 0x2f, 0x00, 0x00, // ttl=64, protocol=GRE(47), checksum=0
        0x0a, 0x00, 0x00, 0x01, // src ip: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // dst ip: 10.0.0.2
    ];

    // Patch IPv4 total length
    let ip_total_len = (20 + data.len()) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Append GRE payload
    frame.extend_from_slice(data);

    // Parse - GRE parser triggered by ip_protocol=47
    let _ = parse_packet(&registry, 1, &frame);
});
