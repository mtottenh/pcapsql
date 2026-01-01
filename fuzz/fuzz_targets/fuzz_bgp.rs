//! Fuzz target for BGP (Border Gateway Protocol) parser.
//!
//! BGP is the most complex protocol parser (1669 lines) with:
//! - OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE_REFRESH messages
//! - Variable-length path attributes
//! - AS path parsing (2-byte vs 4-byte ASNs)
//! - NLRI prefix length validation
//! - Capability negotiation

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

fuzz_target!(|data: &[u8]| {
    // Skip very small inputs
    if data.is_empty() {
        return;
    }

    let registry = default_registry();

    // Build frame: Ethernet (14) + IPv4 (20) + TCP (20) + BGP payload
    // Total header overhead: 54 bytes
    let mut frame = vec![
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst mac
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
        0x08, 0x00, // ethertype IPv4
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x00, // version=4, ihl=5, dscp=0, total_len (patched below)
        0x00, 0x01, 0x00, 0x00, // id=1, flags=0, frag_offset=0
        0x40, 0x06, 0x00, 0x00, // ttl=64, protocol=TCP(6), checksum=0
        0x0a, 0x00, 0x00, 0x01, // src ip: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // dst ip: 10.0.0.2
        // TCP header (20 bytes)
        0x00, 0x50, // src_port = 80
        0x00, 0xb3, // dst_port = 179 (BGP)
        0x00, 0x00, 0x00, 0x01, // seq = 1
        0x00, 0x00, 0x00, 0x00, // ack = 0
        0x50, 0x18, // data_offset=5, flags=PSH|ACK
        0xff, 0xff, // window = 65535
        0x00, 0x00, // checksum = 0
        0x00, 0x00, // urgent_ptr = 0
    ];

    // Patch IPv4 total length (IP header + TCP header + payload)
    let ip_total_len = (40 + data.len()) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Append BGP payload (the fuzz data)
    frame.extend_from_slice(data);

    // Parse through the full chain - BGP parser triggered by dst_port=179
    let _ = parse_packet(&registry, 1, &frame);
});
