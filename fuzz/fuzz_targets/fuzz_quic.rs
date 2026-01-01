//! Fuzz target for QUIC (Quick UDP Internet Connections) parser.
//!
//! QUIC parser (844 lines) handles:
//! - Long header packets (Initial, 0-RTT, Handshake, Retry)
//! - Short header packets (post-handshake)
//! - Variable-length integer (varint) parsing
//! - Connection ID extraction (DCID, SCID)
//! - Version negotiation
//! - SNI extraction from Initial packets

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

// Include generated frame wrappers
include!("../src/frames.rs");

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let registry = default_registry();

    // Clone QUIC frame header and patch lengths
    let mut frame = QUIC_FRAME.to_vec();

    // Patch IPv4 total length (offset 16-17): IP(20) + UDP(8) + payload
    let ip_total_len = (28 + data.len()) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Patch UDP length (offset 38-39): UDP(8) + payload
    let udp_len = (8 + data.len()) as u16;
    frame[38] = (udp_len >> 8) as u8;
    frame[39] = (udp_len & 0xff) as u8;

    // Append QUIC payload (the fuzz data)
    frame.extend_from_slice(data);

    // Parse through the full chain - QUIC parser triggered by dst_port=443
    let _ = parse_packet(&registry, 1, &frame);
});
