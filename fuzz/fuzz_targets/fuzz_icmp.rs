//! Fuzz target for ICMP and ICMPv6 parsers.
//!
//! ICMP parser (294 lines) handles:
//! - Echo request/reply
//! - Destination unreachable
//! - Time exceeded
//! - Redirect
//! - ICMPv6 Neighbor Discovery messages

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

    // Test ICMPv4: frame with protocol=1
    {
        let mut frame_v4 = ICMP_FRAME.to_vec();

        // Patch IPv4 total length (offset 16-17): IP(20) + payload
        let ip_len = (20 + data.len()) as u16;
        frame_v4[16] = (ip_len >> 8) as u8;
        frame_v4[17] = (ip_len & 0xff) as u8;

        // Append ICMP payload
        frame_v4.extend_from_slice(data);

        // Parse - ICMP parser triggered by ip_protocol=1
        let _ = parse_packet(&registry, 1, &frame_v4);
    }

    // Test ICMPv6: frame with next_header=58
    {
        let mut frame_v6 = ICMPV6_FRAME.to_vec();

        // Patch IPv6 payload length (offset 18-19)
        let payload_len = data.len() as u16;
        frame_v6[18] = (payload_len >> 8) as u8;
        frame_v6[19] = (payload_len & 0xff) as u8;

        // Append ICMPv6 payload
        frame_v6.extend_from_slice(data);

        // Parse - ICMPv6 parser triggered by next_header=58
        let _ = parse_packet(&registry, 1, &frame_v6);
    }
});
