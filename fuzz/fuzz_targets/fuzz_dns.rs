//! Fuzz target for DNS (Domain Name System) parser.
//!
//! DNS parser (937 lines) uses the simple-dns library and handles:
//! - Query/response parsing
//! - Multiple record types (A, AAAA, MX, TXT, CNAME, etc.)
//! - EDNS0 extensions
//! - Name compression

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

    // Clone DNS frame header and patch lengths
    let mut frame = DNS_FRAME.to_vec();

    // Patch IPv4 total length (offset 16-17): IP(20) + UDP(8) + payload
    let ip_total_len = (28 + data.len()) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Patch UDP length (offset 38-39): UDP(8) + payload
    let udp_len = (8 + data.len()) as u16;
    frame[38] = (udp_len >> 8) as u8;
    frame[39] = (udp_len & 0xff) as u8;

    // Append DNS payload (the fuzz data)
    frame.extend_from_slice(data);

    // Parse through the full chain - DNS parser triggered by dst_port=53
    let _ = parse_packet(&registry, 1, &frame);
});
