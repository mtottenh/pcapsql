//! Fuzz target for SSH (Secure Shell) parser.
//!
//! SSH parser (844 lines) handles:
//! - Protocol identification string parsing (SSH-2.0-...)
//! - Binary packet format (length, padding, payload)
//! - KEXINIT message parsing (algorithm negotiation)
//! - USERAUTH_REQUEST parsing
//! - CHANNEL_OPEN parsing
//! - Post-encryption packet detection

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

    // Clone SSH frame header and patch lengths
    let mut frame = SSH_FRAME.to_vec();

    // Patch IPv4 total length (offset 16-17): IP(20) + TCP(20) + payload
    let ip_total_len = (40 + data.len()) as u16;
    frame[16] = (ip_total_len >> 8) as u8;
    frame[17] = (ip_total_len & 0xff) as u8;

    // Append SSH payload (the fuzz data)
    frame.extend_from_slice(data);

    // Parse through the full chain - SSH parser triggered by dst_port=22
    let _ = parse_packet(&registry, 1, &frame);
});
