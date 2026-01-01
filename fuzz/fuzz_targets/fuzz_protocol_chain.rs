//! Fuzz target for the protocol parsing chain.
//!
//! This is the main entry point for all packet data, exercising all 24+ protocol parsers.
//! Tests:
//! - Protocol detection via can_parse() priority
//! - Header bounds checking in each parser
//! - Payload extraction and chaining
//! - Tunnel tracking (VXLAN, GRE, GTP, MPLS)

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_core::{default_registry, parse_packet};

fuzz_target!(|data: &[u8]| {
    let registry = default_registry();

    // Test with Ethernet link type (most common, linktype 1)
    let _ = parse_packet(&registry, 1, data);

    // Test with Linux SLL link type (linktype 113)
    let _ = parse_packet(&registry, 113, data);

    // Test with raw IP (linktype 101)
    let _ = parse_packet(&registry, 101, data);
});
