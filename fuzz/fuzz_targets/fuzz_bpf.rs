//! Fuzz target for BPF (Berkeley Packet Filter) expression parser.
//!
//! This target tests the tcpdump-style BPF filter parsing:
//!
//! - Expression syntax parsing (tcp, udp, host, port, etc.)
//! - Nested expressions with parentheses
//! - Operator precedence (NOT > AND > OR)
//! - Protocol qualifiers (ip, tcp, udp, icmp, etc.)
//! - Direction qualifiers (src, dst)
//! - Numeric literals and ranges
//! - CIDR notation parsing

#![no_main]

use libfuzzer_sys::fuzz_target;
use pcapsql_datafusion::query::bpf::parse_bpf_filter;

fuzz_target!(|data: &[u8]| {
    // BPF expressions are text-based, try to interpret as UTF-8
    if let Ok(expr) = std::str::from_utf8(data) {
        // Skip empty or whitespace-only inputs (they're expected to fail)
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return;
        }

        // Parse the BPF filter expression
        // This should never panic, only return Ok or Err
        let _ = parse_bpf_filter(expr);
    }
});
