//! Protocol pruning for query optimization.
//!
//! When executing SQL queries that only reference certain protocol tables,
//! we can skip parsing protocols that aren't needed. This module provides
//! utilities to compute the required set of protocols and check whether
//! to continue parsing.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::collections::HashSet;
//! use pcapsql_core::protocol::{default_registry, compute_required_protocols};
//!
//! let registry = default_registry();
//!
//! // Query only touches TCP table
//! let required = compute_required_protocols(&["tcp"], &registry);
//!
//! // Required set includes TCP and its dependencies
//! assert!(required.contains("tcp"));
//! assert!(required.contains("ipv4"));
//! assert!(required.contains("ethernet"));
//!
//! // But not unrelated protocols
//! assert!(!required.contains("dns"));
//! assert!(!required.contains("http"));
//! ```

use std::collections::HashSet;

use super::registry::{Protocol, ProtocolRegistry};

/// Compute the set of protocols required to satisfy a query.
///
/// Given a set of queried table names (e.g., `["tcp", "ipv4"]`), returns
/// all protocols that must be parsed, including transitive dependencies.
///
/// # Arguments
///
/// * `queried_tables` - Names of protocol tables referenced in the query
/// * `registry` - Protocol registry containing parser definitions
///
/// # Returns
///
/// A set of protocol names that must be parsed. Always includes "frames"
/// (the base frame data) plus all queried protocols and their dependencies.
pub fn compute_required_protocols(
    queried_tables: &[&str],
    registry: &ProtocolRegistry,
) -> HashSet<String> {
    let mut required = HashSet::new();

    // Always need the ability to read frames
    required.insert("frames".to_string());

    // For each queried table, add it and its dependencies
    for table in queried_tables {
        add_with_dependencies(table, registry, &mut required);
    }

    required
}

/// Recursively add a protocol and all its dependencies to the required set.
fn add_with_dependencies(protocol: &str, registry: &ProtocolRegistry, required: &mut HashSet<String>) {
    // Get parser from registry
    if let Some(parser) = registry.get_parser(protocol) {
        let name = parser.name().to_string();
        if required.insert(name) {
            // Newly added, also add dependencies
            for dep in parser.dependencies() {
                add_with_dependencies(dep, registry, required);
            }
        }
    } else {
        // Protocol not in registry, just add the name
        // (e.g., "frames" is not a parser but a pseudo-table)
        required.insert(protocol.to_string());
    }
}

/// Check if parsing should continue given the current parse results and required set.
///
/// Returns `true` if there are required protocols that haven't been parsed yet,
/// meaning parsing should continue.
///
/// # Arguments
///
/// * `parsed_so_far` - Names of protocols already parsed from the current packet
/// * `required` - Set of protocols needed for the query
///
/// # Returns
///
/// `true` if parsing should continue, `false` if all required protocols have been found.
pub fn should_continue_parsing(parsed_so_far: &[&str], required: &HashSet<String>) -> bool {
    // Continue if there are required protocols we haven't parsed yet
    for req in required {
        // Skip "frames" as it's always available without parsing
        if req == "frames" {
            continue;
        }
        if !parsed_so_far.contains(&req.as_str()) {
            return true;
        }
    }
    false
}

/// Check if a specific parser should be run.
///
/// Returns `true` if:
/// 1. The parser's output is directly needed by the query, OR
/// 2. The parser is on the path to a needed protocol (i.e., some required
///    protocol depends on this one)
///
/// # Arguments
///
/// * `parser_name` - Name of the parser to check
/// * `required` - Set of protocols needed for the query
/// * `registry` - Protocol registry containing parser definitions
pub fn should_run_parser(
    parser_name: &str,
    required: &HashSet<String>,
    registry: &ProtocolRegistry,
) -> bool {
    // Directly required
    if required.contains(parser_name) {
        return true;
    }

    // Check if any required protocol depends on this one
    for req in required {
        if let Some(parser) = registry.get_parser(req) {
            if parser.dependencies().contains(&parser_name) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::default_registry;

    #[test]
    fn test_compute_required_protocols_tcp() {
        let registry = default_registry();

        // TCP requires ethernet -> ipv4/ipv6 -> tcp
        let required = compute_required_protocols(&["tcp"], &registry);

        assert!(required.contains("frames"));
        assert!(required.contains("tcp"));
        assert!(required.contains("ipv4"));
        assert!(required.contains("ipv6"));
        assert!(required.contains("ethernet"));

        // Should NOT include unrelated protocols
        assert!(!required.contains("dns"));
        assert!(!required.contains("dhcp"));
        assert!(!required.contains("tls"));
    }

    #[test]
    fn test_compute_required_protocols_dns() {
        let registry = default_registry();

        // DNS requires ethernet -> ipv4/ipv6 -> udp/tcp -> dns
        let required = compute_required_protocols(&["dns"], &registry);

        assert!(required.contains("frames"));
        assert!(required.contains("dns"));
        assert!(required.contains("udp"));
        assert!(required.contains("tcp")); // DNS can run over TCP
        assert!(required.contains("ipv4"));
        assert!(required.contains("ipv6"));
        assert!(required.contains("ethernet"));

        // Should NOT include TLS, SSH, etc.
        assert!(!required.contains("tls"));
        assert!(!required.contains("ssh"));
    }

    #[test]
    fn test_compute_required_protocols_ethernet_only() {
        let registry = default_registry();

        // Ethernet only needs ethernet layer
        let required = compute_required_protocols(&["ethernet"], &registry);

        assert!(required.contains("frames"));
        assert!(required.contains("ethernet"));

        // Should NOT include any L3+ protocols
        assert!(!required.contains("ipv4"));
        assert!(!required.contains("tcp"));
        assert!(!required.contains("dns"));
    }

    #[test]
    fn test_compute_required_protocols_multiple_tables() {
        let registry = default_registry();

        // Join between TCP and DNS requires both paths
        let required = compute_required_protocols(&["tcp", "dns"], &registry);

        assert!(required.contains("tcp"));
        assert!(required.contains("dns"));
        assert!(required.contains("udp")); // For DNS
        assert!(required.contains("ipv4"));
        assert!(required.contains("ethernet"));
    }

    #[test]
    fn test_should_continue_parsing() {
        let required: HashSet<String> = ["frames", "ethernet", "ipv4", "tcp"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Nothing parsed yet - should continue
        assert!(should_continue_parsing(&[], &required));

        // Ethernet parsed - should continue
        assert!(should_continue_parsing(&["ethernet"], &required));

        // Ethernet + IPv4 parsed - should continue (need TCP)
        assert!(should_continue_parsing(&["ethernet", "ipv4"], &required));

        // All required parsed - should stop
        assert!(!should_continue_parsing(&["ethernet", "ipv4", "tcp"], &required));
    }

    #[test]
    fn test_should_run_parser() {
        let registry = default_registry();
        let required: HashSet<String> = ["tcp"].iter().map(|s| s.to_string()).collect();

        // TCP is directly required
        assert!(should_run_parser("tcp", &required, &registry));

        // IPv4/IPv6 are dependencies of TCP
        assert!(should_run_parser("ipv4", &required, &registry));
        assert!(should_run_parser("ipv6", &required, &registry));

        // DNS is not required
        assert!(!should_run_parser("dns", &required, &registry));

        // UDP is not required when only TCP is needed
        assert!(!should_run_parser("udp", &required, &registry));
    }

    #[test]
    fn test_vxlan_dependencies() {
        let registry = default_registry();

        // VXLAN requires the full encapsulation path
        let required = compute_required_protocols(&["vxlan"], &registry);

        assert!(required.contains("vxlan"));
        assert!(required.contains("udp"));
        assert!(required.contains("ipv4"));
        assert!(required.contains("ipv6"));
        assert!(required.contains("ethernet"));
    }
}
