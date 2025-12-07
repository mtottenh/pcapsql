//! Per-protocol table schema definitions.
//!
//! This module provides schema definitions for individual protocol tables.
//! Each table contains only the fields relevant to that protocol, with
//! `frame_number` as the primary key for JOINs.
//!
//! Field names are normalized (without protocol prefix) for cleaner SQL:
//! - `dns.query_name` becomes just `query_name` in the `dns` table
//! - JOINs use `frame_number` as the linking key

mod arp;
mod dhcp;
mod dns;
mod ethernet;
mod frames;
mod http;
mod http_messages;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod ntp;
mod quic;
mod ssh;
mod tcp;
mod tcp_connections;
mod tcp_streams;
mod tls;
mod tls_sessions;
mod udp;
mod vlan;

pub use arp::arp_table_schema;
pub use dhcp::dhcp_table_schema;
pub use dns::dns_table_schema;
pub use ethernet::ethernet_table_schema;
pub use frames::frames_table_schema;
pub use http::http_table_schema;
pub use http_messages::{build_http_messages_batch, http_messages_schema};
pub use icmp::icmp_table_schema;
pub use icmpv6::icmpv6_table_schema;
pub use ipv4::ipv4_table_schema;
pub use ipv6::ipv6_table_schema;
pub use ntp::ntp_table_schema;
pub use quic::quic_table_schema;
pub use ssh::ssh_table_schema;
pub use tcp::tcp_table_schema;
pub use tcp_connections::{build_tcp_connections_batch, tcp_connections_schema};
pub use tcp_streams::{build_tcp_streams_batch, tcp_streams_schema, StreamData};
pub use tls::tls_table_schema;
pub use tls_sessions::{build_tls_sessions_batch, tls_sessions_schema};
pub use udp::udp_table_schema;
pub use vlan::vlan_table_schema;

use arrow::datatypes::{DataType, Field, Schema};

/// Schema for the `frame_number` column (used in all protocol tables).
pub fn frame_number_field() -> Field {
    Field::new("frame_number", DataType::UInt64, false)
}

/// Get all protocol table names.
pub fn all_table_names() -> Vec<&'static str> {
    vec![
        "frames", "ethernet", "arp", "vlan", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6",
        "dns", "dhcp", "ntp", "http", "tls", "ssh", "quic",
    ]
}

/// Get a table schema by protocol name.
pub fn get_table_schema(name: &str) -> Option<Schema> {
    match name {
        "frames" => Some(frames_table_schema()),
        "ethernet" => Some(ethernet_table_schema()),
        "arp" => Some(arp_table_schema()),
        "vlan" => Some(vlan_table_schema()),
        "ipv4" => Some(ipv4_table_schema()),
        "ipv6" => Some(ipv6_table_schema()),
        "tcp" => Some(tcp_table_schema()),
        "udp" => Some(udp_table_schema()),
        "icmp" => Some(icmp_table_schema()),
        "icmpv6" => Some(icmpv6_table_schema()),
        "dns" => Some(dns_table_schema()),
        "dhcp" => Some(dhcp_table_schema()),
        "ntp" => Some(ntp_table_schema()),
        "http" => Some(http_table_schema()),
        "tls" => Some(tls_table_schema()),
        "ssh" => Some(ssh_table_schema()),
        "quic" => Some(quic_table_schema()),
        _ => None,
    }
}

/// Get all table schemas as (name, schema) pairs.
pub fn all_table_schemas() -> Vec<(&'static str, Schema)> {
    vec![
        ("frames", frames_table_schema()),
        ("ethernet", ethernet_table_schema()),
        ("arp", arp_table_schema()),
        ("vlan", vlan_table_schema()),
        ("ipv4", ipv4_table_schema()),
        ("ipv6", ipv6_table_schema()),
        ("tcp", tcp_table_schema()),
        ("udp", udp_table_schema()),
        ("icmp", icmp_table_schema()),
        ("icmpv6", icmpv6_table_schema()),
        ("dns", dns_table_schema()),
        ("dhcp", dhcp_table_schema()),
        ("ntp", ntp_table_schema()),
        ("http", http_table_schema()),
        ("tls", tls_table_schema()),
        ("ssh", ssh_table_schema()),
        ("quic", quic_table_schema()),
    ]
}

/// Strip the protocol prefix from a field name.
///
/// Examples:
/// - `"dns.query_name"` -> `"query_name"`
/// - `"tcp.src_port"` -> `"src_port"`
/// - `"frame_number"` -> `"frame_number"` (unchanged)
pub fn strip_protocol_prefix(field_name: &str) -> &str {
    field_name
        .find('.')
        .map(|idx| &field_name[idx + 1..])
        .unwrap_or(field_name)
}

/// Create a new field with the protocol prefix stripped.
pub fn normalize_field(field: &Field) -> Field {
    let new_name = strip_protocol_prefix(field.name());
    Field::new(new_name, field.data_type().clone(), field.is_nullable())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_protocol_prefix() {
        assert_eq!(strip_protocol_prefix("dns.query_name"), "query_name");
        assert_eq!(strip_protocol_prefix("tcp.src_port"), "src_port");
        assert_eq!(strip_protocol_prefix("frame_number"), "frame_number");
        assert_eq!(strip_protocol_prefix("ipv4.src_ip"), "src_ip");
    }

    #[test]
    fn test_all_tables_have_frame_number() {
        for (name, schema) in all_table_schemas() {
            assert!(
                schema.field_with_name("frame_number").is_ok(),
                "Table '{}' should have frame_number field",
                name
            );
        }
    }

    #[test]
    fn test_no_protocol_prefix_in_fields() {
        for (name, schema) in all_table_schemas() {
            for field in schema.fields() {
                assert!(
                    !field.name().contains('.'),
                    "Table '{}' has field '{}' with protocol prefix",
                    name,
                    field.name()
                );
            }
        }
    }

    #[test]
    fn test_get_table_schema() {
        assert!(get_table_schema("frames").is_some());
        assert!(get_table_schema("dns").is_some());
        assert!(get_table_schema("tcp").is_some());
        assert!(get_table_schema("nonexistent").is_none());
    }
}
