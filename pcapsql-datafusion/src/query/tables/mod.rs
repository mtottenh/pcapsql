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
mod bgp;
mod dhcp;
mod dns;
mod ethernet;
mod frames;
mod gre;
mod gtp;
mod http;
mod http2;
mod http_messages;
mod icmp;
mod icmpv6;
mod ipsec;
mod ipv4;
mod ipv6;
mod linux_sll;
mod mpls;
mod netlink;
mod ntp;
mod ospf;
mod quic;
mod rtnetlink;
mod ssh;
mod tcp;
mod tcp_connections;
mod tcp_streams;
mod tls;
mod tls_sessions;
mod udp;
mod vlan;
mod vxlan;

pub use arp::arp_table_schema;
pub use bgp::bgp_table_schema;
pub use dhcp::dhcp_table_schema;
pub use dns::dns_table_schema;
pub use ethernet::ethernet_table_schema;
pub use frames::frames_table_schema;
pub use gre::gre_table_schema;
pub use gtp::gtp_table_schema;
pub use http::http_table_schema;
pub use http2::http2_table_schema;
pub use http_messages::{build_http_messages_batch, http_messages_schema};
pub use icmp::icmp_table_schema;
pub use icmpv6::icmpv6_table_schema;
pub use ipsec::ipsec_table_schema;
pub use ipv4::ipv4_table_schema;
pub use ipv6::ipv6_table_schema;
pub use linux_sll::linux_sll_table_schema;
pub use mpls::mpls_table_schema;
pub use netlink::netlink_table_schema;
pub use ntp::ntp_table_schema;
pub use ospf::ospf_table_schema;
pub use quic::quic_table_schema;
pub use rtnetlink::rtnetlink_table_schema;
pub use ssh::ssh_table_schema;
pub use tcp::tcp_table_schema;
pub use tcp_connections::{build_tcp_connections_batch, tcp_connections_schema};
pub use tcp_streams::{build_tcp_streams_batch, tcp_streams_schema, StreamData};
pub use tls::tls_table_schema;
pub use tls_sessions::{build_tls_sessions_batch, tls_sessions_schema};
pub use udp::udp_table_schema;
pub use vlan::vlan_table_schema;
pub use vxlan::vxlan_table_schema;

use arrow::datatypes::{DataType, Field, Schema};

/// Schema for the `frame_number` column (used in all protocol tables).
pub fn frame_number_field() -> Field {
    Field::new("frame_number", DataType::UInt64, false)
}

/// Encapsulation fields for tunnel-aware queries.
///
/// These fields are automatically added to all protocol tables (except frames)
/// to support queries on tunneled traffic.
///
/// - `encap_depth`: Encapsulation depth (0 = outer/no tunnel, 1+ = inside tunnel)
/// - `tunnel_type`: Type of enclosing tunnel (vxlan, gre, gtp, mpls, ipinip, ip6inip, ipsec)
/// - `tunnel_id`: Tunnel identifier (VNI, GRE key, TEID, MPLS label)
pub fn encap_fields() -> Vec<Field> {
    vec![
        Field::new("encap_depth", DataType::UInt8, false),
        Field::new("tunnel_type", DataType::Utf8, true),
        Field::new("tunnel_id", DataType::UInt64, true),
    ]
}

/// Append encapsulation fields to a schema.
fn with_encap_fields(schema: Schema) -> Schema {
    let mut fields: Vec<Field> = schema.fields().iter().map(|f| f.as_ref().clone()).collect();
    fields.extend(encap_fields());
    Schema::new(fields)
}

/// Get all protocol table names.
pub fn all_table_names() -> Vec<&'static str> {
    vec![
        "frames",
        "ethernet",
        "linux_sll",
        "arp",
        "vlan",
        "mpls",
        "ipv4",
        "ipv6",
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "gre",
        "vxlan",
        "gtp",
        "ipsec",
        "bgp",
        "ospf",
        "dns",
        "dhcp",
        "ntp",
        "http",
        "http2",
        "tls",
        "ssh",
        "quic",
        "netlink",
        "rtnetlink",
    ]
}

/// Get a table schema by protocol name.
///
/// All protocol tables (except "frames") automatically include encapsulation
/// columns (`encap_depth`, `tunnel_type`, `tunnel_id`) for tunnel-aware queries.
pub fn get_table_schema(name: &str) -> Option<Schema> {
    match name {
        // "frames" doesn't have encap fields - it's raw packet metadata
        "frames" => Some(frames_table_schema()),
        // All protocol tables include encap fields for tunnel support
        "ethernet" => Some(with_encap_fields(ethernet_table_schema())),
        "linux_sll" => Some(with_encap_fields(linux_sll_table_schema())),
        "arp" => Some(with_encap_fields(arp_table_schema())),
        "vlan" => Some(with_encap_fields(vlan_table_schema())),
        "mpls" => Some(with_encap_fields(mpls_table_schema())),
        "ipv4" => Some(with_encap_fields(ipv4_table_schema())),
        "ipv6" => Some(with_encap_fields(ipv6_table_schema())),
        "tcp" => Some(with_encap_fields(tcp_table_schema())),
        "udp" => Some(with_encap_fields(udp_table_schema())),
        "icmp" => Some(with_encap_fields(icmp_table_schema())),
        "icmpv6" => Some(with_encap_fields(icmpv6_table_schema())),
        "gre" => Some(with_encap_fields(gre_table_schema())),
        "vxlan" => Some(with_encap_fields(vxlan_table_schema())),
        "gtp" => Some(with_encap_fields(gtp_table_schema())),
        "ipsec" => Some(with_encap_fields(ipsec_table_schema())),
        "bgp" => Some(with_encap_fields(bgp_table_schema())),
        "ospf" => Some(with_encap_fields(ospf_table_schema())),
        "dns" => Some(with_encap_fields(dns_table_schema())),
        "dhcp" => Some(with_encap_fields(dhcp_table_schema())),
        "ntp" => Some(with_encap_fields(ntp_table_schema())),
        "http" => Some(with_encap_fields(http_table_schema())),
        "http2" => Some(with_encap_fields(http2_table_schema())),
        "tls" => Some(with_encap_fields(tls_table_schema())),
        "ssh" => Some(with_encap_fields(ssh_table_schema())),
        "quic" => Some(with_encap_fields(quic_table_schema())),
        "netlink" => Some(with_encap_fields(netlink_table_schema())),
        "rtnetlink" => Some(with_encap_fields(rtnetlink_table_schema())),
        _ => None,
    }
}

/// Get all table schemas as (name, schema) pairs.
///
/// All protocol tables (except "frames") include encapsulation columns.
pub fn all_table_schemas() -> Vec<(&'static str, Schema)> {
    all_table_names()
        .into_iter()
        .filter_map(|name| get_table_schema(name).map(|schema| (name, schema)))
        .collect()
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
