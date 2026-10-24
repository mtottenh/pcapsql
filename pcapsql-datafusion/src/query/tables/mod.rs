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
mod sll2;
mod ssh;
mod tcp;
mod tcp_connections;
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
pub use http_messages::http_messages_table_schema;
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
pub use sll2::sll2_table_schema;
pub use ssh::ssh_table_schema;
pub use tcp::tcp_table_schema;
pub use tcp_connections::tcp_connections_table_schema;
pub use tls::tls_table_schema;
pub use tls_sessions::tls_sessions_table_schema;
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
        "sll2",
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
        "tcp_connections",
        "tls_sessions",
        "http_messages",
    ]
}

/// Tables produced by stream analysis (TCP reassembly → TLS → HTTP) rather
/// than by per-packet parsing. They are built by the stream subscriber of
/// the packet pass, which needs the whole capture in order (one partition).
pub const STREAM_TABLES: &[&str] = &["http2", "tcp_connections", "tls_sessions", "http_messages"];

/// True for a stream-analysis table (see [`STREAM_TABLES`]).
pub fn is_stream_table(name: &str) -> bool {
    STREAM_TABLES.contains(&name)
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
        "sll2" => Some(with_encap_fields(sll2_table_schema())),
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
        "tcp_connections" => Some(with_encap_fields(tcp_connections_table_schema())),
        "tls_sessions" => Some(with_encap_fields(tls_sessions_table_schema())),
        "http_messages" => Some(with_encap_fields(http_messages_table_schema())),
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

    /// Parser fields (`proto.field` descriptors) that the protocol's table
    /// does not expose as a column yet. The builders drop these values; the
    /// list pins the gap so that a parser field silently falling out of a
    /// table is caught, and shrinks as columns are added (which changes
    /// `SELECT *` and therefore the golden snapshots).
    const NOT_EXPOSED_AS_COLUMNS: &[&str] = &[
        "mpls.is_reserved_label",
        "mpls.special_label_name",
        "ipv6.ext_hop_by_hop",
        "ipv6.ext_routing",
        "ipv6.ext_fragment",
        "ipv6.ext_destination",
        "ipv6.frag_offset",
        "ipv6.frag_more",
        "ipv6.frag_id",
        "ipv6.routing_type",
        "ipv6.segments_left",
        "gre.version_valid",
        "gre.version_name",
        "gre.checksum_valid",
        "gre.header_length",
        "vxlan.i_flag_valid",
        "vxlan.flags_valid",
        "vxlan.inner_frame_length",
        "gtp.npdu",
        "gtp.extension_headers",
        "gtp.extension_header_count",
        "gtp.piggyback",
        "gtp.teid_present",
        "ospf.neighbor_count",
        "ospf.dd_interface_mtu",
        "ospf.dd_options",
        "ospf.dd_flags",
        "ospf.dd_sequence",
        "ospf.dd_lsa_count",
        "ospf.lsu_lsa_count",
        "ospf.lsa_age",
        "ospf.lsa_type",
        "ospf.lsa_type_name",
        "ospf.lsa_id",
        "ospf.lsa_advertising_router",
        "ospf.lsa_sequence",
        "ospf.lsa_ack_count",
    ];

    /// Every parser field descriptor (`proto.field`) with a column in its
    /// protocol's table must agree with that column's Arrow type: the
    /// builders convert each `FieldValue` into the column's type, so a width
    /// mismatch here is where a parser value would be narrowed (or a pushed
    /// filter compared at a different width than the stored column). The one
    /// sanctioned difference is an address: descriptors call it `String`
    /// (engine-agnostic), the tables store it typed (IPv4 `UInt32`, IPv6
    /// `FixedSizeBinary(16)`, MAC `FixedSizeBinary(6)`). Fields with no
    /// column must be listed in `NOT_EXPOSED_AS_COLUMNS`; columns with no
    /// descriptor (never populated) are errors too.
    #[test]
    fn parser_field_descriptors_match_table_schemas() {
        use crate::query::arrow_schema::to_arrow_type;
        use pcapsql_core::{default_registry, DataKind, Protocol};

        let registry = default_registry();
        let mut problems = Vec::new();
        for parser in registry.all_parsers() {
            let name = parser.name();
            let Some(schema) = get_table_schema(name) else {
                problems.push(format!("{name}: parser has no table schema"));
                continue;
            };
            let descriptors = parser.schema_fields();
            for fd in &descriptors {
                let column = strip_protocol_prefix(fd.name);
                match schema.field_with_name(column) {
                    Err(_) => {
                        if !NOT_EXPOSED_AS_COLUMNS.contains(&fd.name) {
                            problems.push(format!(
                                "{name}.{column}: no such table column (add it, or list it \
                                 in NOT_EXPOSED_AS_COLUMNS)"
                            ));
                        }
                    }
                    Ok(field) => {
                        if NOT_EXPOSED_AS_COLUMNS.contains(&fd.name) {
                            problems.push(format!(
                                "{name}.{column}: listed in NOT_EXPOSED_AS_COLUMNS but exposed"
                            ));
                        }
                        let want = to_arrow_type(&fd.kind);
                        let typed_address = fd.kind == DataKind::String
                            && matches!(
                                field.data_type(),
                                DataType::UInt32
                                    | DataType::FixedSizeBinary(16)
                                    | DataType::FixedSizeBinary(6)
                            );
                        if field.data_type() != &want && !typed_address {
                            problems.push(format!(
                                "{name}.{column}: descriptor {want} vs table column {}",
                                field.data_type()
                            ));
                        }
                    }
                }
            }
            // Columns the builders fill from the frame or the parse context,
            // not from a parser field.
            let engine_columns = ["frame_number", "encap_depth", "tunnel_type", "tunnel_id"];
            for field in schema.fields() {
                let column = field.name().as_str();
                if engine_columns.contains(&column) {
                    continue;
                }
                if !descriptors
                    .iter()
                    .any(|fd| strip_protocol_prefix(fd.name) == column)
                {
                    problems.push(format!("{name}.{column}: table column has no parser field"));
                }
            }
        }
        assert!(
            problems.is_empty(),
            "descriptor / table schema drift:\n  {}",
            problems.join("\n  ")
        );
    }

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
                "Table '{name}' should have frame_number field"
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
