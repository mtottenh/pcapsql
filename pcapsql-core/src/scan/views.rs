//! The `*_packets` views: one row per occurrence of a protocol in a frame,
//! with the frame's metadata and the lower layers' columns beside the
//! protocol's.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! A [`PacketsView`] is a fixed [`FusedScan`] with named columns:
//! `tcp_packets` is `frames` joined with `tcp` on `frame_number`, and with
//! `ethernet`, `ipv4` and `ipv6` on `(frame_number, encap_depth)`. A
//! frontend whose engine cannot fuse joins itself scans a view as one
//! output of a pass ([`PacketsView::scan`]): one pass over the capture, no
//! join.
//!
//! # What a view contains
//!
//! Every view is anchored on one protocol table: it has one row per row of
//! that table (per TCP segment, per DNS message), in capture order and
//! within a frame in the order of the anchor's layers, outermost first. The
//! other layers are those of the **same encapsulation level** as the anchor
//! row, so a TCP segment inside a tunnel carries the inner addresses. A
//! level without a layer has NULL in that layer's columns when the layer is
//! optional (a left join: the MAC addresses inside an IP-in-IP tunnel) and
//! gives no row when the view requires it (an inner join: the `tcp` layer
//! under `tls`). A level with two layers of one table would give a row for
//! each, as the join does; the parsers emit at most one of each of these
//! tables per level.
//!
//! The definitions are those of the SQL views of the DataFusion frontend
//! (`pcapsql-datafusion/src/query/views`), column for column: the same
//! columns under the same names in the same order, and the same rows. That
//! crate's tests compare the two over its test corpus. The DataFusion views
//! that are not a join of this shape (`packets`, `tunneled_packets`,
//! `ip4_in_ip6`, `ip6_in_ip6`: full joins, and joins between different
//! encapsulation levels) are not here.

use std::sync::OnceLock;

use super::catalog::{Catalog, ColKind, TableDef, TimestampUnit};
use super::plan::{
    FusedColumn, FusedFilter, FusedMember, FusedScan, FusedValue, JoinKind, MemberJoin, ScanPlan,
};
use crate::default_registry;

/// One column of a [`PacketsView`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewColumn {
    /// The column's name, unique within the view.
    pub name: &'static str,
    /// What it stores; a timestamp is declared as [`ColKind::TsMicros`]
    /// (see [`ViewColumn::kind_in`]).
    pub kind: ColKind,
    /// Whether it can hold NULL.
    pub nullable: bool,
    /// True for the frame's `frame_number`, by which the rows are ordered.
    pub is_frame_number: bool,
    /// True for the frame's `timestamp`.
    pub is_timestamp: bool,
    value: FusedValue,
}

impl ViewColumn {
    /// The column's kind with timestamps stored in `unit`.
    pub const fn kind_in(&self, unit: TimestampUnit) -> ColKind {
        self.kind.with_timestamp_unit(unit)
    }
}

/// A `*_packets` view: a fixed fused join with named columns.
#[derive(Clone, Debug)]
pub struct PacketsView {
    /// The view's name (`tcp_packets`).
    pub name: &'static str,
    /// One line on what it holds.
    pub description: &'static str,
    /// The protocol table the view has one row per row of.
    pub anchor: &'static str,
    members: Vec<ViewMember>,
    columns: Vec<ViewColumn>,
    filter: Option<FusedFilter>,
}

/// One table of a view's join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewMember {
    /// The table (`frames`, `tcp`).
    pub table: &'static str,
    /// The name the view's definition calls it by (`f`, `ip4`).
    pub alias: &'static str,
    /// The table and its join, as the scan plan has them.
    pub member: FusedMember,
}

impl PacketsView {
    /// Every view, in the order the DataFusion frontend lists them.
    pub fn all() -> &'static [PacketsView] {
        static VIEWS: OnceLock<Vec<PacketsView>> = OnceLock::new();
        VIEWS.get_or_init(|| {
            let catalog = Catalog::builtin();
            DEFINITIONS
                .iter()
                .map(|definition| definition.resolve(catalog))
                .collect()
        })
    }

    /// The view called `name`.
    pub fn get(name: &str) -> Option<&'static PacketsView> {
        Self::all().iter().find(|view| view.name == name)
    }

    /// The view's columns, in order.
    pub fn columns(&self) -> &[ViewColumn] {
        &self.columns
    }

    /// The tables the view joins, in join order: `frames`, the anchor, then
    /// the other layers.
    pub fn members(&self) -> &[ViewMember] {
        &self.members
    }

    /// What a column holds, in terms of [`members`](Self::members).
    pub fn value(&self, column: usize) -> &FusedValue {
        &self.columns[column].value
    }

    /// The rows the view keeps of its join; `None` for all of them.
    pub fn filter(&self) -> Option<&FusedFilter> {
        self.filter.as_ref()
    }

    /// The scan of the view's `columns` (indices into
    /// [`columns`](Self::columns)), in that order; an empty list scans the
    /// rows without columns (a row count).
    ///
    /// # Panics
    ///
    /// If an index is not a column of the view.
    pub fn scan(&self, columns: &[usize]) -> FusedScan {
        FusedScan {
            members: self.members.iter().map(|m| m.member).collect(),
            columns: columns
                .iter()
                .map(|&index| {
                    let column = &self.columns[index];
                    FusedColumn {
                        name: Some(column.name),
                        value: column.value.clone(),
                    }
                })
                .collect(),
            filter: self.filter.clone(),
            fetch: None,
        }
    }

    /// The scan of every column.
    pub fn full_scan(&self) -> FusedScan {
        let all: Vec<usize> = (0..self.columns.len()).collect();
        self.scan(&all)
    }
}

/// A column of a view's definition: members are named by their alias.
enum Item {
    /// A member's column, under its own name.
    Col(&'static str, &'static str),
    /// A member's column, under another name.
    As(&'static str, &'static str, &'static str),
    /// `COALESCE` of member columns, under a name.
    Coalesce(&'static str, &'static [(&'static str, &'static str)]),
    /// A label by which members have a row, under a name.
    Present(
        &'static str,
        &'static [(&'static str, &'static str)],
        &'static str,
    ),
}

/// A view as it is written down: `frames f` joined with the anchor on
/// `frame_number`, and every other table joined with the anchor on
/// `(frame_number, encap_depth)`.
struct Def {
    name: &'static str,
    description: &'static str,
    /// The anchor: its table and alias.
    anchor: (&'static str, &'static str),
    /// The other layers: join kind, table, alias.
    joins: &'static [(JoinKind, &'static str, &'static str)],
    columns: &'static [Item],
    /// `alias.column IN (values)`.
    filter: Option<(&'static str, &'static str, &'static [i64])>,
}

impl Def {
    fn resolve(&self, catalog: &Catalog) -> PacketsView {
        let name = self.name;
        let member = |table: &'static str, alias: &'static str, join: Option<MemberJoin>| {
            let (id, _) = catalog
                .table(table)
                .unwrap_or_else(|| panic!("{name}: no table {table}"));
            ViewMember {
                table,
                alias,
                member: FusedMember { table: id, join },
            }
        };
        let mut members = vec![
            member("frames", "f", None),
            member(
                self.anchor.0,
                self.anchor.1,
                Some(MemberJoin {
                    kind: JoinKind::Inner,
                    with: 0,
                    depth: false,
                }),
            ),
        ];
        for (kind, table, alias) in self.joins {
            members.push(member(
                table,
                alias,
                Some(MemberJoin {
                    kind: *kind,
                    with: 1,
                    depth: true,
                }),
            ));
        }
        let table_of = |index: usize| -> &TableDef { catalog.get(members[index].member.table) };
        let resolve = |alias: &str, column: &str| {
            let index = members
                .iter()
                .position(|m| m.alias == alias)
                .unwrap_or_else(|| panic!("{name}: no member {alias}"));
            let (id, _) = table_of(index)
                .column(column)
                .unwrap_or_else(|| panic!("{name}: no column {alias}.{column}"));
            (index as u16, id)
        };
        let values: Vec<(&'static str, FusedValue)> = self
            .columns
            .iter()
            .map(|item| match item {
                Item::Col(alias, column) | Item::As(alias, column, _) => {
                    let (member, id) = resolve(alias, column);
                    let name = match item {
                        Item::As(_, _, name) => *name,
                        _ => *column,
                    };
                    (name, FusedValue::Column { member, column: id })
                }
                Item::Coalesce(name, arguments) => (
                    *name,
                    FusedValue::Coalesce(arguments.iter().map(|(a, c)| resolve(a, c)).collect()),
                ),
                Item::Present(name, cases, otherwise) => (
                    *name,
                    FusedValue::Present {
                        cases: cases
                            .iter()
                            .map(|(alias, label)| (resolve(alias, "frame_number").0, *label))
                            .collect(),
                        otherwise,
                    },
                ),
            })
            .collect();
        let filter = self.filter.map(|(alias, column, any_of)| {
            let (member, column) = resolve(alias, column);
            FusedFilter {
                member,
                column,
                any_of: any_of.to_vec(),
            }
        });

        // The columns' kinds and nullability are the plan's: compile the
        // whole view once.
        let scan = FusedScan {
            members: members.iter().map(|m| m.member).collect(),
            columns: values
                .iter()
                .map(|(name, value)| FusedColumn {
                    name: Some(name),
                    value: value.clone(),
                })
                .collect(),
            filter: filter.clone(),
            fetch: None,
        };
        let compiled = ScanPlan {
            fused: vec![scan],
            timestamps: TimestampUnit::Micros,
            ..ScanPlan::default()
        }
        .compile(catalog, &default_registry())
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        let columns = values
            .into_iter()
            .zip(compiled.outputs()[0].columns.iter())
            .map(|((name, value), out)| {
                let of_frames = |source| {
                    matches!(&value, FusedValue::Column { member: 0, .. }) && out.source == source
                };
                ViewColumn {
                    name,
                    kind: out.kind,
                    nullable: out.nullable,
                    is_frame_number: of_frames(super::ColumnSource::FrameNumber),
                    is_timestamp: of_frames(super::ColumnSource::Timestamp),
                    value,
                }
            })
            .collect();
        PacketsView {
            name,
            description: self.description,
            anchor: self.anchor.0,
            members,
            columns,
            filter,
        }
    }
}

use Item::{As, Coalesce, Col, Present};
use JoinKind::{Inner, Left};

/// The views. Each is the SQL view of the same name of the DataFusion
/// frontend, which stays the reference: a change there is made here too
/// (its tests fail otherwise).
#[rustfmt::skip]
const DEFINITIONS: &[Def] = &[
    Def {
        name: "tcp_packets",
        description: "TCP packets with IP addresses and frame metadata",
        anchor: ("tcp", "tcp"),
        joins: &[(Left, "ethernet", "e"), (Left, "ipv4", "ip4"), (Left, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("f", "length"),
            Col("e", "src_mac"),
            Col("e", "dst_mac"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Coalesce("ttl", &[("ip4", "ttl"), ("ip6", "hop_limit")]),
            Col("tcp", "src_port"),
            Col("tcp", "dst_port"),
            Col("tcp", "seq"),
            Col("tcp", "ack"),
            Col("tcp", "flags"),
            Col("tcp", "window"),
            Col("tcp", "checksum"),
            Col("tcp", "urgent_ptr"),
            Col("tcp", "encap_depth"),
            Col("tcp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "udp_packets",
        description: "UDP packets with IP addresses and frame metadata",
        anchor: ("udp", "udp"),
        joins: &[(Left, "ethernet", "e"), (Left, "ipv4", "ip4"), (Left, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("f", "length"),
            Col("e", "src_mac"),
            Col("e", "dst_mac"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("udp", "src_port"),
            Col("udp", "dst_port"),
            As("udp", "length", "udp_length"),
            Col("udp", "checksum"),
            Col("udp", "encap_depth"),
            Col("udp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "dns_packets",
        description: "DNS queries and responses with transport detection (UDP/TCP/DoT/DoH)",
        anchor: ("dns", "dns"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Left, "tcp", "tcp"), (Left, "udp", "udp"), (Left, "tls", "tls"), (Left, "http", "http")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Coalesce("src_port", &[("tcp", "src_port"), ("udp", "src_port")]),
            Coalesce("dst_port", &[("tcp", "dst_port"), ("udp", "dst_port")]),
            Present("transport", &[("http", "DoH"), ("tls", "DoT"), ("tcp", "TCP")], "UDP"),
            Col("dns", "transaction_id"),
            Col("dns", "is_query"),
            Col("dns", "opcode"),
            Col("dns", "is_authoritative"),
            Col("dns", "is_truncated"),
            Col("dns", "recursion_desired"),
            Col("dns", "recursion_available"),
            Col("dns", "response_code"),
            Col("dns", "query_count"),
            Col("dns", "answer_count"),
            Col("dns", "authority_count"),
            Col("dns", "additional_count"),
            Col("dns", "query_name"),
            Col("dns", "query_type"),
            Col("dns", "query_class"),
            Col("dns", "answer_ip4s"),
            Col("dns", "answer_ip6s"),
            Col("dns", "answer_cnames"),
            Col("dns", "answer_types"),
            Col("dns", "answer_ttls"),
            Col("dns", "has_edns"),
            Col("dns", "edns_udp_size"),
            Col("dns", "encap_depth"),
            Col("dns", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "http_packets",
        description: "HTTP requests and responses with TCP/IP context",
        anchor: ("http", "http"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "tcp", "tcp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("tcp", "src_port"),
            Col("tcp", "dst_port"),
            Col("http", "is_request"),
            Col("http", "method"),
            Col("http", "uri"),
            Col("http", "version"),
            Col("http", "status_code"),
            Col("http", "status_text"),
            Col("http", "host"),
            Col("http", "content_type"),
            Col("http", "content_length"),
            Col("http", "user_agent"),
            Col("http", "server"),
            Col("http", "encap_depth"),
            Col("http", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "tls_packets",
        description: "TLS records with TCP/IP context",
        anchor: ("tls", "tls"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "tcp", "tcp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("tcp", "src_port"),
            Col("tcp", "dst_port"),
            As("tcp", "flags", "tcp_flags"),
            Col("tls", "record_type"),
            Col("tls", "version"),
            Col("tls", "handshake_type"),
            Col("tls", "sni"),
            Col("tls", "cipher_suites"),
            Col("tls", "selected_cipher"),
            Col("tls", "encap_depth"),
            Col("tls", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "ssh_packets",
        description: "SSH packets with TCP/IP context",
        anchor: ("ssh", "ssh"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "tcp", "tcp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("tcp", "src_port"),
            Col("tcp", "dst_port"),
            Col("ssh", "protocol_version"),
            Col("ssh", "software_version"),
            Col("ssh", "comments"),
            Col("ssh", "msg_type"),
            Col("ssh", "msg_type_name"),
            Col("ssh", "encrypted"),
            Col("ssh", "kex_algorithms"),
            Col("ssh", "host_key_algorithms"),
            Col("ssh", "encryption_algorithms"),
            Col("ssh", "mac_algorithms"),
            Col("ssh", "compression_algorithms"),
            Col("ssh", "auth_username"),
            Col("ssh", "auth_service"),
            Col("ssh", "auth_method"),
            Col("ssh", "channel_type"),
            Col("ssh", "channel_id"),
            Col("ssh", "encap_depth"),
            Col("ssh", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "quic_packets",
        description: "QUIC packets with UDP/IP context",
        anchor: ("quic", "quic"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "udp", "udp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("udp", "src_port"),
            Col("udp", "dst_port"),
            Col("quic", "header_form"),
            Col("quic", "long_packet_type"),
            Col("quic", "version"),
            Col("quic", "version_name"),
            Col("quic", "dcid_length"),
            Col("quic", "dcid"),
            Col("quic", "scid_length"),
            Col("quic", "scid"),
            Col("quic", "token_length"),
            Col("quic", "packet_length"),
            Col("quic", "spin_bit"),
            Col("quic", "key_phase"),
            Col("quic", "sni"),
            Col("quic", "encap_depth"),
            Col("quic", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "arp_packets",
        description: "ARP requests and replies with Ethernet context",
        anchor: ("arp", "arp"),
        joins: &[(Left, "ethernet", "e")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("e", "src_mac"),
            Col("e", "dst_mac"),
            Col("arp", "hardware_type"),
            Col("arp", "protocol_type"),
            Col("arp", "hardware_size"),
            Col("arp", "protocol_size"),
            Col("arp", "operation"),
            Col("arp", "sender_mac"),
            Col("arp", "sender_ip"),
            Col("arp", "target_mac"),
            Col("arp", "target_ip"),
            Col("arp", "encap_depth"),
            Col("arp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "icmp_packets",
        description: "ICMP messages with IPv4 context",
        anchor: ("icmp", "icmp"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("icmp", "type"),
            Col("icmp", "code"),
            Col("icmp", "type_name"),
            Col("icmp", "checksum"),
            Col("icmp", "identifier"),
            Col("icmp", "sequence"),
            Col("icmp", "next_hop_mtu"),
            Col("icmp", "gateway"),
            Col("icmp", "encap_depth"),
            Col("icmp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "icmpv6_packets",
        description: "ICMPv6 messages with IPv6 context (including NDP and MLD)",
        anchor: ("icmpv6", "icmpv6"),
        joins: &[(Inner, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("ip6", "src_ip"),
            Col("ip6", "dst_ip"),
            Col("icmpv6", "type"),
            Col("icmpv6", "code"),
            Col("icmpv6", "type_name"),
            Col("icmpv6", "checksum"),
            Col("icmpv6", "echo_id"),
            Col("icmpv6", "echo_seq"),
            Col("icmpv6", "mtu"),
            Col("icmpv6", "pointer"),
            Col("icmpv6", "ndp_target_address"),
            Col("icmpv6", "ndp_cur_hop_limit"),
            Col("icmpv6", "ndp_managed_flag"),
            Col("icmpv6", "ndp_other_flag"),
            Col("icmpv6", "ndp_router_lifetime"),
            Col("icmpv6", "ndp_reachable_time"),
            Col("icmpv6", "ndp_retrans_timer"),
            Col("icmpv6", "ndp_router_flag"),
            Col("icmpv6", "ndp_solicited_flag"),
            Col("icmpv6", "ndp_override_flag"),
            Col("icmpv6", "ndp_source_mac"),
            Col("icmpv6", "ndp_target_mac"),
            Col("icmpv6", "ndp_prefix"),
            Col("icmpv6", "ndp_prefix_length"),
            Col("icmpv6", "mld_max_response_delay"),
            Col("icmpv6", "mld_multicast_address"),
            Col("icmpv6", "mld_num_group_records"),
            Col("icmpv6", "encap_depth"),
            Col("icmpv6", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "ndp_packets",
        description: "NDP messages (Router/Neighbor Solicitation/Advertisement, Redirect)",
        anchor: ("icmpv6", "icmpv6"),
        joins: &[(Inner, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("ip6", "src_ip"),
            Col("ip6", "dst_ip"),
            Col("ip6", "hop_limit"),
            Col("icmpv6", "type"),
            Col("icmpv6", "code"),
            Col("icmpv6", "type_name"),
            Col("icmpv6", "ndp_target_address"),
            Col("icmpv6", "ndp_cur_hop_limit"),
            Col("icmpv6", "ndp_managed_flag"),
            Col("icmpv6", "ndp_other_flag"),
            Col("icmpv6", "ndp_router_lifetime"),
            Col("icmpv6", "ndp_reachable_time"),
            Col("icmpv6", "ndp_retrans_timer"),
            Col("icmpv6", "ndp_router_flag"),
            Col("icmpv6", "ndp_solicited_flag"),
            Col("icmpv6", "ndp_override_flag"),
            Col("icmpv6", "ndp_source_mac"),
            Col("icmpv6", "ndp_target_mac"),
            Col("icmpv6", "ndp_prefix"),
            Col("icmpv6", "ndp_prefix_length"),
            Col("icmpv6", "encap_depth"),
            Col("icmpv6", "tunnel_type"),
        ],
        filter: Some(("icmpv6", "type", &[133, 134, 135, 136, 137])),
    },
    Def {
        name: "mld_packets",
        description: "MLD messages (Multicast Listener Discovery queries and reports)",
        anchor: ("icmpv6", "icmpv6"),
        joins: &[(Inner, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("ip6", "src_ip"),
            Col("ip6", "dst_ip"),
            Col("ip6", "hop_limit"),
            Col("icmpv6", "type"),
            Col("icmpv6", "code"),
            Col("icmpv6", "type_name"),
            Col("icmpv6", "mld_max_response_delay"),
            Col("icmpv6", "mld_multicast_address"),
            Col("icmpv6", "mld_num_group_records"),
            Col("icmpv6", "encap_depth"),
            Col("icmpv6", "tunnel_type"),
        ],
        filter: Some(("icmpv6", "type", &[130, 131, 132, 143])),
    },
    Def {
        name: "dhcp_packets",
        description: "DHCP messages with UDP/IP context",
        anchor: ("dhcp", "dhcp"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "udp", "udp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("udp", "src_port"),
            Col("udp", "dst_port"),
            Col("dhcp", "op"),
            Col("dhcp", "htype"),
            Col("dhcp", "hlen"),
            Col("dhcp", "hops"),
            Col("dhcp", "xid"),
            Col("dhcp", "secs"),
            Col("dhcp", "flags"),
            Col("dhcp", "ciaddr"),
            Col("dhcp", "yiaddr"),
            Col("dhcp", "siaddr"),
            Col("dhcp", "giaddr"),
            Col("dhcp", "chaddr"),
            Col("dhcp", "message_type"),
            Col("dhcp", "server_id"),
            Col("dhcp", "lease_time"),
            Col("dhcp", "subnet_mask"),
            Col("dhcp", "router"),
            Col("dhcp", "dns_servers"),
            Col("dhcp", "encap_depth"),
            Col("dhcp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "ntp_packets",
        description: "NTP messages with UDP/IP context",
        anchor: ("ntp", "ntp"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "udp", "udp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("udp", "src_port"),
            Col("udp", "dst_port"),
            Col("ntp", "version"),
            Col("ntp", "mode"),
            Col("ntp", "leap_indicator"),
            Col("ntp", "stratum"),
            Col("ntp", "poll"),
            Col("ntp", "precision"),
            Col("ntp", "root_delay"),
            Col("ntp", "root_dispersion"),
            Col("ntp", "reference_id"),
            Col("ntp", "reference_ts"),
            Col("ntp", "origin_ts"),
            Col("ntp", "receive_ts"),
            Col("ntp", "transmit_ts"),
            Col("ntp", "encap_depth"),
            Col("ntp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "gre_packets",
        description: "GRE tunneled packets with IP context",
        anchor: ("gre", "gre"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("gre", "version"),
            Col("gre", "protocol"),
            Col("gre", "checksum_present"),
            Col("gre", "key_present"),
            Col("gre", "sequence_present"),
            Col("gre", "key"),
            Col("gre", "sequence"),
            Col("gre", "checksum"),
            Col("gre", "encap_depth"),
            Col("gre", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "mpls_packets",
        description: "MPLS labeled packets with Ethernet context",
        anchor: ("mpls", "mpls"),
        joins: &[(Inner, "ethernet", "eth")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("eth", "src_mac"),
            Col("eth", "dst_mac"),
            Col("mpls", "label"),
            Col("mpls", "tc"),
            Col("mpls", "bottom"),
            Col("mpls", "ttl"),
            Col("mpls", "stack_depth"),
            Col("mpls", "labels"),
            Col("mpls", "encap_depth"),
            Col("mpls", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "vxlan_packets",
        description: "VXLAN encapsulated frames with UDP/IP context",
        anchor: ("vxlan", "vxlan"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "udp", "udp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("udp", "src_port"),
            Col("udp", "dst_port"),
            Col("vxlan", "flags"),
            Col("vxlan", "vni"),
            Col("vxlan", "encap_depth"),
            Col("vxlan", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "gtp_packets",
        description: "GTP tunneled packets with UDP/IP context",
        anchor: ("gtp", "gtp"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "udp", "udp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("udp", "src_port"),
            Col("udp", "dst_port"),
            Col("gtp", "version"),
            Col("gtp", "protocol_type"),
            Col("gtp", "message_type"),
            Col("gtp", "length"),
            Col("gtp", "teid"),
            Col("gtp", "sequence"),
            Col("gtp", "npdu"),
            Col("gtp", "extension_headers"),
            Col("gtp", "extension_header_count"),
            Col("gtp", "piggyback"),
            Col("gtp", "teid_present"),
            Col("gtp", "encap_depth"),
            Col("gtp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "ipsec_packets",
        description: "IPsec (ESP/AH) packets with IP context",
        anchor: ("ipsec", "ipsec"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("ipsec", "protocol"),
            Col("ipsec", "spi"),
            Col("ipsec", "sequence"),
            Col("ipsec", "ah_next_header"),
            Col("ipsec", "ah_icv_length"),
            Col("ipsec", "encap_depth"),
            Col("ipsec", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "bgp_packets",
        description: "BGP messages with TCP/IP context",
        anchor: ("bgp", "bgp"),
        joins: &[(Left, "ipv4", "ip4"), (Left, "ipv6", "ip6"), (Inner, "tcp", "tcp")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            As("ip4", "src_ip", "src_ip_v4"),
            As("ip4", "dst_ip", "dst_ip_v4"),
            As("ip6", "src_ip", "src_ip_v6"),
            As("ip6", "dst_ip", "dst_ip_v6"),
            Col("tcp", "src_port"),
            Col("tcp", "dst_port"),
            Col("bgp", "message_type"),
            Col("bgp", "message_type_name"),
            Col("bgp", "length"),
            Col("bgp", "version"),
            Col("bgp", "my_as"),
            Col("bgp", "hold_time"),
            Col("bgp", "bgp_id"),
            Col("bgp", "withdrawn_routes_len"),
            Col("bgp", "path_attr_len"),
            Col("bgp", "my_as_4byte"),
            Col("bgp", "capabilities"),
            Col("bgp", "withdrawn_routes"),
            Col("bgp", "withdrawn_count"),
            Col("bgp", "origin"),
            Col("bgp", "origin_name"),
            Col("bgp", "as_path"),
            Col("bgp", "as_path_length"),
            Col("bgp", "next_hop"),
            Col("bgp", "med"),
            Col("bgp", "local_pref"),
            Col("bgp", "atomic_aggregate"),
            Col("bgp", "aggregator_as"),
            Col("bgp", "aggregator_ip"),
            Col("bgp", "nlri"),
            Col("bgp", "nlri_count"),
            Col("bgp", "error_code"),
            Col("bgp", "error_code_name"),
            Col("bgp", "error_subcode"),
            Col("bgp", "afi"),
            Col("bgp", "safi"),
            Col("bgp", "encap_depth"),
            Col("bgp", "tunnel_type"),
        ],
        filter: None,
    },
    Def {
        name: "ospf_packets",
        description: "OSPF routing messages with IPv4 context",
        anchor: ("ospf", "ospf"),
        joins: &[(Inner, "ipv4", "ip4")],
        columns: &[
            Col("f", "frame_number"),
            Col("f", "timestamp"),
            Col("ip4", "src_ip"),
            Col("ip4", "dst_ip"),
            Col("ospf", "version"),
            Col("ospf", "message_type"),
            Col("ospf", "message_type_name"),
            Col("ospf", "length"),
            Col("ospf", "router_id"),
            Col("ospf", "area_id"),
            Col("ospf", "auth_type"),
            Col("ospf", "hello_interval"),
            Col("ospf", "dead_interval"),
            Col("ospf", "designated_router"),
            Col("ospf", "backup_dr"),
            Col("ospf", "neighbor_count"),
            Col("ospf", "dd_interface_mtu"),
            Col("ospf", "dd_options"),
            Col("ospf", "dd_flags"),
            Col("ospf", "dd_sequence"),
            Col("ospf", "dd_lsa_count"),
            Col("ospf", "lsu_lsa_count"),
            Col("ospf", "lsa_ack_count"),
            Col("ospf", "lsa_age"),
            Col("ospf", "lsa_type"),
            Col("ospf", "lsa_type_name"),
            Col("ospf", "lsa_id"),
            Col("ospf", "lsa_advertising_router"),
            Col("ospf", "lsa_sequence"),
            Col("ospf", "encap_depth"),
            Col("ospf", "tunnel_type"),
        ],
        filter: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_view_resolves_against_the_catalogue() {
        let views = PacketsView::all();
        assert_eq!(views.len(), 21);
        let mut names = HashSet::new();
        for view in views {
            assert!(names.insert(view.name), "{} twice", view.name);
            assert!(view.name.ends_with("_packets"), "{}", view.name);
            assert!(!view.description.is_empty(), "{}", view.name);
            // No view shadows a table.
            assert!(
                Catalog::builtin().table(view.name).is_none(),
                "{}",
                view.name
            );
            assert_eq!(PacketsView::get(view.name).unwrap().name, view.name);

            // frames, the anchor on frame_number, the rest on the anchor's
            // level.
            let members = view.members();
            assert_eq!(members[0].table, "frames");
            assert_eq!(members[0].member.join, None);
            assert_eq!(members[1].table, view.anchor);
            assert_eq!(
                members[1].member.join,
                Some(MemberJoin {
                    kind: JoinKind::Inner,
                    with: 0,
                    depth: false
                })
            );
            let mut aliases = HashSet::new();
            for member in members {
                assert!(
                    aliases.insert(member.alias),
                    "{}: {}",
                    view.name,
                    member.alias
                );
            }
            for member in &members[2..] {
                let join = member.member.join.unwrap();
                assert!(
                    join.depth && join.with == 1,
                    "{}: {}",
                    view.name,
                    member.alias
                );
            }

            let mut columns = HashSet::new();
            for column in view.columns() {
                assert!(columns.insert(column.name), "{}.{}", view.name, column.name);
            }
            // The frame's number and time lead, and say so.
            let [number, time, ..] = view.columns() else {
                panic!("{}: fewer than two columns", view.name);
            };
            assert_eq!((number.name, number.kind), ("frame_number", ColKind::U64));
            assert!(number.is_frame_number && !number.is_timestamp && !number.nullable);
            assert_eq!((time.name, time.kind), ("timestamp", ColKind::TsMicros));
            assert!(time.is_timestamp && !time.is_frame_number && !time.nullable);
            assert_eq!(time.kind_in(TimestampUnit::Nanos), ColKind::TsNanos);
            assert_eq!(
                view.columns()
                    .iter()
                    .filter(|c| c.is_frame_number || c.is_timestamp)
                    .count(),
                2,
                "{}",
                view.name
            );
            // The anchor's level is a column of every view.
            let depth = view.columns().iter().find(|c| c.name == "encap_depth");
            assert_eq!(
                depth.map(|c| (c.kind, c.nullable)),
                Some((ColKind::U8, false))
            );
        }
        assert!(PacketsView::get("packets").is_none());
        assert!(PacketsView::get("tcp").is_none());
    }

    #[test]
    fn tcp_packets_is_the_documented_join() {
        let view = PacketsView::get("tcp_packets").unwrap();
        assert_eq!(view.anchor, "tcp");
        let members: Vec<(&str, &str)> =
            view.members().iter().map(|m| (m.table, m.alias)).collect();
        assert_eq!(
            members,
            [
                ("frames", "f"),
                ("tcp", "tcp"),
                ("ethernet", "e"),
                ("ipv4", "ip4"),
                ("ipv6", "ip6")
            ]
        );
        let columns: Vec<(&str, ColKind, bool)> = view
            .columns()
            .iter()
            .map(|c| (c.name, c.kind, c.nullable))
            .collect();
        assert_eq!(
            columns,
            [
                ("frame_number", ColKind::U64, false),
                ("timestamp", ColKind::TsMicros, false),
                ("length", ColKind::U32, false),
                ("src_mac", ColKind::Fixed(6), true),
                ("dst_mac", ColKind::Fixed(6), true),
                ("src_ip_v4", ColKind::U32, true),
                ("dst_ip_v4", ColKind::U32, true),
                ("src_ip_v6", ColKind::Fixed(16), true),
                ("dst_ip_v6", ColKind::Fixed(16), true),
                ("ttl", ColKind::U8, true),
                ("src_port", ColKind::U16, true),
                ("dst_port", ColKind::U16, true),
                ("seq", ColKind::U32, true),
                ("ack", ColKind::U32, true),
                ("flags", ColKind::U16, true),
                ("window", ColKind::U16, true),
                ("checksum", ColKind::U16, true),
                ("urgent_ptr", ColKind::U16, true),
                ("encap_depth", ColKind::U8, false),
                ("tunnel_type", ColKind::Str, true),
            ]
        );
        assert!(matches!(view.value(9), FusedValue::Coalesce(arguments) if arguments.len() == 2));
        assert!(view.filter().is_none());
    }

    #[test]
    fn a_scan_keeps_the_projection_order_and_the_view_s_names() {
        let view = PacketsView::get("dns_packets").unwrap();
        let index = |name: &str| view.columns().iter().position(|c| c.name == name).unwrap();
        let projection = [index("transport"), index("src_port"), index("frame_number")];
        let scan = view.scan(&projection);
        assert_eq!(scan.members.len(), view.members().len());
        let plan = ScanPlan {
            fused: vec![scan],
            timestamps: TimestampUnit::Nanos,
            ..ScanPlan::default()
        }
        .compile(Catalog::builtin(), &default_registry())
        .unwrap();
        let names: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
        assert_eq!(names, ["transport", "src_port", "frame_number"]);
        // Members without an output column are still parsed: they decide
        // the transport and the ports.
        let required = plan.scope().required().unwrap();
        for protocol in ["dns", "tcp", "udp", "tls", "http"] {
            assert!(required.contains(protocol), "{protocol}");
        }
        assert!(view.scan(&[]).columns.is_empty());
        assert_eq!(view.full_scan().columns.len(), view.columns().len());
    }

    #[test]
    fn the_subsets_of_icmpv6_are_filters_on_its_type() {
        for (name, types) in [
            ("ndp_packets", &[133, 134, 135, 136, 137][..]),
            ("mld_packets", &[130, 131, 132, 143][..]),
        ] {
            let view = PacketsView::get(name).unwrap();
            assert_eq!(view.anchor, "icmpv6");
            let filter = view.filter().unwrap();
            assert_eq!(filter.member, 1);
            assert_eq!(filter.any_of, types);
            let (_, icmpv6) = Catalog::builtin().table("icmpv6").unwrap();
            assert_eq!(icmpv6.get(filter.column).name, "type");
        }
        assert!(PacketsView::get("icmpv6_packets")
            .unwrap()
            .filter()
            .is_none());
    }
}
