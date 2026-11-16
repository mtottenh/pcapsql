//! The built-in tables of [`Catalog::builtin`](super::Catalog::builtin).
//!
//! One function per table lists its own columns, in table order. The
//! columns every table of a kind shares are added by [`protocol_table`] and
//! [`stream_table`]:
//!
//! - `frame_number` leads every table and is the join key to `frames`.
//! - A protocol table continues with `timestamp`, the capture time of the
//!   row's frame. It is an opt-in column ([`ColumnDef::default`] is `false`):
//!   an engine that cannot fuse the join against `frames` exposes it so that
//!   a time-aware query needs one scan, and the others leave it out.
//! - Every table but `frames` ends with the encapsulation columns
//!   `encap_depth`, `tunnel_type` and `tunnel_id`.
//!
//! Column names are the parser's field names without the protocol prefix
//! (`dns.query_name` is `query_name` in `dns`). Comments starting with `--`
//! head a group of columns.

use super::catalog::ColKind::*;
use super::catalog::{ColKind, ColumnDef, ColumnSource, TableDef, TableKind};

/// Every built-in table. The order is the order tables are listed in and
/// defines their [`TableId`](super::TableId)s.
pub(super) fn builtin_tables() -> Vec<TableDef> {
    vec![
        TableDef {
            name: "frames",
            description: "Raw frame metadata (timestamp, length, etc.)",
            kind: TableKind::Frames,
            columns: frames().into(),
        },
        protocol_table("ethernet", "Ethernet II frames (Layer 2)", ethernet()),
        protocol_table(
            "linux_sll",
            "Linux cooked capture v1 (tcpdump -i any)",
            linux_sll(),
        ),
        protocol_table("sll2", "Linux cooked capture v2", sll2()),
        protocol_table("arp", "Address Resolution Protocol", arp()),
        protocol_table("vlan", "IEEE 802.1Q VLAN tags", vlan()),
        protocol_table("mpls", "Multiprotocol Label Switching", mpls()),
        protocol_table("ipv4", "Internet Protocol version 4", ipv4()),
        protocol_table("ipv6", "Internet Protocol version 6", ipv6()),
        protocol_table("tcp", "Transmission Control Protocol", tcp()),
        protocol_table("udp", "User Datagram Protocol", udp()),
        protocol_table("icmp", "Internet Control Message Protocol", icmp()),
        protocol_table("icmpv6", "ICMPv6 for IPv6", icmpv6()),
        protocol_table("gre", "Generic Routing Encapsulation", gre()),
        protocol_table("vxlan", "Virtual Extensible LAN", vxlan()),
        protocol_table("gtp", "GPRS Tunneling Protocol", gtp()),
        protocol_table("ipsec", "IP Security (ESP/AH)", ipsec()),
        protocol_table("bgp", "Border Gateway Protocol", bgp()),
        protocol_table("ospf", "Open Shortest Path First", ospf()),
        protocol_table("dns", "Domain Name System", dns()),
        protocol_table("dhcp", "Dynamic Host Configuration Protocol", dhcp()),
        protocol_table("ntp", "Network Time Protocol", ntp()),
        protocol_table(
            "http",
            "HTTP/1.x request and status lines with headers (per packet)",
            http(),
        ),
        stream_table("http2", "HTTP/2 frames of decrypted TLS streams", http2()),
        protocol_table("tls", "Transport Layer Security", tls()),
        protocol_table("ssh", "Secure Shell Protocol", ssh()),
        protocol_table("quic", "QUIC Transport Protocol", quic()),
        protocol_table(
            "netlink",
            "Linux netlink messages (nlmon captures)",
            netlink(),
        ),
        protocol_table(
            "rtnetlink",
            "Linux rtnetlink (route/link/address messages)",
            rtnetlink(),
        ),
        stream_table(
            "tcp_connections",
            "Reassembled TCP connections",
            tcp_connections(),
        ),
        stream_table(
            "tls_sessions",
            "TLS sessions of reassembled connections",
            tls_sessions(),
        ),
        stream_table(
            "http_messages",
            "HTTP/1.x messages of reassembled connections",
            http_messages(),
        ),
    ]
}

/// A protocol table: `frame_number`, the opt-in `timestamp`, the parser's
/// `fields`, then the encapsulation columns of the layer the row was parsed
/// from.
fn protocol_table(
    name: &'static str,
    description: &'static str,
    fields: Vec<ColumnDef>,
) -> TableDef {
    let mut columns = vec![
        ColumnDef::new("frame_number", U64, ColumnSource::FrameNumber).required(),
        ColumnDef::new("timestamp", TsMicros, ColumnSource::Timestamp)
            .required()
            .opt_in(),
    ];
    columns.extend(fields);
    columns.extend([
        // Encapsulation depth (0 = outer/no tunnel, 1+ = inside tunnel)
        ColumnDef::new("encap_depth", U8, ColumnSource::EncapDepth).required(),
        // Type of enclosing tunnel (vxlan, gre, gtp, mpls, ipinip, ip6inip, ipsec)
        ColumnDef::new("tunnel_type", Str, ColumnSource::TunnelType),
        // Tunnel identifier (VNI, GRE key, TEID, MPLS label)
        ColumnDef::new("tunnel_id", U64, ColumnSource::TunnelId),
    ]);
    TableDef {
        name,
        description,
        kind: TableKind::Protocol,
        columns: columns.into(),
    }
}

/// A stream table: `frame_number` (the frame the row is attributed to),
/// the table's own `columns`, then the encapsulation columns. Reassembly
/// follows the innermost TCP flow and does not attribute a row to a tunnel,
/// so the stream builders fill those with depth 0 and no tunnel.
fn stream_table(
    name: &'static str,
    description: &'static str,
    columns: Vec<ColumnDef>,
) -> TableDef {
    let mut all = vec![stream("frame_number", U64).required()];
    all.extend(columns);
    all.extend([
        stream("encap_depth", U8).required(),
        stream("tunnel_type", Str),
        stream("tunnel_id", U64),
    ]);
    TableDef {
        name,
        description,
        kind: TableKind::Stream,
        columns: all.into(),
    }
}

/// A nullable column filled from the parser field of the same name.
const fn field(name: &'static str, kind: ColKind) -> ColumnDef {
    ColumnDef::field(name, kind)
}

/// A nullable column computed by stream analysis.
const fn stream(name: &'static str, kind: ColKind) -> ColumnDef {
    ColumnDef::new(name, kind, ColumnSource::Stream)
}

/// The `frames` table contains raw packet metadata and data.
/// This is the base table that all other protocol tables reference.
///
/// - `frame_number`: Unique identifier (1-indexed)
fn frames() -> Vec<ColumnDef> {
    vec![
        ColumnDef::new("frame_number", U64, ColumnSource::FrameNumber).required(),
        // Capture timestamp
        ColumnDef::new("timestamp", TsMicros, ColumnSource::Timestamp).required(),
        // Captured length
        ColumnDef::new("length", U32, ColumnSource::CapturedLen).required(),
        // Original packet length on wire
        ColumnDef::new("original_length", U32, ColumnSource::OriginalLen).required(),
        // Link layer type (e.g., 1 = Ethernet)
        ColumnDef::new("link_type", U16, ColumnSource::LinkType).required(),
        // Complete packet bytes
        ColumnDef::new("raw_data", Bin, ColumnSource::RawData).required(),
    ]
}

/// The `ethernet` table contains Ethernet II frame headers.
fn ethernet() -> Vec<ColumnDef> {
    vec![
        // Source MAC address (6 bytes)
        field("src_mac", Fixed(6)),
        // Destination MAC address (6 bytes)
        field("dst_mac", Fixed(6)),
        // EtherType field (e.g., 0x0800 = IPv4)
        field("ethertype", U16),
    ]
}

/// The `linux_sll` table contains Linux cooked capture header fields.
///
/// ## Usage
///
/// ```sql
/// SELECT * FROM linux_sll WHERE arphrd_name = 'NETLINK';
/// SELECT * FROM linux_sll WHERE packet_type_name = 'OUTGOING';
/// ```
fn linux_sll() -> Vec<ColumnDef> {
    vec![
        // Packet type (0=host, 1=broadcast, 2=multicast, 3=otherhost, 4=outgoing)
        field("packet_type", U16),
        // Human-readable packet type name
        field("packet_type_name", Str),
        // ARPHRD link layer type
        field("arphrd_type", U16),
        // Human-readable ARPHRD type name
        field("arphrd_name", Str),
        // Link layer address length
        field("addr_len", U16),
        // Link layer address (up to 8 bytes)
        field("addr", Bin),
        // Protocol type (ethertype or netlink family)
        field("protocol", U16),
    ]
}

/// The `sll2` table contains second-generation Linux cooked capture header
/// fields (LINKTYPE_LINUX_SLL2 = 276), the default link type for
/// `tcpdump -i any` with libpcap >= 1.10.
///
/// ## Usage
///
/// ```sql
/// SELECT interface_index, count(*) FROM sll2 GROUP BY interface_index;
/// SELECT * FROM sll2 WHERE packet_type_name = 'OUTGOING';
/// ```
fn sll2() -> Vec<ColumnDef> {
    vec![
        // Protocol type (ethertype or netlink family)
        field("protocol", U16),
        // Index of the interface the packet was captured on
        field("interface_index", U32),
        // ARPHRD link layer type
        field("arphrd_type", U16),
        // Human-readable ARPHRD type name
        field("arphrd_name", Str),
        // Packet type (0=host, 1=broadcast, 2=multicast, 3=otherhost, 4=outgoing)
        field("packet_type", U8),
        // Human-readable packet type name
        field("packet_type_name", Str),
        // Link layer address length
        field("addr_len", U8),
        // Link layer address (up to 8 bytes)
        field("addr", Bin),
    ]
}

/// The `arp` table contains Address Resolution Protocol fields.
///
/// ## Address Storage
///
/// - MAC addresses: `Fixed(6)` (48 bits)
/// - IPv4 addresses: `U32` (32 bits, network byte order)
///
/// Use the `mac()` and `ip4()` functions for queries:
/// ```sql
/// SELECT * FROM arp WHERE sender_ip = ip4('192.168.1.1');
/// SELECT * FROM arp WHERE sender_mac = mac('aa:bb:cc:dd:ee:ff');
/// ```
fn arp() -> Vec<ColumnDef> {
    vec![
        // Hardware type (1 = Ethernet)
        field("hardware_type", U16),
        // Protocol type (0x0800 = IPv4)
        field("protocol_type", U16),
        // Hardware address size (6 for Ethernet)
        field("hardware_size", U8),
        // Protocol address size (4 for IPv4)
        field("protocol_size", U8),
        // Operation code (1 = Request, 2 = Reply)
        field("operation", U16),
        // Human-readable operation name
        field("operation_name", Str),
        // -- MAC addresses stored as Fixed(6)
        // Sender MAC address (Fixed(6))
        field("sender_mac", Fixed(6)),
        // -- IPv4 addresses stored as U32 (network byte order)
        // Sender IP address (U32)
        field("sender_ip", U32),
        // Target MAC address (Fixed(6))
        field("target_mac", Fixed(6)),
        // Target IP address (U32)
        field("target_ip", U32),
    ]
}

/// The `vlan` table contains 802.1Q VLAN tag fields.
fn vlan() -> Vec<ColumnDef> {
    vec![
        // VLAN identifier (12 bits)
        field("vlan_id", U16),
        // Priority Code Point (3 bits)
        field("priority", U8),
        // Drop Eligible Indicator (1 bit)
        field("dei", Bool),
        // Encapsulated protocol type
        field("inner_ethertype", U16),
    ]
}

/// The `mpls` table contains MPLS (Multi-Protocol Label Switching) fields.
fn mpls() -> Vec<ColumnDef> {
    vec![
        // Top label value (20-bit)
        field("label", U32),
        // Traffic Class (3-bit)
        field("tc", U8),
        // Bottom of stack flag
        field("bottom", Bool),
        // Time to Live
        field("ttl", U8),
        // Number of labels in the stack
        field("stack_depth", U8),
        // Comma-separated list of all labels
        field("labels", Str),
    ]
}

/// The `ipv4` table contains IPv4 header fields.
///
/// ## Address Storage
///
/// IPv4 addresses are stored as `U32` in network byte order (big-endian).
/// This enables:
/// - Efficient CIDR range queries via bitwise operations
/// - Correct numerical ordering (not lexicographic)
/// - 4x storage reduction vs UTF-8 strings
///
/// Use the `ip4()` function to convert string literals in queries:
/// ```sql
/// SELECT * FROM ipv4 WHERE src_ip = ip4('192.168.1.1');
/// SELECT * FROM ipv4 WHERE ip_in_cidr(src_ip, '10.0.0.0/8');
/// SELECT * FROM ipv4 WHERE src_ip BETWEEN ip4('10.0.0.0') AND ip4('10.0.0.255');
/// ```
fn ipv4() -> Vec<ColumnDef> {
    vec![
        // IP version (always 4)
        field("version", U8),
        // Internet Header Length
        field("ihl", U8),
        // Differentiated Services Code Point
        field("dscp", U8),
        // Explicit Congestion Notification
        field("ecn", U8),
        // Total packet length
        field("total_length", U16),
        // Identification field
        field("identification", U16),
        // Don't Fragment flag
        field("dont_fragment", Bool),
        // More Fragments flag
        field("more_fragments", Bool),
        // Fragment offset
        field("fragment_offset", U16),
        // Time To Live
        field("ttl", U8),
        // Protocol number (6=TCP, 17=UDP, 1=ICMP)
        field("protocol", U8),
        // Header checksum
        field("checksum", U16),
        // -- IPv4 addresses stored as U32 (4 bytes, network byte order)
        // Source IP address (U32, network byte order)
        field("src_ip", U32),
        // Destination IP address (U32, network byte order)
        field("dst_ip", U32),
    ]
}

/// The `ipv6` table contains IPv6 header fields.
///
/// ## Address Storage
///
/// IPv6 addresses are stored as `Fixed(16)` (128 bits).
/// This enables:
/// - Efficient prefix/CIDR matching via bitwise operations
/// - Correct binary ordering
/// - Compact storage (16 bytes vs 39+ bytes for string)
///
/// Use the `ip6()` function to convert string literals in queries:
/// ```sql
/// SELECT * FROM ipv6 WHERE src_ip = ip6('fe80::1');
/// SELECT * FROM ipv6 WHERE ip6_in_cidr(src_ip, '2001:db8::/32');
/// ```
fn ipv6() -> Vec<ColumnDef> {
    vec![
        // IP version (always 6)
        field("version", U8),
        // Traffic class
        field("traffic_class", U8),
        // Flow label
        field("flow_label", U32),
        // Payload length
        field("payload_length", U16),
        // Next header protocol number
        field("next_header", U8),
        // Hop limit (similar to TTL)
        field("hop_limit", U8),
        // -- IPv6 addresses stored as Fixed(16) (128 bits)
        // Source IPv6 address (Fixed(16))
        field("src_ip", Fixed(16)),
        // Destination IPv6 address (Fixed(16))
        field("dst_ip", Fixed(16)),
        // -- Extension header chain
        // `ext_hop_by_hop`, `ext_routing`, `ext_fragment`, `ext_destination`: whether the
        // extension header chain contains that header (`next_header` is the first header of the
        // chain; the transport is found after it)
        field("ext_hop_by_hop", Bool),
        field("ext_routing", Bool),
        field("ext_fragment", Bool),
        field("ext_destination", Bool),
        // `frag_offset`, `frag_more`, `frag_id`: Fragment header
        field("frag_offset", U16),
        field("frag_more", Bool),
        field("frag_id", U32),
        // `routing_type`, `segments_left`: Routing header
        field("routing_type", U8),
        field("segments_left", U8),
    ]
}

/// The `tcp` table contains TCP segment header fields.
fn tcp() -> Vec<ColumnDef> {
    vec![
        // Source port
        field("src_port", U16),
        // Destination port
        field("dst_port", U16),
        // Sequence number
        field("seq", U32),
        // Acknowledgment number
        field("ack", U32),
        // Data offset (header length in 32-bit words)
        field("data_offset", U8),
        // Combined flags value
        field("flags", U16),
        // `flag_fin`, `flag_syn`, `flag_rst`, `flag_psh`, `flag_ack`, `flag_urg`: Individual
        // flags
        field("flag_fin", Bool),
        field("flag_syn", Bool),
        field("flag_rst", Bool),
        field("flag_psh", Bool),
        field("flag_ack", Bool),
        field("flag_urg", Bool),
        // Window size
        field("window", U16),
        // Checksum
        field("checksum", U16),
        // Urgent pointer
        field("urgent_ptr", U16),
        // Length of TCP options
        field("options_length", U8),
        // -- TCP options fields
        // Comma-separated list of TCP options present
        field("options", Str),
        // Maximum Segment Size (option 2)
        field("mss", U16),
        // Window scale factor (option 3)
        field("window_scale", U8),
        // SACK permitted (option 4)
        field("sack_permitted", Bool),
        // SACK block left edges (option 5)
        field("sack_left_edges", ListU32),
        // SACK block right edges (option 5)
        field("sack_right_edges", ListU32),
        // TCP timestamp value (option 8)
        field("ts_val", U32),
        // TCP timestamp echo reply (option 8)
        field("ts_ecr", U32),
    ]
}

/// The `udp` table contains UDP datagram header fields.
fn udp() -> Vec<ColumnDef> {
    vec![
        // Source port
        field("src_port", U16),
        // Destination port
        field("dst_port", U16),
        // Datagram length (header + data)
        field("length", U16),
        // Checksum
        field("checksum", U16),
    ]
}

/// The `icmp` table contains ICMP (Internet Control Message Protocol) fields.
///
/// ## Address Storage
///
/// - IPv4 gateway address: `U32` (32 bits, network byte order)
///
/// Use the `ip4()` function for queries:
/// ```sql
/// SELECT * FROM icmp WHERE gateway = ip4('192.168.1.1');
/// ```
fn icmp() -> Vec<ColumnDef> {
    vec![
        // ICMP type (e.g., 8 = Echo Request)
        field("type", U8),
        // ICMP code (subtype)
        field("code", U8),
        // ICMP checksum
        field("checksum", U16),
        // Human-readable type name
        field("type_name", Str),
        // Echo request/reply identifier
        field("identifier", U16),
        // Echo request/reply sequence number
        field("sequence", U16),
        // MTU for "fragmentation needed" errors
        field("next_hop_mtu", U16),
        // -- Gateway address stored as U32 (network byte order)
        // Gateway address for redirects (U32)
        field("gateway", U32),
    ]
}

/// The `icmpv6` table contains ICMPv6 fields including NDP and MLD messages.
///
/// ## Address Storage
///
/// - IPv6 addresses: `Fixed(16)` (128 bits)
/// - MAC addresses: `Fixed(6)` (48 bits)
///
/// Use the `ip6()` and `mac()` functions for queries:
/// ```sql
/// SELECT * FROM icmpv6 WHERE ndp_target_address = ip6('fe80::1');
/// SELECT * FROM icmpv6 WHERE ndp_source_mac = mac('aa:bb:cc:dd:ee:ff');
/// ```
fn icmpv6() -> Vec<ColumnDef> {
    vec![
        // -- Core ICMPv6 fields
        field("type", U8),
        field("code", U8),
        field("checksum", U16),
        field("type_name", Str),
        // -- Echo request/reply
        field("echo_id", U16),
        field("echo_seq", U16),
        // -- Packet Too Big
        field("mtu", U32),
        // -- Parameter Problem
        field("pointer", U32),
        // -- NDP common - IPv6 address stored as Fixed(16)
        field("ndp_target_address", Fixed(16)),
        // -- Router Advertisement
        field("ndp_cur_hop_limit", U8),
        field("ndp_managed_flag", Bool),
        field("ndp_other_flag", Bool),
        field("ndp_router_lifetime", U16),
        field("ndp_reachable_time", U32),
        field("ndp_retrans_timer", U32),
        // -- Neighbor Advertisement
        field("ndp_router_flag", Bool),
        field("ndp_solicited_flag", Bool),
        field("ndp_override_flag", Bool),
        // -- NDP Options - MAC addresses stored as Fixed(6)
        field("ndp_source_mac", Fixed(6)),
        field("ndp_target_mac", Fixed(6)),
        // -- IPv6 prefix stored as Fixed(16)
        field("ndp_prefix", Fixed(16)),
        field("ndp_prefix_length", U8),
        // -- MLD - IPv6 multicast address stored as Fixed(16)
        field("mld_max_response_delay", U16),
        field("mld_multicast_address", Fixed(16)),
        field("mld_num_group_records", U16),
    ]
}

/// The `gre` table contains GRE (Generic Routing Encapsulation) fields.
fn gre() -> Vec<ColumnDef> {
    vec![
        // C flag - checksum present
        field("checksum_present", Bool),
        // K flag - key present
        field("key_present", Bool),
        // S flag - sequence number present
        field("sequence_present", Bool),
        // GRE version (0 or 1)
        field("version", U8),
        // Encapsulated protocol (ethertype)
        field("protocol", U16),
        // Optional checksum value
        field("checksum", U16),
        // Optional key value
        field("key", U32),
        // Optional sequence number
        field("sequence", U32),
    ]
}

/// The `vxlan` table contains VXLAN (Virtual Extensible LAN) fields.
fn vxlan() -> Vec<ColumnDef> {
    vec![
        // VXLAN flags byte (I flag in bit 3)
        field("flags", U8),
        // VXLAN Network Identifier (24-bit)
        field("vni", U32),
    ]
}

/// The `gtp` table contains GTP (GPRS Tunneling Protocol) fields.
fn gtp() -> Vec<ColumnDef> {
    vec![
        // GTP version (1 for GTPv1)
        field("version", U8),
        // 1 = GTP, 0 = GTP'
        field("protocol_type", U8),
        // Message type code
        field("message_type", U8),
        // Payload length
        field("length", U16),
        // Tunnel Endpoint Identifier
        field("teid", U32),
        // Optional sequence number
        field("sequence", U32),
        // -- GTPv1 optional header fields
        // N-PDU number (GTPv1, PN flag)
        field("npdu", U8),
        // GTPv1 extension header chain, comma-separated `Name(0xNN)` entries in header order
        field("extension_headers", Str),
        // Extension headers in the chain
        field("extension_header_count", U8),
        // -- GTPv2-C flags
        // GTPv2-C P flag (another message follows this one)
        field("piggyback", Bool),
        // GTPv2-C T flag (the header carries a TEID)
        field("teid_present", Bool),
    ]
}

/// The `ipsec` table contains IPsec (ESP and AH) fields.
fn ipsec() -> Vec<ColumnDef> {
    vec![
        // "ESP" or "AH"
        field("protocol", Str),
        // Security Parameters Index
        field("spi", U32),
        // Sequence number
        field("sequence", U32),
        // Next header (AH only)
        field("ah_next_header", U8),
        // ICV length in bytes (AH only)
        field("ah_icv_length", U8),
    ]
}

/// The `bgp` table contains BGP (Border Gateway Protocol) fields.
fn bgp() -> Vec<ColumnDef> {
    vec![
        // BGP message type code
        field("message_type", U8),
        // Human-readable message type name
        field("message_type_name", Str),
        // Total message length
        field("length", U16),
        // -- OPEN
        // BGP version (OPEN message)
        field("version", U8),
        // My AS number (OPEN message)
        field("my_as", U16),
        // AS number from the 4-byte-AS capability, or `my_as` when the OPEN carries none (OPEN
        // message)
        field("my_as_4byte", U32),
        // Hold time in seconds (OPEN message)
        field("hold_time", U16),
        // Router ID as IP string (OPEN message)
        field("bgp_id", Str),
        // Capability names, comma-separated (OPEN message)
        field("capabilities", Str),
        // -- UPDATE
        // Withdrawn routes length (UPDATE message)
        field("withdrawn_routes_len", U16),
        // Withdrawn prefixes, comma-separated (UPDATE message)
        field("withdrawn_routes", Str),
        // Number of withdrawn prefixes (UPDATE message)
        field("withdrawn_count", U16),
        // Path attributes length (UPDATE message)
        field("path_attr_len", U16),
        // `origin`, `origin_name`: ORIGIN attribute code and name (UPDATE message)
        field("origin", U8),
        field("origin_name", Str),
        // AS_PATH, space-separated AS numbers; an AS_SET in braces (UPDATE message)
        field("as_path", Str),
        // AS_PATH length (one per AS_SEQUENCE entry, one per AS_SET) (UPDATE message)
        field("as_path_length", U16),
        // NEXT_HOP IPv4 address as a string (UPDATE message)
        field("next_hop", Str),
        // MULTI_EXIT_DISC (UPDATE message)
        field("med", U32),
        // LOCAL_PREF (UPDATE message)
        field("local_pref", U32),
        // ATOMIC_AGGREGATE present (UPDATE message)
        field("atomic_aggregate", Bool),
        // `aggregator_as`, `aggregator_ip`: AGGREGATOR attribute (UPDATE message)
        field("aggregator_as", U32),
        field("aggregator_ip", Str),
        // Announced prefixes, comma-separated (UPDATE message)
        field("nlri", Str),
        // Number of announced prefixes (UPDATE message)
        field("nlri_count", U16),
        // -- NOTIFICATION
        // `error_code`, `error_code_name`, `error_subcode`: NOTIFICATION message
        field("error_code", U8),
        field("error_code_name", Str),
        field("error_subcode", U8),
        // -- ROUTE-REFRESH
        // `afi`, `safi`: Address family (ROUTE-REFRESH message)
        field("afi", U16),
        field("safi", U8),
    ]
}

/// The `ospf` table contains OSPF (Open Shortest Path First) fields.
fn ospf() -> Vec<ColumnDef> {
    vec![
        // OSPF version (2 or 3)
        field("version", U8),
        // OSPF packet type code
        field("message_type", U8),
        // Human-readable packet type name
        field("message_type_name", Str),
        // Packet length
        field("length", U16),
        // Router ID as IP string
        field("router_id", Str),
        // Area ID as IP string
        field("area_id", Str),
        // Authentication type
        field("auth_type", U16),
        // -- Hello
        // Hello interval in seconds (Hello packet)
        field("hello_interval", U16),
        // Dead interval in seconds (Hello packet)
        field("dead_interval", U32),
        // DR IP address (Hello packet)
        field("designated_router", Str),
        // BDR IP address (Hello packet)
        field("backup_dr", Str),
        // Neighbours listed (Hello packet)
        field("neighbor_count", U16),
        // -- Database Description
        // `dd_interface_mtu`, `dd_options`, `dd_flags`, `dd_sequence`: Database Description
        // packet header
        field("dd_interface_mtu", U16),
        field("dd_options", U8),
        field("dd_flags", U8),
        field("dd_sequence", U32),
        // LSA headers in a Database Description packet
        field("dd_lsa_count", U16),
        // -- Link State Update / Acknowledgment
        // LSAs in a Link State Update packet
        field("lsu_lsa_count", U32),
        // LSA headers in a Link State Acknowledgment packet
        field("lsa_ack_count", U16),
        // -- First LSA header (DD, LSU, LSAck)
        field("lsa_age", U16),
        field("lsa_type", U8),
        field("lsa_type_name", Str),
        field("lsa_id", Str),
        field("lsa_advertising_router", Str),
        field("lsa_sequence", U32),
    ]
}

/// The `dns` table contains DNS (Domain Name System) query and response fields.
fn dns() -> Vec<ColumnDef> {
    vec![
        // DNS transaction identifier
        field("transaction_id", U16),
        // True if this is a query, false if response
        field("is_query", Bool),
        // Operation code
        field("opcode", U8),
        // Authoritative answer flag
        field("is_authoritative", Bool),
        // Truncation flag
        field("is_truncated", Bool),
        // Recursion desired flag
        field("recursion_desired", Bool),
        // Recursion available flag
        field("recursion_available", Bool),
        // Response code (0 = NOERROR, 3 = NXDOMAIN, etc.)
        field("response_code", U8),
        // Number of questions
        field("query_count", U16),
        // Number of answer RRs
        field("answer_count", U16),
        // Number of authority RRs
        field("authority_count", U16),
        // Number of additional RRs
        field("additional_count", U16),
        // First query domain name
        field("query_name", Str),
        // First query type (1 = A, 28 = AAAA, etc.)
        field("query_type", U16),
        // First query class (1 = IN)
        field("query_class", U16),
        // -- New list fields for DNS answers
        // List of A record IP addresses (as u32)
        field("answer_ip4s", ListU32),
        // List of AAAA record IP addresses (as 16-byte binary)
        field("answer_ip6s", ListFixed(16)),
        // List of CNAME record values
        field("answer_cnames", ListStr),
        // List of answer record types
        field("answer_types", ListU16),
        // List of answer TTL values
        field("answer_ttls", ListU32),
        // -- EDNS fields
        // Whether EDNS is present
        field("has_edns", Bool),
        // EDNS UDP payload size
        field("edns_udp_size", U16),
    ]
}

/// The `dhcp` table contains DHCP (Dynamic Host Configuration Protocol) fields.
///
/// ## Address Storage
///
/// - IPv4 addresses: `U32` (32 bits, network byte order)
/// - MAC addresses: `Fixed(6)` (48 bits)
/// - Subnet mask: `U32` (32 bits, as bitmask)
///
/// Use the `ip4()` and `mac()` functions for queries:
/// ```sql
/// SELECT * FROM dhcp WHERE yiaddr = ip4('192.168.1.100');
/// SELECT * FROM dhcp WHERE chaddr = mac('aa:bb:cc:dd:ee:ff');
/// ```
fn dhcp() -> Vec<ColumnDef> {
    vec![
        // -- BOOTP header fields
        field("op", U8),
        field("htype", U8),
        field("hlen", U8),
        field("hops", U8),
        field("xid", U32),
        field("secs", U16),
        field("flags", U16),
        // -- IPv4 addresses stored as U32 (network byte order)
        // Client IP address
        field("ciaddr", U32),
        // Your (client) IP address
        field("yiaddr", U32),
        // Server IP address
        field("siaddr", U32),
        // Gateway IP address
        field("giaddr", U32),
        // -- MAC address stored as Fixed(6)
        field("chaddr", Fixed(6)),
        // -- Common DHCP options
        field("message_type", U8),
        // Server identifier (IPv4)
        field("server_id", U32),
        field("lease_time", U32),
        // Subnet mask as bitmask
        field("subnet_mask", U32),
        // Default gateway (IPv4)
        field("router", U32),
        // -- DNS servers as comma-separated string (multiple IPs)
        field("dns_servers", Str),
    ]
}

/// The `ntp` table contains NTP (Network Time Protocol) fields.
fn ntp() -> Vec<ColumnDef> {
    vec![
        // NTP version (3 or 4)
        field("version", U8),
        // Mode (1-7: symmetric, client, server, broadcast, etc.)
        field("mode", U8),
        // Leap indicator (0-3)
        field("leap_indicator", U8),
        // Stratum level (0-15)
        field("stratum", U8),
        // Poll interval exponent
        field("poll", I8),
        // Clock precision exponent
        field("precision", I8),
        // Root delay (seconds as f64)
        field("root_delay", F64),
        // Root dispersion (seconds as f64)
        field("root_dispersion", F64),
        // Reference identifier
        field("reference_id", Str),
        // Reference timestamp
        field("reference_ts", F64),
        // Origin timestamp
        field("origin_ts", F64),
        // Receive timestamp
        field("receive_ts", F64),
        // Transmit timestamp
        field("transmit_ts", F64),
    ]
}

/// The `http` table has one row per TCP segment that starts an HTTP/1.x
/// message: the request line or status line and the headers present in
/// that segment, as parsed per packet by `pcapsql_core`'s `http` protocol.
/// Reassembled messages (bodies, headers spanning segments, keep-alive
/// streams) are the stream table `http_messages`.
fn http() -> Vec<ColumnDef> {
    vec![
        // True if this is a request, false if response
        field("is_request", Bool),
        // True if the whole header block is in this segment
        field("headers_complete", Bool),
        // HTTP method (GET, POST, etc.)
        field("method", Str),
        // Request URI
        field("uri", Str),
        // HTTP version (e.g., "HTTP/1.1")
        field("version", Str),
        // Response status code (200, 404, etc.)
        field("status_code", U16),
        // Response status text
        field("status_text", Str),
        // Payload bytes after the header block in this segment (headers complete only; may
        // include pipelined requests or chunk framing)
        field("body_length", U64),
        // Host header value
        field("host", Str),
        // Content-Type header value
        field("content_type", Str),
        // Content-Length header value
        field("content_length", U64),
        // User-Agent header value
        field("user_agent", Str),
        // Server header value
        field("server", Str),
        // Transfer-Encoding header value
        field("transfer_encoding", Str),
        // Connection header value
        field("connection", Str),
        // Cookie header value
        field("cookie", Str),
        // First Set-Cookie header value
        field("set_cookie", Str),
        // Referer header value
        field("referer", Str),
        // Accept header value
        field("accept", Str),
        // Accept-Encoding header value
        field("accept_encoding", Str),
        // Accept-Language header value
        field("accept_language", Str),
        // Cache-Control header value
        field("cache_control", Str),
        // Authorization type (e.g., "Bearer", "Basic")
        field("authorization", Str),
        // Location header value (for redirects)
        field("location", Str),
        // X-Forwarded-For header value
        field("x_forwarded_for", Str),
        // X-Real-IP header value
        field("x_real_ip", Str),
    ]
}

/// The `http2` table contains HTTP/2 frame-level data parsed from decrypted
/// TLS streams. It includes frame metadata, headers (for HEADERS frames),
/// and stream state information.
fn http2() -> Vec<ColumnDef> {
    vec![
        // -- Frame information
        // Reassembled TCP connection the frame belongs to
        stream("connection_id", U64),
        // HTTP/2 frame type (DATA, HEADERS, SETTINGS, etc.)
        stream("frame_type", Str),
        // HTTP/2 stream identifier (0 for connection-level frames)
        stream("stream_id", U32),
        // Raw frame flags byte
        stream("flags", U8),
        // Frame payload length
        stream("length", U32),
        // -- Request (pseudo-headers)
        // HTTP method (:method pseudo-header)
        stream("method", Str),
        // Request path (:path pseudo-header)
        stream("path", Str),
        // Host/authority (:authority pseudo-header)
        stream("authority", Str),
        // URL scheme (:scheme pseudo-header)
        stream("scheme", Str),
        // -- Response
        // HTTP status code (:status pseudo-header)
        stream("status", U16),
        // -- Headers
        // Content-Type header value
        stream("content_type", Str),
        // Content-Length header value
        stream("content_length", U64),
        // User-Agent header value
        stream("user_agent", Str),
        // -- DATA frames
        // Length of data payload
        stream("data_length", U64),
        // Whether END_STREAM flag is set
        stream("end_stream", Bool),
        // Whether END_HEADERS flag is set
        stream("end_headers", Bool),
        // Length of padding (if PADDED flag set)
        stream("padding_length", U8),
        // -- SETTINGS frames
        // Whether ACK flag is set
        stream("ack", Bool),
        // SETTINGS_HEADER_TABLE_SIZE value
        stream("header_table_size", U32),
        // SETTINGS_MAX_CONCURRENT_STREAMS value
        stream("max_concurrent_streams", U32),
        // SETTINGS_INITIAL_WINDOW_SIZE value
        stream("initial_window_size", U32),
        // SETTINGS_MAX_FRAME_SIZE value
        stream("max_frame_size", U32),
        // -- Error handling
        // Error code from RST_STREAM or GOAWAY
        stream("error_code", U32),
        // Human-readable error name
        stream("error_name", Str),
        // -- GOAWAY frames
        // Last stream ID from GOAWAY
        stream("last_stream_id", U32),
        // -- WINDOW_UPDATE frames
        // Window size increment
        stream("window_increment", U32),
        // -- PRIORITY frames
        // Exclusive dependency flag
        stream("priority_exclusive", Bool),
        // Stream dependency
        stream("priority_dependency", U32),
        // Priority weight (1-256)
        stream("priority_weight", U8),
        // -- PUSH_PROMISE frames
        // Promised stream ID
        stream("promised_stream_id", U32),
    ]
}

/// The `tls` table contains TLS/SSL handshake and record fields.
///
/// ## Decryption Foundation
///
/// The `client_random` and `server_random` fields are essential for TLS decryption
/// when used with SSLKEYLOGFILE. The `session_id` field tracks session resumption.
///
/// ## JA3 Fingerprinting
///
/// JA3 and JA3S fingerprints enable TLS client/server fingerprinting for
/// threat hunting and security analysis.
fn tls() -> Vec<ColumnDef> {
    vec![
        // -- Core identification
        // -- Record layer
        // TLS record type (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application)
        field("record_type", U8),
        // Record layer version (e.g., 0x0303 for TLS 1.2)
        field("record_version", U16),
        // TLS version string (e.g., "TLS 1.2", "TLS 1.3")
        field("version", Str),
        // -- Handshake
        // Handshake message type (1=ClientHello, 2=ServerHello, etc.)
        field("handshake_type", U8),
        // Handshake protocol version
        field("handshake_version", U16),
        // -- Decryption foundation fields
        // 32-byte random from ClientHello (key lookup)
        field("client_random", Fixed(32)),
        // 32-byte random from ServerHello (key derivation)
        field("server_random", Fixed(32)),
        // Session identifier for resumption tracking
        field("session_id", Bin),
        // Length of session ID
        field("session_id_length", U8),
        // -- Cipher suites
        // Offered cipher suites (semicolon-separated, from ClientHello)
        field("cipher_suites", Str),
        // Number of offered cipher suites
        field("cipher_suite_count", U16),
        // Selected cipher suite name (from ServerHello)
        field("selected_cipher", Str),
        // Selected cipher suite ID (for decryption)
        field("selected_cipher_id", U16),
        // -- Compression
        // Offered compression methods
        field("compression_methods", Str),
        // Selected compression method
        field("selected_compression", U8),
        // -- Extensions
        // Server Name Indication hostname
        field("sni", Str),
        // Application-Layer Protocol Negotiation (e.g., "h2;http/1.1")
        field("alpn", Str),
        // TLS 1.3 supported_versions extension
        field("supported_versions", Str),
        // Offered signature algorithms
        field("signature_algorithms", Str),
        // Elliptic curves / named groups
        field("supported_groups", Str),
        // EC point format extension
        field("ec_point_formats", Str),
        // Total extensions length
        field("extensions_length", U16),
        // List of extension type IDs
        field("extension_types", Str),
        // -- Alerts
        // Alert severity (1=Warning, 2=Fatal)
        field("alert_level", U8),
        // Alert description code
        field("alert_description", U8),
        // Alert description name
        field("alert_description_str", Str),
        // -- Heartbeat
        // True if this is a heartbeat record
        field("is_heartbeat", Bool),
        // Heartbeat message type
        field("heartbeat_type", U8),
        // -- Other record types
        // True if ChangeCipherSpec record
        field("is_change_cipher_spec", Bool),
        // True if Application Data record
        field("has_app_data", Bool),
        // Length of encrypted application data
        field("app_data_length", U32),
        // -- JA3 fingerprinting
        // JA3 fingerprint string (ClientHello)
        field("ja3", Str),
        // MD5 hash of JA3 string
        field("ja3_hash", Str),
        // JA3S fingerprint string (ServerHello)
        field("ja3s", Str),
        // MD5 hash of JA3S string
        field("ja3s_hash", Str),
        // -- Certificate info
        // Number of certificates in chain
        field("certificate_count", U16),
    ]
}

/// The `ssh` table contains SSH protocol fields including version identification,
/// binary packet headers, key exchange, authentication, and channel information.
fn ssh() -> Vec<ColumnDef> {
    vec![
        // -- Protocol identification
        // SSH protocol version (e.g., "2.0")
        field("protocol_version", Str),
        // Software version string (e.g., "OpenSSH_8.9p1")
        field("software_version", Str),
        // Optional comments from identification string
        field("comments", Str),
        // -- Binary packet
        // Binary packet length
        field("packet_length", U32),
        // Padding length in binary packet
        field("padding_length", U8),
        // SSH message type number
        field("msg_type", U8),
        // Human-readable message type name
        field("msg_type_name", Str),
        // True if packet appears to be encrypted
        field("encrypted", Bool),
        // -- KEXINIT
        // Key exchange algorithms (from KEXINIT)
        field("kex_algorithms", Str),
        // Host key algorithms (from KEXINIT)
        field("host_key_algorithms", Str),
        // Encryption algorithms (from KEXINIT)
        field("encryption_algorithms", Str),
        // MAC algorithms (from KEXINIT)
        field("mac_algorithms", Str),
        // Compression algorithms (from KEXINIT)
        field("compression_algorithms", Str),
        // -- USERAUTH
        // Username from USERAUTH_REQUEST
        field("auth_username", Str),
        // Service name from USERAUTH_REQUEST
        field("auth_service", Str),
        // Authentication method from USERAUTH_REQUEST
        field("auth_method", Str),
        // -- CHANNEL
        // Channel type from CHANNEL_OPEN
        field("channel_type", Str),
        // Channel ID from CHANNEL_OPEN
        field("channel_id", U32),
    ]
}

/// The `quic` table contains QUIC transport protocol fields including
/// header type, version, connection IDs, and packet metadata.
fn quic() -> Vec<ColumnDef> {
    vec![
        // "long" or "short"
        field("header_form", Str),
        // For long headers: "Initial", "0-RTT", "Handshake", "Retry"
        field("long_packet_type", Str),
        // QUIC version number
        field("version", U32),
        // Human-readable version name (e.g., "QUIC v1")
        field("version_name", Str),
        // Destination Connection ID length
        field("dcid_length", U8),
        // Destination Connection ID (hex encoded)
        field("dcid", Str),
        // Source Connection ID length (long header only)
        field("scid_length", U8),
        // Source Connection ID (hex encoded, long header only)
        field("scid", Str),
        // Token length (Initial packets only)
        field("token_length", U32),
        // Packet length (from header)
        field("packet_length", U32),
        // Latency spin bit (short header only)
        field("spin_bit", Bool),
        // Key phase bit (short header only)
        field("key_phase", Bool),
        // Server Name Indication (if extractable from Initial packet)
        field("sni", Str),
    ]
}

/// The `netlink` table contains Linux Netlink message header fields.
///
/// ## Usage
///
/// ```sql
/// SELECT * FROM netlink WHERE is_request = true;
/// SELECT * FROM netlink WHERE family_name = 'ROUTE';
/// ```
fn netlink() -> Vec<ColumnDef> {
    vec![
        // Netlink message length
        field("msg_len", U32),
        // Netlink message type
        field("msg_type", U16),
        // Netlink message flags
        field("msg_flags", U16),
        // Sequence number
        field("msg_seq", U32),
        // Port ID (process ID)
        field("msg_pid", U32),
        // Human-readable message type name
        field("msg_type_name", Str),
        // True if NLM_F_REQUEST flag set
        field("is_request", Bool),
        // True if NLM_F_MULTIPART flag set
        field("is_multipart", Bool),
        // True if NLM_F_ACK flag set
        field("is_ack", Bool),
        // True if NLM_F_ECHO flag set
        field("is_echo", Bool),
        // Netlink family number
        field("family", U8),
        // Human-readable family name
        field("family_name", Str),
    ]
}

/// The `rtnetlink` table contains Linux routing netlink message fields.
///
/// ## Usage
///
/// ```sql
/// SELECT * FROM rtnetlink WHERE msg_type_name = 'RTM_NEWLINK';
/// SELECT if_name, mtu FROM rtnetlink WHERE link_index IS NOT NULL;
/// SELECT address, prefix_len FROM rtnetlink WHERE msg_type_name = 'RTM_NEWADDR';
/// ```
fn rtnetlink() -> Vec<ColumnDef> {
    vec![
        // -- Common fields
        // RTNetlink message type
        field("msg_type", U16),
        // Human-readable message type name
        field("msg_type_name", Str),
        // -- Link message fields
        // Interface index
        field("link_index", U32),
        // Link layer type
        field("link_type", U16),
        // Link flags
        field("link_flags", U32),
        // Interface name
        field("if_name", Str),
        // Maximum transmission unit
        field("mtu", U32),
        // Hardware address (MAC)
        field("hw_addr", Fixed(6)),
        // -- Address message fields
        // Address family number
        field("addr_family", U8),
        // Human-readable address family name
        field("addr_family_name", Str),
        // Network prefix length
        field("prefix_len", U8),
        // Interface index for address
        field("addr_index", U32),
        // IP address
        field("address", Str),
        // Local IP address
        field("local_addr", Str),
        // -- Route message fields
        // Route address family
        field("route_family", U8),
        // Destination prefix length
        field("dst_prefix_len", U8),
        // Source prefix length
        field("src_prefix_len", U8),
        // Routing table ID
        field("route_table", U8),
        // Route origin protocol
        field("route_protocol", U8),
        // Route scope
        field("route_scope", U8),
        // Route type
        field("route_type", U8),
        // Destination address
        field("destination", Str),
        // Gateway address
        field("gateway", Str),
        // Output interface index
        field("oif_index", U32),
    ]
}

/// One row per TCP connection tracked by stream reassembly (a stream-analysis
/// table: built from the whole capture in order, not per packet).
///
/// ## Usage
///
/// ```sql
/// SELECT client_ip, server_ip, server_port, state, bytes_to_server, bytes_to_client
/// FROM tcp_connections ORDER BY start_time;
/// ```
///
/// - `frame_number`: first frame of the connection (join key / capture order)
fn tcp_connections() -> Vec<ColumnDef> {
    vec![
        // Stream-manager connection id (shared with the other stream tables)
        stream("connection_id", U64).required(),
        // `client_ip`, `server_ip`, `client_port`, `server_port`: endpoints (client = SYN
        // sender)
        stream("client_ip", Str),
        stream("server_ip", Str),
        stream("client_port", U16),
        stream("server_port", U16),
        // Final TCP state seen (`established`, `closed`, `reset`, `mid_stream`, …)
        stream("state", Str),
        // First segment; `end_time`, `duration_us`: last segment of a connection that reached a
        // terminal state (NULL while still open)
        stream("start_time", TsMicros),
        stream("end_time", TsMicros),
        stream("duration_us", I64),
        // `first_frame`, `last_frame`: frame range
        stream("first_frame", U64),
        stream("last_frame", U64),
        // `packets_to_server`, `packets_to_client`: every segment in that direction (handshake
        // and pure ACKs included); `bytes_to_server`, `bytes_to_client`: payload bytes
        stream("packets_to_server", U32),
        stream("packets_to_client", U32),
        stream("bytes_to_server", U64),
        stream("bytes_to_client", U64),
        // Reached a terminal state (closed, time_wait or reset)
        stream("is_complete", Bool),
    ]
}

/// One row per TCP connection that carried a TLS handshake (a stream-analysis
/// table: built from reassembled streams, not per packet).
///
/// ## Usage
///
/// ```sql
/// SELECT sni, alpn, version, cipher_suite, is_decrypted FROM tls_sessions;
/// ```
///
/// - `frame_number`: frame carrying the ClientHello (join key / capture order)
fn tls_sessions() -> Vec<ColumnDef> {
    vec![
        // Stream-manager connection id (shared with `tcp_connections`)
        stream("connection_id", U64).required(),
        // Negotiated version from the ServerHello (`TLS 1.2`, …), else the client's
        stream("version", Str),
        // `cipher_suite`, `cipher_suite_id`: selected suite from the ServerHello
        stream("cipher_suite", Str),
        stream("cipher_suite_id", U16),
        // `sni`, `alpn`: ClientHello extensions
        stream("sni", Str),
        stream("alpn", Str),
        // A keylog decrypted this session (the Finished message was read)
        stream("is_decrypted", Bool).required(),
        // Frame carrying the ServerHello, if seen
        stream("server_hello_frame", U64),
    ]
}

/// One row per HTTP/1.x request or response reassembled from a TCP stream
/// (a stream-analysis table, not per packet).
///
/// ## Usage
///
/// ```sql
/// SELECT method, uri, host, status_code FROM http_messages ORDER BY frame_number;
/// ```
///
/// - `frame_number`: frame that completed the message (join key / capture order)
fn http_messages() -> Vec<ColumnDef> {
    vec![
        // `connection_id`, `message_id`, `direction`: stream identity
        stream("connection_id", U64).required(),
        stream("message_id", U32).required(),
        stream("direction", Str).required(),
        // `is_request`, `method`, `uri`, `http_version`, `status_code`: start line
        stream("is_request", Bool),
        stream("method", Str),
        stream("uri", Str),
        stream("http_version", Str),
        stream("status_code", U16),
        // `host`, `content_type`, `content_length`, `user_agent`, `server`: common headers
        stream("host", Str),
        stream("content_type", Str),
        stream("content_length", U64),
        stream("user_agent", Str),
        stream("server", Str),
    ]
}
