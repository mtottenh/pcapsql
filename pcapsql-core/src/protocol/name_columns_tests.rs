//! Every name column a parser writes agrees with its table in
//! [`format::names`](crate::format::names).
//!
//! The parsers read those tables rather than keep their own, so that
//! `icmp.type_name` and `icmp_type_name(icmp.type)` are the same text. This
//! parses a layer for every number a column's code can take and compares
//! the column with the table, and fails for a name column that is not
//! listed here.

use std::ops::RangeInclusive;

use super::{default_registry, HintKey, ParseBuf, ParseContext};
use crate::format::names::*;
use crate::schema::DataKind;

/// A name column and the table it has to agree with.
struct NameColumn {
    /// The column, `protocol.field`.
    column: &'static str,
    /// The numbers to check. Every value of a code of 16 bits or fewer.
    codes: &'static [RangeInclusive<u32>],
    /// A layer of the protocol whose code is the number, and the context to
    /// parse it in.
    layer: fn(u32) -> (Vec<u8>, ParseContext),
    /// The table's text for the number; `None` where the column is NULL.
    table: fn(u32) -> Option<String>,
}

const U8: &[RangeInclusive<u32>] = &[RangeInclusive::new(0, 0xff)];
const U16: &[RangeInclusive<u32>] = &[RangeInclusive::new(0, 0xffff)];

/// The narrowing a table's argument needs: the ranges above keep every
/// number within the code's width.
fn code<T: TryFrom<u32>>(number: u32) -> T {
    T::try_from(number).unwrap_or_else(|_| panic!("{number} does not fit the code's width"))
}

fn text(name: Name) -> Option<String> {
    Some(name.to_string())
}

fn context(hint: Option<(HintKey, u64)>) -> ParseContext {
    let mut context = ParseContext::new(1);
    if let Some((key, value)) = hint {
        context.insert_hint(key, value);
    }
    context
}

/// A BGP message: the marker, the length, the type and the body.
fn bgp_message(message_type: u8, body: &[u8]) -> (Vec<u8>, ParseContext) {
    let mut message = vec![0xff; 16];
    let length = u16::try_from(19 + body.len()).expect("a short message");
    message.extend_from_slice(&length.to_be_bytes());
    message.push(message_type);
    message.extend_from_slice(body);
    (message, context(None))
}

/// An OSPFv2 packet: the 24-byte header and the body.
fn ospf_packet(packet_type: u8, body: &[u8]) -> (Vec<u8>, ParseContext) {
    let mut packet = vec![2, packet_type];
    let length = u16::try_from(24 + body.len()).expect("a short packet");
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0; 20]);
    packet.extend_from_slice(body);
    (packet, context(Some((HintKey::IpProtocol, 89))))
}

/// A Linux cooked-capture v1 header.
fn sll_header(packet_type: u16, arphrd: u16) -> (Vec<u8>, ParseContext) {
    let mut header = Vec::new();
    header.extend_from_slice(&packet_type.to_be_bytes());
    header.extend_from_slice(&arphrd.to_be_bytes());
    header.extend_from_slice(&6u16.to_be_bytes());
    header.extend_from_slice(&[0; 8]);
    header.extend_from_slice(&0x0800u16.to_be_bytes());
    (header, ParseContext::new(113))
}

/// A Linux cooked-capture v2 header.
fn sll2_header(packet_type: u8, arphrd: u16) -> (Vec<u8>, ParseContext) {
    let mut header = Vec::new();
    header.extend_from_slice(&0x0800u16.to_be_bytes());
    header.extend_from_slice(&[0; 6]);
    header.extend_from_slice(&arphrd.to_be_bytes());
    header.push(packet_type);
    header.push(6);
    header.extend_from_slice(&[0; 8]);
    (header, ParseContext::new(276))
}

/// A netlink message header of a type, in a context of a netlink family.
fn netlink_header(msg_type: u16, family: u8) -> (Vec<u8>, ParseContext) {
    let mut header = Vec::new();
    header.extend_from_slice(&16u32.to_le_bytes());
    header.extend_from_slice(&msg_type.to_le_bytes());
    header.extend_from_slice(&[0; 10]);
    let mut context = ParseContext::new(253);
    context.insert_hint(HintKey::NetlinkFamily, u64::from(family));
    (header, context)
}

/// An rtnetlink payload under a netlink message of a type.
fn rtnetlink_payload(msg_type: u16, payload: Vec<u8>) -> (Vec<u8>, ParseContext) {
    let mut context = ParseContext::new(253);
    context.parent_protocol = Some("netlink");
    context.insert_hint(HintKey::NetlinkFamily, 0);
    context.insert_hint(HintKey::NetlinkMsgType, u64::from(msg_type));
    (payload, context)
}

/// A TLS record.
fn tls_record(content_type: u8, version: u16, body: &[u8]) -> (Vec<u8>, ParseContext) {
    let mut record = vec![content_type];
    record.extend_from_slice(&version.to_be_bytes());
    let length = u16::try_from(body.len()).expect("a short record");
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(body);
    (record, context(Some((HintKey::DstPort, 443))))
}

const NAME_COLUMNS: &[NameColumn] = &[
    NameColumn {
        column: "arp.operation_name",
        codes: U16,
        layer: |operation| {
            let mut packet = vec![0, 1, 0x08, 0x00, 6, 4];
            packet.extend_from_slice(&code::<u16>(operation).to_be_bytes());
            packet.extend_from_slice(&[0; 20]);
            (packet, context(Some((HintKey::EtherType, 0x0806))))
        },
        table: |operation| text(arp_operation_name(code(operation))),
    },
    NameColumn {
        column: "bgp.message_type_name",
        codes: U8,
        layer: |message_type| bgp_message(code(message_type), &[]),
        table: |message_type| text(bgp_message_type_name(code(message_type))),
    },
    NameColumn {
        column: "bgp.origin_name",
        codes: U8,
        // An UPDATE with no withdrawn routes and one path attribute: ORIGIN.
        layer: |origin| bgp_message(2, &[0, 0, 0, 4, 0x40, 1, 1, code(origin)]),
        table: |origin| text(bgp_origin_name(code(origin))),
    },
    NameColumn {
        column: "bgp.error_code_name",
        codes: U8,
        layer: |error| bgp_message(3, &[code(error), 0]),
        table: |error| text(bgp_error_code_name(code(error))),
    },
    NameColumn {
        // A list of names: an OPEN with one capability names that one.
        column: "bgp.capabilities",
        codes: U8,
        layer: |capability| {
            // Version 4, AS 65000, hold time 180, an identifier, and one
            // optional parameter of type 2 (capabilities) with one
            // capability of no length.
            let mut open = vec![4, 0xfd, 0xe8, 0, 180, 10, 0, 0, 1, 4, 2, 2];
            open.extend_from_slice(&[code(capability), 0]);
            bgp_message(1, &open)
        },
        table: |capability| text(bgp_capability_name(code(capability))),
    },
    NameColumn {
        column: "gre.version_name",
        codes: &[RangeInclusive::new(0, 7)],
        layer: |version| {
            let mut header = code::<u16>(version).to_be_bytes().to_vec();
            header.extend_from_slice(&0x0800u16.to_be_bytes());
            (header, context(Some((HintKey::IpProtocol, 47))))
        },
        table: |version| text(gre_version_name(code(version))),
    },
    NameColumn {
        column: "icmp.type_name",
        codes: U8,
        layer: |icmp_type| {
            let mut message = vec![code(icmp_type)];
            message.extend_from_slice(&[0; 35]);
            (message, context(Some((HintKey::IpProtocol, 1))))
        },
        table: |icmp_type| text(icmp_type_name(code(icmp_type))),
    },
    NameColumn {
        column: "icmpv6.type_name",
        codes: U8,
        layer: |icmpv6_type| {
            let mut message = vec![code(icmpv6_type)];
            message.extend_from_slice(&[0; 47]);
            (message, context(Some((HintKey::IpProtocol, 58))))
        },
        table: |icmpv6_type| text(icmpv6_type_name(code(icmpv6_type))),
    },
    NameColumn {
        column: "linux_sll.packet_type_name",
        codes: U16,
        layer: |packet_type| sll_header(code(packet_type), 1),
        table: |packet_type| text(sll_packet_type_name(code(packet_type))),
    },
    NameColumn {
        column: "linux_sll.arphrd_name",
        codes: U16,
        layer: |arphrd| sll_header(0, code(arphrd)),
        table: |arphrd| text(arphrd_name(code(arphrd))),
    },
    NameColumn {
        column: "sll2.packet_type_name",
        codes: U8,
        layer: |packet_type| sll2_header(code(packet_type), 1),
        table: |packet_type| text(sll_packet_type_name(code(packet_type))),
    },
    NameColumn {
        column: "sll2.arphrd_name",
        codes: U16,
        layer: |arphrd| sll2_header(0, code(arphrd)),
        table: |arphrd| text(arphrd_name(code(arphrd))),
    },
    NameColumn {
        column: "mpls.special_label_name",
        // Every special-purpose label, and ordinary ones up to the largest.
        codes: &[0..=4096, 0xf_fff0..=0xf_ffff],
        layer: |label| {
            // The label, bottom of stack, TTL 64.
            let entry = (label << 12) | 0x100 | 64;
            (
                entry.to_be_bytes().to_vec(),
                context(Some((HintKey::EtherType, 0x8847))),
            )
        },
        table: |label| mpls_special_label_name(label).map(str::to_string),
    },
    NameColumn {
        column: "netlink.msg_type_name",
        codes: U16,
        layer: |msg_type| netlink_header(code(msg_type), 0),
        table: |msg_type| Some(netlink_msg_type_name(code(msg_type)).to_string()),
    },
    NameColumn {
        column: "netlink.family_name",
        codes: U8,
        layer: |family| netlink_header(16, code(family)),
        table: |family| text(netlink_family_name(code(family))),
    },
    NameColumn {
        column: "rtnetlink.msg_type_name",
        codes: U16,
        layer: |msg_type| rtnetlink_payload(code(msg_type), vec![0; 16]),
        table: |msg_type| text(rtnetlink_msg_type_name(code(msg_type))),
    },
    NameColumn {
        column: "rtnetlink.addr_family_name",
        codes: U8,
        // RTM_NEWADDR: an `ifaddrmsg` starts with the family.
        layer: |family| {
            let mut ifaddrmsg = vec![code(family)];
            ifaddrmsg.extend_from_slice(&[0; 7]);
            rtnetlink_payload(20, ifaddrmsg)
        },
        table: |family| text(address_family_name(code(family))),
    },
    NameColumn {
        column: "ospf.message_type_name",
        codes: U8,
        layer: |packet_type| ospf_packet(code(packet_type), &[]),
        table: |packet_type| text(ospf_packet_type_name(code(packet_type))),
    },
    NameColumn {
        column: "ospf.lsa_type_name",
        codes: U8,
        // A Link State Acknowledgment carries LSA headers; the type is the
        // fourth byte of one.
        layer: |lsa_type| {
            let mut header = vec![0, 1, 0, code(lsa_type)];
            header.extend_from_slice(&[0; 16]);
            ospf_packet(5, &header)
        },
        table: |lsa_type| text(ospf_lsa_type_name(code(lsa_type))),
    },
    NameColumn {
        column: "quic.version_name",
        // The named versions, every draft version, and numbers around them.
        codes: &[
            0..=0x200,
            0x6b33_43cf..=0x6b33_43cf,
            0xfeff_ff00..=0xff00_01ff,
            0xffff_ff00..=0xffff_ffff,
        ],
        // A long-header Initial packet with empty connection IDs.
        layer: |version| {
            let mut packet = vec![0xc0];
            packet.extend_from_slice(&version.to_be_bytes());
            packet.extend_from_slice(&[0; 16]);
            (packet, context(Some((HintKey::DstPort, 443))))
        },
        table: |version| text(quic_version_name(version)),
    },
    NameColumn {
        column: "ssh.msg_type_name",
        codes: U8,
        // A binary packet of twelve bytes: four of padding, the message
        // number, and seven more.
        layer: |msg_type| {
            let mut packet = vec![0, 0, 0, 12, 4, code(msg_type)];
            packet.extend_from_slice(&[0; 10]);
            (packet, context(Some((HintKey::DstPort, 22))))
        },
        table: |msg_type| text(ssh_msg_type_name(code(msg_type))),
    },
    NameColumn {
        column: "tls.version",
        codes: U16,
        // A ChangeCipherSpec record. Its version is 3.x (SSL 3.0 to
        // TLS 1.3 and what comes after): anything else there is not the
        // start of a record, and not a row.
        layer: |version| tls_record(20, code(version), &[1]),
        table: |version| {
            (version >> 8 == 3)
                .then(|| tls_version_name(code(version)))
                .and_then(text)
        },
    },
    NameColumn {
        column: "tls.alert_description_str",
        codes: U8,
        // A fatal alert in a TLS 1.2 record.
        layer: |description| tls_record(21, 0x0303, &[2, code(description)]),
        table: |description| text(tls_alert_description_name(code(description))),
    },
];

/// String columns named `*_name` that are not the name of a code: text
/// taken from the packet.
const NOT_A_CODE_NAME: &[&str] = &["dns.query_name", "rtnetlink.if_name"];

#[test]
fn every_name_column_agrees_with_its_table() {
    let registry = default_registry();
    let mut buf = ParseBuf::default();

    for case in NAME_COLUMNS {
        let (protocol, field) = case.column.split_once('.').expect("protocol.field");
        let parser = registry
            .get_parser(protocol)
            .unwrap_or_else(|| panic!("{}: no parser `{protocol}`", case.column));

        for number in case.codes.iter().cloned().flatten() {
            let (data, context) = (case.layer)(number);
            let mut layers = buf.for_packet();
            let status = layers.parse_layer(parser, &data, &context, None).status;
            let column = layers
                .last()
                .and_then(|layer| layer.get(field).copied())
                .map(|value| {
                    value
                        .as_str()
                        .unwrap_or_else(|| panic!("{}: not a string: {value:?}", case.column))
                        .to_string()
                });
            assert_eq!(
                column,
                (case.table)(number),
                "{} for {number} ({number:#x}) is not what its table in format::names gives \
                 (the parse ended {status:?})",
                case.column,
            );
        }
    }
}

/// A new `*_name` column has to be listed in [`NAME_COLUMNS`] (and so read
/// a table of `format::names`) or in [`NOT_A_CODE_NAME`].
#[test]
fn every_name_column_is_checked() {
    let registry = default_registry();
    let unlisted: Vec<&str> = registry
        .all_parsers()
        .flat_map(super::Protocol::schema_fields)
        .filter(|field| field.kind == DataKind::String && field.name.ends_with("_name"))
        .map(|field| field.name)
        .filter(|name| {
            !NOT_A_CODE_NAME.contains(name) && !NAME_COLUMNS.iter().any(|case| case.column == *name)
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "name columns with no check against a table of format::names: {unlisted:?}"
    );

    for case in NAME_COLUMNS {
        let (protocol, _) = case.column.split_once('.').expect("protocol.field");
        let parser = registry.get_parser(protocol).expect("a registered parser");
        assert!(
            super::Protocol::schema_fields(parser)
                .iter()
                .any(|field| field.name == case.column),
            "{} is not a column of `{protocol}`",
            case.column
        );
    }
}
