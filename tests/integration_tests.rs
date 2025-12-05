//! Integration tests for pcapsql.
//!
//! Tests the full packet parsing pipeline using synthetic packet data.

use pcapsql::protocol::{default_registry, parse_packet, FieldValue, Protocol};

/// Build a complete Ethernet/IPv4/TCP SYN packet.
fn build_tcp_syn_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src MAC
    packet.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4

    // IPv4 header (20 bytes)
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // DSCP + ECN
    packet.extend_from_slice(&[0x00, 0x28]); // Total length: 40
    packet.extend_from_slice(&[0x00, 0x01]); // Identification
    packet.extend_from_slice(&[0x40, 0x00]); // Don't fragment
    packet.push(0x40); // TTL: 64
    packet.push(0x06); // Protocol: TCP
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[192, 168, 1, 100]); // Src IP
    packet.extend_from_slice(&[192, 168, 1, 200]); // Dst IP

    // TCP header (20 bytes)
    packet.extend_from_slice(&[0x30, 0x39]); // Src port: 12345
    packet.extend_from_slice(&[0x00, 0x50]); // Dst port: 80
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq: 1
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack: 0
    packet.push(0x50); // Data offset: 5 (20 bytes)
    packet.push(0x02); // Flags: SYN
    packet.extend_from_slice(&[0xff, 0xff]); // Window: 65535
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

    packet
}

/// Build a complete Ethernet/IPv4/UDP DNS query packet.
fn build_udp_dns_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header
    packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst MAC
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
    packet.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4

    // IPv4 header
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x34]); // Total length: 52
    packet.extend_from_slice(&[0x12, 0x34]); // Identification
    packet.extend_from_slice(&[0x00, 0x00]); // No fragmentation
    packet.push(0x40); // TTL: 64
    packet.push(0x11); // Protocol: UDP
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[10, 0, 0, 1]); // Src IP
    packet.extend_from_slice(&[8, 8, 8, 8]); // Dst IP (Google DNS)

    // UDP header (8 bytes)
    packet.extend_from_slice(&[0xc0, 0x00]); // Src port: 49152
    packet.extend_from_slice(&[0x00, 0x35]); // Dst port: 53 (DNS)
    packet.extend_from_slice(&[0x00, 0x20]); // Length: 32
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum

    // DNS payload (simplified)
    packet.extend_from_slice(&[0x12, 0x34]); // Transaction ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs
    // Query for "example.com" (simplified)
    packet.extend_from_slice(&[0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65]); // "example"
    packet.extend_from_slice(&[0x03, 0x63, 0x6f, 0x6d, 0x00]); // "com" + null
    packet.extend_from_slice(&[0x00, 0x01]); // Type: A
    packet.extend_from_slice(&[0x00, 0x01]); // Class: IN

    packet
}

/// Build an Ethernet/IPv4/ICMP echo request packet.
fn build_icmp_echo_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src MAC
    packet.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4

    // IPv4 header
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x54]); // Total length: 84
    packet.extend_from_slice(&[0x00, 0x00]); // Identification
    packet.extend_from_slice(&[0x40, 0x00]); // Don't fragment
    packet.push(0x40); // TTL: 64
    packet.push(0x01); // Protocol: ICMP
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
    packet.extend_from_slice(&[8, 8, 8, 8]); // Dst IP

    // ICMP header
    packet.push(0x08); // Type: Echo Request
    packet.push(0x00); // Code: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[0x00, 0x01]); // Identifier: 1
    packet.extend_from_slice(&[0x00, 0x01]); // Sequence: 1

    // ICMP payload (64 bytes of data)
    for i in 0..56 {
        packet.push(i as u8);
    }

    packet
}

/// Build an Ethernet/ARP request packet.
fn build_arp_request_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC (broadcast)
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src MAC
    packet.extend_from_slice(&[0x08, 0x06]); // ethertype: ARP

    // ARP header
    packet.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    packet.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    packet.push(0x06); // Hardware size: 6
    packet.push(0x04); // Protocol size: 4
    packet.extend_from_slice(&[0x00, 0x01]); // Operation: Request
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Sender MAC
    packet.extend_from_slice(&[192, 168, 1, 1]); // Sender IP
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Target MAC (unknown)
    packet.extend_from_slice(&[192, 168, 1, 2]); // Target IP

    packet
}

#[test]
fn test_parse_full_tcp_packet() {
    let packet = build_tcp_syn_packet();
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Should have parsed Ethernet, IPv4, and TCP layers
    assert_eq!(results.len(), 3);

    // Check layer names
    assert_eq!(results[0].0, "ethernet");
    assert_eq!(results[1].0, "ipv4");
    assert_eq!(results[2].0, "tcp");

    // Verify Ethernet fields
    let eth_result = &results[0].1;
    assert!(eth_result.is_ok());
    assert_eq!(
        eth_result.get("ethertype"),
        Some(&FieldValue::UInt16(0x0800))
    );

    // Verify IPv4 fields
    let ipv4_result = &results[1].1;
    assert!(ipv4_result.is_ok());
    assert_eq!(ipv4_result.get("protocol"), Some(&FieldValue::UInt8(6)));
    assert_eq!(ipv4_result.get("ttl"), Some(&FieldValue::UInt8(64)));

    // Verify TCP fields
    let tcp_result = &results[2].1;
    assert!(tcp_result.is_ok());
    assert_eq!(tcp_result.get("src_port"), Some(&FieldValue::UInt16(12345)));
    assert_eq!(tcp_result.get("dst_port"), Some(&FieldValue::UInt16(80)));
    assert_eq!(tcp_result.get("flag_syn"), Some(&FieldValue::Bool(true)));
    assert_eq!(tcp_result.get("flag_ack"), Some(&FieldValue::Bool(false)));
}

#[test]
fn test_parse_full_udp_packet() {
    let packet = build_udp_dns_packet();
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Should have parsed Ethernet, IPv4, UDP, and DNS layers
    assert_eq!(results.len(), 4);

    // Check layer names
    assert_eq!(results[0].0, "ethernet");
    assert_eq!(results[1].0, "ipv4");
    assert_eq!(results[2].0, "udp");
    assert_eq!(results[3].0, "dns");

    // Verify UDP fields (DNS query)
    let udp_result = &results[2].1;
    assert!(udp_result.is_ok());
    assert_eq!(udp_result.get("dst_port"), Some(&FieldValue::UInt16(53)));

    // Verify DNS fields
    let dns_result = &results[3].1;
    assert!(dns_result.is_ok());
    assert_eq!(dns_result.get("is_query"), Some(&FieldValue::Bool(true)));
}

#[test]
fn test_parse_full_icmp_packet() {
    let packet = build_icmp_echo_packet();
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Should have parsed Ethernet, IPv4, and ICMP layers
    assert_eq!(results.len(), 3);

    // Check layer names
    assert_eq!(results[0].0, "ethernet");
    assert_eq!(results[1].0, "ipv4");
    assert_eq!(results[2].0, "icmp");

    // Verify IPv4 shows ICMP protocol
    let ipv4_result = &results[1].1;
    assert_eq!(ipv4_result.get("protocol"), Some(&FieldValue::UInt8(1)));

    // Verify ICMP fields
    let icmp_result = &results[2].1;
    assert!(icmp_result.is_ok());
    assert_eq!(icmp_result.get("type"), Some(&FieldValue::UInt8(8))); // Echo Request
    assert_eq!(icmp_result.get("identifier"), Some(&FieldValue::UInt16(1)));
    assert_eq!(icmp_result.get("sequence"), Some(&FieldValue::UInt16(1)));
}

#[test]
fn test_parse_arp_packet() {
    let packet = build_arp_request_packet();
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Should have parsed Ethernet and ARP layers
    assert_eq!(results.len(), 2);

    // Check layer names
    assert_eq!(results[0].0, "ethernet");
    assert_eq!(results[1].0, "arp");

    // Verify Ethernet shows ARP ethertype
    let eth_result = &results[0].1;
    assert_eq!(
        eth_result.get("ethertype"),
        Some(&FieldValue::UInt16(0x0806))
    );

    // Verify ARP fields
    let arp_result = &results[1].1;
    assert!(arp_result.is_ok());
    assert_eq!(arp_result.get("operation"), Some(&FieldValue::UInt16(1))); // Request
}

#[test]
fn test_registry_contains_all_parsers() {
    let registry = default_registry();

    // Check that all expected parsers are registered
    let names: Vec<&str> = registry.all_parsers().map(|p| p.name()).collect();

    assert!(names.contains(&"ethernet"));
    assert!(names.contains(&"ipv4"));
    assert!(names.contains(&"ipv6"));
    assert!(names.contains(&"tcp"));
    assert!(names.contains(&"udp"));
    assert!(names.contains(&"icmp"));
    assert!(names.contains(&"arp"));
}

#[test]
fn test_protocol_chain_hints() {
    let packet = build_tcp_syn_packet();
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Ethernet should hint at IPv4
    let eth_result = &results[0].1;
    assert_eq!(eth_result.child_hints.get("ethertype"), Some(&0x0800u64));

    // IPv4 should hint at TCP
    let ipv4_result = &results[1].1;
    assert_eq!(ipv4_result.child_hints.get("ip_protocol"), Some(&6u64));

    // TCP should provide port hints
    let tcp_result = &results[2].1;
    assert_eq!(tcp_result.child_hints.get("src_port"), Some(&12345u64));
    assert_eq!(tcp_result.child_hints.get("dst_port"), Some(&80u64));
}

#[test]
fn test_empty_packet() {
    let packet: Vec<u8> = vec![];
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Empty packet should produce no results
    assert!(results.is_empty());
}

#[test]
fn test_truncated_packet() {
    // Truncated Ethernet frame (only 10 bytes, needs 14)
    let packet = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33];
    let registry = default_registry();

    let results = parse_packet(&registry, 1, &packet);

    // Should have one result with an error
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "ethernet");
    assert!(!results[0].1.is_ok());
    assert!(results[0].1.error.is_some());
}

#[test]
fn test_non_ethernet_link_type() {
    let packet = build_tcp_syn_packet();
    let registry = default_registry();

    // Use a non-Ethernet link type (e.g., Linux cooked capture = 113)
    let results = parse_packet(&registry, 113, &packet);

    // Should produce no results since Ethernet parser won't match
    assert!(results.is_empty());
}

#[test]
fn test_unknown_ethertype() {
    let mut packet = Vec::new();

    // Ethernet header with unknown ethertype
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst MAC
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src MAC
    packet.extend_from_slice(&[0x12, 0x34]); // Unknown ethertype
    packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // Payload

    let registry = default_registry();
    let results = parse_packet(&registry, 1, &packet);

    // Should only parse Ethernet layer
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "ethernet");
    assert!(results[0].1.is_ok());
}
