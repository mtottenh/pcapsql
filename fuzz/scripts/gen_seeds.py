#!/usr/bin/env python3
"""
Generate seed corpus for P2 fuzz targets using scapy.

This script creates valid protocol packets that serve as starting points
for fuzzing. The fuzzer will mutate these seeds to find edge cases.

Usage:
    uvx --with scapy python3 fuzz/scripts/gen_seeds.py
"""

import os
from scapy.all import (
    DNS, DNSQR, DNSRR, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply,
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr,
    raw
)


def write_seed(corpus_dir: str, name: str, data: bytes):
    """Write a seed file to the corpus directory."""
    path = os.path.join(corpus_dir, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  Created: {name} ({len(data)} bytes)")


def generate_dns_seeds(corpus_dir: str):
    """Generate DNS seed packets."""
    print(f"\nGenerating DNS seeds in {corpus_dir}:")

    # Standard A query
    pkt = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    write_seed(corpus_dir, "a_query", raw(pkt))

    # AAAA query
    pkt = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="AAAA"))
    write_seed(corpus_dir, "aaaa_query", raw(pkt))

    # MX query
    pkt = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="MX"))
    write_seed(corpus_dir, "mx_query", raw(pkt))

    # TXT query
    pkt = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="TXT"))
    write_seed(corpus_dir, "txt_query", raw(pkt))

    # A response with answer
    pkt = DNS(
        qr=1, aa=1, rd=1, ra=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")
    )
    write_seed(corpus_dir, "a_response", raw(pkt))

    # Response with multiple answers
    pkt = DNS(
        qr=1, aa=1, rd=1, ra=1, ancount=2,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34") /
           DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.35")
    )
    write_seed(corpus_dir, "multi_answer", raw(pkt))

    # NXDOMAIN response
    pkt = DNS(qr=1, rcode=3, rd=1, ra=1, qd=DNSQR(qname="nonexistent.example.com"))
    write_seed(corpus_dir, "nxdomain", raw(pkt))


def generate_icmp_seeds(corpus_dir: str):
    """Generate ICMP/ICMPv6 seed packets."""
    print(f"\nGenerating ICMP seeds in {corpus_dir}:")

    # ICMPv4 Echo Request
    pkt = ICMP(type=8, code=0, id=1234, seq=1) / b"ping data"
    write_seed(corpus_dir, "icmp_echo_request", raw(pkt))

    # ICMPv4 Echo Reply
    pkt = ICMP(type=0, code=0, id=1234, seq=1) / b"pong data"
    write_seed(corpus_dir, "icmp_echo_reply", raw(pkt))

    # ICMPv4 Destination Unreachable (Host)
    pkt = ICMP(type=3, code=1)
    write_seed(corpus_dir, "icmp_dest_unreach", raw(pkt))

    # ICMPv4 Time Exceeded
    pkt = ICMP(type=11, code=0)
    write_seed(corpus_dir, "icmp_time_exceeded", raw(pkt))

    # ICMPv6 Echo Request
    pkt = ICMPv6EchoRequest(id=1234, seq=1) / b"ping6 data"
    write_seed(corpus_dir, "icmpv6_echo_request", raw(pkt))

    # ICMPv6 Echo Reply
    pkt = ICMPv6EchoReply(id=1234, seq=1) / b"pong6 data"
    write_seed(corpus_dir, "icmpv6_echo_reply", raw(pkt))

    # ICMPv6 Neighbor Solicitation
    pkt = ICMPv6ND_NS(tgt="fe80::1")
    write_seed(corpus_dir, "icmpv6_ns", raw(pkt))

    # ICMPv6 Neighbor Advertisement
    pkt = ICMPv6ND_NA(tgt="fe80::1", R=1, S=1, O=1) / ICMPv6NDOptSrcLLAddr(lladdr="00:11:22:33:44:55")
    write_seed(corpus_dir, "icmpv6_na", raw(pkt))


def generate_tls_seeds(corpus_dir: str):
    """Generate TLS seed data (raw TLS record layer)."""
    print(f"\nGenerating TLS seeds in {corpus_dir}:")

    # TLS 1.2 ClientHello (minimal)
    # Record: type=22 (handshake), version=0x0301 (TLS 1.0), length
    # Handshake: type=1 (client_hello), length, version, random, session_id, ciphers, compression
    client_hello = bytes([
        # Record layer
        0x16,              # type: Handshake
        0x03, 0x01,        # version: TLS 1.0 (for compat)
        0x00, 0x2f,        # length: 47 bytes
        # Handshake
        0x01,              # type: ClientHello
        0x00, 0x00, 0x2b,  # length: 43 bytes
        0x03, 0x03,        # version: TLS 1.2
        # Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00,              # session_id length: 0
        0x00, 0x02,        # cipher suites length: 2
        0x00, 0x2f,        # TLS_RSA_WITH_AES_128_CBC_SHA
        0x01,              # compression methods length: 1
        0x00,              # null compression
    ])
    write_seed(corpus_dir, "client_hello", client_hello)

    # TLS Alert (warning: close_notify)
    alert = bytes([
        0x15,              # type: Alert
        0x03, 0x03,        # version: TLS 1.2
        0x00, 0x02,        # length: 2
        0x01,              # level: warning
        0x00,              # description: close_notify
    ])
    write_seed(corpus_dir, "alert_close", alert)

    # TLS Alert (fatal: handshake_failure)
    alert_fatal = bytes([
        0x15,              # type: Alert
        0x03, 0x03,        # version: TLS 1.2
        0x00, 0x02,        # length: 2
        0x02,              # level: fatal
        0x28,              # description: handshake_failure
    ])
    write_seed(corpus_dir, "alert_fatal", alert_fatal)

    # TLS Application Data (dummy)
    app_data = bytes([
        0x17,              # type: Application Data
        0x03, 0x03,        # version: TLS 1.2
        0x00, 0x10,        # length: 16
        # Encrypted data (just random bytes)
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ])
    write_seed(corpus_dir, "app_data", app_data)

    # TLS ServerHello (minimal)
    server_hello = bytes([
        0x16,              # type: Handshake
        0x03, 0x03,        # version: TLS 1.2
        0x00, 0x2a,        # length: 42 bytes
        0x02,              # type: ServerHello
        0x00, 0x00, 0x26,  # length: 38 bytes
        0x03, 0x03,        # version: TLS 1.2
        # Random (32 bytes)
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x00,              # session_id length: 0
        0x00, 0x2f,        # cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
        0x00,              # compression: null
    ])
    write_seed(corpus_dir, "server_hello", server_hello)


def generate_tcp_options_seeds(corpus_dir: str):
    """Generate TCP options seed data (raw options bytes)."""
    print(f"\nGenerating TCP options seeds in {corpus_dir}:")

    # MSS only (kind=2, len=4, value=1460)
    mss_only = bytes([
        0x02, 0x04, 0x05, 0xb4,  # MSS = 1460
    ])
    write_seed(corpus_dir, "mss_only", mss_only)

    # Window Scale (kind=3, len=3, value=7)
    wscale_only = bytes([
        0x03, 0x03, 0x07,  # Window scale = 7
        0x00,              # NOP padding
    ])
    write_seed(corpus_dir, "wscale_only", wscale_only)

    # SACK Permitted (kind=4, len=2)
    sack_perm = bytes([
        0x04, 0x02,  # SACK permitted
    ])
    write_seed(corpus_dir, "sack_permitted", sack_perm)

    # Timestamp (kind=8, len=10, TSval=12345, TSecr=0)
    timestamp = bytes([
        0x08, 0x0a,                          # Timestamp option
        0x00, 0x00, 0x30, 0x39,              # TSval = 12345
        0x00, 0x00, 0x00, 0x00,              # TSecr = 0
    ])
    write_seed(corpus_dir, "timestamp", timestamp)

    # Common SYN options: MSS + SACK Permitted + Timestamp + NOP + Window Scale
    syn_options = bytes([
        0x02, 0x04, 0x05, 0xb4,              # MSS = 1460
        0x04, 0x02,                          # SACK permitted
        0x08, 0x0a,                          # Timestamp
        0x00, 0x00, 0x30, 0x39,              # TSval = 12345
        0x00, 0x00, 0x00, 0x00,              # TSecr = 0
        0x01,                                # NOP
        0x03, 0x03, 0x07,                    # Window scale = 7
    ])
    write_seed(corpus_dir, "syn_options", syn_options)

    # SACK blocks (kind=5, len=10+, left_edge, right_edge pairs)
    sack_blocks = bytes([
        0x05, 0x0a,                          # SACK, length=10 (1 block)
        0x00, 0x00, 0x10, 0x00,              # Left edge = 4096
        0x00, 0x00, 0x20, 0x00,              # Right edge = 8192
    ])
    write_seed(corpus_dir, "sack_block", sack_blocks)

    # Multiple SACK blocks
    multi_sack = bytes([
        0x05, 0x12,                          # SACK, length=18 (2 blocks)
        0x00, 0x00, 0x10, 0x00,              # Block 1: left = 4096
        0x00, 0x00, 0x20, 0x00,              # Block 1: right = 8192
        0x00, 0x00, 0x40, 0x00,              # Block 2: left = 16384
        0x00, 0x00, 0x50, 0x00,              # Block 2: right = 20480
    ])
    write_seed(corpus_dir, "multi_sack", multi_sack)

    # End of options list (kind=0)
    end_option = bytes([
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x00,                    # End of options
    ])
    write_seed(corpus_dir, "end_option", end_option)

    # Maximum options (40 bytes of MSS repeated)
    max_options = bytes([
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS
        0x02, 0x04, 0x05, 0xb4,  # MSS (40 bytes total)
    ])
    write_seed(corpus_dir, "max_options", max_options)


def generate_quic_seeds(corpus_dir: str):
    """Generate QUIC seed packets (raw QUIC data after UDP)."""
    print(f"\nGenerating QUIC seeds in {corpus_dir}:")

    # QUIC Initial packet (long header, version 1)
    # Format: header_form(1) | fixed_bit(1) | long_packet_type(2) | reserved(2) | pn_len(2)
    #         version(4) | dcid_len(1) | dcid | scid_len(1) | scid | ...
    initial_packet = bytes([
        0xc0,                                # Long header, Initial packet
        0x00, 0x00, 0x00, 0x01,              # Version 1 (RFC 9000)
        0x08,                                # DCID length = 8
        0x01, 0x02, 0x03, 0x04,              # DCID (8 bytes)
        0x05, 0x06, 0x07, 0x08,
        0x08,                                # SCID length = 8
        0x11, 0x12, 0x13, 0x14,              # SCID (8 bytes)
        0x15, 0x16, 0x17, 0x18,
        0x00,                                # Token length = 0
        0x41, 0x00,                          # Packet length (varint, 256 bytes)
        0x00,                                # Packet number
        # Payload would follow (encrypted)
    ])
    write_seed(corpus_dir, "initial", initial_packet)

    # QUIC Handshake packet
    handshake_packet = bytes([
        0xe0,                                # Long header, Handshake packet
        0x00, 0x00, 0x00, 0x01,              # Version 1
        0x08,                                # DCID length = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x08,                                # SCID length = 8
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x40, 0x10,                          # Packet length (varint)
        0x00,                                # Packet number
    ])
    write_seed(corpus_dir, "handshake", handshake_packet)

    # QUIC Short header packet
    short_header = bytes([
        0x40,                                # Short header, spin=0, key_phase=0
        0x01, 0x02, 0x03, 0x04,              # DCID (typically known length)
        0x05, 0x06, 0x07, 0x08,
        0x00,                                # Packet number
        # Encrypted payload would follow
    ])
    write_seed(corpus_dir, "short_header", short_header)

    # QUIC Version Negotiation (version=0)
    version_neg = bytes([
        0x80,                                # Long header form
        0x00, 0x00, 0x00, 0x00,              # Version = 0 (version negotiation)
        0x08,                                # DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x08,                                # SCID length
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x00, 0x00, 0x00, 0x01,              # Supported version 1
        0xff, 0x00, 0x00, 0x1d,              # Draft-29
    ])
    write_seed(corpus_dir, "version_neg", version_neg)

    # QUIC 0-RTT packet
    zero_rtt = bytes([
        0xd0,                                # Long header, 0-RTT
        0x00, 0x00, 0x00, 0x01,              # Version 1
        0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x40, 0x08,                          # Packet length
        0x00,                                # Packet number
    ])
    write_seed(corpus_dir, "zero_rtt", zero_rtt)

    # QUIC Retry packet
    retry = bytes([
        0xf0,                                # Long header, Retry
        0x00, 0x00, 0x00, 0x01,              # Version 1
        0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        # Retry token would follow
        0xaa, 0xbb, 0xcc, 0xdd,
        # Integrity tag (16 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ])
    write_seed(corpus_dir, "retry", retry)


def generate_ip_options_seeds(corpus_dir: str):
    """Generate IPv4 options and IPv6 extension header seeds."""
    print(f"\nGenerating IP options seeds in {corpus_dir}:")

    # Selector byte (0=IPv4, 1=IPv6, 2=both) + IHL/options data

    # IPv4 with no options (IHL=5)
    ipv4_no_options = bytes([
        0x00,  # selector: IPv4
        0x05,  # IHL = 5 (no options)
    ])
    write_seed(corpus_dir, "ipv4_no_options", ipv4_no_options)

    # IPv4 with NOP options
    ipv4_nop = bytes([
        0x00,  # selector: IPv4
        0x06,  # IHL = 6 (4 bytes of options)
        0x01, 0x01, 0x01, 0x01,  # 4 NOPs
    ])
    write_seed(corpus_dir, "ipv4_nop", ipv4_nop)

    # IPv4 with End of Options
    ipv4_eol = bytes([
        0x00,  # selector: IPv4
        0x06,  # IHL = 6
        0x00, 0x00, 0x00, 0x00,  # End of options list
    ])
    write_seed(corpus_dir, "ipv4_eol", ipv4_eol)

    # IPv4 with Record Route option (kind=7)
    ipv4_record_route = bytes([
        0x00,  # selector: IPv4
        0x08,  # IHL = 8 (12 bytes of options)
        0x07, 0x0b, 0x04,        # Record Route: kind=7, len=11, pointer=4
        0x00, 0x00, 0x00, 0x00,  # Route data slot 1
        0x00, 0x00, 0x00, 0x00,  # Route data slot 2
        0x00,                    # Padding
    ])
    write_seed(corpus_dir, "ipv4_record_route", ipv4_record_route)

    # IPv4 with Timestamp option (kind=68)
    ipv4_timestamp = bytes([
        0x00,  # selector: IPv4
        0x07,  # IHL = 7 (8 bytes of options)
        0x44, 0x08, 0x05, 0x00,  # Timestamp: kind=68, len=8, pointer=5, oflw/flag=0
        0x00, 0x00, 0x00, 0x00,  # Timestamp slot
    ])
    write_seed(corpus_dir, "ipv4_timestamp", ipv4_timestamp)

    # IPv4 with Loose Source Route (kind=131)
    ipv4_lsrr = bytes([
        0x00,  # selector: IPv4
        0x08,  # IHL = 8
        0x83, 0x0b, 0x04,        # LSRR: kind=131, len=11, pointer=4
        0x0a, 0x00, 0x00, 0x01,  # Route: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02,  # Route: 10.0.0.2
        0x00,                    # Padding
    ])
    write_seed(corpus_dir, "ipv4_lsrr", ipv4_lsrr)

    # IPv6 with no extension headers
    ipv6_no_ext = bytes([
        0x01,  # selector: IPv6
        0x3b,  # Next header = 59 (No Next Header)
    ])
    write_seed(corpus_dir, "ipv6_no_ext", ipv6_no_ext)

    # IPv6 with Hop-by-Hop options (NH=0)
    ipv6_hopbyhop = bytes([
        0x01,  # selector: IPv6
        0x00,  # Next header = 0 (Hop-by-Hop)
        # Hop-by-Hop extension header
        0x3b,  # Next header = No Next Header
        0x00,  # Header length (0 = 8 bytes)
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,  # Pad1 + PadN
    ])
    write_seed(corpus_dir, "ipv6_hopbyhop", ipv6_hopbyhop)

    # IPv6 with Fragment header (NH=44)
    ipv6_fragment = bytes([
        0x01,  # selector: IPv6
        0x2c,  # Next header = 44 (Fragment)
        # Fragment extension header (8 bytes)
        0x3b,                    # Next header = No Next Header
        0x00,                    # Reserved
        0x00, 0x01,              # Fragment offset = 0, M=1
        0x12, 0x34, 0x56, 0x78,  # Identification
    ])
    write_seed(corpus_dir, "ipv6_fragment", ipv6_fragment)

    # IPv6 with Routing header (NH=43)
    ipv6_routing = bytes([
        0x01,  # selector: IPv6
        0x2b,  # Next header = 43 (Routing)
        # Routing extension header
        0x3b,  # Next header = No Next Header
        0x02,  # Header length (2 = 24 bytes total)
        0x00,  # Routing type = 0
        0x01,  # Segments left = 1
        0x00, 0x00, 0x00, 0x00,  # Reserved
        # IPv6 address (16 bytes)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ])
    write_seed(corpus_dir, "ipv6_routing", ipv6_routing)

    # IPv6 with Destination Options (NH=60)
    ipv6_destopts = bytes([
        0x01,  # selector: IPv6
        0x3c,  # Next header = 60 (Destination Options)
        # Destination Options extension header
        0x3b,  # Next header = No Next Header
        0x00,  # Header length (0 = 8 bytes)
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,  # Padding
    ])
    write_seed(corpus_dir, "ipv6_destopts", ipv6_destopts)

    # IPv6 with chained extension headers
    ipv6_chain = bytes([
        0x01,  # selector: IPv6
        0x00,  # Next header = 0 (Hop-by-Hop)
        # Hop-by-Hop (8 bytes)
        0x2b,  # Next header = 43 (Routing)
        0x00,  # Header length = 0
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
        # Routing (24 bytes)
        0x3b,  # Next header = No Next Header
        0x02,  # Header length = 2
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ])
    write_seed(corpus_dir, "ipv6_chain", ipv6_chain)


def generate_http_seeds(corpus_dir: str):
    """Generate HTTP/1.x and HTTP/2 seed data."""
    print(f"\nGenerating HTTP seeds in {corpus_dir}:")

    # Selector byte: 0=HTTP1 request, 1=HTTP1 response, 2=HTTP2 request, 3=HTTP2 response

    # HTTP/1.1 GET request
    http1_get = bytes([0x00]) + b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    write_seed(corpus_dir, "http1_get", http1_get)

    # HTTP/1.1 POST request with body
    http1_post = bytes([0x00]) + b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}"
    write_seed(corpus_dir, "http1_post", http1_post)

    # HTTP/1.1 response 200 OK
    http1_200 = bytes([0x01]) + b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>"
    write_seed(corpus_dir, "http1_200", http1_200)

    # HTTP/1.1 response 404
    http1_404 = bytes([0x01]) + b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    write_seed(corpus_dir, "http1_404", http1_404)

    # HTTP/1.1 chunked response
    http1_chunked = bytes([0x01]) + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    write_seed(corpus_dir, "http1_chunked", http1_chunked)

    # HTTP/1.1 request with many headers
    http1_headers = bytes([0x00]) + b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Language: en-US\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nCookie: session=abc123\r\n\r\n"
    write_seed(corpus_dir, "http1_headers", http1_headers)

    # HTTP/2 connection preface
    http2_preface = bytes([0x02]) + b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    write_seed(corpus_dir, "http2_preface", http2_preface)

    # HTTP/2 SETTINGS frame (type=0x04)
    # Frame: length(3) | type(1) | flags(1) | stream_id(4) | payload
    http2_settings = bytes([
        0x02,  # selector: HTTP/2
        0x00, 0x00, 0x00,  # length = 0
        0x04,              # type = SETTINGS
        0x00,              # flags
        0x00, 0x00, 0x00, 0x00,  # stream id = 0
    ])
    write_seed(corpus_dir, "http2_settings", http2_settings)

    # HTTP/2 SETTINGS ACK
    http2_settings_ack = bytes([
        0x02,  # selector
        0x00, 0x00, 0x00,  # length = 0
        0x04,              # type = SETTINGS
        0x01,              # flags = ACK
        0x00, 0x00, 0x00, 0x00,
    ])
    write_seed(corpus_dir, "http2_settings_ack", http2_settings_ack)

    # HTTP/2 HEADERS frame
    http2_headers = bytes([
        0x02,  # selector
        0x00, 0x00, 0x05,  # length = 5
        0x01,              # type = HEADERS
        0x04,              # flags = END_HEADERS
        0x00, 0x00, 0x00, 0x01,  # stream id = 1
        # HPACK encoded headers (minimal)
        0x82,              # :method: GET (indexed)
        0x86,              # :scheme: https (indexed)
        0x84,              # :path: / (indexed)
        0x41, 0x00,        # :authority: "" (literal)
    ])
    write_seed(corpus_dir, "http2_headers", http2_headers)

    # HTTP/2 DATA frame
    http2_data = bytes([
        0x02,  # selector
        0x00, 0x00, 0x05,  # length = 5
        0x00,              # type = DATA
        0x01,              # flags = END_STREAM
        0x00, 0x00, 0x00, 0x01,  # stream id = 1
        0x68, 0x65, 0x6c, 0x6c, 0x6f,  # "hello"
    ])
    write_seed(corpus_dir, "http2_data", http2_data)

    # HTTP/2 WINDOW_UPDATE frame
    http2_window = bytes([
        0x02,  # selector
        0x00, 0x00, 0x04,  # length = 4
        0x08,              # type = WINDOW_UPDATE
        0x00,              # flags
        0x00, 0x00, 0x00, 0x00,  # stream id = 0
        0x00, 0x00, 0x80, 0x00,  # window size increment = 32768
    ])
    write_seed(corpus_dir, "http2_window", http2_window)

    # HTTP/2 PING frame
    http2_ping = bytes([
        0x02,  # selector
        0x00, 0x00, 0x08,  # length = 8
        0x06,              # type = PING
        0x00,              # flags
        0x00, 0x00, 0x00, 0x00,  # stream id = 0
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  # opaque data
    ])
    write_seed(corpus_dir, "http2_ping", http2_ping)

    # HTTP/2 GOAWAY frame
    http2_goaway = bytes([
        0x03,  # selector: HTTP/2 response
        0x00, 0x00, 0x08,  # length = 8
        0x07,              # type = GOAWAY
        0x00,              # flags
        0x00, 0x00, 0x00, 0x00,  # stream id = 0
        0x00, 0x00, 0x00, 0x01,  # last stream id = 1
        0x00, 0x00, 0x00, 0x00,  # error code = NO_ERROR
    ])
    write_seed(corpus_dir, "http2_goaway", http2_goaway)


def generate_bpf_seeds(corpus_dir: str):
    """Generate BPF filter expression seeds."""
    print(f"\nGenerating BPF seeds in {corpus_dir}:")

    # Simple protocol filters
    write_seed(corpus_dir, "tcp", b"tcp")
    write_seed(corpus_dir, "udp", b"udp")
    write_seed(corpus_dir, "icmp", b"icmp")
    write_seed(corpus_dir, "icmp6", b"icmp6")
    write_seed(corpus_dir, "arp", b"arp")
    write_seed(corpus_dir, "ip", b"ip")
    write_seed(corpus_dir, "ip6", b"ip6")

    # Port filters
    write_seed(corpus_dir, "port_80", b"port 80")
    write_seed(corpus_dir, "tcp_port_443", b"tcp port 443")
    write_seed(corpus_dir, "udp_port_53", b"udp port 53")
    write_seed(corpus_dir, "src_port", b"src port 22")
    write_seed(corpus_dir, "dst_port", b"dst port 8080")

    # Host filters
    write_seed(corpus_dir, "host_ipv4", b"host 192.168.1.1")
    write_seed(corpus_dir, "host_ipv6", b"host ::1")
    write_seed(corpus_dir, "src_host", b"src host 10.0.0.1")
    write_seed(corpus_dir, "dst_host", b"dst host 10.0.0.2")

    # Network filters
    write_seed(corpus_dir, "net_cidr", b"net 10.0.0.0/8")
    write_seed(corpus_dir, "net_ipv6", b"net 2001:db8::/32")
    write_seed(corpus_dir, "src_net", b"src net 192.168.0.0/16")
    write_seed(corpus_dir, "dst_net", b"dst net 172.16.0.0/12")

    # Port range
    write_seed(corpus_dir, "portrange", b"portrange 1024-65535")
    write_seed(corpus_dir, "tcp_portrange", b"tcp portrange 80-443")

    # Protocol number
    write_seed(corpus_dir, "proto_6", b"proto 6")
    write_seed(corpus_dir, "proto_17", b"proto 17")

    # Boolean operators
    write_seed(corpus_dir, "and_simple", b"tcp and port 80")
    write_seed(corpus_dir, "or_simple", b"tcp or udp")
    write_seed(corpus_dir, "not_simple", b"not icmp")

    # Complex expressions
    write_seed(corpus_dir, "complex_1", b"tcp port 80 and host 192.168.1.1")
    write_seed(corpus_dir, "complex_2", b"(tcp or udp) and port 443")
    write_seed(corpus_dir, "complex_3", b"not udp and src port 53")
    write_seed(corpus_dir, "complex_4", b"host 10.0.0.1 and (tcp port 22 or tcp port 80)")
    write_seed(corpus_dir, "complex_5", b"src net 192.168.0.0/16 and dst port 443")

    # Nested expressions
    write_seed(corpus_dir, "nested_1", b"((tcp or udp) and port 80) or icmp")
    write_seed(corpus_dir, "nested_2", b"not (host 192.168.1.1 or host 192.168.1.2)")
    write_seed(corpus_dir, "nested_3", b"(tcp and (port 80 or port 443)) and not host 10.0.0.1")

    # Edge cases
    write_seed(corpus_dir, "spaces", b"  tcp   port   80  ")
    write_seed(corpus_dir, "mixed_case", b"TCP Port 80 AND Host 192.168.1.1")


def generate_ssh_seeds(corpus_dir: str):
    """Generate SSH seed packets (raw SSH data after TCP)."""
    print(f"\nGenerating SSH seeds in {corpus_dir}:")

    # SSH Protocol Identification String (OpenSSH)
    banner_openssh = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    write_seed(corpus_dir, "banner_openssh", banner_openssh)

    # SSH Protocol Identification String (Dropbear)
    banner_dropbear = b"SSH-2.0-dropbear_2022.83\r\n"
    write_seed(corpus_dir, "banner_dropbear", banner_dropbear)

    # SSH Protocol Identification String (PuTTY)
    banner_putty = b"SSH-2.0-PuTTY_Release_0.78\r\n"
    write_seed(corpus_dir, "banner_putty", banner_putty)

    # SSH Binary Packet: KEXINIT (msg type 20)
    # Format: packet_length(4) | padding_length(1) | payload | padding
    kexinit = bytes([
        0x00, 0x00, 0x00, 0x24,  # packet_length = 36
        0x06,                    # padding_length = 6
        0x14,                    # SSH_MSG_KEXINIT (20)
        # Cookie (16 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        # kex_algorithms name-list (length + data)
        0x00, 0x00, 0x00, 0x08,  # length = 8
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x78,  # "test-kex"
        # Padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    write_seed(corpus_dir, "kexinit", kexinit)

    # SSH NEWKEYS (msg type 21)
    newkeys = bytes([
        0x00, 0x00, 0x00, 0x0c,  # packet_length = 12
        0x0a,                    # padding_length = 10
        0x15,                    # SSH_MSG_NEWKEYS (21)
        # Padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    write_seed(corpus_dir, "newkeys", newkeys)

    # SSH USERAUTH_REQUEST (msg type 50)
    userauth = bytes([
        0x00, 0x00, 0x00, 0x24,  # packet_length = 36
        0x05,                    # padding_length = 5
        0x32,                    # SSH_MSG_USERAUTH_REQUEST (50)
        # username (length + data)
        0x00, 0x00, 0x00, 0x04,  # length = 4
        0x72, 0x6f, 0x6f, 0x74,  # "root"
        # service (length + data)
        0x00, 0x00, 0x00, 0x0e,  # length = 14
        0x73, 0x73, 0x68, 0x2d,  # "ssh-connection"
        0x63, 0x6f, 0x6e, 0x6e,
        0x65, 0x63, 0x74, 0x69,
        0x6f, 0x6e,
        # method (length + data)
        0x00, 0x00, 0x00, 0x04,  # length = 4
        0x6e, 0x6f, 0x6e, 0x65,  # "none"
        # Padding
        0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    write_seed(corpus_dir, "userauth_request", userauth)

    # SSH CHANNEL_OPEN (msg type 90)
    channel_open = bytes([
        0x00, 0x00, 0x00, 0x1c,  # packet_length = 28
        0x04,                    # padding_length = 4
        0x5a,                    # SSH_MSG_CHANNEL_OPEN (90)
        # channel type (length + data)
        0x00, 0x00, 0x00, 0x07,  # length = 7
        0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,  # "session"
        # sender channel
        0x00, 0x00, 0x00, 0x00,
        # initial window size
        0x00, 0x10, 0x00, 0x00,
        # maximum packet size
        0x00, 0x00, 0x40, 0x00,
        # Padding
        0x00, 0x00, 0x00, 0x00,
    ])
    write_seed(corpus_dir, "channel_open", channel_open)

    # SSH DISCONNECT (msg type 1)
    disconnect = bytes([
        0x00, 0x00, 0x00, 0x18,  # packet_length = 24
        0x06,                    # padding_length = 6
        0x01,                    # SSH_MSG_DISCONNECT (1)
        # reason code
        0x00, 0x00, 0x00, 0x0b,  # BY_APPLICATION
        # description (length + data)
        0x00, 0x00, 0x00, 0x07,  # length = 7
        0x67, 0x6f, 0x6f, 0x64, 0x62, 0x79, 0x65,  # "goodbye"
        # language tag
        0x00, 0x00, 0x00, 0x00,  # empty
        # Padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    write_seed(corpus_dir, "disconnect", disconnect)


def main():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    corpus_base = os.path.join(base_dir, "corpus")

    print("Generating fuzz seed corpus...")

    # Create corpus directories
    for target in ["fuzz_dns", "fuzz_icmp", "fuzz_tls",
                   "fuzz_tcp_options", "fuzz_quic", "fuzz_ssh",
                   "fuzz_ip_options", "fuzz_http", "fuzz_bpf"]:
        target_dir = os.path.join(corpus_base, target)
        os.makedirs(target_dir, exist_ok=True)

    generate_dns_seeds(os.path.join(corpus_base, "fuzz_dns"))
    generate_icmp_seeds(os.path.join(corpus_base, "fuzz_icmp"))
    generate_tls_seeds(os.path.join(corpus_base, "fuzz_tls"))
    generate_tcp_options_seeds(os.path.join(corpus_base, "fuzz_tcp_options"))
    generate_quic_seeds(os.path.join(corpus_base, "fuzz_quic"))
    generate_ssh_seeds(os.path.join(corpus_base, "fuzz_ssh"))
    generate_ip_options_seeds(os.path.join(corpus_base, "fuzz_ip_options"))
    generate_http_seeds(os.path.join(corpus_base, "fuzz_http"))
    generate_bpf_seeds(os.path.join(corpus_base, "fuzz_bpf"))

    print("\nDone!")


if __name__ == "__main__":
    main()
