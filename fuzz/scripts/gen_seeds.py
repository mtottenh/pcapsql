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


def main():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    corpus_base = os.path.join(base_dir, "corpus")

    print("Generating fuzz seed corpus...")

    generate_dns_seeds(os.path.join(corpus_base, "fuzz_dns"))
    generate_icmp_seeds(os.path.join(corpus_base, "fuzz_icmp"))
    generate_tls_seeds(os.path.join(corpus_base, "fuzz_tls"))

    print("\nDone!")


if __name__ == "__main__":
    main()
