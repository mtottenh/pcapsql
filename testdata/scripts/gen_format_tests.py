#!/usr/bin/env python3
"""
Generate test PCAP files in all supported formats for cloud integration testing.

This script generates PCAP files in all 5 formats that pcapsql supports:
- Legacy little-endian microseconds (default)
- Legacy big-endian microseconds
- Legacy little-endian nanoseconds
- Legacy big-endian nanoseconds
- PCAPNG

Usage:
    uvx --with scapy python gen_format_tests.py --output-dir /tmp/generated
"""

import argparse
import os
import struct
import time
from pathlib import Path

# Scapy imports
from scapy.all import Ether, IP, UDP, DNS, DNSQR, Raw, wrpcap
from scapy.utils import PcapNgWriter


# PCAP magic numbers - the same magic is written in different byte orders
# The magic value 0xa1b2c3d4 means microseconds, 0xa1b23c4d means nanoseconds
# LE files write LSB first, BE files write MSB first
PCAP_MAGIC_MICRO = 0xA1B2C3D4  # Microsecond timestamp magic
PCAP_MAGIC_NANO = 0xA1B23C4D   # Nanosecond timestamp magic

# Link type for Ethernet
LINKTYPE_ETHERNET = 1

# PCAP header constants
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535


def generate_dns_packets(count: int = 100) -> list:
    """Generate DNS query/response packets."""
    packets = []
    base_time = time.time()

    for i in range(count):
        # Vary source port and transaction ID
        sport = 10000 + (i % 55535)
        txid = i % 65536

        # DNS query packet
        query = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
            IP(src="192.168.1.100", dst="8.8.8.8") /
            UDP(sport=sport, dport=53) /
            DNS(id=txid, qr=0, qd=DNSQR(qname=f"test{i}.example.com"))
        )
        query.time = base_time + (i * 0.001)  # 1ms apart
        packets.append(query)

        # DNS response packet
        response = (
            Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") /
            IP(src="8.8.8.8", dst="192.168.1.100") /
            UDP(sport=53, dport=sport) /
            DNS(id=txid, qr=1, qd=DNSQR(qname=f"test{i}.example.com"))
        )
        response.time = base_time + (i * 0.001) + 0.0005
        packets.append(response)

    return packets


def generate_large_packets(target_size_mb: int = 10) -> list:
    """Generate enough packets to exceed the target size."""
    packets = []
    base_time = time.time()

    # Each packet is roughly 100-150 bytes
    # To get 10MB, we need about 100K packets
    packet_count = (target_size_mb * 1024 * 1024) // 120

    print(f"Generating {packet_count} packets for {target_size_mb}MB file...")

    for i in range(packet_count):
        # Simple UDP packet with some payload
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
            IP(src=f"10.0.{(i >> 8) & 0xff}.{i & 0xff}", dst="10.0.0.1") /
            UDP(sport=12345, dport=80) /
            Raw(load=f"packet-{i:08d}")
        )
        pkt.time = base_time + (i * 0.0001)
        packets.append(pkt)

        if (i + 1) % 10000 == 0:
            print(f"  Generated {i + 1}/{packet_count} packets...")

    return packets


def write_legacy_pcap(packets: list, filename: str, big_endian: bool = False, nano: bool = False):
    """
    Write packets to a legacy PCAP file with specified byte order.

    Args:
        packets: List of scapy packets
        filename: Output filename
        big_endian: If True, write in big-endian byte order
        nano: If True, use nanosecond timestamps instead of microseconds
    """
    endian = ">" if big_endian else "<"
    magic = PCAP_MAGIC_NANO if nano else PCAP_MAGIC_MICRO

    with open(filename, "wb") as f:
        # Write global header (24 bytes)
        # magic (4) + version_major (2) + version_minor (2) + thiszone (4) +
        # sigfigs (4) + snaplen (4) + network (4)
        header = struct.pack(
            f"{endian}IHHiIII",
            magic,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,  # thiszone (GMT offset)
            0,  # sigfigs (timestamp accuracy)
            PCAP_SNAPLEN,
            LINKTYPE_ETHERNET
        )
        f.write(header)

        # Write each packet
        for pkt in packets:
            pkt_bytes = bytes(pkt)
            pkt_len = len(pkt_bytes)

            # Get timestamp
            ts = float(pkt.time) if hasattr(pkt, 'time') else time.time()
            ts_sec = int(ts)
            if nano:
                ts_subsec = int((ts - ts_sec) * 1_000_000_000)  # nanoseconds
            else:
                ts_subsec = int((ts - ts_sec) * 1_000_000)  # microseconds

            # Packet header: ts_sec (4) + ts_usec/nsec (4) + incl_len (4) + orig_len (4)
            pkt_header = struct.pack(
                f"{endian}IIII",
                ts_sec,
                ts_subsec,
                pkt_len,  # captured length
                pkt_len   # original length
            )
            f.write(pkt_header)
            f.write(pkt_bytes)


def write_le_micro(packets: list, filename: str):
    """Write legacy PCAP with little-endian byte order, microsecond timestamps."""
    write_legacy_pcap(packets, filename, big_endian=False, nano=False)


def write_be_micro(packets: list, filename: str):
    """Write legacy PCAP with big-endian byte order, microsecond timestamps."""
    write_legacy_pcap(packets, filename, big_endian=True, nano=False)


def write_le_nano(packets: list, filename: str):
    """Write legacy PCAP with little-endian byte order, nanosecond timestamps."""
    write_legacy_pcap(packets, filename, big_endian=False, nano=True)


def write_be_nano(packets: list, filename: str):
    """Write legacy PCAP with big-endian byte order, nanosecond timestamps."""
    write_legacy_pcap(packets, filename, big_endian=True, nano=True)


def write_pcapng(packets: list, filename: str):
    """Write packets to PCAPNG format."""
    writer = PcapNgWriter(filename)
    for pkt in packets:
        writer.write(pkt)
    writer.close()


def main():
    parser = argparse.ArgumentParser(
        description="Generate test PCAP files in all supported formats"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="/tmp/generated",
        help="Output directory for generated files"
    )
    parser.add_argument(
        "--large-size",
        type=int,
        default=10,
        help="Size of large test file in MB (default: 10)"
    )
    parser.add_argument(
        "--small-count",
        type=int,
        default=100,
        help="Number of DNS packets for small files (default: 100)"
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir}")

    # Generate small DNS packets for format testing
    print("\nGenerating small DNS packets...")
    small_packets = generate_dns_packets(args.small_count)

    # Write small files in each format
    print("\nWriting format test files...")

    # 1. Small DNS file (for basic tests and compression source)
    small_dns_file = output_dir / "small_dns.pcap"
    write_le_micro(small_packets, str(small_dns_file))
    print(f"  Created: {small_dns_file} ({small_dns_file.stat().st_size} bytes)")

    # 2. Legacy LE Micro
    le_micro_file = output_dir / "format_le_micro.pcap"
    write_le_micro(small_packets, str(le_micro_file))
    print(f"  Created: {le_micro_file} ({le_micro_file.stat().st_size} bytes)")

    # 3. Legacy BE Micro
    be_micro_file = output_dir / "format_be_micro.pcap"
    write_be_micro(small_packets, str(be_micro_file))
    print(f"  Created: {be_micro_file} ({be_micro_file.stat().st_size} bytes)")

    # 4. Legacy LE Nano
    le_nano_file = output_dir / "format_le_nano.pcap"
    write_le_nano(small_packets, str(le_nano_file))
    print(f"  Created: {le_nano_file} ({le_nano_file.stat().st_size} bytes)")

    # 5. Legacy BE Nano
    be_nano_file = output_dir / "format_be_nano.pcap"
    write_be_nano(small_packets, str(be_nano_file))
    print(f"  Created: {be_nano_file} ({be_nano_file.stat().st_size} bytes)")

    # 6. PCAPNG
    pcapng_file = output_dir / "format_pcapng.pcapng"
    write_pcapng(small_packets, str(pcapng_file))
    print(f"  Created: {pcapng_file} ({pcapng_file.stat().st_size} bytes)")

    # Generate large file for chunk boundary testing
    print(f"\nGenerating large file ({args.large_size}MB)...")
    large_packets = generate_large_packets(args.large_size)

    large_file = output_dir / "large_10mb.pcap"
    write_le_micro(large_packets, str(large_file))
    size_mb = large_file.stat().st_size / (1024 * 1024)
    print(f"  Created: {large_file} ({size_mb:.2f} MB)")

    print("\nDone! Generated files:")
    for f in sorted(output_dir.glob("*")):
        size = f.stat().st_size
        if size > 1024 * 1024:
            print(f"  {f.name}: {size / (1024*1024):.2f} MB")
        else:
            print(f"  {f.name}: {size} bytes")


if __name__ == "__main__":
    main()
