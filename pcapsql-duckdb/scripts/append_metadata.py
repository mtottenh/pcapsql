#!/usr/bin/env python3
"""
Append DuckDB extension metadata to a shared library.
Based on DuckDB's extension-ci-tools/scripts/append_extension_metadata.py
"""

import argparse
import os
import shutil
import struct
import sys

def padded_byte_string(s: str, length: int = 32) -> bytes:
    """Encode string as fixed-length ASCII bytes, padded with nulls."""
    encoded = s.encode('ascii')[:length]
    return encoded.ljust(length, b'\x00')

def create_signature_header() -> bytes:
    """Create the WebAssembly custom section header for duckdb_signature."""
    # WASM custom section format
    section_name = b"duckdb_signature"
    name_len = len(section_name)

    # Header: section_id (0), size (varint), name_len (varint), name
    header = bytes([0])  # Custom section ID

    # Calculate total section size (we'll use a placeholder)
    # The actual size calculation would be more complex, but we use a fixed structure
    content_size = 32 * 8 + 256  # 8 fields of 32 bytes + 256 byte signature
    section_size = name_len + 1 + content_size  # +1 for name length byte

    # Simple varint encoding for sizes < 128
    header += bytes([section_size & 0x7F]) if section_size < 128 else struct.pack('<H', section_size | 0x8000)
    header += bytes([name_len])
    header += section_name

    return header

def append_metadata(
    lib_path: str,
    output_path: str,
    extension_name: str,
    duckdb_version: str,
    extension_version: str = "0.1.0",
    platform: str = "linux_amd64",
    abi_type: str = "C_STRUCT"
):
    """Append extension metadata to a shared library."""

    # Copy original library
    temp_path = output_path + ".tmp"
    shutil.copy2(lib_path, temp_path)

    with open(temp_path, 'ab') as f:
        # Write signature header
        f.write(create_signature_header())

        # Write metadata fields (32 bytes each)
        f.write(padded_byte_string(""))  # FIELD8 (unused)
        f.write(padded_byte_string(""))  # FIELD7 (unused)
        f.write(padded_byte_string(""))  # FIELD6 (unused)
        f.write(padded_byte_string(abi_type))  # ABI type
        f.write(padded_byte_string(extension_version))  # Extension version
        f.write(padded_byte_string(duckdb_version))  # DuckDB version
        f.write(padded_byte_string(platform))  # Platform
        f.write(padded_byte_string("4"))  # Signature header

        # Write 256 bytes of padding for signature (unsigned)
        f.write(b'\x00' * 256)

    # Rename to final path
    os.replace(temp_path, output_path)
    print(f"Created extension: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Append metadata to DuckDB extension')
    parser.add_argument('lib_path', help='Path to shared library')
    parser.add_argument('output_path', help='Output extension path')
    parser.add_argument('--name', default='pcapsql', help='Extension name')
    parser.add_argument('--duckdb-version', default='v1.4.2', help='DuckDB version')
    parser.add_argument('--ext-version', default='0.1.0', help='Extension version')
    parser.add_argument('--platform', default='linux_amd64', help='Platform')
    parser.add_argument('--abi-type', default='C_STRUCT', help='ABI type')

    args = parser.parse_args()

    if not os.path.exists(args.lib_path):
        print(f"Error: Library not found: {args.lib_path}", file=sys.stderr)
        sys.exit(1)

    # Create output directory if needed
    os.makedirs(os.path.dirname(args.output_path) or '.', exist_ok=True)

    append_metadata(
        args.lib_path,
        args.output_path,
        args.name,
        args.duckdb_version,
        args.ext_version,
        args.platform,
        args.abi_type
    )

if __name__ == '__main__':
    main()
