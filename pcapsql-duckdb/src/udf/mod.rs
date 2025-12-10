//! Scalar functions for network data operations.
//!
//! ## Address Functions
//!
//! - `ip4(string)` - Parse IPv4 to UInt32
//! - `ip4_to_string(uint32)` - Format UInt32 as IPv4
//! - `ip6(string)` - Parse IPv6 to Blob
//! - `ip6_to_string(blob)` - Format Blob as IPv6
//! - `mac(string)` - Parse MAC to Blob
//! - `mac_to_string(blob)` - Format Blob as MAC
//!
//! ## CIDR Functions
//!
//! - `ip_in_cidr(ip, cidr)` - Check IPv4 in CIDR range
//! - `ip6_in_cidr(ip, cidr)` - Check IPv6 in CIDR range
//!
//! ## Protocol Functions
//!
//! - `tcp_flags_str(flags)` - Format TCP flags
//! - `has_tcp_flag(flags, name)` - Check specific flag
//! - `dns_type_name(type)` - DNS type to name
//! - `dns_rcode_name(rcode)` - DNS rcode to name
//! - `ip_proto_name(proto)` - IP protocol to name
//! - `ethertype_name(type)` - EtherType to name
//!
//! ## Utility Functions
//!
//! - `pcap_hex(blob)` - Blob to hex string
//! - `pcap_unhex(string)` - Hex string to blob
//!
//! ## Example Usage
//!
//! ```sql
//! -- Address functions
//! SELECT ip4('192.168.1.1') AS packed;
//! SELECT ip4_to_string(3232235777) AS ip;
//! SELECT mac('aa:bb:cc:dd:ee:ff') AS packed;
//!
//! -- CIDR matching
//! SELECT ip_in_cidr(ip4('192.168.1.100'), '192.168.0.0/16') AS in_range;
//!
//! -- Protocol helpers
//! SELECT tcp_flags_str(18) AS flags;  -- "SYN,ACK"
//! SELECT has_tcp_flag(18, 'SYN') AS has_syn;
//! SELECT dns_type_name(1) AS type;  -- "A"
//! SELECT ip_proto_name(6) AS proto;  -- "TCP"
//!
//! -- With real data
//! SELECT frame_number, tcp_flags_str(flags) AS flags
//! FROM read_tcp('capture.pcap')
//! WHERE has_tcp_flag(flags, 'SYN')
//! LIMIT 5;
//! ```

mod address;
mod cidr;
mod hex;
mod protocol;

use duckdb::Connection;

/// Register all scalar functions.
pub fn register_all(con: &Connection) -> duckdb::Result<()> {
    address::register(con)?;
    cidr::register(con)?;
    protocol::register(con)?;
    hex::register(con)?;
    Ok(())
}
