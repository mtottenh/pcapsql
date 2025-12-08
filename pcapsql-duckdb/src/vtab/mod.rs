//! Virtual table implementations for DuckDB.
//!
//! This module provides table functions that expose PCAP parsing to DuckDB SQL.
//!
//! ## Available Functions
//!
//! ### Generic
//! - `read_pcap(file, protocol)` - Read any protocol from a PCAP
//!
//! ### Protocol-Specific
//! - `read_ethernet(file)` - Ethernet frames
//! - `read_ipv4(file)` - IPv4 packets
//! - `read_tcp(file)` - TCP segments
//! - `read_dns(file)` - DNS queries/responses
//! - ... and many more (see `pcap_protocols()`)
//!
//! ### Metadata
//! - `pcap_protocols()` - List all supported protocols
//! - `pcap_schema(protocol)` - Show schema for a protocol
//!
//! ## Example Usage
//!
//! ```sql
//! -- List supported protocols
//! SELECT * FROM pcap_protocols();
//!
//! -- Show schema for TCP
//! SELECT * FROM pcap_schema('tcp');
//!
//! -- Read all frames (raw packet metadata)
//! SELECT * FROM read_pcap('capture.pcap', 'frames') LIMIT 10;
//!
//! -- Use protocol-specific function (simpler)
//! SELECT frame_number, src_port, dst_port, flags
//! FROM read_tcp('capture.pcap')
//! WHERE dst_port = 80;
//!
//! -- Or use generic read_pcap
//! SELECT frame_number, src_port, dst_port, flags
//! FROM read_pcap('capture.pcap', 'tcp')
//! WHERE dst_port = 80;
//!
//! -- Read DNS packets
//! SELECT frame_number, query_name, query_type
//! FROM read_dns('capture.pcap');
//!
//! -- Join protocols by frame_number
//! SELECT t.src_port, t.dst_port, d.query_name
//! FROM read_tcp('capture.pcap') t
//! JOIN read_dns('capture.pcap') d USING (frame_number);
//! ```

mod batch_builder;
mod protocol_tables;
mod read_pcap;
mod registry;

pub use read_pcap::{register as register_read_pcap, ReadPcapVTab};
pub use registry::{register as register_registry, PcapProtocolsVTab, PcapSchemaVTab};
pub use protocol_tables::register as register_protocol_tables;

/// Register all VTab functions.
pub fn register_all(con: &duckdb::Connection) -> duckdb::Result<(), Box<dyn std::error::Error>> {
    register_read_pcap(con)?;
    register_registry(con)?;
    register_protocol_tables(con)?;
    Ok(())
}
