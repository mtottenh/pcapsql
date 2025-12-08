//! Virtual table implementations for DuckDB.
//!
//! This module provides table functions that expose PCAP parsing to DuckDB SQL.
//!
//! ## Available Table Functions
//!
//! - `read_pcap(file, protocol)` - Read packets from a PCAP file for a specific protocol
//!
//! ## Example Usage
//!
//! ```sql
//! -- Read all frames (raw packet metadata)
//! SELECT * FROM read_pcap('capture.pcap', 'frames') LIMIT 10;
//!
//! -- Read TCP packets
//! SELECT frame_number, src_port, dst_port, flags
//! FROM read_pcap('capture.pcap', 'tcp')
//! WHERE dst_port = 80;
//!
//! -- Read DNS packets
//! SELECT frame_number, query_name, query_type
//! FROM read_pcap('capture.pcap', 'dns');
//!
//! -- Join protocols by frame_number
//! SELECT t.src_port, t.dst_port, d.query_name
//! FROM read_pcap('capture.pcap', 'tcp') t
//! JOIN read_pcap('capture.pcap', 'dns') d USING (frame_number);
//! ```

mod batch_builder;
mod read_pcap;

pub use read_pcap::{register as register_read_pcap, ReadPcapVTab};
