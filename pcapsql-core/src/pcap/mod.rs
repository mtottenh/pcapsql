//! PCAP file reading module.
//!
//! This module handles reading PCAP and PCAPNG files and
//! exposing raw packets for parsing.
//!
//! The main types are:
//! - [`PcapReader`] - File-based reader with automatic compression handling
//! - [`crate::io::RawPacket`] - Raw packet data (re-exported from io module)

mod reader;

pub use reader::PcapReader;
// RawPacket is exported from crate::io, not duplicated here
