//! PCAP file reading module.
//!
//! This module handles reading PCAP and PCAPNG files and
//! exposing raw packets for parsing.

mod packet;
mod reader;

pub use packet::RawPacket;
pub use reader::PcapReader;
