//! Raw packet representation.

/// A raw packet from a PCAP file.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Frame number (1-indexed).
    pub frame_number: u64,

    /// Timestamp in microseconds since epoch.
    pub timestamp_us: i64,

    /// Captured length (may be less than original).
    pub captured_length: u32,

    /// Original length on the wire.
    pub original_length: u32,

    /// Link layer type (e.g., 1 = Ethernet).
    pub link_type: u16,

    /// Raw packet data.
    pub data: Vec<u8>,
}

impl RawPacket {
    /// Create a new raw packet.
    pub fn new(
        frame_number: u64,
        timestamp_us: i64,
        captured_length: u32,
        original_length: u32,
        link_type: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            frame_number,
            timestamp_us,
            captured_length,
            original_length,
            link_type,
            data,
        }
    }

    /// Check if the packet was truncated during capture.
    pub fn is_truncated(&self) -> bool {
        self.captured_length < self.original_length
    }
}
