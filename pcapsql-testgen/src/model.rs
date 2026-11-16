//! The ground-truth model of a generated capture.

/// One captured frame, as the generator knows it to be.
///
/// Other crates compare their parsed output against this. Every field is the
/// authoritative value; in particular [`Self::data`] is exactly `caplen` bytes
/// (the captured bytes, without any on-disk padding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedFrame {
    /// 1-indexed frame number, global across all sections.
    pub frame_number: u64,
    /// Timestamp in nanoseconds, computed with the per-format formulas.
    pub timestamp_ns: i64,
    /// Captured length in bytes (== `data.len()`).
    pub caplen: u32,
    /// Original on-wire length in bytes (may exceed `caplen`).
    pub origlen: u32,
    /// Link-layer type (e.g. 1 = Ethernet).
    pub link_type: u32,
    /// Exactly `caplen` captured bytes.
    pub data: Vec<u8>,
}

/// A generated capture: the raw file bytes plus the ground-truth frames.
#[derive(Clone, Debug)]
pub struct GeneratedCapture {
    /// The full `.pcap` / `.pcapng` file content.
    pub bytes: Vec<u8>,
    /// Ground truth, in file order.
    pub expected: Vec<ExpectedFrame>,
}
