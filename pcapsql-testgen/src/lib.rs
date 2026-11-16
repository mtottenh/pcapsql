//! Deterministic PCAP / PCAPNG test-data generator.
//!
//! This crate produces byte-exact `.pcap` and `.pcapng` files together with a
//! *ground-truth* model of every frame they contain. It is the test
//! infrastructure behind the reader, boundary-index and partition-equivalence
//! tests: given the same inputs the output is byte-identical, and the bytes
//! are guaranteed (by the crate's own tests) to be parseable by `pcap-parser`
//! — the same crate the rest of the project relies on.
//!
//! # Layout responsibilities
//!
//! The generator is the single source of truth for two things that the readers
//! must agree with:
//!
//! 1. **Byte layout** of every header / record / block (little- or big-endian as
//!    appropriate, padding rules, length fields).
//! 2. **Timestamp math** — the `timestamp_ns` value in [`ExpectedFrame`] is
//!    computed here with the exact formulas documented on the builder functions,
//!    so a reader written to those same formulas will match bit-for-bit.
//!
//! Nothing here depends on `pcapsql-core` (to avoid a dependency cycle) and the
//! library has no runtime dependencies at all: the PRNG is implemented inline.

#![forbid(unsafe_code)]

pub mod corpus;
mod fixtures;
mod legacy;
mod model;
mod pcapng;
mod rng;
mod spec;
#[cfg(test)]
mod tests;

pub use fixtures::{jumbo_straddle_capture, oversized_frame_capture, truncated_capture};
pub use legacy::{legacy_pcap, GenPacket, LegacyVariant};
pub use model::{ExpectedFrame, GeneratedCapture};
pub use pcapng::{
    pcapng, pcapng_ordered, pcapng_ordered_with_byte_order, pcapng_with_byte_order,
    try_tsresol_units, tsresol_units, PcapngBlock, PcapngInterface, PcapngOrderedSection,
    PcapngPacket, PcapngSection,
};
pub use rng::SplitMix64;
pub use spec::{generate, CaptureSpec, Format};
