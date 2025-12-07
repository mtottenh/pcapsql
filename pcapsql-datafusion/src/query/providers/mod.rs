//! Table providers for protocol tables.
//!
//! Supports both in-memory (pre-loaded) and streaming modes.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                   Query: SELECT d.query_name, t.sni                     │
//! │                   FROM dns d JOIN tls t USING (frame_number)            │
//! └─────────────────────────────────────────────────────────────────────────┘
//!                                     │
//!                                     ▼
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                   SortMergeJoinExec                                      │
//! │            (frame_number is sorted in both inputs)                       │
//! └─────────────────────────────────────────────────────────────────────────┘
//!               │                                    │
//!               ▼                                    ▼
//! ┌─────────────────────────────────┐    ┌─────────────────────────────────┐
//! │  ProtocolStreamExec(dns)        │    │  ProtocolStreamExec(tls)        │
//! │  - Opens own file reader        │    │  - Opens own file reader        │
//! │  - Filters to DNS packets       │    │  - Filters to TLS packets       │
//! │  - Emits sorted by frame#       │    │  - Emits sorted by frame#       │
//! └──────────────┬──────────────────┘    └──────────────┬──────────────────┘
//!                │                                       │
//!                └──────────────┬────────────────────────┘
//!                               │
//!                               ▼
//!                     ┌─────────────────┐
//!                     │   PCAP File     │
//!                     │ (OS file cache) │
//!                     └─────────────────┘
//! ```

mod batch_stream;
mod protocol_provider;
mod stream_exec;

pub use batch_stream::ProtocolBatchStream;
pub use protocol_provider::ProtocolTableProvider;
pub use stream_exec::ProtocolStreamExec;
