//! Table providers for protocol tables, backed by a single shared parse pass.
//!
//! ```text
//!                         capture (one source)
//!                               │
//!                    SharedParseState (ONE parse pass)
//!              ┌──────────────┬───┴───┬──────────────┐   parallel partitions
//!              ▼              ▼        ▼              ▼   (seekable sources)
//!         per-protocol Arrow builders (NormalizedBatchSet fan-out)
//!              │              │        │              │
//!              ▼              ▼        ▼              ▼
//!        frames table    ipv4 table  tcp table   dns table   ...
//!              └──────────────┴───────┴──────────────┘
//!                     shared by every ProtocolTableProvider
//! ```
//!
//! A query joining N protocol tables therefore parses the capture once, not N
//! times (#6), and that single pass is parallelized across partitions for
//! seekable sources (#9).

mod protocol_provider;
mod scan_exec;
mod shared;

pub use protocol_provider::{EngineTables, ProtocolTableProvider};
pub use scan_exec::ProtocolScanExec;
pub use shared::{
    run_shared_parse, ParseStats, ParseSubscription, ProgressFn, SharedParseState, TableData,
    TableSubscription,
};
