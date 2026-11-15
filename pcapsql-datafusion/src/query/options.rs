//! How an engine is opened: the capture source and the engine options.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// Named by the documentation only.
#[cfg(doc)]
use super::{auto_target_partitions, fusion, QueryEngine};
use crate::query::providers::ProgressFn;
use crate::query::streaming::MemoryLimitPolicy;
use pcapsql_core::{KeyLog, StdinPacketSource};

/// Where to read a capture from.
///
/// A file or cloud object is seekable and can be read any number of times;
/// the engine partitions it for parallel parsing and, under
/// [`RetentionPolicy::CacheOnTouch`], re-reads it as queries need. Standard
/// input (or any other stream) can be read **once**, sequentially: such an
/// engine runs exactly one parse pass, with the restrictions documented on
/// [`QueryEngine::open`].
#[derive(Clone, Debug)]
pub enum SourceSpec {
    /// Local file path (pcap/pcapng, optionally compressed).
    Path(PathBuf),
    /// Cloud object URL (`s3://…`, `gs://…`, `az://…`); needs the `cloud` feature.
    Url(String),
    /// The process's standard input (pcap/pcapng, optionally compressed),
    /// read sequentially to end of input. The capture header is read when
    /// the engine is opened.
    Stdin,
    /// An already-opened non-seekable stream (a pipe, a socket, an in-memory
    /// buffer): the library form of [`SourceSpec::Stdin`], built with
    /// [`StdinPacketSource::from_reader`].
    Sequential(StdinPacketSource),
}

/// Options for cloud sources (ignored for local paths).
#[derive(Clone, Debug, Default)]
pub struct CloudSourceOptions {
    /// Custom endpoint (S3-compatible stores such as MinIO/SeaweedFS/R2).
    pub endpoint: Option<String>,
    /// Use anonymous (unsigned) requests for public buckets.
    pub anonymous: bool,
    /// Byte-range request chunk size in bytes (`None` = backend default).
    pub chunk_size: Option<usize>,
}

/// What the engine retains between queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Retain nothing: each query parses exactly what it needs (columns,
    /// parse-time predicates, row caps) and the result is dropped after
    /// execution. The right policy for one-shot queries.
    None,
    /// Cache each touched table on first use, so later queries over the same
    /// tables parse nothing. The right policy for the REPL. The cache is
    /// column-aware: a table is cached with the columns the first query
    /// needed (unfiltered, uncapped), a later query needing more columns
    /// re-parses the union and widens the entry, and the entry never
    /// narrows, so reuse stays sound for any later query shape.
    CacheOnTouch,
}

/// Construction options for [`QueryEngine::open`].
#[derive(Clone)]
pub struct EngineOptions {
    /// Packets per RecordBatch.
    pub batch_size: usize,
    /// What to retain between queries (see [`RetentionPolicy`]).
    pub retention: RetentionPolicy,
    /// Partition count for the parallel parse pass. `None` = available
    /// parallelism clamped to 1..=16, except that a memory-mapped file under
    /// 1 MiB is parsed in a single partition (see
    /// [`auto_target_partitions`]); an explicit count is always honoured.
    pub target_partitions: Option<usize>,
    /// TLS keylog enabling the decrypted `http2` table.
    pub keylog: Option<Arc<KeyLog>>,
    /// Memory-map local files. Compressed captures are mapped too: they are
    /// decompressed from the map and parsed as a single partition. Falls
    /// back to buffered file I/O only when mapping the file itself fails.
    pub mmap: bool,
    /// Boundary-index checkpoint stride override (mainly tests/benchmarks).
    pub index_stride: Option<u64>,
    /// Invoked with the cumulative packet count as the parse progresses.
    pub progress: Option<ProgressFn>,
    /// Cloud-source options (ignored for local paths).
    pub cloud: CloudSourceOptions,
    /// Treat the source as an unbounded stream (a live capture piped in):
    /// scans are unbounded, `GROUP BY window_start` over `tumble()` / `hop()`
    /// runs as a streaming aggregate that emits each window as it closes
    /// (see [`crate::query::streaming`]), and results are consumed with
    /// [`QueryEngine::execute_stream`]. Needs a stream source
    /// ([`SourceSpec::Stdin`] / [`SourceSpec::Sequential`]) and
    /// [`RetentionPolicy::None`]; the single-use restrictions of a stream
    /// apply, and queries that need the whole input (stream tables, several
    /// scans of one table, sorts, joins, aggregates without a window) are
    /// rejected at planning.
    pub continuous: bool,
    /// Continuous only: how far behind the largest timestamp seen a row may
    /// be and still count — the watermark trails the stream by this much.
    pub allowed_lateness: Duration,
    /// Continuous only: a partially filled batch is handed to the query once
    /// this long has passed since the last one (checked as packets arrive).
    pub flush_interval: Duration,
    /// Continuous only: close and emit every open window after this long
    /// without any input (`None`: windows close on event time only).
    pub idle_timeout: Option<Duration>,
    /// Fuse frame joins into the parse (see [`fusion`]): the `*_packets`
    /// views and hand-written joins of protocol tables on `frame_number` are
    /// built by the parser instead of DataFusion's join operators. Applies
    /// under [`RetentionPolicy::None`] only; on by default. Off is for
    /// comparing plans and results against the join path.
    pub fuse_frame_joins: bool,
    /// Bytes DataFusion's memory pool may hand out to this engine's queries
    /// (sorts, joins, aggregates, and a continuous query's window state).
    /// `None`: unbounded, DataFusion's default.
    pub memory_limit: Option<usize>,
    /// Continuous only: what the streaming window aggregate does when its
    /// state does not fit the memory limit (see [`MemoryLimitPolicy`]).
    pub on_memory_limit: MemoryLimitPolicy,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            batch_size: 10_000,
            retention: RetentionPolicy::CacheOnTouch,
            target_partitions: None,
            keylog: None,
            mmap: true,
            index_stride: None,
            progress: None,
            cloud: CloudSourceOptions::default(),
            continuous: false,
            allowed_lateness: Duration::from_secs(1),
            flush_interval: Duration::from_secs(1),
            idle_timeout: None,
            fuse_frame_joins: true,
            memory_limit: None,
            on_memory_limit: MemoryLimitPolicy::Error,
        }
    }
}
