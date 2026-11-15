//! The engine's capture source as a type-erased scoped parse.

use std::sync::Arc;
use std::time::Duration;

use super::providers;
use crate::error::{Error, QueryError};
use crate::query::providers::{
    run_shared_parse, run_shared_parse_sequential, run_streaming_parse_sequential,
    ParseSubscription, SharedParseState, StreamingHandle,
};
use pcapsql_core::{KeyLog, PacketSource, ProtocolRegistry, SeekablePacketSource};

/// Type-erased scoped parse over the engine's source: either materialize the
/// subscribed tables (cache-fill) or stream them to the executing plan.
pub(super) trait ParseSource: Send + Sync {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error>;
    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error>;
    /// The source's own answer for the capture time range (microseconds, from
    /// its boundary index); `None` when it has to be scanned for.
    fn time_range_us(&self) -> Option<(i64, i64)>;
    /// Total frame count from the boundary index, if cheaply available
    /// (header-only scan; `None` for compressed/non-seekable sources).
    fn frame_count(&self) -> Option<u64>;
    /// Release a producer waiting for input on the source (a stream whose
    /// pipe has gone quiet), for good: called once a query is done with its
    /// tables. A file source has nothing to release.
    fn cancel(&self) {}
}

/// Binds a concrete seekable source to the parse parameters.
pub(super) struct SourceParser<S: SeekablePacketSource> {
    pub(super) source: Arc<S>,
    pub(super) registry: Arc<ProtocolRegistry>,
    pub(super) batch_size: usize,
    pub(super) partitions: usize,
    pub(super) progress: Option<providers::ProgressFn>,
    /// TLS keylog enabling decrypted HTTP/2 in the stream subscriber.
    pub(super) keylog: Option<Arc<KeyLog>>,
}

impl<S: SeekablePacketSource> ParseSource for SourceParser<S> {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error> {
        run_shared_parse(
            &self.source,
            &self.registry,
            self.batch_size,
            self.partitions,
            self.progress.clone(),
            sub,
            self.keylog.clone(),
        )
    }

    fn time_range_us(&self) -> Option<(i64, i64)> {
        self.source
            .time_range_ns()
            .map(|(start, end)| (start / 1_000, end / 1_000))
    }

    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error> {
        providers::run_streaming_parse(
            &self.source,
            &self.registry,
            self.batch_size,
            self.partitions,
            self.progress.clone(),
            sub,
        )
    }

    fn frame_count(&self) -> Option<u64> {
        self.source.frame_count()
    }
}

/// Binds a non-seekable source (stdin, a pipe) to the parse parameters: one
/// partition through the source's sequential reader; no boundary index, so
/// the time range and the frame count are never known up front (the
/// `count(*)` fast path is off and a time-range UDF cannot be bootstrapped).
pub(super) struct SequentialParser<S: PacketSource> {
    pub(super) source: Arc<S>,
    pub(super) registry: Arc<ProtocolRegistry>,
    pub(super) batch_size: usize,
    pub(super) progress: Option<providers::ProgressFn>,
    pub(super) keylog: Option<Arc<KeyLog>>,
    /// Continuous engines deliver partial batches on this cadence.
    pub(super) flush_interval: Option<Duration>,
}

impl<S: PacketSource> ParseSource for SequentialParser<S> {
    fn materialize(&self, sub: &ParseSubscription) -> Result<SharedParseState, Error> {
        run_shared_parse_sequential(
            self.source.as_ref(),
            &self.registry,
            self.batch_size,
            self.progress.clone(),
            sub,
            self.keylog.clone(),
        )
    }

    fn stream(&self, sub: &ParseSubscription) -> Result<StreamingHandle, Error> {
        run_streaming_parse_sequential(
            &self.source,
            &self.registry,
            self.batch_size,
            self.progress.clone(),
            sub,
            self.flush_interval,
        )
    }

    fn time_range_us(&self) -> Option<(i64, i64)> {
        None
    }

    fn frame_count(&self) -> Option<u64> {
        None
    }

    fn cancel(&self) {
        self.source.cancel_reads();
    }
}

/// The error for anything that would need a second read of a single-use
/// source.
pub(super) fn single_use_error(what: &str) -> Error {
    Error::Query(QueryError::Execution(format!(
        "{what}: stdin can be read once, so an engine over it runs exactly one parse pass"
    )))
}
