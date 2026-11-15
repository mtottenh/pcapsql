//! A query's result as a stream of batches.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use arrow::array::RecordBatch;
use datafusion::execution::session_state::SessionState;
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};
use futures::{Stream, StreamExt};
use tokio::task::JoinHandle;

use super::engine::QueryOutput;
// Named by the documentation only.
use super::planning::fold_producers;
use super::source::ParseSource;
use super::streaming;
#[cfg(doc)]
use super::QueryEngine;
use crate::error::{Error, QueryError};
use crate::query::providers::{ParseStats, PartitionStat, QueryTables};
use crate::query::udf::CaptureTimeRange;

/// A query's result as a stream of batches (see
/// [`QueryEngine::execute_stream`]).
///
/// Owns the query's session state, prepared tables and parse producers.
/// Yields `Err` once and ends on an execution error. Dropping the stream
/// cancels the query: its receivers go away, the source is told to stop
/// waiting for input, and the producers stop. [`QueryStream::finish`] drops
/// the same holders *before* joining the producers, in that order, so a
/// producer waiting on a receiver the plan never drained is released rather
/// than waited for.
pub struct QueryStream {
    pub(super) inner: Option<SendableRecordBatchStream>,
    pub(super) plan: Option<Arc<dyn ExecutionPlan>>,
    pub(super) state: Option<SessionState>,
    pub(super) prepared: Option<Arc<QueryTables>>,
    pub(super) producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    /// The engine's source, told to release a waiting producer when the
    /// stream is finished or dropped.
    pub(super) parse_source: Option<Arc<dyn ParseSource>>,
    /// Statistics known before execution (see [`fold_producers`]).
    pub(super) stats: ParseStats,
    pub(super) bootstrap: ParseStats,
    pub(super) time_range: Arc<CaptureTimeRange>,
    pub(super) last_stats: Arc<RwLock<ParseStats>>,
    /// Batches of a statement that already ran (DDL, EXPLAIN).
    pub(super) ready: VecDeque<RecordBatch>,
}

impl QueryStream {
    pub(super) fn ready(output: QueryOutput) -> Self {
        Self {
            inner: None,
            plan: None,
            state: None,
            prepared: None,
            producers: Vec::new(),
            parse_source: None,
            stats: output.stats,
            bootstrap: ParseStats::default(),
            time_range: Arc::new(CaptureTimeRange::new()),
            last_stats: Arc::new(RwLock::new(ParseStats::default())),
            ready: output.batches.into(),
        }
    }

    /// The physical plan being executed (`None` for a statement that parsed
    /// nothing), e.g. to inspect a continuous query's fused aggregate.
    pub fn plan(&self) -> Option<&Arc<dyn ExecutionPlan>> {
        self.plan.as_ref()
    }

    /// Continuous queries: the streaming aggregate's current watermark in
    /// microseconds since the epoch, once it has one.
    pub fn watermark_us(&self) -> Option<i64> {
        self.plan.as_ref().and_then(streaming::watermark_us)
    }

    /// Continuous queries: rows dropped as late so far.
    pub fn late_rows(&self) -> u64 {
        self.plan.as_ref().map(streaming::late_rows).unwrap_or(0)
    }

    /// Continuous queries: windows emitted so far.
    pub fn windows_emitted(&self) -> u64 {
        self.plan
            .as_ref()
            .map(streaming::windows_emitted)
            .unwrap_or(0)
    }

    /// Continuous queries: windows emitted early because the memory limit
    /// was reached (`on_memory_limit: CloseOldest`).
    pub fn windows_forced(&self) -> u64 {
        self.plan
            .as_ref()
            .map(streaming::windows_forced)
            .unwrap_or(0)
    }

    /// Continuous queries: bytes of window state the streaming aggregate
    /// holds right now (what it accounts to the memory pool).
    pub fn state_bytes(&self) -> u64 {
        self.plan.as_ref().map(streaming::state_bytes).unwrap_or(0)
    }

    /// Release the query's context and join its parse producers, returning
    /// the query's statistics (what `--stats` prints) or the parse error that
    /// ended it. Call it after the stream has ended, or earlier to cancel.
    ///
    /// A producer waiting for input on a quiet pipe is released
    /// ([`pcapsql_core::PacketSource::cancel_reads`]) before it is joined, so
    /// this returns promptly on a source opened from a descriptor (stdin, a
    /// pipe). A source opened from an arbitrary `Read` cannot be released:
    /// its producer returns at the next byte or when the writer closes, so
    /// bound the call with a timeout if that matters.
    pub async fn finish(mut self) -> Result<ParseStats, Error> {
        let late_rows = self.late_rows();
        let windows_forced = self.windows_forced();
        // Order matters: the stream and the plan hold the receivers and the
        // TaskContext, the state and the tables hold the rest.
        self.inner = None;
        self.plan = None;
        self.state = None;
        self.prepared = None;
        let producers = std::mem::take(&mut self.producers);
        // Only a query that started the parse has a producer to release;
        // cancelling is permanent on a single-use source, so a statement
        // that parsed nothing must leave the stream for the next one.
        if let Some(source) = self.parse_source.take() {
            if !producers.is_empty() {
                source.cancel();
            }
        }
        let stats = std::mem::take(&mut self.stats);
        let (mut stats, error) =
            fold_producers(producers, stats, &self.bootstrap, &self.time_range).await;
        stats.late_rows = late_rows;
        stats.windows_forced = windows_forced;
        *self.last_stats.write().expect("stats lock poisoned") = stats.clone();
        match error {
            Some(e) => Err(e),
            None => Ok(stats),
        }
    }
}

impl Drop for QueryStream {
    /// A stream dropped before `finish()` cancels its query: the receivers
    /// go with the fields, and the source releases a producer still waiting
    /// for input. The producers are detached, not joined.
    fn drop(&mut self) {
        if !self.producers.is_empty() {
            if let Some(source) = self.parse_source.take() {
                source.cancel();
            }
        }
    }
}

impl Stream for QueryStream {
    type Item = Result<RecordBatch, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(batch) = self.ready.pop_front() {
            return Poll::Ready(Some(Ok(batch)));
        }
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(batch))) => Poll::Ready(Some(Ok(batch))),
            Poll::Ready(Some(Err(e))) => {
                self.inner = None;
                Poll::Ready(Some(Err(Error::Query(QueryError::from(e)))))
            }
            Poll::Ready(None) => {
                self.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
