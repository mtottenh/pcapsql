//! The fused aggregate's output stream.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arrow::array::RecordBatch;
use arrow::datatypes::SchemaRef;
use datafusion::common::Result;
use datafusion::physical_plan::{RecordBatchStream, SendableRecordBatchStream};
use futures::Stream;

use super::state::AggregateState;

/// The output stream: folds input batches, yields closed windows.
pub(super) struct StreamingAggregateStream {
    pub(super) input: SendableRecordBatchStream,
    pub(super) state: AggregateState,
    pub(super) queue: VecDeque<RecordBatch>,
    pub(super) schema: SchemaRef,
    pub(super) idle_timeout: Option<Duration>,
    pub(super) idle: Option<Pin<Box<tokio::time::Sleep>>>,
    pub(super) done: bool,
}

impl Stream for StreamingAggregateStream {
    type Item = Result<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(batch) = self.queue.pop_front() {
                return Poll::Ready(Some(Ok(batch)));
            }
            if self.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut self.input).poll_next(cx) {
                Poll::Ready(Some(Ok(batch))) => {
                    self.idle = None;
                    match self.state.process(&batch) {
                        Ok(closed) => self.queue.extend(closed),
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    self.done = true;
                    match self.state.emit_all() {
                        Ok(closed) => self.queue.extend(closed),
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Pending => {
                    let Some(idle_timeout) = self.idle_timeout else {
                        return Poll::Pending;
                    };
                    if self.state.is_empty() {
                        // Nothing to close: no timer until a window opens.
                        self.idle = None;
                        return Poll::Pending;
                    }
                    let sleep = self
                        .idle
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle_timeout)));
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.idle = None;
                            match self.state.emit_all() {
                                Ok(closed) => self.queue.extend(closed),
                                Err(e) => return Poll::Ready(Some(Err(e))),
                            }
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl RecordBatchStream for StreamingAggregateStream {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
}
