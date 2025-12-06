//! Streaming execution plan for PCAP files.
//!
//! This module provides a streaming execution plan that reads PCAP packets
//! on-demand as DataFusion pulls batches, supporting filter and limit pushdown.

use std::any::Any;
use std::fmt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use datafusion::common::Result as DFResult;
use datafusion::execution::{SendableRecordBatchStream, TaskContext};
use datafusion::logical_expr::Expr;
use datafusion::physical_expr::{EquivalenceProperties, Partitioning};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionMode, ExecutionPlan, PlanProperties,
};
use futures::stream::Stream;
use tokio::sync::mpsc;

use crate::pcap::PcapReader;
use crate::protocol::{parse_packet, ProtocolRegistry};

use super::filter::FilterEvaluator;
use super::PacketBatchBuilder;

/// Streaming execution plan for PCAP files.
#[derive(Debug, Clone)]
pub struct PcapStreamingExec {
    pcap_path: PathBuf,
    schema: SchemaRef,
    output_schema: SchemaRef,
    registry: Arc<ProtocolRegistry>,
    batch_size: usize,
    projection: Option<Vec<usize>>,
    filters: Vec<Expr>,
    limit: Option<usize>,
    properties: PlanProperties,
}

impl PcapStreamingExec {
    /// Create a new streaming execution plan.
    pub fn new(
        pcap_path: PathBuf,
        schema: SchemaRef,
        registry: Arc<ProtocolRegistry>,
        batch_size: usize,
        projection: Option<Vec<usize>>,
        filters: Vec<Expr>,
        limit: Option<usize>,
    ) -> Self {
        // Create projected schema if projection is specified
        let output_schema = if let Some(ref proj) = projection {
            let projected_fields: Vec<_> = proj
                .iter()
                .map(|&i| schema.field(i).clone())
                .collect();
            Arc::new(arrow::datatypes::Schema::new(projected_fields))
        } else {
            schema.clone()
        };

        let properties = PlanProperties::new(
            EquivalenceProperties::new(output_schema.clone()),
            Partitioning::UnknownPartitioning(1),
            ExecutionMode::Bounded,
        );

        Self {
            pcap_path,
            schema,
            output_schema,
            registry,
            batch_size,
            projection,
            filters,
            limit,
            properties,
        }
    }
}

impl DisplayAs for PcapStreamingExec {
    fn fmt_as(&self, t: DisplayFormatType, f: &mut fmt::Formatter) -> fmt::Result {
        match t {
            DisplayFormatType::Default | DisplayFormatType::Verbose => {
                write!(
                    f,
                    "PcapStreamingExec: file={}, batch_size={}, limit={:?}, filters={}",
                    self.pcap_path.display(),
                    self.batch_size,
                    self.limit,
                    self.filters.len()
                )
            }
        }
    }
}

impl ExecutionPlan for PcapStreamingExec {
    fn name(&self) -> &str {
        "PcapStreamingExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.output_schema.clone()
    }

    fn properties(&self) -> &PlanProperties {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        Ok(self)
    }

    fn execute(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(datafusion::error::DataFusionError::Internal(format!(
                "PcapStreamingExec only supports partition 0, got {partition}"
            )));
        }

        // Create async stream that reads packets
        let stream = create_pcap_stream(
            self.pcap_path.clone(),
            self.schema.clone(),
            self.registry.clone(),
            self.batch_size,
            self.filters.clone(),
            self.limit,
            self.projection.clone(),
        );

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            stream,
        )))
    }
}

/// Create an async stream that reads PCAP packets.
fn create_pcap_stream(
    pcap_path: PathBuf,
    schema: SchemaRef,
    registry: Arc<ProtocolRegistry>,
    batch_size: usize,
    filters: Vec<Expr>,
    limit: Option<usize>,
    projection: Option<Vec<usize>>,
) -> impl Stream<Item = DFResult<RecordBatch>> {
    // Use a channel to communicate between blocking reader and async stream
    let (tx, rx) = mpsc::channel::<DFResult<RecordBatch>>(2);

    // Spawn blocking task to read PCAP file
    let read_task = tokio::task::spawn_blocking(move || {
        read_pcap_batches(
            pcap_path,
            schema,
            registry,
            batch_size,
            filters,
            limit,
            projection,
            tx,
        )
    });

    // Convert receiver to stream
    PcapReceiverStream { rx, read_task }
}

/// Stream adapter that receives batches from the blocking reader.
struct PcapReceiverStream {
    rx: mpsc::Receiver<DFResult<RecordBatch>>,
    read_task: tokio::task::JoinHandle<()>,
}

impl Stream for PcapReceiverStream {
    type Item = DFResult<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll the receiver
        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(batch)) => Poll::Ready(Some(batch)),
            Poll::Ready(None) => {
                // Channel closed, check if task completed with error
                // We don't need to wait for the task since the channel is closed
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Read PCAP file and send batches through channel.
fn read_pcap_batches(
    pcap_path: PathBuf,
    schema: SchemaRef,
    registry: Arc<ProtocolRegistry>,
    batch_size: usize,
    filters: Vec<Expr>,
    limit: Option<usize>,
    projection: Option<Vec<usize>>,
    tx: mpsc::Sender<DFResult<RecordBatch>>,
) {
    // Create filter evaluator if filters are provided
    let filter_refs: Vec<&Expr> = filters.iter().collect();
    let filter_exprs: Vec<Expr> = filter_refs.iter().map(|e| (*e).clone()).collect();
    let filter_evaluator = FilterEvaluator::try_from_exprs(&filter_exprs);

    // Open PCAP reader
    let mut reader = match PcapReader::open(&pcap_path) {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.blocking_send(Err(datafusion::error::DataFusionError::External(
                Box::new(e),
            )));
            return;
        }
    };

    let link_type = reader.link_type();
    let mut builder = PacketBatchBuilder::new(schema.clone(), batch_size);
    let mut rows_emitted: usize = 0;
    let mut rows_in_current_batch: usize = 0;

    loop {
        // Check limit - include rows in current batch that haven't been emitted yet
        if let Some(lim) = limit {
            if rows_emitted + rows_in_current_batch >= lim {
                break;
            }
        }

        // Read next packet
        let raw_packet = match reader.next_packet() {
            Ok(Some(p)) => p,
            Ok(None) => break, // EOF
            Err(e) => {
                let _ = tx.blocking_send(Err(datafusion::error::DataFusionError::External(
                    Box::new(e),
                )));
                return;
            }
        };

        // Parse packet
        let parsed = parse_packet(&registry, link_type, &raw_packet.data);

        // Apply filter pushdown
        if let Some(ref evaluator) = filter_evaluator {
            if !evaluator.matches(&parsed) {
                continue; // Skip non-matching packet
            }
        }

        // Add packet to batch builder
        if let Err(e) = builder.add_packet(&raw_packet, &parsed) {
            let _ = tx.blocking_send(Err(datafusion::error::DataFusionError::External(
                Box::new(e),
            )));
            return;
        }

        rows_in_current_batch += 1;

        // Check if batch is ready
        match builder.try_build() {
            Ok(Some(batch)) => {
                let batch_rows = batch.num_rows();

                // Apply projection if specified
                let batch = if let Some(ref proj) = projection {
                    match apply_projection(batch, proj) {
                        Ok(b) => b,
                        Err(e) => {
                            let _ = tx.blocking_send(Err(e));
                            return;
                        }
                    }
                } else {
                    batch
                };

                rows_emitted += batch_rows;
                rows_in_current_batch = 0;

                if tx.blocking_send(Ok(batch)).is_err() {
                    // Receiver dropped, stop reading
                    return;
                }

                // Check limit after sending batch
                if let Some(lim) = limit {
                    if rows_emitted >= lim {
                        break;
                    }
                }
            }
            Ok(None) => {
                // Batch not full yet, continue
            }
            Err(e) => {
                let _ = tx.blocking_send(Err(datafusion::error::DataFusionError::External(
                    Box::new(e),
                )));
                return;
            }
        }
    }

    // Send final partial batch
    if rows_in_current_batch > 0 {
        match builder.finish() {
            Ok(Some(batch)) => {
                // Apply projection if specified
                let batch = if let Some(ref proj) = projection {
                    match apply_projection(batch, proj) {
                        Ok(b) => b,
                        Err(e) => {
                            let _ = tx.blocking_send(Err(e));
                            return;
                        }
                    }
                } else {
                    batch
                };

                let _ = tx.blocking_send(Ok(batch));
            }
            Ok(None) => {}
            Err(e) => {
                let _ = tx.blocking_send(Err(datafusion::error::DataFusionError::External(
                    Box::new(e),
                )));
            }
        }
    }
}

/// Apply column projection to a record batch.
fn apply_projection(batch: RecordBatch, projection: &[usize]) -> DFResult<RecordBatch> {
    let projected_columns: Vec<_> = projection
        .iter()
        .map(|&i| batch.column(i).clone())
        .collect();

    let projected_fields: Vec<_> = projection
        .iter()
        .map(|&i| batch.schema().field(i).clone())
        .collect();

    let projected_schema = Arc::new(arrow::datatypes::Schema::new(projected_fields));

    RecordBatch::try_new(projected_schema, projected_columns)
        .map_err(|e| datafusion::error::DataFusionError::ArrowError(e, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::default_registry;
    use crate::query::build_packets_schema;
    use tempfile::NamedTempFile;
    use futures::StreamExt;

    fn create_minimal_pcap() -> Vec<u8> {
        let mut data = Vec::new();

        // PCAP global header
        data.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic (little endian)
        data.extend_from_slice(&[0x02, 0x00]); // Version major (2)
        data.extend_from_slice(&[0x04, 0x00]); // Version minor (4)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Thiszone
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Sigfigs
        data.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // Snaplen (65535)
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Network (Ethernet)

        // Add a few packets
        for i in 0..5 {
            let packet_data = create_tcp_packet(i);
            let ts_sec: u32 = 1000000000 + i;
            let ts_usec: u32 = 0;
            let caplen: u32 = packet_data.len() as u32;
            let origlen: u32 = packet_data.len() as u32;

            data.extend_from_slice(&ts_sec.to_le_bytes());
            data.extend_from_slice(&ts_usec.to_le_bytes());
            data.extend_from_slice(&caplen.to_le_bytes());
            data.extend_from_slice(&origlen.to_le_bytes());
            data.extend_from_slice(&packet_data);
        }

        data
    }

    fn create_tcp_packet(seq: u32) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // Dst MAC
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Src MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType (IPv4)

        // IPv4 header (20 bytes)
        packet.push(0x45); // Version + IHL
        packet.push(0x00); // DSCP + ECN
        packet.extend_from_slice(&[0x00, 0x28]); // Total length (40)
        packet.extend_from_slice(&[0x00, 0x00]); // Identification
        packet.extend_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
        packet.push(0x40); // TTL (64)
        packet.push(0x06); // Protocol (TCP)
        packet.extend_from_slice(&[0x00, 0x00]); // Header checksum
        packet.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        packet.extend_from_slice(&[192, 168, 1, 2]); // Dst IP

        // TCP header (20 bytes)
        packet.extend_from_slice(&[0x30, 0x39]); // Src port (12345)
        packet.extend_from_slice(&[0x00, 0x50]); // Dst port (80)
        packet.extend_from_slice(&seq.to_be_bytes()); // Sequence number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack number
        packet.push(0x50); // Data offset (5 * 4 = 20)
        packet.push(0x02); // Flags (SYN)
        packet.extend_from_slice(&[0xff, 0xff]); // Window
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

        packet
    }

    #[tokio::test]
    async fn test_streaming_basic() {
        let pcap_data = create_minimal_pcap();
        let temp = NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), &pcap_data).unwrap();

        let registry = Arc::new(default_registry());
        let schema = Arc::new(build_packets_schema(&registry));

        let exec = PcapStreamingExec::new(
            temp.path().to_path_buf(),
            schema,
            registry,
            100,
            None,
            vec![],
            None,
        );

        let ctx = Arc::new(TaskContext::default());
        let mut stream = exec.execute(0, ctx).unwrap();

        let mut total_rows = 0;
        while let Some(batch) = stream.next().await {
            let batch = batch.unwrap();
            total_rows += batch.num_rows();
        }

        assert_eq!(total_rows, 5);
    }

    #[tokio::test]
    async fn test_streaming_with_limit() {
        let pcap_data = create_minimal_pcap();
        let temp = NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), &pcap_data).unwrap();

        let registry = Arc::new(default_registry());
        let schema = Arc::new(build_packets_schema(&registry));

        let exec = PcapStreamingExec::new(
            temp.path().to_path_buf(),
            schema,
            registry,
            100,
            None,
            vec![],
            Some(3), // Limit to 3 rows
        );

        let ctx = Arc::new(TaskContext::default());
        let mut stream = exec.execute(0, ctx).unwrap();

        let mut total_rows = 0;
        while let Some(batch) = stream.next().await {
            let batch = batch.unwrap();
            total_rows += batch.num_rows();
        }

        assert_eq!(total_rows, 3);
    }
}
