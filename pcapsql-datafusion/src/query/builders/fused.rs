//! Builder for a fused join (see [`crate::query::fusion`]): the joined rows
//! of a frame, built from the frame's own parsed layers.

use std::sync::Arc;

use arrow::array::Array;
use arrow::record_batch::{RecordBatch, RecordBatchOptions};

use super::protocol::DynamicBuilder;
use crate::error::{Error, QueryError};
use crate::query::fusion::{FrameJoinSpec, JoinKind};
use pcapsql_core::io::PacketRef;
use pcapsql_core::{FieldHint, ParseResult};

/// Where an output column's value comes from, resolved once from the spec.
enum Source {
    FrameNumber,
    Timestamp,
    Length,
    OriginalLength,
    LinkType,
    RawData,
    EncapDepth,
    TunnelType,
    TunnelId,
    /// A field by name, with where it was found in the previous row.
    Field(String, FieldHint),
}

/// A member's row for the current frame, as an index into the frame's
/// parsed layers, or one of two markers.
type RowRef = usize;
/// The `frames` table: the packet itself.
const FRAME: RowRef = usize::MAX;
/// A left join that found no row.
const NULL: RowRef = usize::MAX - 1;

/// Builds the Arrow batches of one fused join.
pub struct FusedBatchBuilder {
    spec: Arc<FrameJoinSpec>,
    sources: Vec<(usize, Source)>,
    builders: Vec<DynamicBuilder>,
    batch_size: usize,
    rows: usize,
    /// Scratch, reused across packets: each member's rows for the frame,
    /// and the join's tuples (one slot per member joined so far, flat).
    member_rows: Vec<Vec<RowRef>>,
    tuples: Vec<RowRef>,
    next: Vec<RowRef>,
}

impl FusedBatchBuilder {
    pub fn new(spec: Arc<FrameJoinSpec>, batch_size: usize) -> Self {
        let sources = spec
            .columns
            .iter()
            .map(|c| {
                let is_frames = spec.members[c.member].table == "frames";
                let source = match (is_frames, c.column.as_str()) {
                    (_, "frame_number") => Source::FrameNumber,
                    (true, "timestamp") => Source::Timestamp,
                    (true, "length") => Source::Length,
                    (true, "original_length") => Source::OriginalLength,
                    (true, "link_type") => Source::LinkType,
                    (true, "raw_data") => Source::RawData,
                    (false, "encap_depth") => Source::EncapDepth,
                    (false, "tunnel_type") => Source::TunnelType,
                    (false, "tunnel_id") => Source::TunnelId,
                    (_, name) => Source::Field(name.to_string(), FieldHint::default()),
                };
                (c.member, source)
            })
            .collect();
        let builders = spec
            .schema
            .fields()
            .iter()
            .map(|f| DynamicBuilder::new(f.data_type(), batch_size))
            .collect();
        let members = spec.members.len();
        Self {
            spec,
            sources,
            builders,
            batch_size,
            rows: 0,
            member_rows: vec![Vec::new(); members],
            tuples: Vec::new(),
            next: Vec::new(),
        }
    }

    pub fn row_count(&self) -> usize {
        self.rows
    }

    /// Evaluate the joins over this frame's rows and append the result.
    /// Returns the number of rows appended.
    pub fn add_packet(
        &mut self,
        packet: &PacketRef<'_>,
        parsed: &[(&str, ParseResult<'_>)],
    ) -> usize {
        let depth = |row: RowRef| -> Option<u8> {
            if row == FRAME {
                None
            } else {
                Some(parsed[row].1.encap_depth)
            }
        };
        // Each member's rows for this frame.
        for (m, rows) in self.spec.members.iter().zip(self.member_rows.iter_mut()) {
            rows.clear();
            if m.table == "frames" {
                rows.push(FRAME);
            } else {
                rows.extend(
                    parsed
                        .iter()
                        .enumerate()
                        .filter(|(_, (name, _))| *name == m.table)
                        .map(|(i, _)| i),
                );
            }
        }
        // The join, member by member: a tuple per output row, one slot per
        // member joined so far, flat in `tuples`.
        self.tuples.clear();
        self.tuples.extend_from_slice(&self.member_rows[0]);
        for (i, member) in self.spec.members.iter().enumerate().skip(1) {
            let join = member.join.expect("a non-root member has a join");
            let width = i;
            self.next.clear();
            for tuple in self.tuples.chunks_exact(width) {
                let anchor = tuple[join.with];
                let mut any = false;
                if anchor != NULL {
                    // A NULL key never equals anything.
                    for &candidate in &self.member_rows[i] {
                        if !join.depth || depth(anchor) == depth(candidate) {
                            any = true;
                            self.next.extend_from_slice(tuple);
                            self.next.push(candidate);
                        }
                    }
                }
                if !any && join.kind == JoinKind::Left {
                    self.next.extend_from_slice(tuple);
                    self.next.push(NULL);
                }
            }
            std::mem::swap(&mut self.tuples, &mut self.next);
        }
        let width = self.spec.members.len();
        let added = self.tuples.len() / width;
        for tuple in self.tuples.chunks_exact(width) {
            self.rows += 1;
            for ((member, source), builder) in self.sources.iter_mut().zip(self.builders.iter_mut())
            {
                match tuple[*member] {
                    NULL => builder.append_null(),
                    FRAME => match source {
                        Source::FrameNumber => builder.append_u64(packet.frame_number),
                        Source::Timestamp => builder.append_timestamp(packet.timestamp_ns / 1_000),
                        Source::Length => builder.append_u32(packet.captured_len),
                        Source::OriginalLength => builder.append_u32(packet.original_len),
                        Source::LinkType => builder.append_u16(packet.link_type),
                        Source::RawData => builder.append_binary(packet.data),
                        _ => builder.append_null(),
                    },
                    row => match source {
                        Source::FrameNumber => builder.append_u64(packet.frame_number),
                        Source::EncapDepth => builder.append_u8(parsed[row].1.encap_depth),
                        Source::TunnelType => match parsed[row].1.tunnel_type.as_str() {
                            Some(s) => builder.append_str(s),
                            None => builder.append_null(),
                        },
                        Source::TunnelId => match parsed[row].1.tunnel_id {
                            Some(id) => builder.append_u64(id),
                            None => builder.append_null(),
                        },
                        Source::Field(name, hint) => match parsed[row].1.get_hinted(name, hint) {
                            Some(value) => builder.append_field_value(value),
                            None => builder.append_null(),
                        },
                        _ => builder.append_null(),
                    },
                }
            }
        }
        added
    }

    /// The batch if it is full.
    pub fn try_build(&mut self) -> Result<Option<RecordBatch>, Error> {
        if self.rows >= self.batch_size {
            self.build().map(Some)
        } else {
            Ok(None)
        }
    }

    /// The final partial batch, if any rows are pending.
    pub fn finish(&mut self) -> Result<Option<RecordBatch>, Error> {
        if self.rows > 0 {
            self.build().map(Some)
        } else {
            Ok(None)
        }
    }

    fn build(&mut self) -> Result<RecordBatch, Error> {
        let arrays: Vec<Arc<dyn Array>> = self.builders.iter_mut().map(|b| b.finish()).collect();
        let options = RecordBatchOptions::new().with_row_count(Some(self.rows));
        self.rows = 0;
        for (builder, field) in self.builders.iter_mut().zip(self.spec.schema.fields()) {
            *builder = DynamicBuilder::new(field.data_type(), self.batch_size);
        }
        RecordBatch::try_new_with_options(Arc::clone(&self.spec.schema), arrays, &options)
            .map_err(|e| Error::Query(QueryError::Arrow(e.to_string())))
    }
}
