use crate::schema::FieldDescriptor;

use super::{StreamContext, StreamParseResult};

/// Trait for parsing application protocols from reassembled streams.
pub trait StreamParser: Send + Sync {
    /// Protocol identifier (e.g., "http", "tls").
    fn name(&self) -> &'static str;

    /// Human-readable name.
    fn display_name(&self) -> &'static str {
        self.name()
    }

    /// Check if this parser can handle the stream based on context.
    fn can_parse_stream(&self, context: &StreamContext) -> bool;

    /// Parse from reassembled stream bytes.
    ///
    /// Called repeatedly as more data becomes available.
    /// Parser should be stateless - all state is managed externally.
    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult;

    /// Schema for messages produced by this parser.
    fn message_schema(&self) -> Vec<FieldDescriptor>;
}
