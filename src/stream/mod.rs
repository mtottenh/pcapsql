//! TCP stream processing and application-layer parsing.

mod connection;
mod context;
mod manager;
mod parser;
pub mod parsers;
mod reassembly;
mod registry;

pub use connection::{Connection, ConnectionKey, ConnectionState, ConnectionTracker, TcpFlags};
pub use context::{Direction, ParsedMessage, StreamContext, StreamParseResult};
pub use manager::{StreamConfig, StreamManager};
pub use parser::StreamParser;
pub use reassembly::{Segment, SequenceGap, StreamBuffer, StreamKey, StreamStats, TcpReassembler};
pub use registry::StreamRegistry;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use arrow::datatypes::Field;

    // Test 1: StreamContext construction
    #[test]
    fn test_stream_context_new() {
        let ctx = StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 54321,
            dst_port: 80,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        };
        assert_eq!(ctx.connection_id, 1);
        assert_eq!(ctx.direction, Direction::ToServer);
    }

    // Test 2: StreamParseResult variants
    #[test]
    fn test_parse_result_complete() {
        let result = StreamParseResult::Complete {
            messages: vec![],
            bytes_consumed: 100,
        };
        match result {
            StreamParseResult::Complete { bytes_consumed, .. } => {
                assert_eq!(bytes_consumed, 100);
            }
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn test_parse_result_need_more() {
        let result = StreamParseResult::NeedMore {
            minimum_bytes: Some(50),
        };
        match result {
            StreamParseResult::NeedMore { minimum_bytes } => {
                assert_eq!(minimum_bytes, Some(50));
            }
            _ => panic!("Expected NeedMore"),
        }
    }

    // Test 3: StreamRegistry registration
    // (Need a mock parser for this)
    struct MockParser;
    impl StreamParser for MockParser {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn can_parse_stream(&self, _: &StreamContext) -> bool {
            true
        }
        fn parse_stream(&self, _: &[u8], _: &StreamContext) -> StreamParseResult {
            StreamParseResult::NotThisProtocol
        }
        fn message_schema(&self) -> Vec<Field> {
            vec![]
        }
    }

    #[test]
    fn test_registry_register() {
        let mut registry = StreamRegistry::new();
        registry.register(MockParser);
        assert_eq!(registry.parser_names(), vec!["mock"]);
    }

    // Test 4: StreamRegistry find_parser
    #[test]
    fn test_registry_find_parser() {
        let mut registry = StreamRegistry::new();
        registry.register(MockParser);

        let ctx = StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 1234,
            dst_port: 80,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        };

        let parser = registry.find_parser(&ctx);
        assert!(parser.is_some());
        assert_eq!(parser.unwrap().name(), "mock");
    }

    // Test 5: StreamRegistry get_parser by name
    #[test]
    fn test_registry_get_parser() {
        let mut registry = StreamRegistry::new();
        registry.register(MockParser);

        assert!(registry.get_parser("mock").is_some());
        assert!(registry.get_parser("nonexistent").is_none());
    }

    // Test 6: Empty registry behavior
    #[test]
    fn test_registry_empty() {
        let registry = StreamRegistry::new();
        assert!(registry.parser_names().is_empty());

        let ctx = StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 1234,
            dst_port: 80,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        };
        assert!(registry.find_parser(&ctx).is_none());
    }
}
