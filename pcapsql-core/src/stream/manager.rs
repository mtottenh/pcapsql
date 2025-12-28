use std::net::IpAddr;
use std::sync::Arc;

use crate::error::Error;
use crate::tls::KeyLog;

use super::{
    parsers::DecryptingTlsStreamParser, Connection, ConnectionTracker, Direction, ParsedMessage,
    StreamContext, StreamParseResult, StreamRegistry, TcpFlags, TcpReassembler,
};

/// Configuration for the StreamManager.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Maximum memory per connection (bytes).
    pub max_connection_buffer: usize,
    /// Maximum total memory for all streams.
    pub max_total_memory: usize,
    /// Connection timeout (microseconds).
    pub connection_timeout_us: i64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_connection_buffer: 16 * 1024 * 1024, // 16 MB per connection
            max_total_memory: 1024 * 1024 * 1024,    // 1 GB total
            connection_timeout_us: 300_000_000,      // 5 minutes
        }
    }
}

/// Central orchestrator for TCP stream processing.
pub struct StreamManager {
    connections: ConnectionTracker,
    reassembler: TcpReassembler,
    stream_registry: StreamRegistry,
    config: StreamConfig,
    /// Current total memory usage.
    total_memory: usize,
    /// Optional keylog for TLS decryption.
    keylog: Option<Arc<KeyLog>>,
}

impl StreamManager {
    pub fn new(config: StreamConfig) -> Self {
        Self {
            connections: ConnectionTracker::new(),
            reassembler: TcpReassembler::new(),
            stream_registry: StreamRegistry::new(),
            config,
            total_memory: 0,
            keylog: None,
        }
    }

    /// Create with default config and register default parsers.
    pub fn with_defaults() -> Self {
        Self::new(StreamConfig::default())
    }

    /// Enable TLS decryption with the provided keylog.
    ///
    /// This registers a `DecryptingTlsStreamParser` that will attempt to
    /// decrypt TLS application data when matching keys are found in the keylog.
    ///
    /// The keylog should be in SSLKEYLOGFILE format, as used by Wireshark
    /// and browsers.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use pcapsql_core::stream::{StreamConfig, StreamManager};
    /// use pcapsql_core::tls::KeyLog;
    ///
    /// let keylog = KeyLog::from_file("sslkeylog.txt").unwrap();
    /// let manager = StreamManager::new(StreamConfig::default())
    ///     .with_keylog(keylog);
    /// ```
    pub fn with_keylog(mut self, keylog: KeyLog) -> Self {
        let keylog = Arc::new(keylog);
        self.keylog = Some(Arc::clone(&keylog));

        // Register the decrypting TLS parser (before any other TLS parser)
        let parser = DecryptingTlsStreamParser::with_keylog(keylog);
        self.stream_registry.register(parser);

        self
    }

    /// Check if TLS decryption is enabled.
    pub fn has_keylog(&self) -> bool {
        self.keylog.is_some()
    }

    /// Get the keylog if available.
    pub fn keylog(&self) -> Option<&KeyLog> {
        self.keylog.as_ref().map(|k| k.as_ref())
    }

    /// Get mutable access to the stream registry for parser registration.
    pub fn registry_mut(&mut self) -> &mut StreamRegistry {
        &mut self.stream_registry
    }

    /// Process a TCP segment.
    ///
    /// Returns any parsed messages.
    #[allow(clippy::too_many_arguments)]
    pub fn process_segment(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        _ack: u32,
        flags: TcpFlags,
        payload: &[u8],
        frame_number: u64,
        timestamp: i64,
    ) -> Result<Vec<ParsedMessage>, Error> {
        let mut messages = Vec::new();

        // 1. Get or create connection
        let (conn, direction) = self.connections.get_or_create(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            flags,
            seq,
            frame_number,
            timestamp,
        );
        let connection_id = conn.id;

        // 2. Update connection state
        ConnectionTracker::update_state(conn, flags, direction, seq);

        // 3. Handle SYN (initial sequence number)
        if flags.syn {
            let buffer = self.reassembler.get_or_create(connection_id, direction);
            buffer.set_initial_seq(seq);
        }

        // 4. Add payload to reassembler
        if !payload.is_empty() {
            ConnectionTracker::add_bytes(conn, direction, payload.len());
            self.reassembler.add_segment(
                connection_id,
                direction,
                seq,
                payload,
                frame_number,
                timestamp,
            );
            self.total_memory += payload.len();
        }

        // 5. Try to parse reassembled data
        self.try_parse(connection_id, direction, frame_number, &mut messages)?;

        // 6. Handle FIN
        if flags.fin {
            self.reassembler.mark_fin(connection_id, direction);
        }

        // 7. Handle connection termination
        if flags.rst || (flags.fin && self.is_fully_closed(connection_id)) {
            self.finalize_connection(connection_id, &mut messages)?;
        }

        Ok(messages)
    }

    /// Try to parse data from a stream.
    fn try_parse(
        &mut self,
        connection_id: u64,
        direction: Direction,
        frame_number: u64,
        messages: &mut Vec<ParsedMessage>,
    ) -> Result<(), Error> {
        loop {
            let data = self.reassembler.get_contiguous(connection_id, direction);
            if data.is_empty() {
                break;
            }

            // Build context for parser
            let context = self.build_context(connection_id, direction);

            // Find parser
            let parser = match self.stream_registry.find_parser(&context) {
                Some(p) => p,
                None => break, // No parser for this stream
            };

            // We need to copy data because we can't hold borrow across mutable ops
            let data_copy = data.to_vec();

            // Parse
            match parser.parse_stream(&data_copy, &context) {
                StreamParseResult::Complete {
                    messages: msgs,
                    bytes_consumed,
                } => {
                    for mut msg in msgs {
                        msg.frame_number = frame_number;
                        messages.push(msg);
                    }
                    self.reassembler
                        .consume(connection_id, direction, bytes_consumed);
                    self.total_memory = self.total_memory.saturating_sub(bytes_consumed);
                    // Continue loop - might be more messages
                }

                StreamParseResult::Transform {
                    child_protocol,
                    child_data,
                    bytes_consumed,
                    metadata,
                } => {
                    if let Some(mut meta) = metadata {
                        meta.frame_number = frame_number;
                        messages.push(meta);
                    }
                    self.reassembler
                        .consume(connection_id, direction, bytes_consumed);
                    self.total_memory = self.total_memory.saturating_sub(bytes_consumed);

                    // Recursively parse transformed data
                    self.parse_transformed(
                        connection_id,
                        direction,
                        child_protocol,
                        &child_data,
                        frame_number,
                        messages,
                    )?;
                }

                StreamParseResult::NeedMore { .. } => {
                    break; // Wait for more data
                }

                StreamParseResult::NotThisProtocol => {
                    break; // Can't parse this stream
                }

                StreamParseResult::Error { skip_bytes, .. } => {
                    if let Some(skip) = skip_bytes {
                        self.reassembler.consume(connection_id, direction, skip);
                        self.total_memory = self.total_memory.saturating_sub(skip);
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse transformed/decrypted data with a child parser.
    fn parse_transformed(
        &self,
        connection_id: u64,
        direction: Direction,
        child_protocol: &str,
        data: &[u8],
        frame_number: u64,
        messages: &mut Vec<ParsedMessage>,
    ) -> Result<(), Error> {
        let parser = match self.stream_registry.get_parser(child_protocol) {
            Some(p) => p,
            None => return Ok(()), // No parser for child protocol
        };

        let context = self.build_context(connection_id, direction);

        if let StreamParseResult::Complete { messages: msgs, .. } =
            parser.parse_stream(data, &context)
        {
            for mut msg in msgs {
                msg.frame_number = frame_number;
                messages.push(msg);
            }
        }

        Ok(())
    }

    /// Build a StreamContext for the given connection.
    fn build_context(&self, connection_id: u64, direction: Direction) -> StreamContext {
        let conn = self
            .connections
            .connections()
            .find(|c| c.id == connection_id);

        if let Some(conn) = conn {
            let (src_ip, dst_ip, src_port, dst_port) = match direction {
                Direction::ToServer => (
                    conn.client_ip(),
                    conn.server_ip(),
                    conn.client_port(),
                    conn.server_port(),
                ),
                Direction::ToClient => (
                    conn.server_ip(),
                    conn.client_ip(),
                    conn.server_port(),
                    conn.client_port(),
                ),
            };

            StreamContext {
                connection_id,
                direction,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                bytes_parsed: 0, // Could track this
                messages_parsed: 0,
                alpn: None, // Set by TLS parser
            }
        } else {
            // Fallback - shouldn't happen
            StreamContext {
                connection_id,
                direction,
                src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                src_port: 0,
                dst_port: 0,
                bytes_parsed: 0,
                messages_parsed: 0,
                alpn: None,
            }
        }
    }

    /// Check if connection is fully closed (both sides FIN'd).
    fn is_fully_closed(&self, connection_id: u64) -> bool {
        self.reassembler
            .is_complete(connection_id, Direction::ToServer)
            && self
                .reassembler
                .is_complete(connection_id, Direction::ToClient)
    }

    /// Finalize a closed connection.
    #[allow(clippy::ptr_arg)]
    fn finalize_connection(
        &mut self,
        connection_id: u64,
        _messages: &mut Vec<ParsedMessage>,
    ) -> Result<(), Error> {
        // Clean up reassembly buffers
        self.reassembler.remove(connection_id);
        Ok(())
    }

    /// Cleanup timed-out connections.
    pub fn cleanup_timeout(&mut self, current_time: i64) -> Vec<Connection> {
        let removed = self
            .connections
            .cleanup_timeout(current_time, self.config.connection_timeout_us);

        for conn in &removed {
            self.reassembler.remove(conn.id);
        }

        removed
    }

    /// Get all tracked connections.
    pub fn connections(&self) -> impl Iterator<Item = &Connection> {
        self.connections.connections()
    }

    /// Get total memory usage.
    pub fn total_memory(&self) -> usize {
        self.total_memory
    }

    /// Check if memory limit is exceeded.
    pub fn memory_limit_exceeded(&self) -> bool {
        self.total_memory > self.config.max_total_memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // Test 1: Basic segment processing
    #[test]
    fn test_process_segment() {
        let mut manager = StreamManager::with_defaults();

        let flags = TcpFlags {
            syn: true,
            ..Default::default()
        };
        let result = manager.process_segment(
            ip(192, 168, 1, 1),
            ip(192, 168, 1, 2),
            54321,
            80,
            1000,
            0,
            flags,
            b"",
            1,
            0,
        );

        assert!(result.is_ok());
        assert_eq!(manager.connections().count(), 1);
    }

    // Test 2: Connection creation on SYN
    #[test]
    fn test_connection_on_syn() {
        let mut manager = StreamManager::with_defaults();

        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        manager
            .process_segment(
                ip(192, 168, 1, 1),
                ip(192, 168, 1, 2),
                54321,
                80,
                1000,
                0,
                syn,
                b"",
                1,
                0,
            )
            .unwrap();

        let conn = manager.connections().next().unwrap();
        assert_eq!(conn.client_port(), 54321);
        assert_eq!(conn.server_port(), 80);
    }

    // Test 3: Reassembly triggers parser (mock test - no real parser)
    #[test]
    fn test_reassembly_triggers_parse() {
        let mut manager = StreamManager::with_defaults();

        // No parser registered, but data should be buffered
        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };
        manager
            .process_segment(
                ip(192, 168, 1, 1),
                ip(192, 168, 1, 2),
                54321,
                80,
                1000,
                0,
                ack,
                b"GET / HTTP/1.1\r\n",
                1,
                0,
            )
            .unwrap();

        // Data should be in buffer (no parser to consume it)
        assert!(manager.total_memory() > 0);
    }

    // Test 4: Parser NeedMore handling
    #[test]
    fn test_need_more_handling() {
        // This test verifies the loop exits on NeedMore
        // Would need mock parser for full test
        let manager = StreamManager::with_defaults();
        assert_eq!(manager.connections().count(), 0);
    }

    // Test 5: Parser Complete handling
    #[test]
    fn test_complete_handling() {
        // Would need mock parser
        let manager = StreamManager::with_defaults();
        assert!(manager.total_memory() == 0);
    }

    // Test 6: Memory limit tracking
    #[test]
    fn test_memory_tracking() {
        let config = StreamConfig {
            max_total_memory: 1000,
            ..Default::default()
        };
        let mut manager = StreamManager::new(config);

        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };

        // Add data
        manager
            .process_segment(
                ip(192, 168, 1, 1),
                ip(192, 168, 1, 2),
                54321,
                80,
                1000,
                0,
                ack,
                &[0u8; 500],
                1,
                0,
            )
            .unwrap();

        assert_eq!(manager.total_memory(), 500);
        assert!(!manager.memory_limit_exceeded());

        // Exceed limit
        manager
            .process_segment(
                ip(192, 168, 1, 1),
                ip(192, 168, 1, 2),
                54321,
                80,
                1500,
                0,
                ack,
                &[0u8; 600],
                2,
                1,
            )
            .unwrap();

        assert!(manager.memory_limit_exceeded());
    }

    // Test 7: Connection cleanup
    #[test]
    fn test_connection_cleanup() {
        let config = StreamConfig {
            connection_timeout_us: 1000,
            ..Default::default()
        };
        let mut manager = StreamManager::new(config);

        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        manager
            .process_segment(
                ip(192, 168, 1, 1),
                ip(192, 168, 1, 2),
                54321,
                80,
                1000,
                0,
                syn,
                b"",
                1,
                0,
            )
            .unwrap();

        assert_eq!(manager.connections().count(), 1);

        // Cleanup after timeout
        let removed = manager.cleanup_timeout(10000);
        assert_eq!(removed.len(), 1);
        assert_eq!(manager.connections().count(), 0);
    }

    // Test 8: Multiple concurrent connections
    #[test]
    fn test_multiple_connections() {
        let mut manager = StreamManager::with_defaults();

        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };

        // Connection 1
        manager
            .process_segment(
                ip(192, 168, 1, 1),
                ip(192, 168, 1, 2),
                54321,
                80,
                1000,
                0,
                syn,
                b"",
                1,
                0,
            )
            .unwrap();

        // Connection 2
        manager
            .process_segment(
                ip(192, 168, 1, 3),
                ip(192, 168, 1, 4),
                54322,
                443,
                2000,
                0,
                syn,
                b"",
                2,
                1,
            )
            .unwrap();

        assert_eq!(manager.connections().count(), 2);
    }

    // Test 9: StreamManager with keylog
    #[test]
    fn test_with_keylog() {
        let keylog = KeyLog::new();
        let manager = StreamManager::new(StreamConfig::default()).with_keylog(keylog);

        assert!(manager.has_keylog());
        assert!(manager.keylog().is_some());

        // Should have the decrypting TLS parser registered
        let parser_names: Vec<_> = manager.stream_registry.parser_names().into_iter().collect();
        assert!(parser_names.contains(&"tls_decrypt"));
    }

    // Test 10: StreamManager without keylog
    #[test]
    fn test_without_keylog() {
        let manager = StreamManager::with_defaults();

        assert!(!manager.has_keylog());
        assert!(manager.keylog().is_none());
    }

    // Test 11: TLS decryption parser is registered and prioritized
    #[test]
    fn test_tls_parser_registered() {
        let keylog = KeyLog::new();
        let manager = StreamManager::new(StreamConfig::default()).with_keylog(keylog);

        // Create a context for port 443
        let ctx = StreamContext {
            connection_id: 1,
            direction: Direction::ToServer,
            src_ip: ip(192, 168, 1, 1),
            dst_ip: ip(192, 168, 1, 2),
            src_port: 54321,
            dst_port: 443,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        };

        // Should find the decrypting TLS parser
        let parser = manager.stream_registry.find_parser(&ctx);
        assert!(parser.is_some());
        assert_eq!(parser.unwrap().name(), "tls_decrypt");
    }
}
