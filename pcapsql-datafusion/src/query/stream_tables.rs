//! Stream analysis as a subscriber of the packet pass.
//!
//! TCP reassembly, TLS decryption and the HTTP/1.x / HTTP/2 stream parsers
//! consume the *already parsed* layers of every packet from the single
//! scoped parse pass — there is no second read of the capture and no
//! embedded link/IP/TCP mini-parser. The subscriber feeds
//! [`StreamManager`] and, at the end of the pass, builds the stream tables:
//! `tcp_connections`, `tls_sessions`, `http_messages` and `http2`.
//!
//! Reassembly needs the whole capture in order, so a pass with a stream
//! subscriber runs as one partition (`run_shared_parse` pins it).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use arrow::array::{
    new_null_array, ArrayRef, BooleanBuilder, StringBuilder, TimestampMicrosecondBuilder,
    UInt16Builder, UInt32Builder, UInt64Builder, UInt8Array, UInt8Builder,
};
use arrow::datatypes::{DataType, Schema};
use arrow::record_batch::RecordBatch;

use pcapsql_core::io::PacketRef;
use pcapsql_core::stream::{
    cipher_suite_name, Connection, ConnectionState, Http2StreamParser, HttpStreamParser,
    ParsedMessage, StreamManager, TcpFlags, TlsStreamParser,
};
use pcapsql_core::{FieldValue, KeyLog, ParseResult};

use crate::error::{Error, QueryError};
use crate::query::providers::TableData;

/// Feeds reassembly from parsed packet layers and builds the stream tables.
pub struct StreamSubscriber {
    /// Stream manager for TCP reassembly and protocol parsing.
    manager: StreamManager,
    /// Every message the stream parsers produced, in capture order.
    messages: Vec<ParsedMessage>,
    /// Stream tables requested by the query.
    wanted: HashSet<String>,
}

impl StreamSubscriber {
    /// Create a subscriber producing `wanted` tables, decrypting TLS with
    /// `keylog` when given.
    pub fn new(wanted: HashSet<String>, keylog: Option<Arc<KeyLog>>) -> Self {
        // `with_keylog()` registers the decrypting TLS parser first, so it wins
        // the port-443 match; the plain TLS parser (handshake metadata only)
        // is the fallback without a keylog. Registration order is lookup
        // order.
        let mut manager = match keylog {
            Some(kl) => StreamManager::with_defaults().with_keylog((*kl).clone()),
            None => StreamManager::with_defaults(),
        };
        let registry = manager.registry_mut();
        registry.register(TlsStreamParser::new());
        registry.register(HttpStreamParser::new());
        // HTTP/2 is found as the child of a decrypted TLS stream (ALPN h2).
        registry.register(Http2StreamParser::new());

        Self {
            manager,
            messages: Vec::new(),
            wanted,
        }
    }

    /// Observe one packet with its parsed layers. The innermost IP + TCP
    /// pair (so tunnelled TCP is attributed to the inner flow) is fed to
    /// reassembly; packets without TCP are ignored.
    pub fn observe(
        &mut self,
        packet: &PacketRef<'_>,
        parsed: &[(&'static str, ParseResult<'_>)],
    ) -> Result<(), Error> {
        let Some(segment) = TcpSegment::from_layers(parsed) else {
            return Ok(());
        };
        let messages = self
            .manager
            .process_segment(
                segment.src_ip,
                segment.dst_ip,
                segment.src_port,
                segment.dst_port,
                segment.seq,
                segment.ack,
                segment.flags,
                segment.payload,
                packet.frame_number,
                // The stream manager keeps microseconds.
                packet.timestamp_ns / 1_000,
            )
            .map_err(|e| {
                Error::Query(QueryError::Execution(format!(
                    "Stream processing error: {e}"
                )))
            })?;
        self.messages.extend(messages);
        Ok(())
    }

    /// Build the requested stream tables from the whole pass.
    pub fn finish(self, batch_size: usize) -> Result<HashMap<String, TableData>, Error> {
        let mut out = HashMap::new();
        for name in &self.wanted {
            let schema =
                Arc::new(crate::query::tables::get_table_schema(name).ok_or_else(|| {
                    Error::Query(QueryError::Execution(format!("Unknown table: {name}")))
                })?);
            let batches = match name.as_str() {
                "http2" => chunked(
                    &schema,
                    batch_size,
                    self.http2_messages(),
                    build_http2_batch,
                )?,
                "http_messages" => chunked(
                    &schema,
                    batch_size,
                    self.http_messages(),
                    build_http_messages_batch,
                )?,
                "tcp_connections" => chunked(
                    &schema,
                    batch_size,
                    self.connections(),
                    build_tcp_connections_batch,
                )?,
                "tls_sessions" => chunked(
                    &schema,
                    batch_size,
                    self.tls_sessions(),
                    build_tls_sessions_batch,
                )?,
                other => {
                    return Err(Error::Query(QueryError::Execution(format!(
                        "{other} is not a stream table"
                    ))))
                }
            };
            out.insert(
                name.clone(),
                TableData {
                    schema,
                    partitions: vec![batches],
                },
            );
        }
        Ok(out)
    }

    fn http2_messages(&self) -> Vec<&ParsedMessage> {
        self.messages
            .iter()
            .filter(|m| m.protocol == "http2")
            .collect()
    }

    fn http_messages(&self) -> Vec<&ParsedMessage> {
        self.messages
            .iter()
            .filter(|m| m.protocol == "http")
            .collect()
    }

    /// Connections in capture order (by first frame), the table's declared
    /// `frame_number` ordering.
    fn connections(&self) -> Vec<&Connection> {
        let mut conns: Vec<&Connection> = self.manager.connections().collect();
        conns.sort_by_key(|c| (c.first_frame, c.id));
        conns
    }

    /// One session per connection that carried a TLS handshake, folded from
    /// that connection's TLS records; ordered by ClientHello frame.
    fn tls_sessions(&self) -> Vec<TlsSession> {
        let mut by_conn: HashMap<u64, TlsSession> = HashMap::new();
        for msg in self.messages.iter().filter(|m| m.protocol == "tls") {
            let s = by_conn.entry(msg.connection_id).or_insert(TlsSession {
                connection_id: msg.connection_id,
                ..Default::default()
            });
            match get_str(&msg.fields, "handshake_type") {
                Some("ClientHello") => {
                    s.frame_number = s.frame_number.min_nonzero(msg.frame_number);
                    s.sni = get_str(&msg.fields, "sni").map(str::to_owned);
                    s.alpn = get_str(&msg.fields, "alpn").map(str::to_owned);
                    s.client_version = get_u16(&msg.fields, "client_version");
                }
                Some("ServerHello") => {
                    s.server_hello_frame.get_or_insert(msg.frame_number);
                    // TLS 1.3 negotiates the real version in supported_versions;
                    // the legacy field says 1.2.
                    s.server_version = get_u16(&msg.fields, "selected_version")
                        .or_else(|| get_u16(&msg.fields, "server_version"));
                    s.cipher_suite_id = get_u16(&msg.fields, "cipher_suite");
                    s.cipher_suite = s.cipher_suite_id.map(cipher_suite_name);
                }
                _ => {}
            }
            // The decrypting parser reports the Finished message it could read.
            if msg.fields.contains_key("hs_finished") {
                s.is_decrypted = true;
            }
            if s.frame_number == 0 {
                s.frame_number = msg.frame_number;
            }
        }
        let mut sessions: Vec<TlsSession> = by_conn.into_values().collect();
        sessions.sort_by_key(|s| (s.frame_number, s.connection_id));
        sessions
    }
}

/// Split `rows` into batches of `batch_size` with `build`; an empty table is
/// one empty batch so the schema is advertised either way.
fn chunked<T>(
    schema: &Arc<Schema>,
    batch_size: usize,
    rows: Vec<T>,
    build: fn(&Arc<Schema>, &[T]) -> Result<RecordBatch, Error>,
) -> Result<Vec<RecordBatch>, Error> {
    if rows.is_empty() {
        return Ok(vec![build(schema, &[])?]);
    }
    rows.chunks(batch_size.max(1))
        .map(|chunk| build(schema, chunk))
        .collect()
}

/// The TCP segment a packet carries, read from its parsed layers.
struct TcpSegment<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    fn from_layers(parsed: &[(&'static str, ParseResult<'a>)]) -> Option<Self> {
        let mut ips: Option<(IpAddr, IpAddr)> = None;
        let mut segment = None;
        for (name, result) in parsed {
            match *name {
                "ipv4" | "ipv6" => {
                    if let (Some(FieldValue::IpAddr(s)), Some(FieldValue::IpAddr(d))) =
                        (result.get("src_ip"), result.get("dst_ip"))
                    {
                        ips = Some((*s, *d));
                    }
                }
                "tcp" => {
                    let Some((src_ip, dst_ip)) = ips else {
                        continue;
                    };
                    // A truncated TCP header lacks fields: skip this layer and
                    // keep whatever outer segment was already found.
                    let (Some(src_port), Some(dst_port), Some(seq), Some(ack)) = (
                        get_u16_field(result, "src_port"),
                        get_u16_field(result, "dst_port"),
                        get_u32_field(result, "seq"),
                        get_u32_field(result, "ack"),
                    ) else {
                        continue;
                    };
                    let flag = |f: &str| matches!(result.get(f), Some(FieldValue::Bool(true)));
                    segment = Some(TcpSegment {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        seq,
                        ack,
                        flags: TcpFlags {
                            fin: flag("flag_fin"),
                            syn: flag("flag_syn"),
                            rst: flag("flag_rst"),
                            ack: flag("flag_ack"),
                        },
                        payload: result.remaining,
                    });
                }
                _ => {}
            }
        }
        segment
    }
}

fn get_u16_field(result: &ParseResult<'_>, name: &str) -> Option<u16> {
    match result.get(name) {
        Some(FieldValue::UInt16(v)) => Some(*v),
        _ => None,
    }
}

fn get_u32_field(result: &ParseResult<'_>, name: &str) -> Option<u32> {
    match result.get(name) {
        Some(FieldValue::UInt32(v)) => Some(*v),
        _ => None,
    }
}

/// Per-connection TLS handshake summary.
#[derive(Default)]
struct TlsSession {
    connection_id: u64,
    frame_number: u64,
    server_hello_frame: Option<u64>,
    client_version: Option<u16>,
    server_version: Option<u16>,
    cipher_suite_id: Option<u16>,
    cipher_suite: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
    is_decrypted: bool,
}

trait MinNonZero {
    fn min_nonzero(self, other: u64) -> u64;
}

impl MinNonZero for u64 {
    fn min_nonzero(self, other: u64) -> u64 {
        if self == 0 {
            other
        } else {
            self.min(other)
        }
    }
}

fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Encapsulation columns every table carries: stream rows are not
/// attributed to a tunnel, so depth 0 / no tunnel.
fn push_encap_columns(columns: &mut Vec<ArrayRef>, rows: usize) {
    columns.push(Arc::new(UInt8Array::from(vec![0u8; rows])));
    columns.push(new_null_array(&DataType::Utf8, rows));
    columns.push(new_null_array(&DataType::UInt64, rows));
}

fn to_batch(schema: &Arc<Schema>, columns: Vec<ArrayRef>) -> Result<RecordBatch, Error> {
    RecordBatch::try_new(schema.clone(), columns)
        .map_err(|e| Error::Query(QueryError::Execution(format!("Failed to build batch: {e}"))))
}

fn build_tcp_connections_batch(
    schema: &Arc<Schema>,
    conns: &[&Connection],
) -> Result<RecordBatch, Error> {
    let n = conns.len();
    let mut frame_number = UInt64Builder::with_capacity(n);
    let mut connection_id = UInt64Builder::with_capacity(n);
    let mut client_ip = StringBuilder::new();
    let mut server_ip = StringBuilder::new();
    let mut client_port = UInt16Builder::with_capacity(n);
    let mut server_port = UInt16Builder::with_capacity(n);
    let mut state = StringBuilder::new();
    let mut start_time = TimestampMicrosecondBuilder::with_capacity(n);
    let mut end_time = TimestampMicrosecondBuilder::with_capacity(n);
    let mut duration_us = arrow::array::Int64Builder::with_capacity(n);
    let mut first_frame = UInt64Builder::with_capacity(n);
    let mut last_frame = UInt64Builder::with_capacity(n);
    let mut packets_to_server = UInt32Builder::with_capacity(n);
    let mut packets_to_client = UInt32Builder::with_capacity(n);
    let mut bytes_to_server = UInt64Builder::with_capacity(n);
    let mut bytes_to_client = UInt64Builder::with_capacity(n);
    let mut is_complete = BooleanBuilder::with_capacity(n);

    for conn in conns {
        frame_number.append_value(conn.first_frame);
        connection_id.append_value(conn.id);
        client_ip.append_value(conn.client_ip().to_string());
        server_ip.append_value(conn.server_ip().to_string());
        client_port.append_value(conn.client_port());
        server_port.append_value(conn.server_port());
        state.append_value(conn.state.as_str());
        start_time.append_value(conn.start_time);
        // A connection that reached a terminal state ended at its last
        // activity (the FIN/ACK or RST); an open one has no end yet.
        let complete = matches!(
            conn.state,
            ConnectionState::Closed | ConnectionState::TimeWait | ConnectionState::Reset
        );
        match conn.end_time.or(complete.then_some(conn.last_activity)) {
            Some(end) => {
                end_time.append_value(end);
                duration_us.append_value(end - conn.start_time);
            }
            None => {
                end_time.append_null();
                duration_us.append_null();
            }
        }
        first_frame.append_value(conn.first_frame);
        last_frame.append_value(conn.last_frame);
        packets_to_server.append_value(conn.packets_to_server);
        packets_to_client.append_value(conn.packets_to_client);
        bytes_to_server.append_value(conn.bytes_to_server);
        bytes_to_client.append_value(conn.bytes_to_client);
        is_complete.append_value(complete);
    }

    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(frame_number.finish()),
        Arc::new(connection_id.finish()),
        Arc::new(client_ip.finish()),
        Arc::new(server_ip.finish()),
        Arc::new(client_port.finish()),
        Arc::new(server_port.finish()),
        Arc::new(state.finish()),
        Arc::new(start_time.finish()),
        Arc::new(end_time.finish()),
        Arc::new(duration_us.finish()),
        Arc::new(first_frame.finish()),
        Arc::new(last_frame.finish()),
        Arc::new(packets_to_server.finish()),
        Arc::new(packets_to_client.finish()),
        Arc::new(bytes_to_server.finish()),
        Arc::new(bytes_to_client.finish()),
        Arc::new(is_complete.finish()),
    ];
    push_encap_columns(&mut columns, n);
    to_batch(schema, columns)
}

fn build_tls_sessions_batch(
    schema: &Arc<Schema>,
    sessions: &[TlsSession],
) -> Result<RecordBatch, Error> {
    let n = sessions.len();
    let mut frame_number = UInt64Builder::with_capacity(n);
    let mut connection_id = UInt64Builder::with_capacity(n);
    let mut version = StringBuilder::new();
    let mut cipher_suite = StringBuilder::new();
    let mut cipher_suite_id = UInt16Builder::with_capacity(n);
    let mut sni = StringBuilder::new();
    let mut alpn = StringBuilder::new();
    let mut is_decrypted = BooleanBuilder::with_capacity(n);
    let mut server_hello_frame = UInt64Builder::with_capacity(n);

    for s in sessions {
        frame_number.append_value(s.frame_number);
        connection_id.append_value(s.connection_id);
        version.append_option(s.server_version.or(s.client_version).map(tls_version_name));
        cipher_suite.append_option(s.cipher_suite.as_deref());
        cipher_suite_id.append_option(s.cipher_suite_id);
        sni.append_option(s.sni.as_deref());
        alpn.append_option(s.alpn.as_deref());
        is_decrypted.append_value(s.is_decrypted);
        server_hello_frame.append_option(s.server_hello_frame);
    }

    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(frame_number.finish()),
        Arc::new(connection_id.finish()),
        Arc::new(version.finish()),
        Arc::new(cipher_suite.finish()),
        Arc::new(cipher_suite_id.finish()),
        Arc::new(sni.finish()),
        Arc::new(alpn.finish()),
        Arc::new(is_decrypted.finish()),
        Arc::new(server_hello_frame.finish()),
    ];
    push_encap_columns(&mut columns, n);
    to_batch(schema, columns)
}

fn build_http_messages_batch(
    schema: &Arc<Schema>,
    messages: &[&ParsedMessage],
) -> Result<RecordBatch, Error> {
    let n = messages.len();
    let mut frame_number = UInt64Builder::with_capacity(n);
    let mut connection_id = UInt64Builder::with_capacity(n);
    let mut message_id = UInt32Builder::with_capacity(n);
    let mut direction = StringBuilder::new();
    let mut is_request = BooleanBuilder::with_capacity(n);
    let mut method = StringBuilder::new();
    let mut uri = StringBuilder::new();
    let mut http_version = StringBuilder::new();
    let mut status_code = UInt16Builder::with_capacity(n);
    let mut host = StringBuilder::new();
    let mut content_type = StringBuilder::new();
    let mut content_length = UInt64Builder::with_capacity(n);
    let mut user_agent = StringBuilder::new();
    let mut server = StringBuilder::new();

    for msg in messages {
        frame_number.append_value(msg.frame_number);
        connection_id.append_value(msg.connection_id);
        message_id.append_value(msg.message_id);
        direction.append_value(msg.direction.as_str());
        is_request.append_option(get_bool(&msg.fields, "is_request"));
        method.append_option(get_str(&msg.fields, "method"));
        uri.append_option(get_str(&msg.fields, "uri"));
        http_version.append_option(get_str(&msg.fields, "http_version"));
        status_code.append_option(get_u16(&msg.fields, "status_code"));
        host.append_option(get_str(&msg.fields, "host"));
        content_type.append_option(get_str(&msg.fields, "content_type"));
        content_length.append_option(get_u64(&msg.fields, "content_length"));
        user_agent.append_option(get_str(&msg.fields, "user_agent"));
        server.append_option(get_str(&msg.fields, "server"));
    }

    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(frame_number.finish()),
        Arc::new(connection_id.finish()),
        Arc::new(message_id.finish()),
        Arc::new(direction.finish()),
        Arc::new(is_request.finish()),
        Arc::new(method.finish()),
        Arc::new(uri.finish()),
        Arc::new(http_version.finish()),
        Arc::new(status_code.finish()),
        Arc::new(host.finish()),
        Arc::new(content_type.finish()),
        Arc::new(content_length.finish()),
        Arc::new(user_agent.finish()),
        Arc::new(server.finish()),
    ];
    push_encap_columns(&mut columns, n);
    to_batch(schema, columns)
}

/// Build an Arrow RecordBatch from HTTP/2 messages, against the registered
/// `http2` table schema (encapsulation columns included) so the batches are
/// exactly what the table provider advertises.
fn build_http2_batch(
    schema: &Arc<Schema>,
    messages: &[&ParsedMessage],
) -> Result<RecordBatch, Error> {
    let mut frame_number = UInt64Builder::new();
    let mut connection_id = UInt64Builder::new();
    let mut frame_type = StringBuilder::new();
    let mut stream_id = UInt32Builder::new();
    let mut flags = UInt8Builder::new();
    let mut length = UInt32Builder::new();
    let mut method = StringBuilder::new();
    let mut path = StringBuilder::new();
    let mut authority = StringBuilder::new();
    let mut scheme = StringBuilder::new();
    let mut status = UInt16Builder::new();
    let mut content_type = StringBuilder::new();
    let mut content_length = UInt64Builder::new();
    let mut user_agent = StringBuilder::new();
    let mut data_length = UInt64Builder::new();
    let mut end_stream = BooleanBuilder::new();
    let mut end_headers = BooleanBuilder::new();
    let mut padding_length = UInt8Builder::new();
    let mut ack = BooleanBuilder::new();
    let mut header_table_size = UInt32Builder::new();
    let mut max_concurrent_streams = UInt32Builder::new();
    let mut initial_window_size = UInt32Builder::new();
    let mut max_frame_size = UInt32Builder::new();
    let mut error_code = UInt32Builder::new();
    let mut error_name = StringBuilder::new();
    let mut last_stream_id = UInt32Builder::new();
    let mut window_increment = UInt32Builder::new();
    let mut priority_exclusive = BooleanBuilder::new();
    let mut priority_dependency = UInt32Builder::new();
    let mut priority_weight = UInt8Builder::new();
    let mut promised_stream_id = UInt32Builder::new();

    for msg in messages {
        frame_number.append_value(msg.frame_number);
        connection_id.append_option(get_u64(&msg.fields, "connection_id"));
        frame_type.append_option(get_str(&msg.fields, "frame_type"));
        stream_id.append_option(get_u32(&msg.fields, "stream_id"));
        flags.append_option(get_u8(&msg.fields, "flags"));
        length.append_option(get_u32(&msg.fields, "length"));
        method.append_option(get_str(&msg.fields, "method"));
        path.append_option(get_str(&msg.fields, "path"));
        authority.append_option(get_str(&msg.fields, "authority"));
        scheme.append_option(get_str(&msg.fields, "scheme"));
        status.append_option(get_u16(&msg.fields, "status"));
        content_type.append_option(get_str(&msg.fields, "content_type"));
        content_length.append_option(get_u64(&msg.fields, "content_length"));
        user_agent.append_option(get_str(&msg.fields, "user_agent"));
        data_length.append_option(get_u64(&msg.fields, "data_length"));
        end_stream.append_option(get_bool(&msg.fields, "end_stream"));
        end_headers.append_option(get_bool(&msg.fields, "end_headers"));
        padding_length.append_option(get_u8(&msg.fields, "padding_length"));
        ack.append_option(get_bool(&msg.fields, "ack"));
        header_table_size.append_option(get_u32(&msg.fields, "header_table_size"));
        max_concurrent_streams.append_option(get_u32(&msg.fields, "max_concurrent_streams"));
        initial_window_size.append_option(get_u32(&msg.fields, "initial_window_size"));
        max_frame_size.append_option(get_u32(&msg.fields, "max_frame_size"));
        error_code.append_option(get_u32(&msg.fields, "error_code"));
        error_name.append_option(get_str(&msg.fields, "error_name"));
        last_stream_id.append_option(get_u32(&msg.fields, "last_stream_id"));
        window_increment.append_option(get_u32(&msg.fields, "window_increment"));
        priority_exclusive.append_option(get_bool(&msg.fields, "priority_exclusive"));
        priority_dependency.append_option(get_u32(&msg.fields, "priority_dependency"));
        priority_weight.append_option(get_u8(&msg.fields, "priority_weight"));
        promised_stream_id.append_option(get_u32(&msg.fields, "promised_stream_id"));
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(frame_number.finish()),
        Arc::new(connection_id.finish()),
        Arc::new(frame_type.finish()),
        Arc::new(stream_id.finish()),
        Arc::new(flags.finish()),
        Arc::new(length.finish()),
        Arc::new(method.finish()),
        Arc::new(path.finish()),
        Arc::new(authority.finish()),
        Arc::new(scheme.finish()),
        Arc::new(status.finish()),
        Arc::new(content_type.finish()),
        Arc::new(content_length.finish()),
        Arc::new(user_agent.finish()),
        Arc::new(data_length.finish()),
        Arc::new(end_stream.finish()),
        Arc::new(end_headers.finish()),
        Arc::new(padding_length.finish()),
        Arc::new(ack.finish()),
        Arc::new(header_table_size.finish()),
        Arc::new(max_concurrent_streams.finish()),
        Arc::new(initial_window_size.finish()),
        Arc::new(max_frame_size.finish()),
        Arc::new(error_code.finish()),
        Arc::new(error_name.finish()),
        Arc::new(last_stream_id.finish()),
        Arc::new(window_increment.finish()),
        Arc::new(priority_exclusive.finish()),
        Arc::new(priority_dependency.finish()),
        Arc::new(priority_weight.finish()),
        Arc::new(promised_stream_id.finish()),
    ];
    let mut columns = columns;
    push_encap_columns(&mut columns, messages.len());
    to_batch(schema, columns)
}

// Helper functions to extract values from FieldValue
fn get_str<'a>(fields: &'a HashMap<&'static str, FieldValue>, key: &str) -> Option<&'a str> {
    match fields.get(key) {
        Some(FieldValue::Str(s)) => Some(s),
        Some(FieldValue::OwnedString(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn get_u64(fields: &HashMap<&'static str, FieldValue>, key: &str) -> Option<u64> {
    match fields.get(key) {
        Some(FieldValue::UInt64(v)) => Some(*v),
        _ => None,
    }
}

fn get_u32(fields: &HashMap<&'static str, FieldValue>, key: &str) -> Option<u32> {
    match fields.get(key) {
        Some(FieldValue::UInt32(v)) => Some(*v),
        _ => None,
    }
}

fn get_u16(fields: &HashMap<&'static str, FieldValue>, key: &str) -> Option<u16> {
    match fields.get(key) {
        Some(FieldValue::UInt16(v)) => Some(*v),
        _ => None,
    }
}

fn get_u8(fields: &HashMap<&'static str, FieldValue>, key: &str) -> Option<u8> {
    match fields.get(key) {
        Some(FieldValue::UInt8(v)) => Some(*v),
        _ => None,
    }
}

fn get_bool(fields: &HashMap<&'static str, FieldValue>, key: &str) -> Option<bool> {
    match fields.get(key) {
        Some(FieldValue::Bool(v)) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::tables::{get_table_schema, STREAM_TABLES};

    /// Every stream table's builder must produce exactly the registered
    /// schema, or `SELECT *` fails as soon as a capture has rows.
    #[test]
    fn stream_table_batches_match_registered_schemas() {
        for name in STREAM_TABLES {
            let schema = Arc::new(get_table_schema(name).expect("registered"));
            let batch = match *name {
                "http2" => build_http2_batch(&schema, &[]),
                "http_messages" => build_http_messages_batch(&schema, &[]),
                "tcp_connections" => build_tcp_connections_batch(&schema, &[]),
                "tls_sessions" => build_tls_sessions_batch(&schema, &[]),
                other => panic!("no builder for {other}"),
            }
            .expect("empty batch builds");
            assert_eq!(batch.schema().as_ref(), schema.as_ref(), "{name}");
        }
    }

    #[test]
    fn finish_emits_one_empty_batch_per_wanted_table() {
        let wanted: HashSet<String> = STREAM_TABLES.iter().map(|s| s.to_string()).collect();
        let tables = StreamSubscriber::new(wanted.clone(), None)
            .finish(1000)
            .unwrap();
        assert_eq!(tables.len(), wanted.len());
        for (name, data) in &tables {
            assert_eq!(data.partitions.len(), 1, "{name}");
            assert_eq!(data.total_rows(), 0, "{name}");
            assert_eq!(
                data.schema.as_ref(),
                &get_table_schema(name).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn finish_rejects_a_packet_table() {
        let wanted: HashSet<String> = ["tcp".to_string()].into_iter().collect();
        assert!(StreamSubscriber::new(wanted, None).finish(10).is_err());
    }
}
