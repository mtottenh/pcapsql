//! Stream tables: the rows derived from reassembled TCP streams.
//!
//! **Unstable API** (see the [module](super) documentation).
//!
//! A [stream table](super::TableKind::Stream) is not built per packet. The
//! scan feeds the TCP segment of every frame to a [`StreamManager`]
//! (connection tracking and reassembly, then the TLS, HTTP/1.x and HTTP/2
//! stream parsers; with a key log, TLS is decrypted and HTTP/2 found
//! inside it), and the tables are what that analysis holds when the
//! capture ends:
//!
//! | Table | One row per |
//! |---|---|
//! | `tcp_connections` | connection the manager tracked, by first frame |
//! | `tls_sessions` | connection that carried a TLS handshake, by ClientHello frame |
//! | `http_messages` | HTTP/1.x message of a reassembled stream, in capture order |
//! | `http2` | HTTP/2 frame of a decrypted TLS stream, in capture order |
//!
//! Three steps, each with its type:
//!
//! 1. [`StreamAnalysis`] sees every frame of the partition once
//!    ([`observe`](StreamAnalysis::observe)). It reads the frame's already
//!    parsed layers: there is no second read of the capture.
//! 2. At the end of the partition it becomes the [`StreamTables`]: the rows
//!    of the tables the plan asked for, in table order.
//! 3. A [`StreamWriter`] writes those rows to the outputs' sinks, as many
//!    as fit, and is resumed where it stopped.
//!
//! What each cell holds is decided here, once for every frontend, and
//! written through [`write_value`] like every other cell. Which value a
//! column gets is resolved when the plan is compiled ([`StreamPlan`]), from
//! the column's name in the catalogue.
//!
//! Reassembly needs the capture in order from its first packet, so a scan
//! with a stream table is one partition
//! ([`CompiledScan::requires_single_partition`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::ControlFlow;

use super::catalog::ColKind;
use super::plan::{CompiledScan, OutCol, OutColumn, OutputId};
use super::route::Router;
use super::row::write_value;
use super::sink::{Full, RowSink};
use crate::format::tls_version_name;
use crate::io::PacketRef;
use crate::stream::{
    cipher_suite_name, Connection, ConnectionState, Http2StreamParser, HttpStreamParser,
    OwnedFieldValue, ParsedMessage, StreamManager, TcpFlags, TlsStreamParser,
};
use crate::{Error, FieldValue, KeyLog, LayerRef, PacketLayers};

/// The stream tables this module builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamTable {
    TcpConnections,
    TlsSessions,
    HttpMessages,
    Http2,
}

impl StreamTable {
    /// The table of this name, if stream analysis builds it.
    pub(crate) fn named(name: &str) -> Option<Self> {
        match name {
            "tcp_connections" => Some(Self::TcpConnections),
            "tls_sessions" => Some(Self::TlsSessions),
            "http_messages" => Some(Self::HttpMessages),
            "http2" => Some(Self::Http2),
            _ => None,
        }
    }

    /// The name of the stream parser whose messages are the table's rows.
    fn protocol(self) -> Option<&'static str> {
        match self {
            Self::HttpMessages => Some("http"),
            Self::Http2 => Some("http2"),
            Self::TcpConnections | Self::TlsSessions => None,
        }
    }

    /// What the column `name` of this table holds; `None` for a column the
    /// table does not have.
    fn cell(self, name: &'static str) -> Option<Cell> {
        // Reassembly follows the innermost TCP flow and attributes no row
        // to a tunnel: depth 0, no tunnel.
        match name {
            "encap_depth" => return Some(Cell::EncapDepth),
            "tunnel_type" | "tunnel_id" => return Some(Cell::Null),
            _ => {}
        }
        let cell = match self {
            Self::TcpConnections => Cell::Connection(match name {
                "frame_number" | "first_frame" => ConnectionCell::FirstFrame,
                "connection_id" => ConnectionCell::Id,
                "client_ip" => ConnectionCell::ClientIp,
                "server_ip" => ConnectionCell::ServerIp,
                "client_port" => ConnectionCell::ClientPort,
                "server_port" => ConnectionCell::ServerPort,
                "state" => ConnectionCell::State,
                "start_time" => ConnectionCell::StartTime,
                "end_time" => ConnectionCell::EndTime,
                "duration_us" => ConnectionCell::DurationUs,
                "last_frame" => ConnectionCell::LastFrame,
                "packets_to_server" => ConnectionCell::PacketsToServer,
                "packets_to_client" => ConnectionCell::PacketsToClient,
                "bytes_to_server" => ConnectionCell::BytesToServer,
                "bytes_to_client" => ConnectionCell::BytesToClient,
                "is_complete" => ConnectionCell::IsComplete,
                _ => return None,
            }),
            Self::TlsSessions => Cell::Session(match name {
                "frame_number" => SessionCell::FrameNumber,
                "connection_id" => SessionCell::ConnectionId,
                "version" => SessionCell::Version,
                "cipher_suite" => SessionCell::CipherSuite,
                "cipher_suite_id" => SessionCell::CipherSuiteId,
                "sni" => SessionCell::Sni,
                "alpn" => SessionCell::Alpn,
                "is_decrypted" => SessionCell::IsDecrypted,
                "server_hello_frame" => SessionCell::ServerHelloFrame,
                _ => return None,
            }),
            Self::HttpMessages => Cell::Message(match name {
                "frame_number" => MessageCell::FrameNumber,
                "connection_id" => MessageCell::ConnectionId,
                "message_id" => MessageCell::MessageId,
                "direction" => MessageCell::Direction,
                // Every other column is the message field of its name.
                field => MessageCell::Field(field),
            }),
            Self::Http2 => Cell::Message(match name {
                "frame_number" => MessageCell::FrameNumber,
                // The TCP connection that carried the TLS stream the frame
                // was decrypted from: `tcp_connections.connection_id`.
                "connection_id" => MessageCell::ConnectionId,
                field => MessageCell::Field(field),
            }),
        };
        Some(cell)
    }
}

/// What one output column of a stream table holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cell {
    /// `encap_depth`: always 0.
    EncapDepth,
    /// `tunnel_type`, `tunnel_id`: always NULL.
    Null,
    Connection(ConnectionCell),
    Session(SessionCell),
    Message(MessageCell),
}

/// A column of `tcp_connections`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionCell {
    FirstFrame,
    Id,
    ClientIp,
    ServerIp,
    ClientPort,
    ServerPort,
    State,
    StartTime,
    EndTime,
    DurationUs,
    LastFrame,
    PacketsToServer,
    PacketsToClient,
    BytesToServer,
    BytesToClient,
    IsComplete,
}

/// A column of `tls_sessions`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionCell {
    FrameNumber,
    ConnectionId,
    Version,
    CipherSuite,
    CipherSuiteId,
    Sni,
    Alpn,
    IsDecrypted,
    ServerHelloFrame,
}

/// A column of a table of parsed messages (`http_messages`, `http2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageCell {
    FrameNumber,
    ConnectionId,
    MessageId,
    Direction,
    /// The message's field of this name; NULL in a message without it.
    Field(&'static str),
}

/// A stream output resolved for the writer: its table and, per output
/// column, what the column holds.
#[derive(Clone, Debug)]
pub(crate) struct StreamPlan {
    table: StreamTable,
    cells: Box<[Cell]>,
}

impl StreamPlan {
    /// Resolve the output `columns` of `table`. `Err` is the index of the
    /// first column the table's rows have no value for.
    pub(crate) fn resolve(table: StreamTable, columns: &[OutColumn]) -> Result<Self, usize> {
        let cells = columns
            .iter()
            .enumerate()
            .map(|(index, column)| table.cell(column.name).ok_or(index))
            .collect::<Result<_, _>>()?;
        Ok(Self { table, cells })
    }
}

/// Reassembles the TCP streams of a partition and parses what they carry.
pub(crate) struct StreamAnalysis {
    manager: StreamManager,
    /// Every message the stream parsers produced, in capture order.
    messages: Vec<ParsedMessage>,
}

impl StreamAnalysis {
    /// An analysis that decrypts TLS with `keylog` when given.
    pub(crate) fn new(keylog: Option<&KeyLog>) -> Self {
        // `with_keylog()` registers the decrypting TLS parser first, so it
        // wins the port-443 match; the plain TLS parser (handshake metadata
        // only) is the fallback without a keylog. Registration order is
        // lookup order.
        let mut manager = match keylog {
            Some(keylog) => StreamManager::with_defaults().with_keylog(keylog.clone()),
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
        }
    }

    /// One frame with its parsed layers. The innermost IP + TCP pair (so
    /// tunnelled TCP is attributed to the inner flow) is fed to reassembly;
    /// a frame without TCP is ignored.
    pub(crate) fn observe(
        &mut self,
        packet: &PacketRef<'_>,
        layers: &PacketLayers<'_, '_>,
    ) -> Result<(), Error> {
        let Some(segment) = TcpSegment::from_layers(layers) else {
            return Ok(());
        };
        let messages = self.manager.process_segment(
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
        )?;
        self.messages.extend(messages);
        Ok(())
    }

    /// The rows of the stream tables `plan` has outputs for.
    pub(crate) fn finish(self, plan: &CompiledScan) -> StreamTables {
        let wanted = |table| {
            plan.outputs()
                .iter()
                .any(|output| output.stream().is_some_and(|s| s.table == table))
        };
        let mut connections = Vec::new();
        if wanted(StreamTable::TcpConnections) {
            connections.extend(self.manager.connections().cloned());
            // Capture order: by first frame.
            connections.sort_by_key(|c| (c.first_frame, c.id));
        }
        let sessions = if wanted(StreamTable::TlsSessions) {
            tls_sessions(&self.messages)
        } else {
            Vec::new()
        };
        let of = |table: StreamTable| -> Vec<usize> {
            match table.protocol() {
                Some(protocol) if wanted(table) => (0..self.messages.len())
                    .filter(|&i| self.messages[i].protocol == protocol)
                    .collect(),
                _ => Vec::new(),
            }
        };
        let http = of(StreamTable::HttpMessages);
        let http2 = of(StreamTable::Http2);
        StreamTables {
            connections,
            sessions,
            http,
            http2,
            messages: self.messages,
        }
    }
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
    fn from_layers(layers: &PacketLayers<'_, 'a>) -> Option<Self> {
        let mut ips: Option<(IpAddr, IpAddr)> = None;
        let mut segment = None;
        for layer in layers.iter() {
            match layer.name() {
                "ipv4" | "ipv6" => {
                    if let (Some(FieldValue::IpAddr(src)), Some(FieldValue::IpAddr(dst))) =
                        (layer.get("src_ip"), layer.get("dst_ip"))
                    {
                        ips = Some((*src, *dst));
                    }
                }
                "tcp" => {
                    let Some((src_ip, dst_ip)) = ips else {
                        continue;
                    };
                    // A truncated TCP header lacks fields: skip this layer
                    // and keep whatever outer segment was already found.
                    let (Some(src_port), Some(dst_port), Some(seq), Some(ack)) = (
                        u16_field(layer, "src_port"),
                        u16_field(layer, "dst_port"),
                        u32_field(layer, "seq"),
                        u32_field(layer, "ack"),
                    ) else {
                        continue;
                    };
                    let flag = |name: &str| matches!(layer.get(name), Some(FieldValue::Bool(true)));
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
                        payload: layer.payload(),
                    });
                }
                _ => {}
            }
        }
        segment
    }
}

fn u16_field(layer: LayerRef<'_, '_>, name: &str) -> Option<u16> {
    match layer.get(name) {
        Some(FieldValue::UInt16(v)) => Some(*v),
        _ => None,
    }
}

fn u32_field(layer: LayerRef<'_, '_>, name: &str) -> Option<u32> {
    match layer.get(name) {
        Some(FieldValue::UInt32(v)) => Some(*v),
        _ => None,
    }
}

/// The TLS handshake of one connection: a row of `tls_sessions`.
#[derive(Default)]
struct TlsSession {
    connection_id: u64,
    /// The ClientHello's frame; the first TLS record's when there is none.
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

/// One session per connection that carried a TLS handshake, folded from that
/// connection's TLS records; ordered by ClientHello frame.
fn tls_sessions(messages: &[ParsedMessage]) -> Vec<TlsSession> {
    let text = |message: &ParsedMessage, field: &str| {
        message
            .fields
            .get(field)
            .and_then(OwnedFieldValue::as_str)
            .map(str::to_owned)
    };
    let number = |message: &ParsedMessage, field: &str| match message.fields.get(field) {
        Some(OwnedFieldValue::UInt16(v)) => Some(*v),
        _ => None,
    };
    let mut by_connection: HashMap<u64, TlsSession> = HashMap::new();
    for message in messages.iter().filter(|m| m.protocol == "tls") {
        let session = by_connection
            .entry(message.connection_id)
            .or_insert(TlsSession {
                connection_id: message.connection_id,
                ..Default::default()
            });
        let handshake = message
            .fields
            .get("handshake_type")
            .and_then(OwnedFieldValue::as_str);
        match handshake {
            Some("ClientHello") => {
                session.frame_number = match session.frame_number {
                    0 => message.frame_number,
                    earlier => earlier.min(message.frame_number),
                };
                session.sni = text(message, "sni");
                session.alpn = text(message, "alpn");
                session.client_version = number(message, "client_version");
            }
            Some("ServerHello") => {
                session
                    .server_hello_frame
                    .get_or_insert(message.frame_number);
                // TLS 1.3 negotiates the real version in supported_versions;
                // the legacy field says 1.2.
                session.server_version = number(message, "selected_version")
                    .or_else(|| number(message, "server_version"));
                session.cipher_suite_id = number(message, "cipher_suite");
                session.cipher_suite = session.cipher_suite_id.map(cipher_suite_name);
            }
            _ => {}
        }
        // The decrypting parser reports the Finished message it could read.
        if message.fields.contains_key("hs_finished") {
            session.is_decrypted = true;
        }
        if session.frame_number == 0 {
            session.frame_number = message.frame_number;
        }
    }
    let mut sessions: Vec<TlsSession> = by_connection.into_values().collect();
    sessions.sort_by_key(|s| (s.frame_number, s.connection_id));
    sessions
}

/// The rows of a partition's stream tables, each table in its row order.
/// Only the tables the plan has outputs for are filled.
pub(crate) struct StreamTables {
    connections: Vec<Connection>,
    sessions: Vec<TlsSession>,
    /// The rows of `http_messages`, as indices into `messages`.
    http: Vec<usize>,
    /// The rows of `http2`, as indices into `messages`.
    http2: Vec<usize>,
    messages: Vec<ParsedMessage>,
}

impl StreamTables {
    fn rows(&self, table: StreamTable) -> usize {
        match table {
            StreamTable::TcpConnections => self.connections.len(),
            StreamTable::TlsSessions => self.sessions.len(),
            StreamTable::HttpMessages => self.http.len(),
            StreamTable::Http2 => self.http2.len(),
        }
    }

    /// Write row `row` of the plan's table: one cell per output column.
    fn write_row<S: RowSink>(
        &self,
        plan: &StreamPlan,
        columns: &[OutColumn],
        row: usize,
        sink: &mut S,
    ) -> ControlFlow<Full> {
        let message = |rows: &[usize]| &self.messages[rows[row]];
        for (index, (cell, column)) in plan.cells.iter().zip(columns).enumerate() {
            let col = OutCol(index as u16);
            let kind = column.kind;
            match *cell {
                Cell::EncapDepth => write_value(sink, col, kind, &FieldValue::UInt8(0)),
                Cell::Null => sink.null(col),
                Cell::Connection(cell) => {
                    write_connection_cell(sink, col, kind, cell, &self.connections[row])
                }
                Cell::Session(cell) => {
                    write_session_cell(sink, col, kind, cell, &self.sessions[row])
                }
                Cell::Message(cell) => {
                    let message = match plan.table {
                        StreamTable::Http2 => message(&self.http2),
                        _ => message(&self.http),
                    };
                    write_message_cell(sink, col, kind, cell, message)
                }
            }
        }
        sink.end_row()
    }
}

/// A time the stream manager holds (microseconds) as a value for a
/// timestamp column of `kind`.
fn timestamp(kind: ColKind, micros: i64) -> FieldValue<'static> {
    FieldValue::Int64(match kind {
        ColKind::TsNanos => micros.saturating_mul(1_000),
        _ => micros,
    })
}

fn write_connection_cell<S: RowSink>(
    sink: &mut S,
    col: OutCol,
    kind: ColKind,
    cell: ConnectionCell,
    connection: &Connection,
) {
    use ConnectionCell as C;
    // A connection that reached a terminal state ended at its last activity
    // (the FIN/ACK or RST); an open one has no end yet.
    let complete = matches!(
        connection.state,
        ConnectionState::Closed | ConnectionState::TimeWait | ConnectionState::Reset
    );
    let end = connection
        .end_time
        .or(complete.then_some(connection.last_activity));
    let text;
    let value = match cell {
        C::FirstFrame => FieldValue::UInt64(connection.first_frame),
        C::Id => FieldValue::UInt64(connection.id),
        C::ClientIp => {
            text = connection.client_ip().to_string();
            FieldValue::Str(&text)
        }
        C::ServerIp => {
            text = connection.server_ip().to_string();
            FieldValue::Str(&text)
        }
        C::ClientPort => FieldValue::UInt16(connection.client_port()),
        C::ServerPort => FieldValue::UInt16(connection.server_port()),
        C::State => FieldValue::Str(connection.state.as_str()),
        C::StartTime => timestamp(kind, connection.start_time),
        C::EndTime => end.map_or(FieldValue::Null, |end| timestamp(kind, end)),
        C::DurationUs => end.map_or(FieldValue::Null, |end| {
            FieldValue::Int64(end - connection.start_time)
        }),
        C::LastFrame => FieldValue::UInt64(connection.last_frame),
        C::PacketsToServer => FieldValue::UInt32(connection.packets_to_server),
        C::PacketsToClient => FieldValue::UInt32(connection.packets_to_client),
        C::BytesToServer => FieldValue::UInt64(connection.bytes_to_server),
        C::BytesToClient => FieldValue::UInt64(connection.bytes_to_client),
        C::IsComplete => FieldValue::Bool(complete),
    };
    write_value(sink, col, kind, &value);
}

/// A text that may be absent, as a value.
fn text(text: Option<&str>) -> FieldValue<'_> {
    text.map_or(FieldValue::Null, FieldValue::Str)
}

fn write_session_cell<S: RowSink>(
    sink: &mut S,
    col: OutCol,
    kind: ColKind,
    cell: SessionCell,
    session: &TlsSession,
) {
    use SessionCell as C;
    // The same table as the `tls` parser and `tls_version_name()`.
    let version = session
        .server_version
        .or(session.client_version)
        .map(|v| tls_version_name(v).into_cow());
    let value = match cell {
        C::FrameNumber => FieldValue::UInt64(session.frame_number),
        C::ConnectionId => FieldValue::UInt64(session.connection_id),
        C::Version => text(version.as_deref()),
        C::CipherSuite => text(session.cipher_suite.as_deref()),
        C::CipherSuiteId => session
            .cipher_suite_id
            .map_or(FieldValue::Null, FieldValue::UInt16),
        C::Sni => text(session.sni.as_deref()),
        C::Alpn => text(session.alpn.as_deref()),
        C::IsDecrypted => FieldValue::Bool(session.is_decrypted),
        C::ServerHelloFrame => session
            .server_hello_frame
            .map_or(FieldValue::Null, FieldValue::UInt64),
    };
    write_value(sink, col, kind, &value);
}

fn write_message_cell<S: RowSink>(
    sink: &mut S,
    col: OutCol,
    kind: ColKind,
    cell: MessageCell,
    message: &ParsedMessage,
) {
    use MessageCell as C;
    let value = match cell {
        C::FrameNumber => FieldValue::UInt64(message.frame_number),
        C::ConnectionId => FieldValue::UInt64(message.connection_id),
        C::MessageId => FieldValue::UInt32(message.message_id),
        C::Direction => FieldValue::Str(message.direction.as_str()),
        C::Field(name) => match message.fields.get(name) {
            None => FieldValue::Null,
            Some(OwnedFieldValue::UInt8(v)) => FieldValue::UInt8(*v),
            Some(OwnedFieldValue::UInt16(v)) => FieldValue::UInt16(*v),
            Some(OwnedFieldValue::UInt32(v)) => FieldValue::UInt32(*v),
            Some(OwnedFieldValue::UInt64(v)) => FieldValue::UInt64(*v),
            Some(OwnedFieldValue::Bool(v)) => FieldValue::Bool(*v),
            Some(OwnedFieldValue::Str(v)) => FieldValue::Str(v),
            Some(OwnedFieldValue::OwnedString(v)) => FieldValue::Str(v),
            Some(OwnedFieldValue::OwnedBytes(v)) => FieldValue::Bytes(v),
        },
    };
    write_value(sink, col, kind, &value);
}

/// Writes the rows of a partition's stream tables to the sinks of the
/// plan's stream outputs, output by output, as many rows as fit.
pub(crate) struct StreamWriter {
    tables: StreamTables,
    /// The output being written, as an index into the plan's outputs.
    output: usize,
    /// The next row of that output's table.
    row: usize,
}

impl StreamWriter {
    pub(crate) fn new(tables: StreamTables) -> Self {
        Self {
            tables,
            output: 0,
            row: 0,
        }
    }

    /// Write rows until a sink is full: `Some` is the output whose rows must
    /// be taken before the next call, which carries on behind them. `None`:
    /// every stream output has all its rows (up to its row cap, and none
    /// once it was closed).
    ///
    /// `router` counts the rows and knows which outputs still take any.
    pub(crate) fn write<S: RowSink>(
        &mut self,
        plan: &CompiledScan,
        router: &mut Router,
        sinks: &mut [S],
    ) -> Option<OutputId> {
        while let Some(output) = plan.outputs().get(self.output) {
            if let Some(stream) = output.stream() {
                let id = OutputId(self.output as u16);
                let rows = self.tables.rows(stream.table);
                while self.row < rows && !router.is_done(id) {
                    let sink = &mut sinks[self.output];
                    let full = self
                        .tables
                        .write_row(stream, &output.columns, self.row, sink);
                    self.row += 1;
                    router.count_row(id);
                    if full.is_break() {
                        return Some(id);
                    }
                }
            }
            self.output += 1;
            self.row = 0;
        }
        None
    }
}
