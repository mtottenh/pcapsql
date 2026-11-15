//! Stream tables through the scan driver.
//!
//! A plan with stream tables (`tcp_connections`, `tls_sessions`,
//! `http_messages`, `http2`) is scanned like any other: the driver
//! reassembles the TCP streams while it reads the partition and writes the
//! tables' rows to their sinks when the partition ends. Checked here over
//! the stream corpus capture (an HTTP/1.1 exchange, then a TLS handshake
//! the client resets):
//!
//! 1. the rows themselves, cell by cell where the capture pins them;
//! 2. that sinks of capacity 1, 2, 3 and 2048, read with any number of
//!    packets per step, hold the rows of an unbounded scan, and that the
//!    per-packet tables of the same pass are not disturbed;
//! 3. row caps, a closed output, and a column subset in another order.

mod common;

use std::sync::Arc;

use common::{legacy_capture, reader, scan, vxlan, Scanned};
use pcapsql_core::scan::testing::{Cell, RecordingSink};
use pcapsql_core::scan::{
    Catalog, CompiledScan, OutputId, PartitionScan, ScanPlan, Step, TableScan, TimestampUnit,
};
use pcapsql_core::{default_registry, ProtocolRegistry};
use pcapsql_testgen::corpus::{http_capture, http_frames, padded_http_capture};

const STREAM_TABLES: [&str; 4] = ["tcp_connections", "tls_sessions", "http_messages", "http2"];

fn registry() -> Arc<ProtocolRegistry> {
    Arc::new(default_registry())
}

/// Every default column of `table`.
fn full(table: &str) -> TableScan {
    let (id, def) = Catalog::builtin().table(table).unwrap();
    TableScan::new(id, def.default_columns().map(|(c, _)| c).collect())
}

/// These columns of `table`, in this order.
fn columns(table: &str, names: &[&str]) -> TableScan {
    let (id, def) = Catalog::builtin().table(table).unwrap();
    let columns = names.iter().map(|n| def.column(n).unwrap().0).collect();
    TableScan::new(id, columns)
}

fn compile(plan: &ScanPlan) -> Arc<CompiledScan> {
    Arc::new(
        plan.compile(Catalog::builtin(), &default_registry())
            .unwrap(),
    )
}

/// `frames` and `tcp`, then every stream table, all columns.
fn everything(timestamps: TimestampUnit) -> Arc<CompiledScan> {
    compile(&ScanPlan {
        tables: vec![full("frames"), full("tcp")],
        streams: STREAM_TABLES.iter().map(|t| full(t)).collect(),
        timestamps,
        ..Default::default()
    })
}

/// The value of `column` in each row of output `output`.
fn column(plan: &CompiledScan, scanned: &Scanned, output: usize, column: &str) -> Vec<Cell> {
    let index = plan.outputs()[output]
        .columns
        .iter()
        .position(|c| c.name == column)
        .unwrap_or_else(|| panic!("no column {column}"));
    scanned.rows[output]
        .iter()
        .map(|row| row[index].clone())
        .collect()
}

fn text(s: &str) -> Cell {
    Cell::Str(s.to_string())
}

#[test]
fn stream_tables_come_after_the_per_packet_outputs() {
    let plan = everything(TimestampUnit::Micros);
    assert!(plan.requires_single_partition());
    let catalog = Catalog::builtin();
    let names: Vec<&str> = plan
        .outputs()
        .iter()
        .map(|output| catalog.get(output.table.unwrap()).name)
        .collect();
    assert_eq!(
        names,
        [
            "frames",
            "tcp",
            "tcp_connections",
            "tls_sessions",
            "http_messages",
            "http2"
        ]
    );
}

#[test]
fn the_rows_of_the_stream_corpus() {
    let plan = everything(TimestampUnit::Micros);
    let scanned = scan(&http_capture(), &plan, &registry(), None, 1024);
    assert_eq!(scanned.last, Step::End);
    assert_eq!(scanned.stats.packets, 14);
    assert_eq!(*scanned.stats.rows, [14, 14, 2, 1, 2, 0]);
    let cells = |output, name| column(&plan, &scanned, output, name);

    // tcp_connections: the HTTP exchange closed in order, the TLS one reset.
    assert_eq!(cells(2, "frame_number"), [Cell::U64(1), Cell::U64(9)]);
    assert_eq!(cells(2, "first_frame"), [Cell::U64(1), Cell::U64(9)]);
    assert_eq!(cells(2, "last_frame"), [Cell::U64(8), Cell::U64(14)]);
    assert_eq!(cells(2, "client_ip"), [text("10.0.0.1"), text("10.0.0.1")]);
    assert_eq!(cells(2, "server_ip"), [text("10.0.0.2"), text("10.0.0.2")]);
    assert_eq!(
        cells(2, "client_port"),
        [Cell::U16(40002), Cell::U16(40003)]
    );
    assert_eq!(cells(2, "server_port"), [Cell::U16(80), Cell::U16(443)]);
    assert_eq!(
        cells(2, "is_complete"),
        [Cell::Bool(true), Cell::Bool(true)]
    );
    assert_eq!(cells(2, "encap_depth"), [Cell::U8(0), Cell::U8(0)]);
    assert_eq!(cells(2, "tunnel_type"), [Cell::Null, Cell::Null]);
    assert_eq!(cells(2, "tunnel_id"), [Cell::Null, Cell::Null]);
    // A closed connection has an end and a duration.
    for name in ["end_time", "duration_us"] {
        assert!(cells(2, name).iter().all(|cell| *cell != Cell::Null));
    }

    // tls_sessions: no key log, so nothing is decrypted.
    assert_eq!(cells(3, "frame_number"), [Cell::U64(12)]);
    assert_eq!(cells(3, "server_hello_frame"), [Cell::U64(13)]);
    assert_eq!(cells(3, "sni"), [text("example.test")]);
    assert_eq!(cells(3, "alpn"), [text("h2")]);
    assert_eq!(cells(3, "cipher_suite_id"), [Cell::U16(0x1301)]);
    assert_eq!(cells(3, "is_decrypted"), [Cell::Bool(false)]);
    assert_eq!(cells(3, "connection_id"), cells(2, "connection_id")[1..]);

    // http_messages: the request, then the response.
    assert_eq!(cells(4, "frame_number"), [Cell::U64(4), Cell::U64(5)]);
    assert_eq!(
        cells(4, "is_request"),
        [Cell::Bool(true), Cell::Bool(false)]
    );
    assert_eq!(cells(4, "method"), [text("GET"), Cell::Null]);
    assert_eq!(cells(4, "uri"), [text("/index.html"), Cell::Null]);
    assert_eq!(cells(4, "host"), [text("example.test"), Cell::Null]);
    assert_eq!(cells(4, "status_code"), [Cell::Null, Cell::U16(200)]);
    assert_eq!(cells(4, "content_length"), [Cell::Null, Cell::U64(5)]);
    assert_eq!(cells(4, "server"), [Cell::Null, text("corpus")]);
    assert_eq!(
        cells(4, "connection_id"),
        [
            cells(2, "connection_id")[0].clone(),
            cells(2, "connection_id")[0].clone()
        ]
    );
}

/// Ethernet padding is not TCP payload: the padded capture gives the same
/// stream tables.
#[test]
fn padding_does_not_reach_reassembly() {
    let plan = compile(&ScanPlan {
        streams: STREAM_TABLES.iter().map(|t| full(t)).collect(),
        ..Default::default()
    });
    let plain = scan(&http_capture(), &plan, &registry(), None, 1024);
    let padded = scan(&padded_http_capture(), &plan, &registry(), None, 1024);
    assert_eq!(plain.rows, padded.rows);
    assert_eq!(*plain.stats.rows, [2, 1, 2, 0]);
}

/// Timestamps of a stream table are in the plan's unit.
#[test]
fn stream_timestamps_follow_the_plan_s_unit() {
    let start = |unit| {
        let plan = everything(unit);
        let scanned = scan(&http_capture(), &plan, &registry(), None, 1024);
        let frames = column(&plan, &scanned, 0, "timestamp");
        let starts = column(&plan, &scanned, 2, "start_time");
        // A connection starts with its first frame.
        (frames[0].clone(), starts[0].clone())
    };
    let (frame, connection) = start(TimestampUnit::Micros);
    assert_eq!(frame, connection);
    let Cell::Timestamp(micros) = connection else {
        panic!("{connection:?}");
    };
    let (frame, connection) = start(TimestampUnit::Nanos);
    let Cell::Timestamp(nanos) = connection else {
        panic!("{connection:?}");
    };
    // Reassembly keeps microseconds.
    assert_eq!(nanos, micros * 1_000);
    let Cell::Timestamp(frame) = frame else {
        panic!("{frame:?}");
    };
    assert_eq!(nanos / 1_000, frame / 1_000);
}

/// Sinks of any size, read with any number of packets per step, hold the
/// rows of an unbounded scan: of the stream tables and of the per-packet
/// tables of the same pass.
#[test]
fn bounded_sinks_hold_the_same_rows() {
    let plan = everything(TimestampUnit::Micros);
    let capture = http_capture();
    let registry = registry();
    let whole = scan(&capture, &plan, &registry, None, usize::MAX);
    for capacity in [1, 2, 3, 2048] {
        for max_packets in [1, 3, 1024] {
            let stepped = scan(&capture, &plan, &registry, Some(capacity), max_packets);
            assert_eq!(stepped.rows, whole.rows, "capacity {capacity}");
            assert_eq!(stepped.last, Step::End);
            assert_eq!(stepped.stats, whole.stats);
        }
    }
    // At capacity 1 every row of every output but the last of each is a
    // flush of its own.
    let single = scan(&capture, &plan, &registry, Some(1), 1024);
    assert_eq!(single.flushes, 14 + 14 + 2 + 1 + 2);
}

/// A frame whose rows do not fit a sink is shown to the scan again, and
/// reassembly must see it once all the same. Every frame of the corpus
/// inside VXLAN has two `ethernet` rows, so with sinks of one row each
/// frame is shown twice; the stream tables are those of the plain capture
/// (reassembly follows the innermost TCP flow).
#[test]
fn a_frame_shown_again_is_reassembled_once() {
    let plan = compile(&ScanPlan {
        tables: vec![full("ethernet")],
        streams: STREAM_TABLES.iter().map(|t| full(t)).collect(),
        ..Default::default()
    });
    let registry = registry();
    let plain = legacy_capture(&http_frames());
    let tunnelled: Vec<Vec<u8>> = http_frames()
        .iter()
        .enumerate()
        .map(|(i, frame)| vxlan(i, frame))
        .collect();
    let tunnelled = legacy_capture(&tunnelled);

    let expected = scan(&plain, &plan, &registry, None, 1024);
    assert_eq!(*expected.stats.rows, [14, 2, 1, 2, 0]);
    let whole = scan(&tunnelled, &plan, &registry, None, 1024);
    let stepped = scan(&tunnelled, &plan, &registry, Some(1), 1024);
    assert_eq!(*stepped.stats.rows, [28, 2, 1, 2, 0]);
    assert_eq!(whole.rows[1..], expected.rows[1..]);
    assert_eq!(stepped.rows, whole.rows);
}

/// A column subset in another order, and a table with no columns at all (a
/// row count).
#[test]
fn stream_columns_are_projected() {
    let plan = compile(&ScanPlan {
        streams: vec![
            columns("http_messages", &["status_code", "frame_number", "method"]),
            columns("tcp_connections", &[]),
        ],
        ..Default::default()
    });
    let scanned = scan(&http_capture(), &plan, &registry(), Some(1), 1024);
    assert_eq!(
        scanned.rows[0],
        [
            vec![Cell::Null, Cell::U64(4), text("GET")],
            vec![Cell::U16(200), Cell::U64(5), Cell::Null],
        ]
    );
    assert_eq!(scanned.rows[1], [vec![], vec![]]);
}

/// A row cap on a stream table cuts its rows; the capture is still read to
/// its end, whatever the caps of the per-packet tables.
#[test]
fn row_caps_apply_to_stream_tables() {
    let mut frames = full("frames");
    frames.fetch = Some(3);
    let mut connections = full("tcp_connections");
    connections.fetch = Some(1);
    let plan = compile(&ScanPlan {
        tables: vec![frames],
        streams: vec![connections, full("http_messages")],
        ..Default::default()
    });
    let scanned = scan(&http_capture(), &plan, &registry(), None, 1024);
    assert_eq!(scanned.last, Step::End);
    assert_eq!(scanned.stats.packets, 14);
    assert_eq!(*scanned.stats.rows, [3, 1, 2]);
}

/// A closed stream output gets no rows, and once nothing else is wanted
/// the scan stops without reading the rest of the capture.
#[test]
fn closed_stream_outputs_are_skipped() {
    let plan = compile(&ScanPlan {
        streams: vec![full("tcp_connections"), full("http_messages")],
        ..Default::default()
    });
    let registry = registry();
    let sinks = |plan: &CompiledScan| -> Vec<RecordingSink> {
        plan.outputs()
            .iter()
            .map(|output| RecordingSink::new(&output.columns, None))
            .collect()
    };

    let capture = http_capture();
    let mut scan = PartitionScan::new(reader(&capture), Arc::clone(&plan), Arc::clone(&registry));
    let mut out = sinks(&plan);
    assert_eq!(scan.step(&mut out, 5).unwrap(), Step::More);
    scan.close_output(OutputId(0));
    while scan.step(&mut out, 5).unwrap() == Step::More {}
    assert_eq!(out[0].rows(), 0);
    assert_eq!(out[1].rows(), 2);
    assert_eq!(*scan.stats().rows, [0, 2]);

    let mut scan = PartitionScan::new(reader(&capture), plan, registry);
    assert_eq!(scan.step(&mut out, 5).unwrap(), Step::More);
    scan.close_output(OutputId(0));
    scan.close_output(OutputId(1));
    assert_eq!(scan.step(&mut out, 5).unwrap(), Step::Done);
    assert_eq!(scan.stats().packets, 5);
}
