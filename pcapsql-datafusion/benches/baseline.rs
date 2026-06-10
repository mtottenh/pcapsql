//! Baseline benchmark suite for the query-scoped-parse migration.
//!
//! Establishes the numbers each migration phase is judged against
//! (`docs/query-scoped-parse-migration.md` §8). Run with:
//! ```text
//! cargo bench -p pcapsql-datafusion --bench baseline
//! ```
//!
//! Captures are generated deterministically; sizes are kept modest so a full
//! run completes in minutes while still dominating constant overheads.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use pcapsql_core::{default_registry, parse_packet};
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
use tempfile::TempDir;

/// Packets per generated capture. Large enough that per-packet costs dominate.
const N_PACKETS: usize = 20_000;

/// Build a real Ethernet/IPv4/UDP frame so protocol tables populate.
fn udp_packet(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(42 + payload_len);
    p.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p.extend_from_slice(&[0x08, 0x00]);
    let ip_total = (20 + 8 + payload_len) as u16;
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&ip_total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
    p.push(64);
    p.push(17);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[192, 168, 0, 1]);
    p.extend_from_slice(&[192, 168, 0, 2]);
    let udp_len = (8 + payload_len) as u16;
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend(std::iter::repeat_n(0xAB, payload_len));
    p
}

fn capture_bytes(count: usize, payload: usize) -> Vec<u8> {
    let packets: Vec<GenPacket> = (0..count)
        .map(|i| {
            let data = udp_packet(10_000 + (i % 5000) as u16, 53, payload);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + (i / 1000) as u32,
                ts_frac: (i as u32 * 251) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes
}

/// Write a capture to a temp file, returning (dir guard, path).
fn capture_file(count: usize, payload: usize) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bench.pcap");
    std::fs::write(&path, capture_bytes(count, payload)).unwrap();
    (dir, path)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn build_engine(rt: &tokio::runtime::Runtime, path: &std::path::Path) -> QueryEngine {
    rt.block_on(QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: 4096,
            target_partitions: Some(4),
            ..Default::default()
        },
    ))
    .expect("build engine")
}

/// Raw decode→fields throughput: `parse_packet` over a realistic frame, no
/// Arrow involved. The floor every scoped-parse change is measured against.
fn bench_parse_throughput(c: &mut Criterion) {
    let registry = default_registry();
    let frames: Vec<Vec<u8>> = (0..1000)
        .map(|i| udp_packet(10_000 + i as u16, 53, 256))
        .collect();

    let mut g = c.benchmark_group("parse_throughput");
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.bench_function("full_parse_udp", |b| {
        b.iter(|| {
            let mut fields = 0usize;
            for f in &frames {
                let parsed = parse_packet(&registry, 1, f);
                fields += parsed.len();
            }
            fields
        })
    });
    g.finish();
}

/// Engine construction = (today) the full eager parse + materialization.
/// The migration drives this toward "open the source".
fn bench_engine_open(c: &mut Criterion) {
    let (_dir, path) = capture_file(N_PACKETS, 256);
    let rt = rt();

    let mut g = c.benchmark_group("engine_open");
    g.sample_size(10);
    g.throughput(Throughput::Elements(N_PACKETS as u64));
    g.bench_function("eager_full", |b| {
        b.iter_batched(|| (), |_| build_engine(&rt, &path), BatchSize::PerIteration)
    });
    g.finish();
}

/// Query benches: selective projection, full count, LIMIT, payload column,
/// and a repeated (REPL-shaped) query. Engine built once outside the loop, so
/// pre-migration these measure DataFusion-over-memory; post-migration they
/// include the scoped parse — which is exactly the comparison the migration
/// document calls for (end-to-end cost of answering the question).
fn bench_queries(c: &mut Criterion) {
    let (_dir, path) = capture_file(N_PACKETS, 256);
    let rt = rt();
    let engine = build_engine(&rt, &path);

    let mut g = c.benchmark_group("query");
    g.sample_size(20);

    let cases: &[(&str, &str)] = &[
        (
            "selective",
            "SELECT src_port FROM udp WHERE dst_port = 53 AND src_port < 10100 \
             ORDER BY src_port",
        ),
        ("full_scan_count", "SELECT count(*) AS c FROM frames"),
        (
            "limit",
            "SELECT frame_number FROM frames ORDER BY frame_number LIMIT 10",
        ),
        (
            "no_payload",
            "SELECT frame_number, length FROM frames ORDER BY frame_number DESC LIMIT 5",
        ),
        (
            "with_payload",
            "SELECT frame_number, octet_length(raw_data) AS len FROM frames \
             ORDER BY len DESC LIMIT 5",
        ),
        (
            "join_two_tables",
            "SELECT f.frame_number, u.dst_port FROM frames f \
             JOIN udp u USING (frame_number) ORDER BY f.frame_number DESC LIMIT 5",
        ),
    ];

    for (name, sql) in cases {
        g.bench_function(*name, |b| {
            b.iter(|| rt.block_on(engine.query(sql)).expect("query"))
        });
    }

    // REPL-shaped: the same query repeatedly against one engine. Identical to
    // the cases above today; post-P2 this is the cache-hit path and must not
    // regress.
    g.bench_function("repl_second_query", |b| {
        b.iter(|| {
            rt.block_on(engine.query("SELECT count(*) AS c FROM udp"))
                .expect("query")
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_parse_throughput,
    bench_engine_open,
    bench_queries
);
criterion_main!(benches);
