//! Scan-path benchmarks: reader, parse, routing, coercion and batch building
//! together, which is what a query pays for every packet it reads.
//!
//! `baseline.rs` does not cover this: its `parse_throughput` stops at
//! `parse_packet`, and its `query/*` cases run against an engine that caches
//! tables, so after warm-up they time DataFusion over cached batches. The
//! cases here re-read the capture on every iteration. They are the numbers
//! any change to the scan path (readers, builders, routing, the shared scan
//! layer of `docs/shared-scan-layer-design.md`) is compared against. Run with:
//! ```text
//! cargo bench -p pcapsql-datafusion --bench scan
//! ```
//! Benchmarks build with thin LTO and 16 codegen units (`[profile.bench]` in
//! the workspace `Cargo.toml`), not with the release profile's fat LTO, which
//! needs more memory to link than a 15 GB machine has. Compare numbers taken
//! with the same profile only.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pcapsql_core::io::{FilePacketSource, MmapPacketSource, SeekablePacketSource};
use pcapsql_core::{default_registry, ProtocolRegistry};
use pcapsql_datafusion::query::providers::{run_shared_parse, ParseSubscription, PassOptions};
use pcapsql_datafusion::query::{EngineOptions, QueryEngine, RetentionPolicy, SourceSpec};
use pcapsql_testgen::{legacy_pcap, GenPacket, LegacyVariant};
use tempfile::TempDir;

/// Packets per generated capture. Large enough that per-packet costs dominate.
const N_PACKETS: usize = 20_000;
/// Rows per batch, as the CLI's default engine uses for a one-shot query.
const BATCH_SIZE: usize = 10_000;

const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

fn eth(payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&0x0800u16.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ipv4(proto: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x40, 0x00]);
    p.push(64);
    p.push(proto);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[192, 168, 0, 1]);
    p.extend_from_slice(&[192, 168, 0, 2]);
    p.extend_from_slice(payload);
    p
}

fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(payload);
    p
}

/// TCP segment whose header carries `options` (padded to a 32-bit boundary).
fn tcp(sp: u16, dp: u16, seq: u32, flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut options = options.to_vec();
    let padding = (4 - options.len() % 4) % 4;
    options.extend(std::iter::repeat_n(1, padding)); // NOPs
    let mut p = Vec::with_capacity(20 + options.len() + payload.len());
    p.extend_from_slice(&sp.to_be_bytes());
    p.extend_from_slice(&dp.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push((((20 + options.len()) / 4) as u8) << 4);
    p.push(flags);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    p.extend_from_slice(&options);
    p.extend_from_slice(payload);
    p
}

/// Ethernet/IPv4/UDP with a fixed payload: every column of `udp` and `ipv4`
/// is present, and one row per table per frame.
fn udp_frame(i: usize) -> Vec<u8> {
    eth(&ipv4(
        17,
        i as u16,
        &udp(10_000 + (i % 5000) as u16, 53, &[0xAB; 256]),
    ))
}

/// Ethernet/IPv4/TCP cycling through a SYN with MSS, window scale, SACK
/// permitted and timestamps; a data segment with timestamps and two SACK
/// blocks; and a bare segment with no options. `tcp` therefore fills its
/// list columns on some rows and leaves its optional columns absent on
/// others, which is the lookup-miss path of the row builder.
fn tcp_frame(i: usize) -> Vec<u8> {
    let seq = 1_000 + i as u32 * 100;
    let timestamps = |options: &mut Vec<u8>| {
        options.extend_from_slice(&[8, 10]);
        options.extend_from_slice(&(i as u32).to_be_bytes());
        options.extend_from_slice(&(i as u32 + 1).to_be_bytes());
    };
    let mut options = Vec::new();
    let flags = match i % 3 {
        0 => {
            options.extend_from_slice(&[2, 4, 0x05, 0xB4]); // MSS 1460
            options.extend_from_slice(&[4, 2]); // SACK permitted
            timestamps(&mut options);
            options.extend_from_slice(&[3, 3, 7]); // window scale 7
            0x02
        }
        1 => {
            timestamps(&mut options);
            options.extend_from_slice(&[5, 18]); // SACK, two blocks
            for edge in [seq + 200, seq + 300, seq + 500, seq + 600] {
                options.extend_from_slice(&edge.to_be_bytes());
            }
            0x10
        }
        _ => 0x18,
    };
    eth(&ipv4(
        6,
        i as u16,
        &tcp(40_000, 443, seq, flags, &options, &[0xCD; 64]),
    ))
}

/// Ethernet/IPv4/UDP/VXLAN carrying an inner Ethernet/IPv4/UDP frame: two
/// rows per frame in `ethernet`, `ipv4` and `udp`, at different depths.
fn vxlan_frame(i: usize) -> Vec<u8> {
    let inner = udp_frame(i);
    let mut vxlan = Vec::with_capacity(8 + inner.len());
    vxlan.extend_from_slice(&[0x08, 0, 0, 0]);
    vxlan.extend_from_slice(&(i as u32 % 4096).to_be_bytes()[1..]);
    vxlan.push(0);
    vxlan.extend_from_slice(&inner);
    eth(&ipv4(17, i as u16, &udp(50_000, 4789, &vxlan)))
}

/// Write `N_PACKETS` frames built by `frame` as a legacy pcap.
fn capture_file(dir: &TempDir, name: &str, frame: fn(usize) -> Vec<u8>) -> PathBuf {
    let packets: Vec<GenPacket> = (0..N_PACKETS)
        .map(|i| {
            let data = frame(i);
            let origlen = data.len() as u32;
            GenPacket {
                ts_sec: 1_700_000_000 + (i / 1000) as u32,
                ts_frac: (i as u32 * 251) % 1_000_000,
                data,
                origlen,
            }
        })
        .collect();
    let path = dir.path().join(name);
    std::fs::write(
        &path,
        legacy_pcap(LegacyVariant::LeMicro, 1, 65535, &packets).bytes,
    )
    .unwrap();
    path
}

/// One scoped parse pass producing every column of `tables`, and the rows it
/// built (so a pass that silently produces nothing cannot look fast).
fn parse_pass<S: SeekablePacketSource>(
    source: &Arc<S>,
    registry: &Arc<ProtocolRegistry>,
    tables: &[&str],
    partitions: usize,
) -> usize {
    let subscription = ParseSubscription::tables_full(tables).expect("known tables");
    let options = PassOptions {
        target_partitions: partitions,
        ..PassOptions::new(BATCH_SIZE)
    };
    let (tables, _stats) = run_shared_parse(source, registry, &subscription, &options)
        .expect("parse pass")
        .into_tables();
    tables.values().map(|t| t.total_rows()).sum()
}

/// The parse pass itself, without DataFusion: reader, `parse_packet`,
/// routing, coercion and Arrow batch building.
fn bench_parse_pass(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let registry = Arc::new(default_registry());
    let captures: [(&str, PathBuf, &[&str], usize); 3] = [
        (
            "udp",
            capture_file(&dir, "udp.pcap", udp_frame),
            &["frames", "ipv4", "udp"],
            3 * N_PACKETS,
        ),
        (
            "tcp_options",
            capture_file(&dir, "tcp.pcap", tcp_frame),
            &["frames", "ipv4", "tcp"],
            3 * N_PACKETS,
        ),
        (
            "vxlan",
            capture_file(&dir, "vxlan.pcap", vxlan_frame),
            &["ethernet", "ipv4", "udp", "vxlan"],
            7 * N_PACKETS,
        ),
    ];

    let mut g = c.benchmark_group("scan/parse_pass");
    g.sample_size(20);
    g.throughput(Throughput::Elements(N_PACKETS as u64));
    for (name, path, tables, rows) in &captures {
        // A fine stride, so that four partitions exist for a capture this
        // small. The index is built once, on the first pass.
        let file = Arc::new(
            FilePacketSource::open(path)
                .unwrap()
                .with_index_stride(1024),
        );
        let mmap = Arc::new(
            MmapPacketSource::open(path)
                .unwrap()
                .with_index_stride(1024),
        );
        assert_eq!(parse_pass(&file, &registry, tables, 1), *rows, "{name}");
        assert_eq!(parse_pass(&mmap, &registry, tables, 4), *rows, "{name}");

        g.bench_function(format!("{name}/file/1"), |b| {
            b.iter(|| parse_pass(&file, &registry, tables, 1))
        });
        g.bench_function(format!("{name}/mmap/1"), |b| {
            b.iter(|| parse_pass(&mmap, &registry, tables, 1))
        });
        g.bench_function(format!("{name}/mmap/4"), |b| {
            b.iter(|| parse_pass(&mmap, &registry, tables, 4))
        });
    }
    g.finish();
}

fn build_engine(rt: &tokio::runtime::Runtime, path: &Path) -> QueryEngine {
    rt.block_on(QueryEngine::open(
        SourceSpec::Path(path.to_path_buf()),
        EngineOptions {
            batch_size: BATCH_SIZE,
            target_partitions: Some(4),
            retention: RetentionPolicy::None,
            ..Default::default()
        },
    ))
    .expect("build engine")
}

/// The `query/*` cases of `baseline.rs` on an engine that retains nothing,
/// so every iteration includes the scan the query needs: the end-to-end
/// cost of a one-shot query.
fn bench_one_shot_queries(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let path = capture_file(&dir, "udp.pcap", udp_frame);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = build_engine(&rt, &path);

    let mut g = c.benchmark_group("scan/one_shot_query");
    g.sample_size(20);
    let cases: &[(&str, &str)] = &[
        (
            "selective",
            "SELECT src_port FROM udp WHERE dst_port = 53 AND src_port < 10100 \
             ORDER BY src_port",
        ),
        ("count_udp", "SELECT count(*) AS c FROM udp"),
        (
            "all_columns_udp",
            "SELECT * FROM udp ORDER BY frame_number DESC LIMIT 5",
        ),
        (
            "with_payload",
            "SELECT frame_number, length(hex(raw_data)) / 2 AS len FROM frames \
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
    g.finish();
}

criterion_group!(benches, bench_parse_pass, bench_one_shot_queries);
criterion_main!(benches);
