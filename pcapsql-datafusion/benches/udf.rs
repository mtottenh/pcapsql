//! Scalar UDF benchmarks: one call of a UDF over a batch of 8,192 rows, as
//! DataFusion makes it for a query such as
//! `SELECT ... WHERE ip_in_cidr(src_ip, '10.0.0.0/8')`: the column as an
//! array and a literal argument as a scalar.
//!
//! The `*_array` cases pass the second argument as an array too (a second
//! column), which is the per-row path a constant argument used to take.
//! Criterion reports the time of one call; divide by 8,192 for the time per
//! row. Run with:
//! ```text
//! cargo bench -p pcapsql-datafusion --bench udf
//! ```

use std::sync::Arc;

use arrow::array::{
    ArrayRef, FixedSizeBinaryArray, StringArray, UInt16Array, UInt32Array, UInt8Array,
};
use arrow::datatypes::{DataType, Field};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use datafusion::common::config::ConfigOptions;
use datafusion::common::ScalarValue;
use datafusion::logical_expr::{ColumnarValue, ScalarFunctionArgs, ScalarUDF};
use pcapsql_datafusion::query::udf;

/// Rows per call: DataFusion's default batch size.
const ROWS: usize = 8192;

/// A deterministic pseudo-random sequence (SplitMix64).
fn random(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Every 16th row is NULL, as a column of an outer join or of a table with
/// absent fields is.
fn is_null(row: usize) -> bool {
    row % 16 == 15
}

fn ipv4_column() -> ArrayRef {
    let mut next = random(1);
    Arc::new(
        (0..ROWS)
            .map(|row| {
                // Half the addresses in 10.0.0.0/8.
                let ip = next() as u32;
                (!is_null(row)).then_some(if row % 2 == 0 {
                    0x0A00_0000 | (ip >> 8)
                } else {
                    ip
                })
            })
            .collect::<UInt32Array>(),
    )
}

fn fixed_column(width: usize, seed: u64) -> ArrayRef {
    let mut next = random(seed);
    let rows: Vec<Option<Vec<u8>>> = (0..ROWS)
        .map(|row| {
            let mut bytes: Vec<u8> = (0..width).map(|_| next() as u8).collect();
            if row % 2 == 0 {
                // 2001:db8::/32, with runs of zeros to compress.
                bytes[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
                if width == 16 {
                    bytes[4..12].fill(0);
                }
            }
            (!is_null(row)).then_some(bytes)
        })
        .collect();
    Arc::new(
        FixedSizeBinaryArray::try_from_sparse_iter_with_size(rows.into_iter(), width as i32)
            .unwrap(),
    )
}

fn u16_column(modulus: u64) -> ArrayRef {
    let mut next = random(3);
    Arc::new(
        (0..ROWS)
            .map(|row| (!is_null(row)).then_some((next() % modulus) as u16))
            .collect::<UInt16Array>(),
    )
}

fn u8_column() -> ArrayRef {
    // Mostly TCP and UDP, as a capture is.
    let mut next = random(4);
    Arc::new(
        (0..ROWS)
            .map(|row| {
                (!is_null(row)).then_some(match next() % 8 {
                    0..=3 => 6,
                    4..=6 => 17,
                    _ => next() as u8,
                })
            })
            .collect::<UInt8Array>(),
    )
}

/// The same text on every row: a literal as the array a second column is.
fn repeated(text: &str) -> ArrayRef {
    Arc::new(StringArray::from(vec![text; ROWS]))
}

fn literal(text: &str) -> ColumnarValue {
    ColumnarValue::Scalar(ScalarValue::Utf8(Some(text.to_string())))
}

fn bench_call(c: &mut Criterion, name: &str, udf: ScalarUDF, args: Vec<ColumnarValue>) {
    let arg_fields: Vec<_> = args
        .iter()
        .enumerate()
        .map(|(i, arg)| Arc::new(Field::new(format!("a{i}"), arg.data_type(), true)))
        .collect();
    let types: Vec<DataType> = args.iter().map(|arg| arg.data_type()).collect();
    let return_field = Arc::new(Field::new("out", udf.return_type(&types).unwrap(), true));
    let config_options = Arc::new(ConfigOptions::default());
    let mut group = c.benchmark_group("udf");
    group.throughput(Throughput::Elements(ROWS as u64));
    group.bench_function(name, |b| {
        b.iter(|| {
            let out = udf
                .invoke_with_args(ScalarFunctionArgs {
                    args: args.clone(),
                    arg_fields: arg_fields.clone(),
                    number_rows: ROWS,
                    return_field: Arc::clone(&return_field),
                    config_options: Arc::clone(&config_options),
                })
                .unwrap();
            black_box(out)
        })
    });
    group.finish();
}

fn bench_udfs(c: &mut Criterion) {
    let array = ColumnarValue::Array;

    // A constant pattern.
    bench_call(
        c,
        "ip_in_cidr",
        udf::create_ip_in_cidr_udf(),
        vec![array(ipv4_column()), literal("10.0.0.0/8")],
    );
    bench_call(
        c,
        "ip_in_cidr_array",
        udf::create_ip_in_cidr_udf(),
        vec![array(ipv4_column()), array(repeated("10.0.0.0/8"))],
    );
    bench_call(
        c,
        "ip6_in_cidr",
        udf::create_ip6_in_cidr_udf(),
        vec![array(fixed_column(16, 2)), literal("2001:db8::/32")],
    );
    bench_call(
        c,
        "ip6_in_cidr_array",
        udf::create_ip6_in_cidr_udf(),
        vec![array(fixed_column(16, 2)), array(repeated("2001:db8::/32"))],
    );
    bench_call(
        c,
        "has_tcp_flag",
        udf::create_has_tcp_flag_udf(),
        vec![array(u16_column(0x200)), literal("SYN")],
    );
    bench_call(
        c,
        "has_tcp_flag_array",
        udf::create_has_tcp_flag_udf(),
        vec![array(u16_column(0x200)), array(repeated("SYN"))],
    );

    // Text results.
    bench_call(
        c,
        "ip4_to_string",
        udf::create_ip4_to_string_udf(),
        vec![array(ipv4_column())],
    );
    bench_call(
        c,
        "ip6_to_string",
        udf::create_ip6_to_string_udf(),
        vec![array(fixed_column(16, 2))],
    );
    bench_call(
        c,
        "mac_to_string",
        udf::create_mac_to_string_udf(),
        vec![array(fixed_column(6, 5))],
    );
    bench_call(
        c,
        "ip_proto_name",
        udf::create_ip_proto_name_udf(),
        vec![array(u8_column())],
    );
    bench_call(
        c,
        "dns_type_name",
        udf::create_dns_type_name_udf(),
        vec![array(u16_column(64))],
    );
}

criterion_group!(benches, bench_udfs);
criterion_main!(benches);
