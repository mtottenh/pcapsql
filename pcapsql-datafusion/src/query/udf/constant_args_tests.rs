//! Differential tests of the UDF bodies that treat a constant argument or
//! write their text without a `String` per row.
//!
//! A call `f(column, 'literal')` reaches a body with the literal as a
//! scalar, which is parsed once; `f(column, other_column)` reaches it with
//! two arrays and is evaluated row by row. The two must agree for every
//! constant: a valid one, an invalid one, a NULL, and in every string type.
//! The text functions must give what the `String`-returning kernels of
//! `pcapsql_core::format` give row by row.

use std::sync::Arc;

use arrow::array::{
    Array, ArrayRef, FixedSizeBinaryArray, LargeStringArray, StringArray, StringViewArray,
    UInt16Array, UInt32Array,
};
use arrow::datatypes::{DataType, Field};
use datafusion::common::config::ConfigOptions;
use datafusion::common::{Result as DFResult, ScalarValue};
use datafusion::logical_expr::{ColumnarValue, ScalarFunctionArgs, ScalarUDF};
use pcapsql_core::format::{format_ipv4, format_ipv6, format_mac, has_tcp_flag};

use super::*;

/// One call of `udf`, as DataFusion makes it for a batch of `rows` rows.
fn call(udf: &ScalarUDF, args: Vec<ColumnarValue>, rows: usize) -> DFResult<ArrayRef> {
    let types: Vec<DataType> = args.iter().map(|arg| arg.data_type()).collect();
    let arg_fields = types
        .iter()
        .map(|data_type| Arc::new(Field::new("arg", data_type.clone(), true)))
        .collect();
    let return_field = Arc::new(Field::new("out", udf.return_type(&types)?, true));
    let out = udf.invoke_with_args(ScalarFunctionArgs {
        args,
        arg_fields,
        number_rows: rows,
        return_field,
        config_options: Arc::new(ConfigOptions::default()),
    })?;
    out.into_array(rows)
}

/// `text` as the scalar a literal of each string type is, and as the array
/// a column with that value in each of `rows` rows is.
fn constants(text: Option<&str>, rows: usize) -> Vec<(ScalarValue, ArrayRef)> {
    let owned = text.map(str::to_string);
    vec![
        (
            ScalarValue::Utf8(owned.clone()),
            Arc::new(StringArray::from(vec![text; rows])),
        ),
        (
            ScalarValue::LargeUtf8(owned.clone()),
            Arc::new(LargeStringArray::from(vec![text; rows])),
        ),
        (
            ScalarValue::Utf8View(owned),
            Arc::new(StringViewArray::from(vec![text; rows])),
        ),
    ]
}

/// `udf(column, constant)` gives what `udf(column, column of the constant)`
/// gives, for each of `texts` and for NULL, in every string type.
fn assert_constant_equals_column(udf: &ScalarUDF, column: &ArrayRef, texts: &[&str]) {
    let rows = column.len();
    for text in texts.iter().copied().map(Some).chain([None]) {
        for (scalar, array) in constants(text, rows) {
            let what = format!("{}(column, {scalar:?})", udf.name());
            let constant = call(
                udf,
                vec![
                    ColumnarValue::Array(Arc::clone(column)),
                    ColumnarValue::Scalar(scalar),
                ],
                rows,
            )
            .unwrap_or_else(|e| panic!("{what}: {e}"));
            let per_row = call(
                udf,
                vec![
                    ColumnarValue::Array(Arc::clone(column)),
                    ColumnarValue::Array(array),
                ],
                rows,
            )
            .unwrap_or_else(|e| panic!("{what}, as a column: {e}"));
            assert_eq!(constant.len(), rows, "{what}");
            assert_eq!(constant.data_type(), per_row.data_type(), "{what}");
            assert_eq!(&constant, &per_row, "{what}");
            // Equal arrays may still differ in what a NULL slot holds; the
            // NULLs themselves must be the same rows.
            for row in 0..rows {
                assert_eq!(
                    constant.is_null(row),
                    per_row.is_null(row),
                    "{what}, row {row}"
                );
            }
        }
    }

    // A constant that is not a string is the error it is for a column.
    let scalar = ScalarValue::Int64(Some(8));
    let array = scalar.to_array_of_size(rows).unwrap();
    let constant = call(
        udf,
        vec![
            ColumnarValue::Array(Arc::clone(column)),
            ColumnarValue::Scalar(scalar),
        ],
        rows,
    )
    .unwrap_err();
    let per_row = call(
        udf,
        vec![
            ColumnarValue::Array(Arc::clone(column)),
            ColumnarValue::Array(array),
        ],
        rows,
    )
    .unwrap_err();
    assert_eq!(constant.to_string(), per_row.to_string(), "{}", udf.name());
}

/// IPv4 addresses at the edges of the networks the tests name, with NULLs.
fn ipv4_column() -> ArrayRef {
    let mut ips = vec![
        Some(0),
        Some(u32::MAX),
        None,
        Some(0x0A00_0000),
        Some(0x0AFF_FFFF),
        Some(0x09FF_FFFF),
        Some(0x0B00_0000),
        Some(0xC0A8_0101),
        Some(0xC0A8_0100),
        Some(0xC0A8_00FF),
        None,
        Some(0x7F00_0001),
        Some(0x8000_0000),
    ];
    // More than one 64-row word of the result, NULLs included.
    ips.extend((0..200u32).map(|i| (i % 7 != 0).then_some(i.wrapping_mul(0x0101_0101))));
    Arc::new(UInt32Array::from(ips))
}

fn ipv6_column() -> ArrayRef {
    let mut ips: Vec<Option<[u8; 16]>> = vec![
        Some([0; 16]),
        Some([0xFF; 16]),
        None,
        Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Some([0xfe, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Some([0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Some([0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        // An IPv4-mapped address, which is written with a dotted quad.
        Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]),
        None,
        Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ];
    ips.extend((0..150u8).map(|i| {
        (i % 5 != 0).then(|| {
            let mut ip = [i; 16];
            ip[..2].copy_from_slice(&[0x20, 0x01]);
            ip[4..10].fill(0);
            ip
        })
    }));
    Arc::new(
        FixedSizeBinaryArray::try_from_sparse_iter_with_size(
            ips.iter().map(|ip| ip.as_ref().map(|ip| ip.as_slice())),
            16,
        )
        .unwrap(),
    )
}

fn flags_column() -> ArrayRef {
    let mut flags = vec![
        Some(0),
        Some(u16::MAX),
        None,
        Some(0x002),
        Some(0x012),
        Some(0x100),
    ];
    flags.extend((0..0x200u16).map(|bits| (bits % 11 != 0).then_some(bits)));
    Arc::new(UInt16Array::from(flags))
}

#[test]
fn ip_in_cidr_with_a_constant_network_equals_the_per_row_path() {
    assert_constant_equals_column(
        &create_ip_in_cidr_udf(),
        &ipv4_column(),
        &[
            "10.0.0.0/8",
            "192.168.1.0/24",
            // Host bits set in the network.
            "192.168.1.77/24",
            "0.0.0.0/0",
            "255.255.255.255/32",
            "128.0.0.0/1",
            // Not CIDR notation.
            "10.0.0.0",
            "10.0.0.0/33",
            "10.0.0/8",
            "10.0.0.0/8/8",
            "10.0.0.0/-1",
            " 10.0.0.0/8",
            "fe80::/10",
            "",
        ],
    );
}

#[test]
fn ip6_in_cidr_with_a_constant_prefix_equals_the_per_row_path() {
    assert_constant_equals_column(
        &create_ip6_in_cidr_udf(),
        &ipv6_column(),
        &[
            "fe80::/10",
            "2001:db8::/32",
            "2001:db8::1/128",
            "::/0",
            "::1/127",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
            "2001::/15",
            // Not CIDR notation.
            "fe80::",
            "fe80::/129",
            "fe80::/10/10",
            "10.0.0.0/8",
            "",
        ],
    );
}

#[test]
fn has_tcp_flag_with_a_constant_name_equals_the_per_row_path() {
    let udf = create_has_tcp_flag_udf();
    let column = flags_column();
    let names = [
        "FIN",
        "SYN",
        "RST",
        "PSH",
        "ACK",
        "URG",
        "ECE",
        "CWR",
        "NS",
        // Case-insensitive, also for U+017F LONG S, which upper-cases to S.
        "syn",
        "Ack",
        "\u{17f}yn",
        // Not a flag: never set.
        "",
        "SYN,ACK",
        " SYN",
        "nonsense",
    ];
    assert_constant_equals_column(&udf, &column, &names);

    // And against the kernel directly.
    let flags = column.as_any().downcast_ref::<UInt16Array>().unwrap();
    for name in names {
        let got = call(
            &udf,
            vec![
                ColumnarValue::Array(Arc::clone(&column)),
                ColumnarValue::Scalar(ScalarValue::Utf8(Some(name.to_string()))),
            ],
            column.len(),
        )
        .unwrap();
        let want: arrow::array::BooleanArray = flags
            .iter()
            .map(|flags| flags.map(|flags| has_tcp_flag(flags, name)))
            .collect();
        assert_eq!(got.as_ref(), &want as &dyn Array, "{name:?}");
    }
}

/// A call whose arguments are all constants is not the constant path: it
/// is still evaluated as one row.
#[test]
fn a_call_of_constants_only_is_one_row() {
    let got = call(
        &create_ip_in_cidr_udf(),
        vec![
            ColumnarValue::Scalar(ScalarValue::UInt32(Some(0x0A00_0001))),
            ColumnarValue::Scalar(ScalarValue::Utf8(Some("10.0.0.0/8".to_string()))),
        ],
        1,
    )
    .unwrap();
    assert_eq!(
        got.as_ref(),
        &arrow::array::BooleanArray::from(vec![true]) as &dyn Array
    );
}

#[test]
fn ip4_to_string_equals_the_string_kernel() {
    let column = ipv4_column();
    let got = call(
        &create_ip4_to_string_udf(),
        vec![ColumnarValue::Array(Arc::clone(&column))],
        column.len(),
    )
    .unwrap();
    let want: StringArray = column
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap()
        .iter()
        .map(|ip| ip.map(format_ipv4))
        .collect();
    assert_eq!(got.as_ref(), &want as &dyn Array);
    assert_eq!(got.null_count(), want.null_count());
}

#[test]
fn ip6_to_string_equals_the_string_kernel() {
    let column = ipv6_column();
    let got = call(
        &create_ip6_to_string_udf(),
        vec![ColumnarValue::Array(Arc::clone(&column))],
        column.len(),
    )
    .unwrap();
    let ips = column
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .unwrap();
    let want: StringArray = ips
        .iter()
        .map(|ip| ip.map(|ip| format_ipv6(ip).expect("16 bytes")))
        .collect();
    assert_eq!(got.as_ref(), &want as &dyn Array);
    assert_eq!(got.null_count(), want.null_count());
}

#[test]
fn mac_to_string_equals_the_string_kernel() {
    let macs: Vec<Option<[u8; 6]>> = vec![
        Some([0; 6]),
        Some([0xFF; 6]),
        None,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        Some([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]),
        None,
        Some([0x02, 0x0a, 0x10, 0x9f, 0xa0, 0x00]),
    ];
    let column: ArrayRef = Arc::new(
        FixedSizeBinaryArray::try_from_sparse_iter_with_size(
            macs.iter()
                .map(|mac| mac.as_ref().map(|mac| mac.as_slice())),
            6,
        )
        .unwrap(),
    );
    let got = call(
        &create_mac_to_string_udf(),
        vec![ColumnarValue::Array(Arc::clone(&column))],
        column.len(),
    )
    .unwrap();
    let want: StringArray = macs
        .iter()
        .map(|mac| mac.map(|mac| format_mac(&mac).unwrap_or_default()))
        .collect();
    assert_eq!(got.as_ref(), &want as &dyn Array);
    assert_eq!(got.null_count(), want.null_count());
}
