//! The SQL functions against the kernels they wrap.
//!
//! For a table of inputs, what DuckDB returns must be what `pcapsql_core::format` returns. The
//! kernels are tested against the DataFusion functions in `pcapsql-datafusion`, so this ties the
//! two engines together. BLOB results are compared as hex text.

use std::fmt::Write;

use duckdb_neo::{connection::Connection, Result};
use pcapsql_core::format;
use pcapsql_duckdb_itest::{column, connect};

fn written(write: impl FnOnce(&mut String) -> std::fmt::Result) -> String {
    let mut text = String::new();
    write(&mut text).unwrap();
    text
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    written(|out| format::write_hex(bytes.as_ref(), out))
}

/// How the helpers of this crate render a value: `NULL` for SQL NULL.
fn or_null(value: Option<impl ToString>) -> String {
    value.map_or_else(|| "NULL".to_owned(), |value| value.to_string())
}

/// `expression` over every `i` in `0..count`, in order.
fn over_range(connection: &Connection, expression: &str, count: u32) -> Result<Vec<String>> {
    column(
        connection,
        &format!("SELECT {expression} FROM range({count}) t(i) ORDER BY i"),
    )
}

/// `expression` over a column `s` holding `texts`, in order.
fn over_texts(connection: &Connection, expression: &str, texts: &[&str]) -> Result<Vec<String>> {
    let mut values = String::new();
    for (i, text) in texts.iter().enumerate() {
        let separator = if i == 0 { "" } else { ", " };
        write!(values, "{separator}({i}, '{}')", text.replace('\'', "''")).unwrap();
    }
    column(
        connection,
        &format!("SELECT {expression} FROM (VALUES {values}) t(i, s) ORDER BY i"),
    )
}

/// A SQL list of the texts, to index with a row number.
fn sql_list(texts: &[&str]) -> String {
    let quoted: Vec<String> = texts.iter().map(|text| format!("'{text}'")).collect();
    format!("[{}]", quoted.join(", "))
}

fn assert_same(function: &str, actual: Vec<String>, expected: impl Iterator<Item = String>) {
    let expected: Vec<String> = expected.collect();
    assert_eq!(actual.len(), expected.len(), "{function}: row count");
    for (row, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        assert_eq!(actual, expected, "{function}, row {row}");
    }
}

#[test]
fn names_of_every_value() -> Result<()> {
    let connection = connect()?;
    assert_same(
        "ip_proto_name",
        over_range(&connection, "ip_proto_name(i::UTINYINT)", 256)?,
        (0..=u8::MAX).map(|i| format::ip_proto_name(i).into_owned()),
    );
    assert_same(
        "dns_type_name",
        over_range(&connection, "dns_type_name(i::USMALLINT)", 65536)?,
        (0..=u16::MAX).map(|i| format::dns_type_name(i).into_owned()),
    );
    assert_same(
        "dns_rcode_name",
        over_range(&connection, "dns_rcode_name(i::USMALLINT)", 65536)?,
        (0..=u16::MAX).map(|i| format::dns_rcode_name(i).into_owned()),
    );
    assert_same(
        "ethertype_name",
        over_range(&connection, "ethertype_name(i::USMALLINT)", 65536)?,
        (0..=u16::MAX).map(|i| format::ethertype_name(i).into_owned()),
    );
    Ok(())
}

#[test]
fn tcp_flags_of_every_value() -> Result<()> {
    let connection = connect()?;
    assert_same(
        "tcp_flags_str",
        over_range(&connection, "tcp_flags_str(i::USMALLINT)", 65536)?,
        (0..=u16::MAX).map(|i| written(|out| format::write_tcp_flags(i, out))),
    );

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
        "syn",
        "Ack",
        "",
        "SYNACK",
        "S",
        " SYN",
        // U+017F upper-cases to S.
        "\u{17f}yn",
    ];
    // The name as a literal.
    for name in names {
        assert_same(
            &format!("has_tcp_flag(_, {name:?})"),
            over_range(
                &connection,
                &format!("has_tcp_flag(i::USMALLINT, '{name}')"),
                1024,
            )?,
            (0..1024).map(|i| format::has_tcp_flag(i, name).to_string()),
        );
    }
    // The name as a column that changes from row to row.
    assert_same(
        "has_tcp_flag(_, column)",
        over_range(
            &connection,
            &format!(
                "has_tcp_flag((i * 7 % 512)::USMALLINT, {}[1 + i % {}])",
                sql_list(&names),
                names.len()
            ),
            4096,
        )?,
        (0..4096usize).map(|i| {
            format::has_tcp_flag((i * 7 % 512) as u16, names[i % names.len()]).to_string()
        }),
    );
    Ok(())
}

/// 4097 addresses spread from 0.0.0.0 to 255.255.240.0.
fn ip4_samples() -> impl Iterator<Item = u32> {
    (0..=4096u32).map(|i| i * 1_048_575)
}

const IP4_SAMPLES: &str = "(i * 1048575)::UINTEGER";
const IP4_SAMPLE_COUNT: u32 = 4097;

#[test]
fn ip4_addresses() -> Result<()> {
    let connection = connect()?;
    assert_same(
        "ip4_to_string",
        over_range(
            &connection,
            &format!("ip4_to_string({IP4_SAMPLES})"),
            IP4_SAMPLE_COUNT,
        )?,
        ip4_samples().map(format::format_ipv4),
    );
    assert_same(
        "ip4(ip4_to_string(_))",
        over_range(
            &connection,
            &format!("ip4(ip4_to_string({IP4_SAMPLES}))"),
            IP4_SAMPLE_COUNT,
        )?,
        ip4_samples().map(|ip| or_null(format::parse_ipv4(&format::format_ipv4(ip)))),
    );
    let texts = [
        "192.168.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "10.0.0.1",
        "1.2.3",
        "1.2.3.4.5",
        "256.1.1.1",
        "01.2.3.4",
        " 1.2.3.4",
        "1.2.3.4 ",
        "",
        "::1",
        "1.2.3.-4",
        "0x1.2.3.4",
        "\u{ff11}.2.3.4",
    ];
    assert_same(
        "ip4",
        over_texts(&connection, "ip4(s)", &texts)?,
        texts.iter().map(|text| or_null(format::parse_ipv4(text))),
    );

    let cidrs = [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.168.1.1/16",
        "255.255.240.0/32",
        "128.0.0.0/1",
        "10.0.0.0/33",
        "10.0.0.0",
        "10.0.0.0/",
        "/8",
        "10.0.0.0/8/8",
        "10.0.0.0/ 8",
        "10.0.0.0/+8",
        "10.0.0.0/08",
        "::/0",
        "",
        "bogus",
    ];
    let in_cidr = |ip: u32, cidr: &str| {
        or_null(
            format::parse_cidr_v4(cidr)
                .map(|(network, mask)| format::ipv4_in_cidr(ip, network, mask)),
        )
    };
    // The network as a literal.
    for cidr in cidrs {
        assert_same(
            &format!("ip_in_cidr(_, {cidr:?})"),
            over_range(
                &connection,
                &format!("ip_in_cidr({IP4_SAMPLES}, '{cidr}')"),
                IP4_SAMPLE_COUNT,
            )?,
            ip4_samples().map(|ip| in_cidr(ip, cidr)),
        );
    }
    // The network as a column that changes from row to row.
    assert_same(
        "ip_in_cidr(_, column)",
        over_range(
            &connection,
            &format!(
                "ip_in_cidr({IP4_SAMPLES}, {}[1 + i % {}])",
                sql_list(&cidrs),
                cidrs.len()
            ),
            IP4_SAMPLE_COUNT,
        )?,
        ip4_samples()
            .enumerate()
            .map(|(i, ip)| in_cidr(ip, cidrs[i % cidrs.len()])),
    );
    Ok(())
}

/// A blob of `len` bytes, and the SQL for the same blob where `i` is its length.
fn blob(len: u8) -> Vec<u8> {
    (0..len).map(|j| j.wrapping_mul(37) ^ len).collect()
}

const BLOB: &str = "from_hex(array_to_string(\
    list_transform(range(i), lambda j: format('{:02x}', xor((j * 37) % 256, i))), ''))";

#[test]
fn blobs_of_every_length() -> Result<()> {
    let connection = connect()?;
    assert_same(
        "pcap_hex",
        over_range(&connection, &format!("pcap_hex({BLOB})"), 200)?,
        (0..200).map(|len| hex(blob(len))),
    );
    // Only 16 bytes are an IPv6 address, and only 6 a MAC address.
    assert_same(
        "ip6_to_string",
        over_range(&connection, &format!("ip6_to_string({BLOB})"), 40)?,
        (0..40).map(|len| or_null(format::format_ipv6(&blob(len)))),
    );
    assert_same(
        "mac_to_string",
        over_range(&connection, &format!("mac_to_string({BLOB})"), 40)?,
        (0..40).map(|len| or_null(format::format_mac(&blob(len)))),
    );
    let network = format::parse_ipv6("1000::").unwrap();
    assert_same(
        "ip6_in_cidr",
        over_range(&connection, &format!("ip6_in_cidr({BLOB}, '1000::/4')"), 40)?,
        (0..40).map(|len| {
            let blob = blob(len);
            or_null((blob.len() == 16).then(|| format::ipv6_in_prefix(&blob, &network, 4)))
        }),
    );
    Ok(())
}

#[test]
fn ip6_addresses() -> Result<()> {
    let connection = connect()?;
    let texts = [
        "::",
        "::1",
        "2001:db8::1",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "fe80::1",
        "FE80::ABCD",
        "::ffff:192.168.1.1",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7",
        "1::2::3",
        "2001:db8::g",
        "192.168.1.1",
        "",
        " ::1",
        "::1 ",
        "[::1]",
        "fe80::1%eth0",
        "ff02::1",
        "2001:db8:0:0:1:0:0:1",
        "64:ff9b::1.2.3.4",
        "2001:db8:8000::",
    ];
    assert_same(
        "ip6",
        over_texts(&connection, "lower(hex(ip6(s)))", &texts)?,
        texts
            .iter()
            .map(|text| or_null(format::parse_ipv6(text).map(hex))),
    );
    assert_same(
        "ip6_to_string(ip6(_))",
        over_texts(&connection, "ip6_to_string(ip6(s))", &texts)?,
        texts.iter().map(|text| {
            or_null(format::parse_ipv6(text).and_then(|bytes| format::format_ipv6(&bytes)))
        }),
    );

    let cidrs = [
        "::/0",
        "::1/128",
        "2001:db8::/32",
        "2001:db8::/33",
        "fe80::/10",
        "ff00::/8",
        "::/129",
        "::1",
        "2001:db8::/",
        "10.0.0.0/8",
        "",
        "2001:db8::1/127",
        "1:2:3:4:5:6:7:8/64",
    ];
    let in_cidr = |text: &str, cidr: &str| {
        or_null(format::parse_ipv6(text).and_then(|ip| {
            format::parse_cidr_v6(cidr)
                .map(|(network, prefix_len)| format::ipv6_in_prefix(&ip, &network, prefix_len))
        }))
    };
    // The network as a literal.
    for cidr in cidrs {
        assert_same(
            &format!("ip6_in_cidr(_, {cidr:?})"),
            over_texts(
                &connection,
                &format!("ip6_in_cidr(ip6(s), '{cidr}')"),
                &texts,
            )?,
            texts.iter().map(|text| in_cidr(text, cidr)),
        );
    }
    // The network as a column: every address against every network.
    let pairs: Vec<(&str, &str)> = texts
        .iter()
        .flat_map(|text| cidrs.iter().map(move |cidr| (*text, *cidr)))
        .collect();
    assert_same(
        "ip6_in_cidr(_, column)",
        column(
            &connection,
            &format!(
                "SELECT ip6_in_cidr(ip6(a), c)
                 FROM (SELECT unnest({}) AS a, generate_subscripts({}, 1) AS ai) t,
                      (SELECT unnest({}) AS c, generate_subscripts({}, 1) AS ci) u
                 ORDER BY ai, ci",
                sql_list(&texts),
                sql_list(&texts),
                sql_list(&cidrs),
                sql_list(&cidrs)
            ),
        )?,
        pairs.iter().map(|(text, cidr)| in_cidr(text, cidr)),
    );
    Ok(())
}

#[test]
fn mac_addresses() -> Result<()> {
    let connection = connect()?;
    let texts = [
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "aabbccddeeff",
        "AABBCCDDEEFF",
        "a:b:c:d:e:f",
        "0-1-2-3-4-5",
        " aa:bb:cc:dd:ee:ff ",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aa:bb-cc:dd-ee:ff",
        "aabb.ccdd.eeff",
        "aabbccddeef",
        "aabbccddeefff",
        "gg:bb:cc:dd:ee:ff",
        "aaa:bb:cc:dd:ee:ff",
        "",
        ":::::",
        "+a:bb:cc:dd:ee:ff",
        "00:00:00:00:00:00",
    ];
    assert_same(
        "mac",
        over_texts(&connection, "lower(hex(mac(s)))", &texts)?,
        texts
            .iter()
            .map(|text| or_null(format::parse_mac(text).map(hex))),
    );
    assert_same(
        "mac_to_string(mac(_))",
        over_texts(&connection, "mac_to_string(mac(s))", &texts)?,
        texts.iter().map(|text| {
            or_null(format::parse_mac(text).and_then(|bytes| format::format_mac(&bytes)))
        }),
    );
    Ok(())
}

#[test]
fn hex_text() -> Result<()> {
    let connection = connect()?;
    let texts = [
        "",
        "00",
        "deadbeef",
        "DEADBEEF",
        "DeAdBeEf",
        "0xdead",
        "0Xdead",
        "0x",
        " dead ",
        "\tdead\n",
        "abc",
        "0xabc",
        "zz",
        "de ad",
        "de:ad",
        "0x0x00",
        "x0",
        "00112233445566778899aabbccddeeff00",
        "\u{e9}0",
        "+1",
    ];
    assert_same(
        "pcap_unhex",
        over_texts(&connection, "lower(hex(pcap_unhex(s)))", &texts)?,
        texts
            .iter()
            .map(|text| or_null(format::parse_hex(text).map(hex))),
    );
    Ok(())
}
