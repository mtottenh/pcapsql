//! The SQL functions against the kernels they wrap.
//!
//! For a table of inputs, what DuckDB returns must be what `pcapsql_core::format` returns. The
//! kernels are tested against the DataFusion functions in `pcapsql-datafusion`, so this ties the
//! two engines together. BLOB results are compared as hex text.

use std::fmt::Write;

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_core::format;
use pcapsql_duckdb_itest::{column, connect, rows};

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

/// Whether argument `argument` of row `i` of [`over_vectors`] is NULL: here and there in one
/// 64-row word of the validity mask in three, and in a run of 200 rows.
fn is_null(i: u32, argument: u32) -> bool {
    let run = 700 + 100 * argument;
    ((i / 64) % 3 == 1 && i % (5 + 2 * argument) == 3) || (run..run + 200).contains(&i)
}

/// `function` of the `arguments`, each an SQL expression of the row number `i`, over `count`
/// rows, against `expected` of the row number, in the three kinds of vector a function is
/// given: flat (the columns of a table, with the NULLs of [`is_null`]), dictionary (the rows a
/// hash join selects of them) and constant (one row, next to 3,000 others).
fn over_vectors(
    connection: &Connection,
    function: &str,
    arguments: &[&str],
    count: u32,
    expected: impl Fn(u32) -> String,
) -> Result<()> {
    let mut columns = String::new();
    let mut names = Vec::new();
    for (argument, expression) in arguments.iter().enumerate() {
        let (m, run) = (5 + 2 * argument, 700 + 100 * argument);
        write!(
            columns,
            ", CASE WHEN ((i // 64) % 3 = 1 AND i % {m} = 3) OR (i >= {run} AND i < {run} + 200)
                    THEN NULL ELSE {expression} END AS a{argument}"
        )
        .unwrap();
        names.push(format!("a{argument}"));
    }
    connection.execute(
        format!("CREATE OR REPLACE TABLE input AS SELECT i{columns} FROM range({count}) t(i)"),
        Parameters::None,
    )?;
    let call = format!("{function}({})", names.join(", "));
    let expected = |i: u32| {
        let null = (0..arguments.len() as u32).any(|argument| is_null(i, argument));
        or_null((!null).then(|| expected(i)))
    };

    assert_same(
        &format!("{function}, flat"),
        column(connection, &format!("SELECT {call} FROM input ORDER BY i"))?,
        (0..count).map(&expected),
    );
    assert_same(
        &format!("{function}, dictionary"),
        column(
            connection,
            &format!(
                "SELECT {call} FROM input JOIN (SELECT i FROM range(0, {count}, 3) t(i)) USING (i)
                 ORDER BY i"
            ),
        )?,
        (0..count).step_by(3).map(&expected),
    );
    // Rows with a NULL argument among them: 131 and 707 for the first, 135 for the second.
    for i in [0, 1, 131, 135, 200, 707, count / 2, count - 1] {
        let answer = expected(i);
        assert_eq!(
            rows(
                connection,
                &format!(
                    "SELECT count(*), min(x::VARCHAR), max(x::VARCHAR) FROM (
                         SELECT {call} AS x
                         FROM (SELECT * FROM input WHERE i = {i}) one, range(3000) t(n))"
                ),
            )?,
            [vec!["3000".to_owned(), answer.clone(), answer]],
            "{function}, constant, row {i}"
        );
    }
    Ok(())
}

/// A function of one argument and what its kernel answers, as text.
type Kernel<T> = (&'static str, fn(T) -> String);

/// A function that names a code of a type, and its kernel.
type CodeKernel = (&'static str, fn(u8, u8) -> format::Name);

/// A function that tests an address, the length of an address, and its kernel.
type AddressKernel = (&'static str, usize, fn(&[u8]) -> bool);

/// The addresses of the rows of a test: the SQL for the address of a row, given the expression
/// of its number; how many rows have a different address; and the address of a row.
type Addresses = (fn(&str) -> String, u32, fn(u32) -> Vec<u8>);

#[test]
fn names_of_every_byte() -> Result<()> {
    let connection = connect()?;
    let functions: [Kernel<u8>; 13] = [
        ("ip_proto_name", |i| format::ip_proto_name(i).to_string()),
        ("dscp_name", |i| format::dscp_name(i).to_string()),
        ("ecn_name", |i| format::ecn_name(i).to_owned()),
        ("icmp_type_name", |i| format::icmp_type_name(i).to_string()),
        ("icmpv6_type_name", |i| {
            format::icmpv6_type_name(i).to_string()
        }),
        ("bgp_message_type_name", |i| {
            format::bgp_message_type_name(i).to_string()
        }),
        ("bgp_origin_name", |i| {
            format::bgp_origin_name(i).to_string()
        }),
        ("ospf_packet_type_name", |i| {
            format::ospf_packet_type_name(i).to_string()
        }),
        ("ospf_lsa_type_name", |i| {
            format::ospf_lsa_type_name(i).to_string()
        }),
        ("gtp_message_type_name", |i| {
            format::gtp_message_type_name(i).to_string()
        }),
        ("ntp_mode_name", |i| format::ntp_mode_name(i).to_string()),
        ("ntp_stratum_name", |i| {
            format::ntp_stratum_name(i).to_string()
        }),
        ("tls_record_type_name", |i| {
            format::tls_record_type_name(i).to_string()
        }),
    ];
    for (function, kernel) in functions {
        assert_same(
            function,
            over_range(&connection, &format!("{function}(i::UTINYINT)"), 256)?,
            (0..=u8::MAX).map(kernel),
        );
        // Every value five times over, so that each is in a row that is not NULL.
        over_vectors(&connection, function, &["(i % 256)::UTINYINT"], 1280, |i| {
            kernel(i as u8)
        })?;
    }
    Ok(())
}

#[test]
fn names_of_every_word() -> Result<()> {
    let connection = connect()?;
    let functions: [Kernel<u16>; 5] = [
        ("dns_type_name", |i| format::dns_type_name(i).to_string()),
        ("dns_class_name", |i| format::dns_class_name(i).to_string()),
        ("dns_rcode_name", |i| format::dns_rcode_name(i).to_string()),
        ("ethertype_name", |i| format::ethertype_name(i).to_string()),
        ("tls_version_name", |i| {
            format::tls_version_name(i).to_string()
        }),
    ];
    for (function, kernel) in functions {
        assert_same(
            function,
            over_range(&connection, &format!("{function}(i::USMALLINT)"), 65536)?,
            (0..=u16::MAX).map(kernel),
        );
        // The values with names are low, but for the EtherTypes and the TLS versions, which
        // are around 0x0800 and above and around 0x0300: every 13th value reaches those.
        over_vectors(
            &connection,
            function,
            &["(i * 13 % 65536)::USMALLINT"],
            5041,
            |i| kernel((i * 13 % 65536) as u16),
        )?;
        over_vectors(&connection, function, &["i::USMALLINT"], 2500, |i| {
            kernel(i as u16)
        })?;
    }
    Ok(())
}

#[test]
fn names_of_every_type_and_code() -> Result<()> {
    let connection = connect()?;
    let functions: [CodeKernel; 2] = [
        ("icmp_code_name", format::icmp_code_name),
        ("icmpv6_code_name", format::icmpv6_code_name),
    ];
    for (function, kernel) in functions {
        assert_same(
            function,
            over_range(
                &connection,
                &format!("{function}((i // 256)::UTINYINT, (i % 256)::UTINYINT)"),
                65536,
            )?,
            (0..=u16::MAX).map(|i| kernel((i >> 8) as u8, i as u8).to_string()),
        );
        // Sixteen codes of every type, four times over; each argument has NULLs of its own.
        over_vectors(
            &connection,
            function,
            &["(i // 16 % 256)::UTINYINT", "(i % 16)::UTINYINT"],
            16384,
            |i| kernel((i / 16 % 256) as u8, (i % 16) as u8).to_string(),
        )?;
        // A type for the chunk and a code for the row, and the other way around.
        let one = "FROM (SELECT 3::UTINYINT AS three) one, range(256) t(i) ORDER BY i";
        assert_same(
            &format!("{function}(constant, column)"),
            column(
                &connection,
                &format!("SELECT {function}(three, i::UTINYINT) {one}"),
            )?,
            (0..=u8::MAX).map(|code| kernel(3, code).to_string()),
        );
        assert_same(
            &format!("{function}(column, constant)"),
            column(
                &connection,
                &format!("SELECT {function}(i::UTINYINT, three) {one}"),
            )?,
            (0..=u8::MAX).map(|t| kernel(t, 3).to_string()),
        );
    }
    Ok(())
}

#[test]
fn classes_of_ip4_addresses() -> Result<()> {
    let connection = connect()?;
    let functions: [Kernel<u32>; 3] = [
        ("is_private_ip", |ip| {
            format::is_private_ipv4(ip).to_string()
        }),
        ("is_loopback_ip", |ip| {
            format::is_loopback_ipv4(ip).to_string()
        }),
        ("is_multicast_ip", |ip| {
            format::is_multicast_ipv4(ip).to_string()
        }),
    ];
    // The first and the last address of every network the kernels know, and their neighbours.
    let edges = [
        "0.0.0.0",
        "9.255.255.255",
        "10.0.0.0",
        "10.255.255.255",
        "11.0.0.0",
        "126.255.255.255",
        "127.0.0.0",
        "127.0.0.1",
        "127.255.255.255",
        "128.0.0.0",
        "172.15.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "192.169.0.0",
        "223.255.255.255",
        "224.0.0.0",
        "239.255.255.255",
        "240.0.0.0",
        "255.255.255.255",
    ];
    for (function, kernel) in functions {
        // Every /16, each at a different address of it.
        assert_same(
            function,
            over_range(
                &connection,
                &format!("{function}((i * 65536 + i)::UINTEGER)"),
                65536,
            )?,
            (0..=65535u32).map(|i| kernel(i * 65536 + i)),
        );
        assert_same(
            &format!("{function}, edges"),
            over_texts(&connection, &format!("{function}(ip4(s))"), &edges)?,
            edges
                .iter()
                .map(|text| kernel(format::parse_ipv4(text).unwrap())),
        );
        // Every /16 again, in an order that puts each kind of address in every chunk.
        over_vectors(
            &connection,
            function,
            &["(i * 40503 % 65536 * 65536 + i)::UINTEGER"],
            65536,
            |i| kernel(i * 40503 % 65536 * 65536 + i),
        )?;
    }
    Ok(())
}

/// A 16-byte blob with the low 16 bits of `i` in its first two bytes, and the SQL for the same
/// blob where `row` is the expression of `i`.
fn ip6_of_row(i: u32) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[..2].copy_from_slice(&(i as u16).to_be_bytes());
    bytes[15] = 1;
    bytes
}

fn ip6_of_row_sql(row: &str) -> String {
    format!("from_hex(format('{{:04x}}', ({row}) % 65536) || repeat('00', 13) || '01')")
}

/// A 6-byte blob with the low 8 bits of `i` in its first byte, and the rest all ones in every
/// other 256 values of `i`, so that 511 is the broadcast address; and the SQL for the same blob
/// where `row` is the expression of `i`.
fn mac_of_row(i: u32) -> Vec<u8> {
    let rest = if i / 256 % 2 == 1 { 0xff } else { 0 };
    vec![i as u8, rest, rest, rest, rest, rest]
}

fn mac_of_row_sql(row: &str) -> String {
    format!(
        "from_hex(format('{{:02x}}', ({row}) % 256)
             || repeat(CASE WHEN ({row}) // 256 % 2 = 1 THEN 'ff' ELSE '00' END, 5))"
    )
}

#[test]
fn classes_of_ip6_and_mac_addresses() -> Result<()> {
    let connection = connect()?;
    let functions: [AddressKernel; 5] = [
        ("is_multicast_ip6", 16, format::is_multicast_ipv6),
        ("is_link_local_ip6", 16, format::is_link_local_ipv6),
        ("mac_is_broadcast", 6, format::is_broadcast_mac),
        ("mac_is_multicast", 6, format::is_multicast_mac),
        ("mac_is_local", 6, format::is_local_mac),
    ];
    for (function, len, kernel) in functions {
        // Only 16 bytes are an IPv6 address, and only 6 a MAC address: the kernels answer for
        // the first bytes of anything, and the functions return NULL for another length.
        assert_same(
            &format!("{function}, every length"),
            over_range(&connection, &format!("{function}({BLOB})"), 40)?,
            (0..40).map(|i| {
                let blob = blob(i);
                or_null((blob.len() == len).then(|| kernel(&blob)))
            }),
        );
        let (address, count, bytes): Addresses = if len == 16 {
            (ip6_of_row_sql, 65536, ip6_of_row)
        } else {
            (mac_of_row_sql, 512, mac_of_row)
        };
        assert_same(
            function,
            over_range(&connection, &format!("{function}({})", address("i")), count)?,
            (0..count).map(|i| kernel(&bytes(i)).to_string()),
        );
        // In an order that puts each kind of address in every chunk.
        over_vectors(&connection, function, &[&address("i * 40503")], 8192, |i| {
            kernel(&bytes(i * 40503)).to_string()
        })?;
    }
    assert_eq!(
        format::format_mac(&mac_of_row(511)).as_deref(),
        Some("ff:ff:ff:ff:ff:ff")
    );
    Ok(())
}
