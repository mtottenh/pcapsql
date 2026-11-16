//! The scalar functions other than `ip4` and `ip4_to_string` (see `extension.rs` for those),
//! queried in-process. `differential.rs` has every function against its kernel.
//!
//! The expected values are those of the DataFusion engine. Where the extension for DuckDB 1.x
//! answered differently, the test says so.

use duckdb_neo::{connection::Connection, Parameters, Result};
use pcapsql_duckdb_itest::{column, connect, rows, value};

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

/// `SELECT <expression>`, one value.
fn eval(connection: &Connection, expression: &str) -> Result<String> {
    value(connection, &format!("SELECT {expression}"))
}

/// A one-row table: joined to `range(n)`, its columns reach a function as constant vectors.
fn create_constants(connection: &Connection) -> Result<()> {
    connection.execute(
        "CREATE TABLE one AS SELECT
             '2001:db8::1' AS ip6_text, ip6('2001:db8::1') AS ip6_bytes,
             'aa:bb:cc:dd:ee:ff' AS mac_text, mac('aa:bb:cc:dd:ee:ff') AS mac_bytes,
             ip4('192.168.1.100') AS ip4_value, '192.168.0.0/16' AS cidr4, '2001:db8::/32' AS cidr6,
             18::USMALLINT AS flags, 'syn' AS flag, 6::UTINYINT AS proto, 28::USMALLINT AS qtype,
             3::USMALLINT AS rcode, 2048::USMALLINT AS ethertype,
             '\\xDE\\xAD'::BLOB AS bytes, 'dead' AS hex_text,
             3::UTINYINT AS icmp_type, 1::UTINYINT AS icmp_code, 46::UTINYINT AS dscp,
             771::USMALLINT AS tls_version, ip6('fe80::1') AS link_local,
             NULL::VARCHAR AS null_text, NULL::BLOB AS null_bytes, NULL::USMALLINT AS null_u16,
             NULL::UTINYINT AS null_u8, NULL::UINTEGER AS null_u32",
        Parameters::None,
    )?;
    Ok(())
}

/// Every scalar function of the extension: its parameters, their types and its return type.
const SIGNATURES: [(&str, &str, &str, &str); 40] = [
    (
        "bgp_message_type_name",
        "[message_type]",
        "[UTINYINT]",
        "VARCHAR",
    ),
    ("bgp_origin_name", "[origin]", "[UTINYINT]", "VARCHAR"),
    ("dns_class_name", "[class]", "[USMALLINT]", "VARCHAR"),
    ("dns_rcode_name", "[rcode]", "[USMALLINT]", "VARCHAR"),
    ("dns_type_name", "[qtype]", "[USMALLINT]", "VARCHAR"),
    ("dscp_name", "[dscp]", "[UTINYINT]", "VARCHAR"),
    ("ecn_name", "[ecn]", "[UTINYINT]", "VARCHAR"),
    ("ethertype_name", "[ethertype]", "[USMALLINT]", "VARCHAR"),
    (
        "gtp_message_type_name",
        "[message_type]",
        "[UTINYINT]",
        "VARCHAR",
    ),
    (
        "has_tcp_flag",
        "[flags, flag]",
        "[USMALLINT, VARCHAR]",
        "BOOLEAN",
    ),
    (
        "icmp_code_name",
        "[type, code]",
        "[UTINYINT, UTINYINT]",
        "VARCHAR",
    ),
    ("icmp_type_name", "[type]", "[UTINYINT]", "VARCHAR"),
    (
        "icmpv6_code_name",
        "[type, code]",
        "[UTINYINT, UTINYINT]",
        "VARCHAR",
    ),
    ("icmpv6_type_name", "[type]", "[UTINYINT]", "VARCHAR"),
    ("ip4", "[address]", "[VARCHAR]", "UINTEGER"),
    ("ip4_to_string", "[address]", "[UINTEGER]", "VARCHAR"),
    ("ip6", "[address]", "[VARCHAR]", "BLOB"),
    (
        "ip6_in_cidr",
        "[address, cidr]",
        "[BLOB, VARCHAR]",
        "BOOLEAN",
    ),
    ("ip6_to_string", "[address]", "[BLOB]", "VARCHAR"),
    (
        "ip_in_cidr",
        "[address, cidr]",
        "[UINTEGER, VARCHAR]",
        "BOOLEAN",
    ),
    ("ip_proto_name", "[protocol]", "[UTINYINT]", "VARCHAR"),
    ("is_link_local_ip6", "[address]", "[BLOB]", "BOOLEAN"),
    ("is_loopback_ip", "[address]", "[UINTEGER]", "BOOLEAN"),
    ("is_multicast_ip", "[address]", "[UINTEGER]", "BOOLEAN"),
    ("is_multicast_ip6", "[address]", "[BLOB]", "BOOLEAN"),
    ("is_private_ip", "[address]", "[UINTEGER]", "BOOLEAN"),
    ("mac", "[address]", "[VARCHAR]", "BLOB"),
    ("mac_is_broadcast", "[address]", "[BLOB]", "BOOLEAN"),
    ("mac_is_local", "[address]", "[BLOB]", "BOOLEAN"),
    ("mac_is_multicast", "[address]", "[BLOB]", "BOOLEAN"),
    ("mac_to_string", "[address]", "[BLOB]", "VARCHAR"),
    ("ntp_mode_name", "[mode]", "[UTINYINT]", "VARCHAR"),
    ("ntp_stratum_name", "[stratum]", "[UTINYINT]", "VARCHAR"),
    ("ospf_lsa_type_name", "[lsa_type]", "[UTINYINT]", "VARCHAR"),
    (
        "ospf_packet_type_name",
        "[packet_type]",
        "[UTINYINT]",
        "VARCHAR",
    ),
    ("pcap_hex", "[bytes]", "[BLOB]", "VARCHAR"),
    ("pcap_unhex", "[hex]", "[VARCHAR]", "BLOB"),
    ("tcp_flags_str", "[flags]", "[USMALLINT]", "VARCHAR"),
    (
        "tls_record_type_name",
        "[record_type]",
        "[UTINYINT]",
        "VARCHAR",
    ),
    ("tls_version_name", "[version]", "[USMALLINT]", "VARCHAR"),
];

#[test]
fn signatures() -> Result<()> {
    let connection = connect()?;
    let names: Vec<String> = SIGNATURES
        .iter()
        .map(|(name, ..)| format!("'{name}'"))
        .collect();
    let expected: Vec<Vec<String>> = SIGNATURES
        .iter()
        .map(|(name, parameters, types, returns)| row(&[name, parameters, types, returns]))
        .collect();
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT function_name, parameters::VARCHAR, parameter_types::VARCHAR, return_type
                 FROM duckdb_functions()
                 WHERE function_type = 'scalar' AND function_name IN ({})
                 ORDER BY function_name",
                names.join(", ")
            ),
        )?,
        expected
    );
    Ok(())
}

#[test]
fn ip6_parses_text() -> Result<()> {
    let connection = connect()?;
    assert_eq!(eval(&connection, "typeof(ip6('::1'))")?, "BLOB");
    assert_eq!(
        eval(&connection, "hex(ip6('2001:db8::1'))")?,
        "20010DB8000000000000000000000001"
    );
    assert_eq!(eval(&connection, "octet_length(ip6('::'))")?, "16");
    assert_eq!(
        eval(&connection, "hex(ip6('::ffff:192.168.1.1'))")?,
        "00000000000000000000FFFFC0A80101"
    );
    // Not an IPv6 address: NULL, not an error.
    for text in ["", "192.168.1.1", "2001:db8::g", "1::2::3", " ::1"] {
        assert_eq!(
            eval(&connection, &format!("ip6('{text}')"))?,
            "NULL",
            "{text:?}"
        );
    }
    assert_eq!(eval(&connection, "ip6(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT hex(ip6(x)) FROM (VALUES ('::1'), (NULL), ('bogus'), ('fe80::1')) t(x)",
        )?,
        [
            "00000000000000000000000000000001",
            "NULL",
            "NULL",
            "FE800000000000000000000000000001"
        ]
    );
    Ok(())
}

#[test]
fn ip6_to_string_formats_bytes() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        eval(&connection, "typeof(ip6_to_string(ip6('::1')))")?,
        "VARCHAR"
    );
    assert_eq!(
        eval(
            &connection,
            "ip6_to_string(ip6('2001:0db8:0000:0000:0000:0000:0000:0001'))"
        )?,
        "2001:db8::1"
    );
    assert_eq!(
        eval(
            &connection,
            "ip6_to_string(from_hex('00000000000000000000000000000000'))"
        )?,
        "::"
    );
    // A blob that is not 16 bytes is not an address.
    assert_eq!(
        eval(&connection, "ip6_to_string('\\x01\\x02'::BLOB)")?,
        "NULL"
    );
    assert_eq!(eval(&connection, "ip6_to_string(''::BLOB)")?, "NULL");
    assert_eq!(
        eval(&connection, "ip6_to_string(from_hex(repeat('00', 17)))")?,
        "NULL"
    );
    assert_eq!(eval(&connection, "ip6_to_string(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT ip6_to_string(x)
             FROM (VALUES (ip6('fe80::1')), (NULL), ('\\x00'::BLOB), (ip6('::1'))) t(x)",
        )?,
        ["fe80::1", "NULL", "NULL", "::1"]
    );
    Ok(())
}

#[test]
fn mac_parses_text() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        eval(&connection, "typeof(mac('aa:bb:cc:dd:ee:ff'))")?,
        "BLOB"
    );
    for text in [
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "Aa:bB:cc:DD:ee:ff",
    ] {
        assert_eq!(
            eval(&connection, &format!("hex(mac('{text}'))"))?,
            "AABBCCDDEEFF",
            "{text}"
        );
    }
    // As in DataFusion; the extension for DuckDB 1.x returned NULL for the 12-digit form.
    assert_eq!(
        eval(&connection, "hex(mac('aabbccddeeff'))")?,
        "AABBCCDDEEFF"
    );
    assert_eq!(
        eval(&connection, "hex(mac('  aa:bb:cc:dd:ee:ff '))")?,
        "AABBCCDDEEFF"
    );
    assert_eq!(
        eval(&connection, "hex(mac('a:b:c:d:e:f'))")?,
        "0A0B0C0D0E0F"
    );
    for text in [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "gg:bb:cc:dd:ee:ff",
        "aabbccddeef",
        "aa:bb-cc:dd-ee:ff",
    ] {
        assert_eq!(
            eval(&connection, &format!("mac('{text}')"))?,
            "NULL",
            "{text:?}"
        );
    }
    assert_eq!(eval(&connection, "mac(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT hex(mac(x))
             FROM (VALUES ('00:11:22:33:44:55'), (NULL), ('bogus'), ('ff-ff-ff-ff-ff-ff')) t(x)",
        )?,
        ["001122334455", "NULL", "NULL", "FFFFFFFFFFFF"]
    );
    Ok(())
}

#[test]
fn mac_to_string_formats_bytes() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        eval(&connection, "mac_to_string(from_hex('AABBCCDDEEFF'))")?,
        "aa:bb:cc:dd:ee:ff"
    );
    assert_eq!(
        eval(&connection, "mac_to_string(mac('0-1-2-3-4-5'))")?,
        "00:01:02:03:04:05"
    );
    assert_eq!(eval(&connection, "typeof(mac_to_string(NULL))")?, "VARCHAR");
    // A blob that is not 6 bytes is not an address.
    assert_eq!(
        eval(&connection, "mac_to_string(from_hex('AABBCCDDEE'))")?,
        "NULL"
    );
    assert_eq!(
        eval(&connection, "mac_to_string(from_hex('AABBCCDDEEFF00'))")?,
        "NULL"
    );
    assert_eq!(eval(&connection, "mac_to_string(ip6('::1'))")?, "NULL");
    assert_eq!(eval(&connection, "mac_to_string(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT mac_to_string(x) FROM (VALUES
                 (mac('00:11:22:33:44:55')), (NULL), (''::BLOB), (mac('ffffffffffff'))) t(x)",
        )?,
        ["00:11:22:33:44:55", "NULL", "NULL", "ff:ff:ff:ff:ff:ff"]
    );
    Ok(())
}

#[test]
fn ip_in_cidr_tests_membership() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        eval(&connection, "typeof(ip_in_cidr(1, '0.0.0.0/0'))")?,
        "BOOLEAN"
    );
    for (address, cidr, expected) in [
        ("192.168.1.100", "192.168.0.0/16", "true"),
        ("192.169.0.1", "192.168.0.0/16", "false"),
        ("10.0.0.1", "10.0.0.1/32", "true"),
        ("10.0.0.2", "10.0.0.1/32", "false"),
        ("8.8.8.8", "0.0.0.0/0", "true"),
        // Host bits in the network are ignored.
        ("192.168.200.1", "192.168.1.1/16", "true"),
        // Not CIDR notation: NULL, not an error.
        ("10.0.0.1", "10.0.0.0", "NULL"),
        ("10.0.0.1", "10.0.0.0/33", "NULL"),
        ("10.0.0.1", "10.0.0/8", "NULL"),
        ("10.0.0.1", "10.0.0.0/8/8", "NULL"),
        ("10.0.0.1", "::/0", "NULL"),
        ("10.0.0.1", "", "NULL"),
    ] {
        assert_eq!(
            eval(
                &connection,
                &format!("ip_in_cidr(ip4('{address}'), '{cidr}')")
            )?,
            expected,
            "{address} in {cidr}"
        );
    }
    assert_eq!(eval(&connection, "ip_in_cidr(NULL, '10.0.0.0/8')")?, "NULL");
    assert_eq!(
        eval(&connection, "ip_in_cidr(ip4('10.0.0.1'), NULL)")?,
        "NULL"
    );

    // A column of addresses against a literal network.
    assert_eq!(
        column(
            &connection,
            "SELECT ip_in_cidr(ip4(x), '10.0.0.0/8')
             FROM (VALUES ('10.1.2.3'), (NULL), ('11.0.0.1'), ('10.255.255.255')) t(x)",
        )?,
        ["true", "NULL", "false", "true"]
    );
    assert_eq!(
        column(
            &connection,
            "SELECT ip_in_cidr(ip4(x), 'not a network') FROM (VALUES ('10.1.2.3'), (NULL)) t(x)",
        )?,
        ["NULL", "NULL"]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM range(1024) t(i) WHERE ip_in_cidr(i::UINTEGER, '0.0.1.0/24')",
        )?,
        "256"
    );

    // A network per row: repeated, changing, invalid and NULL.
    assert_eq!(
        column(
            &connection,
            "SELECT ip_in_cidr(ip4(a), c) FROM (VALUES
                 ('10.1.2.3', '10.0.0.0/8'),
                 ('11.1.2.3', '10.0.0.0/8'),
                 ('11.1.2.3', '11.0.0.0/8'),
                 ('11.1.2.3', 'bogus'),
                 ('11.1.2.3', 'bogus'),
                 ('11.1.2.3', NULL),
                 (NULL, '11.0.0.0/8'),
                 ('11.1.2.3', '11.0.0.0/8'),
                 ('bogus', '11.0.0.0/8')) t(a, c)",
        )?,
        ["true", "false", "true", "NULL", "NULL", "NULL", "NULL", "true", "NULL"]
    );
    // Over several chunks: every third row has a network, every third has text that is not
    // one, every third has NULL.
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), count(hit), count(*) FILTER (hit) FROM (
                 SELECT ip_in_cidr(i::UINTEGER,
                                   CASE i % 3 WHEN 0 THEN '0.0.0.0/22' WHEN 1 THEN 'x' END) AS hit
                 FROM range(6000) t(i))",
        )?,
        [row(&["6000", "2000", "342"])]
    );
    Ok(())
}

#[test]
fn ip6_in_cidr_tests_membership() -> Result<()> {
    let connection = connect()?;
    for (address, cidr, expected) in [
        ("fe80::1", "fe80::/10", "true"),
        ("2001:db8::1", "fe80::/10", "false"),
        ("2001:db8:ffff::1", "2001:db8::/32", "true"),
        ("2001:db9::1", "2001:db8::/32", "false"),
        ("::1", "::1/128", "true"),
        ("::2", "::1/128", "false"),
        ("abcd::1", "::/0", "true"),
        // A prefix that ends inside a byte.
        ("2001:db8:8000::", "2001:db8::/33", "false"),
        ("2001:db8:7fff::", "2001:db8::/33", "true"),
        // Not CIDR notation: NULL, not an error.
        ("::1", "::1", "NULL"),
        ("::1", "::/129", "NULL"),
        ("::1", "10.0.0.0/8", "NULL"),
        ("::1", "", "NULL"),
    ] {
        assert_eq!(
            eval(
                &connection,
                &format!("ip6_in_cidr(ip6('{address}'), '{cidr}')")
            )?,
            expected,
            "{address} in {cidr}"
        );
    }
    assert_eq!(
        eval(&connection, "typeof(ip6_in_cidr(NULL, NULL))")?,
        "BOOLEAN"
    );
    assert_eq!(eval(&connection, "ip6_in_cidr(NULL, '::/0')")?, "NULL");
    assert_eq!(eval(&connection, "ip6_in_cidr(ip6('::1'), NULL)")?, "NULL");
    // A blob that is not 16 bytes is not an address, whatever the network.
    assert_eq!(
        eval(&connection, "ip6_in_cidr('\\x01'::BLOB, '::/0')")?,
        "NULL"
    );
    assert_eq!(
        eval(&connection, "ip6_in_cidr(mac('aa:bb:cc:dd:ee:ff'), '::/0')")?,
        "NULL"
    );

    assert_eq!(
        column(
            &connection,
            "SELECT ip6_in_cidr(ip6(a), '2001:db8::/32')
             FROM (VALUES ('2001:db8::5'), (NULL), ('::1'), ('2001:db8:1::')) t(a)",
        )?,
        ["true", "NULL", "false", "true"]
    );
    assert_eq!(
        column(
            &connection,
            "SELECT ip6_in_cidr(a, c) FROM (VALUES
                 (ip6('fe80::1'), 'fe80::/10'),
                 (ip6('fe80::1'), 'ff00::/8'),
                 (ip6('fe80::1'), 'bogus'),
                 ('\\x00'::BLOB, 'fe80::/10'),
                 (ip6('fe80::1'), NULL),
                 (NULL, 'fe80::/10'),
                 (ip6('febf::'), 'fe80::/10')) t(a, c)",
        )?,
        ["true", "false", "NULL", "NULL", "NULL", "NULL", "true"]
    );
    Ok(())
}

#[test]
fn tcp_flags_str_names_the_set_flags() -> Result<()> {
    let connection = connect()?;
    assert_eq!(eval(&connection, "typeof(tcp_flags_str(0))")?, "VARCHAR");
    for (flags, expected) in [
        (2, "SYN"),
        (18, "SYN,ACK"),
        (17, "FIN,ACK"),
        (4, "RST"),
        (24, "PSH,ACK"),
        (511, "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS"),
        (256, "NS"),
        // Bits above NS are not flags.
        (1026, "SYN"),
    ] {
        assert_eq!(
            eval(&connection, &format!("tcp_flags_str({flags})"))?,
            expected,
            "{flags}"
        );
    }
    // As in DataFusion, no flag is the empty string; the extension for DuckDB 1.x gave 'NONE'.
    assert_eq!(eval(&connection, "tcp_flags_str(0) = ''")?, "true");
    assert_eq!(eval(&connection, "tcp_flags_str(512) = ''")?, "true");
    assert_eq!(eval(&connection, "tcp_flags_str(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT tcp_flags_str(x) FROM (VALUES (2::USMALLINT), (NULL), (0), (16)) t(x)",
        )?,
        ["SYN", "NULL", "", "ACK"]
    );
    Ok(())
}

#[test]
fn has_tcp_flag_tests_one_flag() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        eval(&connection, "typeof(has_tcp_flag(0, 'SYN'))")?,
        "BOOLEAN"
    );
    for (flags, name, expected) in [
        (18, "SYN", "true"),
        (18, "ACK", "true"),
        (18, "syn", "true"),
        (18, "Ack", "true"),
        (18, "RST", "false"),
        (18, "FIN", "false"),
        (256, "NS", "true"),
        (0, "SYN", "false"),
        // A name that is not a flag is never set: false, not NULL and not an error.
        (511, "BOGUS", "false"),
        (511, "", "false"),
        (511, " SYN", "false"),
    ] {
        assert_eq!(
            eval(&connection, &format!("has_tcp_flag({flags}, '{name}')"))?,
            expected,
            "{flags} {name:?}"
        );
    }
    assert_eq!(eval(&connection, "has_tcp_flag(NULL, 'SYN')")?, "NULL");
    assert_eq!(eval(&connection, "has_tcp_flag(18, NULL)")?, "NULL");

    assert_eq!(
        column(
            &connection,
            "SELECT has_tcp_flag(x, 'ack') FROM (VALUES (2::USMALLINT), (NULL), (18), (16)) t(x)",
        )?,
        ["false", "NULL", "true", "true"]
    );
    assert_eq!(
        column(
            &connection,
            "SELECT has_tcp_flag(x, 'nothing') FROM (VALUES (2::USMALLINT), (NULL), (511)) t(x)",
        )?,
        ["false", "NULL", "false"]
    );
    // A flag name per row.
    assert_eq!(
        column(
            &connection,
            "SELECT has_tcp_flag(f, n) FROM (VALUES
                 (18::USMALLINT, 'SYN'), (18, 'SYN'), (18, 'RST'), (4, 'RST'), (4, NULL),
                 (NULL, 'RST'), (4, 'bogus'), (4, 'rst')) t(f, n)",
        )?,
        ["true", "true", "false", "true", "NULL", "NULL", "false", "true"]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM range(512) t(i)
             WHERE has_tcp_flag(i::USMALLINT, 'SYN') AND NOT has_tcp_flag(i::USMALLINT, 'ACK')",
        )?,
        "128"
    );
    Ok(())
}

#[test]
fn dns_type_name_names_record_types() -> Result<()> {
    let connection = connect()?;
    assert_eq!(eval(&connection, "typeof(dns_type_name(1))")?, "VARCHAR");
    for (qtype, expected) in [
        (1, "A"),
        (2, "NS"),
        (5, "CNAME"),
        (15, "MX"),
        (16, "TXT"),
        (28, "AAAA"),
        (33, "SRV"),
        (65, "HTTPS"),
        (255, "ANY"),
        (257, "CAA"),
        // Types the extension for DuckDB 1.x did not know (it gave TYPE99, TYPE64, TYPE32769).
        (99, "SPF"),
        (64, "SVCB"),
        (32769, "DLV"),
        // Unassigned.
        (0, "TYPE0"),
        (12345, "TYPE12345"),
        (65535, "TYPE65535"),
    ] {
        assert_eq!(
            eval(&connection, &format!("dns_type_name({qtype})"))?,
            expected,
            "{qtype}"
        );
    }
    assert_eq!(eval(&connection, "dns_type_name(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT dns_type_name(x) FROM (VALUES (1::USMALLINT), (NULL), (4242), (28)) t(x)",
        )?,
        ["A", "NULL", "TYPE4242", "AAAA"]
    );
    Ok(())
}

#[test]
fn dns_rcode_name_names_response_codes() -> Result<()> {
    let connection = connect()?;
    for (rcode, expected) in [
        (0, "NOERROR"),
        (1, "FORMERR"),
        (2, "SERVFAIL"),
        (3, "NXDOMAIN"),
        (5, "REFUSED"),
        (16, "BADVERS"),
        (23, "BADCOOKIE"),
        (24, "RCODE24"),
        (255, "RCODE255"),
        // Above 255 there are no names. The extension for DuckDB 1.x looked at the low byte
        // only: 256 was NOERROR and 259 was NXDOMAIN.
        (256, "RCODE256"),
        (259, "RCODE259"),
        (4095, "RCODE4095"),
        (65535, "RCODE65535"),
    ] {
        assert_eq!(
            eval(&connection, &format!("dns_rcode_name({rcode})"))?,
            expected,
            "{rcode}"
        );
    }
    assert_eq!(eval(&connection, "dns_rcode_name(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT dns_rcode_name(x) FROM (VALUES (3::USMALLINT), (NULL), (259), (0)) t(x)",
        )?,
        ["NXDOMAIN", "NULL", "RCODE259", "NOERROR"]
    );
    Ok(())
}

#[test]
fn ip_proto_name_names_protocols() -> Result<()> {
    let connection = connect()?;
    for (protocol, expected) in [
        (1, "ICMP"),
        (6, "TCP"),
        (17, "UDP"),
        (47, "GRE"),
        (58, "ICMPv6"),
        (89, "OSPF"),
        // The IANA table; the extension for DuckDB 1.x knew 11 protocols and gave PROTO4,
        // PROTO0 and PROTO136 here.
        (4, "IPv4"),
        (0, "HOPOPT"),
        (136, "UDPLite"),
        // Unassigned: 'Proto 200', where the extension for DuckDB 1.x gave 'PROTO200'.
        (200, "Proto 200"),
        (255, "Proto 255"),
    ] {
        assert_eq!(
            eval(&connection, &format!("ip_proto_name({protocol})"))?,
            expected,
            "{protocol}"
        );
    }
    assert_eq!(eval(&connection, "ip_proto_name(NULL)")?, "NULL");
    // The argument is UTINYINT.
    assert!(eval(&connection, "ip_proto_name(256)").is_err());
    assert_eq!(
        column(
            &connection,
            "SELECT ip_proto_name(x) FROM (VALUES (6::UTINYINT), (NULL), (201), (17)) t(x)",
        )?,
        ["TCP", "NULL", "Proto 201", "UDP"]
    );
    Ok(())
}

#[test]
fn ethertype_name_names_ethertypes() -> Result<()> {
    let connection = connect()?;
    for (ethertype, expected) in [
        (0x0800, "IPv4"),
        (0x0806, "ARP"),
        (0x86DD, "IPv6"),
        (0x8100, "VLAN"),
        (0x88CC, "LLDP"),
        // Spelled as in DataFusion; the extension for DuckDB 1.x gave 'PPPoE-Discovery',
        // 'MPLS-MC' and 'EAPoL'.
        (0x8863, "PPPoE Discovery"),
        (0x8848, "MPLS Multicast"),
        (0x888E, "EAP over LAN"),
        // Unknown: the value in hex.
        (0x1234, "0x1234"),
        (0x00ab, "0x00AB"),
        (0xFFFF, "0xFFFF"),
    ] {
        assert_eq!(
            eval(&connection, &format!("ethertype_name({ethertype})"))?,
            expected,
            "{ethertype}"
        );
    }
    assert_eq!(eval(&connection, "ethertype_name(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT ethertype_name(x) FROM (VALUES (2048::USMALLINT), (NULL), (1), (34525)) t(x)",
        )?,
        ["IPv4", "NULL", "0x0001", "IPv6"]
    );
    Ok(())
}

#[test]
fn pcap_hex_encodes_bytes() -> Result<()> {
    let connection = connect()?;
    assert_eq!(eval(&connection, "typeof(pcap_hex(''::BLOB))")?, "VARCHAR");
    assert_eq!(
        eval(&connection, "pcap_hex('\\xDE\\xAD\\xBE\\xEF'::BLOB)")?,
        "deadbeef"
    );
    assert_eq!(eval(&connection, "pcap_hex('\\x00\\x0F'::BLOB)")?, "000f");
    assert_eq!(eval(&connection, "pcap_hex(''::BLOB) = ''")?, "true");
    assert_eq!(eval(&connection, "pcap_hex(NULL)")?, "NULL");
    assert_eq!(
        eval(&connection, "pcap_hex(mac('AA:BB:CC:DD:EE:FF'))")?,
        "aabbccddeeff"
    );
    // Longer than DuckDB stores inline, and longer than one block of the kernel.
    assert_eq!(
        eval(
            &connection,
            "pcap_hex(from_hex(repeat('0123456789ABCDEF', 100))) = repeat('0123456789abcdef', 100)"
        )?,
        "true"
    );
    assert_eq!(
        column(
            &connection,
            "SELECT pcap_hex(x) FROM (VALUES
                 ('\\x01'::BLOB), (NULL), (''::BLOB), ('\\xFF\\x00'::BLOB)) t(x)",
        )?,
        ["01", "NULL", "", "ff00"]
    );
    Ok(())
}

#[test]
fn pcap_unhex_decodes_text() -> Result<()> {
    let connection = connect()?;
    assert_eq!(eval(&connection, "typeof(pcap_unhex('00'))")?, "BLOB");
    assert_eq!(
        eval(&connection, "hex(pcap_unhex('deadbeef'))")?,
        "DEADBEEF"
    );
    assert_eq!(
        eval(&connection, "hex(pcap_unhex('DeAdBeEf'))")?,
        "DEADBEEF"
    );
    assert_eq!(eval(&connection, "octet_length(pcap_unhex(''))")?, "0");
    // As in DataFusion; the extension for DuckDB 1.x returned NULL for each of these.
    assert_eq!(eval(&connection, "hex(pcap_unhex('  dead '))")?, "DEAD");
    assert_eq!(eval(&connection, "hex(pcap_unhex('0xdead'))")?, "DEAD");
    assert_eq!(eval(&connection, "hex(pcap_unhex(' 0Xdead\n'))")?, "DEAD");
    for text in ["abc", "zz", "de ad", "de:ad", "0x0xdead", "0xabc"] {
        assert_eq!(
            eval(&connection, &format!("pcap_unhex('{text}')"))?,
            "NULL",
            "{text:?}"
        );
    }
    assert_eq!(eval(&connection, "pcap_unhex(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT hex(pcap_unhex(x)) FROM (VALUES ('01'), (NULL), ('odd'), (''), ('ff00')) t(x)",
        )?,
        ["01", "NULL", "NULL", "", "FF00"]
    );
    // One buffer takes the bytes of every row of a chunk: a row gets its own bytes and nothing
    // of what a longer row, or one that stopped at a character that is not hex, left there.
    assert_eq!(
        column(
            &connection,
            "SELECT hex(pcap_unhex(x)) FROM (VALUES
                 ('00112233445566778899aabbccddeeff0123'), ('ab'), ('0011223344zz'), (''),
                 ('abc'), ('cd'), (NULL), ('ef01'), ('0x'), ('FFEEDDCCBBAA99887766554433221100'))
                 t(x)",
        )?,
        [
            "00112233445566778899AABBCCDDEEFF0123",
            "AB",
            "NULL",
            "",
            "NULL",
            "CD",
            "NULL",
            "EF01",
            "",
            "FFEEDDCCBBAA99887766554433221100"
        ]
    );
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), count(b), bool_and(pcap_hex(b) = h) FROM (
                 SELECT h, pcap_unhex(h) AS b FROM (
                     SELECT CASE WHEN i % 5 <> 0
                                 THEN repeat(format('{:04x}', i), (1 + i % 40)::INTEGER) END AS h
                     FROM range(5000) t(i)))",
        )?,
        [row(&["5000", "4000", "true"])]
    );
    Ok(())
}

#[test]
fn round_trips_keep_nulls_over_many_chunks() -> Result<()> {
    let connection = connect()?;
    // More rows than one vector holds, with a NULL every seventh row.
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), count(s), count(DISTINCT s), bool_and(ip6(s) = b),
                    bool_and(pcap_hex(b) = h)
             FROM (SELECT h, b, ip6_to_string(b) AS s FROM (
                 SELECT h, pcap_unhex(h) AS b FROM (
                     SELECT CASE WHEN i % 7 <> 0
                                 THEN format('20010db8{:08x}{:016x}', i, i * 977) END AS h
                     FROM range(10000) t(i))))",
        )?,
        [row(&["10000", "8571", "8571", "true", "true"])]
    );
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), count(s), count(DISTINCT s), bool_and(mac(s) = b),
                    bool_and(mac(replace(s, ':', '')) = b), bool_and(mac(replace(s, ':', '-')) = b)
             FROM (SELECT b, mac_to_string(b) AS s FROM (
                 SELECT pcap_unhex(CASE WHEN i % 7 <> 0
                                        THEN format('{:012x}', i * 1000003) END) AS b
                 FROM range(10000) t(i)))",
        )?,
        [row(&["10000", "8571", "8571", "true", "true", "true"])]
    );
    Ok(())
}

#[test]
fn constant_vectors() -> Result<()> {
    let connection = connect()?;
    create_constants(&connection)?;
    // A cross join hands the one-row side to the function as a constant vector spanning the
    // whole chunk (see `scalars_read_constant_vectors` in extension.rs).
    let from = "FROM one, range(3000) t(i)";
    for (expression, expected) in [
        ("hex(ip6(ip6_text))", "20010DB8000000000000000000000001"),
        ("ip6_to_string(ip6_bytes)", "2001:db8::1"),
        ("hex(mac(mac_text))", "AABBCCDDEEFF"),
        ("mac_to_string(mac_bytes)", "aa:bb:cc:dd:ee:ff"),
        ("ip_in_cidr(ip4_value, cidr4)", "true"),
        ("ip_in_cidr(ip4_value, '10.0.0.0/8')", "false"),
        ("ip6_in_cidr(ip6_bytes, cidr6)", "true"),
        ("ip6_in_cidr(ip6_bytes, 'fe80::/10')", "false"),
        ("tcp_flags_str(flags)", "SYN,ACK"),
        ("has_tcp_flag(flags, flag)", "true"),
        ("has_tcp_flag(flags, 'RST')", "false"),
        ("dns_type_name(qtype)", "AAAA"),
        ("dns_rcode_name(rcode)", "NXDOMAIN"),
        ("ip_proto_name(proto)", "TCP"),
        ("ethertype_name(ethertype)", "IPv4"),
        ("pcap_hex(bytes)", "dead"),
        ("hex(pcap_unhex(hex_text))", "DEAD"),
        ("dns_class_name(rcode)", "CH"),
        ("dscp_name(dscp)", "EF"),
        ("ecn_name(icmp_type)", "CE"),
        ("icmp_type_name(icmp_type)", "Destination Unreachable"),
        ("icmpv6_type_name(icmp_type)", "Time Exceeded"),
        ("icmp_code_name(icmp_type, icmp_code)", "Host Unreachable"),
        ("icmp_code_name(icmp_type, 3)", "Port Unreachable"),
        (
            "icmp_code_name(11, icmp_code)",
            "Fragment Reassembly Time Exceeded",
        ),
        (
            "icmpv6_code_name(icmp_code, icmp_type)",
            "Address Unreachable",
        ),
        ("bgp_message_type_name(icmp_type)", "NOTIFICATION"),
        ("bgp_origin_name(icmp_code)", "EGP"),
        ("ospf_packet_type_name(icmp_type)", "Link State Request"),
        ("ospf_lsa_type_name(icmp_code)", "Router-LSA"),
        ("gtp_message_type_name(icmp_code)", "Echo Request"),
        ("ntp_mode_name(icmp_type)", "Client"),
        ("ntp_stratum_name(icmp_type)", "Secondary (stratum 3)"),
        ("ntp_stratum_name(dscp)", "Reserved (46)"),
        ("tls_record_type_name(proto)", "Unknown (6)"),
        ("tls_version_name(tls_version)", "TLS 1.2"),
        ("tls_version_name(qtype)", "Unknown (0x001c)"),
        ("is_private_ip(ip4_value)", "true"),
        ("is_loopback_ip(ip4_value)", "false"),
        ("is_multicast_ip(ip4_value)", "false"),
        ("is_multicast_ip6(ip6_bytes)", "false"),
        ("is_link_local_ip6(link_local)", "true"),
        ("mac_is_broadcast(mac_bytes)", "false"),
        ("mac_is_multicast(mac_bytes)", "false"),
        ("mac_is_local(mac_bytes)", "true"),
    ] {
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*), min(x)::VARCHAR, max(x)::VARCHAR
                     FROM (SELECT {expression} AS x {from})"
                ),
            )?,
            [row(&["3000", expected, expected])],
            "{expression}"
        );
    }

    // A constant pattern next to a column of values, and a constant value next to a column of
    // patterns.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*) FILTER (ip_in_cidr(i::UINTEGER, cidr4)),
                        count(*) FILTER (ip_in_cidr((ip4_value + i)::UINTEGER, cidr4)),
                        count(*) FILTER (ip_in_cidr(ip4_value, '192.168.1.0/' || (i % 33))),
                        count(*) FILTER (has_tcp_flag(i::USMALLINT, flag)),
                        count(*) FILTER (has_tcp_flag(
                            flags, CASE i % 3 WHEN 0 THEN 'SYN' WHEN 1 THEN 'RST' ELSE 'ack' END)),
                        count(*) FILTER (ip6_in_cidr(ip6_bytes, '2001:db8::/' || (i % 200)))
                 {from}"
            ),
        )?,
        // 192.168.1.100 is in 192.168.1.0/n for n up to 25; 2001:db8::1 is in 2001:db8::/n for
        // n up to 127, and n above 128 is not a prefix length.
        [row(&["0", "3000", "2366", "1500", "2000", "1920"])]
    );

    // A constant NULL stays NULL in every row, in either argument.
    for expression in [
        "ip6(null_text)",
        "ip6_to_string(null_bytes)",
        "mac(null_text)",
        "mac_to_string(null_bytes)",
        "ip_in_cidr(ip4_value, null_text)",
        "ip_in_cidr(i::UINTEGER, null_text)",
        "ip_in_cidr(NULL::UINTEGER, cidr4)",
        "ip6_in_cidr(ip6_bytes, null_text)",
        "ip6_in_cidr(null_bytes, cidr6)",
        "tcp_flags_str(null_u16)",
        "has_tcp_flag(null_u16, flag)",
        "has_tcp_flag(flags, null_text)",
        "has_tcp_flag(i::USMALLINT, null_text)",
        "dns_type_name(null_u16)",
        "dns_rcode_name(null_u16)",
        "ip_proto_name(null_u16::UTINYINT)",
        "ethertype_name(null_u16)",
        "pcap_hex(null_bytes)",
        "pcap_unhex(null_text)",
        "dns_class_name(null_u16)",
        "dscp_name(null_u8)",
        "ecn_name(null_u8)",
        "icmp_type_name(null_u8)",
        "icmpv6_type_name(null_u8)",
        "icmp_code_name(null_u8, icmp_code)",
        "icmp_code_name(icmp_type, null_u8)",
        "icmp_code_name(null_u8, (i % 256)::UTINYINT)",
        "icmp_code_name((i % 256)::UTINYINT, null_u8)",
        "icmpv6_code_name(null_u8, null_u8)",
        "bgp_message_type_name(null_u8)",
        "bgp_origin_name(null_u8)",
        "ospf_packet_type_name(null_u8)",
        "ospf_lsa_type_name(null_u8)",
        "gtp_message_type_name(null_u8)",
        "ntp_mode_name(null_u8)",
        "ntp_stratum_name(null_u8)",
        "tls_record_type_name(null_u8)",
        "tls_version_name(null_u16)",
        "is_private_ip(null_u32)",
        "is_loopback_ip(null_u32)",
        "is_multicast_ip(null_u32)",
        "is_multicast_ip6(null_bytes)",
        "is_link_local_ip6(null_bytes)",
        "mac_is_broadcast(null_bytes)",
        "mac_is_multicast(null_bytes)",
        "mac_is_local(null_bytes)",
        // A constant that is not a pattern, or not an address.
        "ip_in_cidr(i::UINTEGER, mac_text)",
        "ip6_in_cidr(ip6_bytes, cidr4)",
        "ip6_in_cidr(mac_bytes, cidr6)",
        "ip6_to_string(mac_bytes)",
        "mac_to_string(ip6_bytes)",
        "is_multicast_ip6(mac_bytes)",
        "is_link_local_ip6(mac_bytes)",
        "mac_is_broadcast(ip6_bytes)",
        "mac_is_multicast(ip6_bytes)",
        "mac_is_local(link_local)",
        "ip6(mac_text)",
        "mac(ip6_text)",
        "pcap_unhex(mac_text)",
    ] {
        assert_eq!(
            rows(
                &connection,
                &format!("SELECT count(*), count({expression}) {from}")
            )?,
            [row(&["3000", "0"])],
            "{expression}"
        );
    }
    Ok(())
}

#[test]
fn dictionary_vectors() -> Result<()> {
    let connection = connect()?;
    connection.execute(
        "CREATE TABLE packets AS SELECT
             i, (i * 65537)::UINTEGER AS ip, (i % 512)::USMALLINT AS flags,
             pcap_unhex(format('{:012x}', i)) AS mac_bytes, format('{:012x}', i) AS mac_text,
             CASE i % 4 WHEN 0 THEN '0.0.0.0/1' WHEN 1 THEN 'bogus' WHEN 2 THEN '128.0.0.0/1' END
                 AS cidr
         FROM range(6000) t(i)",
        Parameters::None,
    )?;
    // A hash join passes on the probe rows that matched as a selection over the scanned vector
    // (see `scalars_read_dictionary_vectors` in extension.rs).
    let from = "FROM packets JOIN (SELECT i FROM range(1, 6000, 3) t(i)) USING (i)";
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*),
                        count(*) FILTER (tcp_flags_str(flags) = tcp_flags_str((i % 512)::USMALLINT)),
                        count(*) FILTER (has_tcp_flag(flags, 'SYN') = (((i % 512) & 2) <> 0)),
                        count(*) FILTER (mac_to_string(mac_bytes) = mac_to_string(pcap_unhex(mac_text))),
                        count(*) FILTER (mac(mac_text) = mac_bytes),
                        count(*) FILTER (pcap_hex(mac_bytes) = mac_text),
                        count(*) FILTER (ip_in_cidr(ip, '0.1.0.0/16') = (i = 1)),
                        count(ip_in_cidr(ip, cidr)),
                        count(*) FILTER (ip_in_cidr(ip, cidr))
                 {from}"
            ),
        )?,
        // Of the 2000 joined rows, half have a network in `cidr`, and every address is below
        // 128.0.0.0.
        [row(&["2000", "2000", "2000", "2000", "2000", "2000", "2000", "1000", "500"])]
    );
    // The new functions against themselves over the same value computed from the row number,
    // which is not behind the selection; `differential.rs` has each against its kernel.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*) FILTER (
                            dscp_name((flags % 256)::UTINYINT) = dscp_name((i % 256)::UTINYINT)),
                        count(*) FILTER (
                            icmp_code_name((flags % 256)::UTINYINT, (flags % 16)::UTINYINT)
                            = icmp_code_name((i % 256)::UTINYINT, (i % 16)::UTINYINT)),
                        count(*) FILTER (tls_version_name(flags) = tls_version_name((i % 512)::USMALLINT)),
                        count(*) FILTER (is_private_ip(ip) = (i BETWEEN 2560 AND 2815)),
                        count(*) FILTER (is_private_ip(ip)),
                        count(*) FILTER (mac_is_local(mac_bytes) = ((i >> 40) & 2 = 2)),
                        count(*) FILTER (is_multicast_ip6(mac_bytes) IS NULL)
                 {from}"
            ),
        )?,
        // The address of row `i` is `i` twice, in its high and its low half: 10.x.x.x is `i`
        // from 2560 to 2815, a third of which are joined.
        [row(&["2000", "2000", "2000", "2000", "86", "2000", "2000"])]
    );
    Ok(())
}

/// `ip_in_cidr` and `has_tcp_flag` with a literal pattern store the answers of a chunk at once
/// and then make the rows of NULL values NULL from the input's validity mask: a NULL at any row
/// of a chunk (the first and last of a 64-row word of the mask, a run across two chunks) stays
/// NULL, and every other row has its own answer.
#[test]
fn a_constant_pattern_keeps_nulls_at_any_row() -> Result<()> {
    let connection = connect()?;
    connection.execute(
        "CREATE TABLE sparse AS SELECT i,
             CASE WHEN i % 64 IN (0, 63) OR i % 7 = 3 OR i BETWEEN 2040 AND 2110
                       OR i BETWEEN 4096 AND 4159
                  THEN NULL ELSE i END AS x
         FROM range(10000) t(i)",
        Parameters::None,
    )?;
    // The scanned vectors, then the same rows behind the selection of a hash join.
    for from in [
        "FROM sparse",
        "FROM sparse JOIN (SELECT i FROM range(0, 10000, 3) t(i)) USING (i)",
    ] {
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*) = count(*) FILTER (
                                ip_in_cidr(x::UINTEGER, '0.0.16.0/20')
                                IS NOT DISTINCT FROM ((x & 4294963200) = 4096)),
                            count(*) = count(*) FILTER (
                                has_tcp_flag((x % 512)::USMALLINT, 'syn')
                                IS NOT DISTINCT FROM (((x % 512) & 2) <> 0)),
                            count(*) - count(x) = count(*) FILTER (
                                ip_in_cidr(x::UINTEGER, '0.0.16.0/20') IS NULL),
                            count(*) FILTER (ip_in_cidr(x::UINTEGER, '0.0.16.0/20')) > 0,
                            count(*) FILTER (ip_in_cidr(x::UINTEGER, 'no network') IS NULL)
                                = count(*)
                     {from}"
                ),
            )?,
            [row(&["true", "true", "true", "true", "true"])],
            "{from}"
        );
    }
    Ok(())
}

/// What `ip_in_cidr` answers for the two networks of [`create_flat`], and `has_tcp_flag` for its
/// two flags, in SQL.
const CIDR_SQL: [&str; 2] = ["(ip & 4294967232) = 64", "(ip & 4294967040) = 0"];
const FLAG_SQL: [&str; 2] = ["(flags & 2) <> 0", "(flags & 16) <> 0"];

/// The table `flat`: `n` rows of an address and TCP flags, both NULL in the rows where `null`,
/// an expression of the row number `i` and of `n`, is true; and a network and a flag name that
/// differ from one row to the next, so that as arguments they are not a constant.
fn create_flat(connection: &Connection, n: usize, null: &str) -> Result<()> {
    connection.execute(
        format!(
            "CREATE OR REPLACE TABLE flat AS SELECT i,
                 CASE WHEN {null} THEN NULL ELSE (i * 37 % 300)::UINTEGER END AS ip,
                 CASE WHEN {null} THEN NULL ELSE (i * 37 % 512)::USMALLINT END AS flags,
                 CASE WHEN i % 2 = 0 THEN '0.0.0.64/26' ELSE '0.0.0.0/24' END AS cidr,
                 CASE WHEN i % 2 = 0 THEN 'SYN' ELSE 'ack' END AS flag
             FROM (SELECT i, {n} AS n FROM range({n}) t(i))"
        ),
        Parameters::None,
    )?;
    Ok(())
}

/// The answers of `ip_in_cidr` and `has_tcp_flag` for the rows of `flat`, with a literal
/// pattern and with the pattern of the row, against each other and against the expression in
/// SQL; and the NULLs of the answers against the NULLs of the values.
fn check_flat(connection: &Connection, context: &str) -> Result<()> {
    let [cidr_even, cidr_odd] = CIDR_SQL;
    let [flag_even, flag_odd] = FLAG_SQL;
    let cidr = format!("CASE WHEN i % 2 = 0 THEN {cidr_even} ELSE {cidr_odd} END");
    let flag = format!("CASE WHEN i % 2 = 0 THEN {flag_even} ELSE {flag_odd} END");

    // The functions as the projection of the scan of the table, whose vectors are flat: each
    // literal pattern for every row, and the pattern of the row.
    connection.execute(
        "CREATE OR REPLACE TABLE answered AS SELECT i, ip, flags,
             ip_in_cidr(ip, '0.0.0.64/26') AS cidr_even, ip_in_cidr(ip, '0.0.0.0/24') AS cidr_odd,
             ip_in_cidr(ip, cidr) AS cidr_row,
             has_tcp_flag(flags, 'SYN') AS flag_even, has_tcp_flag(flags, 'ack') AS flag_odd,
             has_tcp_flag(flags, flag) AS flag_row,
             ip_in_cidr(ip, 'no network') AS no_cidr, has_tcp_flag(flags, 'no flag') AS no_flag
         FROM flat",
        Parameters::None,
    )?;
    assert_eq!(
        rows(
            connection,
            &format!(
                "SELECT count(*) FILTER (cidr_even IS DISTINCT FROM ({cidr_even})),
                        count(*) FILTER (cidr_odd IS DISTINCT FROM ({cidr_odd})),
                        count(*) FILTER (
                            CASE WHEN i % 2 = 0 THEN cidr_even ELSE cidr_odd END
                            IS DISTINCT FROM cidr_row),
                        count(*) FILTER (flag_even IS DISTINCT FROM ({flag_even})),
                        count(*) FILTER (flag_odd IS DISTINCT FROM ({flag_odd})),
                        count(*) FILTER (
                            CASE WHEN i % 2 = 0 THEN flag_even ELSE flag_odd END
                            IS DISTINCT FROM flag_row),
                        count(*) FILTER (
                            (ip IS NULL) <> (cidr_even IS NULL) OR (ip IS NULL) <> (cidr_odd IS NULL)
                            OR (ip IS NULL) <> (cidr_row IS NULL)),
                        count(*) FILTER (
                            (flags IS NULL) <> (flag_even IS NULL)
                            OR (flags IS NULL) <> (flag_odd IS NULL)
                            OR (flags IS NULL) <> (flag_row IS NULL)),
                        count(*) FILTER (no_cidr IS NOT NULL),
                        count(*) FILTER (no_flag IS DISTINCT FROM (flags - flags <> 0))
                 FROM answered"
            ),
        )?,
        [row(&["0"; 10])],
        "{context}, projected"
    );

    // The same in one expression, where a `CASE` gives the function the rows of each branch
    // behind a selection, and behind the selection of a hash join.
    for (kind, from) in [
        ("flat", "FROM flat"),
        (
            "dictionary",
            "FROM flat JOIN (SELECT i FROM range(0, 40000, 3) t(i)) USING (i)",
        ),
    ] {
        assert_eq!(
            rows(
                connection,
                &format!(
                    "SELECT count(*) FILTER (
                                CASE WHEN i % 2 = 0 THEN ip_in_cidr(ip, '0.0.0.64/26')
                                     ELSE ip_in_cidr(ip, '0.0.0.0/24') END
                                IS DISTINCT FROM ip_in_cidr(ip, cidr)),
                            count(*) FILTER (
                                ip_in_cidr(ip, cidr) IS DISTINCT FROM ({cidr})),
                            count(*) FILTER (
                                ip_in_cidr(ip, '0.0.0.64/26') IS DISTINCT FROM ({cidr_even})),
                            count(*) FILTER (
                                CASE WHEN i % 2 = 0 THEN has_tcp_flag(flags, 'SYN')
                                     ELSE has_tcp_flag(flags, 'ack') END
                                IS DISTINCT FROM has_tcp_flag(flags, flag)),
                            count(*) FILTER (
                                has_tcp_flag(flags, flag) IS DISTINCT FROM ({flag})),
                            count(*) FILTER (
                                has_tcp_flag(flags, 'ack') IS DISTINCT FROM ({flag_odd})),
                            count(*) FILTER (ip_in_cidr(ip, 'no network') IS NOT NULL),
                            count(*) FILTER (has_tcp_flag(flags, 'no flag')),
                            count(ip_in_cidr(ip, '0.0.0.0/24')) = count(ip),
                            count(has_tcp_flag(flags, 'ack')) = count(flags)
                     {from}"
                ),
            )?,
            [row(&[
                "0", "0", "0", "0", "0", "0", "0", "0", "true", "true"
            ])],
            "{context}, {kind}"
        );
    }
    Ok(())
}

/// The numbers of rows of the tests of a flat chunk: around a word of the validity mask and
/// around a chunk.
const CHUNK_SIZES: [usize; 13] = [0, 1, 2, 63, 64, 65, 127, 128, 129, 2047, 2048, 2049, 4097];

/// The NULLs of the tests of a flat chunk: a name, and the rows that are NULL as an expression
/// of the row number `i` and the number of rows `n`.
const NULLS: [(&str, &str); 21] = [
    ("none", "false"),
    ("first", "i = 0"),
    ("last", "i = n - 1"),
    ("first of each word", "i % 64 = 0"),
    ("last of each word", "i % 64 = 63"),
    ("word edges", "i % 64 IN (0, 63)"),
    ("all but the first of each word", "i % 64 <> 0"),
    ("all but the last of each word", "i % 64 <> 63"),
    ("chunk edges", "i IN (2047, 2048)"),
    ("alternate rows", "i % 2 = 0"),
    ("alternate words", "i // 64 % 2 = 0"),
    ("the other alternate words", "i // 64 % 2 = 1"),
    ("some", "i % 7 = 3"),
    (
        "one of each word, and one word in five",
        "i % 64 = 3 OR i // 64 % 5 = 0",
    ),
    (
        "one of each word but one word in five",
        "i % 64 = 3 AND i // 64 % 5 <> 0",
    ),
    (
        "one of each word but one word in three",
        "i % 64 = 3 AND i // 64 % 3 <> 0",
    ),
    ("1% at random", "hash(i) % 100 < 1"),
    ("50% at random", "hash(i) % 100 < 50"),
    ("99% at random", "hash(i) % 100 < 99"),
    ("all but one", "i <> n / 2"),
    ("all", "true"),
];

/// `ip_in_cidr` and `has_tcp_flag` with a literal pattern read the values of a flat chunk as
/// slices, of the rows of the 64-row words of the validity mask that have no NULL, and the rows
/// of the other words a row at a time or not at all; a chunk with NULLs in most of its words,
/// and one behind a selection, they read a row at a time. They answer what the per-row path
/// answers (the one a pattern from a column takes) and what the expression in SQL does, and
/// their NULLs are those of the values: for chunks of every size around a word of the mask and
/// around a whole chunk, with no NULL, a NULL in every row, at either end, at one edge of each
/// word or both, in every row but that edge, in alternate rows and in alternate words, in most
/// words with the others whole or NULL, here and there, and in 1%, 50% and 99% of the rows at
/// random; and for the same rows behind a constant vector and behind the selection of a hash
/// join.
#[test]
fn a_constant_pattern_answers_like_the_per_row_path() -> Result<()> {
    let connection = connect()?;
    for n in CHUNK_SIZES {
        for (name, null) in NULLS {
            create_flat(&connection, n, null)?;
            check_flat(&connection, &format!("{n} rows, NULLs: {name}"))?;
        }
        // One value for every row of the chunk: a constant vector.
        let all = n.to_string();
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*),
                            count(*) FILTER (ip_in_cidr(ip, '0.0.0.64/26')),
                            count(*) FILTER (NOT ip_in_cidr(ip, '0.0.0.0/26')),
                            count(ip_in_cidr(missing, '0.0.0.0/0')),
                            count(*) FILTER (has_tcp_flag(flags, 'ack')),
                            count(*) FILTER (NOT has_tcp_flag(flags, 'fin')),
                            count(has_tcp_flag(no_flags, 'ack'))
                     FROM (SELECT 100::UINTEGER AS ip, NULL::UINTEGER AS missing,
                                  18::USMALLINT AS flags, NULL::USMALLINT AS no_flags) one,
                          range({n}) t(i)"
                ),
            )?,
            [row(&[&all, &all, &all, "0", &all, &all, "0"])],
            "{n} rows, constant"
        );
    }
    Ok(())
}

/// The same for NULLs in runs, as the `tcp_flags` of packets that are not TCP are: a run of
/// every length from 1 to 200 rows, each starting at a different row of its word of the
/// validity mask, with from 1 to 97 rows that are not NULL between one run and the next.
#[test]
fn a_constant_pattern_answers_around_runs_of_nulls() -> Result<()> {
    let connection = connect()?;
    let mut next = 0;
    let runs: Vec<String> = (1..=200)
        .map(|length| {
            let start = next + length * 37 % 97 + 1;
            next = start + length;
            format!("({start}, {next})")
        })
        .collect();
    connection.execute(
        format!(
            "CREATE TABLE null_rows AS SELECT unnest(range(first, last)) AS i
             FROM (VALUES {}) run(first, last)",
            runs.join(", ")
        ),
        Parameters::None,
    )?;
    // Rows after the last run, and a last word of the mask that is not whole.
    let n = next + 77;
    create_flat(&connection, n, "i IN (SELECT i FROM null_rows)")?;
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), count(*) - count(ip), count(*) - count(flags) FROM flat"
        )?,
        [row(&[&n.to_string(), "20100", "20100"])]
    );
    check_flat(&connection, "runs of NULLs")
}

/// `expected` for each expression, then NULL for a NULL argument of each function named.
fn check_values(connection: &Connection, values: &[(&str, &str)]) -> Result<()> {
    for (expression, expected) in values {
        assert_eq!(eval(connection, expression)?, *expected, "{expression}");
    }
    Ok(())
}

#[test]
fn names_of_ip_and_icmp_numbers() -> Result<()> {
    let connection = connect()?;
    check_values(
        &connection,
        &[
            ("dscp_name(0)", "CS0/BE"),
            ("dscp_name(8)", "CS1"),
            ("dscp_name(10)", "AF11"),
            ("dscp_name(46)", "EF"),
            ("dscp_name(44)", "VA"),
            ("dscp_name(1)", "LE"),
            // A code point without a name.
            ("dscp_name(63)", "DSCP63"),
            // Only the low six bits are the code point.
            ("dscp_name(110)", "EF"),
            ("dscp_name(255)", "DSCP63"),
            ("ecn_name(0)", "Not-ECT"),
            ("ecn_name(1)", "ECT(1)"),
            ("ecn_name(2)", "ECT(0)"),
            ("ecn_name(3)", "CE"),
            // Only the low two bits.
            ("ecn_name(7)", "CE"),
            ("ecn_name(252)", "Not-ECT"),
            ("icmp_type_name(0)", "Echo Reply"),
            ("icmp_type_name(3)", "Destination Unreachable"),
            ("icmp_type_name(8)", "Echo Request"),
            ("icmp_type_name(11)", "Time Exceeded"),
            ("icmp_type_name(200)", "Type 200"),
            ("icmpv6_type_name(1)", "Destination Unreachable"),
            ("icmpv6_type_name(128)", "Echo Request"),
            ("icmpv6_type_name(135)", "Neighbor Solicitation"),
            (
                "icmpv6_type_name(143)",
                "Version 2 Multicast Listener Report",
            ),
            ("icmpv6_type_name(250)", "Type 250"),
            // The code is named for its type.
            ("icmp_code_name(3, 3)", "Port Unreachable"),
            (
                "icmp_code_name(3, 13)",
                "Communication Administratively Prohibited",
            ),
            ("icmp_code_name(3, 99)", "Destination Unreachable (code 99)"),
            ("icmp_code_name(11, 0)", "TTL Exceeded in Transit"),
            ("icmp_code_name(5, 1)", "Redirect for Host"),
            ("icmp_code_name(8, 0)", "No Code"),
            ("icmp_code_name(8, 7)", "Code 7"),
            ("icmp_code_name(40, 2)", "Code 2"),
            ("icmpv6_code_name(1, 0)", "No Route to Destination"),
            ("icmpv6_code_name(1, 4)", "Port Unreachable"),
            (
                "icmpv6_code_name(1, 77)",
                "Destination Unreachable (code 77)",
            ),
            (
                "icmpv6_code_name(3, 1)",
                "Fragment Reassembly Time Exceeded",
            ),
            ("icmpv6_code_name(135, 0)", "No Code"),
            ("icmpv6_code_name(135, 5)", "Code 5"),
            ("icmpv6_code_name(138, 1)", "Router Renumbering Result"),
            ("icmpv6_code_name(139, 9)", "NI Query (code 9)"),
            ("dscp_name(NULL)", "NULL"),
            ("ecn_name(NULL)", "NULL"),
            ("icmp_type_name(NULL)", "NULL"),
            ("icmpv6_type_name(NULL)", "NULL"),
            // NULL when either argument is.
            ("icmp_code_name(NULL, 0)", "NULL"),
            ("icmp_code_name(3, NULL)", "NULL"),
            ("icmp_code_name(NULL, NULL)", "NULL"),
            ("icmpv6_code_name(NULL, 0)", "NULL"),
            ("icmpv6_code_name(1, NULL)", "NULL"),
            ("typeof(icmp_code_name(3, 3))", "VARCHAR"),
            ("typeof(ecn_name(0))", "VARCHAR"),
        ],
    )?;
    // The arguments are UTINYINT.
    for expression in [
        "dscp_name(256)",
        "ecn_name(-1)",
        "icmp_type_name(256)",
        "icmp_code_name(3, 256)",
        "icmp_code_name(256, 3)",
        "icmpv6_code_name(1, -1)",
    ] {
        assert!(eval(&connection, expression).is_err(), "{expression}");
    }
    assert_eq!(
        rows(
            &connection,
            "SELECT icmp_type_name(t), icmp_code_name(t, c), icmpv6_code_name(t, c), ecn_name(c)
             FROM (VALUES (3::UTINYINT, 1::UTINYINT), (NULL, 1), (3, NULL), (8, 0), (1, 200),
                          (NULL, NULL)) v(t, c)",
        )?,
        [
            row(&[
                "Destination Unreachable",
                "Host Unreachable",
                "Fragment Reassembly Time Exceeded",
                "ECT(1)"
            ]),
            row(&["NULL", "NULL", "NULL", "ECT(1)"]),
            row(&["Destination Unreachable", "NULL", "NULL", "NULL"]),
            row(&["Echo Request", "No Code", "No Code", "Not-ECT"]),
            row(&[
                "Type 1",
                "Code 200",
                "Destination Unreachable (code 200)",
                "Not-ECT"
            ]),
            row(&["NULL", "NULL", "NULL", "NULL"]),
        ]
    );
    Ok(())
}

#[test]
fn names_of_application_protocol_numbers() -> Result<()> {
    let connection = connect()?;
    check_values(
        &connection,
        &[
            ("dns_class_name(1)", "IN"),
            ("dns_class_name(3)", "CH"),
            ("dns_class_name(4)", "HS"),
            ("dns_class_name(254)", "NONE"),
            ("dns_class_name(255)", "ANY"),
            ("dns_class_name(2)", "CLASS2"),
            ("dns_class_name(65535)", "CLASS65535"),
            ("bgp_message_type_name(1)", "OPEN"),
            ("bgp_message_type_name(2)", "UPDATE"),
            ("bgp_message_type_name(3)", "NOTIFICATION"),
            ("bgp_message_type_name(4)", "KEEPALIVE"),
            ("bgp_message_type_name(5)", "ROUTE-REFRESH"),
            ("bgp_message_type_name(0)", "Unknown (0)"),
            ("bgp_message_type_name(9)", "Unknown (9)"),
            ("bgp_origin_name(0)", "IGP"),
            ("bgp_origin_name(1)", "EGP"),
            ("bgp_origin_name(2)", "INCOMPLETE"),
            ("bgp_origin_name(3)", "Unknown (3)"),
            ("ospf_packet_type_name(1)", "Hello"),
            ("ospf_packet_type_name(2)", "Database Description"),
            ("ospf_packet_type_name(3)", "Link State Request"),
            ("ospf_packet_type_name(4)", "Link State Update"),
            ("ospf_packet_type_name(5)", "Link State Acknowledgment"),
            ("ospf_packet_type_name(0)", "Unknown (0)"),
            ("ospf_packet_type_name(6)", "Unknown (6)"),
            ("ospf_lsa_type_name(1)", "Router-LSA"),
            ("ospf_lsa_type_name(2)", "Network-LSA"),
            ("ospf_lsa_type_name(3)", "Summary-LSA-Network"),
            ("ospf_lsa_type_name(5)", "AS-External-LSA"),
            ("ospf_lsa_type_name(7)", "NSSA-External-LSA"),
            ("ospf_lsa_type_name(11)", "Opaque-AS-LSA"),
            ("ospf_lsa_type_name(0)", "Unknown (0)"),
            ("ospf_lsa_type_name(12)", "Unknown (12)"),
            ("gtp_message_type_name(1)", "Echo Request"),
            ("gtp_message_type_name(16)", "Create PDP Context Request"),
            ("gtp_message_type_name(26)", "Error Indication"),
            ("gtp_message_type_name(100)", "Delete Bearer Response"),
            ("gtp_message_type_name(255)", "G-PDU"),
            ("gtp_message_type_name(0)", "Unknown (0)"),
            ("ntp_mode_name(0)", "Reserved"),
            ("ntp_mode_name(1)", "Symmetric Active"),
            ("ntp_mode_name(3)", "Client"),
            ("ntp_mode_name(4)", "Server"),
            ("ntp_mode_name(5)", "Broadcast"),
            ("ntp_mode_name(7)", "Private"),
            // The mode is three bits of the header; the function takes a byte.
            ("ntp_mode_name(8)", "Unknown (8)"),
            ("ntp_stratum_name(0)", "Unspecified"),
            ("ntp_stratum_name(1)", "Primary Reference"),
            ("ntp_stratum_name(2)", "Secondary (stratum 2)"),
            ("ntp_stratum_name(15)", "Secondary (stratum 15)"),
            ("ntp_stratum_name(16)", "Unsynchronized"),
            ("ntp_stratum_name(17)", "Reserved (17)"),
            ("ntp_stratum_name(255)", "Reserved (255)"),
            ("tls_record_type_name(20)", "ChangeCipherSpec"),
            ("tls_record_type_name(21)", "Alert"),
            ("tls_record_type_name(22)", "Handshake"),
            ("tls_record_type_name(23)", "ApplicationData"),
            ("tls_record_type_name(24)", "Heartbeat"),
            ("tls_record_type_name(0)", "Unknown (0)"),
            ("tls_record_type_name(25)", "Unknown (25)"),
            ("tls_version_name(768)", "SSL 3.0"),
            ("tls_version_name(769)", "TLS 1.0"),
            ("tls_version_name(770)", "TLS 1.1"),
            ("tls_version_name(771)", "TLS 1.2"),
            ("tls_version_name(772)", "TLS 1.3"),
            // A version without a name is the value in hex.
            ("tls_version_name(0)", "Unknown (0x0000)"),
            ("tls_version_name(773)", "Unknown (0x0305)"),
            ("tls_version_name(65535)", "Unknown (0xffff)"),
            ("dns_class_name(NULL)", "NULL"),
            ("bgp_message_type_name(NULL)", "NULL"),
            ("bgp_origin_name(NULL)", "NULL"),
            ("ospf_packet_type_name(NULL)", "NULL"),
            ("ospf_lsa_type_name(NULL)", "NULL"),
            ("gtp_message_type_name(NULL)", "NULL"),
            ("ntp_mode_name(NULL)", "NULL"),
            ("ntp_stratum_name(NULL)", "NULL"),
            ("tls_record_type_name(NULL)", "NULL"),
            ("tls_version_name(NULL)", "NULL"),
        ],
    )?;
    // The arguments are UTINYINT, and USMALLINT for a DNS class and a TLS version.
    for expression in [
        "bgp_message_type_name(256)",
        "ntp_stratum_name(-1)",
        "tls_record_type_name(256)",
        "dns_class_name(65536)",
        "tls_version_name(65536)",
    ] {
        assert!(eval(&connection, expression).is_err(), "{expression}");
    }
    // Text made of the number between names, in one chunk: each row gets its own.
    assert_eq!(
        column(
            &connection,
            "SELECT bgp_message_type_name(x) FROM (VALUES
                 (200::UTINYINT), (1), (NULL), (7), (2), (201), (NULL), (4)) t(x)",
        )?,
        [
            "Unknown (200)",
            "OPEN",
            "NULL",
            "Unknown (7)",
            "UPDATE",
            "Unknown (201)",
            "NULL",
            "KEEPALIVE"
        ]
    );
    Ok(())
}

#[test]
fn ip4_addresses_are_classified() -> Result<()> {
    let connection = connect()?;
    check_values(
        &connection,
        &[
            ("typeof(is_private_ip(0))", "BOOLEAN"),
            ("is_private_ip(ip4('10.0.0.0'))", "true"),
            ("is_private_ip(ip4('10.255.255.255'))", "true"),
            ("is_private_ip(ip4('9.255.255.255'))", "false"),
            ("is_private_ip(ip4('11.0.0.0'))", "false"),
            ("is_private_ip(ip4('172.16.0.0'))", "true"),
            ("is_private_ip(ip4('172.31.255.255'))", "true"),
            ("is_private_ip(ip4('172.15.255.255'))", "false"),
            ("is_private_ip(ip4('172.32.0.0'))", "false"),
            ("is_private_ip(ip4('192.168.0.0'))", "true"),
            ("is_private_ip(ip4('192.168.255.255'))", "true"),
            ("is_private_ip(ip4('192.169.0.0'))", "false"),
            ("is_private_ip(ip4('8.8.8.8'))", "false"),
            // RFC 1918 only: not the loopback, link-local or shared address space.
            ("is_private_ip(ip4('127.0.0.1'))", "false"),
            ("is_private_ip(ip4('169.254.1.1'))", "false"),
            ("is_private_ip(ip4('100.64.0.1'))", "false"),
            ("is_loopback_ip(ip4('127.0.0.0'))", "true"),
            ("is_loopback_ip(ip4('127.0.0.1'))", "true"),
            ("is_loopback_ip(ip4('127.255.255.255'))", "true"),
            ("is_loopback_ip(ip4('126.255.255.255'))", "false"),
            ("is_loopback_ip(ip4('128.0.0.0'))", "false"),
            ("is_multicast_ip(ip4('224.0.0.0'))", "true"),
            ("is_multicast_ip(ip4('224.0.0.251'))", "true"),
            ("is_multicast_ip(ip4('239.255.255.255'))", "true"),
            ("is_multicast_ip(ip4('223.255.255.255'))", "false"),
            ("is_multicast_ip(ip4('240.0.0.0'))", "false"),
            ("is_multicast_ip(ip4('255.255.255.255'))", "false"),
            // A literal that fits UINTEGER is an address.
            ("is_private_ip(167772161)", "true"),
            ("is_private_ip(NULL)", "NULL"),
            ("is_loopback_ip(NULL)", "NULL"),
            ("is_multicast_ip(NULL)", "NULL"),
            // Text that is not an address is NULL from `ip4`, and stays NULL.
            ("is_private_ip(ip4('10.0.0'))", "NULL"),
        ],
    )?;
    // The argument is UINTEGER: not text, and not a number that is no address.
    for expression in [
        "is_private_ip('10.0.0.1')",
        "is_private_ip(4294967296)",
        "is_loopback_ip(-1)",
        "is_multicast_ip(ip6('ff02::1'))",
    ] {
        assert!(eval(&connection, expression).is_err(), "{expression}");
    }
    assert_eq!(
        rows(
            &connection,
            "SELECT is_private_ip(ip4(x)), is_loopback_ip(ip4(x)), is_multicast_ip(ip4(x))
             FROM (VALUES ('192.168.1.1'), (NULL), ('127.0.0.1'), ('224.0.0.1'), ('bogus'),
                          ('1.1.1.1')) t(x)",
        )?,
        [
            row(&["true", "false", "false"]),
            row(&["NULL", "NULL", "NULL"]),
            row(&["false", "true", "false"]),
            row(&["false", "false", "true"]),
            row(&["NULL", "NULL", "NULL"]),
            row(&["false", "false", "false"]),
        ]
    );
    Ok(())
}

#[test]
fn ip6_and_mac_addresses_are_classified() -> Result<()> {
    let connection = connect()?;
    check_values(
        &connection,
        &[
            ("typeof(is_multicast_ip6(ip6('::')))", "BOOLEAN"),
            ("is_multicast_ip6(ip6('ff02::1'))", "true"),
            ("is_multicast_ip6(ip6('ff00::'))", "true"),
            ("is_multicast_ip6(ip6('fe80::1'))", "false"),
            ("is_multicast_ip6(ip6('::ffff:224.0.0.1'))", "false"),
            ("is_link_local_ip6(ip6('fe80::1'))", "true"),
            ("is_link_local_ip6(ip6('febf:ffff::1'))", "true"),
            ("is_link_local_ip6(ip6('fec0::1'))", "false"),
            ("is_link_local_ip6(ip6('fe7f::1'))", "false"),
            ("is_link_local_ip6(ip6('::1'))", "false"),
            ("mac_is_broadcast(mac('ff:ff:ff:ff:ff:ff'))", "true"),
            ("mac_is_broadcast(mac('ff:ff:ff:ff:ff:fe'))", "false"),
            ("mac_is_broadcast(mac('00:00:00:00:00:00'))", "false"),
            ("mac_is_multicast(mac('01:00:5e:00:00:fb'))", "true"),
            ("mac_is_multicast(mac('33:33:00:00:00:01'))", "true"),
            // The broadcast address is a group address.
            ("mac_is_multicast(mac('ff:ff:ff:ff:ff:ff'))", "true"),
            ("mac_is_multicast(mac('00:11:22:33:44:55'))", "false"),
            ("mac_is_multicast(mac('02:11:22:33:44:55'))", "false"),
            ("mac_is_local(mac('02:00:00:00:00:01'))", "true"),
            ("mac_is_local(mac('fe:ff:ff:ff:ff:ff'))", "true"),
            ("mac_is_local(mac('00:11:22:33:44:55'))", "false"),
            ("mac_is_local(mac('01:00:5e:00:00:fb'))", "false"),
            ("is_multicast_ip6(NULL)", "NULL"),
            ("is_link_local_ip6(NULL)", "NULL"),
            ("mac_is_broadcast(NULL)", "NULL"),
            ("mac_is_multicast(NULL)", "NULL"),
            ("mac_is_local(NULL)", "NULL"),
            // A blob that is not 16 bytes is not an IPv6 address, and one that is not 6 is not
            // a MAC address, whatever its first bytes are.
            ("is_multicast_ip6('\\xFF'::BLOB)", "NULL"),
            ("is_multicast_ip6(mac('ff:ff:ff:ff:ff:ff'))", "NULL"),
            ("is_multicast_ip6(''::BLOB)", "NULL"),
            ("is_multicast_ip6(from_hex(repeat('ff', 17)))", "NULL"),
            ("is_link_local_ip6('\\xFE\\x80'::BLOB)", "NULL"),
            ("is_link_local_ip6(mac('fe:80:00:00:00:01'))", "NULL"),
            ("mac_is_broadcast(ip6('ffff:ffff:ffff::'))", "NULL"),
            ("mac_is_broadcast(from_hex(repeat('ff', 5)))", "NULL"),
            ("mac_is_broadcast(from_hex(repeat('ff', 7)))", "NULL"),
            ("mac_is_multicast('\\x01'::BLOB)", "NULL"),
            ("mac_is_multicast(ip6('ff02::1'))", "NULL"),
            ("mac_is_local('\\x02'::BLOB)", "NULL"),
            ("mac_is_local(''::BLOB)", "NULL"),
        ],
    )?;
    // The argument is a BLOB: not an IPv4 address.
    assert!(eval(&connection, "is_multicast_ip6(ip4('224.0.0.1'))").is_err());
    assert!(eval(&connection, "mac_is_local(2)").is_err());
    assert_eq!(
        rows(
            &connection,
            "SELECT is_multicast_ip6(x), is_link_local_ip6(x), mac_is_broadcast(x),
                    mac_is_multicast(x), mac_is_local(x)
             FROM (VALUES (ip6('ff02::fb')), (NULL), (mac('ff:ff:ff:ff:ff:ff')), (ip6('fe80::1')),
                          ('\\x03'::BLOB), (mac('03:00:00:00:00:00')), (ip6('2001:db8::1')))
                  t(x)",
        )?,
        [
            row(&["true", "false", "NULL", "NULL", "NULL"]),
            row(&["NULL", "NULL", "NULL", "NULL", "NULL"]),
            row(&["NULL", "NULL", "true", "true", "true"]),
            row(&["false", "true", "NULL", "NULL", "NULL"]),
            row(&["NULL", "NULL", "NULL", "NULL", "NULL"]),
            row(&["NULL", "NULL", "false", "true", "true"]),
            row(&["false", "false", "NULL", "NULL", "NULL"]),
        ]
    );
    Ok(())
}

/// What the three tests of an IPv4 address answer for `address`, in SQL.
const CLASS_SQL: [(&str, &str); 3] = [
    (
        "is_private_ip",
        "(address >> 24) = 10 OR (address >> 20) = 2753 OR (address >> 16) = 49320",
    ),
    ("is_loopback_ip", "(address >> 24) = 127"),
    ("is_multicast_ip", "(address >> 28) = 14"),
];

/// The tests of an IPv4 address read the values of a flat chunk as `ip_in_cidr` with a literal
/// pattern does (`a_constant_pattern_answers_like_the_per_row_path`): they answer what the
/// expression in SQL does, and their NULLs are those of the addresses, for the same sizes of
/// chunk and the same NULLs, for the rows behind the selection of a hash join, and for a
/// constant vector.
#[test]
fn a_test_of_an_address_answers_like_sql_whatever_the_nulls() -> Result<()> {
    let connection = connect()?;
    for n in CHUNK_SIZES {
        for (name, null) in NULLS {
            create_flat(&connection, n, null)?;
            // The 300 values of `ip`, spread over the address space: some of every class.
            connection.execute(
                "CREATE OR REPLACE TABLE addresses AS
                 SELECT i, (ip * 14316557)::UINTEGER AS address FROM flat",
                Parameters::None,
            )?;
            for from in [
                "FROM addresses",
                "FROM addresses JOIN (SELECT i FROM range(0, 40000, 3) t(i)) USING (i)",
            ] {
                for (function, sql) in CLASS_SQL {
                    assert_eq!(
                        rows(
                            &connection,
                            &format!(
                                "SELECT count(*) FILTER ({function}(address) IS DISTINCT FROM ({sql})),
                                        count({function}(address)) = count(address)
                                 {from}"
                            ),
                        )?,
                        [row(&["0", "true"])],
                        "{function}, {n} rows, NULLs: {name}, {from}"
                    );
                }
            }
        }
        // One address for every row of the chunk: a constant vector.
        let all = n.to_string();
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*),
                            count(*) FILTER (is_private_ip(private)),
                            count(*) FILTER (NOT is_private_ip(loopback)),
                            count(*) FILTER (is_loopback_ip(loopback)),
                            count(*) FILTER (NOT is_multicast_ip(loopback)),
                            count(is_private_ip(missing)) + count(is_loopback_ip(missing))
                                + count(is_multicast_ip(missing))
                     FROM (SELECT ip4('10.1.2.3') AS private, ip4('127.0.0.1') AS loopback,
                                  NULL::UINTEGER AS missing) one,
                          range({n}) t(i)"
                ),
            )?,
            [row(&[&all, &all, &all, &all, &all, "0"])],
            "{n} rows, constant"
        );
    }
    // Every class is among the addresses.
    create_flat(&connection, 300, "false")?;
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*) FILTER (is_private_ip(address)) > 0,
                    count(*) FILTER (is_loopback_ip(address)) > 0,
                    count(*) FILTER (is_multicast_ip(address)) > 0
             FROM (SELECT (ip * 14316557)::UINTEGER AS address FROM flat)",
        )?,
        [row(&["true", "true", "true"])]
    );
    Ok(())
}
