//! The scalar functions other than `ip4` and `ip4_to_string` (see `extension.rs` for those),
//! queried in-process.
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
             NULL::VARCHAR AS null_text, NULL::BLOB AS null_bytes, NULL::USMALLINT AS null_u16",
        Parameters::None,
    )?;
    Ok(())
}

#[test]
fn signatures() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        rows(
            &connection,
            "SELECT function_name, parameters::VARCHAR, parameter_types::VARCHAR, return_type
             FROM duckdb_functions()
             WHERE function_type = 'scalar' AND function_name IN (
                 'ip4', 'ip4_to_string', 'ip6', 'ip6_to_string', 'mac', 'mac_to_string',
                 'ip_in_cidr', 'ip6_in_cidr', 'tcp_flags_str', 'has_tcp_flag', 'dns_type_name',
                 'dns_rcode_name', 'ip_proto_name', 'ethertype_name', 'pcap_hex', 'pcap_unhex')
             ORDER BY function_name",
        )?,
        [
            row(&["dns_rcode_name", "[rcode]", "[USMALLINT]", "VARCHAR"]),
            row(&["dns_type_name", "[qtype]", "[USMALLINT]", "VARCHAR"]),
            row(&["ethertype_name", "[ethertype]", "[USMALLINT]", "VARCHAR"]),
            row(&[
                "has_tcp_flag",
                "[flags, flag]",
                "[USMALLINT, VARCHAR]",
                "BOOLEAN"
            ]),
            row(&["ip4", "[address]", "[VARCHAR]", "UINTEGER"]),
            row(&["ip4_to_string", "[address]", "[UINTEGER]", "VARCHAR"]),
            row(&["ip6", "[address]", "[VARCHAR]", "BLOB"]),
            row(&[
                "ip6_in_cidr",
                "[address, cidr]",
                "[BLOB, VARCHAR]",
                "BOOLEAN"
            ]),
            row(&["ip6_to_string", "[address]", "[BLOB]", "VARCHAR"]),
            row(&[
                "ip_in_cidr",
                "[address, cidr]",
                "[UINTEGER, VARCHAR]",
                "BOOLEAN"
            ]),
            row(&["ip_proto_name", "[protocol]", "[UTINYINT]", "VARCHAR"]),
            row(&["mac", "[address]", "[VARCHAR]", "BLOB"]),
            row(&["mac_to_string", "[address]", "[BLOB]", "VARCHAR"]),
            row(&["pcap_hex", "[bytes]", "[BLOB]", "VARCHAR"]),
            row(&["pcap_unhex", "[hex]", "[VARCHAR]", "BLOB"]),
            row(&["tcp_flags_str", "[flags]", "[USMALLINT]", "VARCHAR"]),
        ]
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
        // A constant that is not a pattern, or not an address.
        "ip_in_cidr(i::UINTEGER, mac_text)",
        "ip6_in_cidr(ip6_bytes, cidr4)",
        "ip6_in_cidr(mac_bytes, cidr6)",
        "ip6_to_string(mac_bytes)",
        "mac_to_string(ip6_bytes)",
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

/// `ip_in_cidr` and `has_tcp_flag` with a literal pattern read a flat chunk without NULLs as a
/// slice and every other chunk a row at a time. Both answer what the per-row path answers (the
/// one a pattern from a column takes) and what the expression in SQL does: for chunks of every
/// size around a 64-row word of the validity mask and around a whole chunk, with no NULL, a
/// NULL at either end, at the edges of a word, here and there, and in every row; and for the
/// same rows behind a constant vector and behind the selection of a hash join.
#[test]
fn a_constant_pattern_answers_like_the_per_row_path() -> Result<()> {
    let connection = connect()?;
    let nulls = [
        ("none", "false"),
        ("first", "i = 0"),
        ("last", "i = n - 1"),
        ("word edges", "i % 64 IN (0, 63)"),
        ("chunk edges", "i IN (2047, 2048)"),
        ("some", "i % 7 = 3"),
        ("all but one", "i <> n / 2"),
        ("all", "true"),
    ];
    // What each function answers, in SQL.
    let cidr = "CASE WHEN i % 2 = 0 THEN (ip & 4294967232) = 64 ELSE (ip & 4294967040) = 0 END";
    let flag = "CASE WHEN i % 2 = 0 THEN (flags & 2) <> 0 ELSE (flags & 16) <> 0 END";
    for n in [0, 1, 2, 63, 64, 65, 127, 128, 129, 2047, 2048, 2049, 4097] {
        for (name, null) in nulls {
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
            for (kind, from) in [
                ("flat", "FROM flat"),
                (
                    "dictionary",
                    "FROM flat JOIN (SELECT i FROM range(0, 5000, 3) t(i)) USING (i)",
                ),
            ] {
                assert_eq!(
                    rows(
                        &connection,
                        &format!(
                            "SELECT count(*) FILTER (
                                        CASE WHEN i % 2 = 0 THEN ip_in_cidr(ip, '0.0.0.64/26')
                                             ELSE ip_in_cidr(ip, '0.0.0.0/24') END
                                        IS DISTINCT FROM ip_in_cidr(ip, cidr)),
                                    count(*) FILTER (
                                        ip_in_cidr(ip, cidr) IS DISTINCT FROM ({cidr})),
                                    count(*) FILTER (
                                        CASE WHEN i % 2 = 0 THEN has_tcp_flag(flags, 'SYN')
                                             ELSE has_tcp_flag(flags, 'ack') END
                                        IS DISTINCT FROM has_tcp_flag(flags, flag)),
                                    count(*) FILTER (
                                        has_tcp_flag(flags, flag) IS DISTINCT FROM ({flag})),
                                    count(*) FILTER (ip_in_cidr(ip, 'no network') IS NOT NULL),
                                    count(*) FILTER (has_tcp_flag(flags, 'no flag')),
                                    count(ip_in_cidr(ip, '0.0.0.0/24')) = count(ip),
                                    count(has_tcp_flag(flags, 'ack')) = count(flags)
                             {from}"
                        ),
                    )?,
                    [row(&["0", "0", "0", "0", "0", "0", "true", "true"])],
                    "{n} rows, NULLs: {name}, {kind}"
                );
            }
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
