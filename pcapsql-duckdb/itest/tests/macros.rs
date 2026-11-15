//! The `format_*` macros, queried in-process.

use duckdb_neo::{Parameters, Result};
use pcapsql_duckdb_itest::{column, connect, rows, value};

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

#[test]
fn macros_are_registered() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        rows(
            &connection,
            "SELECT function_name, function_type, parameters::VARCHAR, macro_definition
             FROM duckdb_functions()
             WHERE function_name IN ('format_ip4', 'format_ip6', 'format_mac', 'format_ip4_list',
                                     'format_ip6_list', 'format_mac_list')
             ORDER BY function_name",
        )?,
        [
            row(&["format_ip4", "macro", "[ip]", "ip4_to_string(ip)"]),
            row(&[
                "format_ip4_list",
                "macro",
                "[ips]",
                "list_transform(ips, (lambda x: ip4_to_string(x)))"
            ]),
            row(&["format_ip6", "macro", "[ip]", "ip6_to_string(ip)"]),
            row(&[
                "format_ip6_list",
                "macro",
                "[ips]",
                "list_transform(ips, (lambda x: ip6_to_string(x)))"
            ]),
            row(&["format_mac", "macro", "[mac]", "mac_to_string(mac)"]),
            row(&[
                "format_mac_list",
                "macro",
                "[macs]",
                "list_transform(macs, (lambda x: mac_to_string(x)))"
            ]),
        ]
    );
    Ok(())
}

#[test]
fn macros_belong_to_the_extension() -> Result<()> {
    let connection = connect()?;
    // Registered with the extension, not created by a statement: the macros are in the system
    // catalog, next to the scalar functions.
    assert_eq!(
        rows(
            &connection,
            "SELECT DISTINCT database_name, schema_name, internal FROM duckdb_functions()
             WHERE function_name IN ('format_ip4', 'format_ip6', 'format_mac', 'format_ip4_list',
                                     'format_ip6_list', 'format_mac_list', 'ip4_to_string')",
        )?,
        [row(&["system", "main", "true"])]
    );
    assert!(connection
        .execute("DROP MACRO format_ip4", Parameters::None)
        .is_err());

    // A macro of the same name that the user creates is theirs: it is found first, and dropping
    // it brings the extension's macro back.
    connection.execute("CREATE MACRO format_ip4(ip) AS 'mine'", Parameters::None)?;
    assert_eq!(value(&connection, "SELECT format_ip4(1)")?, "mine");
    connection.execute("DROP MACRO format_ip4", Parameters::None)?;
    assert_eq!(value(&connection, "SELECT format_ip4(1)")?, "0.0.0.1");
    Ok(())
}

#[test]
fn format_ip4() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(&connection, "SELECT format_ip4(3232235777)")?,
        "192.168.1.1"
    );
    assert_eq!(
        value(&connection, "SELECT format_ip4(ip4('10.0.0.1'))")?,
        "10.0.0.1"
    );
    assert_eq!(
        value(&connection, "SELECT typeof(format_ip4(0))")?,
        "VARCHAR"
    );
    assert_eq!(value(&connection, "SELECT format_ip4(NULL)")?, "NULL");
    assert_eq!(
        column(
            &connection,
            "SELECT format_ip4(x) FROM (VALUES (16909060::UINTEGER), (NULL), (256)) t(x)",
        )?,
        ["1.2.3.4", "NULL", "0.0.1.0"]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT count(DISTINCT format_ip4(i::UINTEGER)) FROM range(5000) t(i)"
        )?,
        "5000"
    );
    // The macro takes what ip4_to_string takes.
    assert!(value(&connection, "SELECT format_ip4('text')").is_err());
    assert!(value(&connection, "SELECT format_ip4()").is_err());
    assert!(value(&connection, "SELECT format_ip4(1, 2)").is_err());
    Ok(())
}

#[test]
fn format_ip6() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(&connection, "SELECT format_ip6(ip6('2001:0db8::0001'))")?,
        "2001:db8::1"
    );
    assert_eq!(value(&connection, "SELECT format_ip6(NULL)")?, "NULL");
    assert_eq!(
        value(&connection, "SELECT format_ip6('\\x01'::BLOB)")?,
        "NULL"
    );
    assert_eq!(
        column(
            &connection,
            "SELECT format_ip6(x) FROM (VALUES (ip6('::1')), (NULL), (ip6('fe80::2'))) t(x)",
        )?,
        ["::1", "NULL", "fe80::2"]
    );
    Ok(())
}

#[test]
fn format_mac() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(&connection, "SELECT format_mac(mac('AA-BB-CC-DD-EE-FF'))")?,
        "aa:bb:cc:dd:ee:ff"
    );
    assert_eq!(value(&connection, "SELECT format_mac(NULL)")?, "NULL");
    assert_eq!(
        value(&connection, "SELECT format_mac('\\x01'::BLOB)")?,
        "NULL"
    );
    assert_eq!(
        column(
            &connection,
            "SELECT format_mac(x) FROM (VALUES
                 (mac('000000000001')), (NULL), (mac('ff:ff:ff:ff:ff:ff'))) t(x)",
        )?,
        ["00:00:00:00:00:01", "NULL", "ff:ff:ff:ff:ff:ff"]
    );
    Ok(())
}

#[test]
fn format_ip4_list() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(
            &connection,
            "SELECT format_ip4_list([ip4('192.168.1.1'), NULL, ip4('10.0.0.1')])",
        )?,
        "[192.168.1.1, NULL, 10.0.0.1]"
    );
    assert_eq!(
        value(&connection, "SELECT typeof(format_ip4_list([1::UINTEGER]))")?,
        "VARCHAR[]"
    );
    assert_eq!(
        value(&connection, "SELECT format_ip4_list([]::UINTEGER[])")?,
        "[]"
    );
    assert_eq!(
        value(&connection, "SELECT format_ip4_list(NULL::UINTEGER[])")?,
        "NULL"
    );
    // The aggregated addresses of a group, the use the macro was written for.
    assert_eq!(
        rows(
            &connection,
            "SELECT g, format_ip4_list(list(x ORDER BY x)) FROM (
                 SELECT i % 2 AS g, (167772160 + i)::UINTEGER AS x FROM range(4) t(i))
             GROUP BY g ORDER BY g",
        )?,
        [
            row(&["0", "[10.0.0.0, 10.0.0.2]"]),
            row(&["1", "[10.0.0.1, 10.0.0.3]"]),
        ]
    );
    Ok(())
}

#[test]
fn format_ip6_list() -> Result<()> {
    let connection = connect()?;
    // DuckDB quotes text that holds a colon when it renders a list.
    assert_eq!(
        value(
            &connection,
            "SELECT format_ip6_list([ip6('::1'), NULL, '\\x00'::BLOB, ip6('2001:db8::')])",
        )?,
        "['::1', NULL, NULL, '2001:db8::']"
    );
    assert_eq!(
        value(&connection, "SELECT format_ip6_list([]::BLOB[])")?,
        "[]"
    );
    assert_eq!(
        value(&connection, "SELECT format_ip6_list(NULL::BLOB[])")?,
        "NULL"
    );
    Ok(())
}

#[test]
fn format_mac_list() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(
            &connection,
            "SELECT format_mac_list([mac('aa:bb:cc:dd:ee:ff'), NULL, mac('00-00-00-00-00-01')])",
        )?,
        "['aa:bb:cc:dd:ee:ff', NULL, '00:00:00:00:00:01']"
    );
    assert_eq!(
        value(&connection, "SELECT format_mac_list([]::BLOB[])")?,
        "[]"
    );
    assert_eq!(
        column(
            &connection,
            "SELECT format_mac_list(l) FROM (VALUES
                 ([mac('000000000001')]), (NULL),
                 ([mac('000000000002'), mac('000000000003')])) t(l)",
        )?,
        [
            "['00:00:00:00:00:01']",
            "NULL",
            "['00:00:00:00:00:02', '00:00:00:00:00:03']"
        ]
    );
    Ok(())
}
