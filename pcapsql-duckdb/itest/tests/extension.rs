//! The functions the extension registers, queried in-process.

use duckdb_neo::{
    connection::Connection,
    scalar::MicroScalar,
    vector::{StorageKind, Vector},
    Result,
};
use pcapsql_duckdb_itest::{column, connect, rows, value};

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

#[test]
fn extension_is_loaded_at_startup() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        rows(
            &connection,
            "SELECT loaded, install_mode FROM duckdb_extensions() WHERE extension_name = 'pcapsql'",
        )?,
        [row(&["true", "STATICALLY_LINKED"])]
    );
    Ok(())
}

#[test]
fn pcap_protocols_lists_the_catalogue() -> Result<()> {
    let connection = connect()?;

    assert_eq!(
        rows(
            &connection,
            "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM pcap_protocols())",
        )?,
        [
            row(&["name", "VARCHAR"]),
            row(&["description", "VARCHAR"]),
            row(&["field_count", "UINTEGER"]),
            row(&["kind", "VARCHAR"]),
        ]
    );

    let names = column(&connection, "SELECT name FROM pcap_protocols()")?;
    // `frames`, the 27 protocol tables and the 4 stream tables of the shared catalogue.
    assert_eq!(names.len(), 32);
    assert!(names.is_sorted(), "{names:?}");
    for expected in ["frames", "ethernet", "ipv4", "tcp", "dns", "tls"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} is missing"
        );
    }
    for stream in ["tcp_connections", "tls_sessions", "http_messages", "http2"] {
        assert!(names.iter().any(|name| name == stream), "{stream}");
    }

    assert_eq!(
        rows(
            &connection,
            "SELECT description, field_count, kind FROM pcap_protocols() WHERE name = 'frames'",
        )?,
        [row(&[
            "Raw frame metadata (timestamp, length, etc.)",
            "6",
            "frames"
        ])]
    );
    assert_eq!(
        rows(
            &connection,
            "SELECT kind, count(*) FROM pcap_protocols() GROUP BY kind ORDER BY kind",
        )?,
        [
            row(&["frames", "1"]),
            row(&["protocol", "27"]),
            row(&["stream", "4"])
        ]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM pcap_protocols() WHERE field_count > 0 AND description <> ''",
        )?,
        "32"
    );
    // Two scans in one query each have their own position.
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM pcap_protocols() a JOIN pcap_protocols() b USING (name)",
        )?,
        "32"
    );
    Ok(())
}

#[test]
fn pcap_schema_lists_the_columns_a_scan_returns() -> Result<()> {
    let connection = connect()?;

    assert_eq!(
        rows(
            &connection,
            "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM pcap_schema('tcp'))",
        )?,
        [
            row(&["column_name", "VARCHAR"]),
            row(&["column_type", "VARCHAR"]),
            row(&["nullable", "BOOLEAN"]),
        ]
    );

    assert_eq!(
        rows(&connection, "SELECT * FROM pcap_schema('frames')")?,
        [
            row(&["frame_number", "UBIGINT", "false"]),
            row(&["timestamp", "TIMESTAMP_NS", "false"]),
            row(&["length", "UINTEGER", "false"]),
            row(&["original_length", "UINTEGER", "false"]),
            row(&["link_type", "USMALLINT", "false"]),
            row(&["raw_data", "BLOB", "false"]),
        ]
    );
    assert_eq!(
        rows(&connection, "SELECT * FROM pcap_schema('ethernet')")?,
        [
            row(&["frame_number", "UBIGINT", "false"]),
            // Not part of the table in the DataFusion engine; here it is (decision D5).
            row(&["timestamp", "TIMESTAMP_NS", "false"]),
            row(&["src_mac", "BLOB", "true"]),
            row(&["dst_mac", "BLOB", "true"]),
            row(&["ethertype", "USMALLINT", "true"]),
            row(&["encap_depth", "UTINYINT", "false"]),
            row(&["tunnel_type", "VARCHAR", "true"]),
            row(&["tunnel_id", "UBIGINT", "true"]),
        ]
    );

    // Addresses are typed as the scalar functions take them.
    assert_eq!(
        rows(
            &connection,
            "SELECT column_name, column_type FROM pcap_schema('ipv4')
             WHERE column_name IN ('src_ip', 'dst_ip')",
        )?,
        [row(&["src_ip", "UINTEGER"]), row(&["dst_ip", "UINTEGER"])]
    );
    assert_eq!(
        rows(
            &connection,
            "SELECT column_name, column_type FROM pcap_schema('ipv6')
             WHERE column_name IN ('src_ip', 'dst_ip')",
        )?,
        [row(&["src_ip", "BLOB"]), row(&["dst_ip", "BLOB"])]
    );

    // Every table `pcap_protocols()` lists has a schema of `field_count` columns, the first of
    // them `frame_number`. A table of the frames has exactly one TIMESTAMP_NS, named
    // `timestamp`; a stream table has no frame's time (`stream_tables.rs`).
    // (The argument must be a constant: a table function takes no lateral column.)
    let mut type_names = std::collections::BTreeSet::new();
    for protocol in rows(
        &connection,
        "SELECT name, field_count FROM pcap_protocols() WHERE kind <> 'stream'",
    )? {
        let (name, field_count) = (&protocol[0], &protocol[1]);
        assert_eq!(
            rows(
                &connection,
                &format!(
                    "SELECT count(*), first(column_name),
                            count(*) FILTER (column_name = 'timestamp'
                                             AND column_type = 'TIMESTAMP_NS'),
                            count(*) FILTER (column_type LIKE 'TIMESTAMP%'),
                            count(DISTINCT column_name)
                     FROM pcap_schema('{name}')"
                ),
            )?,
            [row(&[field_count, "frame_number", "1", "1", field_count])],
            "{name}"
        );
        type_names.extend(column(
            &connection,
            &format!("SELECT column_type FROM pcap_schema('{name}')"),
        )?);
    }
    // No column has a type name DuckDB does not know, and lists are among them.
    assert!(type_names.len() >= 10, "{type_names:?}");
    for list in ["BLOB[]", "UINTEGER[]", "USMALLINT[]", "VARCHAR[]"] {
        assert!(type_names.contains(list), "{type_names:?}");
    }
    for type_name in type_names {
        assert_eq!(
            value(&connection, &format!("SELECT typeof(NULL::{type_name})"))?,
            type_name
        );
    }

    // The name is matched whatever its case.
    assert_eq!(
        rows(&connection, "SELECT * FROM pcap_schema('Ethernet')")?,
        rows(&connection, "SELECT * FROM pcap_schema('ethernet')")?
    );

    // A stream table has a schema like any other (`stream_tables.rs`).
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM pcap_schema('tcp_connections')"
        )?,
        "20"
    );

    // An unknown table and NULL are bind errors.
    for (argument, message) in [
        ("'nope'", "no protocol table 'nope'"),
        ("NULL", "must not be NULL"),
    ] {
        let error = value(
            &connection,
            &format!("SELECT count(*) FROM pcap_schema({argument})"),
        )
        .unwrap_err();
        assert!(error.message.contains(message), "{argument}: {error}");
    }
    assert!(value(&connection, "SELECT count(*) FROM pcap_schema()").is_err());
    Ok(())
}

#[test]
fn ip4_parses_text() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(&connection, "SELECT typeof(ip4('10.0.0.1'))")?,
        "UINTEGER"
    );
    assert_eq!(
        value(&connection, "SELECT ip4('192.168.1.1')")?,
        "3232235777"
    );
    assert_eq!(
        value(&connection, "SELECT ip4('255.255.255.255')")?,
        "4294967295"
    );
    assert_eq!(value(&connection, "SELECT ip4('0.0.0.0')")?, "0");
    // Text that is not an address is NULL, not an error.
    assert_eq!(value(&connection, "SELECT ip4('192.168.1')")?, "NULL");
    assert_eq!(value(&connection, "SELECT ip4('')")?, "NULL");
    assert_eq!(value(&connection, "SELECT ip4(NULL)")?, "NULL");
    Ok(())
}

#[test]
fn ip4_to_string_formats_numbers() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        value(&connection, "SELECT typeof(ip4_to_string(1))")?,
        "VARCHAR"
    );
    assert_eq!(
        value(&connection, "SELECT ip4_to_string(3232235777)")?,
        "192.168.1.1"
    );
    assert_eq!(value(&connection, "SELECT ip4_to_string(0)")?, "0.0.0.0");
    assert_eq!(
        value(&connection, "SELECT ip4_to_string(4294967295)")?,
        "255.255.255.255"
    );
    assert_eq!(value(&connection, "SELECT ip4_to_string(NULL)")?, "NULL");
    assert_eq!(
        value(&connection, "SELECT ip4_to_string(ip4('172.16.254.3'))")?,
        "172.16.254.3"
    );
    Ok(())
}

#[test]
fn scalars_keep_nulls_row_by_row() -> Result<()> {
    let connection = connect()?;
    assert_eq!(
        column(
            &connection,
            "SELECT ip4(x) FROM (VALUES ('1.2.3.4'), (NULL), ('bogus'), ('0.0.1.0')) t(x)",
        )?,
        ["16909060", "NULL", "NULL", "256"]
    );
    assert_eq!(
        column(
            &connection,
            "SELECT ip4_to_string(x) FROM (VALUES (16909060::UINTEGER), (NULL), (256)) t(x)",
        )?,
        ["1.2.3.4", "NULL", "0.0.1.0"]
    );
    // More rows than one vector holds, with a NULL every seventh row.
    assert_eq!(
        rows(
            &connection,
            "SELECT count(*), count(s), count(DISTINCT s), bool_and(ip4(s) = x) FROM (
                 SELECT x, ip4_to_string(x) AS s FROM (
                     SELECT CASE WHEN i % 7 <> 0 THEN (i * 65537)::UINTEGER END AS x FROM range(10000) t(i)))",
        )?,
        [row(&["10000", "8571", "8571", "true"])]
    );
    Ok(())
}

/// Registers `storage_kind(x)`, which reports how DuckDB stored the argument vector it was given.
fn register_storage_kind_probes(connection: &Connection) -> Result<()> {
    fn kind<T: duckdb_neo::vector::NativeElement>(input: &Vector<'_, T>) -> &'static str {
        match input.storage_kind() {
            StorageKind::Flat => "FLAT",
            StorageKind::Constant => "CONSTANT",
            StorageKind::Dictionary => "DICTIONARY",
            StorageKind::Other => "OTHER",
        }
    }
    MicroScalar::create(
        "storage_kind_of_uinteger",
        |_context, input: Vector<'_, u32>, mut output: Vector<'_, String>| {
            let kind = kind(&input);
            let mut writer = output.writer()?;
            (0..writer.len()).try_for_each(|row| writer.set(row, kind))
        },
    )
    .register(connection)?;
    MicroScalar::create(
        "storage_kind_of_varchar",
        |_context, input: Vector<'_, String>, mut output: Vector<'_, String>| {
            let kind = kind(&input);
            let mut writer = output.writer()?;
            (0..writer.len()).try_for_each(|row| writer.set(row, kind))
        },
    )
    .register(connection)
}

#[test]
fn scalars_read_constant_vectors() -> Result<()> {
    let connection = connect()?;
    register_storage_kind_probes(&connection)?;
    connection.execute(
        "CREATE TABLE one AS SELECT 3232235777::UINTEGER AS n, '10.1.2.3' AS s, \
         NULL::UINTEGER AS null_n, NULL::VARCHAR AS null_s",
        duckdb_neo::Parameters::None,
    )?;

    // A cross join hands the one-row side to the function as a constant vector spanning the
    // whole chunk: one stored value for 3000 logical rows.
    let from = "FROM one, range(3000)";
    assert_eq!(
        column(
            &connection,
            &format!("SELECT DISTINCT storage_kind_of_uinteger(n) {from}")
        )?,
        ["CONSTANT"]
    );
    assert_eq!(
        column(
            &connection,
            &format!("SELECT DISTINCT storage_kind_of_varchar(s) {from}")
        )?,
        ["CONSTANT"]
    );

    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), min(ip4_to_string(n)), max(ip4_to_string(n)) {from}"),
        )?,
        [row(&["3000", "192.168.1.1", "192.168.1.1"])]
    );
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), min(ip4(s)), max(ip4(s)) {from}")
        )?,
        [row(&["3000", "167838211", "167838211"])]
    );
    // A constant NULL stays NULL in every row.
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT count(*), count(ip4_to_string(null_n)), count(ip4(null_s)) {from}"),
        )?,
        [row(&["3000", "0", "0"])]
    );
    Ok(())
}

#[test]
fn scalars_read_dictionary_vectors() -> Result<()> {
    let connection = connect()?;
    register_storage_kind_probes(&connection)?;
    connection.execute(
        "CREATE TABLE addresses AS SELECT i, (i * 65537)::UINTEGER AS n, \
         ip4_to_string((i * 65537)::UINTEGER) AS s FROM range(6000) t(i)",
        duckdb_neo::Parameters::None,
    )?;

    // A hash join passes on the probe rows that matched as a selection over the scanned vector.
    let from = "FROM addresses JOIN (SELECT i FROM range(1, 6000, 3) t(i)) USING (i)";
    assert_eq!(
        column(
            &connection,
            &format!("SELECT DISTINCT storage_kind_of_uinteger(n) {from}")
        )?,
        ["DICTIONARY"]
    );
    assert_eq!(
        column(
            &connection,
            &format!("SELECT DISTINCT storage_kind_of_varchar(s) {from}")
        )?,
        ["DICTIONARY"]
    );

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT count(*), bool_and(ip4_to_string(n) = s), bool_and(ip4(s) = n) {from}"
            ),
        )?,
        [row(&["2000", "true", "true"])]
    );
    Ok(())
}
