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
fn pcap_protocols_lists_the_registry() -> Result<()> {
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
        ]
    );

    let names = column(&connection, "SELECT name FROM pcap_protocols()")?;
    // The 27 parsers of core's default registry and the `frames` pseudo-protocol.
    assert_eq!(names.len(), 28);
    assert!(names.is_sorted(), "{names:?}");
    for expected in ["frames", "ethernet", "ipv4", "tcp", "dns", "tls"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} is missing"
        );
    }

    assert_eq!(
        rows(
            &connection,
            "SELECT description, field_count FROM pcap_protocols() WHERE name = 'frames'",
        )?,
        [row(&["Raw frame metadata (timestamp, length, etc.)", "5"])]
    );
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM pcap_protocols() WHERE field_count > 0 AND description <> ''",
        )?,
        "28"
    );
    // Two scans in one query each have their own position.
    assert_eq!(
        value(
            &connection,
            "SELECT count(*) FROM pcap_protocols() a JOIN pcap_protocols() b USING (name)",
        )?,
        "28"
    );
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
