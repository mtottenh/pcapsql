//! SQL macro registration for pcapsql extension.
//!
//! Registers helper macros that make working with IP addresses and other
//! binary data more convenient by providing automatic formatting.

use duckdb::Connection;

/// Register all SQL macros for the extension.
pub fn register_all(con: &Connection) -> duckdb::Result<(), Box<dyn std::error::Error>> {
    register_ip_macros(con)?;
    register_mac_macros(con)?;
    Ok(())
}

/// Register IP address formatting macros.
fn register_ip_macros(con: &Connection) -> duckdb::Result<(), Box<dyn std::error::Error>> {
    // format_ip4_list: Convert a list of UInt32 IPv4 addresses to readable strings
    con.execute(
        r#"
        CREATE OR REPLACE MACRO format_ip4_list(ips) AS
            list_transform(ips, x -> ip4_to_string(x))
        "#,
        [],
    )?;

    // format_ip6_list: Convert a list of 16-byte IPv6 blobs to readable strings
    con.execute(
        r#"
        CREATE OR REPLACE MACRO format_ip6_list(ips) AS
            list_transform(ips, x -> ip6_to_string(x))
        "#,
        [],
    )?;

    // format_ip4: Convert a single UInt32 IPv4 address to readable string
    con.execute(
        r#"
        CREATE OR REPLACE MACRO format_ip4(ip) AS
            ip4_to_string(ip)
        "#,
        [],
    )?;

    // format_ip6: Convert a single 16-byte IPv6 blob to readable string
    con.execute(
        r#"
        CREATE OR REPLACE MACRO format_ip6(ip) AS
            ip6_to_string(ip)
        "#,
        [],
    )?;

    Ok(())
}

/// Register MAC address formatting macros.
fn register_mac_macros(con: &Connection) -> duckdb::Result<(), Box<dyn std::error::Error>> {
    // format_mac_list: Convert a list of 6-byte MAC blobs to readable strings
    con.execute(
        r#"
        CREATE OR REPLACE MACRO format_mac_list(macs) AS
            list_transform(macs, x -> mac_to_string(x))
        "#,
        [],
    )?;

    // format_mac: Convert a single 6-byte MAC blob to readable string
    con.execute(
        r#"
        CREATE OR REPLACE MACRO format_mac(mac) AS
            mac_to_string(mac)
        "#,
        [],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Note: Macro registration is tested via integration tests with the actual
    // DuckDB extension, since unit tests don't have access to a properly
    // initialized DuckDB runtime.
    //
    // Test with:
    //   duckdb -unsigned -c "LOAD 'path/to/pcapsql.duckdb_extension'; SELECT format_ip4(3232235777);"
    //
    // Expected: "192.168.1.1"
}
