//! SQL macros: shorthand for formatting address columns, and the capture-relative time
//! functions.
//!
//! The macros belong to the extension, like its functions: they are registered while the
//! extension loads, not created with `CREATE MACRO` on a connection, so they exist for every
//! connection and are never written to a database file.
//!
//! # Capture time
//!
//! `start_time(files)`, `end_time(files)` and `relative_time(ts, files)` are the command-line
//! tool's `start_time()`, `end_time()` and `relative_time(ts)`, with the capture as an
//! argument: that tool has one capture per session, and DuckDB has none. Each is a scalar
//! subquery over `pcap_time_range(files)` (`engine::table`), which reads the record headers of
//! the files: over several files the start is the smallest of theirs and the end the largest.
//! The subquery does not depend on the row, so DuckDB runs it once per statement however many
//! rows the macro is applied to, and `files` must be a constant, as for any scan.
//!
//! `relative_time` is in seconds as a `DOUBLE`, like the command-line tool's, from timestamps
//! in nanoseconds where that tool has microseconds: the two agree to the last bit on a
//! capture with microsecond timestamps (while the difference is below 2^53 ns, 104 days) and
//! this one keeps the nanoseconds of one that has them. Without a frame in the files the three
//! are NULL, where the command-line tool answers the Unix epoch.

use duckdb_neo::{
    extension::Extension,
    macro_function::{MacroBody, MacroFunctionBuilder},
    signature::{FunctionDocumentationBuilder, FunctionParameter, SignatureBuilder},
    types::Any,
    Result,
};

/// A macro: its name, its parameters, its body and what it is for.
const MACROS: [(&str, &[&str], &str, &str); 9] = [
    (
        "format_ip4",
        &["ip"],
        "ip4_to_string(ip)",
        "Formats a UINTEGER IPv4 address as dotted-quad text.",
    ),
    (
        "format_ip6",
        &["ip"],
        "ip6_to_string(ip)",
        "Formats a 16-byte IPv6 address as text.",
    ),
    (
        "format_mac",
        &["mac"],
        "mac_to_string(mac)",
        "Formats a 6-byte MAC address as colon-separated hex.",
    ),
    (
        "format_ip4_list",
        &["ips"],
        "list_transform(ips, lambda x: ip4_to_string(x))",
        "Formats each UINTEGER IPv4 address of a list as dotted-quad text.",
    ),
    (
        "format_ip6_list",
        &["ips"],
        "list_transform(ips, lambda x: ip6_to_string(x))",
        "Formats each 16-byte IPv6 address of a list as text.",
    ),
    (
        "format_mac_list",
        &["macs"],
        "list_transform(macs, lambda x: mac_to_string(x))",
        "Formats each 6-byte MAC address of a list as colon-separated hex.",
    ),
    (
        "start_time",
        &["files"],
        "(SELECT min(start_time) FROM pcap_time_range(files))",
        "The smallest timestamp of a frame of the capture files; NULL without frames.",
    ),
    (
        "end_time",
        &["files"],
        "(SELECT max(end_time) FROM pcap_time_range(files))",
        "The largest timestamp of a frame of the capture files; NULL without frames.",
    ),
    (
        "relative_time",
        &["ts", "files"],
        // The difference of the two integers first, then the division: exact where a
        // difference of DOUBLE seconds since 1970 would not be.
        "(epoch_ns(ts) - epoch_ns((SELECT min(start_time) FROM pcap_time_range(files)))) / 1e9",
        "Seconds from the start of the capture files to a timestamp, as a DOUBLE.",
    ),
];

pub(super) fn register(extension: &Extension) -> Result<()> {
    for (name, parameters, body, description) in MACROS {
        // Untyped, as in `CREATE MACRO name(parameter)`: the functions in the body decide
        // which arguments are accepted.
        let signature = parameters
            .iter()
            .fold(SignatureBuilder::new(), |signature, parameter| {
                signature.param(FunctionParameter::new::<Any>(*parameter))
            })
            .documentation(FunctionDocumentationBuilder::new().description(description));
        MacroFunctionBuilder::new(name, signature, MacroBody::Scalar(body.to_owned()))
            .register(extension)?;
    }
    Ok(())
}
