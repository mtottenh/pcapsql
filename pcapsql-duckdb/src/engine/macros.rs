//! SQL macros: shorthand for formatting address columns.
//!
//! The macros belong to the extension, like its functions: they are registered while the
//! extension loads, not created with `CREATE MACRO` on a connection, so they exist for every
//! connection and are never written to a database file.

use duckdb_neo::{
    extension::Extension,
    macro_function::{MacroBody, MacroFunctionBuilder},
    signature::{FunctionDocumentationBuilder, FunctionParameter, SignatureBuilder},
    types::Any,
    Result,
};

/// A macro: its name, its one parameter, its body and what it is for.
const MACROS: [(&str, &str, &str, &str); 6] = [
    (
        "format_ip4",
        "ip",
        "ip4_to_string(ip)",
        "Formats a UINTEGER IPv4 address as dotted-quad text.",
    ),
    (
        "format_ip6",
        "ip",
        "ip6_to_string(ip)",
        "Formats a 16-byte IPv6 address as text.",
    ),
    (
        "format_mac",
        "mac",
        "mac_to_string(mac)",
        "Formats a 6-byte MAC address as colon-separated hex.",
    ),
    (
        "format_ip4_list",
        "ips",
        "list_transform(ips, lambda x: ip4_to_string(x))",
        "Formats each UINTEGER IPv4 address of a list as dotted-quad text.",
    ),
    (
        "format_ip6_list",
        "ips",
        "list_transform(ips, lambda x: ip6_to_string(x))",
        "Formats each 16-byte IPv6 address of a list as text.",
    ),
    (
        "format_mac_list",
        "macs",
        "list_transform(macs, lambda x: mac_to_string(x))",
        "Formats each 6-byte MAC address of a list as colon-separated hex.",
    ),
];

pub(super) fn register(extension: &Extension) -> Result<()> {
    for (name, parameter, body, description) in MACROS {
        MacroFunctionBuilder::new(
            name,
            // Untyped, as in `CREATE MACRO name(parameter)`: the function in the body decides
            // which arguments are accepted.
            SignatureBuilder::new()
                .param(FunctionParameter::new::<Any>(parameter))
                .documentation(FunctionDocumentationBuilder::new().description(description)),
            MacroBody::Scalar(body.to_owned()),
        )
        .register(extension)?;
    }
    Ok(())
}
