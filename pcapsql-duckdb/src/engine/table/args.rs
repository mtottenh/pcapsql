//! The arguments of a scan function: its signature, the files argument and what it expands
//! to, and the named parameters.

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    error::DuckDBError,
    signature::{FunctionParameter, FunctionParameterKind, SignatureBuilder},
    types::Any,
    Result,
};

use super::{PcapScan, FILENAME, KEYLOG};
use crate::engine::{
    fs,
    relation::{self, Relation},
};

/// The table `read_pcap` reads when `protocol` is not given.
pub(super) const DEFAULT_PROTOCOL: &str = "frames";

/// Where each argument is in the list `bind` is handed: the positional parameters, then the
/// named ones in the order [`PcapScan::signature`] declares them.
pub(super) struct ArgumentPositions {
    pub(super) protocol: Option<usize>,
    pub(super) strict: usize,
    pub(super) filename: usize,
    /// `keylog`, on the functions that take it ([`PcapScan::takes_keylog`]).
    pub(super) keylog: Option<usize>,
}

impl PcapScan {
    const FILE: usize = 0;

    /// Whether the function has the `keylog` parameter: the functions that can read a stream
    /// table, which are those of the stream tables and `read_pcap`.
    pub(super) fn takes_keylog(&self) -> bool {
        self.relation.is_none_or(Relation::is_stream)
    }

    pub(super) fn positions(&self) -> ArgumentPositions {
        let protocol = self.relation.is_none().then_some(Self::FILE + 1);
        let strict = protocol.unwrap_or(Self::FILE) + 1;
        ArgumentPositions {
            protocol,
            strict,
            filename: strict + 1,
            keylog: self.takes_keylog().then_some(strict + 2),
        }
    }

    pub(super) fn signature(&self) -> SignatureBuilder {
        let mut signature = SignatureBuilder::new().param(FunctionParameter::new::<Any>("files"));
        if self.relation.is_none() {
            signature = signature.param(
                FunctionParameter::with_default::<String>("protocol", DEFAULT_PROTOCOL.to_owned())
                    .kind(FunctionParameterKind::Named),
            );
        }
        signature = signature
            .param(
                FunctionParameter::with_default::<bool>("strict", false)
                    .kind(FunctionParameterKind::Named),
            )
            .param(
                FunctionParameter::with_default::<bool>(FILENAME, false)
                    .kind(FunctionParameterKind::Named),
            );
        if self.takes_keylog() {
            // NULL when the call does not give it: the setting then decides
            // (`table::keylog`).
            signature = signature.param(
                FunctionParameter::new::<String>(KEYLOG)
                    .default_value(None::<String>)
                    .kind(FunctionParameterKind::Named),
            );
        }
        signature
    }

    /// The entries of the one positional argument: the path or pattern, or those of the list,
    /// in its order.
    pub(super) fn file_argument(&self, arguments: &[BindArgument]) -> Result<Vec<String>> {
        let argument = arguments
            .get(Self::FILE)
            .ok_or_else(|| self.invalid("a capture file is required"))?;
        let value = argument
            .value
            .as_ref()
            .ok_or_else(|| self.invalid("the capture file must be a constant"))?;
        if value.is_null()? {
            return Err(self.invalid("the capture file must not be NULL"));
        }
        let entry = |value: &duckdb_neo::value::Value| -> Result<String> {
            if value.is_null()? {
                return Err(self.invalid("the capture file must not be NULL"));
            }
            let path = value.get::<String>()?.unwrap_or_default();
            if path.is_empty() {
                return Err(self.invalid("the capture file must not be an empty path"));
            }
            Ok(path)
        };
        // The type by its text, which is also what the last message quotes. Its id would not
        // tell a VARCHAR from a type defined on top of one (JSON), which is not a path.
        let declared = argument.logical_type.to_text()?;
        match declared.as_str() {
            "VARCHAR" => Ok(vec![entry(value)?]),
            // The type of `[]` is not a list of VARCHAR, whatever DuckDB calls it.
            _ if declared.ends_with("[]") && value.child_count()? == 0 => {
                Err(self.invalid("the list of capture files is empty"))
            }
            "VARCHAR[]" => value.children()?.iter().map(entry).collect(),
            _ => Err(self.invalid(format_args!(
                "the capture files must be a VARCHAR path or pattern, or a list of them, not \
                 {declared}"
            ))),
        }
    }

    /// The files of a call: every entry of the argument expanded through DuckDB's file system
    /// (see the module documentation on files).
    pub(super) fn files(&self, context: &Context, entries: &[String]) -> Result<Vec<String>> {
        let mut files = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut matched = fs::glob(context, entry)?;
            if matched.is_empty() {
                if has_wildcard(entry) {
                    return Err(self.error(
                        DuckDBError::IoFileNotFound,
                        format_args!("no file matches the pattern '{entry}'"),
                    ));
                }
                // Not a pattern: the open says what is wrong with the path.
                matched.push(entry.clone());
            }
            // `glob` promises no order.
            matched.sort_unstable();
            files.append(&mut matched);
        }
        Ok(files)
    }

    /// A named parameter. DuckDB delivers its default when the call does not give it.
    pub(super) fn named<T: duckdb_neo::types::FromValue>(
        &self,
        arguments: &[BindArgument],
        index: usize,
        parameter: &str,
    ) -> Result<T> {
        arguments
            .get(index)
            .and_then(|argument| argument.value.as_ref())
            .map(|value| value.get::<T>())
            .transpose()?
            .flatten()
            .ok_or_else(|| {
                self.invalid(format_args!(
                    "{parameter} must be a constant and must not be NULL"
                ))
            })
    }

    /// What the call reads: the function's own table or view, or the one `protocol` names.
    pub(super) fn relation(&self, arguments: &[BindArgument]) -> Result<Relation> {
        if let Some(relation) = self.relation {
            return Ok(relation);
        }
        let index = self.positions().protocol.expect("read_pcap has protocol");
        let protocol: String = self.named(arguments, index, "protocol")?;
        // The names are lower case; any case is accepted, as `pcap_schema` does.
        Relation::find(&protocol.to_ascii_lowercase()).ok_or_else(|| {
            self.invalid(format_args!(
                "there is no protocol table '{protocol}'; {}",
                relation::WHERE_TO_LOOK
            ))
        })
    }
}

/// Whether an entry of the files argument is a pattern rather than a path: the characters
/// DuckDB's file systems take for wildcards (`FileSystem::HasGlob`).
pub(super) fn has_wildcard(entry: &str) -> bool {
    entry.contains(['*', '?', '['])
}
