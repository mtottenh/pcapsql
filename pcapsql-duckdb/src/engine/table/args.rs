//! The arguments of a scan function: its signature, where each argument is, and the table or
//! view the call reads. The files argument is that of every function over capture files
//! ([`CaptureFunction`]).

use duckdb_neo::{
    bind_arguments::BindArgument,
    signature::{FunctionParameter, FunctionParameterKind, SignatureBuilder},
    types::Any,
    Result,
};

use super::{function::CaptureFunction, PcapScan, FILENAME, KEYLOG};
use crate::engine::relation::{self, Relation};

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
