//! The TLS key log of a scan of a stream table.
//!
//! A key log is the file a TLS client or server writes when `SSLKEYLOGFILE` is set (NSS key log
//! format): per session, the secrets its record keys are derived from. With it the scan layer
//! decrypts the TLS streams it reassembles, which is what `tls_sessions.is_decrypted` reports
//! and where the rows of `http2` come from.
//!
//! - **Where it is named.** The `keylog` parameter of the call, or, when the call does not give
//!   it (or gives NULL), the setting `pcapsql_keylog`. The parameter wins: `keylog := ''` reads
//!   without a key log whatever the setting says.
//! - **Who takes it.** The functions of the stream tables, and `read_pcap`, which may read
//!   one. Only a stream table is built from decrypted streams: when `read_pcap` reads a packet
//!   table or a view, the parameter is accepted and not looked at (the file is not opened), as
//!   the setting is for every scan that is not of a stream table.
//! - **How it is read.** At bind, through DuckDB's file system like a capture
//!   ([`DuckFile`]), so it can be wherever DuckDB can read and the session's access rules
//!   apply. A file that cannot be opened or is not a key log fails the statement there.
//!   An entry of a label pcapsql does not read (`ECH_SECRET`, `ECH_CONFIG`, ...) is skipped
//!   and counted, as Wireshark does; a leading byte order mark is ignored. A malformed entry
//!   of a label it reads, or a line that is not an entry at all, is an error.
//! - **What is said about it.** Its path, the number of the line that is wrong, and what was
//!   expected there; of skipped entries, only how many there are. Never a label, a random or
//!   a secret: a file given by mistake may be
//!   anything, a private key included. The most a message repeats of the file is the one
//!   character of a field that is not a hexadecimal digit.
//!
//! One key log serves every file of the call: a session is looked up by its client random.

use std::sync::Arc;

use duckdb_neo::{bind_arguments::BindArgument, connection::Context, Error, Result};
use pcapsql_core::{KeyLog, KeyLogError};

use super::{function::CaptureFunction, PcapScan, KEYLOG};
use crate::engine::{fs::DuckFile, relation::Relation, settings};

/// The key log of a call, parsed.
pub(super) struct Keys(Arc<KeyLog>);

impl Keys {
    pub(super) fn keylog(&self) -> &KeyLog {
        &self.0
    }

    /// For how many TLS sessions the key log has secrets.
    pub(super) fn sessions(&self) -> usize {
        self.0.session_count()
    }

    /// How many entries of labels pcapsql does not read were skipped.
    pub(super) fn skipped(&self) -> usize {
        self.0.skipped_count()
    }
}

/// Without the secrets, which `KeyLog`'s own `Debug` would print.
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys({} sessions)", self.sessions())
    }
}

/// What is wrong with a key log, without anything the file holds.
fn describe(error: &KeyLogError) -> String {
    match error {
        KeyLogError::Io(error) => error.to_string(),
        // The messages of these two say what was expected and how long what was found is.
        KeyLogError::InvalidHex { line, message }
        | KeyLogError::InvalidFormat { line, message } => {
            format!("line {line}: {message}")
        }
        // The label is whatever the line starts with: not repeated. (An unknown label on a
        // line shaped like an entry is skipped, not an error.)
        KeyLogError::UnknownKeyType { line, .. } => {
            format!(
                "line {line} is not a key log entry (an unknown label, not followed by a \
                 64-digit client random and a hexadecimal value)"
            )
        }
    }
}

impl PcapScan {
    /// The key log the call decrypts TLS with, if it reads a stream table and one is named
    /// (see the module documentation).
    pub(super) fn keylog(
        &self,
        context: &Context,
        arguments: &[BindArgument],
        relation: Relation,
    ) -> Result<Option<Keys>> {
        if !relation.is_stream() {
            return Ok(None);
        }
        let (path, origin) = match self.keylog_argument(arguments)? {
            Some(path) => (path, String::new()),
            None => (
                settings::keylog(context)?,
                format!(" (the setting {})", settings::KEYLOG),
            ),
        };
        if path.is_empty() {
            return Ok(None);
        }
        let file = DuckFile::open(context, &path).map_err(|error| Error {
            code: error.code,
            message: format!(
                "{}: cannot open the key log '{path}'{origin}: {}",
                self.name, error.message
            ),
        })?;
        let keylog = KeyLog::from_reader(file).map_err(|error| {
            self.invalid(format_args!(
                "'{path}'{origin} is not a TLS key log pcapsql can read (NSS key log format, \
                 the file SSLKEYLOGFILE names): {}",
                describe(&error)
            ))
        })?;
        Ok(Some(Keys(Arc::new(keylog))))
    }

    /// The `keylog` parameter: `None` when the call does not give it, or gives NULL.
    fn keylog_argument(&self, arguments: &[BindArgument]) -> Result<Option<String>> {
        let Some(index) = self.positions().keylog else {
            return Ok(None);
        };
        let value = arguments
            .get(index)
            .and_then(|argument| argument.value.as_ref())
            .ok_or_else(|| self.invalid(format_args!("{KEYLOG} must be a constant")))?;
        value.get::<String>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SECRET: &str = "5ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2";

    fn failure(text: &str) -> String {
        describe(&KeyLog::parse(text).unwrap_err())
    }

    #[test]
    fn what_is_wrong_with_a_key_log_is_said_without_its_content() {
        for (text, expected) in [
            (
                format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM}"),
                "line 1: expected 3 space-separated fields, got 2",
            ),
            (
                format!("# a comment\n\nNOT_A_LABEL {RANDOM} {SECRET}z"),
                "line 3 is not a key log entry (an unknown label, not followed by a 64-digit \
                 client random and a hexadecimal value)",
            ),
            (
                format!("CLIENT_TRAFFIC_SECRET_0 {SECRET}00 {SECRET}"),
                "line 1: expected 64 hex chars for client_random, got 66",
            ),
        ] {
            assert_eq!(failure(&text), expected);
        }
        // Whatever the line holds, none of it is in the message.
        for text in [
            format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {SECRET}xyz"),
            format!("CLIENT_RANDOM {RANDOM} {SECRET}"),
            format!("{SECRET} {RANDOM} {SECRET}"),
            format!("-----BEGIN PRIVATE KEY-----\n{SECRET}"),
        ] {
            let message = failure(&text);
            assert!(message.starts_with("line 1"), "{message}");
            for part in [SECRET, RANDOM, "5ec2", "BEGIN", "xyz"] {
                assert!(!message.contains(part), "{message}");
            }
        }
    }

    #[test]
    fn an_entry_of_an_unknown_label_is_skipped() {
        let text = format!(
            "\u{feff}ECH_SECRET {RANDOM} {SECRET}\nCLIENT_TRAFFIC_SECRET_0 {RANDOM} {SECRET}\n\
             ECH_CONFIG {RANDOM} 0011\n"
        );
        let keys = Keys(Arc::new(KeyLog::parse(&text).unwrap()));
        assert_eq!((keys.sessions(), keys.skipped()), (1, 2));
    }

    #[test]
    fn the_debug_form_of_a_key_log_has_no_secret() {
        let text = format!(
            "CLIENT_TRAFFIC_SECRET_0 {RANDOM} {SECRET}\nSERVER_TRAFFIC_SECRET_0 {RANDOM} {SECRET}"
        );
        let keys = Keys(Arc::new(KeyLog::parse(&text).unwrap()));
        assert_eq!(keys.sessions(), 1);
        assert_eq!(format!("{keys:?}"), "Keys(1 sessions)");
    }
}
