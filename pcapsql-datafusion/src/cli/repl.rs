//! Interactive REPL (Read-Eval-Print Loop).

use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result as RlResult};

/// REPL meta-commands (prefixed with `.`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplCommand {
    /// Show help
    Help,
    /// List tables
    Tables,
    /// Show schema
    Schema,
    /// List protocols
    Protocols,
    /// Exit the REPL
    Quit,
    /// Execute SQL query
    Sql(String),
    /// Export query results to file
    /// First String is filename, second is optional SQL query
    Export(String, Option<String>),
    /// Show cache statistics
    CacheStats,
    /// Reset cache statistics counters
    CacheStatsReset,
    /// Show capture time information
    TimeInfo,
    /// Hex dump of a packet frame
    Hexdump(u64),
    /// Show capture statistics (packets, bytes, duration, protocols)
    Stats,
    /// Show top N values for a column
    Top(String, usize),
    /// Show histogram distribution for a column
    Histogram(String),
    /// Unknown command
    Unknown(String),
    /// Empty input
    Empty,
}

impl ReplCommand {
    /// Parse a line of input into a command.
    pub fn parse(input: &str) -> Self {
        let trimmed = input.trim();

        if trimmed.is_empty() {
            return ReplCommand::Empty;
        }

        // Check for dot commands
        if trimmed.starts_with('.') {
            let lower = trimmed.to_lowercase();

            // Handle .export specially since it has arguments
            if lower.starts_with(".export ") || lower == ".export" {
                return Self::parse_export(trimmed);
            }

            // Handle .cachestats specially since it has an optional "reset" argument
            if lower.starts_with(".cachestats") || lower.starts_with(".cs") {
                return Self::parse_cachestats(trimmed);
            }

            // Handle .hexdump specially since it requires a frame number argument
            if lower.starts_with(".hexdump") {
                return Self::parse_hexdump(trimmed);
            }

            // Handle .top specially since it has column and optional count arguments
            if lower.starts_with(".top") {
                return Self::parse_top(trimmed);
            }

            // Handle .histogram specially since it has a column argument
            if lower.starts_with(".histogram") || lower.starts_with(".hist") {
                return Self::parse_histogram(trimmed);
            }

            match lower.as_str() {
                ".stats" => ReplCommand::Stats,
                ".help" | ".h" | ".?" => ReplCommand::Help,
                ".tables" | ".t" => ReplCommand::Tables,
                ".schema" | ".s" => ReplCommand::Schema,
                ".protocols" | ".p" => ReplCommand::Protocols,
                ".quit" | ".exit" | ".q" => ReplCommand::Quit,
                ".timeinfo" | ".ti" => ReplCommand::TimeInfo,
                _ => ReplCommand::Unknown(trimmed.to_string()),
            }
        } else if trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit") {
            ReplCommand::Quit
        } else {
            ReplCommand::Sql(trimmed.to_string())
        }
    }

    /// Parse .export command with arguments.
    fn parse_export(input: &str) -> Self {
        // Format: .export <filename> [SELECT ...]
        let rest = input.strip_prefix(".export").unwrap_or(input).trim();

        if rest.is_empty() {
            return ReplCommand::Unknown(".export requires a filename".to_string());
        }

        // Check if there's a SQL query after the filename
        // Filename ends at first whitespace, SQL starts after
        let parts: Vec<&str> = rest.splitn(2, char::is_whitespace).collect();

        match parts.as_slice() {
            [filename] => ReplCommand::Export(filename.to_string(), None),
            [filename, query] => {
                let query = query.trim();
                if query.is_empty() {
                    ReplCommand::Export(filename.to_string(), None)
                } else {
                    ReplCommand::Export(filename.to_string(), Some(query.to_string()))
                }
            }
            _ => ReplCommand::Unknown(".export requires a filename".to_string()),
        }
    }

    /// Parse .cachestats command with optional "reset" argument.
    fn parse_cachestats(input: &str) -> Self {
        // Format: .cachestats [reset] or .cs [reset]
        // Strip prefix case-insensitively
        let lower = input.to_lowercase();
        let rest = if lower.starts_with(".cachestats") {
            input[".cachestats".len()..].trim()
        } else if lower.starts_with(".cs") {
            input[".cs".len()..].trim()
        } else {
            ""
        };

        if rest.is_empty() {
            ReplCommand::CacheStats
        } else if rest.eq_ignore_ascii_case("reset") {
            ReplCommand::CacheStatsReset
        } else {
            ReplCommand::Unknown(format!(
                "Unknown cachestats subcommand: '{rest}'. Use '.cachestats' or '.cachestats reset'"
            ))
        }
    }

    /// Parse .hexdump command with required frame number argument.
    fn parse_hexdump(input: &str) -> Self {
        // Format: .hexdump <frame_number>
        let rest = input
            .strip_prefix(".hexdump")
            .or_else(|| input.strip_prefix(".HEXDUMP"))
            .unwrap_or(input)
            .trim();

        if rest.is_empty() {
            ReplCommand::Unknown(".hexdump requires a frame number".to_string())
        } else {
            match rest.parse::<u64>() {
                Ok(frame_num) => ReplCommand::Hexdump(frame_num),
                Err(_) => ReplCommand::Unknown(format!("Invalid frame number: {rest}")),
            }
        }
    }

    /// Parse .top command with column name and optional count.
    fn parse_top(input: &str) -> Self {
        // Format: .top <column> [N]
        let lower = input.to_lowercase();
        let rest = if lower.starts_with(".top") {
            input[".top".len()..].trim()
        } else {
            ""
        };

        if rest.is_empty() {
            return ReplCommand::Unknown(".top requires a column name".to_string());
        }

        let parts: Vec<&str> = rest.split_whitespace().collect();
        match parts.as_slice() {
            [column] => ReplCommand::Top(column.to_string(), 10), // Default to 10
            [column, count] => match count.parse::<usize>() {
                Ok(n) if n > 0 => ReplCommand::Top(column.to_string(), n),
                Ok(_) => ReplCommand::Unknown("Count must be greater than 0".to_string()),
                Err(_) => ReplCommand::Unknown(format!("Invalid count: {count}")),
            },
            _ => ReplCommand::Unknown("Usage: .top <column> [count]".to_string()),
        }
    }

    /// Parse .histogram command with column name.
    fn parse_histogram(input: &str) -> Self {
        // Format: .histogram <column> or .hist <column>
        let lower = input.to_lowercase();
        let rest = if lower.starts_with(".histogram") {
            input[".histogram".len()..].trim()
        } else if lower.starts_with(".hist") {
            input[".hist".len()..].trim()
        } else {
            ""
        };

        if rest.is_empty() {
            ReplCommand::Unknown(".histogram requires a column name".to_string())
        } else {
            // Just take the first word as the column name
            let column = rest.split_whitespace().next().unwrap_or(rest);
            ReplCommand::Histogram(column.to_string())
        }
    }

    /// Check if this is a quit command.
    pub fn is_quit(&self) -> bool {
        matches!(self, ReplCommand::Quit)
    }
}

/// Input from the REPL - either a command or a request to quit.
#[derive(Debug)]
pub enum ReplInput {
    /// User provided input
    Command(ReplCommand),
    /// User pressed Ctrl-D or Ctrl-C
    Exit,
}

/// Interactive SQL REPL using rustyline for line editing and history.
pub struct Repl {
    editor: DefaultEditor,
    history_file: Option<String>,
}

impl Repl {
    /// Create a new REPL instance.
    pub fn new() -> RlResult<Self> {
        let editor = DefaultEditor::new()?;
        Ok(Self {
            editor,
            history_file: None,
        })
    }

    /// Set the history file path.
    pub fn with_history(mut self, path: &str) -> Self {
        self.history_file = Some(path.to_string());
        if let Err(e) = self.editor.load_history(path) {
            tracing::debug!("Could not load history: {}", e);
        }
        self
    }

    /// Read a complete input from the user (handles multi-line SQL).
    pub fn read_input(&mut self) -> RlResult<ReplInput> {
        let mut buffer = String::new();
        let mut first_line = true;

        loop {
            let prompt = if first_line { "pcapsql> " } else { "    ...> " };

            match self.editor.readline(prompt) {
                Ok(line) => {
                    let trimmed = line.trim();

                    // Add to history if non-empty
                    if !trimmed.is_empty() {
                        let _ = self.editor.add_history_entry(&line);
                    }

                    // Handle dot commands immediately (single line)
                    if first_line && trimmed.starts_with('.') {
                        return Ok(ReplInput::Command(ReplCommand::parse(trimmed)));
                    }

                    // Handle quit commands
                    if first_line
                        && (trimmed.eq_ignore_ascii_case("quit")
                            || trimmed.eq_ignore_ascii_case("exit"))
                    {
                        return Ok(ReplInput::Command(ReplCommand::Quit));
                    }

                    buffer.push_str(&line);
                    buffer.push('\n');

                    // Check if statement is complete (ends with semicolon)
                    if trimmed.ends_with(';') {
                        return Ok(ReplInput::Command(ReplCommand::Sql(buffer)));
                    }

                    // Empty line on first input
                    if first_line && trimmed.is_empty() {
                        return Ok(ReplInput::Command(ReplCommand::Empty));
                    }

                    first_line = false;
                }
                Err(ReadlineError::Eof) | Err(ReadlineError::Interrupted) => {
                    return Ok(ReplInput::Exit);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Save history to file.
    pub fn save_history(&mut self) {
        if let Some(ref path) = self.history_file {
            if let Err(e) = self.editor.save_history(path) {
                tracing::debug!("Could not save history: {}", e);
            }
        }
    }
}

impl Default for Repl {
    fn default() -> Self {
        Self::new().expect("Failed to create REPL")
    }
}

impl Drop for Repl {
    fn drop(&mut self) {
        self.save_history();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_commands() {
        assert_eq!(ReplCommand::parse(".help"), ReplCommand::Help);
        assert_eq!(ReplCommand::parse(".H"), ReplCommand::Help);
        assert_eq!(ReplCommand::parse(".tables"), ReplCommand::Tables);
        assert_eq!(ReplCommand::parse(".quit"), ReplCommand::Quit);
        assert_eq!(ReplCommand::parse("exit"), ReplCommand::Quit);
        assert_eq!(ReplCommand::parse(""), ReplCommand::Empty);
        assert!(matches!(
            ReplCommand::parse("SELECT * FROM packets"),
            ReplCommand::Sql(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".unknown"),
            ReplCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_parse_export_filename_only() {
        assert_eq!(
            ReplCommand::parse(".export output.parquet"),
            ReplCommand::Export("output.parquet".to_string(), None)
        );
        assert_eq!(
            ReplCommand::parse(".export results.csv"),
            ReplCommand::Export("results.csv".to_string(), None)
        );
    }

    #[test]
    fn test_parse_export_with_query() {
        assert_eq!(
            ReplCommand::parse(".export output.csv SELECT * FROM tcp"),
            ReplCommand::Export(
                "output.csv".to_string(),
                Some("SELECT * FROM tcp".to_string())
            )
        );
        assert_eq!(
            ReplCommand::parse(
                ".export data.json SELECT src_ip, dst_ip FROM packets WHERE protocol = 'TCP'"
            ),
            ReplCommand::Export(
                "data.json".to_string(),
                Some("SELECT src_ip, dst_ip FROM packets WHERE protocol = 'TCP'".to_string())
            )
        );
    }

    #[test]
    fn test_parse_export_no_filename() {
        assert!(matches!(
            ReplCommand::parse(".export"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".export "),
            ReplCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_parse_cachestats() {
        assert_eq!(ReplCommand::parse(".cachestats"), ReplCommand::CacheStats);
        assert_eq!(ReplCommand::parse(".Cachestats"), ReplCommand::CacheStats);
        assert_eq!(ReplCommand::parse(".CACHESTATS"), ReplCommand::CacheStats);
        assert_eq!(ReplCommand::parse(".cs"), ReplCommand::CacheStats);
        assert_eq!(ReplCommand::parse(".CS"), ReplCommand::CacheStats);
    }

    #[test]
    fn test_parse_cachestats_reset() {
        assert_eq!(
            ReplCommand::parse(".cachestats reset"),
            ReplCommand::CacheStatsReset
        );
        assert_eq!(
            ReplCommand::parse(".cachestats RESET"),
            ReplCommand::CacheStatsReset
        );
        assert_eq!(
            ReplCommand::parse(".cs reset"),
            ReplCommand::CacheStatsReset
        );
        assert_eq!(
            ReplCommand::parse(".CS Reset"),
            ReplCommand::CacheStatsReset
        );
    }

    #[test]
    fn test_parse_cachestats_unknown_subcommand() {
        assert!(matches!(
            ReplCommand::parse(".cachestats foo"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".cs clear"),
            ReplCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_parse_timeinfo() {
        assert_eq!(ReplCommand::parse(".timeinfo"), ReplCommand::TimeInfo);
        assert_eq!(ReplCommand::parse(".ti"), ReplCommand::TimeInfo);
        assert_eq!(ReplCommand::parse(".TIMEINFO"), ReplCommand::TimeInfo);
        assert_eq!(ReplCommand::parse(".TI"), ReplCommand::TimeInfo);
    }

    #[test]
    fn test_parse_hexdump() {
        assert_eq!(ReplCommand::parse(".hexdump 42"), ReplCommand::Hexdump(42));
        assert_eq!(ReplCommand::parse(".hexdump 1"), ReplCommand::Hexdump(1));
        assert_eq!(
            ReplCommand::parse(".HEXDUMP 100"),
            ReplCommand::Hexdump(100)
        );
    }

    #[test]
    fn test_parse_hexdump_invalid() {
        assert!(matches!(
            ReplCommand::parse(".hexdump"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".hexdump abc"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".hexdump -1"),
            ReplCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_parse_stats() {
        assert_eq!(ReplCommand::parse(".stats"), ReplCommand::Stats);
        assert_eq!(ReplCommand::parse(".STATS"), ReplCommand::Stats);
        assert_eq!(ReplCommand::parse(".Stats"), ReplCommand::Stats);
    }

    #[test]
    fn test_parse_top() {
        assert_eq!(
            ReplCommand::parse(".top dst_port"),
            ReplCommand::Top("dst_port".to_string(), 10)
        );
        assert_eq!(
            ReplCommand::parse(".top src_ip 5"),
            ReplCommand::Top("src_ip".to_string(), 5)
        );
        assert_eq!(
            ReplCommand::parse(".TOP length 20"),
            ReplCommand::Top("length".to_string(), 20)
        );
    }

    #[test]
    fn test_parse_top_invalid() {
        assert!(matches!(
            ReplCommand::parse(".top"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".top dst_port abc"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".top dst_port 0"),
            ReplCommand::Unknown(_)
        ));
    }

    #[test]
    fn test_parse_histogram() {
        assert_eq!(
            ReplCommand::parse(".histogram length"),
            ReplCommand::Histogram("length".to_string())
        );
        assert_eq!(
            ReplCommand::parse(".hist dst_port"),
            ReplCommand::Histogram("dst_port".to_string())
        );
        assert_eq!(
            ReplCommand::parse(".HISTOGRAM frame_number"),
            ReplCommand::Histogram("frame_number".to_string())
        );
    }

    #[test]
    fn test_parse_histogram_invalid() {
        assert!(matches!(
            ReplCommand::parse(".histogram"),
            ReplCommand::Unknown(_)
        ));
        assert!(matches!(
            ReplCommand::parse(".hist"),
            ReplCommand::Unknown(_)
        ));
    }
}
