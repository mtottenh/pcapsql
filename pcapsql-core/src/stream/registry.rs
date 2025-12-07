use super::{StreamContext, StreamParser};

/// Registry of available stream parsers.
pub struct StreamRegistry {
    parsers: Vec<Box<dyn StreamParser>>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// Register a stream parser.
    pub fn register<P: StreamParser + 'static>(&mut self, parser: P) {
        self.parsers.push(Box::new(parser));
    }

    /// Find a parser that can handle this stream.
    pub fn find_parser(&self, context: &StreamContext) -> Option<&dyn StreamParser> {
        self.parsers
            .iter()
            .find(|p| p.can_parse_stream(context))
            .map(|p| p.as_ref())
    }

    /// Get a parser by name.
    pub fn get_parser(&self, name: &str) -> Option<&dyn StreamParser> {
        self.parsers
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// Get all registered parser names.
    pub fn parser_names(&self) -> Vec<&'static str> {
        self.parsers.iter().map(|p| p.name()).collect()
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}
