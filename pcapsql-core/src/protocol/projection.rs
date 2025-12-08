//! Field projection configuration for parsing optimization.
//!
//! When executing SQL queries that only need certain columns,
//! we can skip extracting fields that aren't needed. This module provides
//! configuration structures to specify which fields to extract.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::collections::HashSet;
//! use pcapsql_core::protocol::{ProjectionConfig, default_registry};
//!
//! // Create projection requesting only ports from TCP
//! let mut config = ProjectionConfig::new();
//! config.add_protocol_fields("tcp", &["src_port", "dst_port"]);
//!
//! // Parse with projection
//! let fields = config.get("tcp");
//! let result = parser.parse_projected(&data, &context, fields);
//! ```

use std::collections::{HashMap, HashSet};

/// Configuration for field projection during parsing.
///
/// Stores per-protocol field sets that control which fields are extracted.
/// Fields not in the set are skipped during parsing, reducing CPU usage.
#[derive(Debug, Clone, Default)]
pub struct ProjectionConfig {
    /// Per-protocol field projections.
    /// Key is protocol name, value is set of required field names.
    protocol_fields: HashMap<String, HashSet<String>>,

    /// If true, always include fields needed for protocol chaining.
    /// These are fields required to detect and parse child protocols.
    include_chain_fields: bool,
}

impl ProjectionConfig {
    /// Create a new empty projection configuration.
    pub fn new() -> Self {
        Self {
            protocol_fields: HashMap::new(),
            include_chain_fields: true,
        }
    }

    /// Create configuration that includes chain fields.
    ///
    /// Chain fields are those needed to detect and parse child protocols,
    /// such as IP protocol number or TCP/UDP ports.
    pub fn with_chain_fields(mut self) -> Self {
        self.include_chain_fields = true;
        self
    }

    /// Disable automatic inclusion of chain fields.
    pub fn without_chain_fields(mut self) -> Self {
        self.include_chain_fields = false;
        self
    }

    /// Add required fields for a protocol.
    ///
    /// # Arguments
    ///
    /// * `protocol` - Protocol name (e.g., "tcp", "dns")
    /// * `fields` - Field names to extract (e.g., "src_port", "dst_port")
    pub fn add_protocol_fields<I, S>(&mut self, protocol: &str, fields: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let field_set = self
            .protocol_fields
            .entry(protocol.to_string())
            .or_insert_with(HashSet::new);

        for field in fields {
            field_set.insert(field.as_ref().to_string());
        }
    }

    /// Builder-style method to add protocol fields.
    pub fn with_protocol_fields<I, S>(mut self, protocol: &str, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.add_protocol_fields(protocol, fields);
        self
    }

    /// Get the projection for a specific protocol.
    ///
    /// Returns None if no projection is configured for this protocol,
    /// meaning all fields should be extracted.
    pub fn get(&self, protocol: &str) -> Option<&HashSet<String>> {
        self.protocol_fields.get(protocol)
    }

    /// Check if any projection is configured.
    pub fn is_empty(&self) -> bool {
        self.protocol_fields.is_empty()
    }

    /// Check if chain fields should be included.
    pub fn include_chain_fields(&self) -> bool {
        self.include_chain_fields
    }

    /// Get all protocol names with configured projections.
    pub fn protocols(&self) -> impl Iterator<Item = &str> {
        self.protocol_fields.keys().map(|s| s.as_str())
    }

    /// Create a projection config from DataFusion projection indices.
    ///
    /// Converts projection indices to field names based on schema.
    ///
    /// # Arguments
    ///
    /// * `protocol` - Protocol name
    /// * `field_names` - Iterator of field names to include
    pub fn from_field_names<I, S>(protocol: &str, field_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut config = Self::new();
        config.add_protocol_fields(protocol, field_names);
        config
    }
}

/// Fields required for protocol chaining.
///
/// These fields must be extracted even if not in the projection,
/// because they're needed to detect and parse child protocols.
pub fn chain_fields_for_protocol(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "ethernet" => &["ethertype"],
        "vlan" => &["ethertype"],
        "ipv4" => &["protocol", "src_ip", "dst_ip"],
        "ipv6" => &["next_header", "src_ip", "dst_ip"],
        "tcp" => &["src_port", "dst_port"],
        "udp" => &["src_port", "dst_port"],
        "gre" => &["protocol_type"],
        "mpls" => &["bottom_of_stack"],
        "vxlan" => &["vni"],
        "gtp" => &["teid"],
        _ => &[],
    }
}

/// Merge projection with chain fields if needed.
///
/// Returns a new set containing the projection fields plus any
/// chain fields needed for protocol detection.
pub fn merge_with_chain_fields(
    protocol: &str,
    projection: Option<&HashSet<String>>,
    include_chain: bool,
) -> Option<HashSet<String>> {
    let projection = projection?;

    if !include_chain {
        return Some(projection.clone());
    }

    let chain_fields = chain_fields_for_protocol(protocol);
    if chain_fields.is_empty() {
        return Some(projection.clone());
    }

    let mut merged = projection.clone();
    for field in chain_fields {
        merged.insert((*field).to_string());
    }

    Some(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_projection_config_new() {
        let config = ProjectionConfig::new();
        assert!(config.is_empty());
        assert!(config.include_chain_fields());
    }

    #[test]
    fn test_add_protocol_fields() {
        let mut config = ProjectionConfig::new();
        config.add_protocol_fields("tcp", &["src_port", "dst_port"]);

        let fields = config.get("tcp");
        assert!(fields.is_some());
        let fields = fields.unwrap();
        assert!(fields.contains("src_port"));
        assert!(fields.contains("dst_port"));
        assert!(!fields.contains("seq"));
    }

    #[test]
    fn test_builder_pattern() {
        let config = ProjectionConfig::new()
            .with_protocol_fields("tcp", &["src_port", "dst_port"])
            .with_protocol_fields("udp", &["src_port", "dst_port", "length"]);

        assert!(!config.is_empty());
        assert!(config.get("tcp").is_some());
        assert!(config.get("udp").is_some());
        assert!(config.get("dns").is_none());
    }

    #[test]
    fn test_chain_fields() {
        assert!(!chain_fields_for_protocol("ethernet").is_empty());
        assert!(!chain_fields_for_protocol("ipv4").is_empty());
        assert!(!chain_fields_for_protocol("tcp").is_empty());
        assert!(chain_fields_for_protocol("dns").is_empty());
    }

    #[test]
    fn test_merge_with_chain_fields() {
        let projection: HashSet<String> = ["src_port"].iter().map(|s| s.to_string()).collect();

        // With chain fields enabled
        let merged = merge_with_chain_fields("tcp", Some(&projection), true);
        assert!(merged.is_some());
        let merged = merged.unwrap();
        assert!(merged.contains("src_port"));
        assert!(merged.contains("dst_port")); // Chain field added

        // Without chain fields
        let merged = merge_with_chain_fields("tcp", Some(&projection), false);
        assert!(merged.is_some());
        let merged = merged.unwrap();
        assert!(merged.contains("src_port"));
        assert!(!merged.contains("dst_port")); // Chain field NOT added
    }

    #[test]
    fn test_from_field_names() {
        let config = ProjectionConfig::from_field_names("dns", &["query_name", "query_type"]);

        let fields = config.get("dns").unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.contains("query_name"));
        assert!(fields.contains("query_type"));
    }
}
