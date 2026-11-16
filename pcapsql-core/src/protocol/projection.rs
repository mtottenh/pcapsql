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
            .or_default();

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

/// The fields one parser extracts in a projected parse
/// ([`Protocol::parse_projected`](super::Protocol::parse_projected)).
///
/// A set of positions in the parser's field list
/// ([`Protocol::field_names`](super::Protocol::field_names)). The names a
/// [`ParseScope`](super::ParseScope) asks for are resolved into it once per
/// scope and parser; in the packet loop a parser asks about a field by its
/// position, a constant, and the answer is a bit test however many fields
/// are asked for. The empty set asks for no field: the layer is parsed for
/// what the layers after it need (the hints, the remaining bytes, whether
/// the bytes are a layer of the protocol at all) and writes nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FieldSet {
    bits: u64,
}

impl FieldSet {
    /// The longest field list a projected parse can have.
    pub const CAPACITY: usize = 64;

    /// No field.
    pub const NONE: Self = Self { bits: 0 };

    /// Every field, whatever the list: what a parser's full parse asks its
    /// projected parse for.
    pub(crate) const ALL: Self = Self { bits: u64::MAX };

    /// The fields called `names` in the field list `fields` (a parser's
    /// [`field_names`](super::Protocol::field_names), at most
    /// [`CAPACITY`](Self::CAPACITY) long). A name the list does not have is
    /// not a field the parser can write, and is left out.
    pub fn resolve<S: AsRef<str>>(fields: &[&str], names: impl IntoIterator<Item = S>) -> Self {
        debug_assert!(fields.len() <= Self::CAPACITY, "{} fields", fields.len());
        let bits = names
            .into_iter()
            .filter_map(|name| fields.iter().position(|field| *field == name.as_ref()))
            .filter(|&position| position < Self::CAPACITY)
            .fold(0, |bits, position| bits | 1 << position);
        Self { bits }
    }

    /// Every field of a list of `len` fields (`len` at most
    /// [`CAPACITY`](Self::CAPACITY)).
    pub fn all_of(len: usize) -> Self {
        debug_assert!(len <= Self::CAPACITY, "{len} fields");
        let bits = if len >= Self::CAPACITY {
            u64::MAX
        } else {
            (1 << len) - 1
        };
        Self { bits }
    }

    /// A set of the fields at the positions of the bits of `bits`.
    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Whether `field` is in the set.
    #[inline]
    pub(crate) fn has(self, field: impl ParserField) -> bool {
        self.bits >> field.position() & 1 != 0
    }

    /// Whether any field of `fields` is in the set.
    #[inline]
    pub(crate) fn has_any(self, fields: FieldSet) -> bool {
        self.bits & fields.bits != 0
    }

    /// Whether the field at `position` of the list is in the set.
    #[inline]
    pub fn contains(self, position: usize) -> bool {
        position < Self::CAPACITY && self.bits >> position & 1 != 0
    }

    /// The number of fields.
    pub fn len(self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Whether there is no field.
    pub fn is_empty(self) -> bool {
        self.bits == 0
    }
}

/// A field of one parser's field list, by its position there: the variants
/// of the enum [`field_list!`] declares.
pub(crate) trait ParserField: Copy {
    /// The field's position in the list.
    fn position(self) -> u32;
}

/// Declares the field list of a parser with a projected parse.
///
/// ```ignore
/// field_list! {
///     /// The fields of a `udp` layer, in the order the parser writes them.
///     enum Field {
///         SrcPort = "src_port",
///         DstPort = "dst_port",
///     }
///     groups {
///         /// Both ports.
///         PORTS = [SrcPort, DstPort];
///     }
/// }
/// ```
///
/// gives the enum, with a variant per field at the position of its name in
/// `Field::NAMES` (what the parser's
/// [`field_names`](super::Protocol::field_names) returns), and a constant
/// [`FieldSet`] per group. A parser asks the projection about a field with
/// `projection.has(Field::SrcPort)` and about a group with
/// `projection.has_any(Field::PORTS)`.
macro_rules! field_list {
    (
        $(#[$meta:meta])*
        enum $name:ident {
            $($variant:ident = $field:literal,)+
        }
        $(
            groups {
                $(
                    $(#[$group_meta:meta])*
                    $group:ident = [$($member:ident),+ $(,)?];
                )+
            }
        )?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum $name {
            $($variant,)+
        }

        impl $name {
            /// The names of the fields, each at the position of its variant.
            const NAMES: &'static [&'static str] = &[$($field,)+];
            $($(
                $(#[$group_meta])*
                const $group: $crate::protocol::FieldSet = $crate::protocol::FieldSet::from_bits(
                    0 $(| 1 << $name::$member as u32)+
                );
            )+)?
        }

        impl $crate::protocol::ParserField for $name {
            #[inline]
            fn position(self) -> u32 {
                self as u32
            }
        }

        const _: () = assert!($name::NAMES.len() <= $crate::protocol::FieldSet::CAPACITY);
    };
}
pub(crate) use field_list;

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
        config.add_protocol_fields("tcp", ["src_port", "dst_port"]);

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
            .with_protocol_fields("tcp", ["src_port", "dst_port"])
            .with_protocol_fields("udp", ["src_port", "dst_port", "length"]);

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

    field_list! {
        /// A list of four fields.
        enum Field {
            A = "a",
            B = "b",
            C = "c",
            D = "d",
        }
        groups {
            /// Two of them.
            BD = [B, D];
        }
    }

    #[test]
    fn a_field_set_is_resolved_from_names_against_a_list() {
        assert_eq!(Field::NAMES, ["a", "b", "c", "d"]);
        let set = FieldSet::resolve(Field::NAMES, ["d", "b", "x", "b", ""]);
        assert_eq!(set.len(), 2);
        assert!(set.has(Field::B) && set.has(Field::D));
        assert!(!set.has(Field::A) && !set.has(Field::C));
        assert!(set.contains(1) && set.contains(3) && !set.contains(0));
        assert!(!set.contains(64) && !set.contains(usize::MAX));
        assert_eq!(set, Field::BD);
        assert!(set.has_any(Field::BD));
        assert!(!FieldSet::resolve(Field::NAMES, ["a", "c"]).has_any(Field::BD));

        let none = FieldSet::resolve(Field::NAMES, ["x"]);
        assert!(none.is_empty());
        assert_eq!(none, FieldSet::NONE);
        assert_eq!(FieldSet::default(), FieldSet::NONE);
        assert!(!none.has(Field::A));

        let all = FieldSet::all_of(Field::NAMES.len());
        assert_eq!(all, FieldSet::resolve(Field::NAMES, Field::NAMES));
        assert_eq!(all.len(), 4);
        assert_eq!(FieldSet::all_of(0), FieldSet::NONE);
        assert_eq!(FieldSet::all_of(64).len(), 64);
        assert!(FieldSet::ALL.has(Field::A) && FieldSet::ALL.has(Field::D));
    }

    #[test]
    fn test_from_field_names() {
        let config = ProjectionConfig::from_field_names("dns", ["query_name", "query_type"]);

        let fields = config.get("dns").unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.contains("query_name"));
        assert!(fields.contains("query_type"));
    }
}
