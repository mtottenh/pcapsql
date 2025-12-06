//! Filter pushdown evaluation for streaming queries.
//!
//! This module provides a way to evaluate simple WHERE clause predicates
//! against parsed packet fields without going through DataFusion's full
//! expression evaluation machinery.

use datafusion::common::ScalarValue;
use datafusion::logical_expr::{BinaryExpr, Expr, Operator};

use crate::protocol::{FieldValue, ParseResult};

/// Comparison operators for predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

impl CompareOp {
    /// Convert from DataFusion operator.
    fn from_datafusion(op: &Operator) -> Option<Self> {
        match op {
            Operator::Eq => Some(CompareOp::Eq),
            Operator::NotEq => Some(CompareOp::NotEq),
            Operator::Lt => Some(CompareOp::Lt),
            Operator::LtEq => Some(CompareOp::LtEq),
            Operator::Gt => Some(CompareOp::Gt),
            Operator::GtEq => Some(CompareOp::GtEq),
            _ => None,
        }
    }

    /// Evaluate comparison between two i64 values.
    fn compare_i64(self, left: i64, right: i64) -> bool {
        match self {
            CompareOp::Eq => left == right,
            CompareOp::NotEq => left != right,
            CompareOp::Lt => left < right,
            CompareOp::LtEq => left <= right,
            CompareOp::Gt => left > right,
            CompareOp::GtEq => left >= right,
        }
    }

    /// Evaluate comparison between two strings.
    fn compare_str(self, left: &str, right: &str) -> bool {
        match self {
            CompareOp::Eq => left == right,
            CompareOp::NotEq => left != right,
            CompareOp::Lt => left < right,
            CompareOp::LtEq => left <= right,
            CompareOp::Gt => left > right,
            CompareOp::GtEq => left >= right,
        }
    }
}

/// A simple predicate that can be evaluated against packet data.
#[derive(Debug, Clone)]
pub enum SimplePredicate {
    /// String equality: column = 'value'
    StringCompare {
        field: String,
        op: CompareOp,
        value: String,
    },
    /// Integer comparison: column <op> value
    IntCompare {
        field: String,
        op: CompareOp,
        value: i64,
    },
    /// Protocol equality: protocol = 'TCP'
    ProtocolEquals { value: String },
    /// AND of two predicates
    And(Box<SimplePredicate>, Box<SimplePredicate>),
    /// Always true (used for unsupported filters that DataFusion will handle)
    AlwaysTrue,
}

impl SimplePredicate {
    /// Evaluate this predicate against parsed packet data.
    pub fn matches(&self, parsed: &[(&'static str, ParseResult)]) -> bool {
        match self {
            SimplePredicate::StringCompare { field, op, value } => {
                if let Some(field_value) = get_field_value(parsed, field) {
                    if let Some(s) = field_value.as_string() {
                        return op.compare_str(&s, value);
                    }
                }
                // Field not found or not a string - doesn't match (unless NotEq)
                *op == CompareOp::NotEq
            }
            SimplePredicate::IntCompare { field, op, value } => {
                if let Some(field_value) = get_field_value(parsed, field) {
                    if let Some(v) = field_value.as_i64() {
                        return op.compare_i64(v, *value);
                    }
                }
                // Field not found or not numeric - doesn't match (unless NotEq)
                *op == CompareOp::NotEq
            }
            SimplePredicate::ProtocolEquals { value } => {
                // Check transport protocol name
                let protocol = get_protocol_name(parsed);
                protocol.map_or(false, |p| p.eq_ignore_ascii_case(value))
            }
            SimplePredicate::And(left, right) => left.matches(parsed) && right.matches(parsed),
            SimplePredicate::AlwaysTrue => true,
        }
    }
}

/// Get a field value from parsed packet data.
fn get_field_value<'a>(
    parsed: &'a [(&'static str, ParseResult)],
    field_name: &str,
) -> Option<&'a FieldValue> {
    // Handle common field mappings
    match field_name {
        // Ethernet fields
        "eth_src" => find_field(parsed, "ethernet", "src_mac"),
        "eth_dst" => find_field(parsed, "ethernet", "dst_mac"),
        "eth_type" => find_field(parsed, "ethernet", "ethertype"),
        // IP fields
        "src_ip" => find_field(parsed, "ipv4", "src_ip")
            .or_else(|| find_field(parsed, "ipv6", "src_ip")),
        "dst_ip" => find_field(parsed, "ipv4", "dst_ip")
            .or_else(|| find_field(parsed, "ipv6", "dst_ip")),
        "ip_ttl" => find_field(parsed, "ipv4", "ttl").or_else(|| find_field(parsed, "ipv6", "hop_limit")),
        "ip_protocol" => find_field(parsed, "ipv4", "protocol")
            .or_else(|| find_field(parsed, "ipv6", "next_header")),
        // Port fields
        "src_port" => find_field(parsed, "tcp", "src_port")
            .or_else(|| find_field(parsed, "udp", "src_port")),
        "dst_port" => find_field(parsed, "tcp", "dst_port")
            .or_else(|| find_field(parsed, "udp", "dst_port")),
        // TCP fields
        "tcp_flags" => find_field(parsed, "tcp", "flags"),
        "tcp_seq" => find_field(parsed, "tcp", "seq"),
        "tcp_ack" => find_field(parsed, "tcp", "ack"),
        // ICMP fields
        "icmp_type" => find_field(parsed, "icmp", "type"),
        "icmp_code" => find_field(parsed, "icmp", "code"),
        // Frame fields - need to be handled at a higher level
        "frame_number" | "timestamp" | "length" | "original_length" | "payload_length" => None,
        // Try to find in any protocol
        _ => {
            for (_, result) in parsed {
                if let Some(v) = result.get(field_name) {
                    return Some(v);
                }
            }
            None
        }
    }
}

/// Find a field in a specific protocol's parse result.
fn find_field<'a>(
    parsed: &'a [(&'static str, ParseResult)],
    protocol: &str,
    field: &str,
) -> Option<&'a FieldValue> {
    parsed
        .iter()
        .find(|(name, _)| *name == protocol)
        .and_then(|(_, result)| result.get(field))
}

/// Get the transport protocol name from parsed data.
fn get_protocol_name(parsed: &[(&'static str, ParseResult)]) -> Option<&'static str> {
    for (name, _) in parsed.iter().rev() {
        match *name {
            "tcp" => return Some("TCP"),
            "udp" => return Some("UDP"),
            "icmp" => return Some("ICMP"),
            _ => {}
        }
    }
    // Check if we at least have IP
    for (name, _) in parsed {
        if *name == "ipv4" || *name == "ipv6" {
            return Some("IP");
        }
    }
    None
}

/// Filter evaluator for streaming queries.
#[derive(Debug, Clone)]
pub struct FilterEvaluator {
    predicate: SimplePredicate,
}

impl FilterEvaluator {
    /// Try to create a filter evaluator from DataFusion expressions.
    ///
    /// Returns None if none of the expressions can be pushed down.
    /// For expressions we can't handle, we include AlwaysTrue predicates
    /// and let DataFusion filter the results.
    pub fn try_from_exprs(exprs: &[Expr]) -> Option<Self> {
        if exprs.is_empty() {
            return None;
        }

        // Convert each expression and AND them together
        let mut predicates: Vec<SimplePredicate> = Vec::new();
        let mut has_pushable = false;

        for expr in exprs {
            if let Some(pred) = convert_expr(expr) {
                if !matches!(pred, SimplePredicate::AlwaysTrue) {
                    has_pushable = true;
                }
                predicates.push(pred);
            } else {
                predicates.push(SimplePredicate::AlwaysTrue);
            }
        }

        if !has_pushable {
            return None;
        }

        // Combine all predicates with AND
        let predicate = predicates
            .into_iter()
            .reduce(|acc, pred| SimplePredicate::And(Box::new(acc), Box::new(pred)))
            .unwrap_or(SimplePredicate::AlwaysTrue);

        Some(Self { predicate })
    }

    /// Evaluate the filter against parsed packet data.
    pub fn matches(&self, parsed: &[(&'static str, ParseResult)]) -> bool {
        self.predicate.matches(parsed)
    }
}

/// Convert a DataFusion expression to a simple predicate.
fn convert_expr(expr: &Expr) -> Option<SimplePredicate> {
    match expr {
        Expr::BinaryExpr(BinaryExpr { left, op, right }) => {
            convert_binary_expr(left.as_ref(), op, right.as_ref())
        }
        Expr::Column(_) => {
            // A column by itself is truthy if non-null, but we can't easily check
            Some(SimplePredicate::AlwaysTrue)
        }
        _ => Some(SimplePredicate::AlwaysTrue),
    }
}

/// Convert a binary expression to a simple predicate.
fn convert_binary_expr(left: &Expr, op: &Operator, right: &Expr) -> Option<SimplePredicate> {
    // Handle AND
    if *op == Operator::And {
        let left_pred = convert_expr(left)?;
        let right_pred = convert_expr(right)?;
        return Some(SimplePredicate::And(
            Box::new(left_pred),
            Box::new(right_pred),
        ));
    }

    // Handle OR - we can't short-circuit efficiently, so return AlwaysTrue
    if *op == Operator::Or {
        return Some(SimplePredicate::AlwaysTrue);
    }

    // Handle comparison operators
    let compare_op = CompareOp::from_datafusion(op)?;

    // Try column = literal pattern
    if let (Expr::Column(col), Expr::Literal(lit)) = (left, right) {
        return convert_column_literal_compare(&col.name, compare_op, lit);
    }

    // Try literal = column pattern (reverse)
    if let (Expr::Literal(lit), Expr::Column(col)) = (left, right) {
        // Reverse the operator for symmetric comparisons
        let reversed_op = match compare_op {
            CompareOp::Lt => CompareOp::Gt,
            CompareOp::LtEq => CompareOp::GtEq,
            CompareOp::Gt => CompareOp::Lt,
            CompareOp::GtEq => CompareOp::LtEq,
            other => other,
        };
        return convert_column_literal_compare(&col.name, reversed_op, lit);
    }

    // Can't push down this expression
    Some(SimplePredicate::AlwaysTrue)
}

/// Convert a column = literal comparison to a simple predicate.
fn convert_column_literal_compare(
    column: &str,
    op: CompareOp,
    literal: &ScalarValue,
) -> Option<SimplePredicate> {
    // Handle protocol column specially
    if column == "protocol" {
        if let ScalarValue::Utf8(Some(s)) = literal {
            if op == CompareOp::Eq {
                return Some(SimplePredicate::ProtocolEquals { value: s.clone() });
            }
        }
        return Some(SimplePredicate::AlwaysTrue);
    }

    // Handle string columns
    match literal {
        ScalarValue::Utf8(Some(s)) | ScalarValue::LargeUtf8(Some(s)) => {
            Some(SimplePredicate::StringCompare {
                field: column.to_string(),
                op,
                value: s.clone(),
            })
        }
        // Handle integer types
        ScalarValue::Int8(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        ScalarValue::Int16(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        ScalarValue::Int32(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        ScalarValue::Int64(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v,
        }),
        ScalarValue::UInt8(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        ScalarValue::UInt16(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        ScalarValue::UInt32(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        ScalarValue::UInt64(Some(v)) => Some(SimplePredicate::IntCompare {
            field: column.to_string(),
            op,
            value: *v as i64,
        }),
        _ => Some(SimplePredicate::AlwaysTrue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::logical_expr::col;
    use datafusion::prelude::lit;

    fn create_tcp_parsed() -> Vec<(&'static str, ParseResult<'static>)> {
        use std::collections::HashMap;

        let mut eth_fields = HashMap::new();
        eth_fields.insert("src_mac", FieldValue::String("00:11:22:33:44:55".to_string()));
        eth_fields.insert("dst_mac", FieldValue::String("ff:ff:ff:ff:ff:ff".to_string()));
        eth_fields.insert("ethertype", FieldValue::UInt16(0x0800));

        let mut ipv4_fields = HashMap::new();
        ipv4_fields.insert("src_ip", FieldValue::String("192.168.1.1".to_string()));
        ipv4_fields.insert("dst_ip", FieldValue::String("192.168.1.2".to_string()));
        ipv4_fields.insert("ttl", FieldValue::UInt8(64));
        ipv4_fields.insert("protocol", FieldValue::UInt8(6));

        let mut tcp_fields = HashMap::new();
        tcp_fields.insert("src_port", FieldValue::UInt16(12345));
        tcp_fields.insert("dst_port", FieldValue::UInt16(80));
        tcp_fields.insert("flags", FieldValue::UInt16(0x02));

        vec![
            (
                "ethernet",
                ParseResult {
                    fields: eth_fields,
                    remaining: &[],
                    child_hints: HashMap::new(),
                    error: None,
                },
            ),
            (
                "ipv4",
                ParseResult {
                    fields: ipv4_fields,
                    remaining: &[],
                    child_hints: HashMap::new(),
                    error: None,
                },
            ),
            (
                "tcp",
                ParseResult {
                    fields: tcp_fields,
                    remaining: &[],
                    child_hints: HashMap::new(),
                    error: None,
                },
            ),
        ]
    }

    #[test]
    fn test_protocol_equals() {
        let parsed = create_tcp_parsed();

        let pred = SimplePredicate::ProtocolEquals {
            value: "TCP".to_string(),
        };
        assert!(pred.matches(&parsed));

        let pred = SimplePredicate::ProtocolEquals {
            value: "UDP".to_string(),
        };
        assert!(!pred.matches(&parsed));
    }

    #[test]
    fn test_port_compare() {
        let parsed = create_tcp_parsed();

        let pred = SimplePredicate::IntCompare {
            field: "dst_port".to_string(),
            op: CompareOp::Eq,
            value: 80,
        };
        assert!(pred.matches(&parsed));

        let pred = SimplePredicate::IntCompare {
            field: "dst_port".to_string(),
            op: CompareOp::Gt,
            value: 443,
        };
        assert!(!pred.matches(&parsed));
    }

    #[test]
    fn test_ip_compare() {
        let parsed = create_tcp_parsed();

        let pred = SimplePredicate::StringCompare {
            field: "src_ip".to_string(),
            op: CompareOp::Eq,
            value: "192.168.1.1".to_string(),
        };
        assert!(pred.matches(&parsed));

        let pred = SimplePredicate::StringCompare {
            field: "src_ip".to_string(),
            op: CompareOp::Eq,
            value: "10.0.0.1".to_string(),
        };
        assert!(!pred.matches(&parsed));
    }

    #[test]
    fn test_and_predicate() {
        let parsed = create_tcp_parsed();

        let pred = SimplePredicate::And(
            Box::new(SimplePredicate::ProtocolEquals {
                value: "TCP".to_string(),
            }),
            Box::new(SimplePredicate::IntCompare {
                field: "dst_port".to_string(),
                op: CompareOp::Eq,
                value: 80,
            }),
        );
        assert!(pred.matches(&parsed));

        let pred = SimplePredicate::And(
            Box::new(SimplePredicate::ProtocolEquals {
                value: "UDP".to_string(),
            }),
            Box::new(SimplePredicate::IntCompare {
                field: "dst_port".to_string(),
                op: CompareOp::Eq,
                value: 80,
            }),
        );
        assert!(!pred.matches(&parsed));
    }

    #[test]
    fn test_from_datafusion_expr() {
        // protocol = 'TCP'
        let expr = col("protocol").eq(lit("TCP"));
        let evaluator = FilterEvaluator::try_from_exprs(&[expr]).unwrap();
        let parsed = create_tcp_parsed();
        assert!(evaluator.matches(&parsed));

        // dst_port = 80
        let expr = col("dst_port").eq(lit(80i32));
        let evaluator = FilterEvaluator::try_from_exprs(&[expr]).unwrap();
        assert!(evaluator.matches(&parsed));

        // dst_port = 443
        let expr = col("dst_port").eq(lit(443i32));
        let evaluator = FilterEvaluator::try_from_exprs(&[expr]).unwrap();
        assert!(!evaluator.matches(&parsed));
    }

    #[test]
    fn test_empty_exprs() {
        let evaluator = FilterEvaluator::try_from_exprs(&[]);
        assert!(evaluator.is_none());
    }
}
