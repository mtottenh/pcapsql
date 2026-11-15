//! Applying a translated BPF filter to a SQL query.

use super::SqlFilter;

/// Apply BPF filter to a SQL query.
///
/// Injects the filter into the WHERE clause of the query.
/// If the query already has a WHERE, adds an AND clause.
///
/// The keywords are found in an ASCII-upper-cased copy of the query, which has
/// the query's own byte offsets: `str::to_uppercase` can change the length of
/// non-ASCII text, and an offset found in its output is not one in the query.
pub fn apply_bpf_filter(query: &str, filter: &Option<SqlFilter>) -> String {
    let filter = match filter {
        Some(f) => f,
        None => return query.to_string(),
    };

    let query_upper = query.to_ascii_uppercase();
    let where_clause = &filter.where_clause;

    // Simple heuristic: find WHERE clause position
    // This handles basic cases; complex queries with subqueries may need more work
    if let Some(where_pos) = find_where_position(&query_upper) {
        // Query has a WHERE clause - add AND before the next clause (ORDER BY, GROUP BY, LIMIT, etc.)
        let after_where = &query[where_pos + 5..];

        // Find the end of the existing WHERE clause
        if let Some(end_pos) = find_where_end(&after_where.to_ascii_uppercase()) {
            let where_content = &after_where[..end_pos];
            let rest = &after_where[end_pos..];
            format!(
                "{}WHERE ({}) AND ({}){}",
                &query[..where_pos],
                where_content.trim(),
                where_clause,
                rest
            )
        } else {
            // WHERE clause extends to end of query
            format!("{query} AND ({where_clause})")
        }
    } else {
        // No WHERE clause - find appropriate insertion point
        if let Some(pos) = find_clause_position(&query_upper) {
            // Insert before ORDER BY, GROUP BY, LIMIT, etc.
            format!(
                "{} WHERE ({}) {}",
                query[..pos].trim(),
                where_clause,
                &query[pos..]
            )
        } else {
            // Append to end
            format!(
                "{} WHERE ({})",
                query.trim_end_matches(';').trim(),
                where_clause
            )
        }
    }
}

/// Find position of WHERE keyword in query (not in subquery).
fn find_where_position(query_upper: &str) -> Option<usize> {
    // Simple approach: find last WHERE that's not preceded by SELECT (in subquery)
    let mut depth: i32 = 0;
    let bytes = query_upper.as_bytes();

    for i in 0..bytes.len() {
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && bytes[i..].starts_with(b"WHERE") {
            // Make sure it's a complete keyword (not part of "NOWHERE" etc.)
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let after_ok = i + 5 >= bytes.len() || !bytes[i + 5].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return Some(i);
            }
        }
    }
    None
}

/// Find position of ORDER BY, GROUP BY, HAVING, LIMIT at top level.
fn find_clause_position(query_upper: &str) -> Option<usize> {
    let clauses = ["ORDER BY", "GROUP BY", "HAVING", "LIMIT"];
    let mut depth: i32 = 0;
    let bytes = query_upper.as_bytes();

    for i in 0..bytes.len() {
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            for clause in &clauses {
                if bytes[i..].starts_with(clause.as_bytes()) {
                    let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                    let end = i + clause.len();
                    let after_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        return Some(i);
                    }
                }
            }
        }
    }
    None
}

/// Find end of WHERE clause (before ORDER BY, GROUP BY, HAVING, LIMIT).
fn find_where_end(after_where_upper: &str) -> Option<usize> {
    find_clause_position(after_where_upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> Option<SqlFilter> {
        Some(SqlFilter {
            where_clause: "tcp.frame_number IS NOT NULL".to_string(),
        })
    }

    #[test]
    fn no_filter_leaves_the_query_alone() {
        let query = "SELECT 'ﬁ' FROM tcp WHERE dst_port = 80";
        assert_eq!(apply_bpf_filter(query, &None), query);
    }

    #[test]
    fn ascii_queries() {
        assert_eq!(
            apply_bpf_filter("select * from tcp where dst_port = 80", &filter()),
            "select * from tcp where dst_port = 80 AND (tcp.frame_number IS NOT NULL)"
        );
        assert_eq!(
            apply_bpf_filter(
                "SELECT * FROM tcp WHERE dst_port = 80 ORDER BY frame_number",
                &filter()
            ),
            "SELECT * FROM tcp WHERE (dst_port = 80) AND (tcp.frame_number IS NOT NULL)\
             ORDER BY frame_number"
        );
        assert_eq!(
            apply_bpf_filter("SELECT * FROM tcp order by frame_number", &filter()),
            "SELECT * FROM tcp WHERE (tcp.frame_number IS NOT NULL) order by frame_number"
        );
        assert_eq!(
            apply_bpf_filter("SELECT * FROM tcp;", &filter()),
            "SELECT * FROM tcp WHERE (tcp.frame_number IS NOT NULL)"
        );
    }

    /// `ﬁ` (3 bytes) upper-cases to `FI` (2 bytes) and `ı` (2 bytes) to `I` (1 byte), so an
    /// offset found in `to_uppercase()` output is 2 bytes short in the query itself. Inside
    /// parentheses the keyword search never looked at them, and the splice landed in `tcp`.
    #[test]
    fn text_before_where_that_shrinks_when_upper_cased() {
        assert_eq!(
            apply_bpf_filter(
                "SELECT upper('ﬁı') AS u FROM tcp WHERE dst_port = 80 ORDER BY 1",
                &filter()
            ),
            "SELECT upper('ﬁı') AS u FROM tcp WHERE (dst_port = 80) AND \
             (tcp.frame_number IS NOT NULL)ORDER BY 1"
        );
    }

    /// `ΐ` (2 bytes) upper-cases to three characters (6 bytes): the offset is 4 bytes long.
    #[test]
    fn text_before_where_that_grows_when_upper_cased() {
        assert_eq!(
            apply_bpf_filter(
                "SELECT upper('ΐ') AS u FROM tcp WHERE dst_port = 80 LIMIT 5",
                &filter()
            ),
            "SELECT upper('ΐ') AS u FROM tcp WHERE (dst_port = 80) AND \
             (tcp.frame_number IS NOT NULL)LIMIT 5"
        );
    }

    /// Outside parentheses the keyword search sliced the text at every byte, and a byte inside
    /// a character is not a place a `str` can be sliced: it panicked.
    #[test]
    fn non_ascii_text_outside_parentheses() {
        assert_eq!(
            apply_bpf_filter(
                "SELECT 'é' AS label, src_port FROM tcp WHERE dst_port = 80",
                &filter()
            ),
            "SELECT 'é' AS label, src_port FROM tcp WHERE dst_port = 80 AND \
             (tcp.frame_number IS NOT NULL)"
        );
        assert_eq!(
            apply_bpf_filter("SELECT 'ß→ﬁ' AS label FROM tcp", &filter()),
            "SELECT 'ß→ﬁ' AS label FROM tcp WHERE (tcp.frame_number IS NOT NULL)"
        );
    }

    #[test]
    fn non_ascii_text_between_where_and_the_next_clause() {
        assert_eq!(
            apply_bpf_filter(
                "SELECT * FROM dns WHERE lower(query_name) = lower('ﬁıΐ.example') GROUP BY 1",
                &filter()
            ),
            "SELECT * FROM dns WHERE (lower(query_name) = lower('ﬁıΐ.example')) AND \
             (tcp.frame_number IS NOT NULL)GROUP BY 1"
        );
    }

    #[test]
    fn non_ascii_text_before_the_clause_a_where_goes_in_front_of() {
        assert_eq!(
            apply_bpf_filter("SELECT upper('ﬁ') AS u FROM tcp ORDER BY 1", &filter()),
            "SELECT upper('ﬁ') AS u FROM tcp WHERE (tcp.frame_number IS NOT NULL) ORDER BY 1"
        );
    }
}
