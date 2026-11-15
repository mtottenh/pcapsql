//! Applying a translated BPF filter to a SQL query.

use super::SqlFilter;

/// Apply BPF filter to a SQL query.
///
/// Injects the filter into the WHERE clause of the query.
/// If the query already has a WHERE, adds an AND clause.
pub fn apply_bpf_filter(query: &str, filter: &Option<SqlFilter>) -> String {
    let filter = match filter {
        Some(f) => f,
        None => return query.to_string(),
    };

    let query_upper = query.to_uppercase();
    let where_clause = &filter.where_clause;

    // Simple heuristic: find WHERE clause position
    // This handles basic cases; complex queries with subqueries may need more work
    if let Some(where_pos) = find_where_position(&query_upper) {
        // Query has a WHERE clause - add AND before the next clause (ORDER BY, GROUP BY, LIMIT, etc.)
        let after_where = &query[where_pos + 5..];

        // Find the end of the existing WHERE clause
        if let Some(end_pos) = find_where_end(&after_where.to_uppercase()) {
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
        } else if depth == 0 && query_upper[i..].starts_with("WHERE") {
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
                if query_upper[i..].starts_with(clause) {
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
