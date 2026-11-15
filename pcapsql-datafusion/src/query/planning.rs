//! What a statement needs from the capture, decided from its plan.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::execution::session_state::SessionState;
use datafusion::logical_expr::{DdlStatement, Expr, LogicalPlan, Statement};
use tokio::task::JoinHandle;

use super::engine::QueryOutput;
use super::{fusion, tables};
use crate::error::{Error, QueryError};
use crate::query::providers::{ParseStats, PartitionStat, QueryTables};
use crate::query::udf::CaptureTimeRange;

/// Names of the UDFs whose result depends on the capture's full time range.
const TIME_RANGE_UDFS: &[&str] = &["start_time", "end_time", "relative_time"];

/// Does any expression in the plan call a time-range UDF?
///
/// Runs on the *unoptimized* plan (see [`QueryEngine::execute`]). A user view
/// is normally already inlined there: DataFusion's `LogicalPlanBuilder::scan`
/// expands a view's plan at SQL planning, so `CREATE VIEW v AS SELECT
/// relative_time(…) …` followed by `SELECT * FROM v` is detected like a
/// direct call. A `TableScan` that still carries a view plan
/// (`TableSource::get_logical_plan`) is searched too, so the detection does
/// not depend on that planner detail.
pub(super) fn uses_time_range_udfs(plan: &LogicalPlan) -> bool {
    let mut found = false;
    let _ = plan.apply_with_subqueries(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            if let Some(view_plan) = scan.source.get_logical_plan() {
                if uses_time_range_udfs(&view_plan) {
                    found = true;
                    return Ok(TreeNodeRecursion::Stop);
                }
            }
        }
        let _ = node.apply_expressions(|expr| {
            let _ = expr.apply(|e| {
                if let Expr::ScalarFunction(f) = e {
                    if TIME_RANGE_UDFS.contains(&f.name()) {
                        found = true;
                        return Ok(TreeNodeRecursion::Stop);
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            });
            Ok(if found {
                TreeNodeRecursion::Stop
            } else {
                TreeNodeRecursion::Continue
            })
        });
        Ok(if found {
            TreeNodeRecursion::Stop
        } else {
            TreeNodeRecursion::Continue
        })
    });
    found
}

/// What one query needs from one table, harvested from its optimized plan.
#[derive(Debug, Default)]
pub(super) struct TableNeeds {
    /// Referenced columns (`None` = all, e.g. `SELECT *`).
    pub(super) columns: Option<HashSet<String>>,
    /// Filters pushed into the scan (`Inexact`; DataFusion re-checks).
    pub(super) filters: Vec<Expr>,
    /// Pushed-down LIMIT.
    pub(super) fetch: Option<usize>,
    /// Number of scans of this table in the plan (self-joins disable
    /// per-scan scoping so one materialization can serve every scan).
    pub(super) scan_count: usize,
    /// A fused join (see [`fusion`]) rather than a protocol table: the parse
    /// builds it from the spec.
    pub(super) fused: Option<Arc<fusion::FrameJoinSpec>>,
}

/// A query's prepared tables plus what is still in flight.
pub(super) struct PreparedQuery {
    /// What the query's providers serve; handed to DataFusion on the query's
    /// session state and dropped with the query.
    pub(super) tables: Arc<QueryTables>,
    /// Streaming producers to await after execution (fold stats, surface
    /// parse errors).
    pub(super) producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    /// Statistics known before execution (materialize path, cache hit, fast
    /// path); streaming folds the producers' numbers in afterwards.
    pub(super) stats: ParseStats,
}

/// Walk an optimized plan and collect per-table needs for our tables.
pub(super) fn harvest_table_needs(
    plan: &LogicalPlan,
    known_tables: &HashSet<String>,
) -> Result<HashMap<String, TableNeeds>, Error> {
    let mut needs: HashMap<String, TableNeeds> = HashMap::new();
    plan.apply_with_subqueries(|node| {
        if let Some(spec) = fusion::fused_spec_of(node) {
            // The parse builds the whole fused table (its projection is
            // applied by the scan); a LIMIT pushed into the scan caps it.
            let fetch = match node {
                LogicalPlan::TableScan(scan) => scan.fetch,
                _ => None,
            };
            let entry = needs.entry(spec.name.clone()).or_default();
            entry.scan_count += 1;
            entry.fetch = if entry.scan_count == 1 { fetch } else { None };
            entry.fused = Some(spec);
            return Ok(TreeNodeRecursion::Continue);
        }
        if let LogicalPlan::TableScan(scan) = node {
            let name = scan.table_name.table();
            if known_tables.contains(name) {
                let columns: Option<HashSet<String>> = scan.projection.as_ref().map(|indices| {
                    let schema = scan.source.schema();
                    indices
                        .iter()
                        .map(|&i| schema.field(i).name().clone())
                        .collect()
                });
                let entry = needs.entry(name.to_string()).or_default();
                entry.scan_count += 1;
                if entry.scan_count == 1 {
                    entry.columns = columns;
                    entry.filters = scan.filters.clone();
                    entry.fetch = scan.fetch;
                } else {
                    // Multiple scans of one table: one materialization must
                    // serve them all — union columns, drop predicates/caps.
                    entry.columns = match (entry.columns.take(), columns) {
                        (Some(mut a), Some(b)) => {
                            a.extend(b);
                            Some(a)
                        }
                        _ => None,
                    };
                    entry.filters.clear();
                    entry.fetch = None;
                }
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .map_err(|e| Error::Query(QueryError::Execution(e.to_string())))?;
    Ok(needs)
}

/// A statement after logical planning: finished (it parsed nothing), or a
/// query to prepare and execute.
pub(super) enum Planned {
    Done(Box<QueryOutput>),
    Query(Box<PlannedQuery>),
}

/// A query ready to prepare and execute.
pub(super) struct PlannedQuery {
    pub(super) state: SessionState,
    pub(super) optimized: LogicalPlan,
    pub(super) bootstrap: ParseStats,
}

/// Join a streaming pass's producers and fold their statistics (and any
/// parse error, which fails the query closed) into the query's.
///
/// `stats` is what was known before execution (the materialize path, a cache
/// hit, the fast path); a streaming pass replaces it with the producers'
/// numbers. `bootstrap` is a time-range bootstrap pass this query paid for.
pub(super) async fn fold_producers(
    producers: Vec<JoinHandle<Result<PartitionStat, Error>>>,
    mut stats: ParseStats,
    bootstrap: &ParseStats,
    time_range: &CaptureTimeRange,
) -> (ParseStats, Option<Error>) {
    let mut producer_error = None;
    if !producers.is_empty() {
        let outcomes = futures::future::join_all(producers).await;
        stats = ParseStats {
            parse_passes: 1,
            partitions: outcomes.len(),
            complete_scan: true,
            ..Default::default()
        };
        let mut start = i64::MAX;
        let mut end = i64::MIN;
        for outcome in outcomes {
            match outcome {
                Ok(Ok(p)) => {
                    stats.packets_scanned += p.packets;
                    stats.complete_scan &= !p.capped;
                    if p.min_us != i64::MAX {
                        start = start.min(p.min_us);
                    }
                    if p.max_us != i64::MIN {
                        end = end.max(p.max_us);
                    }
                    for output in p.outputs {
                        let table = output.table.to_string();
                        let rows = usize::try_from(output.rows).unwrap_or(usize::MAX);
                        *stats.rows_built.entry(table.clone()).or_insert(0) += rows;
                        let overflow = output.overflow;
                        if overflow.total_bytes > 0 {
                            *stats.overflowed_bytes.entry(table.clone()).or_insert(0) +=
                                overflow.total_bytes;
                            *stats.overflow_peak_bytes.entry(table).or_insert(0) +=
                                overflow.peak_bytes;
                        }
                    }
                }
                Ok(Err(e)) => producer_error = producer_error.or(Some(e)),
                Err(join_err) => {
                    producer_error = producer_error.or(Some(Error::Query(QueryError::Execution(
                        format!("parse producer panicked: {join_err}"),
                    ))))
                }
            }
        }
        if start != i64::MAX {
            stats.start_ts_us = start;
            stats.end_ts_us = end;
            time_range.record(start, end);
            if stats.complete_scan {
                time_range.mark_complete();
            }
        }
    }
    // A time-range bootstrap pass (source without a boundary index) is part
    // of what this query cost; fold it in rather than hide it.
    stats.parse_passes += bootstrap.parse_passes;
    stats.packets_scanned += bootstrap.packets_scanned;
    (stats, producer_error)
}

/// What a statement does with the capture, decided from the top node of the
/// unoptimized plan **before** anything is prepared.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum StatementKind {
    /// Reads capture tables: harvest, prepare, execute.
    Query,
    /// Builds and displays a plan but never polls a scan (`EXPLAIN`):
    /// planned without prepared tables, nothing parsed.
    PlanOnly,
    /// DDL / session statement (`CREATE VIEW`, `DESCRIBE`, `SET`, …):
    /// executed on the shared context, nothing parsed.
    Statement,
}

/// Classify a statement. `CREATE TABLE … AS SELECT` over a capture table and
/// `EXECUTE` are rejected: DataFusion runs their input on the plain session
/// state, where no table is prepared.
pub(super) fn classify_statement(
    plan: &LogicalPlan,
    known_tables: &HashSet<String>,
) -> Result<StatementKind, Error> {
    Ok(match plan {
        LogicalPlan::Explain(_) => StatementKind::PlanOnly,
        LogicalPlan::Ddl(DdlStatement::CreateMemoryTable(cmd)) => {
            if harvest_table_needs(&cmd.input, known_tables)?.is_empty() {
                StatementKind::Statement
            } else {
                return Err(Error::Query(QueryError::Execution(
                    "CREATE TABLE … AS SELECT over a capture table is not supported; \
                     CREATE VIEW over it, or run the SELECT and keep its batches"
                        .into(),
                )));
            }
        }
        LogicalPlan::Statement(Statement::Execute(_)) => {
            return Err(Error::Query(QueryError::Execution(
                "EXECUTE of a prepared statement is not supported through \
                 QueryEngine::query; run the statement's SQL directly"
                    .into(),
            )));
        }
        LogicalPlan::Ddl(_) | LogicalPlan::Statement(_) | LogicalPlan::DescribeTable(_) => {
            StatementKind::Statement
        }
        _ => StatementKind::Query,
    })
}

/// Does a cached column set cover what a query needs?
///
/// `cached` is the cached entry's column names (`None` = not cached).
/// `needed` is the query's projected columns (`None` = all columns).
pub(super) fn cache_covers(
    cached: Option<&std::collections::HashSet<String>>,
    needed: &Option<HashSet<String>>,
    table: &str,
) -> bool {
    let Some(cached) = cached else {
        return false; // not cached
    };
    match needed {
        // Needs every column: covered only if the cache is the full table.
        None => tables::get_table_schema(table)
            .map(|schema| cached.len() == schema.fields().len())
            .unwrap_or(false),
        Some(cols) => cols.iter().all(|c| cached.contains(c)),
    }
}

/// Union of a cached column set and a query's needed columns; `None`
/// (all columns) on either side widens to all.
pub(super) fn column_union(
    cached: Option<std::collections::HashSet<String>>,
    needed: &Option<HashSet<String>>,
) -> Option<HashSet<String>> {
    match (cached, needed) {
        (_, None) => None,
        (None, Some(n)) => Some(n.clone()),
        (Some(mut c), Some(n)) => {
            c.extend(n.iter().cloned());
            Some(c)
        }
    }
}
