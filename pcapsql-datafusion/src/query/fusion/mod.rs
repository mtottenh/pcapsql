//! Frame-join fusion: the parser emits a view's joined row itself.
//!
//! Every protocol table of one parse pass is produced by the same producer,
//! which has all of a frame's layers in hand at once. The `*_packets` views
//! join those tables back together on `frame_number` (and, for the layers of
//! one encapsulation level, `encap_depth`), so a query over a view spends
//! three to five joins reassembling the row the parser just took apart. On a
//! stream that is worse than slow: a join of two unbounded inputs either
//! buffers one side for ever or releases rows only when the other side
//! moves, so a continuous query could not use a view at all.
//!
//! [`FuseFrameJoins`] is a logical optimizer rule, run last, that recognizes
//! such a join tree in the optimized plan and replaces it with a scan of a
//! synthetic table (a [`FrameJoinProvider`] carrying a [`FrameJoinSpec`]).
//! The parse pass then builds that table directly
//! ([`crate::query::builders::FusedBatchBuilder`]): per packet it evaluates
//! the joins over the frame's own rows, which is exact SQL semantics (inner
//! and left joins, every match, nulls for a missing left side) over a handful
//! of rows, with no join operator left in the plan.
//!
//! # What fuses
//!
//! A tree of `INNER` / `LEFT` joins whose leaves are protocol-table scans
//! (optionally under a `SubqueryAlias`, a column-only `Projection`, or, on an
//! inner side, a `Filter`), whose `ON` clauses are exactly
//! `a.frame_number = b.frame_number`, optionally with
//! `a.encap_depth = b.encap_depth` on the same pair of members, and nothing
//! else. A `Filter` under an inner join is hoisted above the fused scan (an
//! inner join commutes with a filter on its input); one under the right side
//! of a left join does not commute, so that tree is left alone. Anything
//! else (`FULL` joins as in the `packets` view, non-equi conditions, a
//! `LIMIT` on a leaf) falls back to DataFusion's joins.
//!
//! The replacement keeps the join's output schema exactly, qualifiers
//! included: the fused scan has one column per (qualifier, name) with a
//! flattened unique name, and a projection on top re-qualifies them, so the
//! rest of the plan does not notice the change.
//!
//! # When
//!
//! Only under `RetentionPolicy::None`, which is every `--stdin`, one-shot and
//! continuous query: there the exchange hands batches to DataFusion as they
//! form and nothing is cached, so the fused table is simply one more table of
//! the pass. The `CacheOnTouch` engine (the REPL) keeps the per-table cache
//! and DataFusion's joins, which also makes it the reference the golden
//! corpus checks the fused results against.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use arrow::datatypes::{Field, Schema, SchemaRef};
use async_trait::async_trait;
use datafusion::catalog::Session;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{Column, Result, TableReference};
use datafusion::datasource::{provider_as_source, source_as_provider, TableProvider, TableType};
use datafusion::logical_expr::expr::Alias;
use datafusion::logical_expr::{
    Expr, Filter, JoinType, LogicalPlan, LogicalPlanBuilder, Projection,
    TableProviderFilterPushDown,
};
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use datafusion::physical_plan::ExecutionPlan;

use crate::query::providers::ProtocolTableProvider;
use crate::query::tables;

/// How a member joins into the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JoinKind {
    Inner,
    Left,
}

/// One table of a fused join.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Member {
    /// Protocol table (`frames`, `tcp`, …).
    pub table: String,
    /// Its qualifier in the plan (`f`, `tcp`, `ip4`).
    pub alias: String,
    /// `None` for the first member (the root of the tree); otherwise the
    /// join that brings it in.
    pub join: Option<MemberJoin>,
}

/// The join of one member onto an earlier one: equal `frame_number` (always,
/// and trivially true within one frame) and, when `depth` is set, equal
/// `encap_depth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemberJoin {
    pub kind: JoinKind,
    /// Index of the member whose keys this one is compared with.
    pub with: usize,
    pub depth: bool,
}

/// One output column of the fused table.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FusedColumn {
    /// Member the value comes from.
    pub member: usize,
    /// Column of that member's table.
    pub column: String,
}

/// A fused join: what the parser builds in place of the join tree.
#[derive(Clone, Debug)]
pub struct FrameJoinSpec {
    /// Synthetic table name, unique per spec.
    pub name: String,
    /// In join order; `members[0]` is the root.
    pub members: Vec<Member>,
    /// Schema of the fused table (flattened unique column names).
    pub schema: SchemaRef,
    /// Source of each schema field.
    pub columns: Vec<FusedColumn>,
}

impl FrameJoinSpec {
    /// Protocol tables the parse must produce for this spec, with the
    /// columns each needs (`frame_number` and the encapsulation
    /// pseudo-columns included; the subscription's scope drops them, as for
    /// a plain table).
    pub fn member_fields(&self) -> HashMap<String, std::collections::HashSet<String>> {
        let mut out: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        for (i, member) in self.members.iter().enumerate() {
            let entry = out.entry(member.table.clone()).or_default();
            for col in self.columns.iter().filter(|c| c.member == i) {
                entry.insert(col.column.clone());
            }
        }
        out
    }

    /// `table (alias) kind table (alias) …` for plan display and errors.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        for m in &self.members {
            if let Some(join) = &m.join {
                s.push_str(match join.kind {
                    JoinKind::Inner => " JOIN ",
                    JoinKind::Left => " LEFT JOIN ",
                });
            }
            s.push_str(&m.table);
            if m.alias != m.table {
                s.push(' ');
                s.push_str(&m.alias);
            }
        }
        s
    }
}

impl fmt::Display for FrameJoinSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.describe())
    }
}

/// The table provider of a fused join: a protocol-table provider under the
/// spec's synthetic name (the parse pass serves it like any other table),
/// plus the spec itself for the engine's harvest.
pub struct FrameJoinProvider {
    spec: Arc<FrameJoinSpec>,
    inner: ProtocolTableProvider,
}

impl FrameJoinProvider {
    pub fn new(spec: Arc<FrameJoinSpec>, default_partitions: usize, unbounded: bool) -> Self {
        // The rows come out in the root member's order: its frame_number
        // and, for a protocol table, its encap_depth, never null because the
        // root is always present. Declaring that keeps capture order across
        // partitions without a sort, as for a protocol table.
        let ordering: Vec<String> = ["frame_number", "encap_depth"]
            .iter()
            .map_while(|name| {
                spec.columns
                    .iter()
                    .position(|c| c.member == 0 && c.column == *name)
                    .map(|i| spec.schema.field(i).name().clone())
            })
            .collect();
        let inner = ProtocolTableProvider::new(
            spec.name.clone(),
            Arc::clone(&spec.schema),
            default_partitions,
        )
        .with_unbounded(unbounded)
        .with_ordering(ordering);
        Self { spec, inner }
    }

    pub fn spec(&self) -> &Arc<FrameJoinSpec> {
        &self.spec
    }
}

impl fmt::Debug for FrameJoinProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameJoinProvider")
            .field("spec", &self.spec.describe())
            .finish()
    }
}

#[async_trait]
impl TableProvider for FrameJoinProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.spec.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> Result<Vec<TableProviderFilterPushDown>> {
        Ok(vec![
            TableProviderFilterPushDown::Unsupported;
            filters.len()
        ])
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        self.inner.scan(state, projection, filters, limit).await
    }
}

/// The fused-join spec behind a `TableScan`, if it scans one.
pub fn fused_spec_of(plan: &LogicalPlan) -> Option<Arc<FrameJoinSpec>> {
    let LogicalPlan::TableScan(scan) = plan else {
        return None;
    };
    let provider = source_as_provider(&scan.source).ok()?;
    provider
        .as_any()
        .downcast_ref::<FrameJoinProvider>()
        .map(|p| Arc::clone(p.spec()))
}

/// Logical optimizer rule replacing frame-join trees with fused scans (see
/// the module documentation).
#[derive(Debug)]
pub struct FuseFrameJoins {
    /// Nominal partition count of the engine's parse (what a plan-only scan
    /// displays).
    partitions: usize,
    /// Continuous engine: the fused scan is unbounded like every other.
    unbounded: bool,
}

impl FuseFrameJoins {
    pub fn new(partitions: usize, unbounded: bool) -> Self {
        Self {
            partitions,
            unbounded,
        }
    }
}

impl OptimizerRule for FuseFrameJoins {
    fn name(&self) -> &str {
        "fuse_frame_joins"
    }

    fn apply_order(&self) -> Option<datafusion::optimizer::ApplyOrder> {
        // Top down by hand: a match is replaced whole and not descended into,
        // so the largest tree wins.
        None
    }

    fn supports_rewrite(&self) -> bool {
        true
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> Result<Transformed<LogicalPlan>> {
        plan.transform_down_with_subqueries(|node| {
            if !matches!(
                node,
                LogicalPlan::Join(_) | LogicalPlan::Projection(_) | LogicalPlan::Limit(_)
            ) {
                // A Filter at the top of a tree stays where it is; the tree
                // below it is matched on the way down.
                return Ok(Transformed::no(node));
            }
            match match_tree(&node, Ctx::root()) {
                Some(tree) if tree.members.len() > 1 => {
                    let fused = replace(&node, tree, self.partitions, self.unbounded)?;
                    Ok(Transformed::new(fused, true, TreeNodeRecursion::Jump))
                }
                _ => Ok(Transformed::no(node)),
            }
        })
    }
}

/// A member's columns the tree knows: `(qualifier, name)` as the plan spells
/// them. A leaf's columns are spelled with its table name (the spelling a
/// filter pushed under a `SubqueryAlias` keeps) and, above the alias, with
/// the alias. Every spelling is qualified: the unqualified `frame_number`
/// would be ambiguous by construction.
type ColumnMap = HashMap<(Option<TableReference>, String), FusedColumn>;

/// The join tree under a node, as far as it fuses.
struct Tree {
    members: Vec<Member>,
    columns: ColumnMap,
    /// Filters found under inner sides, to re-apply above the fused scan.
    filters: Vec<Expr>,
    /// The query's LIMIT when it sits inside the tree (`skip`, `fetch`), to
    /// re-apply above the fused scan; see the `Limit` arm of [`match_tree`].
    limit: Option<(usize, Option<usize>)>,
}

/// Where in the tree the matcher is.
#[derive(Clone, Copy)]
struct Ctx {
    /// Below a join: a `Limit` here can only be a pushdown copy.
    under_join: bool,
    /// The LIMIT above (`skip`, `fetch`), when known: the one copies must
    /// agree with.
    outer_limit: Option<(usize, Option<usize>)>,
}

impl Ctx {
    fn root() -> Self {
        Self {
            under_join: false,
            outer_limit: None,
        }
    }

    fn under_join(self) -> Self {
        Self {
            under_join: true,
            ..self
        }
    }
}

/// Match the join tree rooted at `plan`, or `None` if any part of it is not
/// a fusible frame join.
fn match_tree(plan: &LogicalPlan, ctx: Ctx) -> Option<Tree> {
    match plan {
        LogicalPlan::TableScan(scan) => {
            // A `fetch` on a leaf comes with a `Limit` above it, which the
            // `Limit` arm judges; `scan.filters` are inexact copies of
            // `Filter` nodes that stay in the plan (the provider never
            // accepts a filter as exact).
            if fused_spec_of(plan).is_some() {
                return None;
            }
            let provider = source_as_provider(&scan.source).ok()?;
            let table = provider
                .as_any()
                .downcast_ref::<ProtocolTableProvider>()?
                .table_name()
                .to_string();
            if tables::is_stream_table(&table) || tables::get_table_schema(&table).is_none() {
                return None;
            }
            let alias = scan.table_name.table().to_string();
            let mut columns = ColumnMap::new();
            for (qualifier, field) in scan.projected_schema.iter() {
                columns.insert(
                    (qualifier.cloned(), field.name().clone()),
                    FusedColumn {
                        member: 0,
                        column: field.name().clone(),
                    },
                );
            }
            Some(Tree {
                members: vec![Member {
                    table,
                    alias,
                    join: None,
                }],
                columns,
                filters: Vec::new(),
                limit: None,
            })
        }
        LogicalPlan::SubqueryAlias(alias) => {
            let mut tree = match_tree(&alias.input, ctx)?;
            let qualifier = alias.alias.clone();
            if tree.members.len() == 1 {
                // A leaf: its columns are also spelled with the alias now.
                tree.members[0].alias = qualifier.table().to_string();
                let aliased: Vec<_> = tree
                    .columns
                    .iter()
                    .map(|((_, name), column)| {
                        ((Some(qualifier.clone()), name.clone()), column.clone())
                    })
                    .collect();
                tree.columns.extend(aliased);
            } else {
                // A view (or derived table) over a tree: its output fields
                // are the input's, positionally, under the alias.
                let input_schema = alias.input.schema();
                for (i, (q, field)) in input_schema.iter().enumerate() {
                    let column = tree
                        .columns
                        .get(&(q.cloned(), field.name().clone()))?
                        .clone();
                    let out = alias.schema.field(i).name().clone();
                    tree.columns.insert((Some(qualifier.clone()), out), column);
                }
            }
            Some(tree)
        }
        LogicalPlan::Projection(proj) => {
            if !proj.expr.iter().all(|e| matches!(e, Expr::Column(_))) {
                return None;
            }
            // Column-only projections only narrow what flows up; the fused
            // scan carries exactly what the root schema asks for.
            match_tree(&proj.input, ctx)
        }
        LogicalPlan::Filter(filter) => {
            let mut tree = match_tree(&filter.input, ctx)?;
            if tree.members.len() != 1 {
                return None;
            }
            tree.filters.push(filter.predicate.clone());
            Some(tree)
        }
        // The query's LIMIT may sit inside the tree, under the final
        // projection; it is re-applied above the fused scan. The limit
        // pushdown also copies it (as `LIMIT skip + fetch`) onto the
        // preserved side of every left join below it, down to the leaves;
        // those copies, which the query's LIMIT implies, go. A LIMIT under a
        // join that is not such a copy (a derived table's own) cannot be
        // moved, so its tree is left to DataFusion.
        LogicalPlan::Limit(limit) => {
            use datafusion::logical_expr::{FetchType, SkipType};
            let skip = match limit.get_skip_type().ok()? {
                SkipType::Literal(n) => n,
                SkipType::UnsupportedExpr => return None,
            };
            let fetch = match limit.get_fetch_type().ok()? {
                FetchType::Literal(f) => f,
                FetchType::UnsupportedExpr => return None,
            };
            if ctx.under_join {
                let (outer_skip, outer_fetch) = ctx.outer_limit?;
                let needed = outer_fetch.map(|f| f + outer_skip);
                let copy = skip == 0
                    && match (fetch, needed) {
                        (None, _) => true,
                        (Some(f), Some(n)) => f >= n,
                        (Some(_), None) => false,
                    };
                if !copy {
                    return None;
                }
                return match_tree(&limit.input, ctx);
            }
            if ctx.outer_limit.is_some() {
                // Two stacked limits above the joins: not a shape the
                // optimizer produces; leave it alone.
                return None;
            }
            let inner = Ctx {
                under_join: false,
                outer_limit: Some((skip, fetch)),
            };
            let mut tree = match_tree(&limit.input, inner)?;
            if tree.members.len() < 2 {
                return None;
            }
            tree.limit = Some((skip, fetch));
            Some(tree)
        }
        LogicalPlan::Join(join) => {
            let kind = match join.join_type {
                JoinType::Inner => JoinKind::Inner,
                JoinType::Left => JoinKind::Left,
                _ => return None,
            };
            if join.filter.is_some() || join.on.is_empty() {
                return None;
            }
            let mut left = match_tree(&join.left, ctx.under_join())?;
            let right = match_tree(&join.right, ctx.under_join())?;
            if right.members.len() != 1 {
                return None;
            }
            // The right leaf's spellings must be new to the tree: the same
            // table under two aliases shares its table-name spelling, and
            // then a filter pushed under either alias would be ambiguous.
            if right.columns.keys().any(|k| left.columns.contains_key(k)) {
                return None;
            }
            if kind == JoinKind::Left && !right.filters.is_empty() {
                // A filter under the preserved-null side does not commute
                // with the join.
                return None;
            }
            // The keys: frame_number = frame_number, and optionally
            // encap_depth = encap_depth, between one left member and the
            // right leaf.
            let mut with: Option<usize> = None;
            let mut depth = false;
            for (l, r) in &join.on {
                let (Expr::Column(l), Expr::Column(r)) = (l, r) else {
                    return None;
                };
                let (lc, rc) = match (left.columns.get(&key(l)), right.columns.get(&key(r))) {
                    (Some(lc), Some(rc)) => (lc.clone(), rc.clone()),
                    _ => match (right.columns.get(&key(l)), left.columns.get(&key(r))) {
                        // The same pair written the other way round.
                        (Some(rc), Some(lc)) => (lc.clone(), rc.clone()),
                        _ => return None,
                    },
                };
                if lc.column != rc.column {
                    return None;
                }
                match with {
                    None => with = Some(lc.member),
                    Some(w) if w == lc.member => {}
                    Some(_) => return None,
                }
                match lc.column.as_str() {
                    "frame_number" => {}
                    "encap_depth" => depth = true,
                    _ => return None,
                }
            }
            let with = with?;
            if !join
                .on
                .iter()
                .any(|(l, _)| matches!(l, Expr::Column(c) if c.name == "frame_number"))
            {
                return None;
            }
            let index = left.members.len();
            let mut member = right.members.into_iter().next()?;
            member.join = Some(MemberJoin { kind, with, depth });
            left.members.push(member);
            for ((q, name), column) in right.columns {
                left.columns.insert(
                    (q, name),
                    FusedColumn {
                        member: index,
                        column: column.column,
                    },
                );
            }
            left.filters.extend(right.filters);
            Some(left)
        }
        _ => None,
    }
}

fn key(column: &Column) -> (Option<TableReference>, String) {
    (column.relation.clone(), column.name.clone())
}

/// Build the fused scan for `tree` and the projection that gives it the
/// root's schema back.
fn replace(
    root: &LogicalPlan,
    tree: Tree,
    partitions: usize,
    unbounded: bool,
) -> Result<LogicalPlan> {
    let root_schema = root.schema();
    let mut fields: Vec<Field> = Vec::new();
    let mut columns: Vec<FusedColumn> = Vec::new();
    // One fused column per (member, column), however many spellings the
    // plan has for it (`f.frame_number` above the alias, `frames.frame_number`
    // in a filter pushed under it).
    let mut positions: HashMap<FusedColumn, usize> = HashMap::new();
    let mut add = |field: &Field,
                   column: &FusedColumn,
                   fields: &mut Vec<Field>,
                   columns: &mut Vec<FusedColumn>|
     -> usize {
        if let Some(&i) = positions.get(column) {
            return i;
        }
        let member = &tree.members[column.member];
        let name = format!("{}__{}", member.alias, field.name());
        fields.push(Field::new(
            name,
            field.data_type().clone(),
            field.is_nullable(),
        ));
        columns.push(column.clone());
        positions.insert(column.clone(), fields.len() - 1);
        fields.len() - 1
    };
    // The root's own output first, in order.
    let mut output: Vec<(Option<TableReference>, String, usize)> = Vec::new();
    for (qualifier, field) in root_schema.iter() {
        let column = tree
            .columns
            .get(&(qualifier.cloned(), field.name().clone()))
            .ok_or_else(|| {
                datafusion::common::DataFusionError::Internal(format!(
                    "fuse_frame_joins: output column {}.{} has no member",
                    qualifier.map(|q| q.to_string()).unwrap_or_default(),
                    field.name()
                ))
            })?;
        let i = add(field, column, &mut fields, &mut columns);
        output.push((qualifier.cloned(), field.name().clone(), i));
    }
    // Then whatever the hoisted filters need beyond that.
    let mut filters = Vec::with_capacity(tree.filters.len());
    for predicate in &tree.filters {
        let rewritten = predicate
            .clone()
            .transform_up(|e| {
                let Expr::Column(c) = &e else {
                    return Ok(Transformed::no(e));
                };
                let Some(column) = tree.columns.get(&key(c)) else {
                    return Err(datafusion::common::DataFusionError::Internal(format!(
                        "fuse_frame_joins: filter column {c} has no member"
                    )));
                };
                let member = &tree.members[column.member];
                let schema = tables::get_table_schema(&member.table).expect("member table");
                let field = schema
                    .field_with_name(&column.column)
                    .map_err(|e| datafusion::common::DataFusionError::Internal(e.to_string()))?;
                let i = add(field, column, &mut fields, &mut columns);
                Ok(Transformed::yes(Expr::Column(Column::new_unqualified(
                    fields[i].name().clone(),
                ))))
            })?
            .data;
        filters.push(rewritten);
    }

    let limit = tree.limit;
    let members = tree.members;
    let name = spec_name(&members, &columns);
    let spec = Arc::new(FrameJoinSpec {
        name: name.clone(),
        members,
        schema: Arc::new(Schema::new(fields)),
        columns,
    });
    let provider = Arc::new(FrameJoinProvider::new(spec, partitions, unbounded));
    let mut plan = LogicalPlanBuilder::scan(
        TableReference::bare(name),
        provider_as_source(provider),
        None,
    )?
    .build()?;
    for predicate in filters {
        plan = LogicalPlan::Filter(Filter::try_new(predicate, Arc::new(plan))?);
    }
    let scan_schema = plan.schema().clone();
    let exprs: Vec<Expr> = output
        .into_iter()
        .map(|(qualifier, name, i)| {
            let field = scan_schema.field(i).name().clone();
            Expr::Alias(Alias::new(
                Expr::Column(Column::new_unqualified(field)),
                qualifier,
                name,
            ))
        })
        .collect();
    let plan = LogicalPlan::Projection(Projection::try_new(exprs, Arc::new(plan))?);
    match limit {
        Some((skip, fetch)) => LogicalPlanBuilder::from(plan).limit(skip, fetch)?.build(),
        None => Ok(plan),
    }
}

/// `fused_<tables>_<hash>`: readable in a plan, and distinct for two fused
/// scans that differ in members or columns.
fn spec_name(members: &[Member], columns: &[FusedColumn]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    members.hash(&mut hasher);
    columns.hash(&mut hasher);
    let tables: Vec<&str> = members.iter().map(|m| m.table.as_str()).collect();
    format!("fused_{}_{:016x}", tables.join("_"), hasher.finish())
}
