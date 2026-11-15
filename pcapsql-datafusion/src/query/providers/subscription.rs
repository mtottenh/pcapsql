//! What a parse pass must produce, in DataFusion's terms.
//!
//! The engine harvests each query's optimized plan into a
//! [`ParseSubscription`] (which tables, which columns, parse-time
//! predicates, row caps). A subscription is the scan layer's [`ScanPlan`]
//! plus what only this frontend has: the fused joins' specs (their Arrow
//! schemas and synthetic table names). A pass compiles it once
//! ([`CompiledSubscription`]): the plan's [`CompiledScan`] gives the parse
//! scope and each output's columns, predicate and row cap, and the Arrow
//! schemas are derived from those columns.
//!
//! The outputs of a compiled subscription are the scan's, in its order (the
//! protocol tables, the fused joins, the stream tables), and everything a
//! pass keeps per output is indexed by the scan's
//! [`OutputId`](pcapsql_core::scan::OutputId). Table names appear where the
//! engine asks for a table and where statistics are reported.

use std::collections::HashSet;
use std::sync::Arc;

use arrow::datatypes::SchemaRef;

use pcapsql_core::scan::{
    Catalog, CompiledScan, OutputPlan, PlanError, RowPredicate, ScanPlan, TableScan,
};
use pcapsql_core::ProtocolRegistry;

use crate::error::{Error, QueryError};
use crate::query::arrow_schema::out_columns_to_arrow_schema;
use crate::query::fusion::FrameJoinSpec;

/// One table's subscription within a parse pass, in DataFusion's terms.
#[derive(Clone, Debug, Default)]
pub struct TableSubscription {
    /// Columns to materialize (schema order is preserved); `None` = all.
    pub columns: Option<HashSet<String>>,
    /// Parse-time predicate (conservative; DataFusion re-checks). Built by
    /// [`row_predicate`](crate::query::row_predicate) for the same table.
    pub predicate: Option<RowPredicate>,
    /// Per-partition row cap from a pushed-down `LIMIT`.
    pub fetch: Option<usize>,
}

/// One fused join's subscription within a parse pass.
#[derive(Clone, Debug)]
pub struct FusedSubscription {
    pub spec: Arc<FrameJoinSpec>,
    /// Per-partition row cap from a pushed-down `LIMIT`.
    pub fetch: Option<usize>,
}

/// What one parse pass materializes: the tables a query references, each
/// with optional column scoping, predicates and row caps.
///
/// It wraps the scan layer's [`ScanPlan`], which holds all of that with
/// tables and columns resolved against the table catalogue, and adds the
/// fused joins' [`FrameJoinSpec`]s, which carry the Arrow schema and the
/// synthetic table name a fused join is served under.
#[derive(Clone, Debug, Default)]
pub struct ParseSubscription {
    /// Per-packet protocol tables (`tables`), fused joins (`fused`, in name
    /// order) and stream-analysis tables (`streams`); timestamps in
    /// microseconds, every frame.
    plan: ScanPlan,
    /// The spec of each of `plan.fused`, in the same order.
    fused: Vec<Arc<FrameJoinSpec>>,
}

fn execution_error(message: impl Into<String>) -> Error {
    Error::Query(QueryError::Execution(message.into()))
}

fn plan_error(error: PlanError) -> Error {
    Error::Query(error.into())
}

impl ParseSubscription {
    /// Subscribe to the given tables with full columns, no predicates, no
    /// caps (the cache-fill shape). Fails on a name that is not a per-packet
    /// table, or that is given twice.
    pub fn tables_full<I, S>(names: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut subscription = Self::default();
        for name in names {
            subscription.subscribe_table(name.as_ref(), TableSubscription::default())?;
        }
        Ok(subscription)
    }

    /// Subscribe to a per-packet table (`frames` or a protocol table): the
    /// columns DataFusion sees of it, in schema order, restricted to
    /// `sub.columns`. Fails on an unknown table or column, a stream table
    /// (see [`Self::subscribe_stream_table`]) and a table already
    /// subscribed.
    pub fn subscribe_table(&mut self, name: &str, sub: TableSubscription) -> Result<(), Error> {
        let (id, table) = Catalog::builtin()
            .table(name)
            .ok_or_else(|| execution_error(format!("Unknown table: {name}")))?;
        if table.is_stream() {
            return Err(plan_error(PlanError::NotAPacketTable(table.name)));
        }
        if self.plan.tables.iter().any(|scan| scan.table == id) {
            return Err(plan_error(PlanError::DuplicateTable(table.name)));
        }
        if let Some(wanted) = &sub.columns {
            let unknown = wanted
                .iter()
                .find(|column| !table.default_columns().any(|(_, c)| c.name == *column));
            if let Some(column) = unknown {
                return Err(Error::Query(QueryError::UnknownColumn {
                    table: name.to_string(),
                    column: column.clone(),
                }));
            }
        }
        let columns = table
            .default_columns()
            .filter(|(_, c)| sub.columns.as_ref().is_none_or(|set| set.contains(c.name)))
            .map(|(id, _)| id)
            .collect();
        self.plan.tables.push(TableScan {
            table: id,
            columns,
            predicate: sub.predicate,
            fetch: sub.fetch.map(|rows| rows as u64),
        });
        Ok(())
    }

    /// Subscribe to a fused join (see [`crate::query::fusion`]): built per
    /// packet from the frame's layers and served like a table, under the
    /// spec's synthetic name.
    pub fn subscribe_fused(&mut self, sub: FusedSubscription) -> Result<(), Error> {
        if self.fused.iter().any(|spec| spec.name == sub.spec.name) {
            return Err(execution_error(format!(
                "fused join {} is subscribed twice",
                sub.spec.name
            )));
        }
        let scan = sub.spec.to_fused_scan(sub.fetch)?;
        // Kept in name order, so that the order the joins are fed in does
        // not depend on the order they were subscribed in.
        let at = self.fused.partition_point(|spec| spec.name < sub.spec.name);
        self.plan.fused.insert(at, scan);
        self.fused.insert(at, sub.spec);
        Ok(())
    }

    /// Subscribe to a stream-analysis table (`tables::stream_table_names`),
    /// built in full by the scan of the same pass when the capture ends. Any
    /// such table pins the pass to one partition. Subscribing one twice is
    /// a no-op.
    pub fn subscribe_stream_table(&mut self, name: &str) -> Result<(), Error> {
        let (id, table) = Catalog::builtin()
            .table(name)
            .ok_or_else(|| execution_error(format!("Unknown table: {name}")))?;
        if !table.is_stream() {
            return Err(plan_error(PlanError::NotAStreamTable(table.name)));
        }
        if !self.plan.streams.iter().any(|scan| scan.table == id) {
            let columns = table.default_columns().map(|(id, _)| id).collect();
            self.plan.streams.push(TableScan::new(id, columns));
        }
        Ok(())
    }

    /// The subscription as the scan layer's plan.
    pub fn plan(&self) -> &ScanPlan {
        &self.plan
    }

    /// Nothing to parse: no packet table, no fused join and no stream table.
    pub fn is_empty(&self) -> bool {
        !self.has_packet_tables() && !self.has_stream_tables()
    }

    /// Whether the pass builds anything per packet: a protocol table or a
    /// fused join.
    pub fn has_packet_tables(&self) -> bool {
        !self.plan.tables.is_empty() || !self.plan.fused.is_empty()
    }

    /// Whether the pass builds a stream-analysis table (and therefore runs
    /// as one partition).
    pub fn has_stream_tables(&self) -> bool {
        !self.plan.streams.is_empty()
    }

    /// Resolve the subscription for one pass against `registry`: the parse
    /// scope (the subscribed tables' protocols, the fused joins' members
    /// included, plus dependency closure, with per-protocol field
    /// projections where columns are scoped), and per delivered table its
    /// Arrow schema, predicate and row cap.
    pub fn compile(&self, registry: &ProtocolRegistry) -> Result<CompiledSubscription, Error> {
        let catalog = Catalog::builtin();
        let scan = Arc::new(self.plan.compile(catalog, registry).map_err(plan_error)?);
        // `scan.outputs()` is the plan's tables, its fused joins, then its
        // stream tables.
        let table = |scan: &TableScan, out: &OutputPlan| SubscribedOutput {
            name: Arc::from(catalog.get(scan.table).name),
            schema: Arc::new(out_columns_to_arrow_schema(&out.columns)),
            spec: None,
        };
        let (packet_outputs, stream_outputs) = scan
            .outputs()
            .split_at(self.plan.tables.len() + self.plan.fused.len());
        let tables = self
            .plan
            .tables
            .iter()
            .zip(packet_outputs)
            .map(|(scan, out)| table(scan, out));
        let fused = self.fused.iter().map(|spec| SubscribedOutput {
            name: Arc::from(spec.name.as_str()),
            schema: Arc::clone(&spec.schema),
            spec: Some(Arc::clone(spec)),
        });
        let streams = self
            .plan
            .streams
            .iter()
            .zip(stream_outputs)
            .map(|(scan, out)| table(scan, out));
        let outputs: Vec<SubscribedOutput> = tables.chain(fused).chain(streams).collect();
        debug_assert_eq!(outputs.len(), scan.outputs().len());
        Ok(CompiledSubscription {
            first_stream: packet_outputs.len(),
            scan,
            outputs,
        })
    }
}

/// One table a pass delivers, as DataFusion sees it.
#[derive(Clone, Debug)]
pub struct SubscribedOutput {
    /// The table's name: a protocol or stream table's, or a fused join's
    /// synthetic one.
    pub name: Arc<str>,
    /// The Arrow schema it materializes: the subscribed columns of a table
    /// (derived from the compiled plan's columns), the spec's schema for a
    /// fused join.
    pub schema: SchemaRef,
    /// The spec, for a fused join.
    pub spec: Option<Arc<FrameJoinSpec>>,
}

/// A [`ParseSubscription`] resolved for one pass (see
/// [`ParseSubscription::compile`]).
#[derive(Clone, Debug)]
pub struct CompiledSubscription {
    /// Shared with the scan of every partition of the pass.
    scan: Arc<CompiledScan>,
    /// One per output of `scan.outputs()`, in the same order.
    outputs: Vec<SubscribedOutput>,
    /// The index of the first stream table among the outputs.
    first_stream: usize,
}

impl CompiledSubscription {
    /// The compiled scan plan: the parse scope and, per output, its
    /// columns, predicate and row cap.
    pub fn scan(&self) -> &CompiledScan {
        &self.scan
    }

    /// [`Self::scan`], shared: what a partition's `PartitionScan` holds.
    pub fn shared_scan(&self) -> Arc<CompiledScan> {
        Arc::clone(&self.scan)
    }

    /// The tables the pass delivers (protocol tables, fused joins, then
    /// stream tables), each with its part of the compiled plan. The
    /// position of a table is its
    /// [`OutputId`](pcapsql_core::scan::OutputId).
    pub fn outputs(&self) -> impl ExactSizeIterator<Item = (&SubscribedOutput, &OutputPlan)> {
        self.outputs.iter().zip(self.scan.outputs())
    }

    /// The names of the stream-analysis tables among [`Self::outputs`].
    /// Any pins the pass to one partition.
    pub fn stream_tables(&self) -> impl Iterator<Item = &str> {
        self.outputs[self.first_stream..]
            .iter()
            .map(|output| &*output.name)
    }
}

#[cfg(test)]
pub(super) mod testing {
    use super::*;
    use crate::query::fusion::{FusedColumn, JoinKind, Member, MemberJoin};
    use arrow::datatypes::{DataType, Field, Schema};

    /// A column set of these names.
    pub fn names(columns: &[&str]) -> Option<HashSet<String>> {
        Some(columns.iter().map(|c| c.to_string()).collect())
    }

    /// `frames` left-joined with `tcp`, two columns, capped at 4 rows.
    pub fn fused(name: &str) -> FusedSubscription {
        let schema = Schema::new(vec![
            Field::new("f__frame_number", DataType::UInt64, false),
            Field::new("tcp__dst_port", DataType::UInt16, true),
        ]);
        FusedSubscription {
            spec: Arc::new(FrameJoinSpec {
                name: name.to_string(),
                members: vec![
                    Member {
                        table: "frames".to_string(),
                        alias: "f".to_string(),
                        join: None,
                    },
                    Member {
                        table: "tcp".to_string(),
                        alias: "tcp".to_string(),
                        join: Some(MemberJoin {
                            kind: JoinKind::Left,
                            with: 0,
                            depth: false,
                        }),
                    },
                ],
                schema: Arc::new(schema),
                columns: vec![
                    FusedColumn {
                        member: 0,
                        column: "frame_number".to_string(),
                    },
                    FusedColumn {
                        member: 1,
                        column: "dst_port".to_string(),
                    },
                ],
            }),
            fetch: Some(4),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{fused, names};
    use super::*;
    use crate::query::tables;
    use arrow::datatypes::Schema;
    use pcapsql_core::scan::{CmpOp, TimestampUnit};
    use std::collections::HashMap;

    /// The schema `table` is compiled to.
    fn schema_of(compiled: &CompiledSubscription, table: &str) -> Option<SchemaRef> {
        compiled
            .outputs()
            .find(|(output, _)| &*output.name == table)
            .map(|(output, _)| Arc::clone(&output.schema))
    }

    fn output_names(compiled: &CompiledSubscription) -> Vec<&str> {
        compiled
            .outputs()
            .map(|(output, _)| &*output.name)
            .collect()
    }

    /// A subscribed table's schema is derived from the compiled plan and is
    /// the table's Arrow schema restricted to the subscribed columns, in
    /// schema order, whatever order (a set) they were named in.
    #[test]
    fn schemas_derive_from_the_plan() {
        let registry = pcapsql_core::default_registry();
        for name in tables::all_table_names() {
            let full = tables::get_table_schema(name).unwrap();
            if tables::is_stream_table(name) {
                // A stream table is subscribed whole.
                let mut all = ParseSubscription::default();
                all.subscribe_stream_table(name).unwrap();
                let compiled = all.compile(&registry).unwrap();
                assert_eq!(*schema_of(&compiled, name).unwrap(), full, "{name}");
                continue;
            }
            let all = ParseSubscription::tables_full([name]).unwrap();
            let compiled = all.compile(&registry).unwrap();
            assert_eq!(*schema_of(&compiled, name).unwrap(), full, "{name}");

            let every_other: Vec<&str> = full
                .fields()
                .iter()
                .step_by(2)
                .map(|f| f.name().as_str())
                .collect();
            let mut some = ParseSubscription::default();
            some.subscribe_table(
                name,
                TableSubscription {
                    columns: names(&every_other),
                    ..Default::default()
                },
            )
            .unwrap();
            let schema = schema_of(&some.compile(&registry).unwrap(), name).unwrap();
            let expected: Vec<_> = full.fields().iter().step_by(2).cloned().collect();
            assert_eq!(*schema, Schema::new(expected), "{name}");
        }
    }

    #[test]
    fn plan_holds_tables_fused_joins_and_stream_tables() {
        let (tcp_id, tcp) = Catalog::builtin().table("tcp").unwrap();
        let (dst_port, _) = tcp.column("dst_port").unwrap();
        let predicate = RowPredicate::cmp(dst_port, CmpOp::Eq, 443);

        let mut sub = ParseSubscription::default();
        assert!(sub.is_empty());
        sub.subscribe_table(
            "tcp",
            TableSubscription {
                columns: names(&["dst_port", "frame_number"]),
                predicate: Some(predicate.clone()),
                fetch: Some(9),
            },
        )
        .unwrap();
        sub.subscribe_fused(fused("fused_b")).unwrap();
        sub.subscribe_fused(fused("fused_a")).unwrap();
        assert!(sub.has_packet_tables());
        assert!(!sub.has_stream_tables());
        sub.subscribe_stream_table("tls_sessions").unwrap();
        sub.subscribe_stream_table("tls_sessions").unwrap();
        assert!(sub.has_stream_tables());
        assert!(!sub.is_empty());

        let plan = sub.plan();
        assert_eq!(plan.timestamps, TimestampUnit::Micros);
        assert!(plan.frames.is_all());
        let [scan] = plan.tables.as_slice() else {
            panic!("one table scan");
        };
        assert_eq!(scan.table, tcp_id);
        // Schema order, not the order the columns were named in.
        let (frame_number, _) = tcp.column("frame_number").unwrap();
        assert_eq!(scan.columns, vec![frame_number, dst_port]);
        assert_eq!(scan.predicate, Some(predicate));
        assert_eq!(scan.fetch, Some(9));
        assert_eq!(plan.fused.len(), 2);
        assert_eq!(plan.fused[0].fetch, Some(4));
        assert_eq!(plan.streams.len(), 1);

        let registry = pcapsql_core::default_registry();
        let compiled = sub.compile(&registry).unwrap();
        assert!(compiled.scan().requires_single_partition());
        assert_eq!(
            compiled.stream_tables().collect::<Vec<_>>(),
            ["tls_sessions"]
        );
        let outputs: Vec<_> = compiled.outputs().collect();
        // Fused joins are kept in name order; the stream tables come last.
        assert_eq!(
            output_names(&compiled),
            ["tcp", "fused_a", "fused_b", "tls_sessions"]
        );
        assert!(outputs[3].0.spec.is_none());
        assert_eq!(
            *outputs[3].0.schema,
            tables::get_table_schema("tls_sessions").unwrap()
        );
        assert!(outputs[0].0.spec.is_none());
        assert!(outputs[0].1.predicate().is_some());
        assert_eq!(outputs[0].1.fetch(), Some(9));
        // A fused join keeps its spec's schema.
        let spec = outputs[1].0.spec.as_ref().unwrap();
        assert_eq!(spec.name, "fused_a");
        assert!(Arc::ptr_eq(&outputs[1].0.schema, &spec.schema));
        assert_eq!(outputs[1].1.columns.len(), spec.schema.fields().len());
        assert_eq!(outputs[1].1.fetch(), Some(4));
        assert!(schema_of(&compiled, "udp").is_none());
    }

    /// The scope is what the plan compiles to: the subscribed protocols with
    /// their dependencies, projected to the fields the columns read.
    #[test]
    fn compiled_scope_follows_the_subscribed_columns() {
        let registry = pcapsql_core::default_registry();
        let mut sub = ParseSubscription::tables_full(["dns", "frames"]).unwrap();
        sub.subscribe_table(
            "udp",
            TableSubscription {
                columns: names(&["frame_number", "dst_port", "encap_depth"]),
                ..Default::default()
            },
        )
        .unwrap();
        let compiled = sub.compile(&registry).unwrap();
        let scope = compiled.scan().scope();
        assert_eq!(
            scope.required(),
            pcapsql_core::ParseScope::for_tables(&["dns", "udp"], &registry).required()
        );
        assert_eq!(
            scope.projections(),
            &HashMap::from([("udp".to_string(), HashSet::from(["dst_port".to_string()]))])
        );
        assert!(!compiled.scan().requires_single_partition());
    }

    #[test]
    fn invalid_subscriptions_are_errors() {
        let mut sub = ParseSubscription::default();
        assert!(sub
            .subscribe_table("nonexistent", TableSubscription::default())
            .is_err());
        // A stream table is not built per packet, and the reverse.
        assert!(sub
            .subscribe_table("tcp_connections", TableSubscription::default())
            .is_err());
        assert!(sub.subscribe_stream_table("tcp").is_err());
        assert!(sub.subscribe_stream_table("nonexistent").is_err());
        // A column the table does not have, or one DataFusion does not see.
        for column in ["query_name", "timestamp"] {
            let error = sub
                .subscribe_table(
                    "tcp",
                    TableSubscription {
                        columns: names(&["dst_port", column]),
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(
                matches!(&error, Error::Query(QueryError::UnknownColumn { table, column: c })
                    if table == "tcp" && c == column),
                "{error}"
            );
        }
        assert!(sub.is_empty());
        // One subscription per table and per fused join.
        sub.subscribe_table("tcp", TableSubscription::default())
            .unwrap();
        assert!(sub
            .subscribe_table("tcp", TableSubscription::default())
            .is_err());
        sub.subscribe_fused(fused("fused_a")).unwrap();
        assert!(sub.subscribe_fused(fused("fused_a")).is_err());
        assert!(ParseSubscription::tables_full(["udp", "udp"]).is_err());
        let registry = pcapsql_core::default_registry();
        assert_eq!(
            output_names(&sub.compile(&registry).unwrap()),
            ["tcp", "fused_a"]
        );
    }
}
