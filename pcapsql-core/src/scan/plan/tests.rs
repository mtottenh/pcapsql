use super::*;
use crate::default_registry;
use crate::scan::CmpOp;

fn catalog() -> &'static Catalog {
    Catalog::builtin()
}

fn id(table: &str) -> TableId {
    catalog().table(table).expect("table").0
}

fn cols(table: &str, names: &[&str]) -> Vec<ColId> {
    let (_, def) = catalog().table(table).expect("table");
    names
        .iter()
        .map(|n| def.column(n).unwrap_or_else(|| panic!("{table}.{n}")).0)
        .collect()
}

fn default_cols(table: &str) -> Vec<ColId> {
    let (_, def) = catalog().table(table).expect("table");
    def.default_columns().map(|(c, _)| c).collect()
}

fn scan(table: &str, names: &[&str]) -> TableScan {
    TableScan::new(id(table), cols(table, names))
}

fn full(table: &str) -> TableScan {
    TableScan::new(id(table), default_cols(table))
}

/// Compiled as by a frontend that builds stream tables: several plans
/// here have some.
fn compile(plan: &ScanPlan) -> Result<CompiledScan, PlanError> {
    plan.compile_with_streams(catalog(), &default_registry())
}

/// A plan with stream tables compiles only for a frontend that says it
/// builds them: the scan driver would give them no rows.
#[test]
fn stream_tables_need_a_frontend_that_builds_them() {
    let registry = default_registry();
    let plan = ScanPlan {
        tables: vec![full("frames")],
        streams: vec![scan("tls_sessions", &[]), full("tcp_connections")],
        ..ScanPlan::default()
    };
    assert_eq!(
        plan.compile(catalog(), &registry).unwrap_err(),
        PlanError::StreamsNotBuilt("tls_sessions")
    );
    let compiled = plan.compile_with_streams(catalog(), &registry).unwrap();
    assert_eq!(compiled.outputs().len(), 1);
    assert_eq!(compiled.stream_outputs().len(), 2);
    // Without stream tables the two are the same.
    let plain = ScanPlan {
        tables: vec![full("frames"), full("tcp")],
        fused: plan.fused.clone(),
        ..ScanPlan::default()
    };
    let compiled = plain.compile(catalog(), &registry).unwrap();
    assert_eq!(compiled.outputs().len(), 2);
    assert!(compiled.stream_outputs().is_empty());
    // A stream table the catalogue does not have is that error first.
    let nowhere = TableId(u16::MAX);
    let unknown = ScanPlan {
        streams: vec![TableScan::new(nowhere, vec![])],
        ..ScanPlan::default()
    };
    assert_eq!(
        unknown.compile(catalog(), &registry).unwrap_err(),
        PlanError::UnknownTable(nowhere)
    );
}

fn set(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_empty_plan_parses_nothing() {
    let compiled = compile(&ScanPlan::default()).unwrap();
    assert!(compiled.outputs().is_empty());
    assert!(compiled.stream_outputs().is_empty());
    assert!(!compiled.requires_single_partition());
    assert_eq!(compiled.scope().required(), Some(&set(&["frames"])));
    assert!(compiled.scope().projections().is_empty());
    assert_eq!(compiled.timestamps(), TimestampUnit::Micros);
}

#[test]
fn outputs_follow_the_plan_in_column_order() {
    let plan = ScanPlan {
        tables: vec![
            scan("tcp", &["dst_port", "frame_number", "tunnel_type"]),
            scan("frames", &["timestamp", "length"]),
        ],
        ..ScanPlan::default()
    };
    let compiled = compile(&plan).unwrap();
    let [tcp, frames] = compiled.outputs() else {
        panic!("two outputs");
    };
    assert_eq!(tcp.table, Some(id("tcp")));
    assert_eq!(
        tcp.columns.to_vec(),
        vec![
            OutColumn {
                name: "dst_port",
                kind: ColKind::U16,
                nullable: true,
                source: ColumnSource::Field("dst_port"),
            },
            OutColumn {
                name: "frame_number",
                kind: ColKind::U64,
                nullable: false,
                source: ColumnSource::FrameNumber,
            },
            OutColumn {
                name: "tunnel_type",
                kind: ColKind::Str,
                nullable: true,
                source: ColumnSource::TunnelType,
            },
        ]
    );
    assert_eq!(frames.table, Some(id("frames")));
    assert_eq!(
        frames
            .columns
            .iter()
            .map(|c| (c.name, c.kind, c.source))
            .collect::<Vec<_>>(),
        vec![
            ("timestamp", ColKind::TsMicros, ColumnSource::Timestamp),
            ("length", ColKind::U32, ColumnSource::CapturedLen),
        ]
    );
    assert!(tcp.predicate().is_none());
    assert_eq!(tcp.fetch(), None);
}

#[test]
fn scope_is_the_dependency_closure_with_field_projections() {
    let plan = ScanPlan {
        tables: vec![
            scan("tcp", &["frame_number", "dst_port", "encap_depth"]),
            full("dns"),
            scan("frames", &["length"]),
        ],
        ..ScanPlan::default()
    };
    let registry = default_registry();
    let compiled = plan.compile(catalog(), &registry).unwrap();
    let scope = compiled.scope();
    assert_eq!(
        scope.required(),
        ParseScope::for_tables(&["tcp", "dns", "frames"], &registry).required()
    );
    // Pseudo-columns are not parser fields; a table read in full has no
    // projection; `frames` is not parsed.
    assert_eq!(
        scope.projections(),
        &HashMap::from([("tcp".to_string(), set(&["dst_port"]))])
    );
}

#[test]
fn a_scan_without_field_columns_projects_no_fields() {
    let plan = ScanPlan {
        tables: vec![scan("udp", &[]), scan("tcp", &["frame_number"])],
        ..ScanPlan::default()
    };
    let compiled = compile(&plan).unwrap();
    assert_eq!(
        compiled.scope().projections(),
        &HashMap::from([
            ("udp".to_string(), HashSet::new()),
            ("tcp".to_string(), HashSet::new())
        ])
    );
    assert!(compiled.outputs()[0].columns.is_empty());
}

#[test]
fn timestamp_unit_applies_to_every_timestamp_column() {
    for (unit, kind) in [
        (TimestampUnit::Micros, ColKind::TsMicros),
        (TimestampUnit::Nanos, ColKind::TsNanos),
    ] {
        let plan = ScanPlan {
            tables: vec![scan("frames", &["frame_number", "timestamp"])],
            streams: vec![full("tcp_connections")],
            timestamps: unit,
            ..ScanPlan::default()
        };
        let compiled = compile(&plan).unwrap();
        assert_eq!(compiled.timestamps(), unit);
        let frames = &compiled.outputs()[0];
        assert_eq!(frames.columns[0].kind, ColKind::U64);
        assert_eq!(frames.columns[1].kind, kind);
        let stream = &compiled.stream_outputs()[0];
        let stamps: Vec<ColKind> = stream
            .columns
            .iter()
            .map(|c| c.kind)
            .filter(|k| k.is_timestamp())
            .collect();
        assert!(!stamps.is_empty());
        assert!(stamps.iter().all(|k| *k == kind), "{stamps:?}");
    }
}

/// The protocol tables' `timestamp` is not a default column, but a plan
/// can select it; it is read from the packet, not from a parser field.
#[test]
fn the_opt_in_timestamp_column_is_selectable() {
    let (_, tcp) = catalog().table("tcp").unwrap();
    let (timestamp, def) = tcp.column("timestamp").unwrap();
    assert!(!def.default);
    assert!(!default_cols("tcp").contains(&timestamp));

    let plan = ScanPlan {
        tables: vec![scan("tcp", &["timestamp", "dst_port"])],
        timestamps: TimestampUnit::Nanos,
        ..ScanPlan::default()
    };
    let compiled = compile(&plan).unwrap();
    assert_eq!(
        compiled.outputs()[0].columns[0],
        OutColumn {
            name: "timestamp",
            kind: ColKind::TsNanos,
            nullable: false,
            source: ColumnSource::Timestamp,
        }
    );
    assert_eq!(
        compiled.scope().projections(),
        &HashMap::from([("tcp".to_string(), set(&["dst_port"]))])
    );

    // Every column, opt-in included, still reads every field: no
    // projection.
    let all: Vec<ColId> = tcp.columns().map(|(c, _)| c).collect();
    let plan = ScanPlan {
        tables: vec![TableScan::new(id("tcp"), all)],
        ..ScanPlan::default()
    };
    assert!(compile(&plan).unwrap().scope().projections().is_empty());
}

#[test]
fn stream_tables_pin_one_partition_and_parse_tcp_in_full() {
    let plan = ScanPlan {
        tables: vec![
            scan("tcp", &["dst_port"]),
            scan("ipv4", &["ttl"]),
            scan("udp", &["dst_port"]),
        ],
        streams: vec![full("http_messages"), scan("tls_sessions", &[])],
        ..ScanPlan::default()
    };
    let registry = default_registry();
    let compiled = plan.compile_with_streams(catalog(), &registry).unwrap();
    assert!(compiled.requires_single_partition());
    assert_eq!(compiled.outputs().len(), 3);
    let [http, tls] = compiled.stream_outputs() else {
        panic!("two stream outputs");
    };
    assert_eq!(http.table, Some(id("http_messages")));
    assert_eq!(catalog().get(id("http_messages")).kind, TableKind::Stream);
    assert_eq!(http.columns.len(), default_cols("http_messages").len());
    assert!(http
        .columns
        .iter()
        .all(|c| c.source == ColumnSource::Stream));
    assert!(tls.columns.is_empty());
    // The stream analysis reads tcp and the IP layers in full; other
    // tables keep their projection.
    assert_eq!(
        compiled.scope().projections(),
        &HashMap::from([("udp".to_string(), set(&["dst_port"]))])
    );
    assert_eq!(
        compiled.scope().required(),
        ParseScope::for_tables(&["tcp", "ipv4", "udp"], &registry).required()
    );

    // Stream tables alone still parse tcp and what it depends on.
    let plan = ScanPlan {
        streams: vec![full("tcp_connections")],
        ..ScanPlan::default()
    };
    let compiled = plan.compile_with_streams(catalog(), &registry).unwrap();
    assert!(compiled.requires_single_partition());
    assert!(compiled.outputs().is_empty());
    assert_eq!(
        compiled.scope().required(),
        ParseScope::for_tables(&["tcp"], &registry).required()
    );
    assert!(compiled.scope().projections().is_empty());

    let plan = ScanPlan {
        tables: vec![full("tcp")],
        ..ScanPlan::default()
    };
    assert!(!compile(&plan).unwrap().requires_single_partition());
}

#[test]
fn predicate_and_fetch_reach_the_output() {
    let (_, tcp) = catalog().table("tcp").unwrap();
    let dst_port = tcp.column("dst_port").unwrap().0;
    let frame_number = tcp.column("frame_number").unwrap().0;
    let plan = ScanPlan {
        tables: vec![
            TableScan {
                predicate: Some(RowPredicate::cmp(dst_port, CmpOp::Eq, 443)),
                fetch: Some(7),
                ..scan("tcp", &["frame_number"])
            },
            TableScan {
                // Cannot drop a row: no compiled predicate.
                predicate: Some(RowPredicate::cmp(frame_number, CmpOp::Eq, 1)),
                ..scan("udp", &["frame_number"])
            },
        ],
        ..ScanPlan::default()
    };
    let compiled = compile(&plan).unwrap();
    let [tcp_out, udp_out] = compiled.outputs() else {
        panic!("two outputs");
    };
    assert_eq!(tcp_out.fetch(), Some(7));
    assert!(tcp_out.predicate().is_some());
    assert!(udp_out.predicate().is_none());
    // The predicate's field is extracted although it is not an output
    // column; a predicate that cannot drop a row adds nothing.
    assert_eq!(
        compiled.scope().projections(),
        &HashMap::from([
            ("tcp".to_string(), set(&["dst_port"])),
            ("udp".to_string(), HashSet::new()),
        ])
    );
}

#[test]
fn fused_scans_resolve_members_and_columns() {
    let frames = id("frames");
    let tcp = id("tcp");
    let ipv4 = id("ipv4");
    let col = |table: &str, name: &str| cols(table, &[name])[0];
    let plan = ScanPlan {
        tables: vec![scan("tcp", &["src_port"])],
        fused: vec![FusedScan {
            members: vec![
                FusedMember {
                    table: frames,
                    join: None,
                },
                FusedMember {
                    table: tcp,
                    join: Some(MemberJoin {
                        kind: JoinKind::Inner,
                        with: 0,
                        depth: false,
                    }),
                },
                FusedMember {
                    table: ipv4,
                    join: Some(MemberJoin {
                        kind: JoinKind::Left,
                        with: 1,
                        depth: true,
                    }),
                },
            ],
            columns: vec![
                (0, col("frames", "timestamp")).into(),
                (1, col("tcp", "dst_port")).into(),
                (1, col("tcp", "encap_depth")).into(),
                (2, col("ipv4", "encap_depth")).into(),
                (2, col("ipv4", "ttl")).into(),
            ],
            filter: None,
            fetch: Some(3),
        }],
        ..ScanPlan::default()
    };
    let registry = default_registry();
    let compiled = plan.compile(catalog(), &registry).unwrap();
    let [_, fused] = compiled.outputs() else {
        panic!("a table and a fused output");
    };
    assert_eq!(fused.table, None);
    assert_eq!(fused.fetch(), Some(3));
    assert_eq!(
        fused
            .columns
            .iter()
            .map(|c| (c.name, c.nullable, c.source))
            .collect::<Vec<_>>(),
        vec![
            ("timestamp", false, ColumnSource::Timestamp),
            ("dst_port", true, ColumnSource::Field("dst_port")),
            ("encap_depth", false, ColumnSource::EncapDepth),
            // Left-joined: NULL when the frame has no such row.
            ("encap_depth", true, ColumnSource::EncapDepth),
            ("ttl", true, ColumnSource::Field("ttl")),
        ]
    );
    // The table scan's and the fused member's columns are united.
    assert_eq!(
        compiled.scope().projections(),
        &HashMap::from([
            ("tcp".to_string(), set(&["src_port", "dst_port"])),
            ("ipv4".to_string(), set(&["ttl"])),
        ])
    );
    assert_eq!(
        compiled.scope().required(),
        ParseScope::for_tables(&["tcp", "ipv4"], &registry).required()
    );
}

#[test]
fn a_fused_member_without_columns_is_still_parsed() {
    let plan = ScanPlan {
        fused: vec![FusedScan {
            members: vec![
                FusedMember {
                    table: id("frames"),
                    join: None,
                },
                FusedMember {
                    table: id("dns"),
                    join: Some(MemberJoin {
                        kind: JoinKind::Inner,
                        with: 0,
                        depth: false,
                    }),
                },
            ],
            columns: vec![(0, cols("frames", &["frame_number"])[0]).into()],
            filter: None,
            fetch: None,
        }],
        ..ScanPlan::default()
    };
    let registry = default_registry();
    let compiled = plan.compile(catalog(), &registry).unwrap();
    assert_eq!(
        compiled.scope().required(),
        ParseScope::for_tables(&["dns"], &registry).required()
    );
    assert_eq!(
        compiled.scope().projections(),
        &HashMap::from([("dns".to_string(), HashSet::new())])
    );
}

#[test]
fn unknown_tables_and_columns_are_errors() {
    let nowhere = TableId(u16::MAX);
    let bad_column = ColId(u16::MAX);
    let with = |f: &dyn Fn(&mut ScanPlan)| {
        let mut plan = ScanPlan::default();
        f(&mut plan);
        compile(&plan).unwrap_err()
    };

    assert_eq!(
        with(&|p| p.tables.push(TableScan::new(nowhere, vec![]))),
        PlanError::UnknownTable(nowhere)
    );
    assert_eq!(
        with(&|p| p.streams.push(TableScan::new(nowhere, vec![]))),
        PlanError::UnknownTable(nowhere)
    );
    assert_eq!(
        with(&|p| p.fused.push(FusedScan {
            members: vec![FusedMember {
                table: nowhere,
                join: None
            }],
            columns: vec![],
            filter: None,
            fetch: None,
        })),
        PlanError::UnknownTable(nowhere)
    );

    let unknown = |table| PlanError::UnknownColumn {
        table,
        column: bad_column,
    };
    assert_eq!(
        with(&|p| p.tables.push(TableScan::new(id("tcp"), vec![bad_column]))),
        unknown("tcp")
    );
    assert_eq!(
        with(&|p| p
            .streams
            .push(TableScan::new(id("tls_sessions"), vec![bad_column]))),
        unknown("tls_sessions")
    );
    assert_eq!(
        with(&|p| p.fused.push(FusedScan {
            members: vec![FusedMember {
                table: id("udp"),
                join: None
            }],
            columns: vec![(0, bad_column).into()],
            filter: None,
            fetch: None,
        })),
        unknown("udp")
    );
    assert_eq!(
        with(&|p| p.tables.push(TableScan {
            predicate: Some(RowPredicate::And(vec![RowPredicate::cmp(
                bad_column,
                CmpOp::Eq,
                1
            )])),
            ..scan("tcp", &["dst_port"])
        })),
        unknown("tcp")
    );
    assert_eq!(
        unknown("tcp").to_string(),
        format!("table tcp has no column {}", u16::MAX)
    );
}

#[test]
fn misplaced_and_repeated_tables_are_errors() {
    let with = |f: &dyn Fn(&mut ScanPlan)| {
        let mut plan = ScanPlan::default();
        f(&mut plan);
        compile(&plan).unwrap_err()
    };
    assert_eq!(
        with(&|p| p.tables.push(full("tcp_connections"))),
        PlanError::NotAPacketTable("tcp_connections")
    );
    assert_eq!(
        with(&|p| p.streams.push(full("tcp"))),
        PlanError::NotAStreamTable("tcp")
    );
    assert_eq!(
        with(&|p| p.streams.push(full("frames"))),
        PlanError::NotAStreamTable("frames")
    );
    assert_eq!(
        with(&|p| p.tables.extend([full("tcp"), scan("tcp", &[])])),
        PlanError::DuplicateTable("tcp")
    );
    assert_eq!(
        with(&|p| p.streams.extend([full("http2"), full("http2")])),
        PlanError::DuplicateTable("http2")
    );
    let (_, sessions) = catalog().table("tls_sessions").unwrap();
    let first = sessions.columns().next().unwrap().0;
    assert_eq!(
        with(&|p| p.streams.push(TableScan {
            predicate: Some(RowPredicate::cmp(first, CmpOp::Eq, 1)),
            ..full("tls_sessions")
        })),
        PlanError::StreamPredicate("tls_sessions")
    );
    // A frame predicate and stream tables do not go together, whatever
    // else the plan holds; either alone is fine.
    let bounded = FramePredicate {
        frames: (std::ops::Bound::Unbounded, std::ops::Bound::Included(10)),
        ..FramePredicate::all()
    };
    let timed = FramePredicate {
        time_ns: (std::ops::Bound::Excluded(0), std::ops::Bound::Unbounded),
        ..FramePredicate::all()
    };
    for frames in [&bounded, &timed] {
        assert_eq!(
            with(&|p| {
                p.frames = frames.clone();
                p.streams.push(full("tcp_connections"));
            }),
            PlanError::StreamFramePredicate
        );
        assert_eq!(
            with(&|p| {
                p.frames = frames.clone();
                p.tables.push(full("frames"));
                p.streams.push(scan("tls_sessions", &[]));
            }),
            PlanError::StreamFramePredicate
        );
        let alone = ScanPlan {
            tables: vec![full("frames"), full("tcp")],
            frames: frames.clone(),
            ..Default::default()
        };
        let compiled = compile(&alone).unwrap();
        assert_eq!(compiled.frames(), frames);
        assert!(!compiled.requires_single_partition());
    }
    let streams = ScanPlan {
        tables: vec![full("frames")],
        streams: vec![full("tcp_connections")],
        ..Default::default()
    };
    assert!(compile(&streams).unwrap().frames().is_all());
    // The same table as a scan and as a fused member is fine.
    let plan = ScanPlan {
        tables: vec![full("tcp")],
        fused: vec![FusedScan {
            members: vec![FusedMember {
                table: id("tcp"),
                join: None,
            }],
            columns: vec![],
            filter: None,
            fetch: None,
        }],
        ..ScanPlan::default()
    };
    assert!(compile(&plan).is_ok());
}

#[test]
fn malformed_fused_joins_are_errors() {
    let inner = |with| {
        Some(MemberJoin {
            kind: JoinKind::Inner,
            with,
            depth: false,
        })
    };
    let member = |table: &str, join| FusedMember {
        table: id(table),
        join,
    };
    let reason = |members: Vec<FusedMember>, columns: Vec<(u16, ColId)>| {
        let plan = ScanPlan {
            fused: vec![FusedScan {
                members,
                columns: columns.into_iter().map(Into::into).collect(),
                filter: None,
                fetch: None,
            }],
            ..ScanPlan::default()
        };
        match compile(&plan).unwrap_err() {
            PlanError::InvalidFused { fused: 0, reason } => reason,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(reason(vec![], vec![]), "no members");
    assert_eq!(
        reason(vec![member("frames", inner(0))], vec![]),
        "the first member cannot have a join"
    );
    assert_eq!(
        reason(vec![member("frames", None), member("tcp", None)], vec![]),
        "a later member needs a join"
    );
    assert_eq!(
        reason(
            vec![member("frames", None), member("tcp", inner(1))],
            vec![]
        ),
        "a member can only join an earlier member"
    );
    assert_eq!(
        reason(vec![member("frames", None)], vec![(1, ColId(0))]),
        "a column names a member the join does not have"
    );

    let plan = ScanPlan {
        fused: vec![FusedScan {
            members: vec![member("frames", None), member("tls_sessions", inner(0))],
            columns: vec![],
            filter: None,
            fetch: None,
        }],
        ..ScanPlan::default()
    };
    assert_eq!(
        compile(&plan).unwrap_err(),
        PlanError::NotAPacketTable("tls_sessions")
    );
}

/// `frames`, `tcp` on the frame, `ipv4` and `ipv6` left-joined on the
/// level of `tcp`.
fn tcp_join(columns: Vec<FusedColumn>, filter: Option<FusedFilter>) -> ScanPlan {
    let join = |kind, with, depth| Some(MemberJoin { kind, with, depth });
    ScanPlan {
        fused: vec![FusedScan {
            members: vec![
                FusedMember {
                    table: id("frames"),
                    join: None,
                },
                FusedMember {
                    table: id("tcp"),
                    join: join(JoinKind::Inner, 0, false),
                },
                FusedMember {
                    table: id("ipv4"),
                    join: join(JoinKind::Left, 1, true),
                },
                FusedMember {
                    table: id("ipv6"),
                    join: join(JoinKind::Left, 1, true),
                },
            ],
            columns,
            filter,
            fetch: None,
        }],
        ..ScanPlan::default()
    }
}

#[test]
fn computed_columns_of_a_fused_join_are_named_typed_and_parsed() {
    let col = |table: &str, name: &str| cols(table, &[name])[0];
    let plan = tcp_join(
        vec![
            FusedColumn {
                name: Some("src_ip_v4"),
                value: FusedValue::Column {
                    member: 2,
                    column: col("ipv4", "src_ip"),
                },
            },
            FusedColumn {
                name: Some("ttl"),
                value: FusedValue::Coalesce(vec![
                    (2, col("ipv4", "ttl")),
                    (3, col("ipv6", "hop_limit")),
                ]),
            },
            FusedColumn {
                name: Some("family"),
                value: FusedValue::Present {
                    cases: vec![(2, "v4"), (3, "v6")],
                    otherwise: "none",
                },
            },
            (1, col("tcp", "encap_depth")).into(),
        ],
        Some(FusedFilter {
            member: 1,
            column: col("tcp", "dst_port"),
            any_of: vec![80, 443],
        }),
    );
    let compiled = compile(&plan).unwrap();
    let columns: Vec<_> = compiled.outputs()[0]
        .columns
        .iter()
        .map(|c| (c.name, c.kind, c.nullable, c.source))
        .collect();
    assert_eq!(
        columns,
        [
            (
                "src_ip_v4",
                ColKind::U32,
                true,
                ColumnSource::Field("src_ip")
            ),
            ("ttl", ColKind::U8, true, ColumnSource::Computed),
            ("family", ColKind::Str, false, ColumnSource::Computed),
            ("encap_depth", ColKind::U8, false, ColumnSource::EncapDepth),
        ]
    );
    // Every argument of a computed column, and the filter's column, is
    // extracted.
    let projections = compiled.scope().projections();
    let fields = |protocol: &str| {
        let mut fields: Vec<&str> = projections[protocol].iter().map(String::as_str).collect();
        fields.sort_unstable();
        fields
    };
    assert_eq!(fields("ipv4"), ["src_ip", "ttl"]);
    assert_eq!(fields("ipv6"), ["hop_limit"]);
    assert_eq!(fields("tcp"), ["dst_port"]);
}

#[test]
fn malformed_computed_columns_and_filters_are_errors() {
    let col = |table: &str, name: &str| cols(table, &[name])[0];
    let reason = |plan: ScanPlan| match compile(&plan).unwrap_err() {
        PlanError::InvalidFused { fused: 0, reason } => reason,
        other => panic!("{other:?}"),
    };
    let computed = |name, value| tcp_join(vec![FusedColumn { name, value }], None);
    assert_eq!(
        reason(computed(Some("x"), FusedValue::Coalesce(vec![]))),
        "a COALESCE without arguments"
    );
    assert_eq!(
        reason(computed(
            Some("x"),
            FusedValue::Coalesce(vec![(2, col("ipv4", "ttl")), (1, col("tcp", "dst_port"))])
        )),
        "the arguments of a COALESCE differ in kind"
    );
    assert_eq!(
        reason(computed(
            None,
            FusedValue::Coalesce(vec![(2, col("ipv4", "ttl"))])
        )),
        "a computed column needs a name"
    );
    assert_eq!(
        reason(computed(
            Some("x"),
            FusedValue::Present {
                cases: vec![(4, "no such member")],
                otherwise: "",
            }
        )),
        "a column names a member the join does not have"
    );
    assert_eq!(
        reason(computed(
            Some("x"),
            FusedValue::Coalesce(vec![(9, col("ipv4", "ttl"))])
        )),
        "a column names a member the join does not have"
    );

    let filtered = |member, column| {
        tcp_join(
            vec![],
            Some(FusedFilter {
                member,
                column,
                any_of: vec![1],
            }),
        )
    };
    assert_eq!(
        reason(filtered(1, col("tcp", "encap_depth"))),
        "the filter is not on a parser field"
    );
    assert_eq!(
        reason(filtered(0, col("frames", "frame_number"))),
        "the filter is not on a parser field"
    );
    assert_eq!(
        reason(filtered(3, col("ipv6", "src_ip"))),
        "the filter is not on an integer column"
    );
    assert_eq!(
        reason(filtered(7, col("tcp", "dst_port"))),
        "a column names a member the join does not have"
    );
    assert!(compile(&filtered(1, col("tcp", "dst_port"))).is_ok());
}
