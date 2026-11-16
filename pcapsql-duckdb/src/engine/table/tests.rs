use pcapsql_core::io::{Compression, StreamHeader};
use pcapsql_core::scan::FramePredicate;

use super::args::{has_wildcard, DEFAULT_PROTOCOL};
use super::report::parsed_protocols;
use super::*;

fn bound(relation: &str) -> BindData {
    let relation = Relation::find(relation).unwrap();
    BindData {
        files: Box::new(["x.pcap".to_owned()]),
        total_size: 0,
        relation,
        columns: relation.columns().len(),
        filename: None,
        strict: false,
        pushed: Pushed::new(Some(0), Some(1)),
    }
}

fn scan(relation: &str) -> PcapScan {
    PcapScan {
        name: format!("read_{relation}"),
        relation: Relation::find(relation),
    }
}

/// Where the column `name` of `relation` is declared.
fn index(relation: &str, name: &str) -> usize {
    Relation::find(relation)
        .unwrap()
        .columns()
        .iter()
        .position(|column| column.name == name)
        .unwrap_or_else(|| panic!("{relation}.{name}"))
}

/// The plan `init_global_state` compiles for a projection.
fn compiled(relation: &str, projected: &[usize]) -> CompiledScan {
    let bound = bound(relation);
    let projection = scan(relation).projection(&bound, projected).unwrap();
    bound
        .relation
        .plan(&projection.columns, FramePredicate::all())
        .compile(Catalog::builtin(), protocols())
        .unwrap()
}

#[test]
fn a_frames_projection_parses_no_protocol() {
    let bound = bound("frames");
    let all: Vec<usize> = (0..bound.columns).collect();
    // frame_number alone, every column, and no column at all (a row count).
    for projection in [&[0][..], &all[..], &[usize::MAX][..]] {
        let plan = compiled("frames", projection);
        assert_eq!(parsed_protocols(&plan), "none", "{projection:?}");
        assert!(plan.scope().projections().is_empty());
    }
    assert_eq!(index("frames", "frame_number"), 0);
}

#[test]
fn a_protocol_table_parses_its_protocol_and_what_it_depends_on_only() {
    let plan = compiled("tcp", &[0]);
    let protocols = parsed_protocols(&plan);
    assert!(protocols.contains("tcp (no fields)"), "{protocols}");
    // Nothing above TCP. (UDP is there: a tunnel over UDP can carry TCP.)
    for other in ["dns", "http", "tls", "icmp", "bgp", "arp"] {
        assert!(!protocols.contains(other), "{protocols}");
    }
    // frame_number comes from the packet record: no TCP field is extracted for it.
    assert_eq!(
        plan.scope()
            .projections()
            .get("tcp")
            .map(|fields| fields.len()),
        Some(0)
    );

    // A field column extracts that field and no other.
    let plan = compiled("tcp", &[0, index("tcp", "dst_port")]);
    let fields = &plan.scope().projections()["tcp"];
    assert_eq!(fields.len(), 1);
    assert!(fields.contains("dst_port"));
    assert!(parsed_protocols(&plan).contains("tcp (fields: dst_port)"));

    // Every column: the parser runs unprojected.
    let all: Vec<usize> = (0..bound("tcp").columns).collect();
    let protocols = parsed_protocols(&compiled("tcp", &all));
    assert!(protocols.contains("tcp, "), "{protocols}");
}

#[test]
fn the_output_columns_follow_the_projection_order() {
    let index = |name: &str| index("tcp", name);
    let plan = compiled("tcp", &[index("dst_port"), index("timestamp"), 0]);
    let names: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
    assert_eq!(names, ["dst_port", "timestamp", "frame_number"]);
    // The opt-in timestamp of a protocol table, in this engine's unit.
    assert_eq!(
        types::sql_name(plan.outputs()[0].columns[1].kind),
        "TIMESTAMP_NS"
    );
}

#[test]
fn a_view_is_one_fused_output_that_parses_what_its_columns_need() {
    let index = |name: &str| index("tcp_packets", name);
    // The frame's columns and the anchor's level: every member is parsed (its rows decide
    // which joined rows there are), none has a field extracted.
    let plan = compiled(
        "tcp_packets",
        &[index("encap_depth"), index("timestamp"), 0],
    );
    assert_eq!(plan.outputs().len(), 1);
    assert_eq!(plan.outputs()[0].table, None);
    let names: Vec<&str> = plan.outputs()[0].columns.iter().map(|c| c.name).collect();
    assert_eq!(names, ["encap_depth", "timestamp", "frame_number"]);
    assert_eq!(
        types::sql_name(plan.outputs()[0].columns[1].kind),
        "TIMESTAMP_NS"
    );
    let protocols = parsed_protocols(&plan);
    for member in ["ethernet", "ipv4", "ipv6", "tcp"] {
        assert!(
            protocols.contains(&format!("{member} (no fields)")),
            "{protocols}"
        );
    }
    for other in ["dns", "http", "tls"] {
        assert!(!protocols.contains(other), "{protocols}");
    }

    // The view's own names; a computed column extracts each of its arguments.
    let plan = compiled("tcp_packets", &[index("src_ip_v4"), index("ttl")]);
    let fields = |protocol: &str| {
        let mut fields: Vec<&str> = plan.scope().projections()[protocol]
            .iter()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        fields
    };
    assert_eq!(fields("ipv4"), ["src_ip", "ttl"]);
    assert_eq!(fields("ipv6"), ["hop_limit"]);
    assert!(fields("tcp").is_empty() && fields("ethernet").is_empty());

    // A row count still needs the join: a view has a row per anchor row that the required
    // layers stand beside.
    let plan = compiled("tls_packets", &[usize::MAX]);
    assert!(plan.outputs()[0].columns.is_empty());
    let protocols = parsed_protocols(&plan);
    // `tls` has no projected parse: its layers carry every field.
    assert!(
        protocols.split(", ").any(|protocol| protocol == "tls"),
        "{protocols}"
    );
    assert!(protocols.contains("tcp (no fields)"), "{protocols}");
}

#[test]
fn a_view_declares_the_frame_s_number_and_time_for_pushdown() {
    for relation in relation::relations() {
        let columns = relation.columns();
        let of = |frame: FrameColumn| {
            let found: Vec<usize> = columns
                .iter()
                .enumerate()
                .filter(|(_, column)| column.frame == Some(frame))
                .map(|(index, _)| index)
                .collect();
            assert_eq!(found.len(), 1, "{}: {frame:?}", relation.name());
            found[0]
        };
        assert_eq!(of(FrameColumn::Number), 0, "{}", relation.name());
        assert_eq!(of(FrameColumn::Timestamp), 1, "{}", relation.name());
        assert_eq!(columns[0].name, "frame_number", "{}", relation.name());
        assert_eq!(columns[1].name, "timestamp", "{}", relation.name());
        assert_eq!(
            types::sql_name(columns[1].kind),
            "TIMESTAMP_NS",
            "{}",
            relation.name()
        );
    }
}

#[test]
fn a_projection_of_no_declared_column_counts_rows() {
    let bound = bound("udp");
    let scan = scan("udp");
    let columns = |projected: &[usize]| scan.projection(&bound, projected).unwrap().columns;
    assert!(columns(&[usize::MAX]).is_empty());
    assert!(columns(&[]).is_empty());
    // A mix of declared and undeclared columns is refused, not guessed at.
    let error = scan.projection(&bound, &[0, usize::MAX]).unwrap_err();
    assert_eq!(error.code, DuckDBError::QueryNotImplemented);
    assert!(error.message.starts_with("read_udp: "), "{}", error.message);
}

#[test]
fn the_filename_column_is_taken_out_of_the_projection() {
    for relation in ["udp", "udp_packets"] {
        let mut bound = bound(relation);
        let scan = scan(relation);
        let filename = bound.columns;
        // Not declared: its index is no column of the function.
        assert_eq!(
            scan.projection(&bound, &[filename]).unwrap(),
            Projection {
                columns: Vec::new(),
                filename: None
            }
        );
        assert!(scan.projection(&bound, &[0, filename]).is_err());

        bound.filename = Some(filename);
        let projection = |projected: &[usize]| scan.projection(&bound, projected).unwrap();
        // Wherever it is among the projected columns, the others keep their order.
        for (projected, columns, vector) in [
            (&[0, 1, filename][..], vec![0, 1], Some(2)),
            (&[filename, 1, 0][..], vec![1, 0], Some(0)),
            (&[1, filename, 0][..], vec![1, 0], Some(1)),
            (&[1, 0][..], vec![1, 0], None),
            // Alone, or with DuckDB's row identifier: the rows are counted.
            (&[filename][..], vec![], Some(0)),
            (&[usize::MAX, filename][..], vec![], Some(1)),
            (&[usize::MAX][..], vec![], None),
        ] {
            assert_eq!(
                projection(projected),
                Projection {
                    columns,
                    filename: vector
                },
                "{relation} {projected:?}"
            );
        }
        assert!(scan.projection(&bound, &[0, usize::MAX, filename]).is_err());
    }
}

#[test]
fn no_relation_has_a_column_called_filename() {
    for relation in relation::relations() {
        for column in relation.columns() {
            assert_ne!(column.name, FILENAME, "{}", relation.name());
        }
    }
}

#[test]
fn a_pattern_is_an_entry_with_a_wildcard() {
    for pattern in ["*.pcap", "a?.pcap", "day[12].pcap", "captures/**/x.pcap"] {
        assert!(has_wildcard(pattern), "{pattern}");
    }
    for path in ["a.pcap", "/var/captures/a b.pcap.gz", "s3://bucket/a.pcap"] {
        assert!(!has_wildcard(path), "{path}");
    }
}

#[test]
fn every_scan_table_gets_a_function_and_none_is_called_pcap() {
    // `read_pcap` is the generic function; a table of that name would collide with it.
    assert!(Relation::find("pcap").is_none());
    assert!(relation::scan_table(DEFAULT_PROTOCOL).is_some());
    let mut names = std::collections::HashSet::new();
    for relation in relation::relations() {
        assert!(names.insert(relation.name()), "{} twice", relation.name());
        let function = PcapScan {
            name: String::new(),
            relation: Some(relation),
        };
        assert_eq!(function.positions().strict, 1);
        assert_eq!(function.positions().filename, 2);
    }
    // The tables, then the views.
    assert_eq!(
        names.len(),
        relation::scan_tables().count() + relation::views().len()
    );
    assert!(names.contains("tcp") && names.contains("tcp_packets"));
}

#[test]
fn the_row_estimate_grows_with_the_file_and_is_never_zero() {
    let header = |compression| StreamHeader {
        compression,
        format: pcapsql_core::io::PcapFormat::LegacyLeMicro,
        link_type: 1,
        snaplen: 65535,
        header_len: 24,
    };
    let plain = header(Compression::None);
    assert_eq!(estimated_rows(0, &plain), 1);
    assert_eq!(estimated_rows(24, &plain), 1);
    assert_eq!(estimated_rows(512 * 1000, &plain), 1000);
    assert_eq!(estimated_rows(512 * 1000, &header(Compression::Gzip)), 4000);
    assert!(estimated_rows(u64::MAX, &header(Compression::Gzip)) > 0);
}
