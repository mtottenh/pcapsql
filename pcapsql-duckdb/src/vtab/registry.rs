//! Protocol registry utilities for DuckDB.
//!
//! Provides metadata about available protocols and their schemas.
//!
//! ## Available Functions
//!
//! - `pcap_protocols()` - List all supported protocols
//! - `pcap_schema(protocol)` - Show schema for a specific protocol

use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};

use duckdb::core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId};
use duckdb::vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab};
use duckdb::Result as DuckResult;

use pcapsql_core::{default_registry, schema::DataKind, Protocol};

use crate::error::DuckDbError;

/// Maximum rows per output chunk.
const BATCH_SIZE: usize = 2048;

/// Get a description for a protocol by name.
fn protocol_description(name: &str) -> &'static str {
    match name {
        "ethernet" => "Ethernet II frames (Layer 2)",
        "vlan" => "IEEE 802.1Q VLAN tags",
        "arp" => "Address Resolution Protocol",
        "mpls" => "Multiprotocol Label Switching",
        "ipv4" => "Internet Protocol version 4",
        "ipv6" => "Internet Protocol version 6",
        "tcp" => "Transmission Control Protocol",
        "udp" => "User Datagram Protocol",
        "icmp" => "Internet Control Message Protocol",
        "icmpv6" => "ICMPv6 for IPv6",
        "dns" => "Domain Name System",
        "dhcp" => "Dynamic Host Configuration Protocol",
        "ntp" => "Network Time Protocol",
        "tls" => "Transport Layer Security",
        "ssh" => "Secure Shell Protocol",
        "quic" => "QUIC Transport Protocol",
        "vxlan" => "Virtual Extensible LAN",
        "gre" => "Generic Routing Encapsulation",
        "gtp" => "GPRS Tunneling Protocol",
        "ipsec" => "IP Security (ESP/AH)",
        "bgp" => "Border Gateway Protocol",
        "ospf" => "Open Shortest Path First",
        "frames" => "Raw frame metadata (timestamp, length, etc.)",
        _ => "Protocol parser",
    }
}

/// Information about a single protocol for the protocols table.
#[derive(Debug, Clone)]
struct ProtocolInfo {
    name: String,
    description: String,
    field_count: usize,
}

/// Bind data for pcap_protocols().
pub struct ProtocolsBindData {
    protocols: Vec<ProtocolInfo>,
}

// Safety: BindData is read-only after construction
unsafe impl Send for ProtocolsBindData {}
unsafe impl Sync for ProtocolsBindData {}

/// Init data for pcap_protocols().
pub struct ProtocolsInitData {
    current_row: AtomicUsize,
}

// Safety: InitData uses thread-safe primitives
unsafe impl Send for ProtocolsInitData {}
unsafe impl Sync for ProtocolsInitData {}

/// Table function that lists all supported protocols.
///
/// Usage: `SELECT * FROM pcap_protocols();`
pub struct PcapProtocolsVTab;

impl VTab for PcapProtocolsVTab {
    type InitData = ProtocolsInitData;
    type BindData = ProtocolsBindData;

    fn bind(bind: &BindInfo) -> DuckResult<Self::BindData, Box<dyn std::error::Error>> {
        // Define output columns
        bind.add_result_column("name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column(
            "description",
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        );
        bind.add_result_column(
            "field_count",
            LogicalTypeHandle::from(LogicalTypeId::UInteger),
        );

        // Collect protocol information
        let registry = default_registry();
        let mut protocols: Vec<ProtocolInfo> = registry
            .all_parsers()
            .map(|proto| ProtocolInfo {
                name: proto.name().to_string(),
                description: protocol_description(proto.name()).to_string(),
                field_count: proto.schema_fields().len(),
            })
            .collect();

        // Add "frames" pseudo-protocol
        protocols.push(ProtocolInfo {
            name: "frames".to_string(),
            description: protocol_description("frames").to_string(),
            field_count: 5, // frame_number, timestamp, length, original_length, link_type
        });

        // Sort by name
        protocols.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(ProtocolsBindData { protocols })
    }

    fn init(_: &InitInfo) -> DuckResult<Self::InitData, Box<dyn std::error::Error>> {
        Ok(ProtocolsInitData {
            current_row: AtomicUsize::new(0),
        })
    }

    fn func(
        func: &TableFunctionInfo<Self>,
        output: &mut DataChunkHandle,
    ) -> DuckResult<(), Box<dyn std::error::Error>> {
        let init_data = func.get_init_data();
        let bind_data = func.get_bind_data();

        let start = init_data.current_row.load(Ordering::Relaxed);
        let remaining = bind_data.protocols.len().saturating_sub(start);
        let batch_size = remaining.min(BATCH_SIZE);

        if batch_size == 0 {
            output.set_len(0);
            return Ok(());
        }

        for i in 0..batch_size {
            let proto = &bind_data.protocols[start + i];

            // name (column 0)
            {
                let vector = output.flat_vector(0);
                if let Ok(name) = CString::new(proto.name.as_str()) {
                    vector.insert(i, name);
                }
            }

            // description (column 1)
            {
                let vector = output.flat_vector(1);
                if let Ok(desc) = CString::new(proto.description.as_str()) {
                    vector.insert(i, desc);
                }
            }

            // field_count (column 2)
            {
                let mut vector = output.flat_vector(2);
                let slice = vector.as_mut_slice::<u32>();
                slice[i] = proto.field_count as u32;
            }
        }

        // Update position
        init_data
            .current_row
            .store(start + batch_size, Ordering::Relaxed);
        output.set_len(batch_size);

        Ok(())
    }

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        None
    }
}

/// Field information for schema table.
#[derive(Debug, Clone)]
struct FieldInfo {
    name: String,
    type_name: String,
    nullable: bool,
}

/// Bind data for pcap_schema(protocol).
pub struct SchemaBindData {
    fields: Vec<FieldInfo>,
}

// Safety: BindData is read-only after construction
unsafe impl Send for SchemaBindData {}
unsafe impl Sync for SchemaBindData {}

/// Init data for pcap_schema().
pub struct SchemaInitData {
    current_row: AtomicUsize,
}

// Safety: InitData uses thread-safe primitives
unsafe impl Send for SchemaInitData {}
unsafe impl Sync for SchemaInitData {}

/// Table function that shows the schema for a protocol.
///
/// Usage: `SELECT * FROM pcap_schema('tcp');`
pub struct PcapSchemaVTab;

impl VTab for PcapSchemaVTab {
    type InitData = SchemaInitData;
    type BindData = SchemaBindData;

    fn bind(bind: &BindInfo) -> DuckResult<Self::BindData, Box<dyn std::error::Error>> {
        let protocol_name = bind.get_parameter(0).to_string().to_lowercase();

        // Define output columns
        bind.add_result_column(
            "column_name",
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        );
        bind.add_result_column(
            "column_type",
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        );
        bind.add_result_column("nullable", LogicalTypeHandle::from(LogicalTypeId::Boolean));

        let registry = default_registry();
        let mut fields = Vec::new();

        // Always add frame_number first
        fields.push(FieldInfo {
            name: "frame_number".to_string(),
            type_name: "UBIGINT".to_string(),
            nullable: false,
        });

        if protocol_name == "frames" {
            fields.extend([
                FieldInfo {
                    name: "timestamp".to_string(),
                    type_name: "BIGINT".to_string(),
                    nullable: false,
                },
                FieldInfo {
                    name: "length".to_string(),
                    type_name: "UINTEGER".to_string(),
                    nullable: false,
                },
                FieldInfo {
                    name: "original_length".to_string(),
                    type_name: "UINTEGER".to_string(),
                    nullable: false,
                },
                FieldInfo {
                    name: "link_type".to_string(),
                    type_name: "USMALLINT".to_string(),
                    nullable: false,
                },
            ]);
        } else if let Some(proto) = registry.get_parser(&protocol_name) {
            for fd in proto.schema_fields() {
                fields.push(FieldInfo {
                    name: fd.name.to_string(),
                    type_name: duckdb_type_name(&fd.kind),
                    nullable: fd.nullable,
                });
            }
        } else {
            return Err(Box::new(DuckDbError::InvalidParameter(format!(
                "Unknown protocol: '{protocol_name}'. Use pcap_protocols() to list available protocols."
            ))));
        }

        Ok(SchemaBindData { fields })
    }

    fn init(_: &InitInfo) -> DuckResult<Self::InitData, Box<dyn std::error::Error>> {
        Ok(SchemaInitData {
            current_row: AtomicUsize::new(0),
        })
    }

    fn func(
        func: &TableFunctionInfo<Self>,
        output: &mut DataChunkHandle,
    ) -> DuckResult<(), Box<dyn std::error::Error>> {
        let init_data = func.get_init_data();
        let bind_data = func.get_bind_data();

        let start = init_data.current_row.load(Ordering::Relaxed);
        let remaining = bind_data.fields.len().saturating_sub(start);
        let batch_size = remaining.min(BATCH_SIZE);

        if batch_size == 0 {
            output.set_len(0);
            return Ok(());
        }

        for i in 0..batch_size {
            let field = &bind_data.fields[start + i];

            // column_name (column 0)
            {
                let vector = output.flat_vector(0);
                if let Ok(name) = CString::new(field.name.as_str()) {
                    vector.insert(i, name);
                }
            }

            // column_type (column 1)
            {
                let vector = output.flat_vector(1);
                if let Ok(type_name) = CString::new(field.type_name.as_str()) {
                    vector.insert(i, type_name);
                }
            }

            // nullable (column 2)
            {
                let mut vector = output.flat_vector(2);
                let slice = vector.as_mut_slice::<bool>();
                slice[i] = field.nullable;
            }
        }

        // Update position
        init_data
            .current_row
            .store(start + batch_size, Ordering::Relaxed);
        output.set_len(batch_size);

        Ok(())
    }

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        Some(vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)])
    }
}

/// Convert DataKind to DuckDB type name string.
fn duckdb_type_name(kind: &DataKind) -> String {
    match kind {
        DataKind::Bool => "BOOLEAN".to_string(),
        DataKind::UInt8 => "UTINYINT".to_string(),
        DataKind::UInt16 => "USMALLINT".to_string(),
        DataKind::UInt32 => "UINTEGER".to_string(),
        DataKind::UInt64 => "UBIGINT".to_string(),
        DataKind::Int64 => "BIGINT".to_string(),
        DataKind::Float64 => "DOUBLE".to_string(),
        DataKind::String => "VARCHAR".to_string(),
        DataKind::Binary => "BLOB".to_string(),
        DataKind::FixedBinary(n) => format!("BLOB[{n}]"),
        DataKind::TimestampMicros => "BIGINT".to_string(), // Stored as microseconds
        DataKind::List(inner) => format!("{}[]", duckdb_type_name(inner)),
    }
}

/// Register registry table functions.
pub fn register(con: &duckdb::Connection) -> DuckResult<(), Box<dyn std::error::Error>> {
    con.register_table_function::<PcapProtocolsVTab>("pcap_protocols")?;
    con.register_table_function::<PcapSchemaVTab>("pcap_schema")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duckdb_type_names() {
        assert_eq!(duckdb_type_name(&DataKind::Bool), "BOOLEAN");
        assert_eq!(duckdb_type_name(&DataKind::UInt32), "UINTEGER");
        assert_eq!(duckdb_type_name(&DataKind::String), "VARCHAR");
        assert_eq!(duckdb_type_name(&DataKind::Binary), "BLOB");
        assert_eq!(duckdb_type_name(&DataKind::FixedBinary(6)), "BLOB[6]");
    }

    #[test]
    fn test_protocol_descriptions() {
        assert_eq!(protocol_description("tcp"), "Transmission Control Protocol");
        assert_eq!(protocol_description("dns"), "Domain Name System");
        assert_eq!(
            protocol_description("frames"),
            "Raw frame metadata (timestamp, length, etc.)"
        );
    }
}
