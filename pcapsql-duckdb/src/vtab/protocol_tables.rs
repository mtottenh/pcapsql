//! Protocol-specific table functions.
//!
//! Provides `read_tcp()`, `read_dns()`, etc. for each supported protocol.
//!
//! These are convenience wrappers around `read_pcap(file, 'protocol')`.
//!
//! ## Usage
//!
//! ```sql
//! -- Instead of:
//! SELECT * FROM read_pcap('capture.pcap', 'tcp');
//!
//! -- You can use:
//! SELECT * FROM read_tcp('capture.pcap');
//! ```

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use duckdb::core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId};
use duckdb::vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab};
use duckdb::Result as DuckResult;
use parking_lot::Mutex;

use pcapsql_core::{
    default_registry, parse_packet, FieldValue, FilePacketReader, FilePacketSource, PacketReader,
    PacketSource, Protocol, ProtocolRegistry,
};

use crate::duckdb_schema::to_duckdb_type;
use crate::error::DuckDbError;

use super::batch_builder;

/// Maximum rows per output chunk.
const BATCH_SIZE: usize = 2048;

/// Bind data for protocol-specific VTabs.
pub struct ProtocolBindData {
    /// Path to the PCAP file.
    pub file_path: String,
    /// Protocol name (fixed for each VTab type).
    pub protocol_name: &'static str,
    /// Mapping from field name to column index.
    pub field_indices: HashMap<String, usize>,
}

// Safety: BindData is read-only after construction
unsafe impl Send for ProtocolBindData {}
unsafe impl Sync for ProtocolBindData {}

/// Init data for protocol-specific VTabs.
pub struct ProtocolInitData {
    /// Packet reader (wrapped for thread safety).
    reader: Mutex<Option<FilePacketReader>>,
    /// Protocol registry.
    registry: Arc<ProtocolRegistry>,
    /// Current frame number.
    frame_number: AtomicU64,
    /// Whether we've finished reading.
    done: AtomicBool,
}

// Safety: InitData uses thread-safe primitives
unsafe impl Send for ProtocolInitData {}
unsafe impl Sync for ProtocolInitData {}

/// Shared bind implementation for protocol VTabs.
fn bind_protocol(
    bind: &BindInfo,
    protocol_name: &'static str,
) -> DuckResult<ProtocolBindData, Box<dyn std::error::Error>> {
    let file_path = bind.get_parameter(0).to_string();

    let registry = default_registry();
    let proto = registry.get_parser(protocol_name).ok_or_else(|| {
        DuckDbError::InvalidParameter(format!("Unknown protocol: {}", protocol_name))
    })?;

    // Add frame_number column first
    bind.add_result_column("frame_number", LogicalTypeHandle::from(LogicalTypeId::UBigint));

    let mut field_indices = HashMap::new();
    field_indices.insert("frame_number".to_string(), 0);

    // Add protocol-specific columns
    for (idx, fd) in proto.schema_fields().iter().enumerate() {
        bind.add_result_column(fd.name, to_duckdb_type(&fd.kind));
        field_indices.insert(fd.name.to_string(), idx + 1);
    }

    Ok(ProtocolBindData {
        file_path,
        protocol_name,
        field_indices,
    })
}

/// Shared init implementation for protocol VTabs.
fn init_protocol(init: &InitInfo) -> DuckResult<ProtocolInitData, Box<dyn std::error::Error>> {
    let bind_data = unsafe { &*init.get_bind_data::<ProtocolBindData>() };

    // Open the PCAP file
    let source = FilePacketSource::open(&bind_data.file_path)
        .map_err(|e| DuckDbError::Extension(format!("Failed to open PCAP file: {}", e)))?;

    // Create reader
    let reader = source.reader(None).map_err(|e| {
        DuckDbError::Extension(format!("Failed to create reader: {}", e))
    })?;

    Ok(ProtocolInitData {
        reader: Mutex::new(Some(reader)),
        registry: Arc::new(default_registry()),
        frame_number: AtomicU64::new(0),
        done: AtomicBool::new(false),
    })
}

/// Shared func implementation for protocol VTabs.
fn func_protocol<T: VTab<InitData = ProtocolInitData, BindData = ProtocolBindData>>(
    func: &TableFunctionInfo<T>,
    output: &mut DataChunkHandle,
) -> DuckResult<(), Box<dyn std::error::Error>> {
    let init_data = func.get_init_data();
    let bind_data = func.get_bind_data();

    // Check if we're done
    if init_data.done.load(Ordering::Relaxed) {
        output.set_len(0);
        return Ok(());
    }

    let mut reader_guard = init_data.reader.lock();
    let reader = match reader_guard.as_mut() {
        Some(r) => r,
        None => {
            output.set_len(0);
            return Ok(());
        }
    };

    let mut row_count = 0;

    // Process packets until we fill a batch or run out
    let result = reader.process_packets(BATCH_SIZE, |packet| {
        let frame_num = init_data.frame_number.fetch_add(1, Ordering::Relaxed) + 1;

        // Parse and check if this packet contains our protocol
        let results = parse_packet(&init_data.registry, packet.link_type, packet.data);

        for (proto_name, parsed) in &results {
            if *proto_name == bind_data.protocol_name {
                output_parsed_row(
                    output,
                    row_count,
                    frame_num,
                    parsed,
                    &bind_data.field_indices,
                );
                row_count += 1;
                break;
            }
        }

        if row_count >= BATCH_SIZE {
            return Err(pcapsql_core::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "batch full",
            )));
        }

        Ok(())
    });

    // Check if we've reached end of file
    match result {
        Ok(count) if count == 0 => {
            init_data.done.store(true, Ordering::Relaxed);
        }
        Err(e) if e.to_string().contains("batch full") => {
            // Normal batch completion - not an error
        }
        Err(_) => {
            // EOF or actual error
            init_data.done.store(true, Ordering::Relaxed);
        }
        _ => {}
    }

    output.set_len(row_count);
    Ok(())
}

/// Output a parsed protocol row.
fn output_parsed_row(
    output: &mut DataChunkHandle,
    row_idx: usize,
    frame_number: u64,
    parsed: &pcapsql_core::ParseResult<'_>,
    field_indices: &HashMap<String, usize>,
) {
    // frame_number is always column 0
    {
        let mut vector = output.flat_vector(0);
        batch_builder::insert_u64(&mut vector, row_idx, frame_number);
    }

    // Fill other columns from parsed data
    for (field_name, col_idx) in field_indices {
        if field_name == "frame_number" {
            continue;
        }

        // Schema field names may have prefix (e.g., "tcp.src_port")
        // but parsed data uses short names (e.g., "src_port")
        let lookup_name = field_name.split('.').last().unwrap_or(field_name.as_str());

        let mut vector = output.flat_vector(*col_idx);
        if let Some(value) = parsed.get(lookup_name) {
            match value {
                FieldValue::Null => {
                    vector.set_null(row_idx);
                }
                FieldValue::Bool(v) => {
                    let slice = vector.as_mut_slice::<bool>();
                    slice[row_idx] = *v;
                }
                FieldValue::UInt8(v) => {
                    let slice = vector.as_mut_slice::<u8>();
                    slice[row_idx] = *v;
                }
                FieldValue::UInt16(v) => {
                    let slice = vector.as_mut_slice::<u16>();
                    slice[row_idx] = *v;
                }
                FieldValue::UInt32(v) => {
                    let slice = vector.as_mut_slice::<u32>();
                    slice[row_idx] = *v;
                }
                FieldValue::UInt64(v) => {
                    let slice = vector.as_mut_slice::<u64>();
                    slice[row_idx] = *v;
                }
                FieldValue::Int64(v) => {
                    let slice = vector.as_mut_slice::<i64>();
                    slice[row_idx] = *v;
                }
                FieldValue::Str(v) => {
                    if let Ok(cstr) = CString::new(*v) {
                        vector.insert(row_idx, cstr);
                    } else {
                        vector.set_null(row_idx);
                    }
                }
                FieldValue::OwnedString(v) => {
                    if let Ok(cstr) = CString::new(v.as_str()) {
                        vector.insert(row_idx, cstr);
                    } else {
                        vector.set_null(row_idx);
                    }
                }
                FieldValue::Bytes(v) => {
                    vector.insert(row_idx, *v);
                }
                FieldValue::OwnedBytes(v) => {
                    vector.insert(row_idx, v.as_slice());
                }
                FieldValue::MacAddr(v) => {
                    vector.insert(row_idx, v.as_slice());
                }
                FieldValue::IpAddr(addr) => {
                    if let Ok(cstr) = CString::new(addr.to_string()) {
                        vector.insert(row_idx, cstr);
                    } else {
                        vector.set_null(row_idx);
                    }
                }
            }
        } else {
            vector.set_null(row_idx);
        }
    }
}

/// Macro to generate a protocol-specific VTab.
///
/// This creates a struct like `ReadTcpVTab` that only reads packets of that protocol.
macro_rules! define_protocol_vtab {
    ($vtab_name:ident, $protocol:expr) => {
        #[doc = concat!("Table function for reading ", $protocol, " packets.")]
        pub struct $vtab_name;

        impl VTab for $vtab_name {
            type InitData = ProtocolInitData;
            type BindData = ProtocolBindData;

            fn bind(bind: &BindInfo) -> DuckResult<Self::BindData, Box<dyn std::error::Error>> {
                bind_protocol(bind, $protocol)
            }

            fn init(init: &InitInfo) -> DuckResult<Self::InitData, Box<dyn std::error::Error>> {
                init_protocol(init)
            }

            fn func(
                func: &TableFunctionInfo<Self>,
                output: &mut DataChunkHandle,
            ) -> DuckResult<(), Box<dyn std::error::Error>> {
                func_protocol::<Self>(func, output)
            }

            fn parameters() -> Option<Vec<LogicalTypeHandle>> {
                Some(vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)]) // file_path only
            }
        }
    };
}

// Define VTabs for all protocols
// Layer 2
define_protocol_vtab!(ReadEthernetVTab, "ethernet");
define_protocol_vtab!(ReadVlanVTab, "vlan");
define_protocol_vtab!(ReadArpVTab, "arp");
define_protocol_vtab!(ReadMplsVTab, "mpls");

// Layer 3
define_protocol_vtab!(ReadIpv4VTab, "ipv4");
define_protocol_vtab!(ReadIpv6VTab, "ipv6");
define_protocol_vtab!(ReadIcmpVTab, "icmp");
define_protocol_vtab!(ReadIcmpv6VTab, "icmpv6");

// Layer 4
define_protocol_vtab!(ReadTcpVTab, "tcp");
define_protocol_vtab!(ReadUdpVTab, "udp");

// Application layer
define_protocol_vtab!(ReadDnsVTab, "dns");
define_protocol_vtab!(ReadDhcpVTab, "dhcp");
define_protocol_vtab!(ReadNtpVTab, "ntp");
define_protocol_vtab!(ReadTlsVTab, "tls");
define_protocol_vtab!(ReadSshVTab, "ssh");
define_protocol_vtab!(ReadQuicVTab, "quic");

// Tunneling protocols
define_protocol_vtab!(ReadVxlanVTab, "vxlan");
define_protocol_vtab!(ReadGreVTab, "gre");
define_protocol_vtab!(ReadGtpVTab, "gtp");
define_protocol_vtab!(ReadIpsecVTab, "ipsec");

// Routing protocols
define_protocol_vtab!(ReadBgpVTab, "bgp");
define_protocol_vtab!(ReadOspfVTab, "ospf");

/// Register all protocol-specific table functions.
pub fn register(con: &duckdb::Connection) -> DuckResult<(), Box<dyn std::error::Error>> {
    // Layer 2
    con.register_table_function::<ReadEthernetVTab>("read_ethernet")?;
    con.register_table_function::<ReadVlanVTab>("read_vlan")?;
    con.register_table_function::<ReadArpVTab>("read_arp")?;
    con.register_table_function::<ReadMplsVTab>("read_mpls")?;

    // Layer 3
    con.register_table_function::<ReadIpv4VTab>("read_ipv4")?;
    con.register_table_function::<ReadIpv6VTab>("read_ipv6")?;
    con.register_table_function::<ReadIcmpVTab>("read_icmp")?;
    con.register_table_function::<ReadIcmpv6VTab>("read_icmpv6")?;

    // Layer 4
    con.register_table_function::<ReadTcpVTab>("read_tcp")?;
    con.register_table_function::<ReadUdpVTab>("read_udp")?;

    // Application layer
    con.register_table_function::<ReadDnsVTab>("read_dns")?;
    con.register_table_function::<ReadDhcpVTab>("read_dhcp")?;
    con.register_table_function::<ReadNtpVTab>("read_ntp")?;
    con.register_table_function::<ReadTlsVTab>("read_tls")?;
    con.register_table_function::<ReadSshVTab>("read_ssh")?;
    con.register_table_function::<ReadQuicVTab>("read_quic")?;

    // Tunneling protocols
    con.register_table_function::<ReadVxlanVTab>("read_vxlan")?;
    con.register_table_function::<ReadGreVTab>("read_gre")?;
    con.register_table_function::<ReadGtpVTab>("read_gtp")?;
    con.register_table_function::<ReadIpsecVTab>("read_ipsec")?;

    // Routing protocols
    con.register_table_function::<ReadBgpVTab>("read_bgp")?;
    con.register_table_function::<ReadOspfVTab>("read_ospf")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_names() {
        // Verify all protocols exist in the registry
        let registry = default_registry();
        let protocols = [
            "ethernet", "vlan", "arp", "mpls", "ipv4", "ipv6", "icmp", "icmpv6", "tcp", "udp",
            "dns", "dhcp", "ntp", "tls", "ssh", "quic", "vxlan", "gre", "gtp", "ipsec", "bgp",
            "ospf",
        ];

        for proto in protocols {
            assert!(
                registry.get_parser(proto).is_some(),
                "Protocol '{}' should exist in registry",
                proto
            );
        }
    }
}
