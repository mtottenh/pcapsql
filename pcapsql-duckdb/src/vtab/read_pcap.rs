//! `read_pcap(file, protocol)` table function.
//!
//! Returns rows from a PCAP file for a specific protocol.
//!
//! ## Usage
//!
//! ```sql
//! -- Read TCP packets from a PCAP file
//! SELECT * FROM read_pcap('capture.pcap', 'tcp') LIMIT 100;
//!
//! -- Read DNS packets
//! SELECT * FROM read_pcap('capture.pcap', 'dns');
//!
//! -- Read all frames (raw packet metadata)
//! SELECT * FROM read_pcap('capture.pcap', 'frames');
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
    default_registry, parse_packet, FilePacketReader, FilePacketSource, PacketReader,
    PacketSource, ParseResult, Protocol, ProtocolRegistry,
};

use crate::duckdb_schema::to_duckdb_type;
use crate::error::DuckDbError;

use super::batch_builder;

/// Maximum rows per output chunk.
const BATCH_SIZE: usize = 2048;

/// Bind data: parameters parsed during bind phase.
///
/// This is shared across threads and should be considered read-only.
pub struct ReadPcapBindData {
    /// Path to the PCAP file.
    pub file_path: String,
    /// Protocol name to extract (e.g., "tcp", "dns", "frames").
    pub protocol_name: String,
    /// Column names in order.
    pub column_names: Vec<String>,
    /// Mapping from field name to column index.
    pub field_indices: HashMap<String, usize>,
}

// Safety: BindData is read-only after construction
unsafe impl Send for ReadPcapBindData {}
unsafe impl Sync for ReadPcapBindData {}

/// Init data: per-invocation state.
///
/// This is shared across threads when parallel execution is enabled.
pub struct ReadPcapInitData {
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
unsafe impl Send for ReadPcapInitData {}
unsafe impl Sync for ReadPcapInitData {}

/// The read_pcap virtual table.
pub struct ReadPcapVTab;

impl VTab for ReadPcapVTab {
    type InitData = ReadPcapInitData;
    type BindData = ReadPcapBindData;

    fn bind(bind: &BindInfo) -> DuckResult<Self::BindData, Box<dyn std::error::Error>> {
        // Get parameters: file path and protocol name
        let file_path = bind.get_parameter(0).to_string();
        let protocol_name = bind.get_parameter(1).to_string().to_lowercase();

        // Get protocol schema
        let registry = default_registry();
        let mut column_names = Vec::new();
        let mut field_indices = HashMap::new();

        if protocol_name == "frames" {
            // Special case: frames table with raw packet metadata
            let frame_columns = [
                ("frame_number", LogicalTypeId::UBigint),
                ("timestamp", LogicalTypeId::Bigint),
                ("length", LogicalTypeId::UInteger),
                ("original_length", LogicalTypeId::UInteger),
                ("link_type", LogicalTypeId::USmallint),
            ];

            for (idx, (name, type_id)) in frame_columns.into_iter().enumerate() {
                bind.add_result_column(name, LogicalTypeHandle::from(type_id));
                column_names.push(name.to_string());
                field_indices.insert(name.to_string(), idx);
            }
        } else {
            // Look up protocol in registry
            let protocol = registry.get_parser(&protocol_name).ok_or_else(|| {
                let available: Vec<_> = registry.all_parsers().map(|p| p.name()).collect();
                DuckDbError::InvalidParameter(format!(
                    "Unknown protocol: '{}'. Available: {:?}",
                    protocol_name, available
                ))
            })?;

            // Add frame_number column first
            bind.add_result_column("frame_number", LogicalTypeHandle::from(LogicalTypeId::UBigint));
            column_names.push("frame_number".to_string());
            field_indices.insert("frame_number".to_string(), 0);

            // Add protocol-specific columns
            for (idx, fd) in protocol.schema_fields().iter().enumerate() {
                bind.add_result_column(fd.name, to_duckdb_type(&fd.kind));
                column_names.push(fd.name.to_string());
                field_indices.insert(fd.name.to_string(), idx + 1);
            }
        }

        Ok(ReadPcapBindData {
            file_path,
            protocol_name,
            column_names,
            field_indices,
        })
    }

    fn init(init: &InitInfo) -> DuckResult<Self::InitData, Box<dyn std::error::Error>> {
        let bind_data = unsafe { &*init.get_bind_data::<ReadPcapBindData>() };

        // Open the PCAP file
        let source = FilePacketSource::open(&bind_data.file_path)
            .map_err(|e| DuckDbError::Extension(format!("Failed to open PCAP file: {}", e)))?;

        // Create reader
        let reader = source.reader(None).map_err(|e| {
            DuckDbError::Extension(format!("Failed to create reader: {}", e))
        })?;

        Ok(ReadPcapInitData {
            reader: Mutex::new(Some(reader)),
            registry: Arc::new(default_registry()),
            frame_number: AtomicU64::new(0),
            done: AtomicBool::new(false),
        })
    }

    fn func(
        func: &TableFunctionInfo<Self>,
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

            if bind_data.protocol_name == "frames" {
                // Output frame metadata
                output_frame_row(
                    output,
                    row_count,
                    frame_num,
                    packet.timestamp_us,
                    packet.captured_len,
                    packet.original_len,
                    packet.link_type,
                );
                row_count += 1;
            } else {
                // Parse and check if this packet contains our protocol
                let results = parse_packet(
                    &init_data.registry,
                    packet.link_type,
                    packet.data,
                );

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
            }

            if row_count >= BATCH_SIZE {
                // Signal to stop processing this batch
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

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        Some(vec![
            LogicalTypeHandle::from(LogicalTypeId::Varchar), // file_path
            LogicalTypeHandle::from(LogicalTypeId::Varchar), // protocol_name
        ])
    }
}

/// Output a frame metadata row.
fn output_frame_row(
    output: &mut DataChunkHandle,
    row_idx: usize,
    frame_number: u64,
    timestamp_us: i64,
    captured_len: u32,
    original_len: u32,
    link_type: u16,
) {
    // frame_number (column 0)
    {
        let mut vector = output.flat_vector(0);
        batch_builder::insert_u64(&mut vector, row_idx, frame_number);
    }
    // timestamp (column 1)
    {
        let mut vector = output.flat_vector(1);
        batch_builder::insert_i64(&mut vector, row_idx, timestamp_us);
    }
    // length (column 2)
    {
        let mut vector = output.flat_vector(2);
        batch_builder::insert_u32(&mut vector, row_idx, captured_len);
    }
    // original_length (column 3)
    {
        let mut vector = output.flat_vector(3);
        batch_builder::insert_u32(&mut vector, row_idx, original_len);
    }
    // link_type (column 4)
    {
        let mut vector = output.flat_vector(4);
        batch_builder::insert_u16(&mut vector, row_idx, link_type);
    }
}

/// Output a parsed protocol row.
fn output_parsed_row(
    output: &mut DataChunkHandle,
    row_idx: usize,
    frame_number: u64,
    parsed: &ParseResult<'_>,
    field_indices: &HashMap<String, usize>,
) {
    use pcapsql_core::FieldValue;

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

        // Schema field names are like "arp.hardware_type" but parsed data uses "hardware_type"
        // Strip the protocol prefix to get the actual field name used in ParseResult
        let lookup_name = field_name
            .split('.')
            .last()
            .unwrap_or(field_name.as_str());

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

/// Register the read_pcap table function.
pub fn register(con: &duckdb::Connection) -> DuckResult<(), Box<dyn std::error::Error>> {
    con.register_table_function::<ReadPcapVTab>("read_pcap")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_data_creation() {
        // Test that protocol lookup works
        let registry = default_registry();
        assert!(registry.get_parser("tcp").is_some());
        assert!(registry.get_parser("dns").is_some());
        assert!(registry.get_parser("ethernet").is_some());
    }
}
