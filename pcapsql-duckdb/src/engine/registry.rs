//! `pcap_protocols()`: the tables the extension can read.

use std::sync::atomic::{AtomicUsize, Ordering};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::Context,
    data_chunk::DataChunkRef,
    extension::Extension,
    signature::SignatureBuilder,
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionCallbacks},
    DuckDBType, Result,
};
use pcapsql_core::{default_registry, Protocol};

use super::guard;

pub(super) fn register(extension: &Extension) -> Result<()> {
    guard::table_function("pcap_protocols", SignatureBuilder::new(), PcapProtocols)
        .register(extension)
}

/// One row of `pcap_protocols()`.
#[derive(Debug, PartialEq, Eq)]
struct ProtocolRow {
    name: &'static str,
    description: &'static str,
    field_count: u32,
}

/// The protocols of core's default registry plus the `frames` pseudo-protocol, sorted by name.
fn protocol_rows() -> Vec<ProtocolRow> {
    let mut rows: Vec<ProtocolRow> = default_registry()
        .all_parsers()
        .map(|parser| ProtocolRow {
            name: parser.name(),
            description: protocol_description(parser.name()),
            field_count: parser.schema_fields().len() as u32,
        })
        .collect();
    rows.push(ProtocolRow {
        name: "frames",
        description: protocol_description("frames"),
        // frame_number, timestamp, length, original_length, link_type
        field_count: 5,
    });
    rows.sort_by_key(|row| row.name);
    rows
}

fn protocol_description(name: &str) -> &'static str {
    match name {
        "ethernet" => "Ethernet II frames (Layer 2)",
        "linux_sll" => "Linux cooked capture v1 (tcpdump -i any)",
        "sll2" => "Linux cooked capture v2",
        "netlink" => "Linux netlink messages (nlmon captures)",
        "rtnetlink" => "Linux rtnetlink (route/link/address messages)",
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
        "http" => "HTTP/1.x request and status lines with headers (per packet)",
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

struct PcapProtocols;

impl TableFunctionCallbacks for PcapProtocols {
    type BindData = Vec<ProtocolRow>;
    /// Index of the next row to emit.
    type GlobalState = AtomicUsize;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        _arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Self::BindData> {
        let varchar = String::logical_type(context)?;
        bind_handle.add_result_column("name", &varchar)?;
        bind_handle.add_result_column("description", &varchar)?;
        bind_handle.add_result_column("field_count", &u32::logical_type(context)?)?;

        let rows = protocol_rows();
        bind_handle.set_cardinality(rows.len(), true)?;
        Ok(rows)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bind_data: &Self::BindData,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Self::GlobalState>> {
        Ok(Some(AtomicUsize::new(0)))
    }

    fn exec(
        &self,
        _context: &Context,
        rows: &Self::BindData,
        _local_state: Option<&mut Self::LocalState>,
        next_row: Option<&Self::GlobalState>,
        mut output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let next_row = next_row.expect("init_global_state always returns a state");
        let capacity = output.capacity()?;
        // Claiming a range atomically keeps the rows unique whatever number of threads DuckDB
        // runs the scan on.
        let start = next_row
            .fetch_add(capacity, Ordering::Relaxed)
            .min(rows.len());
        let rows = &rows[start..(start + capacity).min(rows.len())];

        // Projection pushdown is off, so the chunk holds the three declared columns in order.
        // A chunk left at size zero ends the scan.
        let mut names = output.get_vector_at_mut::<String>(0)?;
        names.set_size(rows.len())?;
        let mut writer = names.writer()?;
        for (index, row) in rows.iter().enumerate() {
            writer.set(index, row.name)?;
        }

        let mut descriptions = output.get_vector_at_mut::<String>(1)?;
        descriptions.set_size(rows.len())?;
        let mut writer = descriptions.writer()?;
        for (index, row) in rows.iter().enumerate() {
            writer.set(index, row.description)?;
        }

        let mut field_counts = output.get_vector_at_mut::<u32>(2)?;
        field_counts.set_size(rows.len())?;
        let mut writer = field_counts.writer()?;
        for (index, row) in rows.iter().enumerate() {
            writer.set(index, &row.field_count)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_cover_the_registry_and_frames_in_name_order() {
        let rows = protocol_rows();
        assert_eq!(rows.len(), default_registry().all_parsers().count() + 1);
        assert!(rows.is_sorted_by_key(|row| row.name));

        let frames = rows.iter().find(|row| row.name == "frames").unwrap();
        assert_eq!(frames.field_count, 5);

        let tcp = rows.iter().find(|row| row.name == "tcp").unwrap();
        assert_eq!(tcp.description, "Transmission Control Protocol");
        assert!(tcp.field_count > 0);
    }

    #[test]
    fn test_protocol_descriptions() {
        assert_eq!(protocol_description("tcp"), "Transmission Control Protocol");
        assert_eq!(protocol_description("dns"), "Domain Name System");
        assert_eq!(
            protocol_description("frames"),
            "Raw frame metadata (timestamp, length, etc.)"
        );
        assert_eq!(protocol_description("unknown"), "Protocol parser");
    }
}
