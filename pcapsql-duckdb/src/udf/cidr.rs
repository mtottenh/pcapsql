//! CIDR matching scalar functions.
//!
//! - `ip_in_cidr(ip_uint32, cidr_string)` -> Boolean
//! - `ip6_in_cidr(ip_blob, cidr_string)` -> Boolean

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use duckdb::core::{DataChunkHandle, LogicalTypeHandle, LogicalTypeId};
use duckdb::types::DuckString;
use duckdb::vscalar::{ScalarFunctionSignature, VScalar};
use duckdb::vtab::arrow::WritableVector;
use duckdb::Connection;
use libduckdb_sys::duckdb_string_t;

// ============================================================================
// ip_in_cidr(uint32, string) -> boolean
// ============================================================================

/// Check if an IPv4 address (as u32) is in a CIDR range.
pub struct IpInCidrScalar;

impl VScalar for IpInCidrScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let ip_vec = input.flat_vector(0);
        let cidr_vec = input.flat_vector(1);

        let ip_slice = ip_vec.as_slice_with_len::<u32>(len);
        let cidr_slice = cidr_vec.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();
        let out_ptr = out.as_mut_ptr::<bool>();

        for i in 0..len {
            if ip_vec.row_is_null(i as u64) || cidr_vec.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let ip = ip_slice[i];
            let mut cidr_val = cidr_slice[i];
            let cidr_str = DuckString::new(&mut cidr_val).as_str();

            match parse_cidr_v4(&cidr_str) {
                Some((network, prefix_len)) => {
                    std::ptr::write(out_ptr.add(i), ipv4_in_cidr(ip, network, prefix_len));
                }
                None => {
                    out.set_null(i);
                }
            }
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![
                LogicalTypeHandle::from(LogicalTypeId::UInteger),
                LogicalTypeHandle::from(LogicalTypeId::Varchar),
            ],
            LogicalTypeHandle::from(LogicalTypeId::Boolean),
        )]
    }
}

// ============================================================================
// ip6_in_cidr(blob, string) -> boolean
// ============================================================================

/// Check if an IPv6 address (as 16-byte blob) is in a CIDR range.
pub struct Ip6InCidrScalar;

impl VScalar for Ip6InCidrScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let ip_vec = input.flat_vector(0);
        let cidr_vec = input.flat_vector(1);

        let ip_slice = ip_vec.as_slice_with_len::<duckdb_string_t>(len);
        let cidr_slice = cidr_vec.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();
        let out_ptr = out.as_mut_ptr::<bool>();

        for i in 0..len {
            if ip_vec.row_is_null(i as u64) || cidr_vec.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let mut ip_val = ip_slice[i];
            let mut ip_blob = DuckString::new(&mut ip_val);
            let ip_bytes = ip_blob.as_bytes();

            let mut cidr_val = cidr_slice[i];
            let cidr_str = DuckString::new(&mut cidr_val).as_str();

            if ip_bytes.len() != 16 {
                out.set_null(i);
                continue;
            }

            match parse_cidr_v6(&cidr_str) {
                Some((network, prefix_len)) => {
                    std::ptr::write(
                        out_ptr.add(i),
                        ipv6_in_prefix(ip_bytes, &network, prefix_len),
                    );
                }
                None => {
                    out.set_null(i);
                }
            }
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![
                LogicalTypeHandle::from(LogicalTypeId::Blob),
                LogicalTypeHandle::from(LogicalTypeId::Varchar),
            ],
            LogicalTypeHandle::from(LogicalTypeId::Boolean),
        )]
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Parse IPv4 CIDR notation (e.g., "192.168.0.0/16").
fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr = Ipv4Addr::from_str(parts[0]).ok()?;
    let prefix: u8 = parts[1].parse().ok()?;

    if prefix > 32 {
        return None;
    }

    Some((u32::from(addr), prefix))
}

/// Check if an IPv4 address is in a CIDR range.
fn ipv4_in_cidr(addr: u32, network: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return addr == network;
    }

    let mask = !0u32 << (32 - prefix_len);
    (addr & mask) == (network & mask)
}

/// Parse IPv6 CIDR notation (e.g., "fe80::/10").
fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr = Ipv6Addr::from_str(parts[0]).ok()?;
    let prefix: u8 = parts[1].parse().ok()?;

    if prefix > 128 {
        return None;
    }

    Some((addr.octets(), prefix))
}

/// Check if an IPv6 address is in a CIDR range.
fn ipv6_in_prefix(addr: &[u8], network: &[u8; 16], prefix_len: u8) -> bool {
    if addr.len() != 16 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }

    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    // Check full bytes
    for i in 0..full_bytes.min(16) {
        if addr[i] != network[i] {
            return false;
        }
    }

    // Check remaining bits
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !0u8 << (8 - remaining_bits);
        if (addr[full_bytes] & mask) != (network[full_bytes] & mask) {
            return false;
        }
    }

    true
}

/// Register all CIDR matching functions.
pub fn register(con: &Connection) -> duckdb::Result<()> {
    con.register_scalar_function::<IpInCidrScalar>("ip_in_cidr")?;
    con.register_scalar_function::<Ip6InCidrScalar>("ip6_in_cidr")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_v4() {
        let (network, prefix) = parse_cidr_v4("192.168.0.0/16").unwrap();
        assert_eq!(network, 0xC0A80000);
        assert_eq!(prefix, 16);

        assert!(parse_cidr_v4("invalid").is_none());
        assert!(parse_cidr_v4("192.168.0.0/33").is_none());
    }

    #[test]
    fn test_ipv4_in_cidr() {
        let network = 0xC0A80000; // 192.168.0.0

        // 192.168.1.100 should be in 192.168.0.0/16
        assert!(ipv4_in_cidr(0xC0A80164, network, 16));

        // 10.0.0.1 should NOT be in 192.168.0.0/16
        assert!(!ipv4_in_cidr(0x0A000001, network, 16));

        // Edge cases
        assert!(ipv4_in_cidr(0xC0A80000, 0xC0A80000, 32));
        assert!(ipv4_in_cidr(0x12345678, 0, 0));
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (network, prefix) = parse_cidr_v6("fe80::/10").unwrap();
        assert_eq!(prefix, 10);
        assert_eq!(network[0], 0xfe);
        assert_eq!(network[1], 0x80);

        assert!(parse_cidr_v6("invalid").is_none());
        assert!(parse_cidr_v6("fe80::/129").is_none());
    }

    #[test]
    fn test_ipv6_in_prefix() {
        let (network, prefix) = parse_cidr_v6("fe80::/10").unwrap();

        // fe80::1 should be in fe80::/10
        let addr1 = Ipv6Addr::from_str("fe80::1").unwrap().octets();
        assert!(ipv6_in_prefix(&addr1, &network, prefix));

        // 2001::1 should NOT be in fe80::/10
        let addr2 = Ipv6Addr::from_str("2001::1").unwrap().octets();
        assert!(!ipv6_in_prefix(&addr2, &network, prefix));
    }
}
