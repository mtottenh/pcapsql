//! Address conversion scalar functions.
//!
//! - `ip4(string)` -> UInt32
//! - `ip4_to_string(uint32)` -> String
//! - `ip6(string)` -> Blob(16)
//! - `ip6_to_string(blob)` -> String
//! - `mac(string)` -> Blob(6)
//! - `mac_to_string(blob)` -> String

// Loop indices needed for both null checks and slice access
#![allow(clippy::needless_range_loop)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use duckdb::core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId};
use duckdb::types::DuckString;
use duckdb::vscalar::{ScalarFunctionSignature, VScalar};
use duckdb::vtab::arrow::WritableVector;
use duckdb::Connection;
use libduckdb_sys::duckdb_string_t;

// ============================================================================
// ip4(string) -> uint32
// ============================================================================

/// Parse IPv4 address string to u32.
pub struct Ip4Scalar;

impl VScalar for Ip4Scalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let strings = input.flat_vector(0);
        let string_slice = strings.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();
        let out_ptr = out.as_mut_ptr::<u32>();

        for i in 0..len {
            if strings.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let mut str_val = string_slice[i];
            let s = DuckString::new(&mut str_val).as_str();
            match Ipv4Addr::from_str(&s) {
                Ok(addr) => {
                    std::ptr::write(out_ptr.add(i), u32::from(addr));
                }
                Err(_) => {
                    out.set_null(i);
                }
            }
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)],
            LogicalTypeHandle::from(LogicalTypeId::UInteger),
        )]
    }
}

// ============================================================================
// ip4_to_string(uint32) -> string
// ============================================================================

/// Format u32 as IPv4 address string.
pub struct Ip4ToStringScalar;

impl VScalar for Ip4ToStringScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let values = input.flat_vector(0);
        let value_slice = values.as_slice_with_len::<u32>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if values.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let addr = Ipv4Addr::from(value_slice[i]);
            out.insert(i, addr.to_string().as_str());
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![LogicalTypeHandle::from(LogicalTypeId::UInteger)],
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        )]
    }
}

// ============================================================================
// ip6(string) -> blob(16)
// ============================================================================

/// Parse IPv6 address string to 16-byte blob.
pub struct Ip6Scalar;

impl VScalar for Ip6Scalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let strings = input.flat_vector(0);
        let string_slice = strings.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if strings.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let mut str_val = string_slice[i];
            let s = DuckString::new(&mut str_val).as_str();
            match Ipv6Addr::from_str(&s) {
                Ok(addr) => {
                    let bytes = addr.octets();
                    out.insert(i, bytes.as_slice());
                }
                Err(_) => {
                    out.set_null(i);
                }
            }
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)],
            LogicalTypeHandle::from(LogicalTypeId::Blob),
        )]
    }
}

// ============================================================================
// ip6_to_string(blob) -> string
// ============================================================================

/// Format 16-byte blob as IPv6 address string.
pub struct Ip6ToStringScalar;

impl VScalar for Ip6ToStringScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let values = input.flat_vector(0);
        let value_slice = values.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if values.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            // Get blob data
            let mut blob_val = value_slice[i];
            let mut blob = DuckString::new(&mut blob_val);
            let bytes = blob.as_bytes();

            if bytes.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                let addr = Ipv6Addr::from(arr);
                out.insert(i, addr.to_string().as_str());
            } else {
                out.set_null(i);
            }
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![LogicalTypeHandle::from(LogicalTypeId::Blob)],
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        )]
    }
}

// ============================================================================
// mac(string) -> blob(6)
// ============================================================================

/// Parse MAC address string to 6-byte blob.
pub struct MacScalar;

impl VScalar for MacScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let strings = input.flat_vector(0);
        let string_slice = strings.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if strings.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let mut str_val = string_slice[i];
            let s = DuckString::new(&mut str_val).as_str();
            match parse_mac(&s) {
                Some(bytes) => {
                    out.insert(i, bytes.as_slice());
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
            vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)],
            LogicalTypeHandle::from(LogicalTypeId::Blob),
        )]
    }
}

// ============================================================================
// mac_to_string(blob) -> string
// ============================================================================

/// Format 6-byte blob as MAC address string.
pub struct MacToStringScalar;

impl VScalar for MacToStringScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let values = input.flat_vector(0);
        let value_slice = values.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if values.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            // Get blob data
            let mut blob_val = value_slice[i];
            let mut blob = DuckString::new(&mut blob_val);
            let bytes = blob.as_bytes();

            if bytes.len() == 6 {
                let mac_str = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                out.insert(i, mac_str.as_str());
            } else {
                out.set_null(i);
            }
        }
        Ok(())
    }

    fn signatures() -> Vec<ScalarFunctionSignature> {
        vec![ScalarFunctionSignature::exact(
            vec![LogicalTypeHandle::from(LogicalTypeId::Blob)],
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        )]
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Parse MAC address string (e.g., "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff").
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.trim();
    let sep = if s.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = s.split(sep).collect();

    if parts.len() != 6 {
        return None;
    }

    let mut result = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        result[i] = u8::from_str_radix(part, 16).ok()?;
    }

    Some(result)
}

/// Register all address scalar functions.
pub fn register(con: &Connection) -> duckdb::Result<()> {
    con.register_scalar_function::<Ip4Scalar>("ip4")?;
    con.register_scalar_function::<Ip4ToStringScalar>("ip4_to_string")?;
    con.register_scalar_function::<Ip6Scalar>("ip6")?;
    con.register_scalar_function::<Ip6ToStringScalar>("ip6_to_string")?;
    con.register_scalar_function::<MacScalar>("mac")?;
    con.register_scalar_function::<MacToStringScalar>("mac_to_string")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let mac = parse_mac("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert!(parse_mac("invalid").is_none());
    }
}
