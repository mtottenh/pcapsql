//! Hex conversion functions.
//!
//! - `pcap_hex(blob)` -> String
//! - `pcap_unhex(string)` -> Blob
//!
//! Named `pcap_hex` and `pcap_unhex` to avoid conflict with DuckDB's built-in functions.

// Loop indices needed for both null checks and slice access
#![allow(clippy::needless_range_loop)]

use duckdb::core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId};
use duckdb::types::DuckString;
use duckdb::vscalar::{ScalarFunctionSignature, VScalar};
use duckdb::vtab::arrow::WritableVector;
use duckdb::Connection;
use libduckdb_sys::duckdb_string_t;

// ============================================================================
// pcap_hex(blob) -> string
// ============================================================================

/// Convert blob to hex string.
pub struct PcapHexScalar;

impl VScalar for PcapHexScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let blob_vec = input.flat_vector(0);
        let blob_slice = blob_vec.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if blob_vec.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let mut blob_val = blob_slice[i];
            let mut blob = DuckString::new(&mut blob_val);
            let bytes = blob.as_bytes();
            let hex_str = hex::encode(bytes);
            out.insert(i, hex_str.as_str());
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
// pcap_unhex(string) -> blob
// ============================================================================

/// Convert hex string to blob.
pub struct PcapUnhexScalar;

impl VScalar for PcapUnhexScalar {
    type State = ();

    unsafe fn invoke(
        _state: &Self::State,
        input: &mut DataChunkHandle,
        output: &mut dyn WritableVector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let len = input.len();
        let str_vec = input.flat_vector(0);
        let str_slice = str_vec.as_slice_with_len::<duckdb_string_t>(len);

        let mut out = output.flat_vector();

        for i in 0..len {
            if str_vec.row_is_null(i as u64) {
                out.set_null(i);
                continue;
            }

            let mut str_val = str_slice[i];
            let s = DuckString::new(&mut str_val).as_str();
            match hex::decode(s.as_ref()) {
                Ok(bytes) => {
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

/// Register all hex conversion functions.
pub fn register(con: &Connection) -> duckdb::Result<()> {
    con.register_scalar_function::<PcapHexScalar>("pcap_hex")?;
    con.register_scalar_function::<PcapUnhexScalar>("pcap_unhex")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode([0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex::encode([0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(
            hex::decode("deadbeef").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(hex::decode("00FF").unwrap(), vec![0x00, 0xFF]);
        assert!(hex::decode("invalid!").is_err());
    }
}
