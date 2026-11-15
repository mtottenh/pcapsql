//! The reader of one partition: the capture file under a decompressor under the packet
//! reader, with the bytes it reads counted and its first read error remembered.

use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use duckdb_neo::{connection::Context, Result};
use pcapsql_core::io::{
    Compression, DecompressReader, PacketRange, ReadPacketReader, StreamHeader,
};
use pcapsql_core::scan::PartitionScan;

use super::{function::CaptureFunction, protocols, BindData, PcapScan, Shared};
use crate::engine::fs::DuckFile;

/// A partition being scanned by a worker.
pub(super) struct Scanning {
    pub(super) scan: PartitionScan<ReadPacketReader<Tracked>>,
    /// The first read error of the reader stack under `scan`.
    pub(super) fault: Fault,
    /// The file the partition is of: an index into `BindData::files`.
    pub(super) file: usize,
    /// The number of the partition's first frame.
    pub(super) first_frame: u64,
}

impl PcapScan {
    /// Open file `number` of the scan for its partition `range` and build the partition's scan.
    pub(super) fn open(
        &self,
        context: &Context,
        bound: &BindData,
        shared: &Shared,
        number: usize,
        range: &PacketRange,
    ) -> Result<Scanning> {
        let fault = Fault::default();
        let first_frame = range.start.frame_number;
        let path = bound.files[number].as_str();
        let failed = |error: &dyn std::fmt::Display| {
            self.read_error(path, first_frame.saturating_sub(1), error)
        };
        let reader = match &shared.files[number].index {
            // The whole capture, from its first byte.
            None => {
                let mut file = DuckFile::open(context, path)?;
                // Probed again: the header that counts is that of the file as it is read.
                let header = self.probe(&mut file, path)?;
                file.seek(0)?;
                // The decompressor is ours rather than the reader's, so that a read error
                // can be remembered between the two (`Tracked`).
                let tracked = Tracked::new(file, header.compression, &shared.file_bytes, &fault)
                    .map_err(|error| failed(&error))?;
                let plain = StreamHeader {
                    compression: Compression::None,
                    ..header
                };
                ReadPacketReader::sequential(tracked, &plain, Vec::new())
            }
            // A range of an uncompressed capture: the file is read from the range's first
            // record, and the reader is told by the index what the capture's header said.
            Some(index) => {
                let file = DuckFile::open_at(context, path, range.start.byte_offset)?;
                let tracked = Tracked::new(file, Compression::None, &shared.file_bytes, &fault)
                    .map_err(|error| failed(&error))?;
                ReadPacketReader::at(tracked, index.format, index, range)
            }
        }
        .map_err(|error| failed(&error))?;
        let mut scan = PartitionScan::new(reader, shared.plan.clone(), protocols().clone());
        // Before its first step. Each file is a scan of its own, with its own TLS sessions.
        if let Some(keys) = &bound.keylog {
            scan = scan.with_keylog(keys.keylog());
        }
        Ok(Scanning {
            scan,
            fault,
            file: number,
            first_frame,
        })
    }
}

/// The first read error of a worker's reader stack, which the worker cannot reach into once
/// the packet reader owns it.
#[derive(Debug, Default, Clone)]
pub(super) struct Fault(Arc<Mutex<Option<String>>>);

impl Fault {
    pub(super) fn get(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Keep `error` if it is the first.
    pub(super) fn set(&self, error: &io::Error) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_or_insert_with(|| error.to_string());
    }
}

/// The capture file, counting the bytes read from it for `progress`.
struct Counted {
    file: DuckFile,
    bytes: Arc<AtomicU64>,
}

impl Read for Counted {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.file.read(out)?;
        self.bytes.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

/// The decompressed capture as the capture parser reads it, which keeps failing once a read
/// has failed.
///
/// The sticky error is a guard: a reader that answers a retried read after an error with "end
/// of file" would turn a failed read into a short result.
pub(super) struct Tracked {
    inner: DecompressReader<Counted>,
    fault: Fault,
}

impl Tracked {
    /// `file` from its position on, decompressed, with the bytes read from it added to
    /// `bytes`: the progress of a scan.
    pub(super) fn new(
        file: DuckFile,
        compression: Compression,
        bytes: &Arc<AtomicU64>,
        fault: &Fault,
    ) -> io::Result<Self> {
        let counted = Counted {
            file,
            bytes: bytes.clone(),
        };
        Ok(Self {
            inner: DecompressReader::new(counted, compression)?,
            fault: fault.clone(),
        })
    }
}

impl Read for Tracked {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = self.fault.get() {
            return Err(io::Error::other(error));
        }
        match self.inner.read(out) {
            Err(error) if error.kind() != io::ErrorKind::Interrupted => {
                self.fault.set(&error);
                Err(error)
            }
            result => result,
        }
    }
}
