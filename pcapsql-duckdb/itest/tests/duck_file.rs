//! `DuckFile`, the extension's file reader, inside table-function callbacks.
//!
//! Three test-only table functions use it the way the packet scan will:
//!
//! - `count_packets(path)` opens the capture in `init_local_state`, probes it with core's
//!   `StreamHeader::probe`, and keeps a `ReadPacketReader<DuckFile>` in its local state, which
//!   later `exec` calls read a few packets at a time.
//! - `file_checksum(path, offset, read_size)` opens the file at a byte offset, as a partition
//!   reader does, and reads to the end in reads of a given size.
//! - `file_seeks(path)` moves around in one open file.
//!
//! What they return is compared with the same file read through `std::fs`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use duckdb_neo::{
    bind_arguments::BindArgument,
    connection::{Connection, Context},
    data_chunk::DataChunkRef,
    error::DuckDBError,
    signature::{FunctionParameter, SignatureBuilder},
    table_function::{BindFunctionHandle, ExecColumnInfo, InitColumnData, TableFunctionCallbacks},
    Error, Parameters, Result,
};
use pcapsql_core::io::{
    FilePacketSource, PacketReader, PacketSource, ReadPacketReader, StreamHeader,
};
use pcapsql_core::scan::{ColKind, OutCol, OutColumn, RowSink};
use pcapsql_duckdb::engine::{
    fs::{DuckFile, LOCAL_BUFFER},
    guard, types,
    writer::ChunkWriter,
};
use pcapsql_duckdb_itest::{connect, replay::column, rows, value};

/// Packets `count_packets` reads per `exec` call: several calls for any capture used here.
const STEP: usize = 16;

fn strings(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| cell.to_string()).collect()
}

fn failed(error: impl std::fmt::Display) -> Error {
    Error::invalid_input(error.to_string())
}

fn text_argument(arguments: &[BindArgument], index: usize) -> Result<String> {
    arguments
        .get(index)
        .and_then(|argument| argument.value.as_ref())
        .map(|value| value.get::<String>())
        .transpose()?
        .flatten()
        .ok_or_else(|| Error::invalid_input("expected a VARCHAR argument"))
}

fn integer_argument(arguments: &[BindArgument], index: usize) -> Result<u64> {
    arguments
        .get(index)
        .and_then(|argument| argument.value.as_ref())
        .map(|value| value.get::<i64>())
        .transpose()?
        .flatten()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| Error::invalid_input("expected a BIGINT >= 0 argument"))
}

fn declare(
    context: &Context,
    bind_handle: &BindFunctionHandle<'_>,
    columns: &[OutColumn],
) -> Result<()> {
    for column in columns {
        bind_handle.add_result_column(column.name, &types::logical_type(context, column.kind)?)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// count_packets
// ---------------------------------------------------------------------------------------------

fn count_columns() -> [OutColumn; 6] {
    [
        column("packets", ColKind::U64),
        column("bytes", ColKind::U64),
        column("first_frame", ColKind::U64),
        column("first_timestamp", ColKind::TsNanos),
        column("link_type", ColKind::U32),
        column("file_size", ColKind::U64),
    ]
}

struct CountPackets;

/// What a worker keeps between `exec` calls: the reader owns the open file.
struct Counting {
    reader: ReadPacketReader<DuckFile>,
    link_type: u32,
    file_size: u64,
}

impl TableFunctionCallbacks for CountPackets {
    /// The path.
    type BindData = String;
    type GlobalState = ();
    type LocalState = Counting;

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<String> {
        declare(context, &bind_handle, &count_columns())?;
        text_argument(&arguments, 0)
    }

    fn init_local_state(
        &self,
        context: &Context,
        path: &String,
        _global_state: Option<&()>,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<Counting>> {
        let mut file = DuckFile::open(context, path)?;
        let file_size = file.size()?;
        let (header, head) = StreamHeader::probe(&mut file).map_err(failed)?;
        let reader = ReadPacketReader::sequential(file, &header, head).map_err(failed)?;
        Ok(Some(Counting {
            reader,
            link_type: header.link_type,
            file_size,
        }))
    }

    /// One row per call: what the next [`STEP`] packets add up to.
    fn exec(
        &self,
        _context: &Context,
        _path: &String,
        counting: Option<&mut Counting>,
        _global_state: Option<&()>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let counting = counting.expect("init_local_state opened the file");
        let (mut packets, mut bytes, mut first) = (0u64, 0u64, None);
        counting
            .reader
            .process_packets(STEP, |packet| {
                packets += 1;
                bytes += u64::from(packet.captured_len);
                assert_eq!(packet.data.len(), packet.captured_len as usize);
                first.get_or_insert((packet.frame_number, packet.timestamp_ns));
                Ok(())
            })
            .map_err(failed)?;

        let mut writer = ChunkWriter::new(output, &count_columns())?;
        if let Some((frame, timestamp)) = first {
            writer.u64(OutCol(0), packets);
            writer.u64(OutCol(1), bytes);
            writer.u64(OutCol(2), frame);
            writer.timestamp(OutCol(3), timestamp);
            writer.u32(OutCol(4), counting.link_type);
            writer.u64(OutCol(5), counting.file_size);
            let _ = writer.end_row();
        }
        // No packet left: an empty chunk ends the scan.
        writer.finish()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// file_checksum
// ---------------------------------------------------------------------------------------------

fn fnv1a(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

fn checksum_columns() -> [OutColumn; 5] {
    [
        column("file_size", ColKind::U64),
        column("bytes", ColKind::U64),
        column("fnv1a", ColKind::U64),
        column("position", ColKind::U64),
        column("buffer", ColKind::U64),
    ]
}

struct FileChecksum;

impl TableFunctionCallbacks for FileChecksum {
    /// Path, offset, bytes per read.
    type BindData = (String, u64, u64);
    /// Whether the row has been emitted.
    type GlobalState = AtomicBool;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<Self::BindData> {
        declare(context, &bind_handle, &checksum_columns())?;
        Ok((
            text_argument(&arguments, 0)?,
            integer_argument(&arguments, 1)?,
            integer_argument(&arguments, 2)?,
        ))
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _bind_data: &Self::BindData,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicBool>> {
        Ok(Some(AtomicBool::new(false)))
    }

    fn exec(
        &self,
        context: &Context,
        (path, offset, read_size): &Self::BindData,
        _local_state: Option<&mut ()>,
        emitted: Option<&AtomicBool>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let mut writer = ChunkWriter::new(output, &checksum_columns())?;
        if !emitted.unwrap().swap(true, Ordering::Relaxed) {
            let mut file = DuckFile::open_at(context, path, *offset)?;
            assert_eq!(file.position(), *offset);
            let mut block = vec![0; *read_size as usize];
            let (mut bytes, mut hash) = (0u64, FNV_OFFSET);
            loop {
                let read = file.read(&mut block).map_err(failed)?;
                if read == 0 {
                    break;
                }
                bytes += read as u64;
                hash = fnv1a(hash, &block[..read]);
                assert_eq!(file.position(), offset + bytes);
            }
            writer.u64(OutCol(0), file.size()?);
            writer.u64(OutCol(1), bytes);
            writer.u64(OutCol(2), hash);
            writer.u64(OutCol(3), file.position());
            writer.u64(OutCol(4), file.buffer_capacity() as u64);
            let _ = writer.end_row();
        }
        writer.finish()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// file_seeks
// ---------------------------------------------------------------------------------------------

/// Where `file_seeks` goes, and how many bytes it reads there. `None`: read on from where the
/// last step stopped. The offsets are for a file of [`SEEK_FILE`] bytes.
const SEEKS: [(Option<u64>, usize); 9] = [
    (None, 10),
    // Forward, inside what the first read buffered.
    (Some(100), 50),
    (None, 30),
    // Backward: before the buffered bytes.
    (Some(5), 20),
    // Far ahead: outside the buffer.
    (Some(2 * LOCAL_BUFFER as u64 + 17), 100),
    // To the byte the buffer ends on, and across it.
    (Some(LOCAL_BUFFER as u64 - 4), 8),
    // The end, and past it.
    (Some(SEEK_FILE - 5), 10),
    (Some(SEEK_FILE), 10),
    (Some(SEEK_FILE + 1000), 10),
];

const SEEK_FILE: u64 = 3 * LOCAL_BUFFER as u64 + 12_345;

fn seek_columns() -> [OutColumn; 3] {
    [
        column("step", ColKind::U32),
        column("position", ColKind::U64),
        column("data", ColKind::Bin),
    ]
}

struct FileSeeks;

impl TableFunctionCallbacks for FileSeeks {
    type BindData = String;
    type GlobalState = AtomicBool;
    type LocalState = ();

    fn bind(
        &self,
        context: &Context,
        arguments: Vec<BindArgument>,
        bind_handle: BindFunctionHandle<'_>,
    ) -> Result<String> {
        declare(context, &bind_handle, &seek_columns())?;
        text_argument(&arguments, 0)
    }

    fn init_global_state(
        &self,
        _context: &Context,
        _path: &String,
        _column_data: InitColumnData<'_>,
    ) -> Result<Option<AtomicBool>> {
        Ok(Some(AtomicBool::new(false)))
    }

    fn exec(
        &self,
        context: &Context,
        path: &String,
        _local_state: Option<&mut ()>,
        emitted: Option<&AtomicBool>,
        output: DataChunkRef<'_>,
        _column_info: ExecColumnInfo<'_>,
    ) -> Result<()> {
        let mut writer = ChunkWriter::new(output, &seek_columns())?;
        if !emitted.unwrap().swap(true, Ordering::Relaxed) {
            let mut file = DuckFile::open(context, path)?;
            for (step, (seek, length)) in SEEKS.iter().enumerate() {
                if let Some(offset) = seek {
                    file.seek(*offset)?;
                    assert_eq!(file.position(), *offset);
                }
                let position = file.position();
                // Up to `length` bytes, less only at the end of the file.
                let mut data = Vec::new();
                (&mut file)
                    .take(*length as u64)
                    .read_to_end(&mut data)
                    .map_err(failed)?;
                assert_eq!(file.position(), position + data.len() as u64);
                writer.u32(OutCol(0), step as u32);
                writer.u64(OutCol(1), position);
                writer.bytes(OutCol(2), &data);
                let _ = writer.end_row();
            }
        }
        writer.finish()?;
        Ok(())
    }
}

fn register(connection: &Connection) -> Result<()> {
    let path = || SignatureBuilder::new().param(FunctionParameter::new::<String>("path"));
    guard::table_function("count_packets", path(), CountPackets).register(connection)?;
    guard::table_function(
        "file_checksum",
        path()
            .param(FunctionParameter::new::<i64>("offset"))
            .param(FunctionParameter::new::<i64>("read_size")),
        FileChecksum,
    )
    .register(connection)?;
    guard::table_function("file_seeks", path(), FileSeeks).register(connection)
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A capture of the repository's fuzzing seeds: real traffic, small enough to commit.
fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus/fuzz_pcap_reader")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// Packets, captured bytes, and the first packet's timestamp, as core's own file reader
/// (`std::fs` and `mmap`, nothing of DuckDB) reads `path`.
fn count_with_core(path: &Path) -> (u64, u64, i64) {
    let source = FilePacketSource::open(path).unwrap();
    let mut reader = source.sequential_reader().unwrap();
    let (mut packets, mut bytes, mut first) = (0, 0, None);
    loop {
        let read = reader
            .process_packets(1000, |packet| {
                packets += 1;
                bytes += u64::from(packet.captured_len);
                first.get_or_insert(packet.timestamp_ns);
                Ok(())
            })
            .unwrap();
        if read == 0 {
            break;
        }
    }
    (packets, bytes, first.unwrap())
}

/// A legacy pcap (microseconds, Ethernet) of `packets` packets of `length` bytes each, one
/// second apart from 2023-11-14 22:13:20.5.
fn generated_pcap(packets: u32, length: u32) -> Vec<u8> {
    let mut capture = Vec::new();
    capture.extend(0xa1b2_c3d4u32.to_le_bytes());
    capture.extend(2u16.to_le_bytes());
    capture.extend(4u16.to_le_bytes());
    capture.extend(0i32.to_le_bytes());
    capture.extend(0u32.to_le_bytes());
    capture.extend(65_535u32.to_le_bytes());
    capture.extend(1u32.to_le_bytes());
    for index in 0..packets {
        capture.extend((1_700_000_000 + index).to_le_bytes());
        capture.extend(500_000u32.to_le_bytes());
        capture.extend(length.to_le_bytes());
        capture.extend(length.to_le_bytes());
        capture.extend((0..length).map(|byte| (index + byte) as u8));
    }
    capture
}

fn sql_path(path: &Path) -> String {
    path.to_str().unwrap().replace('\'', "''")
}

fn totals(connection: &Connection, path: &Path) -> Result<Vec<String>> {
    Ok(rows(
        connection,
        &format!(
            "SELECT sum(packets), sum(bytes), count(*), min(first_frame), max(first_frame),
                    min(first_timestamp), any_value(link_type), any_value(file_size)
             FROM count_packets('{}')",
            sql_path(path)
        ),
    )?
    .remove(0))
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[test]
fn a_generated_capture_is_read_through_duckdbs_file_system() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    let directory = tempfile::tempdir().unwrap();

    // 5,000 packets of 300 bytes: more than one buffer of the file, 313 `exec` calls.
    let capture = generated_pcap(5000, 300);
    assert!(capture.len() > LOCAL_BUFFER);
    let path = directory.path().join("generated.pcap");
    std::fs::write(&path, &capture).unwrap();
    assert_eq!(
        totals(&connection, &path)?,
        strings(&[
            "5000",
            "1500000",
            "313",
            "1",
            "4993",
            "2023-11-14 22:13:20.5",
            "1",
            &capture.len().to_string(),
        ])
    );

    // The same capture gzip-compressed: the size is the file's, the packets are the same.
    let compressed = {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&capture).unwrap();
        encoder.finish().unwrap()
    };
    assert!(compressed.len() < capture.len() / 2);
    let gz_path = directory.path().join("generated.pcap.gz");
    std::fs::write(&gz_path, &compressed).unwrap();
    assert_eq!(
        totals(&connection, &gz_path)?,
        strings(&[
            "5000",
            "1500000",
            "313",
            "1",
            "4993",
            "2023-11-14 22:13:20.5",
            "1",
            &compressed.len().to_string(),
        ])
    );

    // A capture with a header and no packet.
    let empty = directory.path().join("empty.pcap");
    std::fs::write(&empty, generated_pcap(0, 0)).unwrap();
    assert_eq!(
        value(
            &connection,
            &format!("SELECT count(*) FROM count_packets('{}')", sql_path(&empty))
        )?,
        "0"
    );
    Ok(())
}

#[test]
fn real_captures_count_as_core_counts_them() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    // Legacy pcap and pcapng, Ethernet and netlink.
    for name in [
        "tcp-ecn-sample.pcap",
        "netlink.pcap",
        "tls12-dsb.pcapng",
        "ldap-ssl.pcapng",
        "dns.cap",
    ] {
        let path = corpus(name);
        let (packets, bytes, first) = count_with_core(&path);
        assert!(packets > STEP as u64, "{name}: {packets} packets");
        let size = std::fs::metadata(&path).unwrap().len();

        let got = rows(
            &connection,
            &format!(
                "SELECT sum(packets), sum(bytes), count(*), min(first_frame),
                        epoch_ns(min(first_timestamp)), any_value(file_size)
                 FROM count_packets('{}')",
                sql_path(&path)
            ),
        )?;
        assert_eq!(
            got,
            [strings(&[
                &packets.to_string(),
                &bytes.to_string(),
                &packets.div_ceil(STEP as u64).to_string(),
                "1",
                &first.to_string(),
                &size.to_string(),
            ])],
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn two_scans_of_one_capture_each_have_their_own_file() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    let path = corpus("tcp-ecn-sample.pcap");
    let (packets, _, _) = count_with_core(&path);
    let scan = format!(
        "(SELECT sum(packets) AS packets FROM count_packets('{}'))",
        sql_path(&path)
    );
    assert_eq!(
        rows(
            &connection,
            &format!("SELECT a.packets, b.packets FROM {scan} a, {scan} b")
        )?,
        [strings(&[&packets.to_string(), &packets.to_string()])]
    );
    Ok(())
}

#[test]
fn opens_follow_duckdbs_access_rules() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    let path = corpus("tcp-ecn-sample.pcap");
    let query = format!(
        "SELECT sum(packets) FROM count_packets('{}')",
        sql_path(&path)
    );
    let (packets, _, _) = count_with_core(&path);
    assert_eq!(value(&connection, &query)?, packets.to_string());

    // A missing file is DuckDB's error, naming the path.
    let error = value(
        &connection,
        "SELECT sum(packets) FROM count_packets('/nonexistent/x.pcap')",
    )
    .unwrap_err();
    assert!(error.message.contains("/nonexistent/x.pcap"), "{error}");

    // A file that is not a capture is core's error, as an ordinary query error.
    let directory = tempfile::tempdir().unwrap();
    let not_a_capture = directory.path().join("notes.txt");
    std::fs::write(&not_a_capture, "not a capture at all, just text\n").unwrap();
    let error = value(
        &connection,
        &format!(
            "SELECT sum(packets) FROM count_packets('{}')",
            sql_path(&not_a_capture)
        ),
    )
    .unwrap_err();
    assert_ne!(error.code, DuckDBError::RuntimeInternal, "{error}");
    assert_eq!(value(&connection, &query)?, packets.to_string());

    // With external access switched off, DuckDB refuses the open that worked a moment ago:
    // the extension has no other way to a file.
    connection.execute("SET enable_external_access = false", Parameters::None)?;
    let error = value(&connection, &query).unwrap_err();
    assert_eq!(error.code, DuckDBError::ConfigurationPermission, "{error}");
    assert!(
        error.message.contains("disabled by configuration"),
        "{error}"
    );
    let error = value(
        &connection,
        &format!(
            "SELECT bytes FROM file_checksum('{}', 0, 4096)",
            sql_path(&path)
        ),
    )
    .unwrap_err();
    assert_eq!(error.code, DuckDBError::ConfigurationPermission, "{error}");
    // The session is otherwise unharmed.
    assert_eq!(value(&connection, "SELECT 42")?, "42");
    Ok(())
}

/// `SEEK_FILE` bytes that do not repeat with any period a buffer could hide.
fn seek_file_bytes() -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..SEEK_FILE)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn a_file_opened_at_an_offset_reads_from_there_to_the_end() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    let directory = tempfile::tempdir().unwrap();
    let bytes = seek_file_bytes();
    let path = directory.path().join("bytes.bin");
    std::fs::write(&path, &bytes).unwrap();
    let size = bytes.len() as u64;

    let buffer = LOCAL_BUFFER as u64;
    for offset in [0, 1, 4096, buffer - 1, buffer, buffer + 1, size - 1, size] {
        // Reads smaller than the buffer, of its size, and larger (which bypass it).
        for read_size in [7, 4096, buffer, 2 * buffer + 3] {
            let rest = &bytes[offset as usize..];
            assert_eq!(
                rows(
                    &connection,
                    &format!(
                        "SELECT * FROM file_checksum('{}', {offset}, {read_size})",
                        sql_path(&path)
                    ),
                )?,
                [strings(&[
                    &size.to_string(),
                    &rest.len().to_string(),
                    &fnv1a(FNV_OFFSET, rest).to_string(),
                    &size.to_string(),
                    &buffer.to_string(),
                ])],
                "offset {offset}, reads of {read_size}"
            );
        }
    }

    // An offset past the end reads nothing.
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT bytes, position FROM file_checksum('{}', {}, 100)",
                sql_path(&path),
                size + 10
            ),
        )?,
        [strings(&["0", &(size + 10).to_string()])]
    );

    // A file smaller than the buffer gets a buffer of its own size, not a megabyte.
    let small = corpus("http.pcap");
    let small_size = std::fs::metadata(&small).unwrap().len();
    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT file_size, bytes, buffer FROM file_checksum('{}', 0, 10)",
                sql_path(&small)
            ),
        )?,
        [strings(&[
            &small_size.to_string(),
            &small_size.to_string(),
            "4096"
        ])]
    );
    Ok(())
}

#[test]
fn seeks_move_the_read_position_in_and_out_of_the_buffer() -> Result<()> {
    let connection = connect()?;
    register(&connection)?;
    let directory = tempfile::tempdir().unwrap();
    let bytes = seek_file_bytes();
    let path = directory.path().join("bytes.bin");
    std::fs::write(&path, &bytes).unwrap();

    // The same steps over the bytes in memory.
    let mut position = 0usize;
    let expected: Vec<Vec<String>> = SEEKS
        .iter()
        .enumerate()
        .map(|(step, (seek, length))| {
            if let Some(offset) = seek {
                position = *offset as usize;
            }
            let start = position.min(bytes.len());
            let data = &bytes[start..(start + length).min(bytes.len())];
            let row = vec![
                step.to_string(),
                position.to_string(),
                data.iter().map(|byte| format!("{byte:02x}")).collect(),
            ];
            position += data.len();
            row
        })
        .collect();
    // The steps reach what they are meant to: the end of the file cuts a read short.
    assert_eq!(expected[6][2].len(), 2 * 5);
    assert_eq!(expected[7][2], "");
    assert_eq!(expected[8][2], "");

    assert_eq!(
        rows(
            &connection,
            &format!(
                "SELECT step, position, pcap_hex(data) FROM file_seeks('{}')",
                sql_path(&path)
            ),
        )?,
        expected
    );
    Ok(())
}
