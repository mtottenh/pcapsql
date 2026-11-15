//! Writing classic libpcap capture files.
//!
//! [`PcapWriter`] is the inverse of the readers of this module for the one
//! format every tool reads: a 24-byte file header, then one 16-byte record
//! header and the captured bytes per packet. It writes to any [`Write`], so a
//! host that owns its own file handles (a database engine's file system, an
//! in-memory buffer) decides where the bytes go and how they are buffered.
//!
//! What a file written here looks like:
//!
//! - little-endian, version 2.4, time zone offset and timestamp accuracy 0;
//! - the magic number says the unit of the timestamps: `0xa1b2c3d4` for
//!   microseconds, `0xa1b23c4d` for nanoseconds ([`TimestampPrecision`]);
//! - one link type for the whole file, which is all the format can say;
//! - a packet longer than the snapshot length is cut to it, and its record
//!   keeps the original length.
//!
//! pcapng is not written.

use std::io::{self, Write};

use thiserror::Error;

/// The snapshot length libpcap and Wireshark treat as the largest: a file
/// with longer packets is refused by some readers.
pub const DEFAULT_SNAPLEN: u32 = 262_144;

/// Size of the file header.
const FILE_HEADER_LEN: u64 = 24;
/// Size of the header of one packet record.
const RECORD_HEADER_LEN: u64 = 16;

const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// The unit of the timestamps of a pcap file, which its magic number names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampPrecision {
    /// Microseconds: magic `0xa1b2c3d4`. A timestamp loses what it has below
    /// a microsecond.
    Micros,
    /// Nanoseconds: magic `0xa1b23c4d`.
    Nanos,
}

impl TimestampPrecision {
    const fn magic(self) -> u32 {
        match self {
            Self::Micros => 0xa1b2_c3d4,
            Self::Nanos => 0xa1b2_3c4d,
        }
    }

    /// The fraction field of a record for `nanos` nanoseconds past a second.
    const fn fraction(self, nanos: u32) -> u32 {
        match self {
            Self::Micros => nanos / 1_000,
            Self::Nanos => nanos,
        }
    }
}

/// What the header of a pcap file says about its packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapWriteOptions {
    /// Link-layer type of every packet (`LINKTYPE_*`, e.g. 1 = Ethernet).
    pub link_type: u16,
    /// Most bytes kept of a packet.
    pub snaplen: u32,
    /// Unit of the timestamps.
    pub precision: TimestampPrecision,
}

/// Why a packet could not be written.
#[derive(Debug, Error)]
pub enum PcapWriteError {
    /// A pcap record counts seconds since 1970 in 32 unsigned bits.
    #[error(
        "timestamp {timestamp_ns} ns since 1970 is outside what a pcap file can store \
         (1970-01-01 00:00:00 to 2106-02-07 06:28:15 UTC)"
    )]
    TimestampOutOfRange {
        /// The timestamp that was given.
        timestamp_ns: i64,
    },
    /// The output failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Writes one classic pcap file to `W`.
///
/// The file header is written by [`new`](Self::new), so a writer that is
/// finished without a packet leaves a valid, empty capture. Nothing is
/// buffered here: give it a buffered `W`.
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    out: W,
    snaplen: u32,
    precision: TimestampPrecision,
    packets: u64,
    bytes: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Start a capture file on `out`: write its header.
    pub fn new(mut out: W, options: PcapWriteOptions) -> io::Result<Self> {
        let mut header = [0u8; FILE_HEADER_LEN as usize];
        header[0..4].copy_from_slice(&options.precision.magic().to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes());
        header[6..8].copy_from_slice(&4u16.to_le_bytes());
        // Bytes 8..16 stay zero: the time zone offset and the accuracy, which no tool sets.
        header[16..20].copy_from_slice(&options.snaplen.to_le_bytes());
        header[20..24].copy_from_slice(&u32::from(options.link_type).to_le_bytes());
        out.write_all(&header)?;
        Ok(Self {
            out,
            snaplen: options.snaplen,
            precision: options.precision,
            packets: 0,
            bytes: FILE_HEADER_LEN,
        })
    }

    /// Append one packet: `data` as it was captured at `timestamp_ns`
    /// nanoseconds since the Unix epoch, of a frame that was `original_len`
    /// bytes on the wire.
    ///
    /// At most the snapshot length of `data` is written. `original_len` is
    /// stored as given, also when it is less than `data` is long: a capture
    /// that says so is copied as it is.
    pub fn write_packet(
        &mut self,
        timestamp_ns: i64,
        original_len: u32,
        data: &[u8],
    ) -> Result<(), PcapWriteError> {
        let out_of_range = || PcapWriteError::TimestampOutOfRange { timestamp_ns };
        let seconds =
            u32::try_from(timestamp_ns.div_euclid(NANOS_PER_SECOND)).map_err(|_| out_of_range())?;
        // Between 0 and 999,999,999: the remainder of a Euclidean division.
        let nanos = timestamp_ns.rem_euclid(NANOS_PER_SECOND) as u32;

        let captured = data.len().min(self.snaplen as usize);
        let mut record = [0u8; RECORD_HEADER_LEN as usize];
        record[0..4].copy_from_slice(&seconds.to_le_bytes());
        record[4..8].copy_from_slice(&self.precision.fraction(nanos).to_le_bytes());
        // No more than `snaplen`, which is a `u32`.
        record[8..12].copy_from_slice(&(captured as u32).to_le_bytes());
        record[12..16].copy_from_slice(&original_len.to_le_bytes());
        self.out.write_all(&record)?;
        self.out.write_all(&data[..captured])?;
        self.packets += 1;
        self.bytes += RECORD_HEADER_LEN + captured as u64;
        Ok(())
    }

    /// Packets written so far.
    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Bytes given to the output so far, the file header among them: the
    /// size of the file when the output is one.
    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }

    /// Flush the output and hand it back.
    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

/// The number of the link-layer type `name`: a `LINKTYPE_*` name of
/// <https://www.tcpdump.org/linktypes.html>, with or without the prefix and
/// in any letter case (`ETHERNET`, `linktype_linux_sll`), or `EN10MB`, which
/// is what libpcap calls Ethernet. `None` for a name that is not known here:
/// only the common types have a name, every type has its number.
pub fn link_type_from_name(name: &str) -> Option<u16> {
    let name = name.trim().to_ascii_uppercase();
    let name = name.strip_prefix("LINKTYPE_").unwrap_or(&name);
    LINK_TYPES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|&(_, number)| number)
}

const LINK_TYPES: &[(&str, u16)] = &[
    ("NULL", 0),
    ("ETHERNET", 1),
    ("EN10MB", 1),
    ("PPP", 9),
    ("PPP_ETHER", 51),
    ("RAW", 101),
    ("C_HDLC", 104),
    ("IEEE802_11", 105),
    ("LOOP", 108),
    ("LINUX_SLL", 113),
    ("PFLOG", 117),
    ("IEEE802_11_RADIOTAP", 127),
    ("BLUETOOTH_HCI_H4", 187),
    ("USB_LINUX", 189),
    ("CAN_SOCKETCAN", 227),
    ("IPV4", 228),
    ("IPV6", 229),
    ("NFLOG", 239),
    ("USBPCAP", 249),
    ("NETLINK", 253),
    ("LINUX_SLL2", 276),
];

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::io::{PacketReader, ReadPacketReader, StreamHeader};

    const LINKTYPE_ETHERNET: u16 = 1;
    const LINKTYPE_LINUX_SLL: u16 = 113;
    const LINKTYPE_NETLINK: u16 = 253;

    const ETHERNET_NANOS: PcapWriteOptions = PcapWriteOptions {
        link_type: LINKTYPE_ETHERNET,
        snaplen: DEFAULT_SNAPLEN,
        precision: TimestampPrecision::Nanos,
    };

    /// What the readers of this crate make of a packet.
    #[derive(Debug, PartialEq, Eq)]
    struct Read {
        timestamp_ns: i64,
        captured_len: u32,
        original_len: u32,
        link_type: u16,
        data: Vec<u8>,
    }

    fn read_back(file: &[u8]) -> Vec<Read> {
        let mut input = Cursor::new(file);
        let (header, head) = StreamHeader::probe(&mut input).expect("a capture header");
        let mut reader =
            ReadPacketReader::sequential(input, &header, head).expect("a readable capture");
        let mut packets = Vec::new();
        loop {
            let delivered = reader
                .process_packets(64, |packet| {
                    packets.push(Read {
                        timestamp_ns: packet.timestamp_ns,
                        captured_len: packet.captured_len,
                        original_len: packet.original_len,
                        link_type: packet.link_type,
                        data: packet.data.to_vec(),
                    });
                    Ok(())
                })
                .expect("readable packets");
            if delivered == 0 {
                break;
            }
        }
        assert!(!reader.truncated(), "the file ends within a record");
        packets
    }

    fn written(options: PcapWriteOptions, packets: &[(i64, u32, &[u8])]) -> Vec<u8> {
        let mut writer = PcapWriter::new(Vec::new(), options).unwrap();
        for &(timestamp_ns, original_len, data) in packets {
            writer
                .write_packet(timestamp_ns, original_len, data)
                .unwrap();
        }
        assert_eq!(writer.packets(), packets.len() as u64);
        let size = writer.bytes_written();
        let file = writer.finish().unwrap();
        assert_eq!(size, file.len() as u64);
        file
    }

    #[test]
    fn the_header_is_that_of_a_little_endian_pcap_2_4() {
        let file = written(
            PcapWriteOptions {
                link_type: LINKTYPE_LINUX_SLL,
                snaplen: 65_535,
                precision: TimestampPrecision::Micros,
            },
            &[],
        );
        assert_eq!(
            file,
            [
                0xd4, 0xc3, 0xb2, 0xa1, // magic, microseconds
                2, 0, 4, 0, // version 2.4
                0, 0, 0, 0, 0, 0, 0, 0, // time zone offset, accuracy
                0xff, 0xff, 0, 0, // snapshot length
                113, 0, 0, 0, // link type
            ]
        );
        assert_eq!(written(ETHERNET_NANOS, &[])[..4], [0x4d, 0x3c, 0xb2, 0xa1]);
    }

    #[test]
    fn an_empty_file_is_a_capture_without_packets() {
        assert_eq!(read_back(&written(ETHERNET_NANOS, &[])), []);
    }

    #[test]
    fn a_record_is_sixteen_bytes_of_header_and_the_packet() {
        let file = written(
            PcapWriteOptions {
                precision: TimestampPrecision::Micros,
                ..ETHERNET_NANOS
            },
            &[(1_700_000_000_123_456_789, 60, &[0xaa, 0xbb, 0xcc])],
        );
        let mut record = Vec::new();
        record.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        record.extend_from_slice(&123_456u32.to_le_bytes());
        record.extend_from_slice(&3u32.to_le_bytes());
        record.extend_from_slice(&60u32.to_le_bytes());
        record.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(file[24..], record);
    }

    #[test]
    fn packets_read_back_as_they_were_written() {
        let payload: Vec<u8> = (0..=255).collect();
        let packets: [(i64, u32, &[u8]); 4] = [
            (0, 0, &[]),
            (1_700_000_000_123_456_789, 256, &payload),
            (1_700_000_000_999_999_999, 1514, &payload[..60]),
            // The last second a record can name.
            (i64::from(u32::MAX) * NANOS_PER_SECOND + 1, 3, &[1, 2, 3]),
        ];
        let file = written(
            PcapWriteOptions {
                link_type: LINKTYPE_NETLINK,
                ..ETHERNET_NANOS
            },
            &packets,
        );
        let expected: Vec<Read> = packets
            .iter()
            .map(|&(timestamp_ns, original_len, data)| Read {
                timestamp_ns,
                captured_len: data.len() as u32,
                original_len,
                link_type: LINKTYPE_NETLINK,
                data: data.to_vec(),
            })
            .collect();
        assert_eq!(read_back(&file), expected);
    }

    #[test]
    fn microseconds_drop_what_is_below_them() {
        let file = written(
            PcapWriteOptions {
                precision: TimestampPrecision::Micros,
                ..ETHERNET_NANOS
            },
            &[(5_000_000_999, 1, &[7]), (5_999_999_999, 1, &[7])],
        );
        let timestamps: Vec<i64> = read_back(&file)
            .iter()
            .map(|packet| packet.timestamp_ns)
            .collect();
        assert_eq!(timestamps, [5_000_000_000, 5_999_999_000]);
    }

    #[test]
    fn a_packet_longer_than_the_snapshot_length_is_cut_and_keeps_its_length() {
        let file = written(
            PcapWriteOptions {
                snaplen: 4,
                ..ETHERNET_NANOS
            },
            &[(1, 9, &[1, 2, 3, 4, 5, 6, 7, 8, 9]), (2, 4, &[1, 2, 3, 4])],
        );
        let packets = read_back(&file);
        assert_eq!(
            (
                packets[0].captured_len,
                packets[0].original_len,
                &packets[0].data[..]
            ),
            (4, 9, &[1, 2, 3, 4][..])
        );
        assert_eq!((packets[1].captured_len, packets[1].original_len), (4, 4));
        assert_eq!(file.len(), 24 + 2 * (16 + 4));
    }

    #[test]
    fn a_timestamp_a_record_cannot_name_is_refused_and_nothing_is_written() {
        let mut writer = PcapWriter::new(Vec::new(), ETHERNET_NANOS).unwrap();
        for timestamp_ns in [-1, i64::MIN, (i64::from(u32::MAX) + 1) * NANOS_PER_SECOND] {
            let error = writer.write_packet(timestamp_ns, 1, &[0]).unwrap_err();
            assert!(
                matches!(error, PcapWriteError::TimestampOutOfRange { timestamp_ns: t } if t == timestamp_ns),
                "{error}"
            );
        }
        assert_eq!(writer.packets(), 0);
        assert_eq!(writer.finish().unwrap().len(), 24);
    }

    #[test]
    fn an_output_that_fails_is_reported() {
        #[derive(Debug)]
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("no space"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            PcapWriter::new(Full, ETHERNET_NANOS)
                .unwrap_err()
                .to_string(),
            "no space"
        );
    }

    #[test]
    fn link_types_have_names() {
        assert_eq!(link_type_from_name("ETHERNET"), Some(1));
        assert_eq!(link_type_from_name("en10mb"), Some(1));
        assert_eq!(link_type_from_name(" LINKTYPE_LINUX_SLL "), Some(113));
        assert_eq!(link_type_from_name("linktype_linux_sll2"), Some(276));
        assert_eq!(link_type_from_name("netlink"), Some(LINKTYPE_NETLINK));
        assert_eq!(link_type_from_name("raw"), Some(101));
        assert_eq!(link_type_from_name("LINKTYPE_"), None);
        assert_eq!(link_type_from_name("token ring"), None);
        assert_eq!(link_type_from_name("1"), None);
    }
}
