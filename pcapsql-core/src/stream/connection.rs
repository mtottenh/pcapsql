use std::collections::HashMap;
use std::net::IpAddr;

use super::Direction;

/// Normalized connection key (lower IP/port first for consistent lookup).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionKey {
    ip_a: IpAddr,
    port_a: u16,
    ip_b: IpAddr,
    port_b: u16,
}

impl ConnectionKey {
    /// Create a normalized connection key.
    /// Ensures (ip_a, port_a) <= (ip_b, port_b) lexicographically.
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                ip_a: src_ip,
                port_a: src_port,
                ip_b: dst_ip,
                port_b: dst_port,
            }
        } else {
            Self {
                ip_a: dst_ip,
                port_a: dst_port,
                ip_b: src_ip,
                port_b: src_port,
            }
        }
    }

    /// Determine direction based on who sent this packet.
    pub fn direction(&self, src_ip: IpAddr, src_port: u16) -> Direction {
        if src_ip == self.ip_a && src_port == self.port_a {
            Direction::ToServer // A is client, sending to server
        } else {
            Direction::ToClient
        }
    }
}

/// TCP connection state (simplified state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    Reset,
    /// Connection started mid-capture (no SYN seen).
    MidStream,
}

impl ConnectionState {
    /// Return a string representation of the state.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::SynSent => "syn_sent",
            ConnectionState::SynReceived => "syn_received",
            ConnectionState::Established => "established",
            ConnectionState::FinWait1 => "fin_wait_1",
            ConnectionState::FinWait2 => "fin_wait_2",
            ConnectionState::CloseWait => "close_wait",
            ConnectionState::Closing => "closing",
            ConnectionState::LastAck => "last_ack",
            ConnectionState::TimeWait => "time_wait",
            ConnectionState::Closed => "closed",
            ConnectionState::Reset => "reset",
            ConnectionState::MidStream => "mid_stream",
        }
    }
}

/// TCP flags for state transitions.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

/// A tracked TCP connection.
#[derive(Debug, Clone)]
pub struct Connection {
    pub id: u64,
    pub key: ConnectionKey,
    pub state: ConnectionState,

    /// Which endpoint is the client (sent SYN).
    /// True if ip_a/port_a is client.
    pub client_is_a: bool,

    /// Initial sequence numbers.
    pub client_isn: u32,
    pub server_isn: u32,

    /// Timing (microseconds).
    pub start_time: i64,
    pub last_activity: i64,
    pub end_time: Option<i64>,

    /// Packet counts.
    pub packets_to_server: u32,
    pub packets_to_client: u32,

    /// Byte counts (payload only).
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,

    /// Frame references.
    pub first_frame: u64,
    pub last_frame: u64,
}

impl Connection {
    /// Get client IP.
    pub fn client_ip(&self) -> IpAddr {
        if self.client_is_a {
            self.key.ip_a
        } else {
            self.key.ip_b
        }
    }

    /// Get server IP.
    pub fn server_ip(&self) -> IpAddr {
        if self.client_is_a {
            self.key.ip_b
        } else {
            self.key.ip_a
        }
    }

    /// Get client port.
    pub fn client_port(&self) -> u16 {
        if self.client_is_a {
            self.key.port_a
        } else {
            self.key.port_b
        }
    }

    /// Get server port.
    pub fn server_port(&self) -> u16 {
        if self.client_is_a {
            self.key.port_b
        } else {
            self.key.port_a
        }
    }

    /// Determine direction based on source IP/port.
    /// This correctly accounts for which endpoint is the client.
    pub fn direction(&self, src_ip: IpAddr, src_port: u16) -> Direction {
        let is_from_a = src_ip == self.key.ip_a && src_port == self.key.port_a;

        if self.client_is_a {
            // A is client, B is server
            if is_from_a {
                Direction::ToServer // Client sending to server
            } else {
                Direction::ToClient // Server sending to client
            }
        } else {
            // B is client, A is server
            if is_from_a {
                Direction::ToClient // Server sending to client
            } else {
                Direction::ToServer // Client sending to server
            }
        }
    }
}

/// Tracks TCP connections.
pub struct ConnectionTracker {
    connections: HashMap<ConnectionKey, Connection>,
    next_id: u64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            next_id: 1,
        }
    }

    /// Get or create a connection for the given packet.
    /// Returns (connection, direction).
    pub fn get_or_create(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        flags: TcpFlags,
        seq: u32,
        frame_number: u64,
        timestamp: i64,
    ) -> (&mut Connection, Direction) {
        let key = ConnectionKey::new(src_ip, src_port, dst_ip, dst_port);

        if !self.connections.contains_key(&key) {
            // Determine who is client based on SYN
            let (state, client_is_a, client_isn) = if flags.syn && !flags.ack {
                // This is the SYN - sender is client
                let client_is_a = src_ip == key.ip_a && src_port == key.port_a;
                (ConnectionState::SynSent, client_is_a, seq)
            } else {
                // Mid-stream connection - guess client by port (lower port = server)
                let client_is_a = key.port_a > key.port_b;
                (ConnectionState::MidStream, client_is_a, 0)
            };

            let conn = Connection {
                id: self.next_id,
                key: key.clone(),
                state,
                client_is_a,
                client_isn,
                server_isn: 0,
                start_time: timestamp,
                last_activity: timestamp,
                end_time: None,
                packets_to_server: 0,
                packets_to_client: 0,
                bytes_to_server: 0,
                bytes_to_client: 0,
                first_frame: frame_number,
                last_frame: frame_number,
            };

            self.next_id += 1;
            self.connections.insert(key.clone(), conn);
        }

        let conn = self.connections.get_mut(&key).unwrap();
        conn.last_activity = timestamp;
        conn.last_frame = frame_number;

        // Compute direction using the connection's knowledge of client/server roles
        let direction = conn.direction(src_ip, src_port);

        (conn, direction)
    }

    /// Update connection state based on TCP flags.
    pub fn update_state(conn: &mut Connection, flags: TcpFlags, direction: Direction, seq: u32) {
        use ConnectionState::*;

        // Update packet counts
        match direction {
            Direction::ToServer => conn.packets_to_server += 1,
            Direction::ToClient => conn.packets_to_client += 1,
        }

        // Handle RST
        if flags.rst {
            conn.state = Reset;
            return;
        }

        // State machine transitions
        conn.state = match (conn.state, flags.syn, flags.ack, flags.fin) {
            // SYN-ACK from server
            (SynSent, true, true, false) if direction == Direction::ToClient => {
                conn.server_isn = seq;
                SynReceived
            }
            // ACK completing handshake
            (SynReceived, false, true, false) if direction == Direction::ToServer => Established,

            // FIN from either side
            (Established, false, _, true) => match direction {
                Direction::ToServer => FinWait1,
                Direction::ToClient => CloseWait,
            },

            // ACK of FIN
            (FinWait1, false, true, false) => FinWait2,
            (CloseWait, false, _, true) => LastAck,
            (FinWait2, false, _, true) => TimeWait,
            (LastAck, false, true, false) => Closed,

            // Simultaneous close
            (FinWait1, false, _, true) => Closing,
            (Closing, false, true, false) => TimeWait,

            // Mid-stream can transition to established on data
            (MidStream, false, true, false) => Established,

            // Stay in current state
            (current, _, _, _) => current,
        };
    }

    /// Add payload bytes to connection stats.
    pub fn add_bytes(conn: &mut Connection, direction: Direction, bytes: usize) {
        match direction {
            Direction::ToServer => conn.bytes_to_server += bytes as u64,
            Direction::ToClient => conn.bytes_to_client += bytes as u64,
        }
    }

    /// Get a connection by key.
    pub fn get(&self, key: &ConnectionKey) -> Option<&Connection> {
        self.connections.get(key)
    }

    /// Get all connections.
    pub fn connections(&self) -> impl Iterator<Item = &Connection> {
        self.connections.values()
    }

    /// Remove timed-out connections.
    pub fn cleanup_timeout(&mut self, current_time: i64, timeout_us: i64) -> Vec<Connection> {
        let mut removed = Vec::new();
        self.connections.retain(|_, conn| {
            if current_time - conn.last_activity > timeout_us {
                removed.push(conn.clone());
                false
            } else {
                true
            }
        });
        removed
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // Test 1: Connection key normalization
    #[test]
    fn test_connection_key_normalization() {
        let key1 = ConnectionKey::new(ip(192, 168, 1, 1), 54321, ip(192, 168, 1, 2), 80);
        let key2 = ConnectionKey::new(ip(192, 168, 1, 2), 80, ip(192, 168, 1, 1), 54321);
        assert_eq!(key1, key2);
    }

    // Test 2: SYN -> SYN-ACK -> ACK
    #[test]
    fn test_three_way_handshake() {
        let mut tracker = ConnectionTracker::new();

        // SYN from client
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        let (conn, dir) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            syn,
            1000,
            1,
            0,
        );
        assert_eq!(conn.state, ConnectionState::SynSent);
        assert_eq!(dir, Direction::ToServer);

        // SYN-ACK from server
        let syn_ack = TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        };
        let (conn, dir) = tracker.get_or_create(
            ip(192, 168, 1, 2),
            80,
            ip(192, 168, 1, 1),
            54321,
            syn_ack,
            2000,
            2,
            1,
        );
        ConnectionTracker::update_state(conn, syn_ack, dir, 2000);
        assert_eq!(conn.state, ConnectionState::SynReceived);

        // ACK from client
        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };
        let (conn, dir) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            ack,
            1001,
            3,
            2,
        );
        ConnectionTracker::update_state(conn, ack, dir, 1001);
        assert_eq!(conn.state, ConnectionState::Established);
    }

    // Test 3: FIN handshake
    #[test]
    fn test_fin_handshake() {
        let mut tracker = ConnectionTracker::new();

        // Establish connection first (simplified)
        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };
        let (conn, _) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            ack,
            1000,
            1,
            0,
        );
        conn.state = ConnectionState::Established;

        // FIN from client
        let fin = TcpFlags {
            fin: true,
            ack: true,
            ..Default::default()
        };
        ConnectionTracker::update_state(conn, fin, Direction::ToServer, 1000);
        assert_eq!(conn.state, ConnectionState::FinWait1);
    }

    // Test 4: RST handling
    #[test]
    fn test_rst_handling() {
        let mut tracker = ConnectionTracker::new();
        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };
        let (conn, _) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            ack,
            1000,
            1,
            0,
        );
        conn.state = ConnectionState::Established;

        let rst = TcpFlags {
            rst: true,
            ..Default::default()
        };
        ConnectionTracker::update_state(conn, rst, Direction::ToServer, 1000);
        assert_eq!(conn.state, ConnectionState::Reset);
    }

    // Test 5: Mid-stream detection
    #[test]
    fn test_mid_stream() {
        let mut tracker = ConnectionTracker::new();
        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };
        let (conn, _) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            ack,
            1000,
            1,
            0, // No SYN, just data
        );
        assert_eq!(conn.state, ConnectionState::MidStream);
    }

    // Test 6: Connection lookup
    #[test]
    fn test_connection_lookup() {
        let mut tracker = ConnectionTracker::new();
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            syn,
            1000,
            1,
            0,
        );

        let key = ConnectionKey::new(ip(192, 168, 1, 1), 54321, ip(192, 168, 1, 2), 80);
        assert!(tracker.get(&key).is_some());
    }

    // Test 7: Packet counting
    #[test]
    fn test_packet_counting() {
        let mut tracker = ConnectionTracker::new();
        let ack = TcpFlags {
            ack: true,
            ..Default::default()
        };

        // Packet to server
        let (conn, dir) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            ack,
            1000,
            1,
            0,
        );
        ConnectionTracker::update_state(conn, ack, dir, 1000);

        // Packet to client
        let (conn, dir) = tracker.get_or_create(
            ip(192, 168, 1, 2),
            80,
            ip(192, 168, 1, 1),
            54321,
            ack,
            2000,
            2,
            1,
        );
        ConnectionTracker::update_state(conn, ack, dir, 2000);

        assert_eq!(conn.packets_to_server, 1);
        assert_eq!(conn.packets_to_client, 1);
    }

    // Test 8: Timeout cleanup
    #[test]
    fn test_timeout_cleanup() {
        let mut tracker = ConnectionTracker::new();
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            syn,
            1000,
            1,
            0,
        );

        // No timeout yet
        let removed = tracker.cleanup_timeout(1000000, 2000000);
        assert!(removed.is_empty());

        // After timeout
        let removed = tracker.cleanup_timeout(5000000, 2000000);
        assert_eq!(removed.len(), 1);
    }

    // Test 9: Simultaneous open (both send SYN)
    #[test]
    fn test_simultaneous_open() {
        let mut tracker = ConnectionTracker::new();

        // First SYN
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        let (conn, _) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            1000,
            ip(192, 168, 1, 2),
            1001,
            syn,
            100,
            1,
            0,
        );
        assert_eq!(conn.state, ConnectionState::SynSent);
    }

    // Test 10: Connection ID uniqueness
    #[test]
    fn test_connection_id_uniqueness() {
        let mut tracker = ConnectionTracker::new();
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };

        let (conn1, _) = tracker.get_or_create(
            ip(192, 168, 1, 1),
            54321,
            ip(192, 168, 1, 2),
            80,
            syn,
            1000,
            1,
            0,
        );
        let id1 = conn1.id;

        let (conn2, _) = tracker.get_or_create(
            ip(192, 168, 1, 3),
            54322,
            ip(192, 168, 1, 4),
            443,
            syn,
            2000,
            2,
            1,
        );
        let id2 = conn2.id;

        assert_ne!(id1, id2);
    }
}
