//! Cross-layer SQL view definitions.
//!
//! This module provides convenience views that JOIN normalized protocol tables
//! for common query patterns. Views make it easy to query across protocol layers
//! without writing complex JOINs manually.
//!
//! Example: The `tcp_packets` view joins frames + ethernet + ipv4/ipv6 + tcp
//! so you can query TCP traffic with timestamps and IP addresses directly.

mod arp;
mod dhcp;
mod dns;
mod http;
mod icmp;
mod icmpv6;
mod ntp;
mod packets;
mod quic;
mod ssh;
mod tcp;
mod tls;
mod udp;

pub use arp::arp_packets_view;
pub use dhcp::dhcp_packets_view;
pub use dns::dns_packets_view;
pub use http::http_packets_view;
pub use icmp::icmp_packets_view;
pub use icmpv6::icmpv6_packets_view;
pub use ntp::ntp_packets_view;
pub use packets::packets_view;
pub use quic::quic_packets_view;
pub use ssh::ssh_packets_view;
pub use tcp::tcp_packets_view;
pub use tls::tls_packets_view;
pub use udp::udp_packets_view;

/// A view definition with its name and SQL.
#[derive(Debug, Clone)]
pub struct ViewDefinition {
    /// The view name (e.g., "tcp_packets")
    pub name: &'static str,
    /// The SQL CREATE VIEW statement body (SELECT ... FROM ...)
    pub sql: &'static str,
    /// Brief description of the view
    pub description: &'static str,
}

/// Get all view definitions.
pub fn all_views() -> Vec<ViewDefinition> {
    vec![
        tcp_packets_view(),
        udp_packets_view(),
        dns_packets_view(),
        http_packets_view(),
        tls_packets_view(),
        ssh_packets_view(),
        quic_packets_view(),
        arp_packets_view(),
        icmp_packets_view(),
        icmpv6_packets_view(),
        dhcp_packets_view(),
        ntp_packets_view(),
        packets_view(),
    ]
}

/// Get a view definition by name.
pub fn get_view(name: &str) -> Option<ViewDefinition> {
    all_views().into_iter().find(|v| v.name == name)
}

/// Get all view names.
pub fn all_view_names() -> Vec<&'static str> {
    vec![
        "tcp_packets",
        "udp_packets",
        "dns_packets",
        "http_packets",
        "tls_packets",
        "ssh_packets",
        "quic_packets",
        "arp_packets",
        "icmp_packets",
        "icmpv6_packets",
        "dhcp_packets",
        "ntp_packets",
        "packets",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_views_have_definitions() {
        let views = all_views();
        assert!(!views.is_empty());

        for view in &views {
            assert!(!view.name.is_empty());
            assert!(!view.sql.is_empty());
            assert!(!view.description.is_empty());
        }
    }

    #[test]
    fn test_get_view() {
        assert!(get_view("tcp_packets").is_some());
        assert!(get_view("dns_packets").is_some());
        assert!(get_view("nonexistent").is_none());
    }

    #[test]
    fn test_all_view_names_match() {
        let views = all_views();
        let names = all_view_names();

        assert_eq!(views.len(), names.len());
        for (view, name) in views.iter().zip(names.iter()) {
            assert_eq!(view.name, *name);
        }
    }
}
