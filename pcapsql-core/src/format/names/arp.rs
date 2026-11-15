//! ARP operation names.

use super::Name;

use crate::protocol::arp_operation as operation;

/// Convert an ARP operation code to its name; `Unknown (n)` otherwise.
pub fn arp_operation_name(op: u16) -> Name {
    match op {
        operation::REQUEST => Name::fixed("Request"),
        operation::REPLY => Name::fixed("Reply"),
        _ => Name::unknown(op),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_operation_name() {
        assert_eq!(arp_operation_name(1), "Request");
        assert_eq!(arp_operation_name(2), "Reply");
        assert_eq!(arp_operation_name(3), "Unknown (3)");
        assert_eq!(arp_operation_name(0), "Unknown (0)");
    }
}
