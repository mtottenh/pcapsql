//! DNS record type, class, response code and opcode names.

use std::borrow::Cow;

use crate::protocol::{rcode, record_type};

/// Convert DNS type number to name.
pub fn dns_type_name(qtype: u16) -> Cow<'static, str> {
    match qtype {
        record_type::A => Cow::Borrowed("A"),
        record_type::NS => Cow::Borrowed("NS"),
        record_type::CNAME => Cow::Borrowed("CNAME"),
        record_type::SOA => Cow::Borrowed("SOA"),
        record_type::PTR => Cow::Borrowed("PTR"),
        record_type::MX => Cow::Borrowed("MX"),
        record_type::TXT => Cow::Borrowed("TXT"),
        17 => Cow::Borrowed("RP"),
        18 => Cow::Borrowed("AFSDB"),
        24 => Cow::Borrowed("SIG"),
        25 => Cow::Borrowed("KEY"),
        record_type::AAAA => Cow::Borrowed("AAAA"),
        29 => Cow::Borrowed("LOC"),
        record_type::SRV => Cow::Borrowed("SRV"),
        35 => Cow::Borrowed("NAPTR"),
        36 => Cow::Borrowed("KX"),
        37 => Cow::Borrowed("CERT"),
        39 => Cow::Borrowed("DNAME"),
        record_type::OPT => Cow::Borrowed("OPT"),
        42 => Cow::Borrowed("APL"),
        43 => Cow::Borrowed("DS"),
        44 => Cow::Borrowed("SSHFP"),
        45 => Cow::Borrowed("IPSECKEY"),
        46 => Cow::Borrowed("RRSIG"),
        47 => Cow::Borrowed("NSEC"),
        48 => Cow::Borrowed("DNSKEY"),
        49 => Cow::Borrowed("DHCID"),
        50 => Cow::Borrowed("NSEC3"),
        51 => Cow::Borrowed("NSEC3PARAM"),
        52 => Cow::Borrowed("TLSA"),
        53 => Cow::Borrowed("SMIMEA"),
        55 => Cow::Borrowed("HIP"),
        59 => Cow::Borrowed("CDS"),
        60 => Cow::Borrowed("CDNSKEY"),
        61 => Cow::Borrowed("OPENPGPKEY"),
        62 => Cow::Borrowed("CSYNC"),
        63 => Cow::Borrowed("ZONEMD"),
        64 => Cow::Borrowed("SVCB"),
        65 => Cow::Borrowed("HTTPS"),
        99 => Cow::Borrowed("SPF"),
        108 => Cow::Borrowed("EUI48"),
        109 => Cow::Borrowed("EUI64"),
        249 => Cow::Borrowed("TKEY"),
        250 => Cow::Borrowed("TSIG"),
        251 => Cow::Borrowed("IXFR"),
        252 => Cow::Borrowed("AXFR"),
        record_type::ANY => Cow::Borrowed("ANY"),
        256 => Cow::Borrowed("URI"),
        257 => Cow::Borrowed("CAA"),
        32768 => Cow::Borrowed("TA"),
        32769 => Cow::Borrowed("DLV"),
        _ => Cow::Owned(format!("TYPE{qtype}")),
    }
}

/// Convert DNS response code to name.
///
/// Takes `u16` because the extended RCODE (header bits plus the EDNS OPT
/// extension) is 12 bits wide. Every assigned name is below 256; anything
/// else gives `RCODE{n}` with the full value.
pub fn dns_rcode_name(rcode_val: u16) -> Cow<'static, str> {
    let Ok(low) = u8::try_from(rcode_val) else {
        return Cow::Owned(format!("RCODE{rcode_val}"));
    };
    match low {
        rcode::NOERROR => Cow::Borrowed("NOERROR"),
        rcode::FORMERR => Cow::Borrowed("FORMERR"),
        rcode::SERVFAIL => Cow::Borrowed("SERVFAIL"),
        rcode::NXDOMAIN => Cow::Borrowed("NXDOMAIN"),
        rcode::NOTIMP => Cow::Borrowed("NOTIMP"),
        rcode::REFUSED => Cow::Borrowed("REFUSED"),
        rcode::YXDOMAIN => Cow::Borrowed("YXDOMAIN"),
        rcode::YXRRSET => Cow::Borrowed("YXRRSET"),
        rcode::NXRRSET => Cow::Borrowed("NXRRSET"),
        rcode::NOTAUTH => Cow::Borrowed("NOTAUTH"),
        rcode::NOTZONE => Cow::Borrowed("NOTZONE"),
        rcode::DSOTYPENI => Cow::Borrowed("DSOTYPENI"),
        rcode::BADVERS => Cow::Borrowed("BADVERS"),
        rcode::BADKEY => Cow::Borrowed("BADKEY"),
        rcode::BADTIME => Cow::Borrowed("BADTIME"),
        rcode::BADMODE => Cow::Borrowed("BADMODE"),
        rcode::BADNAME => Cow::Borrowed("BADNAME"),
        rcode::BADALG => Cow::Borrowed("BADALG"),
        rcode::BADTRUNC => Cow::Borrowed("BADTRUNC"),
        rcode::BADCOOKIE => Cow::Borrowed("BADCOOKIE"),
        _ => Cow::Owned(format!("RCODE{rcode_val}")),
    }
}

/// Convert DNS class to name.
pub fn dns_class_name(class: u16) -> Cow<'static, str> {
    match class {
        1 => Cow::Borrowed("IN"),
        3 => Cow::Borrowed("CH"),
        4 => Cow::Borrowed("HS"),
        254 => Cow::Borrowed("NONE"),
        255 => Cow::Borrowed("ANY"),
        _ => Cow::Owned(format!("CLASS{class}")),
    }
}

/// Convert DNS opcode (header bits 1-4) to its IANA name.
///
/// An unassigned opcode gives `OPCODE{n}`, in the style of `TYPE{n}`,
/// `CLASS{n}` and `RCODE{n}`.
pub fn dns_opcode_name(opcode: u8) -> Cow<'static, str> {
    match opcode {
        0 => Cow::Borrowed("QUERY"),
        1 => Cow::Borrowed("IQUERY"),
        2 => Cow::Borrowed("STATUS"),
        4 => Cow::Borrowed("NOTIFY"),
        5 => Cow::Borrowed("UPDATE"),
        6 => Cow::Borrowed("DSO"),
        _ => Cow::Owned(format!("OPCODE{opcode}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_type_name() {
        assert_eq!(dns_type_name(1), "A");
        assert_eq!(dns_type_name(28), "AAAA");
        assert_eq!(dns_type_name(5), "CNAME");
        assert_eq!(dns_type_name(15), "MX");
        assert_eq!(dns_type_name(2), "NS");
        assert_eq!(dns_type_name(12), "PTR");
        assert_eq!(dns_type_name(6), "SOA");
        assert_eq!(dns_type_name(16), "TXT");
        assert_eq!(dns_type_name(33), "SRV");
        assert_eq!(dns_type_name(255), "ANY");
        assert_eq!(dns_type_name(257), "CAA");
        assert_eq!(dns_type_name(65), "HTTPS");
        // Unknown type
        assert_eq!(dns_type_name(999), "TYPE999");
    }

    #[test]
    fn test_dns_rcode_name() {
        assert_eq!(dns_rcode_name(0), "NOERROR");
        assert_eq!(dns_rcode_name(1), "FORMERR");
        assert_eq!(dns_rcode_name(2), "SERVFAIL");
        assert_eq!(dns_rcode_name(3), "NXDOMAIN");
        assert_eq!(dns_rcode_name(4), "NOTIMP");
        assert_eq!(dns_rcode_name(5), "REFUSED");
        assert_eq!(dns_rcode_name(9), "NOTAUTH");
        // Unknown rcode
        assert_eq!(dns_rcode_name(99), "RCODE99");
    }

    #[test]
    fn test_dns_class_name() {
        assert_eq!(dns_class_name(1), "IN");
        assert_eq!(dns_class_name(3), "CH");
        assert_eq!(dns_class_name(4), "HS");
        assert_eq!(dns_class_name(255), "ANY");
        // Unknown class
        assert_eq!(dns_class_name(99), "CLASS99");
    }

    #[test]
    fn test_dns_rcode_name_above_u8() {
        // Not truncated to the low byte: 256 is not NOERROR.
        assert_eq!(dns_rcode_name(256), "RCODE256");
        assert_eq!(dns_rcode_name(4095), "RCODE4095");
        // Extended RCODEs that have names.
        assert_eq!(dns_rcode_name(16), "BADVERS");
        assert_eq!(dns_rcode_name(23), "BADCOOKIE");
    }

    #[test]
    fn test_dns_opcode_name() {
        assert_eq!(dns_opcode_name(0), "QUERY");
        assert_eq!(dns_opcode_name(1), "IQUERY");
        assert_eq!(dns_opcode_name(2), "STATUS");
        assert_eq!(dns_opcode_name(4), "NOTIFY");
        assert_eq!(dns_opcode_name(5), "UPDATE");
        assert_eq!(dns_opcode_name(6), "DSO");
        // Unassigned
        assert_eq!(dns_opcode_name(3), "OPCODE3");
        assert_eq!(dns_opcode_name(15), "OPCODE15");
    }

    #[test]
    fn known_names_do_not_allocate() {
        assert!(matches!(dns_type_name(1), Cow::Borrowed("A")));
        assert!(matches!(dns_rcode_name(3), Cow::Borrowed("NXDOMAIN")));
        assert!(matches!(dns_class_name(1), Cow::Borrowed("IN")));
        assert!(matches!(dns_type_name(999), Cow::Owned(_)));
    }
}
