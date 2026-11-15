//! DNS record type, class, response code and opcode names.

use super::Name;

use crate::protocol::{rcode, record_type};

/// Convert DNS type number to name.
pub fn dns_type_name(qtype: u16) -> Name {
    match qtype {
        record_type::A => Name::fixed("A"),
        record_type::NS => Name::fixed("NS"),
        record_type::CNAME => Name::fixed("CNAME"),
        record_type::SOA => Name::fixed("SOA"),
        record_type::PTR => Name::fixed("PTR"),
        record_type::MX => Name::fixed("MX"),
        record_type::TXT => Name::fixed("TXT"),
        17 => Name::fixed("RP"),
        18 => Name::fixed("AFSDB"),
        24 => Name::fixed("SIG"),
        25 => Name::fixed("KEY"),
        record_type::AAAA => Name::fixed("AAAA"),
        29 => Name::fixed("LOC"),
        record_type::SRV => Name::fixed("SRV"),
        35 => Name::fixed("NAPTR"),
        36 => Name::fixed("KX"),
        37 => Name::fixed("CERT"),
        39 => Name::fixed("DNAME"),
        record_type::OPT => Name::fixed("OPT"),
        42 => Name::fixed("APL"),
        43 => Name::fixed("DS"),
        44 => Name::fixed("SSHFP"),
        45 => Name::fixed("IPSECKEY"),
        46 => Name::fixed("RRSIG"),
        47 => Name::fixed("NSEC"),
        48 => Name::fixed("DNSKEY"),
        49 => Name::fixed("DHCID"),
        50 => Name::fixed("NSEC3"),
        51 => Name::fixed("NSEC3PARAM"),
        52 => Name::fixed("TLSA"),
        53 => Name::fixed("SMIMEA"),
        55 => Name::fixed("HIP"),
        59 => Name::fixed("CDS"),
        60 => Name::fixed("CDNSKEY"),
        61 => Name::fixed("OPENPGPKEY"),
        62 => Name::fixed("CSYNC"),
        63 => Name::fixed("ZONEMD"),
        64 => Name::fixed("SVCB"),
        65 => Name::fixed("HTTPS"),
        99 => Name::fixed("SPF"),
        108 => Name::fixed("EUI48"),
        109 => Name::fixed("EUI64"),
        249 => Name::fixed("TKEY"),
        250 => Name::fixed("TSIG"),
        251 => Name::fixed("IXFR"),
        252 => Name::fixed("AXFR"),
        record_type::ANY => Name::fixed("ANY"),
        256 => Name::fixed("URI"),
        257 => Name::fixed("CAA"),
        32768 => Name::fixed("TA"),
        32769 => Name::fixed("DLV"),
        _ => Name::numbered("TYPE", qtype, ""),
    }
}

/// Convert DNS response code to name.
///
/// Takes `u16` because the extended RCODE (header bits plus the EDNS OPT
/// extension) is 12 bits wide. Every assigned name is below 256; anything
/// else gives `RCODE{n}` with the full value.
pub fn dns_rcode_name(rcode_val: u16) -> Name {
    let Ok(low) = u8::try_from(rcode_val) else {
        return Name::numbered("RCODE", rcode_val, "");
    };
    match low {
        rcode::NOERROR => Name::fixed("NOERROR"),
        rcode::FORMERR => Name::fixed("FORMERR"),
        rcode::SERVFAIL => Name::fixed("SERVFAIL"),
        rcode::NXDOMAIN => Name::fixed("NXDOMAIN"),
        rcode::NOTIMP => Name::fixed("NOTIMP"),
        rcode::REFUSED => Name::fixed("REFUSED"),
        rcode::YXDOMAIN => Name::fixed("YXDOMAIN"),
        rcode::YXRRSET => Name::fixed("YXRRSET"),
        rcode::NXRRSET => Name::fixed("NXRRSET"),
        rcode::NOTAUTH => Name::fixed("NOTAUTH"),
        rcode::NOTZONE => Name::fixed("NOTZONE"),
        rcode::DSOTYPENI => Name::fixed("DSOTYPENI"),
        rcode::BADVERS => Name::fixed("BADVERS"),
        rcode::BADKEY => Name::fixed("BADKEY"),
        rcode::BADTIME => Name::fixed("BADTIME"),
        rcode::BADMODE => Name::fixed("BADMODE"),
        rcode::BADNAME => Name::fixed("BADNAME"),
        rcode::BADALG => Name::fixed("BADALG"),
        rcode::BADTRUNC => Name::fixed("BADTRUNC"),
        rcode::BADCOOKIE => Name::fixed("BADCOOKIE"),
        _ => Name::numbered("RCODE", rcode_val, ""),
    }
}

/// Convert DNS class to name.
pub fn dns_class_name(class: u16) -> Name {
    match class {
        1 => Name::fixed("IN"),
        3 => Name::fixed("CH"),
        4 => Name::fixed("HS"),
        254 => Name::fixed("NONE"),
        255 => Name::fixed("ANY"),
        _ => Name::numbered("CLASS", class, ""),
    }
}

/// Convert DNS opcode (header bits 1-4) to its IANA name.
///
/// An unassigned opcode gives `OPCODE{n}`, in the style of `TYPE{n}`,
/// `CLASS{n}` and `RCODE{n}`.
pub fn dns_opcode_name(opcode: u8) -> Name {
    match opcode {
        0 => Name::fixed("QUERY"),
        1 => Name::fixed("IQUERY"),
        2 => Name::fixed("STATUS"),
        4 => Name::fixed("NOTIFY"),
        5 => Name::fixed("UPDATE"),
        6 => Name::fixed("DSO"),
        _ => Name::numbered("OPCODE", opcode, ""),
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
        assert_eq!(dns_type_name(1).as_static(), Some("A"));
        assert_eq!(dns_rcode_name(3).as_static(), Some("NXDOMAIN"));
        assert_eq!(dns_class_name(1).as_static(), Some("IN"));
        assert_eq!(dns_type_name(999).as_static(), None);
    }
}
