//! Validation of hand-entered addressing from the portal.
//!
//! Everything here runs before the access point goes down, for the same
//! reason as the passphrase rules: a typo NetworkManager would accept — a
//! gateway outside the subnet, an address that is the subnet's broadcast —
//! does not fail the join. It succeeds, and leaves a device that associated
//! fine and can reach nothing, with the portal gone. The checks are the
//! ones that catch that class of mistake; anything they let through is at
//! least a configuration that can work.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::nm::{IpSettings, StaticIp};

/// More than any resolver uses: glibc reads three.
pub const MAX_DNS_SERVERS: usize = 4;

/// The portal's addressing fields, as typed. Blank means automatic.
#[derive(Debug, Default, Clone, Copy)]
pub struct Fields<'a> {
    pub ipv4_address: &'a str,
    pub ipv4_gateway: &'a str,
    pub ipv6_address: &'a str,
    pub ipv6_gateway: &'a str,
    pub dns: &'a str,
}

/// Turn the typed fields into addressing, or a sentence saying what to fix.
pub fn parse(f: Fields<'_>) -> Result<IpSettings, String> {
    let ipv4 = family(f.ipv4_address, f.ipv4_gateway, "IPv4", parse_v4, check_v4)?;
    let ipv6 = family(f.ipv6_address, f.ipv6_gateway, "IPv6", parse_v6, check_v6)?;
    let dns = dns_servers(f.dns)?;

    // With IPv4 fixed there is no DHCP, and DHCP is where nearly every
    // network hands out its DNS servers. IPv6 router advertisements can
    // carry them too, but an IPv4-only LAN is the common case, and there a
    // missing server leaves a device that is online by every test except
    // the only one the software on it cares about.
    if ipv4.is_some() && dns.is_empty() {
        return Err("Enter at least one DNS server to go with a fixed IPv4 address.".into());
    }

    Ok(IpSettings { ipv4, ipv6, dns })
}

/// One family: an address with its prefix, and an optional gateway.
fn family<A: Copy + PartialEq + std::str::FromStr>(
    address: &str,
    gateway: &str,
    name: &str,
    parse: fn(&str) -> Option<(A, u8)>,
    check: fn(A, u8, Option<A>) -> Result<(), String>,
) -> Result<Option<StaticIp<A>>, String> {
    let (address, gateway) = (address.trim(), gateway.trim());
    if address.is_empty() {
        return if gateway.is_empty() {
            Ok(None)
        } else {
            Err(format!(
                "Enter the {name} address that goes with the {name} gateway, or clear the gateway."
            ))
        };
    }
    let Some((address, prefix)) = parse(address) else {
        return Err(match name {
            "IPv4" => "Enter the IPv4 address with its prefix length, such as 192.168.1.50/24.",
            _ => "Enter the IPv6 address with its prefix length, such as 2001:db8::50/64.",
        }
        .into());
    };
    let gateway = if gateway.is_empty() {
        None
    } else {
        Some(
            gateway
                .parse::<A>()
                .map_err(|_| format!("The {name} gateway must be an {name} address."))?,
        )
    };
    if gateway == Some(address) {
        return Err(format!(
            "The {name} gateway is the router's address, not this device's."
        ));
    }
    check(address, prefix, gateway)?;
    Ok(Some(StaticIp {
        address,
        prefix,
        gateway,
    }))
}

/// `a.b.c.d/nn`, or `a.b.c.d/255.255.255.0` for people who think in masks.
fn parse_v4(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, prefix) = s.split_once('/')?;
    let addr: Ipv4Addr = addr.trim().parse().ok()?;
    let prefix = prefix.trim();
    let prefix = match prefix.parse::<u8>() {
        Ok(p) => p,
        Err(_) => mask_to_prefix(prefix.parse().ok()?)?,
    };
    (prefix <= 32).then_some((addr, prefix))
}

/// The prefix length of a contiguous netmask; `None` for `255.0.255.0`.
fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    (bits.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
}

fn parse_v6(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (addr, prefix) = s.split_once('/')?;
    let addr: Ipv6Addr = addr.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    (prefix <= 128).then_some((addr, prefix))
}

fn check_v4(address: Ipv4Addr, prefix: u8, gateway: Option<Ipv4Addr>) -> Result<(), String> {
    if prefix == 0 {
        return Err("An IPv4 prefix length of 0 is not a subnet. Most networks use /24.".into());
    }
    if !usable_v4(address) {
        return Err(format!("{address} cannot be assigned to a device."));
    }
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let host = u32::from(address) & !mask;
    // /31 and /32 have no network or broadcast address (RFC 3021).
    if prefix <= 30 && (host == 0 || host == !mask) {
        return Err(format!(
            "{address} is the network or broadcast address of /{prefix}, not a device address."
        ));
    }
    if let Some(g) = gateway {
        if !usable_v4(g) {
            return Err(format!("{g} cannot be a gateway."));
        }
        // The one mistake that associates fine and then reaches nothing:
        // there is no on-link route to a gateway outside the subnet.
        if prefix < 32 && u32::from(g) & mask != u32::from(address) & mask {
            return Err(format!(
                "The gateway {g} is not inside {address}/{prefix}. Check the address, the \
                 prefix length and the gateway."
            ));
        }
    }
    Ok(())
}

fn usable_v4(a: Ipv4Addr) -> bool {
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_link_local())
}

fn check_v6(address: Ipv6Addr, prefix: u8, gateway: Option<Ipv6Addr>) -> Result<(), String> {
    if prefix == 0 {
        return Err("An IPv6 prefix length of 0 is not a subnet. Most networks use /64.".into());
    }
    // Link-local is left out: every IPv6 interface configures its own, and
    // NetworkManager does so whatever the method.
    if !usable_v6(address) || is_link_local_v6(address) {
        return Err(format!("{address} cannot be assigned to a device."));
    }
    if let Some(g) = gateway {
        if !usable_v6(g) {
            return Err(format!("{g} cannot be a gateway."));
        }
        // Routers usually advertise themselves by their link-local
        // address, so that is a valid gateway on any prefix.
        let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
        if !is_link_local_v6(g) && u128::from(g) & mask != u128::from(address) & mask {
            return Err(format!(
                "The gateway {g} is neither link-local (fe80::) nor inside {address}/{prefix}."
            ));
        }
    }
    Ok(())
}

fn usable_v6(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.to_ipv4_mapped().is_some())
}

fn is_link_local_v6(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// A list of servers, separated by commas or spaces, either family.
fn dns_servers(raw: &str) -> Result<Vec<IpAddr>, String> {
    let mut out = Vec::new();
    for item in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        if item.is_empty() {
            continue;
        }
        let ip: IpAddr = item
            .parse()
            .map_err(|_| format!("\u{201c}{item}\u{201d} is not an IP address."))?;
        let usable = match ip {
            IpAddr::V4(a) => usable_v4(a),
            // A link-local server would need a zone (`%wlan0`), which the
            // legacy `ipv6.dns` property has no way to carry.
            IpAddr::V6(a) => usable_v6(a) && !is_link_local_v6(a),
        };
        if !usable {
            return Err(format!("{ip} cannot be a DNS server."));
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    if out.len() > MAX_DNS_SERVERS {
        return Err(format!("Enter at most {MAX_DNS_SERVERS} DNS servers."));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(address: &str, gateway: &str, dns: &str) -> Result<IpSettings, String> {
        parse(Fields {
            ipv4_address: address,
            ipv4_gateway: gateway,
            dns,
            ..Fields::default()
        })
    }

    fn v6(address: &str, gateway: &str) -> Result<IpSettings, String> {
        parse(Fields {
            ipv6_address: address,
            ipv6_gateway: gateway,
            ..Fields::default()
        })
    }

    #[test]
    fn blank_fields_are_automatic() {
        let ip = parse(Fields {
            ipv4_address: "  ",
            dns: " , ",
            ..Fields::default()
        })
        .unwrap();
        assert!(ip.is_automatic());
    }

    #[test]
    fn a_typical_static_ipv4_setup_is_accepted() {
        let ip = v4(" 192.168.1.50/24 ", "192.168.1.1", "192.168.1.1, 1.1.1.1").unwrap();
        assert_eq!(
            ip.ipv4,
            Some(StaticIp {
                address: Ipv4Addr::new(192, 168, 1, 50),
                prefix: 24,
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            })
        );
        assert_eq!(ip.ipv6, None, "IPv6 stays automatic");
        assert_eq!(ip.dns.len(), 2);
    }

    #[test]
    fn a_dotted_netmask_is_read_as_a_prefix() {
        let ip = v4("10.0.5.9/255.255.252.0", "10.0.4.1", "10.0.4.1").unwrap();
        assert_eq!(ip.ipv4.unwrap().prefix, 22);
        assert!(v4("10.0.5.9/255.0.255.0", "", "1.1.1.1").is_err());
    }

    /// A bare address could be a /8, a /16 or a /24, and the wrong guess
    /// associates fine and then cannot reach half the LAN.
    #[test]
    fn the_prefix_length_is_required() {
        let e = v4("192.168.1.50", "192.168.1.1", "1.1.1.1").unwrap_err();
        assert!(e.contains("/24"), "{e}");
        assert!(v4("192.168.1.50/33", "", "1.1.1.1").is_err());
        assert!(v4("192.168.1.50/0", "", "1.1.1.1").is_err());
    }

    #[test]
    fn the_gateway_must_be_on_the_subnet() {
        let e = v4("192.168.1.50/24", "192.168.2.1", "1.1.1.1").unwrap_err();
        assert!(e.contains("not inside"), "{e}");
        assert!(v4("192.168.1.50/16", "192.168.2.1", "1.1.1.1").is_ok());
    }

    #[test]
    fn the_gateway_is_not_this_device() {
        assert!(v4("192.168.1.50/24", "192.168.1.50", "1.1.1.1").is_err());
        assert!(v6("2001:db8::50/64", "2001:db8::50").is_err());
    }

    #[test]
    fn network_broadcast_and_special_addresses_are_refused() {
        for bad in [
            "192.168.1.0/24",
            "192.168.1.255/24",
            "0.0.0.0/8",
            "127.0.0.2/8",
            "224.0.0.5/4",
            "169.254.3.4/16",
        ] {
            assert!(v4(bad, "", "1.1.1.1").is_err(), "{bad} was accepted");
        }
        // Point-to-point links have no network or broadcast address.
        assert!(v4("192.168.1.0/31", "", "1.1.1.1").is_ok());
        assert!(v4("192.168.1.7/32", "", "1.1.1.1").is_ok());
    }

    #[test]
    fn a_gateway_without_an_address_is_an_error_not_ignored() {
        let e = v4("", "192.168.1.1", "").unwrap_err();
        assert!(e.contains("address"), "{e}");
        assert!(v6("", "fe80::1").is_err());
    }

    #[test]
    fn a_gateway_of_the_wrong_family_is_refused() {
        assert!(v4("192.168.1.50/24", "fe80::1", "1.1.1.1").is_err());
        assert!(v6("2001:db8::50/64", "192.168.1.1").is_err());
    }

    /// No DHCP means no DNS from DHCP.
    #[test]
    fn a_fixed_ipv4_address_needs_a_dns_server() {
        let e = v4("192.168.1.50/24", "192.168.1.1", "").unwrap_err();
        assert!(e.contains("DNS"), "{e}");
    }

    #[test]
    fn a_typical_static_ipv6_setup_is_accepted() {
        let ip = v6("2001:db8:1::50/64", "fe80::1").unwrap();
        let fixed = ip.ipv6.unwrap();
        assert_eq!(fixed.address, "2001:db8:1::50".parse::<Ipv6Addr>().unwrap());
        assert_eq!(fixed.prefix, 64);
        assert_eq!(fixed.gateway, Some("fe80::1".parse().unwrap()));
        assert_eq!(ip.ipv4, None, "IPv4 stays automatic");
        // An on-prefix router is fine too, and so is none at all.
        assert!(v6("2001:db8:1::50/64", "2001:db8:1::1").is_ok());
        assert!(v6("2001:db8:1::50/64", "").is_ok());
    }

    /// Unlike IPv4, DHCPv4 still runs, and router advertisements may carry
    /// DNS, so a fixed IPv6 address alone does not demand a server.
    #[test]
    fn a_fixed_ipv6_address_alone_does_not_need_dns() {
        assert!(v6("2001:db8::50/64", "fe80::1").unwrap().dns.is_empty());
    }

    #[test]
    fn ipv6_mistakes_are_refused() {
        for (addr, gw) in [
            ("2001:db8::50", ""),
            ("2001:db8::50/129", ""),
            ("2001:db8::50/0", ""),
            ("fe80::50/64", ""),
            ("::1/128", ""),
            ("ff02::1/64", ""),
            ("::ffff:192.168.1.5/96", ""),
            ("2001:db8:1::50/64", "2001:db8:2::1"),
        ] {
            assert!(v6(addr, gw).is_err(), "{addr} via {gw:?} was accepted");
        }
    }

    #[test]
    fn dns_takes_both_families_separated_by_commas_or_spaces() {
        let ip = parse(Fields {
            dns: "1.1.1.1,2606:4700:4700::1111  9.9.9.9\n1.1.1.1",
            ..Fields::default()
        })
        .unwrap();
        let want: Vec<IpAddr> = ["1.1.1.1", "2606:4700:4700::1111", "9.9.9.9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ip.dns, want, "in order, duplicates dropped");
        assert!(!ip.is_automatic());
    }

    #[test]
    fn bad_dns_servers_are_named() {
        let dns = |d| {
            parse(Fields {
                dns: d,
                ..Fields::default()
            })
        };
        assert!(
            dns("dns.example.com")
                .unwrap_err()
                .contains("dns.example.com")
        );
        assert!(dns("0.0.0.0").is_err());
        assert!(dns("fe80::1").is_err());
        assert!(dns("1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4").is_ok());
        assert!(dns("1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9").is_err());
    }
}
