//! Building NetworkManager connection-settings maps: the whole setup AP,
//! and the IP sections of a station profile with static addressing.
//!
//! `nmrs`'s `WifiConnectionBuilder` covers most of this, but not
//! `ipv4.method=manual` (it offers `auto` and `shared` only) and not
//! `ap-isolation`. Since this is the one structure in the program that must
//! be byte-exact — a wrong D-Bus signature surfaces as an opaque
//! `InvalidProperty` at 2am on a customer's device — we build it ourselves
//! and assert its exact shape in tests.
//!
//! ## Why `manual` and not `shared`
//!
//! `ipv4.method=shared` makes NetworkManager spawn its *own* dnsmasq on the
//! interface, listening on udp/67 and udp/53, and install NAT rules. That
//! collides head-on with our in-process DHCP and DNS servers, needs
//! iptables and `NET_ADMIN` in the image, and is a confinement problem under
//! strict snap confinement. `manual` tells NM to do exactly one thing — put
//! an address on the interface and bring it up — and leaves everything above
//! L3 to us.

use std::collections::HashMap;
use std::net::IpAddr;

use nmrs::raw::zvariant::Value;

use crate::nm::{ApSecurity, IpSettings, StaticIp};
use crate::secret::Secret;
use crate::ssid::Ssid;

/// NetworkManager's `a{sa{sv}}` connection settings dictionary.
pub type Settings<'a> = HashMap<&'a str, HashMap<&'a str, Value<'a>>>;

/// Everything needed to describe the setup access point to NetworkManager.
#[derive(Debug, Clone)]
pub struct ApProfile {
    pub id: String,
    pub uuid: String,
    pub interface: String,
    pub ssid: Ssid,
    pub passphrase: Option<Secret>,
    pub security: ApSecurity,
    pub gateway: std::net::Ipv4Addr,
    pub prefix: u8,
    pub channel: Option<u32>,
}

/// Build the AP connection settings.
pub fn ap_settings(p: &ApProfile) -> Settings<'_> {
    let mut settings: Settings<'_> = HashMap::new();

    let mut connection: HashMap<&str, Value<'_>> = HashMap::new();
    connection.insert("id", Value::from(p.id.clone()));
    connection.insert("uuid", Value::from(p.uuid.clone()));
    connection.insert("type", Value::from("802-11-wireless"));
    connection.insert("interface-name", Value::from(p.interface.clone()));
    // CRITICAL. An AP profile that autoconnects resurrects itself after a
    // reboot and the device then never joins real WiFi again. That is a
    // known way to brick a signage player in the field.
    connection.insert("autoconnect", Value::from(false));
    settings.insert("connection", connection);

    let mut wireless: HashMap<&str, Value<'_>> = HashMap::new();
    // `ssid` is `ay` — a byte array, NOT a string. Passing `s` here is the
    // single most common way to get InvalidProperty back from NM.
    wireless.insert("ssid", Value::from(p.ssid.as_bytes().to_vec()));
    wireless.insert("mode", Value::from("ap"));
    // 2.4 GHz: every phone has it, and it avoids the regulatory-domain and
    // DFS complications that make 5 GHz AP mode fragile on embedded radios.
    wireless.insert("band", Value::from("bg"));
    wireless.insert("hidden", Value::from(false));
    if let Some(ch) = p.channel {
        wireless.insert("channel", Value::from(ch));
    }
    // Client-to-client isolation on the setup network: a second device that
    // joins the AP cannot reach the one doing setup, only the gateway (the
    // AP host itself), which is where the portal, DHCP and DNS live — so the
    // portal stays reachable. NM_TERNARY 1 = yes; the property is an int32.
    // Supported since NetworkManager 1.28 (2021); every target OS is newer.
    // The README's threat model relies on this being set.
    wireless.insert("ap-isolation", Value::from(1_i32));
    if p.passphrase.is_some() {
        wireless.insert("security", Value::from("802-11-wireless-security"));
    }
    settings.insert("802-11-wireless", wireless);

    if let Some(psk) = &p.passphrase {
        let mut sec: HashMap<&str, Value<'_>> = HashMap::new();
        match p.security {
            ApSecurity::Wpa3Sae => {
                sec.insert("key-mgmt", Value::from("sae"));
            }
            ApSecurity::Wpa2Psk => {
                sec.insert("key-mgmt", Value::from("wpa-psk"));
            }
        }
        sec.insert("proto", Value::from(vec!["rsn".to_string()]));
        sec.insert("pairwise", Value::from(vec!["ccmp".to_string()]));
        sec.insert("group", Value::from(vec!["ccmp".to_string()]));
        sec.insert("psk", Value::from(psk.expose().to_string()));
        // NM_SETTING_SECRET_FLAG_NONE: the secret is stored in the profile,
        // so NM never needs to ask an agent for it. Without this NM can park
        // the device in NEED_AUTH waiting for an agent that does not exist —
        // the classic "wifi-connect hangs forever".
        sec.insert("psk-flags", Value::from(0u32));
        settings.insert("802-11-wireless-security", sec);
    }

    let mut ipv4: HashMap<&str, Value<'_>> = HashMap::new();
    ipv4.insert("method", Value::from("manual"));
    let mut address: HashMap<String, Value<'_>> = HashMap::new();
    address.insert("address".into(), Value::from(p.gateway.to_string()));
    address.insert("prefix".into(), Value::from(u32::from(p.prefix)));
    ipv4.insert("address-data", Value::from(vec![address]));
    // The AP routes nowhere. Letting it become the system default route
    // would make NM's own connectivity check report LIMITED and confuse the
    // "are we already online?" gate.
    ipv4.insert("never-default", Value::from(true));
    ipv4.insert("may-fail", Value::from(false));
    settings.insert("ipv4", ipv4);

    let mut ipv6: HashMap<&str, Value<'_>> = HashMap::new();
    ipv6.insert("method", Value::from("ignore"));
    settings.insert("ipv6", ipv6);

    settings
}

/// Replace the `ipv4` and `ipv6` sections of a station profile with `ip`.
///
/// nmrs's builder has `ipv4_manual`, but nothing for IPv6 addresses or an
/// IPv6 gateway, and its DNS setter silently does nothing unless `ipv4` was
/// set first. Both families are built here instead, in one place, so their
/// exact D-Bus shapes can be asserted the same way the AP's are.
///
/// Every property used here dates from NetworkManager 1.0 or earlier, so
/// it works on any target OS.
pub fn apply_station_ip(settings: &mut Settings<'static>, ip: &IpSettings) {
    let v4_dns: Vec<u32> = ip
        .dns
        .iter()
        .filter_map(|a| match a {
            // `in_addr_t`: the octets in network order, read as a native
            // integer. `u32::from(Ipv4Addr)` is host order, and NM would
            // read it back with the octets reversed on every Pi.
            IpAddr::V4(v4) => Some(u32::from_ne_bytes(v4.octets())),
            IpAddr::V6(_) => None,
        })
        .collect();
    let v6_dns: Vec<Vec<u8>> = ip
        .dns
        .iter()
        .filter_map(|a| match a {
            IpAddr::V6(v6) => Some(v6.octets().to_vec()),
            IpAddr::V4(_) => None,
        })
        .collect();
    // Servers typed by hand replace what the network advertises, on *both*
    // families: "use these DNS servers" means these, not these as well as
    // whatever a router advertises over the other family.
    let custom_dns = !ip.dns.is_empty();

    let mut ipv4 = family_section(ip.ipv4.as_ref());
    if !v4_dns.is_empty() {
        ipv4.insert("dns", Value::from(v4_dns));
    }
    if custom_dns {
        ipv4.insert("ignore-auto-dns", Value::from(true));
    }
    settings.insert("ipv4", ipv4);

    let mut ipv6 = family_section(ip.ipv6.as_ref());
    if !v6_dns.is_empty() {
        ipv6.insert("dns", Value::from(v6_dns));
    }
    if custom_dns {
        ipv6.insert("ignore-auto-dns", Value::from(true));
    }
    settings.insert("ipv6", ipv6);
}

/// One family's section: `manual` with its address and gateway, or
/// `auto` (DHCP, or SLAAC/DHCPv6) when nothing was configured.
fn family_section<A: ToString>(
    fixed: Option<&StaticIp<A>>,
) -> HashMap<&'static str, Value<'static>> {
    let mut section: HashMap<&str, Value<'_>> = HashMap::new();
    let Some(fixed) = fixed else {
        section.insert("method", Value::from("auto"));
        return section;
    };
    section.insert("method", Value::from("manual"));
    let mut address: HashMap<String, Value<'_>> = HashMap::new();
    address.insert("address".into(), Value::from(fixed.address.to_string()));
    // u32, as for the AP: NM rejects any other integer type here.
    address.insert("prefix".into(), Value::from(u32::from(fixed.prefix)));
    section.insert("address-data", Value::from(vec![address]));
    if let Some(gateway) = &fixed.gateway {
        section.insert("gateway", Value::from(gateway.to_string()));
    }
    section
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmrs::raw::zvariant::Value;
    use std::net::Ipv4Addr;

    fn profile() -> ApProfile {
        ApProfile {
            id: "wifi-connect-ap".into(),
            uuid: "4d0a0f2e-0000-4000-8000-000000000001".into(),
            interface: "wlan0".into(),
            ssid: Ssid::from("Setup"),
            passphrase: Some(Secret::new("abcdefghijklmn")),
            security: ApSecurity::Wpa2Psk,
            gateway: Ipv4Addr::new(192, 168, 42, 1),
            prefix: 24,
            channel: None,
        }
    }

    fn get<'a>(s: &'a Settings<'a>, section: &str, key: &str) -> &'a Value<'a> {
        s.get(section)
            .unwrap_or_else(|| panic!("missing section {section}"))
            .get(key)
            .unwrap_or_else(|| panic!("missing {section}.{key}"))
    }

    /// The single most common cause of an opaque InvalidProperty from NM.
    #[test]
    fn ssid_is_a_byte_array_not_a_string() {
        let p = profile();
        let s = ap_settings(&p);
        let ssid = get(&s, "802-11-wireless", "ssid");

        match ssid {
            Value::Array(a) => {
                let bytes: Vec<u8> = a
                    .iter()
                    .map(|v| u8::try_from(v).expect("ssid elements must be bytes"))
                    .collect();
                assert_eq!(bytes, b"Setup".to_vec());
            }
            other => panic!("ssid must be ay, got {other:?}"),
        }
        assert!(
            !matches!(ssid, Value::Str(_)),
            "ssid must never be serialised as a string"
        );
    }

    #[test]
    fn non_utf8_ssid_reaches_networkmanager_intact() {
        let mut p = profile();
        let raw = vec![0x4d, 0x79, 0xff, 0xfe, 0x4e];
        p.ssid = Ssid::new(raw.clone());
        let s = ap_settings(&p);

        match get(&s, "802-11-wireless", "ssid") {
            Value::Array(a) => {
                let bytes: Vec<u8> = a.iter().map(|v| u8::try_from(v).unwrap()).collect();
                assert_eq!(bytes, raw);
            }
            other => panic!("expected ay, got {other:?}"),
        }
    }

    #[test]
    fn mode_is_ap_and_band_is_two_point_four_gigahertz() {
        let p = profile();
        let s = ap_settings(&p);
        assert_eq!(get(&s, "802-11-wireless", "mode"), &Value::from("ap"));
        assert_eq!(get(&s, "802-11-wireless", "band"), &Value::from("bg"));
    }

    /// Client-to-client isolation must be on: the README's threat model
    /// treats a second device on the setup AP as untrusted. `1` is the
    /// NM_TERNARY "yes"; the property is an int32, not a bool.
    #[test]
    fn ap_isolation_is_enabled() {
        let p = profile();
        let s = ap_settings(&p);
        assert_eq!(
            get(&s, "802-11-wireless", "ap-isolation"),
            &Value::from(1_i32)
        );
    }

    /// An autoconnecting AP profile is a bricking mode: after a reboot the
    /// device comes back up as a hotspot and never rejoins real WiFi.
    #[test]
    fn the_ap_profile_never_autoconnects() {
        let p = profile();
        let s = ap_settings(&p);
        assert_eq!(get(&s, "connection", "autoconnect"), &Value::from(false));
    }

    #[test]
    fn ipv4_is_manual_with_a_static_address() {
        let p = profile();
        let s = ap_settings(&p);
        assert_eq!(get(&s, "ipv4", "method"), &Value::from("manual"));
        assert_eq!(get(&s, "ipv4", "never-default"), &Value::from(true));
        assert_eq!(get(&s, "ipv6", "method"), &Value::from("ignore"));

        match get(&s, "ipv4", "address-data") {
            Value::Array(a) => {
                assert_eq!(a.len(), 1);
                let entry = a.iter().next().unwrap();
                let dict = match entry {
                    Value::Dict(d) => d,
                    other => panic!("address-data entries must be a{{sv}}, got {other:?}"),
                };
                let addr: String = dict.get(&"address").unwrap().unwrap();
                assert_eq!(addr, "192.168.42.1");
                // prefix must be u32: an i32 or u8 here is rejected by NM.
                let prefix: u32 = dict.get(&"prefix").unwrap().unwrap();
                assert_eq!(prefix, 24);
            }
            other => panic!("address-data must be aa{{sv}}, got {other:?}"),
        }
    }

    /// The CRA requirement in structural form: there is no code path that
    /// produces an AP with no security section when a passphrase is set.
    #[test]
    fn the_access_point_is_always_encrypted_when_a_passphrase_is_set() {
        let p = profile();
        let s = ap_settings(&p);
        let sec = s
            .get("802-11-wireless-security")
            .expect("the setup AP must carry a security section");

        assert_eq!(sec.get("key-mgmt").unwrap(), &Value::from("wpa-psk"));
        assert_eq!(sec.get("psk").unwrap(), &Value::from("abcdefghijklmn"));
        assert_eq!(sec.get("psk-flags").unwrap(), &Value::from(0u32));
        assert_eq!(
            sec.get("pairwise").unwrap(),
            &Value::from(vec!["ccmp".to_string()])
        );

        // The cross-reference NM needs in order to apply the section at all.
        assert_eq!(
            get(&s, "802-11-wireless", "security"),
            &Value::from("802-11-wireless-security")
        );
    }

    #[test]
    fn wpa3_mode_emits_sae() {
        let mut p = profile();
        p.security = ApSecurity::Wpa3Sae;
        let s = ap_settings(&p);
        assert_eq!(
            s.get("802-11-wireless-security")
                .unwrap()
                .get("key-mgmt")
                .unwrap(),
            &Value::from("sae")
        );
    }

    /// The `--insecure-open-portal` escape hatch. An open AP must omit the
    /// security section *and* the cross-reference: leaving an empty section
    /// behind is a common cause of "the open network will not connect".
    #[test]
    fn an_open_portal_omits_the_security_section_entirely() {
        let mut p = profile();
        p.passphrase = None;
        let s = ap_settings(&p);

        assert!(!s.contains_key("802-11-wireless-security"));
        assert!(
            s.get("802-11-wireless").unwrap().get("security").is_none(),
            "a dangling security cross-reference stops the AP associating"
        );
    }

    #[test]
    fn channel_is_only_present_when_pinned() {
        let p = profile();
        let s = ap_settings(&p);
        assert!(s.get("802-11-wireless").unwrap().get("channel").is_none());

        let mut p = profile();
        p.channel = Some(6);
        let s = ap_settings(&p);
        assert_eq!(get(&s, "802-11-wireless", "channel"), &Value::from(6u32));
    }

    #[test]
    fn the_profile_is_pinned_to_an_interface() {
        let p = profile();
        let s = ap_settings(&p);
        assert_eq!(
            get(&s, "connection", "interface-name"),
            &Value::from("wlan0")
        );
        assert_eq!(
            get(&s, "connection", "type"),
            &Value::from("802-11-wireless")
        );
    }

    fn static_ip() -> IpSettings {
        IpSettings {
            ipv4: Some(StaticIp {
                address: Ipv4Addr::new(192, 168, 1, 50),
                prefix: 24,
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            }),
            ipv6: Some(StaticIp {
                address: "2001:db8::50".parse().unwrap(),
                prefix: 64,
                gateway: Some("fe80::1".parse().unwrap()),
            }),
            dns: vec![
                "1.1.1.1".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
                "9.9.9.9".parse().unwrap(),
            ],
        }
    }

    fn station_with(ip: &IpSettings) -> Settings<'static> {
        let mut s: Settings<'static> = HashMap::new();
        // What nmrs's builder leaves behind, to prove it is replaced.
        let mut ipv4 = HashMap::new();
        ipv4.insert("method", Value::from("auto"));
        s.insert("ipv4", ipv4);
        apply_station_ip(&mut s, ip);
        s
    }

    /// The single `address-data` entry of a section, as (address, prefix).
    fn only_address(s: &Settings<'_>, section: &str) -> (String, u32) {
        match get(s, section, "address-data") {
            Value::Array(a) => {
                assert_eq!(a.len(), 1);
                let Value::Dict(d) = a.iter().next().unwrap() else {
                    panic!("address-data entries must be a{{sv}}");
                };
                (
                    d.get(&"address").unwrap().unwrap(),
                    d.get(&"prefix").unwrap().unwrap(),
                )
            }
            other => panic!("address-data must be aa{{sv}}, got {other:?}"),
        }
    }

    #[test]
    fn automatic_addressing_is_auto_on_both_families_and_nothing_else() {
        let s = station_with(&IpSettings::default());
        for family in ["ipv4", "ipv6"] {
            let section = s.get(family).unwrap();
            assert_eq!(section.get("method").unwrap(), &Value::from("auto"));
            assert_eq!(section.len(), 1, "{family} carries more than its method");
        }
    }

    #[test]
    fn a_static_ipv4_address_is_manual_with_its_gateway() {
        let s = station_with(&static_ip());
        assert_eq!(get(&s, "ipv4", "method"), &Value::from("manual"));
        assert_eq!(only_address(&s, "ipv4"), ("192.168.1.50".into(), 24));
        assert_eq!(get(&s, "ipv4", "gateway"), &Value::from("192.168.1.1"));
    }

    #[test]
    fn a_static_ipv6_address_is_manual_with_its_gateway() {
        let s = station_with(&static_ip());
        assert_eq!(get(&s, "ipv6", "method"), &Value::from("manual"));
        assert_eq!(only_address(&s, "ipv6"), ("2001:db8::50".into(), 64));
        assert_eq!(get(&s, "ipv6", "gateway"), &Value::from("fe80::1"));
    }

    #[test]
    fn the_families_are_independent() {
        let mut ip = static_ip();
        ip.ipv6 = None;
        ip.dns.clear();
        let s = station_with(&ip);
        assert_eq!(get(&s, "ipv4", "method"), &Value::from("manual"));
        assert_eq!(get(&s, "ipv6", "method"), &Value::from("auto"));

        let mut ip = static_ip();
        ip.ipv4 = None;
        let s = station_with(&ip);
        assert_eq!(get(&s, "ipv4", "method"), &Value::from("auto"));
        assert_eq!(get(&s, "ipv6", "method"), &Value::from("manual"));
    }

    #[test]
    fn no_gateway_means_no_gateway_property() {
        let mut ip = static_ip();
        ip.ipv4.as_mut().unwrap().gateway = None;
        ip.ipv6.as_mut().unwrap().gateway = None;
        let s = station_with(&ip);
        assert!(s.get("ipv4").unwrap().get("gateway").is_none());
        assert!(s.get("ipv6").unwrap().get("gateway").is_none());
    }

    /// `ipv4.dns` is `au` of `in_addr_t`: network-order octets read as a
    /// native integer. A host-order integer reaches NM byte-reversed.
    #[test]
    fn ipv4_dns_is_in_addr_t_in_the_order_given() {
        let s = station_with(&static_ip());
        let expected: Vec<u32> = [[1, 1, 1, 1], [9, 9, 9, 9]]
            .into_iter()
            .map(u32::from_ne_bytes)
            .collect();
        assert_eq!(get(&s, "ipv4", "dns"), &Value::from(expected));
    }

    #[test]
    fn ipv6_dns_is_an_array_of_sixteen_byte_arrays() {
        let s = station_with(&static_ip());
        let want: std::net::Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(
            get(&s, "ipv6", "dns"),
            &Value::from(vec![want.octets().to_vec()])
        );
    }

    /// Typed DNS servers replace the advertised ones on both families, even
    /// one with no server of its own and with automatic addressing.
    #[test]
    fn custom_dns_ignores_advertised_dns_on_both_families() {
        let ip = IpSettings {
            dns: vec!["1.1.1.1".parse().unwrap()],
            ..IpSettings::default()
        };
        let s = station_with(&ip);
        assert_eq!(get(&s, "ipv4", "method"), &Value::from("auto"));
        assert_eq!(get(&s, "ipv4", "ignore-auto-dns"), &Value::from(true));
        assert_eq!(get(&s, "ipv6", "ignore-auto-dns"), &Value::from(true));
        assert!(s.get("ipv6").unwrap().get("dns").is_none());
    }
}
