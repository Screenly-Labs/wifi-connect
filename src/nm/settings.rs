//! Building the NetworkManager connection-settings map for the setup AP.
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

use nmrs::raw::zvariant::Value;

use crate::nm::ApSecurity;
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
}
