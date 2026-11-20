//! Thin D-Bus proxies for the few NetworkManager properties `nmrs` does not
//! expose.
//!
//! `nmrs` reads `WirelessCapabilities` internally but its `dbus` module is
//! private and nothing re-exports it, and we need it for the access-point
//! preflight. Rather than fork or vendor anything, we define the proxies we
//! are missing and run them over **nmrs's own connection**
//! (`NetworkManager::dbus_connection`), so there is exactly one bus
//! connection and exactly one zbus in the dependency tree.
//!
//! zbus is reached through `nmrs::raw` rather than as a direct dependency
//! for the same reason: two semver-incompatible zbus copies would mean two
//! incompatible `Connection` types, and the proxies below could not be
//! built from nmrs's connection at all.

use nmrs::raw::zbus;

/// `org.freedesktop.NetworkManager.Device.Wireless`.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait DeviceWireless {
    /// `NM_WIFI_DEVICE_CAP_*` bitfield. Bit 0x40 is AP mode.
    ///
    /// NetworkManager derives this from the kernel's nl80211
    /// `supported_iftypes`, so it is accurate for mainline drivers.
    #[zbus(property)]
    fn wireless_capabilities(&self) -> zbus::Result<u32>;

    /// `NM_802_11_MODE_*`. 3 is AP — seeing that at startup means a
    /// previous run crashed with the access point still up.
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<u32>;

    /// The factory MAC, which survives MAC randomisation. Used to derive a
    /// stable per-device default SSID suffix.
    #[zbus(property)]
    fn perm_hw_address(&self) -> zbus::Result<String>;
}

/// `org.freedesktop.NetworkManager.Device`.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Device {
    #[zbus(property)]
    fn driver(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn udi(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn managed(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;

    /// `NM_DEVICE_STATE_*`. Polled at AP teardown to tell when the radio has
    /// finished leaving the access-point connection, so a station join is
    /// not started while the device is still deactivating.
    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;

    /// `NM_DEVICE_TYPE_*`. Used to tell a real network interface from the
    /// container plumbing that shares a host with us.
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;
}

/// `org.freedesktop.NetworkManager`, for the device list.
///
/// `nmrs` can find a device by interface name but will not enumerate them,
/// and the "is this host online some other way" question has to look at
/// every device rather than one we can already name.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
pub trait NetworkManagerRoot {
    fn get_devices(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;

    /// Whether NetworkManager was built with connectivity checking at all.
    ///
    /// When this is false, `Connectivity` is not a measurement — it is
    /// NetworkManager's guess from the routing table, and it is
    /// confident about it. Measured on balenaOS: `full` with a cable in,
    /// `limited` with it out, with no probe behind either.
    #[zbus(property)]
    fn connectivity_check_available(&self) -> zbus::Result<bool>;
}

/// The device types that count as "this host has a network".
///
/// An allowlist, not a blocklist, and that is deliberate. A host running
/// containers is covered in interfaces NetworkManager can see — veths,
/// bridges, tunnels, overlays — and several of them report as
/// `ETHERNET` in older NetworkManager versions, so excluding the ones we
/// know about today would quietly start counting whatever Docker
/// invents next. These three are the ways a signage device is actually
/// on a network.
/// Does one NetworkManager device prove this host has a network?
///
/// Split out from the D-Bus walk so the judgement can be tested without
/// a bus: it is the part that decides whether a screen gets an access
/// point raised at it, and the inputs are three integers whose meanings
/// are easy to get wrong.
pub fn counts_as_online(device_type: u32, managed: bool, state: u32) -> bool {
    managed && state == DEVICE_STATE_ACTIVATED && ONLINE_DEVICE_TYPES.contains(&device_type)
}

/// Is one NetworkManager device on its way to proving this host has a
/// network, but not there yet?
///
/// The boot race this exists for: a wired screen whose link is still
/// negotiating or waiting on DHCP when the gate runs. `counts_as_online`
/// rightly says no -- it is not carrying traffic yet -- and a device with
/// no saved WiFi profile used to get an access point raised at it there
/// and then, a few seconds before the cable came up.
///
/// The activating band (40 PREPARE ... 90 SECONDARIES) for every type
/// that would count once it got there. 30 DISCONNECTED too, but only for
/// ethernet: NetworkManager holds a wired port in UNAVAILABLE until it
/// has carrier, so DISCONNECTED there means a cable is in and activation
/// has not started yet. On a radio it is the ordinary idle state, and
/// counting it would make every run with a spare radio sit out the wait.
pub fn is_settling(device_type: u32, managed: bool, state: u32) -> bool {
    if !managed || !ONLINE_DEVICE_TYPES.contains(&device_type) {
        return false;
    }
    matches!(state, 40 | 50 | 60 | 70 | 80 | 90)
        || (device_type == DEVICE_TYPE_ETHERNET && state == DEVICE_STATE_DISCONNECTED)
}

/// `NM_DEVICE_TYPE_ETHERNET`.
pub const DEVICE_TYPE_ETHERNET: u32 = 1;

/// `NM_DEVICE_STATE_DISCONNECTED`.
pub const DEVICE_STATE_DISCONNECTED: u32 = 30;

pub const ONLINE_DEVICE_TYPES: [u32; 3] = [
    1, // NM_DEVICE_TYPE_ETHERNET
    2, // NM_DEVICE_TYPE_WIFI -- a second radio, already associated
    8, // NM_DEVICE_TYPE_MODEM -- cellular, common on balena fleets
];

/// `NM_802_11_MODE_INFRA`: a station, as opposed to an access point.
pub const WIFI_MODE_INFRA: u32 = 2;

/// `NM_802_11_MODE_AP`.
pub const WIFI_MODE_AP: u32 = 3;

/// `NM_DEVICE_STATE_ACTIVATED`.
pub const DEVICE_STATE_ACTIVATED: u32 = 100;

/// `true` while a device is mid-transition: `NM_DEVICE_STATE` in the
/// activating band (40 PREPARE … 90 SECONDARIES) or 110 DEACTIVATING.
/// Starting a station join in any of these states makes NetworkManager
/// reject it with `ConnectionInProgress` ("a connection operation is already
/// in progress"), which is how a join launched milliseconds after AP
/// teardown silently fails.
pub fn is_device_busy(state: u32) -> bool {
    matches!(state, 40 | 50 | 60 | 70 | 80 | 90 | 110)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wired screen: the case the whole predicate exists for.
    #[test]
    fn an_activated_ethernet_link_is_a_network() {
        assert!(counts_as_online(1, true, DEVICE_STATE_ACTIVATED));
    }

    /// Cellular, and a second radio that is already associated.
    #[test]
    fn a_modem_or_a_second_radio_is_a_network() {
        assert!(counts_as_online(8, true, DEVICE_STATE_ACTIVATED));
        assert!(counts_as_online(2, true, DEVICE_STATE_ACTIVATED));
    }

    /// The reason this is an allowlist. A host running containers is
    /// covered in interfaces NetworkManager can see, and a false
    /// positive here is a device that never raises the portal it needs
    /// — the failure nobody notices, because the symptom is a screen
    /// that simply never offers setup.
    #[test]
    fn container_plumbing_is_not_a_network() {
        for device_type in [
            13, // BRIDGE   -- docker0
            20, // VETH     -- one per container
            16, // TUN      -- vpn, tailscale
            17, // IP_TUNNEL
            19, // VXLAN    -- swarm overlay
            14, // GENERIC
            0,  // UNKNOWN
        ] {
            assert!(
                !counts_as_online(device_type, true, DEVICE_STATE_ACTIVATED),
                "device type {device_type} counted as a network"
            );
        }
    }

    /// Unmanaged is NetworkManager saying it does not drive this
    /// interface, so its state means nothing — and it is how container
    /// veths usually present even when they report as ethernet.
    #[test]
    fn an_unmanaged_interface_is_not_a_network() {
        assert!(!counts_as_online(1, false, DEVICE_STATE_ACTIVATED));
    }

    /// A wired link mid-activation -- getting a DHCP lease, say -- is
    /// worth waiting for, and so is one with carrier that has not
    /// started activating yet.
    #[test]
    fn a_wired_link_coming_up_is_settling() {
        for state in [30, 40, 50, 60, 70, 80, 90] {
            assert!(
                is_settling(1, true, state),
                "ethernet in state {state} was not settling"
            );
        }
    }

    /// A modem or second radio mid-activation is settling, but an idle
    /// one is not: DISCONNECTED is where a spare radio lives.
    #[test]
    fn an_idle_radio_is_not_settling() {
        assert!(is_settling(2, true, 70));
        assert!(is_settling(8, true, 50));
        assert!(!is_settling(2, true, 30));
        assert!(!is_settling(8, true, 30));
    }

    /// Nothing to wait for: no cable, already up, failed, going down, or
    /// not a kind of device that would count once it got there.
    #[test]
    fn links_that_are_not_on_their_way_up_are_not_settling() {
        for state in [10, 20, 100, 110, 120] {
            assert!(
                !is_settling(1, true, state),
                "ethernet in state {state} counted as settling"
            );
        }
        assert!(!is_settling(1, false, 70), "an unmanaged port");
        assert!(!is_settling(20, true, 70), "a container veth");
        assert!(!is_settling(13, true, 70), "a bridge");
    }

    /// Anything short of activated is a link that is not carrying
    /// traffic: no carrier, mid-DHCP, or failed.
    #[test]
    fn a_link_that_is_not_up_is_not_a_network() {
        for state in [10, 20, 30, 40, 50, 60, 70, 80, 90, 110, 120] {
            assert!(
                !counts_as_online(1, true, state),
                "device state {state} counted as a network"
            );
        }
    }
}
