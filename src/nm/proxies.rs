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
}

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
