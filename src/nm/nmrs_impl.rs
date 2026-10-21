//! The real [`NetworkControl`], backed by `nmrs`.
//!
//! We depend on `nmrs` rather than driving D-Bus ourselves because it has
//! already solved the part of this problem that is genuinely hard, and that
//! we would have got wrong:
//!
//! NetworkManager reports only a generic `DEVICE_DISCONNECTED` on the
//! *active connection* when an association fails. The real reason lives on
//! the **device's** `StateChanged` signal as it passes through `FAILED` —
//! and NM moves the device `FAILED → DISCONNECTED (reason NONE)` within
//! milliseconds, so reading `Device.StateReason` afterwards returns nothing
//! useful. Capturing the reason therefore means subscribing to *both*
//! signal streams before activating and merging them. nmrs does exactly
//! that, and fixed a bug in its own implementation of it as recently as
//! 3.5.4. The naive version is what ships "the wrong password just hangs".
//!
//! What nmrs does not give us, we add here: the access-point settings map
//! (its builder has no `ipv4_manual`) and `WirelessCapabilities` (its dbus
//! module is private). Both go over nmrs's own bus connection.

use std::time::Duration;

use nmrs::raw::zbus;
use nmrs::{ConnectionError, NetworkManager, WifiSecurity};
use tracing::{debug, info, warn};

use super::proxies::{
    DEVICE_STATE_ACTIVATED, DeviceProxy, DeviceWirelessProxy, WIFI_MODE_AP, WIFI_MODE_INFRA,
    is_device_busy,
};
use super::security;
use super::settings::{ApProfile, ap_settings};
use super::{
    ApConfig, ApHandle, Connectivity, DeviceInfo, JoinFailure, JoinOutcome, JoinRequest,
    NetworkControl, NetworkError, WifiNetwork,
};
use crate::secret::Secret;
use crate::ssid::Ssid;

/// `connection.id` given to the access-point profile. Also what the startup
/// sweep matches on.
pub const AP_PROFILE_ID: &str = "wifi-connect-portal";

pub struct NmrsControl {
    nm: NetworkManager,
}

impl NmrsControl {
    pub async fn connect() -> Result<Self, NetworkError> {
        // nmrs calls zbus's `Connection::system()`, which honours
        // DBUS_SYSTEM_BUS_ADDRESS. That is how the balena container reaches
        // the host bus at /host/run/dbus/system_bus_socket — set in the
        // environment, never with std::env::set_var, which is unsafe in
        // edition 2024 and must precede any thread spawn.
        let nm = NetworkManager::new()
            .await
            .map_err(|e| NetworkError::Unreachable(e.to_string()))?;
        Ok(Self { nm })
    }

    fn bus(&self) -> &zbus::Connection {
        self.nm.dbus_connection()
    }

    /// Read the properties nmrs does not expose, over its own connection.
    async fn device_extras(&self, path: &zbus::zvariant::OwnedObjectPath) -> (u32, u32, String) {
        let wireless = DeviceWirelessProxy::builder(self.bus())
            .path(path.clone())
            .ok()
            .map(|b| b.build());

        let (capabilities, mode) = match wireless {
            Some(fut) => match fut.await {
                Ok(p) => (
                    p.wireless_capabilities().await.unwrap_or(0),
                    p.mode().await.unwrap_or(0),
                ),
                Err(e) => {
                    warn!(error = %e, "could not read wireless capabilities");
                    (0, 0)
                }
            },
            None => (0, 0),
        };

        let driver = match DeviceProxy::builder(self.bus()).path(path.clone()) {
            Ok(b) => match b.build().await {
                Ok(p) => p.driver().await.unwrap_or_default(),
                Err(_) => String::new(),
            },
            Err(_) => String::new(),
        };

        (capabilities, mode, driver)
    }

    /// Join a network whose SSID is not broadcast.
    ///
    /// Built by hand because nmrs's `connect` family cannot set
    /// `802-11-wireless.hidden`, without which the supplicant never sends a
    /// directed probe and the association never completes.
    ///
    /// The tradeoff is weaker failure reporting: `add_and_activate_connection`
    /// returns once activation has *started*, not once it has finished, so
    /// there is no merged device/active-connection signal to read a reason
    /// from and we can only distinguish success from timeout. Acceptable on
    /// this path: the user typed the SSID themselves, so they already know
    /// which network they meant.
    async fn join_hidden(
        &self,
        device: &DeviceInfo,
        request: &JoinRequest,
        budget: Duration,
    ) -> Result<JoinOutcome, NetworkError> {
        use nmrs::builders::{WifiConnectionBuilder, WifiMode};

        let ssid = request.ssid.to_display_string();
        let mut builder = WifiConnectionBuilder::new(ssid.clone())
            .mode(WifiMode::Infrastructure)
            .hidden(true)
            .autoconnect(true)
            .ipv4_auto()
            .ipv6_auto();

        builder = match classify_credentials(request) {
            Credential::Psk(psk) => builder.wpa_psk(psk.expose()),
            Credential::Eap { identity, password } => builder
                .try_wpa_eap(nmrs::EapOptions::new(
                    identity.to_string(),
                    password.expose(),
                ))
                .map_err(|e| NetworkError::Other(e.to_string()))?,
            Credential::Open => builder.open(),
        };

        if let Err(e) = self
            .nm
            .add_and_activate_connection(builder.build(), Some(&device.interface), None)
            .await
        {
            debug!(error = %e, "hidden network activation failed");
            // `add_and_activate_connection` persists the profile before it
            // reports the failure, so delete it rather than leaving an
            // autoconnect-enabled bad profile behind.
            self.delete_profile_quietly(&ssid).await;
            return Ok(JoinOutcome::Failed(classify_failure(&e)));
        }

        let deadline = tokio::time::Instant::now() + budget;
        loop {
            if self.nm.is_connected(&ssid).await.unwrap_or(false) {
                return Ok(JoinOutcome::Joined);
            }
            if tokio::time::Instant::now() >= deadline {
                // The profile was created with autoconnect on; left behind,
                // NetworkManager would keep retrying a known-bad network on
                // every scan. Clean up on the way out so this path does not
                // rely on the caller to do it.
                self.delete_profile_quietly(&ssid).await;
                return Ok(JoinOutcome::Failed(JoinFailure::Timeout));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Delete a saved connection by name, swallowing "nothing to delete".
    async fn delete_profile_quietly(&self, name: &str) {
        match self.nm.forget(name).await {
            Ok(()) | Err(ConnectionError::NoSavedConnection) => {}
            Err(e) => debug!(error = %e, name, "could not delete the profile"),
        }
    }

    /// Trigger a scan and wait, briefly, for `target` to appear in the BSS
    /// cache. Best-effort: `scan_networks` only issues a RequestScan and
    /// returns before results land, so this polls `list_access_points` until
    /// the SSID shows up or a deadline elapses. Compares raw bytes, since an
    /// SSID need not be valid UTF-8.
    async fn rescan_for(&self, interface: &str, target: &Ssid) {
        if let Err(e) = self.nm.scan_networks(Some(interface)).await {
            debug!(error = %e, "RequestScan before join was refused");
        }
        let want = target.as_bytes();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if let Ok(aps) = self.nm.list_access_points(Some(interface)).await
                && aps.iter().any(|ap| ap.ssid_bytes.as_slice() == want)
            {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    /// Poll the device state until it is out of any transitional state, or a
    /// short deadline elapses. Best-effort: any read failure ends the wait
    /// rather than blocking the join.
    async fn wait_until_device_idle(&self, interface: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let busy = match self.nm.wifi_device_by_interface(interface).await {
                Ok(dev) => match DeviceProxy::builder(self.bus()).path(dev.path.clone()) {
                    Ok(b) => match b.build().await {
                        Ok(p) => p.state().await.map(is_device_busy).unwrap_or(false),
                        Err(_) => false,
                    },
                    Err(_) => false,
                },
                Err(_) => false,
            };
            if !busy || tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
}

/// The credential shape a submission implies.
///
/// Decided in one place so the two code paths that need it — the broadcast
/// `try_connect` path via [`credentials_for`] and the hidden-network builder
/// path in [`NmrsBackend::join_hidden`] — cannot drift. Two copies of this
/// classification is exactly the single-source-of-truth problem the portal's
/// server-rendered `needs-*` booleans set out to remove on the UI side.
enum Credential<'a> {
    Psk(&'a Secret),
    // PEAP/MSCHAPv2 and TTLS/PAP are the 90% of enterprise WiFi.
    // Certificate-based EAP-TLS needs key and certificate paths that a
    // captive portal has no way to collect.
    //
    // Known limitation, documented in the README: without a
    // `domain_suffix_match` the supplicant accepts any server certificate
    // the CA store chains to, so this is not proof against a determined
    // on-path attacker.
    Eap {
        identity: &'a str,
        password: &'a Secret,
    },
    // An identity with no password, or neither: treat as open.
    // NetworkManager rejects a security section with nothing in it.
    Open,
}

fn classify_credentials(request: &JoinRequest) -> Credential<'_> {
    match (&request.passphrase, &request.identity) {
        (Some(psk), None) => Credential::Psk(psk),
        (Some(password), Some(identity)) => Credential::Eap {
            identity: identity.as_str(),
            password,
        },
        _ => Credential::Open,
    }
}

/// Build the credentials nmrs wants from a portal submission.
fn credentials_for(request: &JoinRequest) -> WifiSecurity {
    match classify_credentials(request) {
        Credential::Psk(psk) => WifiSecurity::WpaPsk {
            psk: psk.expose().to_string(),
        },
        Credential::Eap { identity, password } => WifiSecurity::WpaEap {
            opts: nmrs::EapOptions::new(identity.to_string(), password.expose()),
        },
        Credential::Open => WifiSecurity::Open,
    }
}

/// Map an nmrs error to a user-facing reason.
///
/// NetworkManager genuinely cannot separate "wrong pre-shared key" from
/// "the AP stopped responding during the four-way handshake" — both land in
/// the supplicant family. We report a rejected password, because it is
/// right the overwhelming majority of the time and because it is the only
/// version a user can act on. "Supplicant disconnected" is right always and
/// actionable never.
fn classify_failure(e: &ConnectionError) -> JoinFailure {
    match e {
        ConnectionError::AuthFailed
        | ConnectionError::MissingPassword
        | ConnectionError::SupplicantTimeout => JoinFailure::BadPassword,
        ConnectionError::NotFound => JoinFailure::SsidNotFound,
        ConnectionError::DhcpFailed => JoinFailure::DhcpFailed,
        ConnectionError::SupplicantConfigFailed => JoinFailure::Unsupported,
        ConnectionError::Timeout | ConnectionError::Stuck(_) => JoinFailure::Timeout,
        _ => JoinFailure::Other,
    }
}

/// A device fully activated in infrastructure mode: a connected station.
/// An activated *access point* is not one — that is a previous run's AP,
/// which the startup sweep deals with.
fn is_activated_station(device_state: u32, wifi_mode: u32) -> bool {
    device_state == DEVICE_STATE_ACTIVATED && wifi_mode == WIFI_MODE_INFRA
}

fn to_connectivity(state: nmrs::ConnectivityState) -> Connectivity {
    match state {
        nmrs::ConnectivityState::Full => Connectivity::Full,
        nmrs::ConnectivityState::Limited | nmrs::ConnectivityState::Portal => Connectivity::Limited,
        nmrs::ConnectivityState::None => Connectivity::None,
        nmrs::ConnectivityState::Unknown => Connectivity::Unknown,
        // The enum is #[non_exhaustive]. A state we have never heard of
        // must not read as "online": that would skip the portal on a device
        // that needs it, which is the worse of the two failures.
        _ => Connectivity::Unknown,
    }
}

/// Map nmrs's decoded security flags onto ours.
///
/// `AccessPoint` is used rather than `Network` precisely because it carries
/// these: `Network` collapses everything to `secured`/`is_psk`/`is_eap`,
/// which cannot tell OWE from WEP (one takes no password, the other does)
/// nor WPA3-only from WPA2.
fn features_of(s: &nmrs::SecurityFeatures) -> security::Features {
    security::Features {
        privacy: s.privacy,
        psk: s.psk,
        eap: s.eap,
        sae: s.sae,
        owe: s.owe,
        owe_transition: s.owe_transition_mode,
        eap_suite_b_192: s.eap_suite_b_192,
    }
}

#[async_trait::async_trait]
impl NetworkControl for NmrsControl {
    async fn find_device(&self, interface: Option<&str>) -> Result<DeviceInfo, NetworkError> {
        let device = match interface {
            Some(name) => self
                .nm
                .wifi_device_by_interface(name)
                .await
                .map_err(|_| NetworkError::NoWifiDevice)?,
            None => self
                .nm
                .list_wifi_devices()
                .await
                .map_err(|e| NetworkError::Other(e.to_string()))?
                .into_iter()
                .next()
                .ok_or(NetworkError::NoWifiDevice)?,
        };

        let (capabilities, mode, driver_extra) = self.device_extras(&device.path).await;
        if mode == WIFI_MODE_AP {
            warn!(
                interface = %device.interface,
                "the radio is already in AP mode; a previous run probably crashed"
            );
        }

        // rfkill. A hardware-blocked radio cannot be turned on in software,
        // so this has to be its own message: "no access point could be
        // raised" sends someone hunting a driver bug when the real answer
        // is a physical switch or a stuck rfkill soft-block.
        match self.nm.wifi_state().await {
            Ok(radio) if !radio.hardware_enabled => return Err(NetworkError::RadioBlocked),
            Ok(radio) if !radio.enabled => {
                // Soft-blocked, which we are allowed to undo.
                info!("the WiFi radio is disabled; enabling it");
                if let Err(e) = self.nm.set_wireless_enabled(true).await {
                    debug!(error = %e, "could not enable the WiFi radio");
                    return Err(NetworkError::RadioBlocked);
                }
                // `set_wireless_enabled` returns before NetworkManager has
                // actually brought the radio up. Raising the AP on a
                // not-yet-ready radio fails transiently and surfaces as the
                // misleading "no access point could be raised". Wait for the
                // radio to report enabled before proceeding.
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    match self.nm.wifi_state().await {
                        Ok(r) if r.enabled => break,
                        _ if tokio::time::Instant::now() >= deadline => {
                            debug!("radio did not report enabled within the deadline");
                            break;
                        }
                        _ => tokio::time::sleep(Duration::from_millis(150)).await,
                    }
                }
            }
            Ok(_) => {}
            Err(e) => debug!(error = %e, "could not read the radio state"),
        }

        Ok(DeviceInfo {
            interface: device.interface,
            driver: device.driver.unwrap_or(driver_extra),
            capabilities,
            managed: device.managed,
        })
    }

    async fn check_connectivity(&self) -> Result<Connectivity, NetworkError> {
        // The forcing call, not the cached `Connectivity` property, which
        // can be arbitrarily stale on a device that just booted.
        match self.nm.check_connectivity().await {
            Ok(s) => Ok(to_connectivity(s)),
            // Connectivity checking is disabled — NM's behaviour wherever no
            // check URI is configured, which includes Debian, Raspberry Pi
            // OS and Ubuntu Server/Core. "Unknown" is the honest answer;
            // `is_online` then asks whether the radio is a connected
            // station, so this must not be read as "offline".
            Err(ConnectionError::ConnectivityCheckDisabled) => {
                debug!("NetworkManager connectivity checking is disabled");
                Ok(Connectivity::Unknown)
            }
            Err(e) => Err(NetworkError::Other(e.to_string())),
        }
    }

    async fn station_activated(&self, device: &DeviceInfo) -> Result<bool, NetworkError> {
        // Best-effort: every failed read answers "not a station", which is
        // the behaviour from before this fallback existed — the portal
        // comes up.
        let dev = match self.nm.wifi_device_by_interface(&device.interface).await {
            Ok(dev) => dev,
            Err(e) => {
                debug!(error = %e, "could not look up the WiFi device");
                return Ok(false);
            }
        };
        let state = match DeviceProxy::builder(self.bus()).path(dev.path.clone()) {
            Ok(b) => match b.build().await {
                Ok(p) => p.state().await.unwrap_or_else(|e| {
                    debug!(error = %e, "could not read the WiFi device's State");
                    0
                }),
                Err(_) => 0,
            },
            Err(_) => 0,
        };
        let mode = match DeviceWirelessProxy::builder(self.bus()).path(dev.path) {
            Ok(b) => match b.build().await {
                Ok(p) => p.mode().await.unwrap_or_else(|e| {
                    debug!(error = %e, "could not read the WiFi device's Mode");
                    0
                }),
                Err(_) => 0,
            },
            Err(_) => 0,
        };
        let activated = is_activated_station(state, mode);
        debug!(
            state,
            mode,
            activated,
            "connectivity unknown; checking whether the radio is a connected station"
        );
        Ok(activated)
    }

    async fn saved_wifi_profile_count(&self) -> Result<usize, NetworkError> {
        let saved = self
            .nm
            .list_saved_connections()
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))?;

        Ok(saved
            .iter()
            .filter(|c| c.connection_type == "802-11-wireless" && c.id != AP_PROFILE_ID)
            .count())
    }

    async fn await_autoconnect(
        &self,
        device: &DeviceInfo,
        budget: Duration,
    ) -> Result<bool, NetworkError> {
        // Poll NM's own connectivity verdict rather than tracking device
        // state ourselves: "associated" is not the same as "usable", and
        // the whole point of the wait is to find out whether the device can
        // actually reach the internet. Through `is_online`, so that with
        // checking disabled — where the verdict is always Unknown — a WiFi
        // station that comes up still ends the wait, instead of the wait running
        // out and the access point being raised over that link.
        let deadline = tokio::time::Instant::now() + budget;
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            if self.is_online(device).await? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            interval.tick().await;
        }
    }

    async fn scan(&self, device: &DeviceInfo) -> Result<Vec<WifiNetwork>, NetworkError> {
        // Rate-limited by NetworkManager; a refusal is not fatal, because
        // the cached access points are usually fresh enough and the portal
        // offers manual entry regardless.
        if let Err(e) = self.nm.scan_networks(Some(&device.interface)).await {
            debug!(error = %e, "RequestScan refused; falling back to cached results");
        }

        // `list_access_points`, not `list_networks`: the former carries the
        // raw SSID bytes and the full security flags. `Network` collapses
        // security to secured/is_psk/is_eap, which cannot distinguish OWE
        // (no password) from WEP (a password), and loses the exact SSID
        // bytes that a non-UTF-8 network needs to be joinable at all.
        let aps = self
            .nm
            .list_access_points(Some(&device.interface))
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))?;

        let mut out: Vec<WifiNetwork> = aps
            .iter()
            // Drop other hotspots (including our own, if a previous run
            // left one up) and hidden networks, whose SSID comes back
            // empty and which have to be typed in by hand anyway.
            .filter(|ap| ap.mode != nmrs::ApMode::Ap && !ap.ssid_bytes.is_empty())
            .map(|ap| {
                WifiNetwork::new(
                    Ssid::new(ap.ssid_bytes.clone()),
                    ap.strength,
                    security::classify(features_of(&ap.security)),
                    Some(ap.frequency_mhz),
                )
            })
            .collect();

        // Strongest first, then one row per SSID: several access points on
        // one network would otherwise fill the list with duplicates.
        out.sort_by_key(|a| std::cmp::Reverse(a.strength));
        out.dedup_by(|a, b| a.ssid_hex == b.ssid_hex);
        Ok(out)
    }

    async fn raise_ap(
        &self,
        device: &DeviceInfo,
        config: &ApConfig,
    ) -> Result<ApHandle, NetworkError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let profile = ApProfile {
            id: AP_PROFILE_ID.to_string(),
            uuid: uuid.clone(),
            interface: device.interface.clone(),
            ssid: config.ssid.clone(),
            passphrase: config.passphrase.clone(),
            security: config.security,
            gateway: config.gateway,
            prefix: config.prefix,
            channel: config.channel,
        };
        let settings = ap_settings(&profile);

        // `specific_object` is "/" for AP mode: there is no access point to
        // target, we are becoming one.
        self.nm
            .add_and_activate_connection(settings, Some(&device.interface), None)
            .await
            .map_err(|e| NetworkError::ApFailed(e.to_string()))?;

        info!(ssid = %config.ssid, interface = %device.interface, "access point raised");
        Ok(ApHandle {
            uuid,
            interface: device.interface.clone(),
        })
    }

    async fn tear_down_ap(&self, handle: &ApHandle) -> Result<(), NetworkError> {
        // Deactivate by the connection's UUID (NetworkManager finds the
        // matching active connection itself) and then delete the profile. A
        // "not active" / "no saved connection" error is success from our
        // point of view: the AP is gone, which is what we wanted.
        if let Err(e) = self.nm.disconnect_by_uuid(&handle.uuid).await {
            debug!(error = %e, "deactivating the access point was a no-op");
        }
        if let Err(e) = self.nm.forget(AP_PROFILE_ID).await {
            debug!(error = %e, "deleting the access-point profile was a no-op");
        }
        // Deactivation is asynchronous: NetworkManager moves the device
        // ACTIVATED -> DEACTIVATING -> DISCONNECTED over several hundred
        // milliseconds. A station join started while it is still
        // DEACTIVATING is rejected outright, so wait for the radio to settle
        // before returning to the caller, which joins next.
        self.wait_until_device_idle(&handle.interface).await;
        Ok(())
    }

    async fn join(
        &self,
        device: &DeviceInfo,
        request: &JoinRequest,
        budget: Duration,
    ) -> Result<JoinOutcome, NetworkError> {
        let ssid = request.ssid.to_display_string();

        // A hidden network needs `802-11-wireless.hidden = true` in the
        // profile, or the supplicant never sends a directed probe and the
        // association simply never completes. nmrs's `connect` family has
        // no hidden option, so that path builds the profile itself.
        if request.hidden {
            return self.join_hidden(device, request, budget).await;
        }

        // The radio could not scan while it was the access point, so its BSS
        // cache is stale by the time we get here. Without a fresh scan,
        // `try_connect` returns "network not found" for a network that is
        // actually in range — including the one the portal just showed the
        // user. Rescan and wait, briefly, for the target to reappear.
        self.rescan_for(&device.interface, &request.ssid).await;

        let attempt = tokio::time::timeout(
            budget,
            self.nm
                .try_connect(&ssid, Some(&device.interface), credentials_for(request)),
        )
        .await;

        match attempt {
            Ok(Ok(())) => Ok(JoinOutcome::Joined),
            Ok(Err(e)) => {
                debug!(error = %e, "join failed");
                Ok(JoinOutcome::Failed(classify_failure(&e)))
            }
            // The hard cap. Without it, a profile missing its secret parks
            // the device in NEED_AUTH waiting for an agent that does not
            // exist, and the tool hangs forever.
            Err(_) => Ok(JoinOutcome::Failed(JoinFailure::Timeout)),
        }
    }

    async fn forget(&self, ssid: &Ssid) -> Result<(), NetworkError> {
        match self.nm.forget(&ssid.to_display_string()).await {
            Ok(()) => Ok(()),
            // Nothing to delete is the normal case when the profile was
            // never created.
            Err(ConnectionError::NoSavedConnection) => Ok(()),
            Err(e) => Err(NetworkError::Other(e.to_string())),
        }
    }

    async fn restore(&self, device: &DeviceInfo) -> Result<(), NetworkError> {
        // Make sure the radio is on and the device is managed, so that
        // NetworkManager's own autoconnect can take over from here.
        if let Err(e) = self.nm.set_device_managed(&device.interface, true).await {
            debug!(error = %e, "device was already managed");
        }
        if let Err(e) = self.nm.set_wireless_enabled(true).await {
            debug!(error = %e, "radio was already enabled");
        }
        Ok(())
    }

    async fn sweep_stale_ap_profiles(&self, interface: &str) -> Result<usize, NetworkError> {
        let saved = self
            .nm
            .list_saved_connections()
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))?;

        let mut removed = 0;
        for c in saved {
            let ours = c.id == AP_PROFILE_ID;
            let on_our_interface = c.interface_name.as_deref() == Some(interface);
            if ours && on_our_interface {
                match self.nm.delete_saved_connection(&c.uuid).await {
                    Ok(()) => removed += 1,
                    Err(e) => warn!(error = %e, uuid = %c.uuid, "could not delete a stale profile"),
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::security::Security;

    /// These three map to genuinely different things a user must do, so
    /// collapsing any of them into "connection failed" loses real
    /// information.
    #[test]
    fn failures_map_to_distinguishable_causes() {
        assert_eq!(
            classify_failure(&ConnectionError::AuthFailed),
            JoinFailure::BadPassword
        );
        assert_eq!(
            classify_failure(&ConnectionError::SupplicantTimeout),
            JoinFailure::BadPassword,
            "NM cannot separate a bad PSK from a vanishing AP; a rejected \
             password is the actionable reading"
        );
        assert_eq!(
            classify_failure(&ConnectionError::NotFound),
            JoinFailure::SsidNotFound
        );
        assert_eq!(
            classify_failure(&ConnectionError::DhcpFailed),
            JoinFailure::DhcpFailed
        );
        assert_eq!(
            classify_failure(&ConnectionError::SupplicantConfigFailed),
            JoinFailure::Unsupported
        );
        assert_eq!(
            classify_failure(&ConnectionError::Timeout),
            JoinFailure::Timeout
        );
    }

    #[test]
    fn connectivity_collapses_portal_and_limited() {
        // Both mean "associated but not usable", which is the only
        // distinction the gate cares about.
        assert_eq!(
            to_connectivity(nmrs::ConnectivityState::Full),
            Connectivity::Full
        );
        assert_eq!(
            to_connectivity(nmrs::ConnectivityState::Portal),
            Connectivity::Limited
        );
        assert_eq!(
            to_connectivity(nmrs::ConnectivityState::Limited),
            Connectivity::Limited
        );
        assert_eq!(
            to_connectivity(nmrs::ConnectivityState::None),
            Connectivity::None
        );
    }

    /// `SecurityFeatures` is #[non_exhaustive], so it is built from
    /// Default and then mutated rather than with a struct literal.
    fn features(set: impl Fn(&mut nmrs::SecurityFeatures)) -> nmrs::SecurityFeatures {
        let mut f = nmrs::SecurityFeatures::default();
        set(&mut f);
        f
    }

    #[test]
    fn nmrs_security_flags_map_onto_ours() {
        let open = features(|_| {});
        assert_eq!(security::classify(features_of(&open)), Security::Open);

        let psk = features(|f| {
            f.privacy = true;
            f.psk = true;
        });
        assert_eq!(security::classify(features_of(&psk)), Security::WpaPsk);

        let eap = features(|f| {
            f.privacy = true;
            f.eap = true;
        });
        assert_eq!(security::classify(features_of(&eap)), Security::Enterprise);
    }

    /// The distinction `Network` cannot express, and the reason this
    /// implementation reads access points instead: OWE is encrypted but
    /// takes no password, while WEP (privacy and nothing else) does.
    #[test]
    fn owe_is_distinguished_from_wep() {
        let owe = features(|f| {
            f.privacy = true;
            f.owe = true;
        });
        let classified = security::classify(features_of(&owe));
        assert_eq!(classified, Security::Owe);
        assert!(
            !classified.needs_passphrase(),
            "OWE must not prompt for a password that does not exist"
        );

        let wep = features(|f| f.privacy = true);
        assert_eq!(security::classify(features_of(&wep)), Security::Wep);
        assert!(security::classify(features_of(&wep)).needs_passphrase());
    }

    /// The other distinction `Network` loses.
    #[test]
    fn wpa3_is_distinguished_from_wpa2() {
        let sae_only = features(|f| {
            f.privacy = true;
            f.sae = true;
        });
        assert_eq!(security::classify(features_of(&sae_only)), Security::Sae);

        let transitional = features(|f| {
            f.privacy = true;
            f.sae = true;
            f.psk = true;
        });
        assert_eq!(
            security::classify(features_of(&transitional)),
            Security::SaeTransitional
        );
    }

    #[test]
    fn enterprise_wins_when_both_are_advertised() {
        let both = features(|f| {
            f.privacy = true;
            f.psk = true;
            f.eap = true;
        });
        assert_eq!(security::classify(features_of(&both)), Security::Enterprise);
    }

    #[test]
    fn only_an_activated_infrastructure_device_is_a_station() {
        assert!(is_activated_station(
            DEVICE_STATE_ACTIVATED,
            WIFI_MODE_INFRA
        ));
        // Our own (or a crashed run's) access point is not a station.
        assert!(!is_activated_station(DEVICE_STATE_ACTIVATED, WIFI_MODE_AP));
        // Still getting an address, or disconnected, is not connected.
        assert!(!is_activated_station(70, WIFI_MODE_INFRA));
        assert!(!is_activated_station(30, WIFI_MODE_INFRA));
        // A failed read (zeroes) must fail towards "not a station".
        assert!(!is_activated_station(0, 0));
    }

    #[test]
    fn the_ap_profile_id_is_stable() {
        // The startup sweep matches on it, so renaming it would orphan
        // profiles left behind by an older build.
        assert_eq!(AP_PROFILE_ID, "wifi-connect-portal");
    }
}
