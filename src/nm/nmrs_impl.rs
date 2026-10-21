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

use super::proxies::{DeviceProxy, DeviceWirelessProxy, WIFI_MODE_AP, is_device_busy};
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

    /// Join by building the station profile ourselves rather than through
    /// nmrs's `connect`.
    ///
    /// Two callers need this:
    ///
    /// * A network whose SSID is not broadcast (`hidden`). nmrs's `connect`
    ///   family cannot set `802-11-wireless.hidden`, without which the
    ///   supplicant never sends a directed probe and the association never
    ///   completes.
    /// * An open join for a network that already has a saved profile, when
    ///   that profile cannot be listed or does not come up; see
    ///   [`route_join`] for why nmrs must not handle that one.
    ///
    /// The profile gets a UUID we mint, so on failure we delete exactly that
    /// profile and nothing that merely shares its name.
    ///
    /// The tradeoff is less precise failure reporting than `try_connect`,
    /// which merges the device's and the active connection's state signals
    /// to recover the real reason; here a failure is classified from
    /// whatever error activation returns, and often reads as a timeout.
    /// Acceptable on both: a hidden SSID was typed by the user, so they
    /// already know which network they meant, and the open fallback reports
    /// the saved profile's reason instead of its own.
    async fn join_with_own_profile(
        &self,
        device: &DeviceInfo,
        request: &JoinRequest,
        budget: Duration,
    ) -> Result<JoinOutcome, NetworkError> {
        use nmrs::builders::{WifiConnectionBuilder, WifiMode};

        let mut builder = WifiConnectionBuilder::new(request.ssid.to_display_string())
            .mode(WifiMode::Infrastructure)
            .hidden(request.hidden)
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

        // Our UUID, not the builder's random one, so the profile can be
        // found again — and deleted — without going by its name.
        let uuid = uuid::Uuid::new_v4().to_string();
        let mut settings = builder.build();
        if let Some(connection) = settings.get_mut("connection") {
            connection.insert("uuid", zbus::zvariant::Value::from(uuid.clone()));
        }

        // nmrs waits for activation here under its own 30 s timeout, which
        // knows nothing of our budget; cap it, so a fallback attempt given
        // the remainder of one cannot overrun it.
        //
        // `Ok` means the active connection reached ACTIVATED (nmrs's
        // `wait_for_connection_activation` succeeds on nothing else), so it
        // is the whole answer. No follow-up `is_connected` poll: that reads
        // the SSID of the *first* WiFi device with an access point, which on
        // a second radio is some other network, and the poll would then run
        // a second full budget and delete the profile that just came up.
        let activated = tokio::time::timeout(
            budget,
            self.nm
                .add_and_activate_connection(settings, Some(&device.interface), None),
        )
        .await;
        let failure = match activated {
            Ok(Ok(_)) => return Ok(JoinOutcome::Joined),
            Ok(Err(e)) => {
                debug!(error = %e, "activating our own station profile failed");
                classify_failure(&e)
            }
            Err(_) => JoinFailure::Timeout,
        };
        // The profile is persisted before activation can fail, with
        // autoconnect on; left behind, NetworkManager would keep retrying a
        // known-bad network on every scan. Delete it here so this path does
        // not rely on the caller to do it.
        self.delete_profile_quietly(&uuid).await;
        Ok(JoinOutcome::Failed(failure))
    }

    /// Delete a saved connection by UUID, swallowing "nothing to delete".
    ///
    /// By UUID and never by name: nmrs's `forget(name)` deletes *every*
    /// saved connection, of any type, whose `connection.id` or SSID equals
    /// the string, which would let a portal user name — and so delete — an
    /// unrelated profile.
    async fn delete_profile_quietly(&self, uuid: &str) {
        if let Err(e) = self.delete_profile(uuid).await {
            debug!(error = %e, uuid, "could not delete the profile");
        }
    }

    /// Activate an existing saved profile for an open join, by its UUID.
    ///
    /// What nmrs's `connect` does with an open join over a saved profile
    /// (`UseSaved`), minus the destructive part: when the saved profile does
    /// not come up, nmrs deletes it before retrying. Here it is left alone,
    /// and the retry with a fresh open profile goes through
    /// [`Self::join_with_own_profile`], whose profile has a UUID we minted
    /// and is the only one deleted if that fails too.
    ///
    /// Trying the saved profile first matters: the portal lets a user submit
    /// a secured network with the password left blank, which is how "use
    /// the password this device already knows" is spelled. A fresh open
    /// profile against a WPA network can only fail.
    async fn join_via_saved_profile(
        &self,
        device: &DeviceInfo,
        request: &JoinRequest,
        uuid: &str,
        budget: Duration,
    ) -> Result<JoinOutcome, NetworkError> {
        let started = tokio::time::Instant::now();
        let attempt = tokio::time::timeout(
            budget,
            self.nm.connect_by_uuid(
                uuid,
                nmrs::ConnectByUuidConfig::default().with_interface(&device.interface),
            ),
        )
        .await;

        let saved_failure = match attempt {
            Ok(Ok(())) => return Ok(JoinOutcome::Joined),
            Ok(Err(e)) => {
                debug!(error = %e, uuid, "the saved profile did not come up");
                classify_failure(&e)
            }
            Err(_) => return Ok(JoinOutcome::Failed(JoinFailure::Timeout)),
        };

        // The network may have become open since the profile was saved. Try
        // a fresh open profile in whatever budget is left, but report the
        // saved profile's reason if that fails as well: "bad password" tells
        // the user to type one, which is the likelier fix.
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining < MIN_FALLBACK_BUDGET {
            return Ok(JoinOutcome::Failed(saved_failure));
        }
        match self
            .join_with_own_profile(device, request, remaining)
            .await?
        {
            JoinOutcome::Joined => Ok(JoinOutcome::Joined),
            JoinOutcome::Failed(_) => Ok(JoinOutcome::Failed(saved_failure)),
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
/// `try_connect` path via [`credentials_for`] and the own-profile builder
/// path in [`NmrsControl::join_with_own_profile`] — cannot drift. Two copies of this
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

/// Shortest budget worth spending on a fresh open profile after a saved one
/// failed to come up. Below this the attempt cannot realistically associate
/// and get a lease, and would only delay the portal's return.
const MIN_FALLBACK_BUDGET: Duration = Duration::from_secs(10);

/// How a broadcast (non-hidden) join is carried out. Hidden joins always
/// build their own profile: see [`NmrsControl::join_with_own_profile`].
#[derive(Debug, PartialEq, Eq)]
enum JoinRoute {
    /// nmrs's `try_connect`, with its precise failure reasons.
    Nmrs,
    /// Activate this saved profile, then fall back to our own open profile.
    Saved(String),
    /// Build our own profile, with a UUID we mint.
    OwnProfile,
}

/// Decide how to carry out a broadcast join.
///
/// `saved` is the list of station profiles already saved for the SSID, or
/// `None` if it could not be read. Only consulted for an open join.
///
/// An **open** join must not reach nmrs 3.5.7's `connect` while a station
/// profile for that SSID is saved. With no credentials it decides to
/// *reuse* that profile (`decide_saved_connection` -> `UseSaved`), and when
/// activation fails it treats the profile as corrupt: `connect_via_saved`
/// **deletes it** and retries with a fresh open profile. So an open join
/// aimed at the device's working PSK profile for the same SSID would cost
/// the device that profile whenever the attempt fails, and it is gone
/// before we get control back. We do the reuse ourselves instead, without
/// the delete. If the listing failed we cannot rule a profile out, so we
/// stay away from nmrs and build our own.
///
/// With credentials (PSK or EAP), nmrs is safe and stays in charge: it
/// builds a *new* profile, deletes that new one itself if activation fails,
/// and removes the old one (`replaces`) only once the new one has come up.
fn route_join(request: &JoinRequest, saved: Option<&[String]>) -> JoinRoute {
    if !matches!(classify_credentials(request), Credential::Open) {
        return JoinRoute::Nmrs;
    }
    match saved {
        Some([]) => JoinRoute::Nmrs,
        Some([first, ..]) => JoinRoute::Saved(first.clone()),
        None => JoinRoute::OwnProfile,
    }
}

/// Whether a saved profile is a station profile for `want`.
///
/// Mirrors nmrs's own lookup (`wifi_profile_matches_ssid`): a WiFi profile,
/// not in AP mode, whose SSID bytes match. The display form is accepted as
/// well as the exact bytes, because nmrs builds profiles from a `&str` and
/// so writes the lossy display form for a non-UTF-8 SSID.
fn is_station_profile_for(
    connection_type: &str,
    mode: Option<&str>,
    profile_ssid: Option<&[u8]>,
    want: &Ssid,
) -> bool {
    let Some(profile_ssid) = profile_ssid else {
        return false;
    };
    connection_type == WIFI_CONNECTION_TYPE
        && mode != Some("ap")
        && (profile_ssid == want.as_bytes() || profile_ssid == want.to_display_string().as_bytes())
}

/// `connection.type` for a WiFi profile.
const WIFI_CONNECTION_TYPE: &str = "802-11-wireless";
/// `802-11-wireless.mode`.
const WIFI_MODE: nmrs::models::Property<String> =
    nmrs::models::Property::new(WIFI_CONNECTION_TYPE, "mode");
/// `802-11-wireless.ssid`, as raw bytes.
const WIFI_SSID: nmrs::models::Property<Vec<u8>> =
    nmrs::models::Property::new(WIFI_CONNECTION_TYPE, "ssid");

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
            // NM can be built with connectivity checking disabled, in which
            // case "unknown" is the honest answer and the portal should
            // come up rather than the tool giving up.
            Err(ConnectionError::ConnectivityCheckDisabled) => {
                debug!("NetworkManager connectivity checking is disabled");
                Ok(Connectivity::Unknown)
            }
            Err(e) => Err(NetworkError::Other(e.to_string())),
        }
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
        _device: &DeviceInfo,
        budget: Duration,
    ) -> Result<bool, NetworkError> {
        // Poll NM's own connectivity verdict rather than tracking device
        // state ourselves: "associated" is not the same as "usable", and
        // the whole point of the wait is to find out whether the device can
        // actually reach the internet.
        let deadline = tokio::time::Instant::now() + budget;
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            if self.check_connectivity().await? == Connectivity::Full {
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
        if let Err(e) = self
            .nm
            .add_and_activate_connection(settings, Some(&device.interface), None)
            .await
        {
            // The profile is persisted before activation can fail. We know
            // its UUID, so remove exactly it rather than leaving it for the
            // next run's sweep.
            self.delete_profile_quietly(&uuid).await;
            return Err(NetworkError::ApFailed(e.to_string()));
        }

        info!(ssid = %config.ssid, interface = %device.interface, "access point raised");
        Ok(ApHandle {
            uuid,
            interface: device.interface.clone(),
        })
    }

    async fn tear_down_ap(&self, handle: &ApHandle) -> Result<(), NetworkError> {
        // Deactivate by the connection's UUID (NetworkManager finds the
        // matching active connection itself) and then delete the profile,
        // also by UUID. A "not active" / "no saved connection" error is
        // success from our point of view: the AP is gone, which is what we
        // wanted.
        //
        // Not `forget(AP_PROFILE_ID)`: nmrs's `forget` deletes every saved
        // connection of any type whose id *or SSID* equals the string, so
        // it would also take out, say, a station profile for a network that
        // happens to be called "wifi-connect-portal".
        if let Err(e) = self.nm.disconnect_by_uuid(&handle.uuid).await {
            debug!(error = %e, "deactivating the access point was a no-op");
        }
        self.delete_profile_quietly(&handle.uuid).await;
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
            return self.join_with_own_profile(device, request, budget).await;
        }

        // The radio could not scan while it was the access point, so its BSS
        // cache is stale by the time we get here. Without a fresh scan,
        // `try_connect` returns "network not found" for a network that is
        // actually in range — including the one the portal just showed the
        // user. Rescan and wait, briefly, for the target to reappear.
        self.rescan_for(&device.interface, &request.ssid).await;

        // An open join must not be handed to nmrs when a profile for this
        // SSID is already saved: on failure nmrs deletes that profile. Only
        // looked up when it can change the answer.
        let saved = if matches!(classify_credentials(request), Credential::Open) {
            match self.station_profile_uuids(&request.ssid).await {
                Ok(uuids) => Some(uuids),
                Err(e) => {
                    debug!(error = %e, "could not list saved profiles; assuming one exists");
                    None
                }
            }
        } else {
            Some(Vec::new())
        };
        match route_join(request, saved.as_deref()) {
            JoinRoute::Nmrs => {}
            JoinRoute::Saved(uuid) => {
                return self
                    .join_via_saved_profile(device, request, &uuid, budget)
                    .await;
            }
            JoinRoute::OwnProfile => {
                return self.join_with_own_profile(device, request, budget).await;
            }
        }

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

    async fn station_profile_uuids(&self, ssid: &Ssid) -> Result<Vec<String>, NetworkError> {
        let saved = self
            .nm
            .list_saved_connections()
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))?;

        Ok(saved
            .into_iter()
            .filter(|c| {
                is_station_profile_for(
                    &c.connection_type,
                    c.get_property(WIFI_MODE).as_deref(),
                    c.get_property(WIFI_SSID).as_deref(),
                    ssid,
                )
            })
            .map(|c| c.uuid)
            .collect())
    }

    async fn delete_profile(&self, uuid: &str) -> Result<(), NetworkError> {
        match self.nm.delete_saved_connection(uuid).await {
            Ok(()) => Ok(()),
            // Already gone — nmrs deletes a fresh profile itself when its
            // activation fails — is what we wanted.
            Err(ConnectionError::SavedConnectionNotFound(_)) => Ok(()),
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
            // Our id, on our interface, *and* in AP mode: a station profile
            // someone happened to name "wifi-connect-portal" is not ours.
            let ours = c.id == AP_PROFILE_ID;
            let on_our_interface = c.interface_name.as_deref() == Some(interface);
            let is_ap = c.get_property(WIFI_MODE).as_deref() == Some("ap");
            if ours && on_our_interface && is_ap {
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

    fn join(ssid: &str, passphrase: Option<&str>, hidden: bool) -> JoinRequest {
        JoinRequest {
            ssid: Ssid::from(ssid),
            identity: None,
            passphrase: passphrase.map(Secret::new),
            hidden,
        }
    }

    /// nmrs 3.5.7 deletes a saved profile it was asked to reuse when that
    /// activation fails and it has no credentials to fall back on, so an
    /// open join must never reach nmrs while such a profile exists. We reuse
    /// it ourselves, by UUID, so a blank password over a saved secured
    /// network still joins with the stored secret.
    #[test]
    fn an_open_join_over_a_saved_profile_reuses_it_without_nmrs() {
        let saved = ["home-uuid".to_string(), "dup-uuid".to_string()];
        assert_eq!(
            route_join(&join("Home", None, false), Some(&saved)),
            JoinRoute::Saved("home-uuid".into())
        );
    }

    /// Unable to list, we cannot rule a saved profile out, so nmrs (which
    /// would delete one on failure) is not used.
    #[test]
    fn an_open_join_with_unreadable_profiles_builds_its_own() {
        assert_eq!(
            route_join(&join("Home", None, false), None),
            JoinRoute::OwnProfile
        );
    }

    /// With credentials nmrs builds a new profile and deletes only that one
    /// on failure, so it can keep its better failure reporting.
    #[test]
    fn a_join_with_credentials_or_nothing_saved_goes_through_nmrs() {
        let saved = ["home-uuid".to_string()];
        assert_eq!(
            route_join(&join("Home", Some("abcdefgh"), false), Some(&saved)),
            JoinRoute::Nmrs
        );
        assert_eq!(
            route_join(&join("Home", Some("abcdefgh"), false), None),
            JoinRoute::Nmrs
        );
        assert_eq!(
            route_join(&join("Cafe", None, false), Some(&[])),
            JoinRoute::Nmrs
        );
    }

    /// Only station WiFi profiles for this exact network count. A wired or
    /// VPN profile whose *name* matches, or our own access point, must never
    /// be mistaken for one — that is the mistake a delete-by-name makes.
    #[test]
    fn station_profile_matching_is_by_type_mode_and_ssid_bytes() {
        let office = Ssid::from("Office");
        let wifi = "802-11-wireless";

        assert!(is_station_profile_for(wifi, None, Some(b"Office"), &office));
        assert!(is_station_profile_for(
            wifi,
            Some("infrastructure"),
            Some(b"Office"),
            &office
        ));

        assert!(!is_station_profile_for(
            wifi,
            Some("ap"),
            Some(b"Office"),
            &office
        ));
        assert!(!is_station_profile_for(
            wifi,
            None,
            Some(b"office"),
            &office
        ));
        assert!(!is_station_profile_for(
            "802-3-ethernet",
            None,
            Some(b"Office"),
            &office
        ));
        assert!(!is_station_profile_for("vpn", None, None, &office));
    }

    /// nmrs builds profiles from a `&str`, so a non-UTF-8 SSID is written in
    /// its lossy display form; the profile it created must still be found.
    #[test]
    fn a_non_utf8_ssid_matches_both_its_bytes_and_nmrs_display_form() {
        let odd = Ssid::new(vec![0x4d, 0x79, 0xff]);
        let display = odd.to_display_string();
        let wifi = "802-11-wireless";
        assert!(is_station_profile_for(
            wifi,
            None,
            Some(&[0x4d, 0x79, 0xff]),
            &odd
        ));
        assert!(is_station_profile_for(
            wifi,
            None,
            Some(display.as_bytes()),
            &odd
        ));
    }

    #[test]
    fn the_ap_profile_id_is_stable() {
        // The startup sweep matches on it, so renaming it would orphan
        // profiles left behind by an older build.
        assert_eq!(AP_PROFILE_ID, "wifi-connect-portal");
    }
}
