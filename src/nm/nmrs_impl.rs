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
use super::settings::{ApProfile, ap_settings, apply_station_ip};
use super::{
    ApConfig, ApHandle, Connectivity, DeviceInfo, EapMethod, JoinFailure, JoinOutcome, JoinRequest,
    NetworkControl, NetworkError, WifiNetwork,
};
use crate::secret::Secret;
use crate::ssid::Ssid;

/// `connection.id` given to the access-point profile. Also what the startup
/// sweep matches on.
pub const AP_PROFILE_ID: &str = "wifi-connect-portal";

pub struct NmrsControl {
    nm: NetworkManager,
    eap_server_check: EapServerCheck,
}

/// Whether an enterprise join verifies the RADIUS server's certificate.
///
/// Without verification, PEAP's protection is illusory: an access point
/// that merely copies the SSID can terminate the TLS tunnel with any
/// certificate, run the MSCHAPv2 exchange, and walk away with something
/// that cracks offline to the user's NT hash. That is the attack
/// `hostapd-wpe` packages, and it needs nothing more than radio range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EapServerCheck {
    /// Chain the server's certificate to the system CA store (and to the
    /// user's server domain, when they gave one). The default.
    #[default]
    SystemCa,
    /// Accept any server certificate. Only for networks whose RADIUS
    /// server uses a private CA that the host store does not carry, and
    /// only by explicit operator choice.
    Insecure,
}

impl NmrsControl {
    pub async fn connect(eap_server_check: EapServerCheck) -> Result<Self, NetworkError> {
        // nmrs calls zbus's `Connection::system()`, which honours
        // DBUS_SYSTEM_BUS_ADDRESS. That is how the balena container reaches
        // the host bus at /host/run/dbus/system_bus_socket — set in the
        // environment, never with std::env::set_var, which is unsafe in
        // edition 2024 and must precede any thread spawn.
        let nm = NetworkManager::new()
            .await
            .map_err(|e| NetworkError::Unreachable(e.to_string()))?;
        Ok(Self {
            nm,
            eap_server_check,
        })
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
            Credential::Eap {
                identity,
                password,
                server_domain,
                method,
            } => builder
                .try_wpa_eap(eap_options(
                    identity,
                    password,
                    server_domain,
                    method,
                    self.eap_server_check,
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
        apply_station_ip(&mut settings, &request.ip);

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
            Ok(Ok(_)) => {
                if !request.ip.is_automatic() {
                    self.replace_older_profiles(&request.ssid, &uuid).await;
                }
                return Ok(JoinOutcome::Joined);
            }
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

    /// Delete every other saved station profile for `ssid`, now that `keep`
    /// has come up.
    ///
    /// What nmrs does for a credentialed join (`replaces`), done here for a
    /// static-IP join, which has to build its own profile. Without it the
    /// device's previous profile for the network, with its DHCP addressing,
    /// stays saved alongside the new one, and NetworkManager may pick it on
    /// the next boot: the static address would hold until the first reboot
    /// and then quietly not. Only after success, so a failed attempt costs
    /// the device nothing it had.
    async fn replace_older_profiles(&self, ssid: &Ssid, keep: &str) {
        match self.station_profile_uuids(ssid).await {
            Ok(uuids) => {
                for uuid in uuids.iter().filter(|u| u.as_str() != keep) {
                    self.delete_profile_quietly(uuid).await;
                }
            }
            Err(e) => warn!(error = %e, "could not list profiles to replace"),
        }
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
    // PEAP/MSCHAPv2 (nmrs's default method) is the bulk of enterprise
    // WiFi. Certificate-based EAP-TLS needs key and certificate paths that
    // a captive portal has no way to collect.
    //
    // How the server is authenticated is decided in [`eap_options`]; see
    // there, and the README's "Requirements and limitations".
    Eap {
        identity: &'a str,
        password: &'a Secret,
        server_domain: Option<&'a str>,
        method: EapMethod,
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
            server_domain: request.server_domain.as_deref(),
            method: request.eap_method,
        },
        _ => Credential::Open,
    }
}

/// The outer (phase-1) identity to send for `identity`.
///
/// PEAP sends the outer identity before the TLS tunnel exists, so whatever
/// goes there crosses the air in clear — to the real network and to any
/// look-alike. The real username belongs inside the tunnel only. The realm
/// is kept, because RADIUS proxies (eduroam is the famous case) route on
/// it; a server that sees a bare "anonymous" may not know where to send
/// the request. `DOMAIN\user` carries no routable realm, so it gets the
/// bare form.
fn anonymous_identity(identity: &str) -> String {
    match identity.rsplit_once('@') {
        Some((_, realm)) if !realm.is_empty() => format!("anonymous@{realm}"),
        _ => "anonymous".to_string(),
    }
}

/// The EAP options for an enterprise join.
///
/// nmrs's `EapOptions::new` defaults to no CA at all, which tells
/// wpa_supplicant to accept any server certificate. We turn the system CA
/// store on instead. Note that it is the *host's* store that matters, not
/// this process's: NetworkManager translates `system-ca-certs` into a
/// `ca_path` for wpa_supplicant, which runs on the host and opens that
/// path in its own filesystem. That is why it works even though our
/// container image is `FROM scratch` with no certificates in it.
///
/// A public CA alone still admits any certificate a public CA will issue,
/// for any name, so the user's server domain, when given, narrows it to
/// the one name that should be there.
///
/// The anonymous outer identity and the server checks apply to TTLS
/// exactly as to PEAP: both run the inner exchange in a TLS tunnel, and
/// both send the outer identity before it exists.
fn eap_options(
    identity: &str,
    password: &Secret,
    server_domain: Option<&str>,
    method: EapMethod,
    check: EapServerCheck,
) -> nmrs::EapOptions {
    let (outer, inner) = match method {
        EapMethod::PeapMschapv2 => (nmrs::EapMethod::Peap, nmrs::Phase2::Mschapv2),
        EapMethod::TtlsMschapv2 => (nmrs::EapMethod::Ttls, nmrs::Phase2::Mschapv2),
        EapMethod::TtlsPap => (nmrs::EapMethod::Ttls, nmrs::Phase2::Pap),
    };
    let mut opts = nmrs::EapOptions::new(identity, password.expose())
        .with_method(outer)
        .with_phase2(inner)
        .with_anonymous_identity(anonymous_identity(identity))
        .with_system_ca_certs(check == EapServerCheck::SystemCa);
    if let Some(domain) = server_domain {
        // Kept under the insecure opt-out too. The operator turned off CA
        // chaining, not the user's own name check; without a trusted CA a
        // forged certificate can carry any name, so this is weak there,
        // but it is what the user asked for and it costs nothing.
        opts = opts.with_domain_suffix_match(domain);
    }
    opts
}

/// TTLS/PAP sends the password itself through the tunnel, so it is never
/// attempted when the far end of that tunnel is not verified.
fn refuses_plaintext(request: &JoinRequest, check: EapServerCheck) -> bool {
    check == EapServerCheck::Insecure
        && matches!(
            classify_credentials(request),
            Credential::Eap { method, .. } if method.sends_password_in_clear()
        )
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
///
/// Hand-configured addressing always builds its own profile: nmrs's
/// `try_connect` has no way to carry it, and reusing a saved profile would
/// silently keep that profile's addressing instead.
fn route_join(request: &JoinRequest, saved: Option<&[String]>) -> JoinRoute {
    if !request.ip.is_automatic() {
        return JoinRoute::OwnProfile;
    }
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
fn credentials_for(request: &JoinRequest, check: EapServerCheck) -> WifiSecurity {
    match classify_credentials(request) {
        Credential::Psk(psk) => WifiSecurity::WpaPsk {
            psk: psk.expose().to_string(),
        },
        Credential::Eap {
            identity,
            password,
            server_domain,
            method,
        } => WifiSecurity::WpaEap {
            opts: eap_options(identity, password, server_domain, method, check),
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
        // that needs it. As Unknown it only counts as online when the radio
        // is already a connected station, the same as no probe at all.
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

        let out: Vec<WifiNetwork> = aps
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

        Ok(strongest_per_ssid(out))
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

        // The portal refuses this before the access point goes down (see
        // `http::api::check_policy`); this is the backstop, so no other
        // caller can send a plaintext password to an unverified server.
        if refuses_plaintext(request, self.eap_server_check) {
            warn!("refusing TTLS/PAP with server verification off");
            return Ok(JoinOutcome::Failed(JoinFailure::Other));
        }

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
        let saved = if request.ip.is_automatic()
            && matches!(classify_credentials(request), Credential::Open)
        {
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
            self.nm.try_connect(
                &ssid,
                Some(&device.interface),
                credentials_for(request, self.eap_server_check),
            ),
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

/// One row per SSID, strongest first.
///
/// Several access points on one network — the 2.4 and 5 GHz radios of the
/// same box, or a mesh — otherwise fill the list with rows that are
/// indistinguishable to the person reading it, and asking someone to
/// choose between two identical names is asking them to guess.
///
/// Sorting by strength and calling `dedup_by` is the obvious way to write
/// this and does not work: `dedup_by` only collapses runs of ADJACENT
/// equal elements, and two radios of one network are adjacent only when no
/// third network's strength happens to fall between them. On a real site
/// that is the exception, not the rule — three networks with two radios
/// each typically interleave, and every duplicate survives. Group by SSID
/// first, keep the strongest of each, then order the result.
fn strongest_per_ssid(mut networks: Vec<WifiNetwork>) -> Vec<WifiNetwork> {
    networks.sort_by(|a, b| {
        a.ssid_hex
            .cmp(&b.ssid_hex)
            .then(b.strength.cmp(&a.strength))
    });
    networks.dedup_by(|a, b| a.ssid_hex == b.ssid_hex);
    // Stable, so equal strengths keep the SSID order above rather than
    // shuffling between scans and moving a row under a tapping finger.
    networks.sort_by_key(|a| std::cmp::Reverse(a.strength));
    networks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::security::Security;

    /// Regression: the list showed one row per radio, not one per network.
    ///
    /// These strengths interleave, which is what a real site looks like and
    /// what defeats a plain `dedup_by` on a strength-sorted list.
    #[test]
    fn one_row_per_ssid_even_when_strengths_interleave() {
        let net = |ssid: &str, strength: u8| {
            WifiNetwork::new(
                Ssid::new(ssid.as_bytes().to_vec()),
                strength,
                Security::WpaPsk,
                Some(2412),
            )
        };
        let scanned = vec![
            net("lab", 90),
            net("iot", 85),
            net("wifi", 80),
            net("lab", 70),
            net("iot", 65),
            net("wifi", 60),
        ];

        let shown = strongest_per_ssid(scanned);

        let names: Vec<&str> = shown.iter().map(|n| n.ssid.as_str()).collect();
        assert_eq!(names, vec!["lab", "iot", "wifi"]);
        // And the row kept is the one the phone can actually hear best.
        assert_eq!(
            shown.iter().map(|n| n.strength).collect::<Vec<_>>(),
            vec![90, 85, 80]
        );
    }

    #[test]
    fn two_networks_sharing_a_name_are_still_one_row() {
        // Same SSID bytes is the same network as far as joining goes: the
        // profile is built from the SSID and the strongest BSS wins.
        let net = |strength: u8| {
            WifiNetwork::new(
                Ssid::new(b"cafe".to_vec()),
                strength,
                Security::WpaPsk,
                Some(5180),
            )
        };

        let shown = strongest_per_ssid(vec![net(40), net(95), net(10)]);

        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].strength, 95);
    }

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

    fn enterprise(identity: &str, server_domain: Option<&str>) -> JoinRequest {
        JoinRequest {
            ssid: Ssid::from("Corp"),
            identity: Some(identity.into()),
            passphrase: Some(Secret::new("hunter2")),
            server_domain: server_domain.map(str::to_string),
            eap_method: Default::default(),
            hidden: false,
            ip: Default::default(),
        }
    }

    fn eap_of(security: WifiSecurity) -> nmrs::EapOptions {
        match security {
            WifiSecurity::WpaEap { opts } => opts,
            other => panic!("expected WPA-EAP, got {other:?}"),
        }
    }

    /// The realm survives, because RADIUS proxies route on it; the user
    /// part never leaves the TLS tunnel.
    #[test]
    fn the_outer_identity_keeps_the_realm_and_drops_the_user() {
        assert_eq!(
            anonymous_identity("alice@example.com"),
            "anonymous@example.com"
        );
        assert_eq!(
            anonymous_identity("alice@staff@uni.example"),
            "anonymous@uni.example",
            "the realm is what follows the LAST @"
        );
        assert_eq!(anonymous_identity("alice"), "anonymous");
        assert_eq!(anonymous_identity(r"CORP\alice"), "anonymous");
        assert_eq!(
            anonymous_identity("alice@"),
            "anonymous",
            "an empty realm is no realm"
        );
    }

    /// The regression this pins: nmrs's defaults validate nothing, which
    /// hands an evil twin the MSCHAPv2 exchange.
    #[test]
    fn enterprise_joins_verify_the_server_by_default() {
        let opts = eap_of(credentials_for(
            &enterprise("alice@example.com", None),
            EapServerCheck::default(),
        ));
        assert!(
            opts.system_ca_certs,
            "the server must chain to the CA store"
        );
        assert_eq!(opts.identity, "alice@example.com");
        assert_eq!(
            opts.anonymous_identity.as_deref(),
            Some("anonymous@example.com"),
            "the real username must not be the cleartext outer identity"
        );
        assert_eq!(opts.domain_suffix_match, None);
    }

    #[test]
    fn a_server_domain_becomes_the_domain_suffix_match() {
        let opts = eap_of(credentials_for(
            &enterprise("alice", Some("radius.example.com")),
            EapServerCheck::SystemCa,
        ));
        assert!(opts.system_ca_certs);
        assert_eq!(
            opts.domain_suffix_match.as_deref(),
            Some("radius.example.com")
        );
        assert_eq!(opts.anonymous_identity.as_deref(), Some("anonymous"));
    }

    /// The opt-out drops CA checking and nothing else: the identity stays
    /// anonymous and a supplied domain still applies.
    #[test]
    fn only_the_explicit_opt_out_skips_server_verification() {
        let opts = eap_of(credentials_for(
            &enterprise("alice@example.com", Some("example.com")),
            EapServerCheck::Insecure,
        ));
        assert!(!opts.system_ca_certs);
        assert_eq!(
            opts.anonymous_identity.as_deref(),
            Some("anonymous@example.com")
        );
        assert_eq!(opts.domain_suffix_match.as_deref(), Some("example.com"));
    }

    #[test]
    fn each_method_maps_to_its_outer_and_inner_method() {
        for (method, outer, inner) in [
            (
                EapMethod::PeapMschapv2,
                nmrs::EapMethod::Peap,
                nmrs::Phase2::Mschapv2,
            ),
            (
                EapMethod::TtlsMschapv2,
                nmrs::EapMethod::Ttls,
                nmrs::Phase2::Mschapv2,
            ),
            (EapMethod::TtlsPap, nmrs::EapMethod::Ttls, nmrs::Phase2::Pap),
        ] {
            let mut r = enterprise("alice@example.com", Some("radius.example.com"));
            r.eap_method = method;
            let opts = eap_of(credentials_for(&r, EapServerCheck::SystemCa));
            assert_eq!((opts.method, opts.phase2), (outer, inner), "{method:?}");
            // TTLS gets the same protections as PEAP.
            assert!(opts.system_ca_certs, "{method:?}");
            assert_eq!(
                opts.anonymous_identity.as_deref(),
                Some("anonymous@example.com")
            );
            assert_eq!(
                opts.domain_suffix_match.as_deref(),
                Some("radius.example.com")
            );
        }
    }

    /// The backstop behind the portal's own check.
    #[test]
    fn ttls_pap_is_never_sent_to_an_unverified_server() {
        let mut r = enterprise("alice", None);
        r.eap_method = EapMethod::TtlsPap;
        assert!(refuses_plaintext(&r, EapServerCheck::Insecure));
        assert!(!refuses_plaintext(&r, EapServerCheck::SystemCa));

        for method in [EapMethod::PeapMschapv2, EapMethod::TtlsMschapv2] {
            r.eap_method = method;
            assert!(!refuses_plaintext(&r, EapServerCheck::Insecure));
        }

        // Without a username it is not an enterprise join at all.
        r.eap_method = EapMethod::TtlsPap;
        r.identity = None;
        assert!(!refuses_plaintext(&r, EapServerCheck::Insecure));
    }

    /// A domain is an enterprise setting; on a PSK network it must not turn
    /// the join into something else.
    #[test]
    fn a_server_domain_without_an_identity_is_ignored() {
        let mut r = enterprise("alice", Some("example.com"));
        r.identity = None;
        r.passphrase = Some(Secret::new("abcdefgh"));
        assert!(matches!(
            credentials_for(&r, EapServerCheck::SystemCa),
            WifiSecurity::WpaPsk { .. }
        ));
    }

    fn join(ssid: &str, passphrase: Option<&str>, hidden: bool) -> JoinRequest {
        JoinRequest {
            ssid: Ssid::from(ssid),
            identity: None,
            passphrase: passphrase.map(Secret::new),
            hidden,
            server_domain: None,
            eap_method: Default::default(),
            ip: Default::default(),
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

    /// nmrs's `try_connect` cannot carry static addressing, and a saved
    /// profile would bring its own, so a hand-configured join builds its own
    /// profile whatever the credentials and whatever is saved.
    #[test]
    fn a_join_with_static_addressing_always_builds_its_own_profile() {
        let saved = ["home-uuid".to_string()];
        let ip = crate::nm::IpSettings {
            ipv6: Some(crate::nm::StaticIp {
                address: "2001:db8::50".parse().unwrap(),
                prefix: 64,
                gateway: None,
            }),
            ..Default::default()
        };
        for (passphrase, saved) in [
            (Some("abcdefgh"), Some(&saved[..])),
            (None, Some(&saved[..])),
            (None, Some(&[][..])),
            (None, None),
        ] {
            let mut request = join("Home", passphrase, false);
            request.ip = ip.clone();
            assert_eq!(route_join(&request, saved), JoinRoute::OwnProfile);
        }
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
