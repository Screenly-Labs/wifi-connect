//! The NetworkManager layer.
//!
//! Everything the rest of the program knows about NetworkManager goes
//! through the [`NetworkControl`] trait. That seam buys three things:
//!
//! * the state machine is testable with no radio and no bus,
//! * `nmrs`'s types do not leak into the portal and the HTTP layer,
//! * if `nmrs` ever stops being maintained, replacing it is one `impl`
//!   rather than a rewrite.
//!
//! We depend on `nmrs` rather than driving D-Bus ourselves because it has
//! already solved the part that is genuinely hard: NetworkManager reports a
//! generic `DEVICE_DISCONNECTED` on the active connection and carries the
//! *real* reason on the device, which it moves out of `FAILED` within
//! milliseconds. Reading the property afterwards returns nothing useful, so
//! the reason has to be captured from a merged signal stream. Getting that
//! wrong is exactly how "the wrong password just hangs" ships.

pub mod fake;
pub mod nmrs_impl;
pub mod proxies;
pub mod security;
pub mod settings;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::secret::Secret;
use crate::ssid::Ssid;
use security::Security;

/// How the setup access point protects itself.
///
/// There is no `Open` variant by design: the access point is always
/// encrypted. The `--insecure-open-portal` escape hatch is expressed as
/// "no passphrase" in the profile, not as a security mode, so that every
/// code path that reaches NetworkManager has to go out of its way to
/// produce an unencrypted AP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApSecurity {
    /// WPA2-PSK/CCMP. The realistic default: AP-mode SAE on `brcmfmac`
    /// (every Raspberry Pi) is unreliable.
    Wpa2Psk,
    /// WPA3-Personal.
    Wpa3Sae,
}

/// A WiFi network as the portal shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WifiNetwork {
    /// Lossy, for display only.
    pub ssid: String,
    /// The exact bytes, for building the profile. Hex so it survives JSON.
    pub ssid_hex: String,
    /// 0-100.
    pub strength: u8,
    pub security: Security,
    pub frequency: Option<u32>,
}

impl WifiNetwork {
    pub fn new(ssid: Ssid, strength: u8, security: Security, frequency: Option<u32>) -> Self {
        Self {
            ssid: ssid.to_display_string(),
            ssid_hex: ssid.to_hex(),
            strength,
            security,
            frequency,
        }
    }
}

/// The WiFi device we are going to drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub interface: String,
    pub driver: String,
    /// Raw `WirelessCapabilities`, so the caller can explain *why* AP mode
    /// is unavailable rather than just that it is.
    pub capabilities: u32,
    pub managed: bool,
}

/// `NM_WIFI_DEVICE_CAP_AP`.
pub const WIFI_DEVICE_CAP_AP: u32 = 0x0000_0040;

impl DeviceInfo {
    pub fn supports_ap_mode(&self) -> bool {
        self.capabilities & WIFI_DEVICE_CAP_AP != 0
    }
}

/// What the user asked us to join.
#[derive(Debug, Clone)]
pub struct JoinRequest {
    pub ssid: Ssid,
    pub identity: Option<String>,
    pub passphrase: Option<Secret>,
    /// For enterprise networks: the domain the RADIUS server's certificate
    /// must belong to (`802-1x.domain-suffix-match`). Ignored otherwise.
    pub server_domain: Option<String>,
    /// For enterprise networks: how the password is proved. Ignored
    /// otherwise.
    pub eap_method: EapMethod,
    pub hidden: bool,
    /// How the joined network addresses this device. The default is
    /// automatic on both families, which is what every join did before
    /// static addressing existed.
    pub ip: IpSettings,
}

/// Addressing for the joined network, per address family.
///
/// `None` for a family means automatic: DHCP for IPv4, router
/// advertisements (SLAAC, and DHCPv6 when the router asks for it) for IPv6.
/// The families are independent, because real networks mix them: a static
/// IPv4 address on a LAN whose router hands out IPv6 by SLAAC is ordinary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSettings {
    pub ipv4: Option<StaticIp<Ipv4Addr>>,
    pub ipv6: Option<StaticIp<Ipv6Addr>>,
    /// DNS servers to use *instead of* whatever the network advertises.
    /// Empty means "whatever the network advertises".
    pub dns: Vec<IpAddr>,
}

impl IpSettings {
    /// Nothing was configured by hand.
    pub fn is_automatic(&self) -> bool {
        self.ipv4.is_none() && self.ipv6.is_none() && self.dns.is_empty()
    }
}

/// One statically assigned address, with the router to reach the rest of
/// the world through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticIp<A> {
    pub address: A,
    pub prefix: u8,
    /// Optional, as it is in NetworkManager: a device on an isolated LAN
    /// has no router to name. Without one there is no default route on
    /// this family.
    pub gateway: Option<A>,
}

/// How an enterprise (802.1X) join proves the user's password, inside the
/// TLS tunnel to the RADIUS server.
///
/// Only the password-based methods: certificate-based EAP-TLS needs a key
/// and certificate that a captive portal has no way to collect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EapMethod {
    /// PEAP with MSCHAPv2. What Windows networks, and most others, run.
    #[default]
    PeapMschapv2,
    /// EAP-TTLS with MSCHAPv2 inside.
    TtlsMschapv2,
    /// EAP-TTLS with PAP inside: the password itself crosses the tunnel.
    /// Common where accounts live in LDAP, which can check a password but
    /// not an MSCHAPv2 response.
    TtlsPap,
}

impl EapMethod {
    /// The portal's form value for each method.
    pub fn from_form(value: &str) -> Option<Self> {
        match value {
            "peap" => Some(Self::PeapMschapv2),
            "ttls-mschapv2" => Some(Self::TtlsMschapv2),
            "ttls-pap" => Some(Self::TtlsPap),
            _ => None,
        }
    }

    /// Whether the password itself, rather than a challenge response, goes
    /// to whoever terminates the tunnel. Under PAP that is the plaintext
    /// password, so the tunnel is only as good as the check on the server
    /// at its far end.
    pub fn sends_password_in_clear(self) -> bool {
        matches!(self, Self::TtlsPap)
    }
}

/// Why a join did not work, in terms the portal can explain.
///
/// NetworkManager genuinely cannot distinguish "wrong pre-shared key" from
/// "the AP stopped responding during the four-way handshake" — both land in
/// the supplicant-disconnect family. We report that as a rejected password
/// because it is correct the overwhelming majority of the time and because
/// it is the only version of the message a user can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JoinFailure {
    BadPassword,
    SsidNotFound,
    DhcpFailed,
    /// The adapter cannot do the security this network requires.
    Unsupported,
    Timeout,
    Other,
}

impl JoinFailure {
    /// The sentence the portal shows. These map to three genuinely different
    /// user actions, which is why "connection failed" is not good enough.
    pub fn message(self, ssid: &str) -> String {
        match self {
            JoinFailure::BadPassword => {
                format!("Could not join \u{201c}{ssid}\u{201d}: the passphrase was not accepted.")
            }
            JoinFailure::SsidNotFound => format!(
                "\u{201c}{ssid}\u{201d} was not found. It may be out of range, or its name may be \
                 misspelled."
            ),
            JoinFailure::DhcpFailed => format!(
                "Joined \u{201c}{ssid}\u{201d}, but the network did not provide an IP address."
            ),
            JoinFailure::Unsupported => format!(
                "Could not join \u{201c}{ssid}\u{201d}: this adapter does not support that \
                 network's security."
            ),
            JoinFailure::Timeout => {
                format!("Timed out joining \u{201c}{ssid}\u{201d}. Please try again.")
            }
            JoinFailure::Other => {
                format!("Could not join \u{201c}{ssid}\u{201d}. Please try again.")
            }
        }
    }
}

/// The outcome of one join attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinOutcome {
    Joined,
    Failed(JoinFailure),
}

/// NetworkManager's connectivity verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    /// Working internet.
    Full,
    /// Associated but behind someone else's captive portal, or no route out.
    Limited,
    None,
    /// NetworkManager did not probe. Usually because connectivity checking
    /// is disabled — the default on Debian, Raspberry Pi OS and Ubuntu
    /// Server/Core, which ship no check URI. This is "we cannot tell", not
    /// "offline": [`NetworkControl::is_online`] then asks whether the WiFi
    /// radio is already a connected station before anything acts on it.
    Unknown,
}

/// How the access point should be raised.
#[derive(Debug, Clone)]
pub struct ApConfig {
    pub ssid: Ssid,
    pub passphrase: Option<Secret>,
    pub security: ApSecurity,
    pub gateway: Ipv4Addr,
    pub prefix: u8,
    pub channel: Option<u32>,
}

/// A raised access point, as a handle to tear down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApHandle {
    /// The AP connection's UUID. Teardown deactivates *this* connection by
    /// UUID; NetworkManager resolves the active connection itself. Passing
    /// the active-connection object path here instead makes it look up a
    /// connection that does not exist, so the AP is never brought down and
    /// the following station join is rejected with "a connection operation
    /// is already in progress".
    pub uuid: String,
    /// The wireless interface the AP is on, so teardown can wait for the
    /// radio to finish leaving the AP before a station join starts.
    pub interface: String,
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("could not reach NetworkManager: {0}")]
    Unreachable(String),
    #[error("no WiFi device was found")]
    NoWifiDevice,
    #[error("the WiFi adapter {interface} cannot operate as an access point (driver: {driver})")]
    ApUnsupported { interface: String, driver: String },
    #[error("NetworkManager is not managing {0}")]
    Unmanaged(String),
    #[error("the WiFi radio is blocked (rfkill or a hardware switch)")]
    RadioBlocked,
    #[error("could not raise the access point: {0}")]
    ApFailed(String),
    #[error(
        "the {0} server could not start, so the portal is unreachable (is port 80 already in use on this host?)"
    )]
    PortalUnavailable(String),
    #[error("NetworkManager error: {0}")]
    Other(String),
}

/// Everything the state machine is allowed to do to the network stack.
#[async_trait::async_trait]
pub trait NetworkControl: Send + Sync + 'static {
    /// Find the device to drive, honouring an explicit `--interface`.
    async fn find_device(&self, interface: Option<&str>) -> Result<DeviceInfo, NetworkError>;

    /// Ask NetworkManager to re-check, rather than reading its cached
    /// property, which can be arbitrarily stale.
    async fn check_connectivity(&self) -> Result<Connectivity, NetworkError>;

    /// Whether the WiFi device we would drive is ACTIVATED as a station
    /// (infrastructure mode, not an access point). Read without probing.
    /// Failed reads must answer `false`: that is the behaviour from before
    /// this fallback existed, and the portal comes up.
    async fn station_activated(&self, device: &DeviceInfo) -> Result<bool, NetworkError>;

    /// The single "are we online?" decision, shared by the startup gate and
    /// the autoconnect wait so the two cannot disagree.
    ///
    /// A definite verdict from the probe stands: `Limited` and `None` mean
    /// the user may need the portal to pick a different network, even if
    /// the radio is associated.
    ///
    /// `Unknown` — no probe ran, usually because checking is disabled —
    /// counts as online only when the radio is already a connected station.
    /// That is the one case where raising the access point does damage: it
    /// would replace that very connection, and with no activity timeout the
    /// device would never get it back. NetworkManager's global `State` is
    /// deliberately *not* consulted: with checking disabled it reads
    /// `CONNECTED_GLOBAL` for any link with a default route, including an
    /// ethernet LAN with no internet, and trusting it there would stop the
    /// portal from ever appearing on a device that needs it.
    async fn is_online(&self, device: &DeviceInfo) -> Result<bool, NetworkError> {
        match self.check_connectivity().await? {
            Connectivity::Full => Ok(true),
            Connectivity::Unknown => self.station_activated(device).await,
            Connectivity::Limited | Connectivity::None => Ok(false),
        }
    }

    /// How many WiFi profiles are already saved.
    ///
    /// Drives the asymmetry in the "should we raise the portal at all" gate:
    /// we wait for autoconnect only when there is something to wait for. A
    /// first-boot device with no profiles should not stare at a blank screen
    /// for a minute before showing the portal.
    async fn saved_wifi_profile_count(&self) -> Result<usize, NetworkError>;

    /// Wait up to `budget` for an existing profile to bring us online.
    async fn await_autoconnect(
        &self,
        device: &DeviceInfo,
        budget: std::time::Duration,
    ) -> Result<bool, NetworkError>;

    /// Scan. Must happen *before* the AP is raised: a radio in AP mode
    /// cannot scan.
    async fn scan(&self, device: &DeviceInfo) -> Result<Vec<WifiNetwork>, NetworkError>;

    /// Raise the setup access point.
    async fn raise_ap(
        &self,
        device: &DeviceInfo,
        config: &ApConfig,
    ) -> Result<ApHandle, NetworkError>;

    /// Deactivate and delete the AP profile this handle names, by its UUID.
    /// Best-effort: a teardown that fails must not stop the rest of the
    /// teardown running.
    async fn tear_down_ap(&self, handle: &ApHandle) -> Result<(), NetworkError>;

    /// Attempt to join, returning a *reason* on failure rather than an error.
    async fn join(
        &self,
        device: &DeviceInfo,
        request: &JoinRequest,
        budget: std::time::Duration,
    ) -> Result<JoinOutcome, NetworkError>;

    /// The UUIDs of every saved *station* (not access-point) WiFi profile
    /// whose SSID is `ssid`.
    ///
    /// Used to work out which profile a failed join created: snapshot before,
    /// snapshot after, and the difference is ours. Matching on the SSID as
    /// well as on "new" narrows that difference to the one network we were
    /// asked to join, so a profile someone else adds through `nmcli` during
    /// the join window is not swept up with it.
    async fn station_profile_uuids(&self, ssid: &Ssid) -> Result<Vec<String>, NetworkError>;

    /// Delete one saved profile, identified by UUID. "Already gone" is
    /// success.
    ///
    /// There is deliberately no delete-by-name. Names are not identities: a
    /// `connection.id` or an SSID typed into the portal can equal the name of
    /// an unrelated profile — `Wired connection 1`, a VPN, the device's real
    /// home network — and a by-name delete takes that profile out with it.
    async fn delete_profile(&self, uuid: &str) -> Result<(), NetworkError>;

    /// Put the device back in managed station mode.
    async fn restore(&self, device: &DeviceInfo) -> Result<(), NetworkError>;

    /// Remove any `mode=ap` profile left behind by a previous crashed run.
    async fn sweep_stale_ap_profiles(&self, interface: &str) -> Result<usize, NetworkError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ap_capability_is_read_from_the_bitfield() {
        let mut d = DeviceInfo {
            interface: "wlan0".into(),
            driver: "brcmfmac".into(),
            capabilities: 0,
            managed: true,
        };
        assert!(!d.supports_ap_mode());

        d.capabilities = WIFI_DEVICE_CAP_AP;
        assert!(d.supports_ap_mode());

        // Other capability bits must not be mistaken for AP support.
        d.capabilities = !WIFI_DEVICE_CAP_AP;
        assert!(!d.supports_ap_mode());
    }

    #[test]
    fn failure_messages_name_the_network_and_differ_per_cause() {
        let msgs: Vec<String> = [
            JoinFailure::BadPassword,
            JoinFailure::SsidNotFound,
            JoinFailure::DhcpFailed,
            JoinFailure::Unsupported,
            JoinFailure::Timeout,
            JoinFailure::Other,
        ]
        .iter()
        .map(|f| f.message("Office WiFi"))
        .collect();

        for m in &msgs {
            assert!(m.contains("Office WiFi"), "message omits the SSID: {m}");
        }

        let unique: std::collections::HashSet<&String> = msgs.iter().collect();
        assert_eq!(unique.len(), msgs.len(), "two causes share a message");

        // The three that imply different user actions must be distinguishable.
        assert!(msgs[0].contains("passphrase"));
        assert!(msgs[1].contains("not found"));
        assert!(msgs[2].contains("IP address"));
    }

    #[test]
    fn network_carries_both_display_and_exact_ssid() {
        let n = WifiNetwork::new(
            Ssid::new(vec![0x4d, 0x79, 0xff]),
            73,
            Security::WpaPsk,
            Some(2437),
        );
        assert_eq!(n.ssid_hex, "4d79ff");
        assert!(n.ssid.contains('\u{fffd}'), "display form should be lossy");
        assert_eq!(
            Ssid::from_hex(&n.ssid_hex).unwrap().as_bytes(),
            &[0x4d, 0x79, 0xff]
        );
    }
}
