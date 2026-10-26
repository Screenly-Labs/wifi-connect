//! An in-memory `NetworkControl` for tests.
//!
//! Deliberately a hand-written fake with a **recorded call log** rather than
//! a mock framework. The assertions that matter in this program are ordering
//! assertions — "we scanned before raising the access point", "the failed
//! station profile was deleted before the AP came back", "teardown ran even
//! on SIGTERM" — and a `Vec<Call>` expresses those far more directly than
//! expectation macros do.
//!
//! It also keeps a small table of **saved profiles**, because the other
//! property that matters is *which* profiles a run deletes. Like
//! NetworkManager, every join attempt leaves a station profile behind (the
//! worst case: nmrs cleans up after some failures itself, but not, for
//! example, when our timeout cancels it mid-activation), and every raise
//! leaves an access-point profile. Deletion is by UUID only, exactly as the
//! trait allows, so a test can seed the table with an unrelated profile that
//! shares a name and prove it survives.

#![cfg(test)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{
    ApConfig, ApHandle, Connectivity, DeviceInfo, JoinOutcome, JoinRequest, NetworkControl,
    NetworkError, WIFI_DEVICE_CAP_AP, WifiNetwork,
};
use crate::ssid::Ssid;

/// One interaction with the network stack, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    FindDevice,
    CheckConnectivity,
    AnotherDeviceOnline,
    StationActivated,
    SavedProfileCount,
    AwaitAutoconnect,
    Scan,
    RaiseAp { ssid: String, encrypted: bool },
    TearDownAp { uuid: String },
    Join { ssid: String },
    DeleteProfile { uuid: String },
    Restore,
    SweepStaleAps,
}

/// A saved NetworkManager profile, reduced to what deletion decisions
/// depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeProfile {
    pub uuid: String,
    /// `connection.id`.
    pub id: String,
    /// `802-11-wireless.ssid`; `None` for a non-WiFi profile.
    pub ssid: Option<String>,
    /// `802-11-wireless.mode == "ap"`.
    pub ap: bool,
}

impl FakeProfile {
    /// A station profile as nmrs names one: `connection.id` is the SSID.
    pub fn station(uuid: &str, ssid: &str) -> Self {
        Self {
            uuid: uuid.into(),
            id: ssid.into(),
            ssid: Some(ssid.into()),
            ap: false,
        }
    }

    /// A non-WiFi profile, e.g. `Wired connection 1` or a VPN.
    pub fn other(uuid: &str, id: &str) -> Self {
        Self {
            uuid: uuid.into(),
            id: id.into(),
            ssid: None,
            ap: false,
        }
    }
}

#[derive(Debug)]
struct State {
    calls: Vec<Call>,
    join_results: Vec<JoinOutcome>,
    ap_raises: u32,
    joins: u32,
    profiles: Vec<FakeProfile>,
}

/// A scriptable network stack.
#[derive(Clone)]
pub struct FakeNm {
    state: Arc<Mutex<State>>,
    pub device: DeviceInfo,
    pub connectivity: Connectivity,
    /// Whether some interface other than the radio is up -- a wired
    /// link, a second radio, a modem.
    pub another_device_online: bool,
    /// Whether NetworkManager's verdict is a measurement. Defaults to
    /// true so existing tests keep asserting what they always did.
    pub connectivity_is_measured: bool,
    pub station_activated: bool,
    pub saved_profiles: usize,
    pub autoconnect_succeeds: bool,
    pub networks: Vec<WifiNetwork>,
    pub ap_fails: bool,
    /// Make `station_profile_uuids` fail, as a D-Bus error would.
    pub profiles_unreadable: bool,
}

impl FakeNm {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                calls: Vec::new(),
                join_results: Vec::new(),
                ap_raises: 0,
                joins: 0,
                profiles: Vec::new(),
            })),
            device: DeviceInfo {
                interface: "wlan0".into(),
                driver: "brcmfmac".into(),
                capabilities: WIFI_DEVICE_CAP_AP,
                managed: true,
            },
            connectivity: Connectivity::None,
            another_device_online: false,
            connectivity_is_measured: true,
            station_activated: false,
            saved_profiles: 0,
            autoconnect_succeeds: false,
            networks: Vec::new(),
            ap_fails: false,
            profiles_unreadable: false,
        }
    }

    /// Seed the saved-profile table with profiles that existed before the run.
    pub fn with_profiles(self, profiles: Vec<FakeProfile>) -> Self {
        self.state.lock().unwrap().profiles = profiles;
        self
    }

    pub fn with_unreadable_profiles(mut self) -> Self {
        self.profiles_unreadable = true;
        self
    }

    /// The saved-profile table as it stands now.
    pub fn profiles(&self) -> Vec<FakeProfile> {
        self.state.lock().unwrap().profiles.clone()
    }

    /// Every UUID the run asked to delete, in order.
    pub fn deleted(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::DeleteProfile { uuid } => Some(uuid),
                _ => None,
            })
            .collect()
    }

    /// Script the outcome of each successive join attempt, in order.
    pub fn with_join_results(self, results: Vec<JoinOutcome>) -> Self {
        self.state.lock().unwrap().join_results = results;
        self
    }

    pub fn with_connectivity_measured(mut self, measured: bool) -> Self {
        self.connectivity_is_measured = measured;
        self
    }

    pub fn with_another_device_online(mut self, online: bool) -> Self {
        self.another_device_online = online;
        self
    }

    pub fn with_connectivity(mut self, c: Connectivity) -> Self {
        self.connectivity = c;
        self
    }

    pub fn with_station_activated(mut self, activated: bool) -> Self {
        self.station_activated = activated;
        self
    }

    pub fn with_saved_profiles(mut self, n: usize) -> Self {
        self.saved_profiles = n;
        self
    }

    pub fn with_autoconnect_success(mut self, ok: bool) -> Self {
        self.autoconnect_succeeds = ok;
        self
    }

    pub fn with_networks(mut self, networks: Vec<WifiNetwork>) -> Self {
        self.networks = networks;
        self
    }

    pub fn without_ap_support(mut self) -> Self {
        self.device.capabilities = 0;
        self
    }

    pub fn unmanaged(mut self) -> Self {
        self.device.managed = false;
        self
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn ap_raise_count(&self) -> u32 {
        self.state.lock().unwrap().ap_raises
    }

    fn record(&self, call: Call) {
        self.state.lock().unwrap().calls.push(call);
    }

    /// Index of the first call matching a predicate, for ordering assertions.
    pub fn position(&self, pred: impl Fn(&Call) -> bool) -> Option<usize> {
        self.calls().iter().position(pred)
    }
}

#[async_trait::async_trait]
impl NetworkControl for FakeNm {
    async fn find_device(&self, _interface: Option<&str>) -> Result<DeviceInfo, NetworkError> {
        self.record(Call::FindDevice);
        Ok(self.device.clone())
    }

    async fn check_connectivity(&self) -> Result<Connectivity, NetworkError> {
        self.record(Call::CheckConnectivity);
        Ok(self.connectivity)
    }

    async fn station_activated(&self, _device: &DeviceInfo) -> Result<bool, NetworkError> {
        self.record(Call::StationActivated);
        Ok(self.station_activated)
    }

    async fn connectivity_is_measured(&self) -> Result<bool, NetworkError> {
        Ok(self.connectivity_is_measured)
    }

    async fn another_device_online(&self, _device: &DeviceInfo) -> Result<bool, NetworkError> {
        self.record(Call::AnotherDeviceOnline);
        Ok(self.another_device_online)
    }

    async fn saved_wifi_profile_count(&self) -> Result<usize, NetworkError> {
        self.record(Call::SavedProfileCount);
        Ok(self.saved_profiles)
    }

    async fn await_autoconnect(
        &self,
        _device: &DeviceInfo,
        _budget: Duration,
    ) -> Result<bool, NetworkError> {
        self.record(Call::AwaitAutoconnect);
        Ok(self.autoconnect_succeeds)
    }

    async fn scan(&self, _device: &DeviceInfo) -> Result<Vec<WifiNetwork>, NetworkError> {
        self.record(Call::Scan);
        Ok(self.networks.clone())
    }

    async fn raise_ap(
        &self,
        _device: &DeviceInfo,
        config: &ApConfig,
    ) -> Result<ApHandle, NetworkError> {
        self.record(Call::RaiseAp {
            ssid: config.ssid.to_display_string(),
            encrypted: config.passphrase.is_some(),
        });
        if self.ap_fails {
            return Err(NetworkError::ApFailed("scripted failure".into()));
        }
        let mut state = self.state.lock().unwrap();
        state.ap_raises += 1;
        // A fresh UUID per raise, as the real implementation mints one, so
        // a test can tell which raise a teardown was aimed at.
        let uuid = format!("ap-{}", state.ap_raises);
        state.profiles.push(FakeProfile {
            uuid: uuid.clone(),
            id: crate::nm::nmrs_impl::AP_PROFILE_ID.into(),
            ssid: Some(config.ssid.to_display_string()),
            ap: true,
        });
        Ok(ApHandle {
            uuid,
            interface: "wlan0".into(),
        })
    }

    async fn tear_down_ap(&self, handle: &ApHandle) -> Result<(), NetworkError> {
        self.record(Call::TearDownAp {
            uuid: handle.uuid.clone(),
        });
        self.state
            .lock()
            .unwrap()
            .profiles
            .retain(|p| p.uuid != handle.uuid);
        Ok(())
    }

    async fn join(
        &self,
        _device: &DeviceInfo,
        request: &JoinRequest,
        _budget: Duration,
    ) -> Result<JoinOutcome, NetworkError> {
        self.record(Call::Join {
            ssid: request.ssid.to_display_string(),
        });
        let mut state = self.state.lock().unwrap();
        // Every attempt leaves a new profile named after the SSID, as
        // NetworkManager does, whatever profiles already carry that name.
        state.joins += 1;
        let uuid = format!("join-{}", state.joins);
        let ssid = request.ssid.to_display_string();
        state.profiles.push(FakeProfile::station(&uuid, &ssid));
        if state.join_results.is_empty() {
            Ok(JoinOutcome::Joined)
        } else {
            Ok(state.join_results.remove(0))
        }
    }

    async fn station_profile_uuids(&self, ssid: &Ssid) -> Result<Vec<String>, NetworkError> {
        if self.profiles_unreadable {
            return Err(NetworkError::Other("scripted failure".into()));
        }
        let want = ssid.to_display_string();
        Ok(self
            .state
            .lock()
            .unwrap()
            .profiles
            .iter()
            .filter(|p| !p.ap && p.ssid.as_deref() == Some(want.as_str()))
            .map(|p| p.uuid.clone())
            .collect())
    }

    async fn delete_profile(&self, uuid: &str) -> Result<(), NetworkError> {
        self.record(Call::DeleteProfile { uuid: uuid.into() });
        self.state
            .lock()
            .unwrap()
            .profiles
            .retain(|p| p.uuid != uuid);
        Ok(())
    }

    async fn restore(&self, _device: &DeviceInfo) -> Result<(), NetworkError> {
        self.record(Call::Restore);
        Ok(())
    }

    async fn sweep_stale_ap_profiles(&self, _interface: &str) -> Result<usize, NetworkError> {
        self.record(Call::SweepStaleAps);
        Ok(0)
    }
}
