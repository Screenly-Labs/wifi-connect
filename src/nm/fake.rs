//! An in-memory `NetworkControl` for tests.
//!
//! Deliberately a hand-written fake with a **recorded call log** rather than
//! a mock framework. The assertions that matter in this program are ordering
//! assertions — "we scanned before raising the access point", "the failed
//! station profile was deleted before the AP came back", "teardown ran even
//! on SIGTERM" — and a `Vec<Call>` expresses those far more directly than
//! expectation macros do.

#![cfg(test)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{
    ApConfig, ApHandle, Connectivity, DeviceInfo, JoinOutcome, JoinRequest, LinkState,
    NetworkControl, NetworkError, WIFI_DEVICE_CAP_AP, WifiNetwork,
};
use crate::ssid::Ssid;

/// One interaction with the network stack, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    FindDevice,
    CheckConnectivity,
    LinkState,
    SavedProfileCount,
    AwaitAutoconnect,
    Scan,
    RaiseAp { ssid: String, encrypted: bool },
    TearDownAp,
    Join { ssid: String },
    Forget { ssid: String },
    Restore,
    SweepStaleAps,
}

#[derive(Debug)]
struct State {
    calls: Vec<Call>,
    join_results: Vec<JoinOutcome>,
    ap_raises: u32,
}

/// A scriptable network stack.
#[derive(Clone)]
pub struct FakeNm {
    state: Arc<Mutex<State>>,
    pub device: DeviceInfo,
    pub connectivity: Connectivity,
    pub link: LinkState,
    pub saved_profiles: usize,
    pub autoconnect_succeeds: bool,
    pub networks: Vec<WifiNetwork>,
    pub ap_fails: bool,
}

impl FakeNm {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                calls: Vec::new(),
                join_results: Vec::new(),
                ap_raises: 0,
            })),
            device: DeviceInfo {
                interface: "wlan0".into(),
                driver: "brcmfmac".into(),
                capabilities: WIFI_DEVICE_CAP_AP,
                managed: true,
            },
            connectivity: Connectivity::None,
            // Nothing connected: NM_STATE_DISCONNECTED, radio idle.
            link: LinkState {
                nm_state: 20,
                station_activated: false,
            },
            saved_profiles: 0,
            autoconnect_succeeds: false,
            networks: Vec::new(),
            ap_fails: false,
        }
    }

    /// Script the outcome of each successive join attempt, in order.
    pub fn with_join_results(self, results: Vec<JoinOutcome>) -> Self {
        self.state.lock().unwrap().join_results = results;
        self
    }

    pub fn with_connectivity(mut self, c: Connectivity) -> Self {
        self.connectivity = c;
        self
    }

    pub fn with_link_state(mut self, link: LinkState) -> Self {
        self.link = link;
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

    async fn link_state(&self, _device: &DeviceInfo) -> Result<LinkState, NetworkError> {
        self.record(Call::LinkState);
        Ok(self.link)
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
        Ok(ApHandle {
            uuid: "00000000-0000-4000-8000-00000000fake".into(),
            interface: "wlan0".into(),
        })
    }

    async fn tear_down_ap(&self, _handle: &ApHandle) -> Result<(), NetworkError> {
        self.record(Call::TearDownAp);
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
        if state.join_results.is_empty() {
            Ok(JoinOutcome::Joined)
        } else {
            Ok(state.join_results.remove(0))
        }
    }

    async fn forget(&self, ssid: &Ssid) -> Result<(), NetworkError> {
        self.record(Call::Forget {
            ssid: ssid.to_display_string(),
        });
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
