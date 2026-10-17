//! The provisioning state machine.
//!
//! ```text
//! Preflight ─► ConnectivityGate ─► Scan ─► RaiseAp ─► Portal ─► Join ─► Success
//!     │               │                                 ▲         │
//!  specific           │ already online ⇒ exit 0         └─ failed ┘
//!  exit codes         │                                 (re-raise, explain)
//! ```
//!
//! Three sequencing decisions are load-bearing, and all three are asserted
//! in the tests at the bottom:
//!
//! 1. **The scan happens before the access point is raised.** A radio in AP
//!    mode cannot scan. (This is also why v1 has no rescan button: a rescan
//!    would mean dropping the AP, disconnecting the user mid-setup.)
//! 2. **The connectivity gate waits for autoconnect only when a saved
//!    profile exists.** Associating plus DHCP plus a probe genuinely takes
//!    15-30s on a cold boot, so the wait is necessary — but a first-boot
//!    device with no profiles has nothing to wait *for*, and making its user
//!    stare at a blank screen for a minute is how the setup flow loses them.
//! 3. **A failed join deletes the station profile before re-raising.**
//!    Otherwise NetworkManager's autoconnect retries a known-bad profile
//!    forever and fights the portal for the radio.
//!
//! The retry loop and the connectivity probe live here, in the binary,
//! rather than in a shell wrapper. The previous integration learned that the
//! hard way: its wrapper ran `wget` under `set -euo pipefail`, so the
//! failing probe aborted the script before the `if [ $? -eq 0 ]` that was
//! meant to detect it, and the captive-portal branch was unreachable for
//! three years.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::nm::{
    ApConfig, ApHandle, Connectivity, DeviceInfo, JoinOutcome, JoinRequest, NetworkControl,
    NetworkError,
};

use crate::state::{PortalState, Shared};

/// Why the program stopped, and with what exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Joined a network, or was already online.
    Online,
    /// The activity timeout elapsed with no successful join.
    TimedOut,
    /// Asked to stop (SIGTERM, SIGINT).
    Cancelled,
}

impl Outcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Online | Outcome::Cancelled => 0,
            Outcome::TimedOut => 6,
        }
    }
}

/// Timing and identity for one run.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub ap: ApConfig,
    pub interface: Option<String>,
    /// How long to let an existing profile bring us online before giving up
    /// and showing the portal.
    pub autoconnect_budget: Duration,
    /// Hard cap on one join attempt. Guards the case where NM parks the
    /// device in NEED_AUTH waiting for a secret agent that does not exist —
    /// the classic "it just hangs".
    pub join_budget: Duration,
    /// Exit after this long with no successful join. Zero means never.
    pub activity_timeout: Duration,
    /// Skip the connectivity gate entirely.
    pub force: bool,
}

/// Run preflight and decide whether the portal is needed at all.
///
/// `Ok(None)` means "already online, nothing to do".
pub async fn preflight<N: NetworkControl>(
    nm: &N,
    config: &RunConfig,
) -> Result<Option<DeviceInfo>, NetworkError> {
    let device = nm.find_device(config.interface.as_deref()).await?;
    info!(
        interface = %device.interface,
        driver = %device.driver,
        "found a WiFi device"
    );

    if !device.managed {
        return Err(NetworkError::Unmanaged(device.interface.clone()));
    }

    // The capability bit comes from the kernel's nl80211 supported_iftypes,
    // so it is accurate for mainline drivers. Out-of-tree vendor drivers
    // sometimes claim AP and then fail to start one; that case surfaces
    // later as an activation failure and is reported separately.
    if !device.supports_ap_mode() {
        return Err(NetworkError::ApUnsupported {
            interface: device.interface.clone(),
            driver: device.driver.clone(),
        });
    }

    // Recover from a previous run that crashed with the AP up.
    match nm.sweep_stale_ap_profiles(&device.interface).await {
        Ok(0) => {}
        Ok(n) => warn!(
            count = n,
            "removed stale access-point profiles from a previous run"
        ),
        Err(e) => warn!(error = %e, "could not sweep stale access-point profiles"),
    }

    if config.force {
        debug!("--force: skipping the connectivity gate");
        return Ok(Some(device));
    }

    if nm.check_connectivity().await? == Connectivity::Full {
        info!("already online; the portal is not needed");
        return Ok(None);
    }

    // The asymmetry that stops the portal racing boot-time autoconnect.
    let saved = nm.saved_wifi_profile_count().await?;
    if saved > 0 {
        info!(
            saved,
            budget_s = config.autoconnect_budget.as_secs(),
            "waiting for a saved network to come up before showing the portal"
        );
        if nm
            .await_autoconnect(&device, config.autoconnect_budget)
            .await?
        {
            info!("a saved network came up; the portal is not needed");
            return Ok(None);
        }
        info!("no saved network came up");
    } else {
        debug!("no saved WiFi profiles; showing the portal immediately");
    }

    Ok(Some(device))
}

/// Everything that must be undone before exiting, whatever the reason.
struct Teardown<'a, N: NetworkControl> {
    nm: &'a N,
    device: &'a DeviceInfo,
    ap: Option<ApHandle>,
}

impl<N: NetworkControl> Teardown<'_, N> {
    /// Best-effort, and each step is independent: a failure in one must not
    /// stop the others, or we leave the radio in AP mode.
    async fn run(&mut self) {
        if let Some(handle) = self.ap.take()
            && let Err(e) = self.nm.tear_down_ap(&handle).await
        {
            warn!(error = %e, "could not tear down the access point");
        }
        if let Err(e) = self
            .nm
            .sweep_stale_ap_profiles(&self.device.interface)
            .await
        {
            warn!(error = %e, "could not sweep access-point profiles");
        }
        if let Err(e) = self.nm.restore(self.device).await {
            warn!(error = %e, "could not restore the device to station mode");
        }
    }
}

/// Raise the portal and run it until a join succeeds, time runs out, or we
/// are cancelled.
pub async fn run_portal<N: NetworkControl>(
    nm: &N,
    device: &DeviceInfo,
    config: &RunConfig,
    shared: &Shared,
    mut joins: mpsc::Receiver<JoinRequest>,
    cancel: CancellationToken,
) -> Result<Outcome, NetworkError> {
    // Scan FIRST. The radio cannot scan once it is an access point.
    let networks = match nm.scan(device).await {
        Ok(n) => n,
        Err(e) => {
            // A failed scan is survivable: the portal still offers manual
            // entry, which is the path a hidden network needs anyway.
            warn!(error = %e, "scan failed; the portal will offer manual entry only");
            Vec::new()
        }
    };
    info!(count = networks.len(), "scan complete");
    shared.set_networks(networks);

    let mut teardown = Teardown {
        nm,
        device,
        ap: None,
    };
    let outcome = portal_loop(
        nm,
        device,
        config,
        shared,
        &mut joins,
        &cancel,
        &mut teardown,
    )
    .await;
    teardown.run().await;
    outcome
}

async fn portal_loop<N: NetworkControl>(
    nm: &N,
    device: &DeviceInfo,
    config: &RunConfig,
    shared: &Shared,
    joins: &mut mpsc::Receiver<JoinRequest>,
    cancel: &CancellationToken,
    teardown: &mut Teardown<'_, N>,
) -> Result<Outcome, NetworkError> {
    let deadline = (!config.activity_timeout.is_zero())
        .then(|| tokio::time::Instant::now() + config.activity_timeout);

    loop {
        // Raise (or re-raise) the access point. The SSID and passphrase are
        // byte-identical every time, which is what lets a phone that joined
        // once reassociate automatically after a failed attempt.
        teardown.ap = Some(nm.raise_ap(device, &config.ap).await?);
        info!(ssid = %config.ap.ssid, "access point is up; portal is live");

        let request = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(Outcome::Cancelled),
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    // No timeout configured: never fire.
                    None => std::future::pending::<()>().await,
                }
            } => {
                info!("activity timeout elapsed with no successful join");
                return Ok(Outcome::TimedOut);
            }
            r = joins.recv() => match r {
                Some(r) => r,
                // The portal dropped its sender, which can only happen on
                // shutdown.
                None => return Ok(Outcome::Cancelled),
            },
        };

        let ssid = request.ssid.to_display_string();
        info!(%ssid, "attempting to join");

        // Drop the access point before attempting the join: the radio
        // cannot be both. The browser has already been answered.
        if let Some(handle) = teardown.ap.take()
            && let Err(e) = nm.tear_down_ap(&handle).await
        {
            warn!(error = %e, "could not tear down the access point before joining");
        }

        match nm.join(device, &request, config.join_budget).await? {
            JoinOutcome::Joined => {
                info!(%ssid, "joined");
                shared.set_state(PortalState::Connected { ssid });
                return Ok(Outcome::Online);
            }
            JoinOutcome::Failed(failure) => {
                warn!(%ssid, ?failure, "join failed");
                // Delete the profile we just created. Leaving it behind
                // means NM autoconnect retries a known-bad profile forever
                // and fights us for the radio.
                if let Err(e) = nm.forget(&request.ssid).await {
                    warn!(error = %e, "could not delete the failed profile");
                }
                shared.record_failure(&ssid, failure);
                // Loop: re-raise the AP so the user can see why and retry.
            }
        }
    }
}

/// Convenience wrapper used by `main`.
pub async fn run<N: NetworkControl>(
    nm: &N,
    config: &RunConfig,
    shared: &Shared,
    joins: mpsc::Receiver<JoinRequest>,
    cancel: CancellationToken,
) -> Result<Outcome, NetworkError> {
    match preflight(nm, config).await? {
        None => Ok(Outcome::Online),
        Some(device) => run_portal(nm, &device, config, shared, joins, cancel).await,
    }
}

/// Resolve the exit code and log the reason.
pub fn report(result: &Result<Outcome, NetworkError>) -> i32 {
    match result {
        Ok(outcome) => {
            debug!(?outcome, "finished");
            outcome.exit_code()
        }
        Err(e) => {
            error!("{e}");
            match e {
                NetworkError::NoWifiDevice => 3,
                NetworkError::ApUnsupported { .. }
                | NetworkError::Unmanaged(_)
                | NetworkError::RadioBlocked => 4,
                NetworkError::Unreachable(_) => 5,
                _ => 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::fake::{Call, FakeNm};
    use crate::nm::security::Security;
    use crate::nm::{ApSecurity, JoinFailure, WifiNetwork};
    use crate::secret::Secret;
    use crate::ssid::Ssid;

    fn config() -> RunConfig {
        RunConfig {
            ap: ApConfig {
                ssid: Ssid::from("Setup"),
                passphrase: Some(Secret::new("abcdefghijklmn")),
                security: ApSecurity::Wpa2Psk,
                gateway: std::net::Ipv4Addr::new(192, 168, 42, 1),
                prefix: 24,
                channel: None,
            },
            interface: None,
            autoconnect_budget: Duration::from_secs(60),
            join_budget: Duration::from_secs(45),
            activity_timeout: Duration::ZERO,
            force: false,
        }
    }

    fn shared() -> (Shared, mpsc::Receiver<JoinRequest>) {
        Shared::new("http://192.168.42.1/".into(), "Test".into())
    }

    fn request(ssid: &str) -> JoinRequest {
        JoinRequest {
            ssid: Ssid::from(ssid),
            identity: None,
            passphrase: Some(Secret::new("abcdefgh")),
            hidden: false,
        }
    }

    // ---- the connectivity gate -------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn an_already_online_device_never_raises_the_portal() {
        let nm = FakeNm::new().with_connectivity(Connectivity::Full);
        assert!(preflight(&nm, &config()).await.unwrap().is_none());
        assert!(
            !nm.calls().iter().any(|c| matches!(c, Call::RaiseAp { .. })),
            "an online device must not broadcast a setup network"
        );
    }

    /// Associating, DHCP and a probe take 15-30s from cold. Without this
    /// wait the portal races boot-time autoconnect and a perfectly
    /// configured device advertises a setup AP anyway.
    #[tokio::test(start_paused = true)]
    async fn a_device_with_saved_profiles_waits_for_autoconnect() {
        let nm = FakeNm::new()
            .with_saved_profiles(1)
            .with_autoconnect_success(true);

        assert!(preflight(&nm, &config()).await.unwrap().is_none());
        assert!(nm.calls().contains(&Call::AwaitAutoconnect));
    }

    /// ...but a first-boot device has nothing to wait for, and making its
    /// user stare at a blank screen for a minute is how setup loses them.
    #[tokio::test(start_paused = true)]
    async fn a_device_with_no_saved_profiles_does_not_wait() {
        let nm = FakeNm::new().with_saved_profiles(0);

        assert!(preflight(&nm, &config()).await.unwrap().is_some());
        assert!(
            !nm.calls().contains(&Call::AwaitAutoconnect),
            "nothing to wait for; the portal should come up at once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn autoconnect_that_does_not_come_up_falls_through_to_the_portal() {
        let nm = FakeNm::new()
            .with_saved_profiles(2)
            .with_autoconnect_success(false);
        assert!(preflight(&nm, &config()).await.unwrap().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn force_skips_the_gate_entirely() {
        let nm = FakeNm::new().with_connectivity(Connectivity::Full);
        let mut cfg = config();
        cfg.force = true;

        assert!(preflight(&nm, &cfg).await.unwrap().is_some());
        assert!(!nm.calls().contains(&Call::CheckConnectivity));
    }

    // ---- preflight failures ----------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn an_adapter_without_ap_support_fails_with_a_specific_error() {
        let nm = FakeNm::new().without_ap_support();
        let err = preflight(&nm, &config()).await.unwrap_err();

        match &err {
            NetworkError::ApUnsupported { interface, driver } => {
                assert_eq!(interface, "wlan0");
                // The driver name belongs in the message: an out-of-tree
                // driver is the usual reason this happens.
                assert_eq!(driver, "brcmfmac");
            }
            other => panic!("expected ApUnsupported, got {other:?}"),
        }
        // Exit code 4: the device is unusable, not merely offline.
        assert_eq!(report(&Err(err)), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unmanaged_device_is_reported_distinctly() {
        let nm = FakeNm::new().unmanaged();
        let err = preflight(&nm, &config()).await.unwrap_err();
        assert!(matches!(err, NetworkError::Unmanaged(_)));
        assert_eq!(report(&Err(err)), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn a_crashed_previous_run_is_swept_before_anything_else() {
        let nm = FakeNm::new();
        preflight(&nm, &config()).await.unwrap();

        let sweep = nm.position(|c| *c == Call::SweepStaleAps).unwrap();
        let find = nm.position(|c| *c == Call::FindDevice).unwrap();
        assert!(find < sweep, "the device must be found before sweeping it");
    }

    // ---- the portal loop -------------------------------------------------

    /// A radio in AP mode cannot scan, so the order is not negotiable.
    #[tokio::test(start_paused = true)]
    async fn the_scan_happens_before_the_access_point_is_raised() {
        let nm = FakeNm::new().with_networks(vec![WifiNetwork::new(
            Ssid::from("Home"),
            80,
            Security::WpaPsk,
            Some(2437),
        )]);
        let (shared, rx) = shared();
        let cancel = CancellationToken::new();

        let device = nm.find_device(None).await.unwrap();
        let handle = {
            let nm = nm.clone();
            let shared = shared.clone();
            let cancel = cancel.clone();
            let cfg = config();
            tokio::spawn(async move { run_portal(&nm, &device, &cfg, &shared, rx, cancel).await })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        handle.await.unwrap().unwrap();

        let scan = nm
            .position(|c| *c == Call::Scan)
            .expect("should have scanned");
        let raise = nm
            .position(|c| matches!(c, Call::RaiseAp { .. }))
            .expect("should have raised an AP");
        assert!(
            scan < raise,
            "scanned after raising the AP: {:?}",
            nm.calls()
        );
    }

    /// The CRA requirement, asserted end-to-end: no run raises an
    /// unencrypted access point.
    #[tokio::test(start_paused = true)]
    async fn the_access_point_is_always_raised_encrypted() {
        let nm = FakeNm::new();
        let (shared, rx) = shared();
        let cancel = CancellationToken::new();
        let device = nm.find_device(None).await.unwrap();

        let handle = {
            let (nm, shared, cancel, cfg) = (nm.clone(), shared.clone(), cancel.clone(), config());
            tokio::spawn(async move { run_portal(&nm, &device, &cfg, &shared, rx, cancel).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        handle.await.unwrap().unwrap();

        let raised: Vec<_> = nm
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::RaiseAp { encrypted, .. } => Some(encrypted),
                _ => None,
            })
            .collect();
        assert!(!raised.is_empty());
        assert!(raised.iter().all(|e| *e), "an unencrypted AP was raised");
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_join_tears_down_and_reports_online() {
        let nm = FakeNm::new().with_join_results(vec![JoinOutcome::Joined]);
        let (shared, rx) = shared();
        let device = nm.find_device(None).await.unwrap();

        shared.submit(request("Home")).await;

        let outcome = run_portal(
            &nm,
            &device,
            &config(),
            &shared,
            rx,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(outcome, Outcome::Online);
        assert_eq!(outcome.exit_code(), 0);
        assert!(matches!(shared.state(), PortalState::Connected { .. }));
        assert!(nm.calls().contains(&Call::Restore), "radio left in AP mode");
    }

    /// The sequence that makes a wrong password explainable.
    #[tokio::test(start_paused = true)]
    async fn a_failed_join_forgets_the_profile_and_raises_the_ap_again() {
        let nm = FakeNm::new().with_join_results(vec![
            JoinOutcome::Failed(JoinFailure::BadPassword),
            JoinOutcome::Joined,
        ]);
        let (shared, rx) = shared();
        let device = nm.find_device(None).await.unwrap();

        // First attempt fails, second succeeds.
        shared.submit(request("Office")).await;

        let cancel = CancellationToken::new();
        let handle = {
            let (nm, shared, cancel, cfg) = (nm.clone(), shared.clone(), cancel.clone(), config());
            tokio::spawn(async move { run_portal(&nm, &device, &cfg, &shared, rx, cancel).await })
        };

        // Let the first attempt fail, then retry.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            matches!(shared.state(), PortalState::Failed { .. }),
            "the failure must be visible to the portal: {:?}",
            shared.state()
        );
        shared.submit(request("Office")).await;

        let outcome = handle.await.unwrap().unwrap();
        assert_eq!(outcome, Outcome::Online);

        let calls = nm.calls();
        let forget = calls
            .iter()
            .position(|c| matches!(c, Call::Forget { .. }))
            .expect("the failed profile must be deleted");
        let second_raise = calls
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(c, Call::RaiseAp { .. }))
            .nth(1)
            .map(|(i, _)| i)
            .expect("the AP must come back so the user can see why");

        assert!(
            forget < second_raise,
            "the bad profile must be deleted before the AP returns, or NM \
             autoconnect fights the portal for the radio: {calls:?}"
        );
        assert_eq!(nm.ap_raise_count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_ap_is_torn_down_before_each_join_attempt() {
        let nm = FakeNm::new().with_join_results(vec![JoinOutcome::Joined]);
        let (shared, rx) = shared();
        let device = nm.find_device(None).await.unwrap();
        shared.submit(request("Home")).await;

        run_portal(
            &nm,
            &device,
            &config(),
            &shared,
            rx,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let calls = nm.calls();
        let raise = calls
            .iter()
            .position(|c| matches!(c, Call::RaiseAp { .. }))
            .unwrap();
        let down = calls.iter().position(|c| *c == Call::TearDownAp).unwrap();
        let join = calls
            .iter()
            .position(|c| matches!(c, Call::Join { .. }))
            .unwrap();

        assert!(raise < down && down < join, "bad ordering: {calls:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_activity_timeout_gives_up_with_a_distinct_exit_code() {
        let nm = FakeNm::new();
        let (shared, rx) = shared();
        let device = nm.find_device(None).await.unwrap();

        let mut cfg = config();
        cfg.activity_timeout = Duration::from_secs(600);

        let outcome = run_portal(&nm, &device, &cfg, &shared, rx, CancellationToken::new())
            .await
            .unwrap();

        assert_eq!(outcome, Outcome::TimedOut);
        assert_eq!(outcome.exit_code(), 6);
        assert!(nm.calls().contains(&Call::Restore));
    }

    /// balena sends SIGTERM on every update. Leaving the radio in AP mode
    /// would strand the device.
    #[tokio::test(start_paused = true)]
    async fn cancellation_still_restores_the_radio() {
        let nm = FakeNm::new();
        let (shared, rx) = shared();
        let device = nm.find_device(None).await.unwrap();
        let cancel = CancellationToken::new();

        let handle = {
            let (nm, shared, cancel, cfg) = (nm.clone(), shared.clone(), cancel.clone(), config());
            tokio::spawn(async move { run_portal(&nm, &device, &cfg, &shared, rx, cancel).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        let outcome = handle.await.unwrap().unwrap();
        assert_eq!(outcome, Outcome::Cancelled);
        assert_eq!(outcome.exit_code(), 0);

        let calls = nm.calls();
        assert!(calls.contains(&Call::TearDownAp), "AP left up: {calls:?}");
        assert!(
            calls.contains(&Call::Restore),
            "radio not restored: {calls:?}"
        );
    }

    /// A failed scan must not be fatal: manual entry is the path a hidden
    /// network needs anyway.
    #[tokio::test(start_paused = true)]
    async fn the_portal_still_comes_up_when_the_scan_finds_nothing() {
        let nm = FakeNm::new().with_networks(vec![]);
        let (shared, rx) = shared();
        let device = nm.find_device(None).await.unwrap();
        let cancel = CancellationToken::new();

        let handle = {
            let (nm, shared, cancel, cfg) = (nm.clone(), shared.clone(), cancel.clone(), config());
            tokio::spawn(async move { run_portal(&nm, &device, &cfg, &shared, rx, cancel).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        handle.await.unwrap().unwrap();

        assert!(nm.ap_raise_count() >= 1);
    }

    #[test]
    fn exit_codes_distinguish_the_failure_modes() {
        assert_eq!(report(&Ok(Outcome::Online)), 0);
        assert_eq!(report(&Ok(Outcome::Cancelled)), 0);
        assert_eq!(report(&Ok(Outcome::TimedOut)), 6);
        assert_eq!(report(&Err(NetworkError::NoWifiDevice)), 3);
        assert_eq!(report(&Err(NetworkError::RadioBlocked)), 4);
        assert_eq!(report(&Err(NetworkError::Unreachable("bus".into()))), 5);
    }
}
