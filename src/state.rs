//! State shared between the HTTP handlers and the state machine.
//!
//! The portal and the join loop run concurrently and communicate through
//! this, not through a channel of their own, because the HTTP side has to be
//! able to answer "what is happening right now?" at any moment — including
//! while the access point is down and the browser is retrying.
//!
//! `last_error` is the piece that makes a wrong password visible. Attempting
//! a join tears the AP down, so the browser that submitted the form loses
//! its server mid-request. We re-raise the AP on failure and the phone
//! rejoins automatically (same SSID, same PSK), and the error it then sees
//! comes from here. It only works because the process never exits between
//! attempts.

use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, watch};

use crate::cli::ThemeMode;
use crate::http::assets::UiDirectory;
use crate::nm::{JoinFailure, JoinRequest, WifiNetwork};

/// What the portal is doing, as the browser sees it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum PortalState {
    /// Waiting for the user to choose a network.
    Portal,
    /// A join is in flight. The access point is about to disappear.
    Joining { ssid: String },
    /// The last attempt failed; the AP has been raised again.
    Failed { ssid: String, error: String },
    /// Joined. The portal is about to shut down.
    Connected { ssid: String },
}

#[derive(Debug)]
struct Inner {
    networks: Vec<WifiNetwork>,
    state: PortalState,
    attempts: u32,
}

/// Handle shared by every HTTP handler.
#[derive(Clone)]
pub struct Shared {
    inner: Arc<Mutex<Inner>>,
    /// Submitted credentials, consumed by the state machine. Capacity 1:
    /// a second submission while one is in flight is rejected rather than
    /// queued, so a double-tapped button cannot queue two joins.
    join_tx: mpsc::Sender<JoinRequest>,
    /// Latched to `true` the first time the access point is up, which is
    /// the first moment the gateway address exists to be bound.
    ap_raised: Arc<watch::Sender<bool>>,
    /// The URL a client should be redirected to.
    pub portal_url: String,
    /// Everything an integrator can change about how the portal looks.
    pub branding: Branding,
    /// Whether enterprise joins check the RADIUS server's certificate,
    /// i.e. `--insecure-eap-skip-server-verification` is off. The portal
    /// refuses TTLS/PAP when it is not; see `http::api::check_policy`.
    pub eap_server_verified: bool,
}

/// The white-labelling surface, resolved at startup.
///
/// One struct rather than four parameters because it keeps growing, and
/// because every field is settled before the first request and never
/// changes afterwards.
#[derive(Clone)]
pub struct Branding {
    /// The product name shown in the page.
    pub name: String,
    /// The integrator's stylesheet, served at `/brand.css`.
    ///
    /// Read once at startup rather than per request: it is a handful of
    /// custom properties, the path is operator-supplied, and reading it
    /// eagerly means a typo in `--brand-css` fails at boot with a clear
    /// message instead of silently serving an unbranded portal to every
    /// client. `Arc<str>` because `Shared` is cloned into every handler.
    pub css: Option<Arc<str>>,
    /// The integrator's logo, served at `/brand-logo`.
    ///
    /// A route rather than a data: URI inlined into the page: it keeps the
    /// HTML small whether or not a logo is set, and a logo that fails to
    /// load degrades to its alt text, where a stylesheet that fails to
    /// load would leave the page unstyled.
    pub logo: Option<BrandLogo>,
    /// Which theme the page starts in.
    ///
    /// `System` follows the phone and leaves the in-page toggle on;
    /// anything else pins the page and takes the toggle away. A captive
    /// portal is open for a minute to get a device onto WiFi, and which
    /// of two colour schemes it uses is the integrator's decision, not
    /// something to ask the person holding the phone.
    pub theme: ThemeMode,
    /// `--ui-directory`, replacing the embedded pages and `/assets/`.
    ///
    /// Read at startup like the rest of this struct; see `UiDirectory`
    /// for why it is all-or-nothing and why that is also the
    /// path-traversal defence.
    pub ui: Option<Arc<UiDirectory>>,
}

/// An image and the content type to serve it as.
///
/// Read at startup like the stylesheet, so a mistyped path stops the
/// portal with the path in the message instead of serving a broken image
/// to every client.
#[derive(Clone)]
pub struct BrandLogo {
    pub bytes: Arc<[u8]>,
    pub content_type: &'static str,
}

impl Branding {
    /// Defaults: no stylesheet, no logo, and follow the phone's setting.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            css: None,
            logo: None,
            theme: ThemeMode::System,
            ui: None,
        }
    }
}

impl Shared {
    pub fn new(portal_url: String, branding: Branding) -> (Self, mpsc::Receiver<JoinRequest>) {
        let (join_tx, join_rx) = mpsc::channel(1);
        (
            Self {
                inner: Arc::new(Mutex::new(Inner {
                    networks: Vec::new(),
                    state: PortalState::Portal,
                    attempts: 0,
                })),
                join_tx,
                ap_raised: Arc::new(watch::Sender::new(false)),
                portal_url,
                branding,
                eap_server_verified: true,
            },
            join_rx,
        )
    }

    /// A poisoned lock means another thread panicked while holding it. The
    /// data behind it is three plain fields with no invariant that a panic
    /// could have broken halfway, so recovering is strictly better than
    /// propagating a panic into every HTTP handler and taking the portal
    /// down with it.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_networks(&self, networks: Vec<WifiNetwork>) {
        self.lock().networks = networks;
    }

    pub fn networks(&self) -> Vec<WifiNetwork> {
        self.lock().networks.clone()
    }

    pub fn state(&self) -> PortalState {
        self.lock().state.clone()
    }

    pub fn attempts(&self) -> u32 {
        self.lock().attempts
    }

    pub fn set_state(&self, state: PortalState) {
        self.lock().state = state;
    }

    pub fn record_failure(&self, ssid: &str, failure: JoinFailure) {
        let mut inner = self.lock();
        inner.attempts += 1;
        inner.state = PortalState::Failed {
            ssid: ssid.to_string(),
            error: failure.message(ssid),
        };
    }

    /// Record that the access point is up. Idempotent: only the first call
    /// after startup changes anything.
    pub fn mark_ap_raised(&self) {
        self.ap_raised.send_replace(true);
    }

    /// Resolve once the access point has been up at least once.
    ///
    /// DNS and HTTP bind the gateway address, which does not exist until
    /// NetworkManager has activated the AP. Before that comes the scan and
    /// the activation itself, together easily longer than any fixed bind
    /// retry budget on a slow radio, so the servers wait for this instead
    /// of guessing.
    pub async fn ap_raised(&self) {
        let mut rx = self.ap_raised.subscribe();
        // Only fails if the sender is dropped, and `self` holds it.
        let _ = rx.wait_for(|up| *up).await;
    }

    /// Is a join already running? Used to answer 409 rather than start a
    /// second one.
    pub fn is_joining(&self) -> bool {
        matches!(self.lock().state, PortalState::Joining { .. })
    }

    /// Hand credentials to the state machine.
    ///
    /// Returns `false` when a join is already in flight.
    pub async fn submit(&self, request: JoinRequest) -> bool {
        if self.is_joining() {
            return false;
        }
        let ssid = request.ssid.to_display_string();
        match self.join_tx.try_send(request) {
            Ok(()) => {
                self.set_state(PortalState::Joining { ssid });
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::security::Security;
    use crate::ssid::Ssid;

    fn shared() -> (Shared, mpsc::Receiver<JoinRequest>) {
        Shared::new("http://192.168.42.1/".into(), Branding::new("WiFi Connect"))
    }

    fn request(ssid: &str) -> JoinRequest {
        JoinRequest {
            ssid: Ssid::from(ssid),
            identity: None,
            passphrase: Some(crate::secret::Secret::new("abcdefgh")),
            server_domain: None,
            eap_method: Default::default(),
            hidden: false,
            ip: Default::default(),
        }
    }

    #[test]
    fn starts_in_the_portal_state() {
        let (s, _rx) = shared();
        assert_eq!(s.state(), PortalState::Portal);
        assert_eq!(s.attempts(), 0);
        assert!(s.networks().is_empty());
    }

    /// The servers bind the gateway address only after this resolves, so
    /// it must not resolve early — and once raised, a later wait (a server
    /// task scheduled after the AP came up) must not block.
    #[tokio::test(start_paused = true)]
    async fn ap_raised_waits_for_the_first_raise_and_then_stays_raised() {
        let (s, _rx) = shared();
        let early = tokio::time::timeout(std::time::Duration::from_secs(60), s.ap_raised()).await;
        assert!(early.is_err(), "resolved before the AP was raised");

        s.mark_ap_raised();
        s.ap_raised().await;
        s.mark_ap_raised();
        s.ap_raised().await;
    }

    #[tokio::test]
    async fn a_submission_moves_to_joining_and_reaches_the_machine() {
        let (s, mut rx) = shared();
        assert!(s.submit(request("Home")).await);

        assert_eq!(
            s.state(),
            PortalState::Joining {
                ssid: "Home".into()
            }
        );
        let got = rx
            .recv()
            .await
            .expect("the state machine should receive it");
        assert_eq!(got.ssid, Ssid::from("Home"));
    }

    /// A double-tapped Connect button must not queue two joins.
    #[tokio::test]
    async fn a_second_submission_while_joining_is_refused() {
        let (s, _rx) = shared();
        assert!(s.submit(request("Home")).await);
        assert!(
            !s.submit(request("Other")).await,
            "second submit should be refused"
        );
        assert!(s.is_joining());
    }

    /// The whole point of keeping state in the process: the error survives
    /// the access point going away and coming back.
    #[tokio::test]
    async fn a_failure_is_remembered_across_the_ap_bounce() {
        let (s, mut rx) = shared();
        s.submit(request("Office WiFi")).await;
        let _ = rx.recv().await;

        s.record_failure("Office WiFi", JoinFailure::BadPassword);

        match s.state() {
            PortalState::Failed { ssid, error } => {
                assert_eq!(ssid, "Office WiFi");
                assert!(error.contains("password"), "unhelpful message: {error}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(s.attempts(), 1);

        // And the portal is usable again for a retry.
        assert!(!s.is_joining());
        assert!(s.submit(request("Office WiFi")).await);
        assert_eq!(s.attempts(), 1, "a retry must not count as a new failure");
    }

    #[test]
    fn networks_round_trip() {
        let (s, _rx) = shared();
        s.set_networks(vec![WifiNetwork::new(
            Ssid::from("Home"),
            80,
            Security::WpaPsk,
            Some(2437),
        )]);
        let got = s.networks();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ssid, "Home");
    }

    #[test]
    fn state_serialises_with_a_discriminator_for_the_poller() {
        let json = serde_json::to_value(PortalState::Joining {
            ssid: "Home".into(),
        })
        .unwrap();
        assert_eq!(json["state"], "joining");
        assert_eq!(json["ssid"], "Home");

        let json = serde_json::to_value(PortalState::Portal).unwrap();
        assert_eq!(json["state"], "portal");
    }

    #[test]
    fn a_poisoned_lock_does_not_take_the_portal_down() {
        let (s, _rx) = shared();
        let s2 = s.clone();
        let _ = std::thread::spawn(move || {
            let _guard = s2.lock();
            panic!("poison the mutex");
        })
        .join();

        // The portal must still answer rather than panicking in every handler.
        assert_eq!(s.state(), PortalState::Portal);
        s.set_state(PortalState::Connected {
            ssid: "Home".into(),
        });
        assert!(matches!(s.state(), PortalState::Connected { .. }));
    }
}
