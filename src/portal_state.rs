//! The portal's state, written where a host application can read it.
//!
//! A device raising a setup access point almost always has a second
//! screen on it — a signage display, a kiosk, an e-ink panel — and that
//! screen is the only way the generated passphrase reaches the person
//! standing in front of it: the passphrase is what gets you *onto* the
//! network, so it cannot be served over the network.
//!
//! That host application needs two facts, and historically had to work
//! for both: the credentials (by re-parsing the `WIFI:` payload out of
//! the QR text file) and whether a portal is running at all (by probing
//! the portal's own HTTP listener, which is bound scoped to the wireless
//! device precisely so that nothing on the customer's LAN — including a
//! sibling container — can reach it). Neither is a sound contract. This
//! file is: one atomic write, one documented schema, no HTTP.
//!
//! **Presence is the liveness signal.** The file is written once a portal
//! run has committed to raising the access point, and removed when the
//! run ends, whatever the outcome. It is deliberately NOT written by the
//! runs that exit immediately because the device turned out to be online
//! — those runs are why the QR files, which are written before that check,
//! could never answer the question on their own.
//!
//! A `SIGKILL` leaves the file behind, so a consumer that must not show
//! stale credentials should corroborate with something the kernel owns:
//! the gateway address is on the wireless interface for exactly as long
//! as the access point is up.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tracing::{error, info, warn};

use crate::private_file;
use crate::qr;
use crate::secret::Secret;
use crate::ssid::Ssid;

/// Bumped only for a change a consumer must be told about: a removed
/// field, or a field whose meaning changes. Adding a field does not bump
/// it, so parse leniently and ignore what you do not know.
pub const SCHEMA: u32 = 1;

/// How the access point is protected, as a stable string rather than a
/// shape a consumer has to infer from which fields are null.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    /// WPA2-PSK or WPA3-SAE: there is a passphrase, and it is below.
    Wpa,
    /// `--insecure-open-portal`: no passphrase, nothing to display.
    Open,
}

impl fmt::Display for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Security::Wpa => write!(f, "wpa"),
            Security::Open => write!(f, "open"),
        }
    }
}

/// One portal run, as JSON.
///
/// Field order here is the field order on disk, which is worth keeping
/// stable: the file is read by people as well as programs, and the first
/// thing anyone wants is what to type into a phone.
#[derive(Debug, Serialize)]
pub struct PortalState {
    pub schema: u32,
    /// Always `true` in a file that exists. It is written out rather than
    /// implied so that a consumer which reads a partial or substituted
    /// file fails closed instead of treating "parsed at all" as "live".
    pub portal_active: bool,
    /// The name on the air, suffix included — not the configured prefix.
    pub ssid: String,
    pub security: Security,
    /// `None` for an open access point.
    pub passphrase: Option<String>,
    /// The `WIFI:` payload, so a host application can render the join QR
    /// at whatever size its screen wants without re-deriving the escaping
    /// rules. `None` for an open access point, which has nothing to join
    /// with.
    pub qr_payload: Option<String>,
    /// Where the portal answers, for the "or open this address" line that
    /// every setup screen ends up needing.
    pub portal_url: String,
    pub gateway: String,
    pub port: u16,
    /// Unix seconds. A consumer can use it to distrust a file left behind
    /// by a killed process; it is not a heartbeat and is not updated
    /// while the portal runs.
    pub started_at_unix: u64,
}

impl PortalState {
    pub fn new(
        ssid: &Ssid,
        passphrase: Option<&Secret>,
        portal_url: String,
        gateway: std::net::Ipv4Addr,
        port: u16,
    ) -> Self {
        let (security, secret, payload) = match passphrase {
            Some(p) => (
                Security::Wpa,
                Some(p.expose().to_owned()),
                Some(qr::wifi_payload(ssid, p, false)),
            ),
            None => (Security::Open, None, None),
        };

        Self {
            schema: SCHEMA,
            portal_active: true,
            ssid: ssid.to_display_string(),
            security,
            passphrase: secret,
            qr_payload: payload,
            portal_url,
            gateway: gateway.to_string(),
            port,
            started_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        }
    }

    /// Write the file and return a guard that removes it again.
    ///
    /// Best-effort by design: a host application that cannot be told the
    /// credentials is a degraded setup experience, while refusing to
    /// raise the access point over it would be no setup experience at
    /// all. Failures are logged at ERROR and the run continues.
    pub fn publish(self, path: &Path) -> Option<StateFile> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
            && let Err(e) = private_file::create_dir(parent)
        {
            error!(
                error = %e,
                path = %parent.display(),
                "could not create the state file's directory"
            );
            return None;
        }

        // Pretty-printed: the other reader of this file is a person with
        // `cat`, debugging why a screen is not showing a passphrase.
        let mut json = match serde_json::to_vec_pretty(&self) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "could not serialise the portal state");
                return None;
            }
        };
        json.push(b'\n');

        // Carries the passphrase in plain text, so it is written like the
        // QR files: 0640, atomically, and never through a symlink planted
        // at the target.
        match private_file::write(path, &json) {
            Ok(()) => {
                info!(path = %path.display(), "wrote the portal state file");
                Some(StateFile {
                    path: path.to_path_buf(),
                })
            }
            Err(e) => {
                error!(error = %e, path = %path.display(), "could not write the portal state file");
                None
            }
        }
    }
}

/// Removes the state file when the portal run ends.
///
/// A guard rather than a call at the end of `run()`: the run has several
/// exits, including the error paths, and a file saying a portal is live
/// after one of them is exactly the failure this whole mechanism exists
/// to prevent.
#[derive(Debug)]
pub struct StateFile {
    path: PathBuf,
}

impl Drop for StateFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => info!(path = %self.path.display(), "removed the portal state file"),
            // Already gone is the normal outcome of an operator clearing
            // the directory, and nothing to report.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                error = %e,
                path = %self.path.display(),
                "could not remove the portal state file; a consumer may \
                 believe the portal is still up"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt;

    /// A scratch directory unique to one test, removed on drop. Matches
    /// private_file's, rather than pulling in a crate.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "wifi-connect-portal-state-{}-{test}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn wpa_state() -> PortalState {
        PortalState::new(
            &Ssid::from("Anthias Setup-G4VV"),
            Some(&Secret::new("brave-plum-42")),
            "http://192.168.42.1:8000/".to_owned(),
            Ipv4Addr::new(192, 168, 42, 1),
            8000,
        )
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    /// The contract, field by field. This test is the schema: a change
    /// that breaks it is a change every consumer has to be told about.
    #[test]
    fn the_file_carries_what_a_setup_screen_needs() {
        let dir = Scratch::new("contract");
        let path = dir.join("state.json");

        let guard = wpa_state().publish(&path).expect("should have written");
        let v = read_json(&path);

        assert_eq!(v["schema"], 1);
        assert_eq!(v["portal_active"], true);
        assert_eq!(v["ssid"], "Anthias Setup-G4VV");
        assert_eq!(v["security"], "wpa");
        assert_eq!(v["passphrase"], "brave-plum-42");
        assert_eq!(v["portal_url"], "http://192.168.42.1:8000/");
        assert_eq!(v["gateway"], "192.168.42.1");
        assert_eq!(v["port"], 8000);
        assert!(v["started_at_unix"].as_u64().unwrap() > 1_700_000_000);

        // The payload is the one a phone would scan, not a second
        // rendering of the credentials that could disagree with them.
        assert_eq!(
            v["qr_payload"],
            "WIFI:T:WPA;S:Anthias Setup-G4VV;P:brave-plum-42;H:false;;"
        );

        drop(guard);
    }

    /// The SSID written is the one on the air, suffix and all — a consumer
    /// printing the configured prefix would send someone looking for a
    /// network that is not being broadcast.
    #[test]
    fn the_ssid_is_the_one_on_the_air() {
        let dir = Scratch::new("ssid");
        let path = dir.join("state.json");
        let ssid = Ssid::from(crate::ssid::with_random_suffix("Anthias Setup", 4).as_str());

        let _guard = PortalState::new(
            &ssid,
            Some(&Secret::new("x".repeat(14))),
            "http://192.168.42.1:8000/".to_owned(),
            Ipv4Addr::new(192, 168, 42, 1),
            8000,
        )
        .publish(&path);

        let v = read_json(&path);
        assert_eq!(v["ssid"], ssid.to_display_string());
        assert_ne!(v["ssid"], "Anthias Setup");
    }

    /// An open portal has nothing to display and must not pretend
    /// otherwise: a screen that renders a `null` passphrase as "null" is
    /// a support call, but one that is told `security: open` can say so.
    #[test]
    fn an_open_portal_reports_no_passphrase() {
        let dir = Scratch::new("open");
        let path = dir.join("state.json");

        let _guard = PortalState::new(
            &Ssid::from("Anthias Setup-G4VV"),
            None,
            "http://192.168.42.1:8000/".to_owned(),
            Ipv4Addr::new(192, 168, 42, 1),
            8000,
        )
        .publish(&path);

        let v = read_json(&path);
        assert_eq!(v["security"], "open");
        assert!(v["passphrase"].is_null());
        assert!(v["qr_payload"].is_null());
        assert_eq!(v["portal_active"], true);
    }

    /// It holds a WPA passphrase in plain text. Same handling as the QR
    /// files, for the same reason.
    #[test]
    fn the_file_is_written_as_a_credential() {
        let dir = Scratch::new("perms");
        let path = dir.join("state.json");

        let _guard = wpa_state().publish(&path);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "mode was {mode:o}");
    }

    /// Presence is the liveness signal, so the removal is the half that
    /// matters: a file left behind says "a portal is up" to every
    /// consumer, forever.
    #[test]
    fn the_file_goes_away_when_the_run_ends() {
        let dir = Scratch::new("drop");
        let path = dir.join("state.json");

        let guard = wpa_state().publish(&path).expect("should have written");
        assert!(path.exists());

        drop(guard);
        assert!(!path.exists(), "the state file outlived the portal run");
    }

    /// Dropping twice, or after an operator cleared the directory, is not
    /// an error worth reporting — and must not panic in a Drop.
    #[test]
    fn removing_a_file_that_is_already_gone_is_quiet() {
        let dir = Scratch::new("gone");
        let path = dir.join("state.json");

        let guard = wpa_state().publish(&path).expect("should have written");
        fs::remove_file(&path).unwrap();
        drop(guard);
    }

    /// The directory is the integrator's — a volume mount, a tmpfs — and
    /// may not exist yet on a first boot.
    #[test]
    fn a_missing_directory_is_created() {
        let dir = Scratch::new("mkdir");
        let path = dir.join("nested/deeper/state.json");

        let _guard = wpa_state().publish(&path).expect("should have written");
        assert!(path.exists());
    }

    /// A state file that cannot be written must not stop the access point
    /// going up: no credentials on the screen is bad, no setup portal at
    /// all is worse.
    #[test]
    fn an_unwritable_path_is_survivable() {
        let dir = Scratch::new("unwritable");
        let blocker = dir.join("state.json");
        // A directory where the file should go: write() cannot replace it.
        fs::create_dir(&blocker).unwrap();

        assert!(
            wpa_state().publish(&blocker).is_none(),
            "should have reported failure rather than claiming a live portal"
        );
    }

    /// Read by people as well as programs.
    #[test]
    fn the_file_is_pretty_printed_and_newline_terminated() {
        let dir = Scratch::new("pretty");
        let path = dir.join("state.json");

        let _guard = wpa_state().publish(&path);

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"), "no trailing newline: {text:?}");
        assert!(text.contains("\n  \"ssid\""), "not indented: {text:?}");
    }
}
