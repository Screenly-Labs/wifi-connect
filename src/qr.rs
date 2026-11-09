//! The join QR code.
//!
//! This is the primary way the setup AP's passphrase reaches the user: they
//! point a camera at the screen and the phone joins. It therefore has to be
//! rendered *locally by the device* — it is what gets you onto the network in
//! the first place, so it cannot be served over that network.
//!
//! Three outputs, one render:
//!
//! * SVG and PNG-ish files on disk (`--qr-output`), for the host app to show
//!   full-screen. This is the path the Anthias integration will consume.
//! * A Unicode half-block rendering on stdout, which a plain HDMI TTY or a
//!   serial console displays directly with no host app at all. Only when
//!   stdout is a terminal or the disk files are missing (or `--qr-stdout`):
//!   otherwise stdout is a log, and a QR there is the passphrase.
//! * Only with `--log-passphrase`: the SSID and passphrase as plain text in
//!   the log, for anyone whose scanner refuses. Off by default, because logs
//!   are shipped and kept far beyond the device's screen.

use std::path::{Path, PathBuf};

use qrcode::{Color, EcLevel, QrCode, render::svg};
use tracing::{info, warn};

use crate::secret::Secret;
use crate::ssid::Ssid;

/// Characters that are structural in a `WIFI:` payload and must be
/// backslash-escaped inside a field. Per the format's grammar these are
/// `\`, `;`, `,`, `:` and `"`.
fn escape_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Build the standard WiFi-join payload a camera app understands.
///
/// The authentication token is `WPA` even when the AP negotiated WPA3-SAE.
/// `T:SAE` is newer and poorly supported by scanners, whereas `T:WPA` is
/// honoured for WPA2 and WPA3-personal alike — and the phone works out the
/// actual suite from the beacon regardless.
pub fn wifi_payload(ssid: &Ssid, passphrase: &Secret, hidden: bool) -> String {
    format!(
        "WIFI:T:WPA;S:{};P:{};H:{};;",
        escape_field(&ssid.to_display_string()),
        escape_field(passphrase.expose()),
        hidden
    )
}

/// A rendered QR code, ready to be written out in any of the three forms.
pub struct JoinQr {
    code: QrCode,
}

impl JoinQr {
    pub fn encode(payload: &str) -> Result<Self, qrcode::types::QrError> {
        // `M` (15%) is plenty for a short payload read off a screen at close
        // range, and keeps the symbol low-density so a cheap camera can
        // resolve it from across a room.
        let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)?;
        Ok(Self { code })
    }

    pub fn to_svg(&self, size: u32) -> String {
        self.code
            .render::<svg::Color<'_>>()
            .min_dimensions(size, size)
            .quiet_zone(true)
            .build()
    }

    /// Render with Unicode half-blocks, two QR rows per terminal line.
    ///
    /// Terminal cells are roughly twice as tall as they are wide, so one
    /// module per cell produces a stretched symbol that many scanners refuse.
    /// Packing two rows into one cell via U+2580/U+2584 gives square modules.
    ///
    /// Colours are deliberate: QR scanners expect dark-on-light, so the
    /// "light" module is rendered as a filled block in the terminal's
    /// foreground colour only if the caller inverts. We emit the
    /// conventional orientation and surround it with a quiet zone, which is
    /// what makes it scannable on a white-on-black console.
    pub fn to_unicode(&self) -> String {
        const QUIET: usize = 2;
        let width = self.code.width();
        let colors = self.code.to_colors();
        let padded = width + QUIET * 2;

        let dark_at = |x: isize, y: isize| -> bool {
            if x < 0 || y < 0 || x >= width as isize || y >= width as isize {
                return false; // quiet zone is light
            }
            colors[y as usize * width + x as usize] == Color::Dark
        };

        let mut out = String::new();
        let mut row = 0usize;
        while row < padded {
            for col in 0..padded {
                let x = col as isize - QUIET as isize;
                let top = dark_at(x, row as isize - QUIET as isize);
                let bottom = dark_at(x, (row + 1) as isize - QUIET as isize);
                // Light modules must be the *bright* cell, so a dark module
                // maps to an absent half-block against a lit background.
                out.push(match (top, bottom) {
                    (false, false) => '\u{2588}', // both light: full block
                    (false, true) => '\u{2580}',  // upper light: upper half
                    (true, false) => '\u{2584}',  // lower light: lower half
                    (true, true) => ' ',          // both dark: empty
                });
            }
            out.push('\n');
            row += 2;
        }
        out
    }
}

/// Removes the QR files a run wrote, when that run ends.
///
/// `wifi-connect-qr.txt` holds the setup passphrase in clear, and
/// `wifi-connect-qr.svg` encodes the same payload. Both are written for
/// one access point, with one passphrase, generated per run — so once
/// the run is over they are a credential for a network that no longer
/// exists, and nothing else is tracking them.
///
/// `portal_state::StateFile` already does this for `state.json`, which
/// is written beside these and carries the same passphrase. Without the
/// guard below the two halves of one session's output have different
/// lifetimes: the state file goes, the credential stays.
///
/// A guard rather than a call at the end of `run()` for the same reason
/// as the state file: the run has several exits, including the one taken
/// before the portal is ever raised — the QR files are written *before*
/// preflight decides a device is already online, so that path publishes
/// a passphrase for an access point that never goes up.
///
/// Only the paths actually written are recorded, so a failed write or a
/// file left by someone else is never removed.
#[derive(Debug, Default)]
pub struct QrFiles {
    paths: Vec<PathBuf>,
}

impl QrFiles {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a file this run wrote, to be removed when the run ends.
    pub fn published(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    /// Whether anything reached disk. This is what decides the stdout
    /// fallback: a run that could not publish the QR to a file has to
    /// print it, or the passphrase reaches nobody.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

impl Drop for QrFiles {
    fn drop(&mut self) {
        for path in &self.paths {
            remove_published(path);
        }
    }
}

fn remove_published(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => info!(path = %path.display(), "removed the join QR file"),
        // Already gone is the normal outcome of an operator clearing the
        // directory, and nothing to report.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            error = %e,
            path = %path.display(),
            "could not remove the join QR file; the setup passphrase for a \
             closed session stays readable on disk"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A scratch directory unique to one test, removed on drop. Matches
    /// private_file's and portal_state's, rather than pulling in a crate.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("wifi-connect-qr-{}-{test}", std::process::id()));
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

    #[test]
    fn payload_has_the_expected_shape() {
        let p = wifi_payload(&Ssid::from("Setup"), &Secret::new("abcdefgh"), false);
        assert_eq!(p, "WIFI:T:WPA;S:Setup;P:abcdefgh;H:false;;");
    }

    /// Operator-supplied SSIDs and passphrases can contain anything, so every
    /// structural character must be escaped or the payload silently truncates
    /// at the first stray `;`.
    #[test]
    fn structural_characters_are_escaped_in_both_fields() {
        let ssid = Ssid::from(r#"My;Net,work:"x"\y"#);
        let pass = Secret::new(r#"pa;ss,wo:rd"q"\z"#);
        let p = wifi_payload(&ssid, &pass, false);

        assert!(
            p.contains(r#"S:My\;Net\,work\:\"x\"\\y;"#),
            "ssid not escaped: {p}"
        );
        assert!(
            p.contains(r#"P:pa\;ss\,wo\:rd\"q\"\\z;"#),
            "pass not escaped: {p}"
        );
    }

    #[test]
    fn escaping_is_a_no_op_for_generated_passphrases() {
        let pass = crate::passphrase::generate();
        assert_eq!(escape_field(pass.expose()), pass.expose());
    }

    #[test]
    fn hidden_flag_is_reflected() {
        let p = wifi_payload(&Ssid::from("S"), &Secret::new("12345678"), true);
        assert!(p.ends_with("H:true;;"));
    }

    #[test]
    fn encodes_and_renders() {
        let payload = wifi_payload(&Ssid::from("Setup"), &Secret::new("abcdefgh"), false);
        let qr = JoinQr::encode(&payload).unwrap();

        let svg = qr.to_svg(256);
        assert!(
            svg.contains("<svg"),
            "not svg: {}",
            &svg[..40.min(svg.len())]
        );
        assert!(svg.contains("</svg>"));

        let uni = qr.to_unicode();
        let lines: Vec<&str> = uni.lines().collect();
        assert!(lines.len() > 10);
        // Every line is the same display width.
        let w = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == w));
    }

    /// A long operator passphrase must still fit in a QR symbol.
    #[test]
    fn encodes_a_maximum_length_passphrase() {
        let pass = Secret::new("x".repeat(63));
        let payload = wifi_payload(&Ssid::from("A rather long network name"), &pass, false);
        assert!(JoinQr::encode(&payload).is_ok());
    }

    /// The point of the guard. `wifi-connect-qr.txt` is the setup
    /// passphrase in clear, and a run that has ended is a passphrase for
    /// an access point that no longer exists.
    #[test]
    fn the_published_files_go_away_when_the_run_ends() {
        let dir = Scratch::new("drop");
        let svg = dir.join("wifi-connect-qr.svg");
        let txt = dir.join("wifi-connect-qr.txt");
        fs::write(&svg, b"<svg/>").unwrap();
        fs::write(&txt, b"WIFI:T:WPA;S:Setup;P:brave-plum-42;H:false;;").unwrap();

        let mut files = QrFiles::new();
        files.published(svg.clone());
        files.published(txt.clone());
        assert!(!files.is_empty());

        drop(files);

        assert!(!svg.exists(), "the QR image outlived the portal run");
        assert!(
            !txt.exists(),
            "the setup passphrase outlived the portal run"
        );
    }

    /// Only what this run wrote. A failed write records nothing, and a
    /// file that happens to sit in the same directory is the operator's.
    #[test]
    fn nothing_unpublished_is_removed() {
        let dir = Scratch::new("unpublished");
        let theirs = dir.join("something-else.txt");
        fs::write(&theirs, b"not ours").unwrap();

        let files = QrFiles::new();
        assert!(files.is_empty());
        drop(files);

        assert!(theirs.exists(), "removed a file this run never wrote");
        assert_eq!(fs::read(&theirs).unwrap(), b"not ours");
    }

    /// An operator clearing the directory, or a tmpfs that went with a
    /// reboot. Not an error worth reporting — and must not panic in a
    /// `Drop`.
    #[test]
    fn removing_a_file_that_is_already_gone_is_quiet() {
        let dir = Scratch::new("gone");
        let txt = dir.join("wifi-connect-qr.txt");
        fs::write(&txt, b"payload").unwrap();

        let mut files = QrFiles::new();
        files.published(txt.clone());
        fs::remove_file(&txt).unwrap();

        drop(files);
    }

    /// A directory where the file should be cannot be unlinked, and the
    /// guard runs in a `Drop` on every exit path including the error
    /// ones. It has to survive that rather than abort the process.
    #[test]
    fn a_file_that_cannot_be_removed_is_survivable() {
        let dir = Scratch::new("stubborn");
        let blocker = dir.join("wifi-connect-qr.txt");
        fs::create_dir(&blocker).unwrap();

        let mut files = QrFiles::new();
        files.published(blocker.clone());
        drop(files);

        assert!(blocker.exists());
    }
}
