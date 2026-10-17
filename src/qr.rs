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
//!   serial console displays directly with no host app at all.
//! * The SSID and passphrase as plain text in the log, for operators and for
//!   anyone whose scanner refuses.

use qrcode::{Color, EcLevel, QrCode, render::svg};

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

#[cfg(test)]
mod tests {
    use super::*;

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

        assert!(p.contains(r#"S:My\;Net\,work\:\"x\"\\y;"#), "ssid not escaped: {p}");
        assert!(p.contains(r#"P:pa\;ss\,wo\:rd\"q\"\\z;"#), "pass not escaped: {p}");
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
        assert!(svg.contains("<svg"), "not svg: {}", &svg[..40.min(svg.len())]);
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
}
