//! The embedded portal UI, and server-side rendering of it.
//!
//! `ui/dist` is built by bun and **committed**, then embedded here. That
//! ordering is deliberate: a `build.rs` that shelled out to bun would break
//! `cargo install`, break the `cross` containers, break snapcraft's build
//! environment, and force everyone who wants to compile a networking daemon
//! to install a JavaScript toolchain first. CI rebuilds the UI and fails if
//! the committed output has drifted.
//!
//! Rendering is literal token substitution, not a template engine. There are
//! four tokens and the page is a fixed shape; a dependency that could render
//! arbitrary templates would be more machinery than the problem has.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::nm::WifiNetwork;
use crate::nm::security::Security;
use crate::state::PortalState;

#[derive(rust_embed::Embed)]
#[folder = "ui/dist/"]
struct Assets;

/// Escape text for interpolation into HTML.
///
/// Every value substituted into the page is attacker-influenced: an SSID is
/// 32 arbitrary bytes chosen by whoever is broadcasting nearby, so a
/// neighbouring network called `<script>…` must not become script in our
/// portal.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn template(name: &str) -> String {
    Assets::get(name)
        .map(|f| String::from_utf8_lossy(f.data.as_ref()).into_owned())
        .unwrap_or_else(|| {
            // Only reachable if ui/dist was not built. Fail visibly rather
            // than serving a blank page that looks like a network fault.
            format!(
                "<!doctype html><html lang=\"en\"><body><h1>Portal assets missing</h1>\
                 <p>{name} was not embedded. Run <code>bun run build</code> in ui/.</p>\
                 </body></html>"
            )
        })
}

/// How many of the four signal bars are lit, from a 0-100 strength.
fn bars_for(strength: u8) -> u8 {
    match strength {
        0..=24 => 1,
        25..=49 => 2,
        50..=74 => 3,
        _ => 4,
    }
}

fn security_label(security: Security) -> &'static str {
    match security {
        Security::Open => "Open",
        Security::Owe => "Open (encrypted)",
        Security::Wep => "WEP (insecure)",
        Security::WpaPsk => "WPA2",
        Security::Sae => "WPA3",
        Security::SaeTransitional => "WPA2/WPA3",
        Security::Enterprise => "Enterprise",
    }
}

fn render_networks(networks: &[WifiNetwork]) -> String {
    if networks.is_empty() {
        return String::from(
            "<p class=\"field hint\">No networks were found. Enter a network name below.</p>",
        );
    }

    let mut out = String::new();
    for (i, n) in networks.iter().enumerate() {
        let lit = bars_for(n.strength);
        let mut bars = String::new();
        for b in 1..=4u8 {
            bars.push_str(if b <= lit {
                "<span class=\"on\"></span>"
            } else {
                "<span></span>"
            });
        }

        let name = escape(&n.ssid);
        let label = security_label(n.security);
        // The first network is pre-selected so that the form is submittable
        // without JavaScript and the common case is one tap.
        let checked = if i == 0 { " checked" } else { "" };

        // The booleans, not just the slug: what a given security type needs
        // is decided once, in nm::security, and the script reads the answer
        // rather than re-deriving it from a string. Two copies of that rule
        // is how OWE ends up prompting for a password that does not exist.
        let needs_pw = n.security.needs_passphrase();
        let needs_id = n.security.needs_identity();

        out.push_str(&format!(
            "<label class=\"net\">\
               <input type=\"radio\" name=\"ssid_hex\" value=\"{hex}\" \
                data-needs-passphrase=\"{needs_pw}\" data-needs-identity=\"{needs_id}\" required{checked}>\
               <span class=\"net__name\">{name}</span>\
               <span class=\"net__meta\">\
                 <span>{label}</span>\
                 <span class=\"bars\" role=\"img\" aria-label=\"Signal {lit} of 4\">{bars}</span>\
               </span>\
             </label>",
            hex = n.ssid_hex,
        ));
    }
    out
}

fn render_banner(state: &PortalState) -> String {
    match state {
        PortalState::Failed { error, .. } => format!(
            "<div class=\"banner\" role=\"alert\">{}</div>",
            escape(error)
        ),
        _ => String::new(),
    }
}

/// Render the portal page.
pub fn render_index(brand: &str, networks: &[WifiNetwork], state: &PortalState) -> String {
    template("index.html")
        .replace("{{BRAND_NAME}}", &escape(brand))
        .replace("{{NETWORKS}}", &render_networks(networks))
        .replace("{{BANNER}}", &render_banner(state))
}

/// Render the portal page carrying a validation error.
pub fn render_index_with_error(brand: &str, networks: &[WifiNetwork], error: &str) -> String {
    template("index.html")
        .replace("{{BRAND_NAME}}", &escape(brand))
        .replace("{{NETWORKS}}", &render_networks(networks))
        .replace(
            "{{BANNER}}",
            &format!(
                "<div class=\"banner\" role=\"alert\">{}</div>",
                escape(error)
            ),
        )
}

/// Render the "connecting…" page.
pub fn render_connecting(brand: &str, ssid: &str) -> String {
    template("connecting.html")
        .replace("{{BRAND_NAME}}", &escape(brand))
        .replace("{{SSID}}", &escape(ssid))
}

/// Serve a file from `ui/dist` under `/assets/`.
pub async fn serve(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| {
                            HeaderValue::from_static("application/octet-stream")
                        }),
                    ),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                file.data.into_owned(),
            )
                .into_response()
        }
        // A 404 here, never the portal redirect: a redirected script or
        // stylesheet would be served HTML and fail in a confusing way.
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::JoinFailure;
    use crate::ssid::Ssid;

    fn net(ssid: &str, strength: u8, security: Security) -> WifiNetwork {
        WifiNetwork::new(Ssid::from(ssid), strength, security, Some(2437))
    }

    #[test]
    fn the_built_ui_is_actually_embedded() {
        // Catches "someone deleted ui/dist" far more usefully than a blank
        // page on a device would.
        assert!(
            Assets::get("index.html").is_some(),
            "ui/dist/index.html is missing"
        );
        assert!(Assets::get("connecting.html").is_some());
    }

    #[test]
    fn every_build_token_is_substituted() {
        let html = render_index(
            "Anthias",
            &[net("Home", 80, Security::WpaPsk)],
            &PortalState::Portal,
        );
        for token in [
            "{{BRAND_NAME}}",
            "{{NETWORKS}}",
            "{{BANNER}}",
            "{{STYLE}}",
            "{{SCRIPT}}",
        ] {
            assert!(!html.contains(token), "{token} survived rendering");
        }
        assert!(html.contains("Anthias"));
    }

    /// An SSID is 32 arbitrary bytes chosen by whoever is broadcasting
    /// nearby. A neighbouring network can therefore choose our markup.
    #[test]
    fn a_hostile_ssid_cannot_inject_markup() {
        let evil = "<script>alert('pwned')</script>";
        let html = render_index(
            "Brand",
            &[net(evil, 50, Security::WpaPsk)],
            &PortalState::Portal,
        );

        assert!(!html.contains("<script>alert"), "SSID was not escaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn a_hostile_ssid_cannot_escape_an_attribute() {
        let evil = r#"x" onfocus="alert(1)"#;
        let html = render_index(
            "Brand",
            &[net(evil, 50, Security::WpaPsk)],
            &PortalState::Portal,
        );
        assert!(
            !html.contains(r#"onfocus="alert"#),
            "attribute escape: {html:.0}"
        );
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn the_brand_name_is_escaped_too() {
        let html = render_index("<b>Brand</b>", &[], &PortalState::Portal);
        assert!(!html.contains("<b>Brand</b>"));
        assert!(html.contains("&lt;b&gt;Brand&lt;/b&gt;"));
    }

    #[test]
    fn networks_carry_their_exact_bytes_and_security() {
        let html = render_index(
            "B",
            &[net("Home", 80, Security::Enterprise)],
            &PortalState::Portal,
        );
        assert!(html.contains(r#"value="486f6d65""#), "ssid_hex missing");
        // Enterprise needs an identity and (for PEAP/TTLS) a password; the
        // script reads these booleans, not a security slug.
        assert!(html.contains(r#"data-needs-identity="true""#));
        assert!(html.contains(r#"data-needs-passphrase="false""#));
        assert!(html.contains("Enterprise"));
    }

    #[test]
    fn the_first_network_is_preselected_so_the_form_works_without_js() {
        let html = render_index(
            "B",
            &[net("A", 90, Security::WpaPsk), net("B", 40, Security::Open)],
            &PortalState::Portal,
        );
        // Match the rendered radio markup specifically. A looser search
        // also hits the `:has(input:checked)` CSS rule and the inlined
        // script's `input[name="ssid_hex"]` selector.
        assert_eq!(
            html.matches(r#"<input type="radio" name="ssid_hex""#)
                .count(),
            2,
            "both networks should be listed"
        );
        assert_eq!(
            html.matches("required checked>").count(),
            1,
            "exactly one network should be preselected"
        );
    }

    #[test]
    fn an_empty_scan_still_offers_manual_entry() {
        let html = render_index("B", &[], &PortalState::Portal);
        assert!(html.contains("No networks were found"));
        // The hidden-network field is in the static template.
        assert!(html.contains("hidden-ssid"));
    }

    /// The error has to be visible on the page the phone lands on after
    /// rejoining the re-raised access point.
    #[test]
    fn a_failure_renders_an_alert_banner() {
        let state = PortalState::Failed {
            ssid: "Office".into(),
            error: JoinFailure::BadPassword.message("Office"),
        };
        let html = render_index("B", &[], &state);

        assert!(html.contains(r#"role="alert""#));
        assert!(html.contains("password was not accepted"));
    }

    #[test]
    fn the_portal_state_renders_no_banner() {
        let html = render_index("B", &[], &PortalState::Portal);
        assert!(!html.contains(r#"class="banner""#));
    }

    #[test]
    fn signal_bars_scale_with_strength() {
        assert_eq!(bars_for(0), 1);
        assert_eq!(bars_for(30), 2);
        assert_eq!(bars_for(60), 3);
        assert_eq!(bars_for(100), 4);
    }

    /// Strength must not be conveyed by the bars alone.
    #[test]
    fn signal_strength_is_also_announced_as_text() {
        let html = render_index(
            "B",
            &[net("Home", 80, Security::WpaPsk)],
            &PortalState::Portal,
        );
        assert!(html.contains(r#"aria-label="Signal 4 of 4""#));
    }

    #[test]
    fn the_connecting_page_names_the_network_and_explains_both_outcomes() {
        let html = render_connecting("Anthias", "Office WiFi");
        assert!(html.contains("Office WiFi"));
        // Saying so is what stops a user power-cycling a device that just
        // worked.
        assert!(html.contains("it worked"));
        assert!(html.contains("setup network reappears"));
    }

    #[test]
    fn a_validation_error_keeps_the_network_list() {
        let html = render_index_with_error(
            "B",
            &[net("Home", 80, Security::WpaPsk)],
            "Choose a network, or enter its name.",
        );
        assert!(html.contains("Choose a network"));
        assert!(html.contains("486f6d65"), "the list must survive the error");
    }
}
