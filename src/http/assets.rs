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

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::cli::ThemeMode;
use crate::nm::WifiNetwork;
use crate::nm::security::Security;
use crate::state::{Branding, PortalState, Shared};

#[derive(rust_embed::Embed)]
#[folder = "ui/dist/"]
struct Assets;

/// The most a `--ui-directory` may hold, in total.
///
/// The embedded UI is under 40 KB because the pages inline their own CSS
/// and script. Eight megabytes is two orders of magnitude of headroom for
/// fonts and images, and small enough that pointing the flag at the wrong
/// directory — `/`, a home directory, a node_modules — fails at boot
/// instead of pulling it into the memory of a Pi Zero-class board.
const UI_DIRECTORY_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// The most files a `--ui-directory` may hold. Same reasoning as the
/// byte cap; a real portal is a handful of files.
const UI_DIRECTORY_MAX_FILES: usize = 256;

/// How deep a `--ui-directory` may nest. Also what stops a symlink to an
/// ancestor *inside* the directory from recursing forever.
const UI_DIRECTORY_MAX_DEPTH: usize = 8;

/// The pages the portal renders. A `--ui-directory` must supply both.
const TEMPLATES: [&str; 2] = ["index.html", "connecting.html"];

/// A `--ui-directory`, read into memory at startup.
///
/// It replaces the embedded UI wholesale rather than file by file: when
/// the flag is set, the pages and everything under `/assets/` come from
/// the directory and nothing falls back to the embedded copy. A per-file
/// fallback would mean an operator who misspells `conecting.html` gets the
/// stock page after the join with their own page before it, and nothing
/// in the log to say why.
///
/// Read eagerly, for the same reason as `--brand-css`: a missing directory
/// or template stops the portal at boot with the path in the message.
/// Reading everything up front is also the path-traversal defence. Requests
/// are answered by an exact lookup in a map whose keys were built from the
/// directory listing, so no request path ever reaches the filesystem and
/// `..`, absolute paths and NUL bytes have nothing to resolve against.
pub struct UiDirectory {
    files: std::collections::HashMap<String, Box<[u8]>>,
}

impl UiDirectory {
    /// Read `dir` and check it is a UI this portal can render.
    pub fn load(dir: &std::path::Path) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};

        let root = std::fs::canonicalize(dir)?;
        if !root.is_dir() {
            return Err(Error::new(ErrorKind::InvalidInput, "not a directory"));
        }

        let mut ui = Self {
            files: std::collections::HashMap::new(),
        };
        let mut total = 0u64;
        ui.read_dir(&root, &root, "", 0, &mut total)?;

        for name in TEMPLATES {
            let Some(bytes) = ui.files.get(name) else {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("{name} is missing; the directory must supply both {TEMPLATES:?}"),
                ));
            };
            if std::str::from_utf8(bytes).is_err() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("{name} is not valid UTF-8"),
                ));
            }
        }

        // The tell for upstream's React build, which is what most people
        // carrying `--ui-directory` over from balena will be pointing at.
        // Its index.html renders an empty <div id="root"> and expects an
        // API this portal does not have; served as-is it is a blank page.
        let index = String::from_utf8_lossy(&ui.files["index.html"]);
        if !index.contains("{{NETWORKS}}") {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "index.html has no {{NETWORKS}} token; the directory must hold \
                 templates written for this portal (start from ui/dist), not \
                 balena's React build",
            ));
        }

        Ok(ui)
    }

    /// Recurse into `dir`, keying each file by its path below `root`.
    fn read_dir(
        &mut self,
        root: &std::path::Path,
        dir: &std::path::Path,
        prefix: &str,
        depth: usize,
        total: &mut u64,
    ) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};

        if depth > UI_DIRECTORY_MAX_DEPTH {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "nested more than {UI_DIRECTORY_MAX_DEPTH} levels deep at {}",
                    dir.display()
                ),
            ));
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("{} is not a UTF-8 file name", entry.path().display()),
                ));
            };
            // Dotfiles are an editor's swap file or a .git directory, never
            // part of a page, and the second would publish the operator's
            // history to anyone on the access point.
            if name.starts_with('.') {
                continue;
            }

            // Resolve symlinks, then insist the target is still inside the
            // directory. A link to /etc/shadow inside the UI directory must
            // not make it servable at /assets/shadow.
            let path = std::fs::canonicalize(entry.path())?;
            if !path.starts_with(root) {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("{} links outside the UI directory", entry.path().display()),
                ));
            }

            let key = format!("{prefix}{name}");
            let meta = std::fs::metadata(&path)?;
            if meta.is_dir() {
                self.read_dir(root, &path, &format!("{key}/"), depth + 1, total)?;
            } else if meta.is_file() {
                *total += meta.len();
                if *total > UI_DIRECTORY_MAX_BYTES || self.files.len() >= UI_DIRECTORY_MAX_FILES {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "more than {UI_DIRECTORY_MAX_FILES} files or \
                             {UI_DIRECTORY_MAX_BYTES} bytes; is this the right directory?"
                        ),
                    ));
                }
                self.files.insert(key, std::fs::read(&path)?.into());
            }
            // Sockets, FIFOs and devices are skipped: opening a FIFO would
            // block startup forever, and none of them is a web asset.
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|b| &b[..])
    }
}

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

fn template(branding: &Branding, name: &str) -> String {
    // Checked at load: both templates exist and are UTF-8.
    if let Some(ui) = &branding.ui {
        return String::from_utf8_lossy(ui.get(name).unwrap_or_default()).into_owned();
    }
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

/// The `<link>` for the integrator stylesheet, or nothing.
///
/// Emitted ONLY when `--brand-css` is set. An unbranded portal must stay a
/// single request: it is served to a captive-portal mini-browser over an
/// access point with no internet, and ui/test/portal.test.ts asserts the
/// built pages pull in nothing external. The href is a fixed literal, so
/// nothing attacker-influenced reaches the markup.
fn render_brand_css(branded: bool) -> &'static str {
    if branded {
        "<link rel=\"stylesheet\" href=\"/brand.css\" />"
    } else {
        ""
    }
}

/// The `data-theme` attribute for `<html>`, or nothing.
///
/// `System` emits nothing and lets the boot script and
/// `prefers-color-scheme` decide. Anything else pins the page here, server
/// side, so it is right in the very first paint — a class added later would
/// flash the wrong scheme on a page the user sees for ten seconds.
fn render_theme_attr(theme: ThemeMode) -> &'static str {
    match theme {
        ThemeMode::System => "",
        ThemeMode::Light => " data-theme=\"light\"",
        ThemeMode::Dark => " data-theme=\"dark\"",
    }
}

/// The in-page theme switcher, or nothing.
///
/// Emitted ONLY when the theme is `System`. When an integrator has pinned
/// one, the control would offer to undo a decision that is theirs to make,
/// on a page whose whole job is to get a device onto WiFi and go away.
fn render_theme_toggle(theme: ThemeMode) -> &'static str {
    match theme {
        ThemeMode::System => {
            "<button class=\"link-btn\" type=\"button\" id=\"theme-toggle\" hidden>Switch theme</button>"
        }
        _ => "",
    }
}

/// The page heading: the logo if there is one, else the product name.
///
/// The logo replaces the name rather than sitting above it — a wordmark
/// under a wordmark is what the Anthias splash screen deliberately does
/// not do — and carries the name as alt text, so the heading still reads
/// correctly to a screen reader and to anyone whose image did not load.
fn render_brand_heading(branding: &Branding) -> String {
    match branding.logo {
        None => escape(&branding.name),
        Some(_) => format!(
            r#"<img class="brand-logo" src="/brand-logo" alt="{}" />"#,
            escape(&branding.name)
        ),
    }
}

/// Render the portal page.
pub fn render_index(branding: &Branding, networks: &[WifiNetwork], state: &PortalState) -> String {
    chrome(template(branding, "index.html"), branding)
        .replace("{{NETWORKS}}", &render_networks(networks))
        .replace("{{BANNER}}", &render_banner(state))
}

/// Substitute everything that is the same on every page.
fn chrome(html: String, branding: &Branding) -> String {
    html.replace("{{BRAND_HEADING}}", &render_brand_heading(branding))
        .replace("{{BRAND_NAME}}", &escape(&branding.name))
        .replace("{{BRAND_CSS}}", render_brand_css(branding.css.is_some()))
        .replace("{{THEME_ATTR}}", render_theme_attr(branding.theme))
        .replace("{{THEME_TOGGLE}}", render_theme_toggle(branding.theme))
}

/// Render the portal page carrying a validation error.
pub fn render_index_with_error(
    branding: &Branding,
    networks: &[WifiNetwork],
    error: &str,
) -> String {
    chrome(template(branding, "index.html"), branding)
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
pub fn render_connecting(branding: &Branding, ssid: &str) -> String {
    chrome(template(branding, "connecting.html"), branding).replace("{{SSID}}", &escape(ssid))
}

/// Serve a file under `/assets/`: from `--ui-directory` when it is set,
/// otherwise from the embedded `ui/dist`.
///
/// Never the filesystem at request time: both sources are exact-match
/// lookups, so a path like `../../etc/passwd` is just a key that is not
/// there.
pub async fn serve(State(shared): State<Shared>, Path(path): Path<String>) -> Response {
    let data = match &shared.branding.ui {
        Some(ui) => ui.get(&path).map(<[u8]>::to_vec),
        None => Assets::get(&path).map(|f| f.data.into_owned()),
    };
    match data {
        Some(data) => {
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
                data,
            )
                .into_response()
        }
        // A 404 here, never the portal redirect: a redirected script or
        // stylesheet would be served HTML and fail in a confusing way.
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// A throwaway `--ui-directory` for tests, removed on drop.
///
/// Hand-rolled rather than a tempfile dev-dependency: it is a dozen lines
/// and only this module and the router tests need it.
#[cfg(test)]
pub(crate) struct TestUiDir(pub std::path::PathBuf);

#[cfg(test)]
impl TestUiDir {
    /// A directory holding minimal, valid templates.
    pub(crate) fn new() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wifi-connect-ui-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ui = Self(dir);
        ui.write(
            "index.html",
            "<title>{{BRAND_NAME}}</title>OVERRIDE-INDEX{{BRAND_CSS}}{{BANNER}}{{NETWORKS}}",
        );
        ui.write("connecting.html", "OVERRIDE-CONNECTING {{SSID}}");
        ui
    }

    pub(crate) fn write(&self, name: &str, contents: &str) {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    pub(crate) fn load(&self) -> std::io::Result<UiDirectory> {
        UiDirectory::load(&self.0)
    }
}

#[cfg(test)]
impl Drop for TestUiDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    /// An unbranded portal: stock theme, no stylesheet.
    fn plain(name: &str) -> Branding {
        Branding::new(name)
    }

    /// As an integrator gets it: a stylesheet is configured.
    fn branded(name: &str) -> Branding {
        Branding {
            css: Some(std::sync::Arc::from(":root{--color-accent:#ffe11a}")),
            ..Branding::new(name)
        }
    }

    /// With a logo configured.
    fn with_logo(name: &str) -> Branding {
        Branding {
            logo: Some(crate::state::BrandLogo {
                bytes: std::sync::Arc::from(&b"<svg/>"[..]),
                content_type: "image/svg+xml",
            }),
            ..Branding::new(name)
        }
    }

    /// With the theme pinned, which is what takes the toggle away.
    fn pinned(name: &str, theme: ThemeMode) -> Branding {
        Branding {
            theme,
            ..Branding::new(name)
        }
    }
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
            &plain("Anthias"),
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
            &plain("Brand"),
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
            &plain("Brand"),
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
        let html = render_index(&plain("<b>Brand</b>"), &[], &PortalState::Portal);
        assert!(!html.contains("<b>Brand</b>"));
        assert!(html.contains("&lt;b&gt;Brand&lt;/b&gt;"));
    }

    #[test]
    fn networks_carry_their_exact_bytes_and_security() {
        let html = render_index(
            &plain("B"),
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
            &plain("B"),
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
        let html = render_index(&plain("B"), &[], &PortalState::Portal);
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
        let html = render_index(&plain("B"), &[], &state);

        assert!(html.contains(r#"role="alert""#));
        assert!(html.contains("password was not accepted"));
    }

    #[test]
    fn the_portal_state_renders_no_banner() {
        let html = render_index(&plain("B"), &[], &PortalState::Portal);
        assert!(!html.contains(r#"class="banner""#));
    }

    /// The single-request property, enforced at render time.
    ///
    /// ui/test/portal.test.ts asserts the BUILT pages pull in nothing
    /// external; this is the other half, because the link is substituted
    /// in afterwards. An unbranded portal must come out byte-identical to
    /// what that test checked.
    #[test]
    fn an_unbranded_portal_links_no_stylesheet() {
        for html in [
            render_index(&plain("B"), &[], &PortalState::Portal),
            render_connecting(&plain("B"), "Home"),
        ] {
            assert!(!html.contains("<link"), "unbranded page links something");
            assert!(
                !html.contains("{{BRAND_CSS}}"),
                "token leaked into the page"
            );
        }
    }

    #[test]
    fn a_branded_portal_links_the_stylesheet_once() {
        for html in [
            render_index(&branded("B"), &[], &PortalState::Portal),
            render_connecting(&branded("B"), "Home"),
        ] {
            assert_eq!(html.matches(r#"href="/brand.css""#).count(), 1);
            assert!(!html.contains("{{BRAND_CSS}}"));
        }
    }

    /// The error page is a separate render path and was the one most
    /// likely to be forgotten.
    #[test]
    fn the_error_page_is_branded_too() {
        let html = render_index_with_error(&branded("B"), &[], "nope");
        assert!(html.contains(r#"href="/brand.css""#));
        assert!(!html.contains("{{BRAND_CSS}}"));
    }

    /// Loaded last or it cannot override anything: the role tokens are
    /// defined in the inline <style> above it.
    #[test]
    fn the_brand_stylesheet_comes_after_the_inline_styles() {
        let html = render_index(&branded("B"), &[], &PortalState::Portal);
        let style = html.find("<style").expect("no inline style");
        let link = html.find(r#"href="/brand.css""#).expect("no brand link");
        assert!(link > style);
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
            &plain("B"),
            &[net("Home", 80, Security::WpaPsk)],
            &PortalState::Portal,
        );
        assert!(html.contains(r#"aria-label="Signal 4 of 4""#));
    }

    #[test]
    fn the_connecting_page_names_the_network_and_explains_both_outcomes() {
        let html = render_connecting(&plain("Anthias"), "Office WiFi");
        assert!(html.contains("Office WiFi"));
        // Saying so is what stops a user power-cycling a device that just
        // worked.
        assert!(html.contains("it worked"));
        assert!(html.contains("setup network reappears"));
    }

    #[test]
    fn a_validation_error_keeps_the_network_list() {
        let html = render_index_with_error(
            &plain("B"),
            &[net("Home", 80, Security::WpaPsk)],
            "Choose a network, or enter its name.",
        );
        assert!(html.contains("Choose a network"));
        assert!(html.contains("486f6d65"), "the list must survive the error");
    }

    #[test]
    fn the_theme_toggle_is_only_offered_when_the_theme_is_not_pinned() {
        // Which of two colour schemes a setup page uses is the
        // integrator's call. Offering to undo it on a page that exists for
        // one minute is noise, so a pinned theme removes the control
        // rather than pre-setting it.
        // The button's markup, not the string: portal.ts looks the element
        // up by id, so "theme-toggle" appears in the inlined script either
        // way and asserting on it would pass for both arms.
        let system = render_index(&plain("B"), &[], &PortalState::Portal);
        assert!(
            system.contains(r#"<button class="link-btn" type="button" id="theme-toggle" hidden>"#)
        );

        for theme in [ThemeMode::Light, ThemeMode::Dark] {
            let html = render_index(&pinned("B", theme), &[], &PortalState::Portal);
            assert!(
                !html.contains(r#"id="theme-toggle""#),
                "a pinned theme must not ship the switcher: {theme:?}"
            );
        }
    }

    #[test]
    fn a_pinned_theme_reaches_the_first_paint() {
        // On <html>, server side. A class added by script after load would
        // flash the other scheme first on a page the user sees for seconds.
        let dark = render_index(&pinned("B", ThemeMode::Dark), &[], &PortalState::Portal);
        assert!(dark.contains(r#"<html lang="en" class="no-js" data-theme="dark">"#));

        let light = render_index(&pinned("B", ThemeMode::Light), &[], &PortalState::Portal);
        assert!(light.contains(r#"data-theme="light""#));

        // Again the tag itself: the stylesheet's dark arms and the boot
        // script both name data-theme on every page.
        let system = render_index(&plain("B"), &[], &PortalState::Portal);
        assert!(
            system.contains(r#"<html lang="en" class="no-js">"#),
            "system must leave the attribute off and let the media query decide"
        );
    }

    #[test]
    fn every_render_substitutes_every_token() {
        // One missing arm and a user reads {{THEME_ATTR}} off the page.
        let pages = [
            render_index(&branded("B"), &[], &PortalState::Portal),
            render_index_with_error(&branded("B"), &[], "nope"),
            render_connecting(&pinned("B", ThemeMode::Dark), "Home"),
        ];
        for page in pages {
            assert!(!page.contains("{{"), "unsubstituted token: {page:.0}");
        }
    }

    #[test]
    fn the_heading_is_the_name_until_a_logo_replaces_it() {
        let plain_html = render_index(&plain("Anthias"), &[], &PortalState::Portal);
        assert!(plain_html.contains("<h1>Anthias</h1>"));
        // The <img>, not the class: the .brand-logo rule is in the inlined
        // stylesheet on every page whether or not a logo is configured.
        assert!(!plain_html.contains("<img"));

        let logo_html = render_index(&with_logo("Anthias"), &[], &PortalState::Portal);
        assert!(
            logo_html.contains(r#"<img class="brand-logo" src="/brand-logo" alt="Anthias" />"#)
        );
        assert!(
            !logo_html.contains("<h1>Anthias</h1>"),
            "the logo replaces the wordmark rather than stacking under it"
        );
    }

    #[test]
    fn a_hostile_brand_name_cannot_escape_the_alt_attribute() {
        // --brand-name is operator-supplied, but it lands in an attribute
        // now as well as in text, and the two escape differently.
        let html = render_index(
            &with_logo(r#"x" onerror="alert(1)"#),
            &[],
            &PortalState::Portal,
        );
        assert!(
            !html.contains(r#"onerror="alert"#),
            "attribute escape: {html:.0}"
        );
        assert!(html.contains("&quot;"));
    }

    fn with_ui(name: &str, ui: UiDirectory) -> Branding {
        Branding {
            ui: Some(std::sync::Arc::new(ui)),
            ..Branding::new(name)
        }
    }

    #[test]
    fn a_ui_directory_replaces_both_pages() {
        let dir = TestUiDir::new();
        let branding = with_ui("Anthias", dir.load().unwrap());

        let index = render_index(
            &branding,
            &[net("<b>Home</b>", 80, Security::WpaPsk)],
            &PortalState::Portal,
        );
        assert!(index.contains("OVERRIDE-INDEX"), "embedded page served");
        assert!(index.contains("<title>Anthias</title>"));
        // The override gets the same rendering, escaping included: an
        // integrator's template is no reason to trust a neighbour's SSID.
        assert!(index.contains("&lt;b&gt;Home&lt;/b&gt;"));
        assert!(!index.contains("{{"), "unsubstituted token: {index:.0}");

        let connecting = render_connecting(&branding, "Office");
        assert_eq!(connecting, "OVERRIDE-CONNECTING Office");
    }

    #[test]
    fn a_missing_ui_directory_fails_to_load() {
        let dir = TestUiDir::new();
        let gone = dir.0.join("not-here");
        let err = UiDirectory::load(&gone)
            .err()
            .expect("loaded a missing dir");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn a_file_is_not_a_ui_directory() {
        let dir = TestUiDir::new();
        assert!(UiDirectory::load(&dir.0.join("index.html")).is_err());
    }

    /// All-or-nothing: no per-file fallback to the embedded page, which
    /// would serve a mixed portal with nothing in the log to say why.
    #[test]
    fn a_ui_directory_missing_a_template_fails_to_load() {
        let dir = TestUiDir::new();
        std::fs::remove_file(dir.0.join("connecting.html")).unwrap();
        let err = dir.load().err().expect("loaded without connecting.html");
        assert!(err.to_string().contains("connecting.html"), "{err}");
    }

    /// What someone migrating from balena will point the flag at.
    #[test]
    fn a_ui_directory_without_the_portal_tokens_is_refused() {
        let dir = TestUiDir::new();
        dir.write(
            "index.html",
            r#"<!doctype html><div id="root"></div><script src="/static/js/main.js"></script>"#,
        );
        let err = dir.load().err().expect("loaded balena's React build");
        assert!(err.to_string().contains("{{NETWORKS}}"), "{err}");
    }

    #[test]
    fn a_ui_directory_serves_nested_files_by_relative_path() {
        let dir = TestUiDir::new();
        dir.write("fonts/brand.woff2", "font");
        let ui = dir.load().unwrap();
        assert_eq!(ui.get("fonts/brand.woff2"), Some(&b"font"[..]));
    }

    #[test]
    fn dotfiles_in_a_ui_directory_are_never_served() {
        let dir = TestUiDir::new();
        dir.write(".git/config", "[remote]");
        dir.write(".index.html.swp", "swap");
        let ui = dir.load().unwrap();
        assert!(ui.get(".git/config").is_none());
        assert!(ui.get(".index.html.swp").is_none());
    }

    /// A symlink is how a file outside the directory would become
    /// servable at /assets/. It is refused at boot, not skipped, because
    /// an operator who made one meant something by it.
    #[test]
    fn a_symlink_out_of_the_ui_directory_is_refused() {
        let dir = TestUiDir::new();
        let outside = TestUiDir::new();
        outside.write("secret", "s3cret");
        std::os::unix::fs::symlink(outside.0.join("secret"), dir.0.join("secret")).unwrap();

        let err = dir.load().err().expect("followed a symlink out");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_symlink_within_the_ui_directory_is_followed() {
        let dir = TestUiDir::new();
        dir.write("real.css", "body{}");
        std::os::unix::fs::symlink(dir.0.join("real.css"), dir.0.join("alias.css")).unwrap();
        assert_eq!(dir.load().unwrap().get("alias.css"), Some(&b"body{}"[..]));
    }

    /// A link to an ancestor would otherwise recurse until the stack ran
    /// out; the depth cap turns it into a startup error.
    #[test]
    fn a_symlink_loop_in_the_ui_directory_fails_rather_than_recursing() {
        let dir = TestUiDir::new();
        std::fs::create_dir(dir.0.join("sub")).unwrap();
        std::os::unix::fs::symlink(&dir.0, dir.0.join("sub").join("loop")).unwrap();
        assert!(dir.load().is_err());
    }

    /// Pointing the flag at `/` or a node_modules must fail at boot, not
    /// read it into memory.
    #[test]
    fn an_oversized_ui_directory_is_refused() {
        let dir = TestUiDir::new();
        for i in 0..=UI_DIRECTORY_MAX_FILES {
            dir.write(&format!("f{i}.txt"), "x");
        }
        let err = dir.load().err().expect("loaded too many files");
        assert!(err.to_string().contains("right directory"), "{err}");
    }
}
