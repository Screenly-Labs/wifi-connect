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
//! a handful of tokens and the page is a fixed shape; a dependency that could
//! render arbitrary templates would be more machinery than the problem has.

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
    files: std::collections::HashMap<String, axum::body::Bytes>,
    /// The `Content-Security-Policy` for every response while this
    /// directory is the UI: the embedded policy's hashes are of the
    /// embedded pages, and would block every inline block an operator has
    /// edited. Computed once here, from these templates; see
    /// `ui_directory_content_security_policy`.
    content_security_policy: HeaderValue,
}

/// Prefix an I/O error with the file it concerns.
///
/// `std::io::Error` carries no path, so without this a dangling symlink
/// three levels down stops the portal with a bare "No such file or
/// directory" while the log names only the top-level directory, which
/// plainly does exist.
fn at(path: &std::path::Path) -> impl FnOnce(std::io::Error) -> std::io::Error + '_ {
    move |e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

fn too_big() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "more than {UI_DIRECTORY_MAX_FILES} files or \
             {UI_DIRECTORY_MAX_BYTES} bytes; is this the right directory?"
        ),
    )
}

/// Read one file of a `--ui-directory`, at most `budget` bytes of it.
///
/// `expected` is the `lstat` of the canonical path. The open is checked
/// against it by device and inode, so a file swapped for a symlink (or a
/// FIFO) between the directory walk and the read is refused rather than
/// followed. The read itself is bounded, so a file that grows after it was
/// measured cannot carry the total past the cap.
fn read_file(
    path: &std::path::Path,
    expected: &std::fs::Metadata,
    budget: u64,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    if expected.len() > budget {
        return Err(too_big());
    }
    let file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        return Err(std::io::Error::other("changed while it was being read"));
    }
    let mut data = Vec::new();
    file.take(budget + 1).read_to_end(&mut data)?;
    if data.len() as u64 > budget {
        return Err(too_big());
    }
    Ok(data)
}

impl UiDirectory {
    /// Read `dir` and check it is a UI this portal can render.
    pub fn load(dir: &std::path::Path) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};

        let root = std::fs::canonicalize(dir).map_err(at(dir))?;
        if !root.is_dir() {
            return Err(Error::new(ErrorKind::InvalidInput, "not a directory"));
        }

        let mut ui = Self {
            files: std::collections::HashMap::new(),
            content_security_policy: HeaderValue::from_static("default-src 'none'"),
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

        ui.content_security_policy = policy_header(&ui_directory_content_security_policy(
            &InlineHashes::of_pages(ui.templates()),
        ));
        Ok(ui)
    }

    /// The two templates, as text. Both were checked to be UTF-8 at load.
    fn templates(&self) -> impl Iterator<Item = (&'static str, std::borrow::Cow<'_, str>)> {
        TEMPLATES.into_iter().map(|name| {
            (
                name,
                String::from_utf8_lossy(self.get(name).unwrap_or_default()),
            )
        })
    }

    /// The `Content-Security-Policy` to send while this UI is served.
    pub fn content_security_policy(&self) -> HeaderValue {
        self.content_security_policy.clone()
    }

    /// Inline blocks in these templates that the policy will not allow.
    ///
    /// Not an error, for the same reason as `missing_tokens`: the page
    /// still loads. But the browser drops the block and says so only in a
    /// console nobody has open on a captive-portal sheet, so the caller
    /// logs these at startup.
    ///
    /// Two ways in. A `{{TOKEN}}` inside a `<script>` or `<style>` body is
    /// substituted per request, after the hash was taken from the
    /// template, so the rendered bytes no longer match it. And only bare
    /// `<script>` and `<style>` tags are hashed (the rule ui/build.ts uses):
    /// an inline `<script type="module">` or `<style media="…">` is not,
    /// so it is blocked. `<script src=…>` is fine; it is allowed by
    /// `'self'`.
    pub fn unhashed_inline_blocks(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, html) in self.templates() {
            for tag in ["script", "style"] {
                for body in inline_blocks(&html, tag) {
                    for token in tokens(body) {
                        out.push(format!("{name}: {token} inside <{tag}>"));
                    }
                }
                for open in attributed_inline_tags(&html, tag) {
                    out.push(format!("{name}: {open}"));
                }
            }
        }
        out
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

        for entry in std::fs::read_dir(dir).map_err(at(dir))? {
            let entry = entry.map_err(at(dir))?;
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
            let path = std::fs::canonicalize(entry.path()).map_err(at(&entry.path()))?;
            if !path.starts_with(root) {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("{} links outside the UI directory", entry.path().display()),
                ));
            }

            let key = format!("{prefix}{name}");
            // `lstat`, not `stat`: `path` is canonical, so its last component
            // is not a link. If it is one now, it was swapped in after
            // canonicalize looked, and it is skipped with the other oddities
            // below rather than followed.
            let meta = std::fs::symlink_metadata(&path).map_err(at(&path))?;
            if meta.is_dir() {
                self.read_dir(root, &path, &format!("{key}/"), depth + 1, total)?;
            } else if meta.is_file() {
                if self.files.len() >= UI_DIRECTORY_MAX_FILES {
                    return Err(too_big());
                }
                let data = read_file(&path, &meta, UI_DIRECTORY_MAX_BYTES - *total)
                    .map_err(at(&entry.path()))?;
                *total += data.len() as u64;
                self.files.insert(key, data.into());
            }
            // Sockets, FIFOs, devices and links swapped in mid-walk are
            // skipped: opening a FIFO would block startup forever, and none
            // of them is a web asset.
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|b| &b[..])
    }

    /// Tokens the embedded pages use that these templates do not.
    ///
    /// Not an error: a template written against an older release, before
    /// `{{BRAND_CSS}}` or `{{BRAND_HEADING}}` existed, still renders and
    /// still joins. But it silently drops whatever the token carried, so
    /// `--brand-css`, `--brand-logo` or `--default-theme` would appear to
    /// do nothing. The caller logs this at startup so that is visible.
    ///
    /// Compared against the embedded copy rather than a hard-coded list,
    /// so a token added to `ui/` later is covered without touching this.
    pub fn missing_tokens(&self) -> Vec<String> {
        let mut missing = Vec::new();
        for name in TEMPLATES {
            let Some(embedded) = Assets::get(name) else {
                continue;
            };
            let embedded = String::from_utf8_lossy(&embedded.data).into_owned();
            let ours = String::from_utf8_lossy(self.get(name).unwrap_or_default());
            for token in tokens(&embedded) {
                if !ours.contains(token) {
                    missing.push(format!("{name}: {token}"));
                }
            }
        }
        missing
    }
}

/// The distinct `{{UPPER_CASE}}` tokens in a template, in order.
fn tokens(html: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let inner = &after[..end];
        if !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            let token = &rest[start..start + 2 + end + 2];
            if !out.contains(&token) {
                out.push(token);
            }
            rest = &after[end + 2..];
        } else {
            rest = after;
        }
    }
    out
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
        Security::Wep => "WEP (not supported)",
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

    // A network we refuse is listed disabled, so it can be found but not
    // chosen, and is never the pre-selected one.
    let first = networks.iter().position(|n| n.security.is_supported());
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
        // The first joinable network is pre-selected so that the form is submittable
        // without JavaScript and the common case is one tap.
        let checked = if Some(i) == first { " checked" } else { "" };
        let disabled = if n.security.is_supported() {
            ""
        } else {
            " disabled"
        };

        // The booleans, not just the slug: what a given security type needs
        // is decided once, in nm::security, and the script reads the answer
        // rather than re-deriving it from a string. Two copies of that rule
        // is how OWE ends up prompting for a password that does not exist.
        let needs_pw = n.security.needs_passphrase();
        let needs_id = n.security.needs_identity();

        out.push_str(&format!(
            "<label class=\"net\">\
               <input type=\"radio\" name=\"ssid_hex\" value=\"{hex}\" \
                data-needs-passphrase=\"{needs_pw}\" data-needs-identity=\"{needs_id}\" required{checked}{disabled}>\
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

/// Fill a template's `{{NAME}}` tokens in a single left-to-right pass.
///
/// One pass, not a chain of `str::replace`: each `replace` scans the output
/// of the one before it, so a value substituted early was re-read as
/// template by every later pass. A neighbouring network broadcasting the
/// SSID `{{BANNER}}` got the banner spliced into the network list; a brand
/// name containing `{{NETWORKS}}` got the whole network list. Escaping does
/// not help — braces are not HTML-special — so the fix is structural: a
/// value, once emitted, is never looked at again.
///
/// An unknown token is kept literally rather than asserted on. The page
/// inlines its stylesheet and script, which are not ours to parse and may
/// one day contain a `{{` of their own; mangling those, or panicking a
/// request over them, would be worse than leaving them alone. A token the
/// template uses but no render supplies is caught instead by the
/// `every_render_substitutes_every_token` test.
fn render(template: &str, tokens: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let known = after.find("}}").and_then(|close| {
            let name = &after[..close];
            tokens
                .iter()
                .find(|(token, _)| *token == name)
                .map(|(_, value)| (*value, close))
        });
        match known {
            Some((value, close)) => {
                out.push_str(value);
                rest = &after[close + 2..];
            }
            None => {
                // Not a token we know: emit ONE brace and resume at the
                // second, so a stray `{{` cannot swallow a real token after
                // it. Skipping both would miss the token in `{{{SSID}}}`,
                // whose first `{{` is a brace short of `{{SSID}}`.
                out.push('{');
                rest = &rest[open + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Render one embedded page: the tokens every page shares, plus its own.
fn render_page(name: &str, branding: &Branding, page_tokens: &[(&str, &str)]) -> String {
    let heading = render_brand_heading(branding);
    let brand_name = escape(&branding.name);
    let mut tokens = vec![
        ("BRAND_HEADING", heading.as_str()),
        ("BRAND_NAME", brand_name.as_str()),
        ("BRAND_CSS", render_brand_css(branding.css.is_some())),
        ("THEME_ATTR", render_theme_attr(branding.theme)),
        ("THEME_TOGGLE", render_theme_toggle(branding.theme)),
    ];
    tokens.extend_from_slice(page_tokens);
    render(&template(branding, name), &tokens)
}

/// Render the portal page.
pub fn render_index(branding: &Branding, networks: &[WifiNetwork], state: &PortalState) -> String {
    render_page(
        "index.html",
        branding,
        &[
            ("NETWORKS", &render_networks(networks)),
            ("BANNER", &render_banner(state)),
        ],
    )
}

/// Render the portal page carrying a validation error.
pub fn render_index_with_error(
    branding: &Branding,
    networks: &[WifiNetwork],
    error: &str,
) -> String {
    let banner = format!(
        "<div class=\"banner\" role=\"alert\">{}</div>",
        escape(error)
    );
    render_page(
        "index.html",
        branding,
        &[
            ("NETWORKS", &render_networks(networks)),
            ("BANNER", &banner),
        ],
    )
}

/// Render the "connecting…" page.
pub fn render_connecting(branding: &Branding, ssid: &str) -> String {
    render_page("connecting.html", branding, &[("SSID", &escape(ssid))])
}

/// The hashes of the inline `<script>` and `<style>` blocks, as written by
/// ui/build.ts into `ui/dist/csp.json`, or as computed from a
/// `--ui-directory` by `of_pages`.
#[derive(Debug, Default, PartialEq, Eq, serde::Deserialize)]
struct InlineHashes {
    script: Vec<String>,
    style: Vec<String>,
}

impl InlineHashes {
    /// The embedded hashes, from `ui/dist/csp.json`.
    fn embedded() -> Self {
        Assets::get("csp.json")
            .and_then(|f| serde_json::from_slice(f.data.as_ref()).ok())
            .unwrap_or_default()
    }

    /// Hash every inline block of `pages` the way ui/build.ts does, so the
    /// embedded pages come out exactly as `csp.json`: distinct, sorted.
    fn of_pages<S: AsRef<str>>(pages: impl IntoIterator<Item = (&'static str, S)>) -> Self {
        let mut script = std::collections::BTreeSet::new();
        let mut style = std::collections::BTreeSet::new();
        for (_, html) in pages {
            let html = html.as_ref();
            script.extend(inline_blocks(html, "script").into_iter().map(csp_source));
            style.extend(inline_blocks(html, "style").into_iter().map(csp_source));
        }
        Self {
            script: script.into_iter().collect(),
            style: style.into_iter().collect(),
        }
    }
}

/// The bodies of the bare `<tag>…</tag>` blocks in `html`, exactly the
/// bytes a browser hashes.
///
/// The same rule as `inlineHashes` in ui/build.ts, which is the regex
/// `<tag>([\s\S]*?)</tag>`: a literal, attribute-free, lower-case opening
/// tag, up to the first closing tag after it. An opening tag with no
/// closing tag after it ends the scan, as it does the regex. Anything else
/// (`<script src>`, `<script type="module">`) is not an inline block to
/// this rule; see `attributed_inline_tags` for the second kind.
fn inline_blocks<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(&open) {
        let body = &rest[start + open.len()..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// Opening `<tag …>`s with attributes that carry an inline body, which
/// the hash rule above does not cover and the policy therefore blocks.
///
/// A `<script>` with `src=` is not one of them: it has no body to hash and
/// is allowed by `'self'`. Case-sensitive like the rule it complements.
fn attributed_inline_tags<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find('>') else { break };
        let attrs = &after[..end];
        let is_attributed = attrs.starts_with(|c: char| c.is_ascii_whitespace());
        if is_attributed && !(tag == "script" && attrs.contains("src=")) {
            out.push(&rest[start..start + open.len() + end + 1]);
        }
        rest = &after[end..];
    }
    out
}

/// The CSP hash source for one inline block body.
fn csp_source(body: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(body.as_bytes());
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Is `source` a CSP hash source we are willing to put in a header?
///
/// The file is ours and committed, but a header value built from it must
/// not be able to smuggle a `;` and a new directive in, so anything that is
/// not exactly `'sha256-<base64>'` is dropped rather than trusted.
fn is_sha256_source(source: &str) -> bool {
    source
        .strip_prefix("'sha256-")
        .and_then(|s| s.strip_suffix('\''))
        .is_some_and(|b64| {
            !b64.is_empty()
                && b64
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
        })
}

/// Build the policy from the embedded hashes.
///
/// Inline script and style are allowed by hash (the `'unsafe-inline'` next
/// to them is a CSP 1.0 fallback that any hash switches off), so the only
/// script that runs is the script we built. That is the backstop for
/// the token substitution above: if an SSID ever did slip through
/// unescaped, the `<script>` it injected would not match a hash.
///
/// Directive by directive:
///
/// - `style-src 'self'`: the optional `/brand.css` link.
/// - `img-src 'self' data:`: `/brand-logo`, and any `data:` image a brand
///   stylesheet uses (there is no internet to fetch anything else from).
/// - `font-src 'self' data:`: likewise for a brand stylesheet's fonts.
/// - `connect-src 'self'`: the connecting page polls `/api/status`.
/// - `form-action 'self'`: the form posts to `/connect` on whatever host the
///   page was loaded as — the portal IP, or a probe hostname such as
///   captive.apple.com that our DNS answered with it. Both are 'self'.
/// - `frame-ancestors 'none'`: nobody may frame the password form.
/// - `base-uri 'none'`: an injected `<base>` cannot re-point `/connect`.
///
/// If the hashes are missing the policy still goes out, just with no script
/// or style allowed: the only page that can be served in that state is the
/// "assets missing" notice, which needs neither.
///
/// `script_self` adds `'self'` to `script-src`, for a `--ui-directory`
/// whose pages may load their script from `/assets/`. The embedded pages
/// inline all of theirs, so the built-in policy leaves it out.
fn build_content_security_policy(hashes: &InlineHashes, script_self: bool) -> String {
    let sources = |list: &[String]| -> String {
        list.iter()
            .filter(|s| is_sha256_source(s))
            .map(|s| format!(" {s}"))
            .collect()
    };
    // `'unsafe-inline'` rides along with the hashes, never without them.
    // CSP Level 2 and later ignore it whenever a hash is present, so every
    // current browser enforces the hashes alone. A CSP 1.0 engine (iOS 9
    // and older, the Chromium 30-33 WebView of Android 4.4) does not know
    // hash sources: without the fallback it would see a directive with no
    // source it understands, block the stylesheet and both scripts, and
    // show an unstyled portal. With no hashes nothing would neutralise it,
    // so then it is left out.
    let with_fallback = |list: &[String]| -> String {
        match sources(list) {
            s if s.is_empty() => s,
            s => format!(" 'unsafe-inline'{s}"),
        }
    };
    let script = match (script_self, with_fallback(&hashes.script)) {
        (true, s) => format!(" 'self'{s}"),
        (false, s) if s.is_empty() => String::from(" 'none'"),
        (false, s) => s,
    };

    format!(
        "default-src 'none'; \
         script-src{script}; \
         style-src 'self'{style}; \
         img-src 'self' data:; \
         font-src 'self' data:; \
         connect-src 'self'; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         base-uri 'none'",
        style = with_fallback(&hashes.style),
    )
}

/// The `Content-Security-Policy` for an SVG response (`/brand-logo`).
///
/// An SVG is a document, so it gets a policy of its own: no script, no
/// network, no framing, but its own inline styling allowed. Exported logos
/// colour themselves with `style="…"` attributes and `<style>` blocks; the
/// page policy, which allows exactly one stylesheet by hash, would strip
/// those and render the mark unstyled wherever it is applied to the SVG —
/// opened directly, or by an engine that honours an image response's
/// policy.
pub const SVG_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     style-src 'unsafe-inline'; \
     img-src data:; \
     font-src data:; \
     frame-ancestors 'none'; \
     base-uri 'none'";

/// The policy for a `--ui-directory`: the embedded policy, with that
/// directory's own hashes in place of the embedded ones and `'self'` added
/// to `script-src`.
///
/// Only those two change. The rest (`form-action`, `frame-ancestors`,
/// `base-uri`, `default-src 'none'`) is what protects the password form,
/// and an operator's template is no reason to relax it. `'self'` is the
/// one widening: a custom UI may well ship `<script src="/assets/…">`,
/// and everything at `/assets/` is the operator's own directory.
fn ui_directory_content_security_policy(hashes: &InlineHashes) -> String {
    build_content_security_policy(hashes, true)
}

/// A policy string as a header value. The sources were filtered by
/// `is_sha256_source`, so this cannot fail; if it somehow did, a policy
/// that allows nothing is the safe way to be wrong.
fn policy_header(policy: &str) -> HeaderValue {
    HeaderValue::from_str(policy).unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'"))
}

/// The `Content-Security-Policy` header value for every portal response
/// served from the embedded UI. A `--ui-directory` carries its own; see
/// `UiDirectory::content_security_policy`.
///
/// Built once: the hashes are compiled into the binary and cannot change.
pub fn content_security_policy() -> HeaderValue {
    static CSP: std::sync::LazyLock<HeaderValue> = std::sync::LazyLock::new(|| {
        policy_header(&build_content_security_policy(
            &InlineHashes::embedded(),
            false,
        ))
    });
    CSP.clone()
}

/// Serve a file under `/assets/`: from `--ui-directory` when it is set,
/// otherwise from the embedded `ui/dist`.
///
/// Never the filesystem at request time: both sources are exact-match
/// lookups, so a path like `../../etc/passwd` is just a key that is not
/// there.
pub async fn serve(State(shared): State<Shared>, Path(path): Path<String>) -> Response {
    let data = match &shared.branding.ui {
        // A refcount bump, not a copy of up to 8 MB per request.
        Some(ui) => ui.files.get(&path).cloned(),
        None => Assets::get(&path).map(|f| match f.data {
            std::borrow::Cow::Borrowed(b) => axum::body::Bytes::from_static(b),
            std::borrow::Cow::Owned(v) => axum::body::Bytes::from(v),
        }),
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
    fn a_wep_network_is_listed_but_cannot_be_chosen() {
        let html = render_index(
            &plain("B"),
            &[
                net("Old", 90, Security::Wep),
                net("New", 70, Security::WpaPsk),
            ],
            &PortalState::Portal,
        );
        assert!(html.contains("WEP (not supported)"));
        assert_eq!(html.matches(" disabled>").count(), 1);
        let new = html.find(r#"value="4e6577""#).expect("New missing");
        let checked = html.find(" checked").expect("nothing pre-selected");
        assert!(checked > new, "the WEP row must not be pre-selected");
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
        assert!(html.contains("passphrase was not accepted"));
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

    /// The sources listed for one directive of `csp`.
    fn directive<'a>(csp: &'a str, name: &str) -> Vec<&'a str> {
        csp.split(';')
            .map(str::trim)
            .find_map(|d| d.strip_prefix(name).and_then(|r| r.strip_prefix(' ')))
            .unwrap_or_else(|| panic!("no {name} in {csp}"))
            .split(' ')
            .collect()
    }

    /// The guard against a UI rebuild silently breaking the portal.
    ///
    /// The hashes are recomputed here from the pages as the SERVER renders
    /// them — every render path, with every token filled in, including
    /// hostile input — so this also proves the token substitution never
    /// reaches into a script or style body. If either half drifts, the
    /// browser would refuse to run the script and nothing would say why.
    #[test]
    fn every_inline_block_in_every_rendered_page_is_allowed_by_the_csp() {
        let csp = content_security_policy().to_str().unwrap().to_owned();
        let failed = PortalState::Failed {
            ssid: "Office".into(),
            error: "</script><script>alert(1)</script>".into(),
        };
        let hostile = [net(
            "</style><script>alert(1)</script>",
            50,
            Security::WpaPsk,
        )];
        let pages = [
            render_index(&plain("B"), &[], &PortalState::Portal),
            render_index(&branded("</script>"), &hostile, &failed),
            render_index(&with_logo("B"), &hostile, &PortalState::Portal),
            render_index(&pinned("B", ThemeMode::Dark), &[], &PortalState::Portal),
            render_index_with_error(&branded("B"), &hostile, "<script>x</script>"),
            render_connecting(&plain("B"), "</script><script>alert(1)</script>"),
            render_connecting(&pinned("B", ThemeMode::Light), "Home"),
        ];

        for page in &pages {
            let scripts = inline_blocks(page, "script");
            let styles = inline_blocks(page, "style");
            // The boot script and the bundle; the one stylesheet. Fewer
            // means the scan missed something, more means input got in.
            assert_eq!(scripts.len(), 2, "script blocks: {page:.0}");
            assert_eq!(styles.len(), 1, "style blocks");

            for (tag, bodies) in [("script-src", scripts), ("style-src", styles)] {
                let allowed = directive(&csp, tag);
                for body in bodies {
                    let source = csp_source(body);
                    assert!(
                        allowed.contains(&source.as_str()),
                        "{tag} lacks {source}; rebuild ui/dist with `bun run build`"
                    );
                }
            }
        }
    }

    #[test]
    fn the_csp_is_built_from_the_embedded_hashes() {
        let csp = content_security_policy().to_str().unwrap().to_owned();
        let script = directive(&csp, "script-src");
        assert!(
            script
                .iter()
                .all(|s| is_sha256_source(s) || *s == "'unsafe-inline'"),
            "script-src must be hashes (plus the CSP 1.0 fallback): {script:?}"
        );
        // 'unsafe-inline' is inert only because hashes sit beside it.
        for name in ["script-src", "style-src"] {
            let sources = directive(&csp, name);
            assert!(
                sources.iter().any(|s| is_sha256_source(s)),
                "{name} has no hashes, so 'unsafe-inline' would be live: {sources:?}"
            );
        }
        assert!(
            !csp.contains("unsafe-eval") && !csp.contains("unsafe-hashes"),
            "{csp}"
        );
    }

    /// The hash file is ours, but it is still spliced into a header.
    #[test]
    fn only_well_formed_hash_sources_reach_the_policy() {
        assert!(is_sha256_source(
            "'sha256-HAtT/QX7BlG2zmsd0ubYmFutrDorJ4HxeDduJ7h6LwM='"
        ));
        for bad in [
            "'unsafe-inline'",
            "'sha256-'",
            "sha256-abc=",
            "'sha256-abc'; script-src *",
            "'sha256-abc' 'unsafe-eval'",
        ] {
            assert!(!is_sha256_source(bad), "{bad} was accepted");
        }
    }

    /// Every token any render substitutes. Kept by hand so that a new token
    /// is a deliberate addition to the re-scan tests below.
    const TOKENS: [&str; 8] = [
        "BRAND_HEADING",
        "BRAND_NAME",
        "BRAND_CSS",
        "THEME_ATTR",
        "THEME_TOGGLE",
        "NETWORKS",
        "BANNER",
        "SSID",
    ];

    /// A neighbour chooses its SSID, and braces are not HTML-special, so
    /// escaping alone let `{{BANNER}}` through to be read as template by a
    /// later substitution pass. Substituted text must never be re-scanned.
    #[test]
    fn an_ssid_spelling_a_token_renders_literally() {
        let failed = PortalState::Failed {
            ssid: "Office".into(),
            error: "join failed".into(),
        };
        for name in TOKENS {
            let ssid = format!("{{{{{name}}}}}");
            let networks = [net(&ssid, 80, Security::WpaPsk)];
            let pages = [
                render_index(&branded("B"), &networks, &failed),
                render_index_with_error(&branded("B"), &networks, "join failed"),
            ];
            for html in pages {
                assert!(
                    html.contains(&format!(r#"<span class="net__name">{ssid}</span>"#)),
                    "{ssid} must be listed as itself"
                );
                assert_eq!(
                    html.matches(r#"role="alert""#).count(),
                    1,
                    "the banner belongs in its slot, once, with {ssid} in the list"
                );
                assert_eq!(html.matches(r#"class="net""#).count(), 1);
                assert_eq!(html.matches(r#"href="/brand.css""#).count(), 1);
            }

            // The connecting page puts the SSID in the heading and the copy.
            let html = render_connecting(&branded("B"), &ssid);
            assert!(html.contains(&format!("<h1>Connecting to {ssid}")));
            assert_eq!(html.matches(&ssid).count(), 2, "{ssid}");
            assert_eq!(html.matches(r#"href="/brand.css""#).count(), 1);
        }
    }

    /// --brand-name is operator-supplied, and substituted first, so it was
    /// re-scanned by every later pass: a name containing `{{NETWORKS}}`
    /// pulled the network list into the heading and the <title>.
    #[test]
    fn a_brand_name_spelling_a_token_renders_literally() {
        let name: String = TOKENS.iter().map(|t| format!("{{{{{t}}}}}")).collect();
        let networks = [net("Home", 80, Security::WpaPsk)];
        let failed = PortalState::Failed {
            ssid: "Office".into(),
            error: "join failed".into(),
        };

        let html = render_index(&plain(&name), &networks, &failed);
        assert!(html.contains(&format!("<h1>{name}</h1>")));
        assert_eq!(html.matches(r#"class="net""#).count(), 1);
        assert_eq!(html.matches(r#"role="alert""#).count(), 1);

        let html = render_index(&with_logo(&name), &networks, &PortalState::Portal);
        assert!(html.contains(&format!(r#"alt="{name}""#)));
        assert_eq!(html.matches(r#"class="net""#).count(), 1);

        let html = render_connecting(&plain(&name), "Home");
        assert!(html.contains(&name));
        assert!(html.contains("<h1>Connecting to Home"));
    }

    #[test]
    fn an_unknown_token_is_left_alone() {
        // The pages inline a stylesheet and a script we do not parse; a
        // `{{` in either is theirs, not ours to rewrite or panic over.
        let tokens = [("A", "x")];
        assert_eq!(render("{{B}} {{A}}", &tokens), "{{B}} x");
        assert_eq!(render("{{A", &tokens), "{{A");
        assert_eq!(render("}}{{", &tokens), "}}{{");
        // A stray `{{` does not swallow the real token that follows it.
        assert_eq!(render("{{{{A}}", &tokens), "{{x");
        assert_eq!(render("{{ {{A}} }}", &tokens), "{{ x }}");
        // Nor does a single brace in front of one, as in CSS or in a
        // mustache-style `{{{A}}}`: the token is the last two of the three.
        assert_eq!(render("{{{A}}}", &tokens), "{x}");
        assert_eq!(render("a{{{{{A}}}}}", &tokens), "a{{{x}}}");
    }

    #[test]
    fn a_substituted_value_is_never_rescanned() {
        let tokens = [("A", "{{B}}"), ("B", "{{A}}")];
        assert_eq!(render("{{A}}|{{B}}", &tokens), "{{B}}|{{A}}");
    }

    /// Positions found by searching for ASCII braces are always char
    /// boundaries, so multibyte text either side of, or inside, a brace
    /// pair must neither panic nor be mangled.
    #[test]
    fn multibyte_text_around_braces_is_sliced_safely() {
        let tokens = [("A", "ö")];
        assert_eq!(render("é{{A}}ü", &tokens), "éöü");
        assert_eq!(render("{{é}}{{A}}", &tokens), "{{é}}ö");
        assert_eq!(render("{{🦀", &tokens), "{{🦀");
        assert_eq!(render("{🦀{{A}}🦀}", &tokens), "{🦀ö🦀}");
    }

    /// The old renderer, verbatim: a chain of `str::replace`. Kept only to
    /// pin the new one to its output wherever no value spells a token.
    fn chained_replace(name: &str, branding: &Branding, page: &[(&str, &str)]) -> String {
        let mut html = template(branding, name)
            .replace("{{BRAND_HEADING}}", &render_brand_heading(branding))
            .replace("{{BRAND_NAME}}", &escape(&branding.name))
            .replace("{{BRAND_CSS}}", render_brand_css(branding.css.is_some()))
            .replace("{{THEME_ATTR}}", render_theme_attr(branding.theme))
            .replace("{{THEME_TOGGLE}}", render_theme_toggle(branding.theme));
        for (token, value) in page {
            html = html.replace(&format!("{{{{{token}}}}}"), value);
        }
        html
    }

    /// For every ordinary input the page must be byte-for-byte what the
    /// chain of `replace` calls produced, so the inlined script and
    /// stylesheet (whose bytes a CSP hash may pin) pass through untouched.
    #[test]
    fn ordinary_values_render_exactly_as_the_chained_replace_did() {
        let brandings = [
            plain("Anthias"),
            plain("Café <&> \"Ünïcødé\" 🦀 {single} }} {"),
            branded("B"),
            with_logo("Logo & Co"),
            pinned("B", ThemeMode::Dark),
            pinned("B", ThemeMode::Light),
        ];
        let networks = [
            net("Home", 80, Security::WpaPsk),
            net("Café 🦀 <b>", 10, Security::Open),
            net("{x} }}{", 55, Security::Sae),
        ];
        let failed = PortalState::Failed {
            ssid: "Office".into(),
            error: "wrong \"password\" é".into(),
        };
        for branding in &brandings {
            for nets in [&networks[..], &[]] {
                for state in [&PortalState::Portal, &failed] {
                    let list = render_networks(nets);
                    let banner = render_banner(state);
                    assert_eq!(
                        render_index(branding, nets, state),
                        chained_replace(
                            "index.html",
                            branding,
                            &[("NETWORKS", &list), ("BANNER", &banner)]
                        ),
                    );
                }
                let list = render_networks(nets);
                let banner = r#"<div class="banner" role="alert">bad &amp; é</div>"#;
                assert_eq!(
                    render_index_with_error(branding, nets, "bad & é"),
                    chained_replace(
                        "index.html",
                        branding,
                        &[("NETWORKS", &list), ("BANNER", banner)]
                    ),
                );
            }
            for ssid in ["Home", "Café 🦀 <b>", "{x} }}{"] {
                assert_eq!(
                    render_connecting(branding, ssid),
                    chained_replace("connecting.html", branding, &[("SSID", &escape(ssid))]),
                );
            }
        }
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

    /// The byte cap, separately from the file cap: one large file is how
    /// a directory of a few files still fills a small board's memory.
    #[test]
    fn a_ui_directory_over_the_byte_cap_is_refused() {
        let dir = TestUiDir::new();
        // One byte over on its own, so it is this file that trips the cap
        // whatever order the directory is listed in.
        let big = vec![b'x'; UI_DIRECTORY_MAX_BYTES as usize + 1];
        std::fs::write(dir.0.join("big.bin"), big).unwrap();
        let err = dir.load().err().expect("loaded more than the byte cap");
        assert!(err.to_string().contains("right directory"), "{err}");
        assert!(err.to_string().contains("big.bin"), "{err}");
    }

    /// An io::Error carries no path; the operator needs to know which of
    /// the files stopped the portal, not just that one did.
    #[test]
    fn a_dangling_symlink_is_named_in_the_error() {
        let dir = TestUiDir::new();
        std::os::unix::fs::symlink(dir.0.join("gone.css"), dir.0.join("dangling.css")).unwrap();
        let err = dir.load().err().expect("loaded a dangling symlink");
        assert!(err.to_string().contains("dangling.css"), "{err}");
    }

    /// A template from before a token existed is accepted, but the token
    /// is reported so --brand-css / --brand-logo / --default-theme do not
    /// silently look broken.
    #[test]
    fn tokens_an_older_template_lacks_are_reported() {
        let dir = TestUiDir::new();
        dir.write("index.html", "{{BRAND_NAME}}{{BANNER}}{{NETWORKS}}");
        let missing = dir.load().unwrap().missing_tokens();
        for expected in [
            "index.html: {{BRAND_CSS}}",
            "index.html: {{BRAND_HEADING}}",
            "index.html: {{THEME_ATTR}}",
            "index.html: {{THEME_TOGGLE}}",
            "connecting.html: {{BRAND_CSS}}",
        ] {
            assert!(
                missing.iter().any(|m| m == expected),
                "{expected} not in {missing:?}"
            );
        }
        assert!(!missing.iter().any(|m| m.contains("{{NETWORKS}}")));
    }

    /// The advice is "start from ui/dist", so a copy of it must report
    /// nothing missing.
    #[test]
    fn a_copy_of_the_embedded_ui_lacks_no_tokens() {
        let dir = copy_of_the_embedded_ui();
        assert_eq!(dir.load().unwrap().missing_tokens(), Vec::<String>::new());
    }

    #[test]
    fn tokens_finds_each_upper_case_token_once() {
        assert_eq!(
            tokens("{{A}} {{lower}} {{B_C}} {{A}} {{ }} {{"),
            vec!["{{A}}", "{{B_C}}"]
        );
    }

    /// A copy of the embedded templates, as `--ui-directory`.
    fn copy_of_the_embedded_ui() -> TestUiDir {
        let dir = TestUiDir::new();
        for name in TEMPLATES {
            let data = Assets::get(name).unwrap().data;
            dir.write(name, std::str::from_utf8(&data).unwrap());
        }
        dir
    }

    /// Every directive of `csp` but the two named, in order.
    fn other_directives<'a>(csp: &'a str, except: &[&str]) -> Vec<&'a str> {
        csp.split(';')
            .map(str::trim)
            .filter(|d| !except.iter().any(|e| d.split(' ').next() == Some(*e)))
            .collect()
    }

    /// The Rust extractor and ui/build.ts must agree byte for byte, or a
    /// `--ui-directory` copied from ui/dist would get a different policy
    /// from the very pages the built-in one was made for.
    #[test]
    fn the_rust_extractor_reproduces_csp_json_from_the_embedded_pages() {
        let pages = TEMPLATES.map(|name| {
            let data = Assets::get(name).unwrap().data;
            (name, String::from_utf8(data.into_owned()).unwrap())
        });
        let embedded = InlineHashes::embedded();
        assert!(!embedded.script.is_empty() && !embedded.style.is_empty());
        assert_eq!(InlineHashes::of_pages(pages), embedded);
    }

    #[test]
    fn inline_blocks_follows_the_build_ts_rule() {
        let html = "<script>a</script><script src=x></script>\
                    <script type=module>b</script><SCRIPT>c</SCRIPT>\
                    <script>\nd\n</script><script>unterminated";
        assert_eq!(inline_blocks(html, "script"), vec!["a", "\nd\n"]);
        assert_eq!(inline_blocks("<style></style>", "style"), vec![""]);
    }

    /// A copy of ui/dist gets exactly the built-in policy, plus `'self'`
    /// for script: same hashes, same everything else.
    #[test]
    fn a_copy_of_the_embedded_ui_gets_the_built_in_policy_plus_self() {
        let ui = copy_of_the_embedded_ui().load().unwrap();
        let built_in = content_security_policy().to_str().unwrap().to_owned();
        assert_eq!(
            ui.content_security_policy().to_str().unwrap(),
            built_in.replacen("script-src ", "script-src 'self' ", 1)
        );
        assert_eq!(ui.unhashed_inline_blocks(), Vec::<String>::new());
    }

    /// The defect this policy exists to fix: an operator's edited inline
    /// blocks were held to the embedded hashes and blocked.
    #[test]
    fn an_edited_ui_directory_is_allowed_by_its_own_hashes() {
        let dir = TestUiDir::new();
        dir.write(
            "index.html",
            "<style>body{color:red}</style>{{BRAND_CSS}}{{BANNER}}{{NETWORKS}}\
             <script>document.title='x'</script><script src=\"/assets/app.js\"></script>",
        );
        dir.write("connecting.html", "<script>poll()</script>{{SSID}}");
        let branding = with_ui("B", dir.load().unwrap());
        let ui = branding.ui.as_ref().unwrap();
        let csp = ui.content_security_policy().to_str().unwrap().to_owned();
        let built_in = content_security_policy().to_str().unwrap().to_owned();

        let script = directive(&csp, "script-src");
        let style = directive(&csp, "style-src");
        assert_eq!(script[0], "'self'", "{csp}");
        assert_eq!(style[0], "'self'", "{csp}");
        for page in [
            render_index(&branding, &[], &PortalState::Portal),
            render_connecting(&branding, "Home"),
        ] {
            for (tag, allowed) in [("script", &script), ("style", &style)] {
                for body in inline_blocks(&page, tag) {
                    let source = csp_source(body);
                    assert!(allowed.contains(&source.as_str()), "{tag} {source}: {csp}");
                }
            }
        }
        // Its own hashes, not the embedded ones riding along.
        for source in directive(&built_in, "script-src") {
            if is_sha256_source(source) {
                assert!(!script.contains(&source), "{source}");
            }
        }
        // Nothing else moved.
        assert_eq!(
            other_directives(&csp, &["script-src", "style-src"]),
            other_directives(&built_in, &["script-src", "style-src"])
        );
        assert_eq!(ui.unhashed_inline_blocks(), Vec::<String>::new());
    }

    /// No inline blocks means no hashes, and then no `'unsafe-inline'`
    /// either: with nothing to switch it off it would allow everything.
    #[test]
    fn a_ui_directory_without_inline_blocks_allows_only_self() {
        let ui = TestUiDir::new().load().unwrap();
        let csp = ui.content_security_policy().to_str().unwrap().to_owned();
        assert_eq!(directive(&csp, "script-src"), vec!["'self'"]);
        assert_eq!(directive(&csp, "style-src"), vec!["'self'"]);
        assert!(!csp.contains("unsafe-inline"), "{csp}");
    }

    /// Blocks the policy will refuse are reported for the startup log.
    #[test]
    fn inline_blocks_the_policy_cannot_allow_are_reported() {
        let dir = TestUiDir::new();
        dir.write(
            "index.html",
            "{{NETWORKS}}<script>var n='{{BRAND_NAME}}'</script>\
             <script type=\"module\">x()</script><style media=\"print\">a{}</style>\
             <script src=\"/assets/a.js\"></script><styles></styles>",
        );
        assert_eq!(
            dir.load().unwrap().unhashed_inline_blocks(),
            vec![
                "index.html: {{BRAND_NAME}} inside <script>",
                r#"index.html: <script type="module">"#,
                r#"index.html: <style media="print">"#,
            ]
        );
    }
}
