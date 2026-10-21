//! The portal's handlers.

use axum::Form;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use tracing::warn;

use crate::nm::security::Security;
use crate::nm::{EapMethod, JoinRequest, WifiNetwork};
use crate::passphrase;
use crate::secret::Secret;
use crate::ssid::Ssid;
use crate::state::{PortalState, Shared};
use crate::static_ip;

use super::{assets, captive};

/// `Cache-Control: no-store` on everything.
///
/// Captive-portal mini-browsers cache aggressively, and a stale portal page
/// after the access point has bounced is indistinguishable from a hang.
fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The integrator's stylesheet, or nothing.
///
/// The pages link this unconditionally, so the markup is byte-identical
/// branded or not — which is the property that keeps a rebrand from coming
/// adrift when the portal's layout changes. An unbranded portal answers
/// with an empty stylesheet rather than a 404: it costs the same single
/// round trip on a link where the client is attached to this very device,
/// and it keeps 404s in the log meaningful.
pub async fn brand_css(State(shared): State<Shared>) -> Response {
    let css = shared.branding.css.as_deref().unwrap_or("");
    no_store(
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            )],
            css.to_owned(),
        )
            .into_response(),
    )
}

/// Serve `--brand-logo`, or 404 when none is configured.
///
/// 404 rather than an empty 200: the page only references this when a logo
/// is set, so a request for it otherwise is a stale cache or a prober, and
/// an empty image body would render as a broken image in the first case.
pub async fn brand_logo(State(shared): State<Shared>) -> Response {
    let Some(logo) = shared.branding.logo.as_ref() else {
        return no_store(StatusCode::NOT_FOUND.into_response());
    };
    no_store(
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(logo.content_type),
            )],
            logo.bytes.to_vec(),
        )
            .into_response(),
    )
}

/// Render the portal page with the current networks and any pending error.
fn render_portal(shared: &Shared) -> String {
    assets::render_index(&shared.branding, &shared.networks(), &shared.state())
}

/// The `Host` header with the default port dropped, so `x:80` and `x` are
/// the same authority, as they are to a browser serialising an origin.
fn host_authority(headers: &HeaderMap) -> Option<&str> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    Some(host.strip_suffix(":80").unwrap_or(host))
}

/// `true` when `authority` names Apple's own domain, where the Captive
/// Network Assistant probes and where we answer with the portal page in
/// place. Nobody but Apple can point a name under `apple.com` at us from
/// the outside, which is what makes it safe to treat as the portal's origin
/// (see [`cross_site_reason`]).
fn is_apple_probe_host(authority: &str) -> bool {
    let name = authority.split(':').next().unwrap_or(authority);
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    name == "apple.com" || name.ends_with(".apple.com")
}

/// Whether a page carrying the form may be served under this request's
/// `Host`, rather than redirected to the portal.
///
/// The form posts back to whatever host it was served under, and
/// [`cross_site_reason`] only accepts the portal's own origin and Apple's.
/// Serving it in place under any other name — `connectivity-check.ubuntu.com`
/// fetching `/`, a user typing `neverssl.com` — would hand out a form whose
/// every submission is refused. Those get the redirect instead, so the form
/// they fill in is always one that can be submitted. No `Host` at all is an
/// HTTP/1.0 client, not a browser; it gets the page.
fn serves_page_in_place(headers: &HeaderMap, portal_url: &str) -> bool {
    let Some(authority) = host_authority(headers) else {
        return headers.get(header::HOST).is_none();
    };
    origin_of(portal_url)
        .and_then(|o| o.strip_prefix("http://"))
        .is_some_and(|p| p.eq_ignore_ascii_case(authority))
        || is_apple_probe_host(authority)
}

pub async fn index(State(shared): State<Shared>, headers: HeaderMap) -> Response {
    if !serves_page_in_place(&headers, &shared.portal_url) {
        return captive::redirect_to_portal(&shared.portal_url);
    }
    no_store(Html(render_portal(&shared)).into_response())
}

/// Apple's probe family: the portal page itself, served as HTML, when the
/// probe is under Apple's own name; otherwise the ordinary redirect.
pub async fn probe_html(State(shared): State<Shared>, headers: HeaderMap) -> Response {
    if !serves_page_in_place(&headers, &shared.portal_url) {
        return captive::redirect_to_portal(&shared.portal_url);
    }
    captive::apple_probe_response(render_portal(&shared))
}

/// Everything else: a redirect to the portal.
pub async fn probe_redirect(State(shared): State<Shared>) -> Response {
    captive::redirect_to_portal(&shared.portal_url)
}

pub async fn captive_portal_api(State(shared): State<Shared>) -> Response {
    captive::CaptivePortalApi::new(&shared.portal_url).into_response()
}

pub async fn networks(State(shared): State<Shared>) -> Response {
    no_store(axum::Json(shared.networks()).into_response())
}

pub async fn status(State(shared): State<Shared>) -> Response {
    #[derive(serde::Serialize)]
    struct Status {
        #[serde(flatten)]
        state: PortalState,
        attempts: u32,
    }

    no_store(
        axum::Json(Status {
            state: shared.state(),
            attempts: shared.attempts(),
        })
        .into_response(),
    )
}

pub async fn connecting(State(shared): State<Shared>) -> Response {
    let ssid = match shared.state() {
        PortalState::Joining { ssid } | PortalState::Connected { ssid } => ssid,
        _ => String::new(),
    };
    no_store(Html(assets::render_connecting(&shared.branding, &ssid)).into_response())
}

/// The form `POST /connect` accepts.
///
/// `ssid_hex` carries the exact SSID bytes; `ssid` is the fallback for a
/// manually typed (hidden) network, where there are no bytes to carry.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ConnectForm {
    #[serde(default)]
    pub ssid_hex: String,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub passphrase: String,
    /// Enterprise only: the domain the RADIUS server's certificate must
    /// belong to. Optional; see [`server_domain`].
    #[serde(default)]
    pub server_domain: String,
    /// Enterprise only: `peap`, `ttls-mschapv2` or `ttls-pap`. Blank is
    /// PEAP, which is what every enterprise join was before there was a
    /// choice.
    #[serde(default)]
    pub eap_method: String,
    /// Static addressing, all optional; blank means automatic. See
    /// [`crate::static_ip`].
    #[serde(default)]
    pub ipv4_address: String,
    #[serde(default)]
    pub ipv4_gateway: String,
    #[serde(default)]
    pub ipv6_address: String,
    #[serde(default)]
    pub ipv6_gateway: String,
    #[serde(default)]
    pub dns: String,
}

/// Why a submission was rejected before we touched the radio.
#[derive(Debug, PartialEq, Eq)]
pub enum FormError {
    NoNetwork,
    BadPassphrase(String),
    BadServerDomain,
    BadEapMethod,
    /// TTLS/PAP while server verification is switched off.
    PlaintextPasswordToUnverifiedServer,
    BadIp(String),
}

impl FormError {
    fn message(&self) -> String {
        match self {
            FormError::NoNetwork => "Choose a network, or enter its name.".into(),
            FormError::BadPassphrase(m) | FormError::BadIp(m) => m.clone(),
            FormError::BadServerDomain => {
                "The server domain must be a host name such as radius.example.com.".into()
            }
            FormError::BadEapMethod => "Choose a sign-in method from the list.".into(),
            FormError::PlaintextPasswordToUnverifiedServer => {
                "TTLS with PAP is turned off on this device: it sends your password as it is, \
                 and this device is set not to check the network's server certificate, so \
                 any look-alike network could read it. Choose another sign-in method, or ask \
                 the device's administrator."
                    .into()
            }
        }
    }
}

/// The longest DNS name, in its dotted text form.
const MAX_DOMAIN_LEN: usize = 253;

/// Validate the optional "server domain" an enterprise user may supply.
///
/// It becomes `802-1x.domain-suffix-match`, which pins the RADIUS server's
/// certificate to a name rather than to "anything the CA store will sign".
/// We accept only what a host name can be — LDH labels of 1 to 63
/// characters, 253 in all — because the value is handed to the supplicant
/// verbatim: wpa_supplicant reads `;` in that field as a separator between
/// alternatives, so letting punctuation through would let one field
/// quietly widen the match. A trailing dot (the absolute form) is dropped
/// rather than refused, since people paste it from DNS tools.
///
/// Blank means "not supplied", which is not an error: system-CA validation
/// still applies without it.
pub fn server_domain(raw: &str) -> Result<Option<String>, FormError> {
    let t = raw.trim();
    let t = t.strip_suffix('.').unwrap_or(t);
    if t.is_empty() {
        return if raw.trim().is_empty() {
            Ok(None)
        } else {
            // A lone "." is not a domain.
            Err(FormError::BadServerDomain)
        };
    }
    if t.len() > MAX_DOMAIN_LEN {
        return Err(FormError::BadServerDomain);
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !t.split('.').all(label_ok) {
        return Err(FormError::BadServerDomain);
    }
    // Certificate name matching is case-insensitive; store one spelling.
    Ok(Some(t.to_ascii_lowercase()))
}

/// Turn a submitted form into a join request.
///
/// Validating here rather than letting NetworkManager reject the profile is
/// what lets the portal say "passwords must be at least 8 characters"
/// instead of surfacing an opaque `InvalidProperty`. It also avoids a
/// thirty-second access-point bounce that teaches the user nothing: on a
/// validation failure the AP never goes down at all.
///
/// `scanned` is the network list the portal offered. A username is what
/// turns a join into an 802.1X one (see `classify_credentials`), so when
/// the user picked a scanned network that is *not* enterprise, any
/// username and server domain that came along are dropped: a stale value
/// from a hidden field, a browser's autofill, or a hand-crafted POST must
/// not turn a WPA-PSK join into a doomed EAP one. A typed (hidden) network,
/// or one that has since left the list, has no recorded security, so there
/// the username alone decides, as before.
pub fn validate(form: &ConnectForm, scanned: &[WifiNetwork]) -> Result<JoinRequest, FormError> {
    let typed = form.ssid.trim();
    let (ssid, hidden) = if !form.ssid_hex.is_empty() {
        (
            Ssid::from_hex(&form.ssid_hex).map_err(|_| FormError::NoNetwork)?,
            false,
        )
    } else if !typed.is_empty() {
        (Ssid::from(typed), true)
    } else {
        return Err(FormError::NoNetwork);
    };

    if ssid.is_empty() {
        return Err(FormError::NoNetwork);
    }

    let known_security = if hidden {
        None
    } else {
        let hex = ssid.to_hex();
        scanned
            .iter()
            .find(|n| n.ssid_hex == hex)
            .map(|n| n.security)
    };

    let identity = {
        let t = form.identity.trim();
        (!t.is_empty()).then(|| t.to_string())
    }
    .filter(|_| known_security.is_none_or(Security::needs_identity));
    let enterprise = identity.is_some();
    // Only a scan result can say WEP; a typed network is assumed WPA.
    let wep = !enterprise && known_security == Some(Security::Wep);

    // An identity is what makes this an enterprise (802.1X) join: the NM
    // backend turns identity + password into WPA-EAP and a bare password
    // into WPA-PSK. The two secrets obey different rules, so which rules
    // apply has to follow the same split.
    let passphrase = match (enterprise, form.passphrase.is_empty()) {
        // Without a password the backend would quietly fall back to an open
        // join and drop the identity on the floor. An enterprise network is
        // never open, so that join can only fail — after an access-point
        // bounce — and the failure would blame a password the user never
        // typed. Ask for it instead.
        (true, true) => {
            return Err(FormError::BadPassphrase(
                "Enter the password for this network.".into(),
            ));
        }
        (true, false) => {
            validate_eap_password(&form.passphrase)?;
            Some(Secret::new(form.passphrase.clone()))
        }
        (false, true) => None,
        (false, false) if wep => {
            validate_wep_key(&form.passphrase)?;
            Some(Secret::new(form.passphrase.clone()))
        }
        (false, false) => {
            passphrase::validate(&form.passphrase)
                .map_err(|e| FormError::BadPassphrase(e.to_string()))?;
            Some(Secret::new(form.passphrase.clone()))
        }
    };

    // Only meaningful next to a username; otherwise ignored rather than
    // validated, so a leftover value cannot fail a PSK join either.
    let (server_domain, eap_method) = if enterprise {
        let method = match form.eap_method.trim() {
            "" => EapMethod::default(),
            m => EapMethod::from_form(m).ok_or(FormError::BadEapMethod)?,
        };
        (server_domain(&form.server_domain)?, method)
    } else {
        (None, EapMethod::default())
    };

    let ip = static_ip::parse(static_ip::Fields {
        ipv4_address: &form.ipv4_address,
        ipv4_gateway: &form.ipv4_gateway,
        ipv6_address: &form.ipv6_address,
        ipv6_gateway: &form.ipv6_gateway,
        dns: &form.dns,
    })
    .map_err(FormError::BadIp)?;

    // Without a key the join is open, whatever the scan said.
    let wep = wep && passphrase.is_some();
    Ok(JoinRequest {
        ssid,
        identity,
        passphrase,
        server_domain,
        eap_method,
        wep,
        hidden,
        ip,
    })
}

/// Refuse a join this device's configuration makes unsafe.
///
/// Separate from [`validate`] because it depends on how the operator set
/// the device up, not on the form. TTLS/PAP hands the password itself to
/// whatever terminates the tunnel; with `--insecure-eap-skip-server-verification`
/// that can be any access point copying the network's name. PEAP and
/// TTLS/MSCHAPv2 are weak there too, but what they leak is a challenge
/// response that has to be cracked; PAP would leak the password outright,
/// so it is the one combination refused rather than warned about.
pub fn check_policy(request: &JoinRequest, server_verified: bool) -> Result<(), FormError> {
    if request.identity.is_some()
        && request.eap_method.sends_password_in_clear()
        && !server_verified
    {
        return Err(FormError::PlaintextPasswordToUnverifiedServer);
    }
    Ok(())
}

/// The longest enterprise password we pass on, in characters.
///
/// EAP itself does not cap the password, but the inner method a PEAP network
/// almost always runs, MSCHAPv2, does: RFC 2759 limits it to 256 Unicode
/// characters. Nothing longer can authenticate there, and a bound keeps an
/// arbitrarily large form field out of the NetworkManager profile.
const EAP_PASSWORD_MAX_LEN: usize = 256;

/// Validate an enterprise (WPA-EAP) password.
///
/// WPA-PSK's 8..=63 printable-ASCII rule is a property of the pre-shared key
/// derivation, not of passwords in general. A RADIUS account password can be
/// short, long or non-ASCII, and holding it to PSK rules locks out users
/// whose credentials are perfectly valid. What we do still refuse is control
/// characters: NUL cannot cross D-Bus inside a string at all, and a newline
/// or similar has no business in a value that ends up in NetworkManager's and
/// wpa_supplicant's line-oriented configuration. No real password needs one.
///
/// Characters outside the Basic Multilingual Plane (emoji, for instance) are
/// refused too. MSCHAPv2 hashes the password as UTF-16, but wpa_supplicant's
/// UTF-8 to UCS-2 conversion (`utf8_to_ucs2` in `ms_funcs.c`) only decodes
/// sequences of up to three bytes: a four-byte one is silently mangled, so
/// the hash can never match and the join is certain to fail, after an
/// access-point bounce, as a wrong password.
fn validate_eap_password(value: &str) -> Result<(), FormError> {
    let len = value.chars().count();
    if len > EAP_PASSWORD_MAX_LEN {
        return Err(FormError::BadPassphrase(format!(
            "Password is too long: {len} characters, maximum is {EAP_PASSWORD_MAX_LEN}"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FormError::BadPassphrase(
            "Password must not contain control characters".into(),
        ));
    }
    if value.chars().any(|c| u32::from(c) > 0xFFFF) {
        return Err(FormError::BadPassphrase(
            "Password must not contain emoji or other characters this network's \
             sign-in cannot carry"
                .into(),
        ));
    }
    Ok(())
}

/// The longest WEP passphrase NetworkManager accepts. Raw keys are shorter
/// still: 5 or 13 characters, or 10 or 26 hex digits.
const WEP_PASSPHRASE_MAX_LEN: usize = 64;

/// Refuse a WEP key NetworkManager would reject.
///
/// Raw keys and passphrases share one field, as on the router, so anything
/// printable up to 64 ASCII characters is let through and
/// [`crate::nm::settings::apply_station_wep`] tells the two apart. WPA's
/// eight-character minimum must not apply: a 40-bit key is five.
fn validate_wep_key(value: &str) -> Result<(), FormError> {
    if !value.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(FormError::BadPassphrase(
            "WEP keys use only printable ASCII characters".into(),
        ));
    }
    if value.len() > WEP_PASSPHRASE_MAX_LEN {
        return Err(FormError::BadPassphrase(format!(
            "WEP key is too long: {} characters, maximum is {WEP_PASSPHRASE_MAX_LEN}",
            value.len()
        )));
    }
    Ok(())
}

/// The `scheme://host[:port]` prefix of an absolute URL, or `None` if it
/// has no scheme or no host.
///
/// That prefix is exactly how a browser serialises an origin (RFC 6454):
/// the portal URL is built as `http://gateway[:port]/`, so its origin is the
/// URL minus the trailing path, and a `Referer` reduces to its origin the
/// same way. No URL crate: the result is only ever compared, never trusted.
fn origin_of(url: &str) -> Option<&str> {
    let after_scheme = url.find("://")? + 3;
    let end = url[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i);
    (end > after_scheme).then(|| &url[..end])
}

/// Why a state-changing request looks forged from another site, if it does.
///
/// `POST /connect` makes the device leave its access point and join whatever
/// network the form names. A phone associated to the setup AP but browsing
/// over cellular can be made, by any web page it visits, to submit a form to
/// `http://<gateway>/connect` — the subnet is on-link, so the POST reaches
/// us. Without this check that page could send the device to a network of
/// the attacker's choosing, or keep knocking it off its AP with failed joins.
///
/// A request is accepted from one of two origins:
///
/// - **the portal's own** (`Shared::portal_url`), which is where every
///   redirect probe lands; and
/// - **the one the request was addressed to** (`http://` + `Host`), but only
///   when that is a name under `apple.com`. Apple's Captive Network
///   Assistant is answered with the portal page *in place* at
///   `http://captive.apple.com/hotspot-detect.html` (see [`probe_html`]),
///   and the form's relative `action="/connect"` then posts back to that
///   same foreign host. Accepting only the portal origin would break setup
///   on every iPhone. Any other `Host` is not accepted, however well its
///   `Origin` matches: that pair is exactly what DNS rebinding produces — an
///   attacker's page, loaded over cellular, re-resolving its own name to
///   the gateway — and an attacker cannot rebind a name under `apple.com`.
///   [`serves_page_in_place`] keeps the form off every other host, so a
///   genuine submission never arrives from one.
///
/// Evidence, checked in this order:
///
/// 1. `Sec-Fetch-Site: cross-site` or `same-site` — the browser itself says
///    the form lives elsewhere. Defence in depth only: browsers send the
///    `Sec-Fetch-*` headers only to potentially trustworthy (HTTPS or
///    loopback) URLs, and the portal is plain HTTP on a private address,
///    so today's browsers never send it here. (Were one to, our own form
///    posts to the very origin it was served from, so it would say
///    `same-origin`, including after the cross-host probe redirect; nothing
///    legitimate is `same-site`.)
/// 2. `Origin`, which every current browser sends on a POST. This is the
///    check that does the work. `Origin: null` (sandboxed iframes, `data:`
///    pages, a POST laundered through a cross-origin redirect) is rejected:
///    it is the classic way past a naive "is the header present?" check.
///    Our own page never produces it because the router pins
///    `Referrer-Policy: same-origin`; under `no-referrer` a browser sends
///    `null` even to its own origin.
/// 3. `Referer`, consulted only when `Origin` is absent (old browsers).
///
/// With none of the three present the request is let through. A client that
/// omits all of them is either a very old browser or not a browser at all —
/// and anything that can speak HTTP to the AP directly can submit the form
/// without our help, so refusing it buys nothing. Refusing it would, though,
/// lock an old captive mini-browser out of setup with no way to recover.
///
/// Why headers rather than a hidden form token: a token stops exactly what
/// this stops. A page on another origin cannot read ours, so it can neither
/// learn a token nor forge the browser-set headers. DNS rebinding would make
/// the attacker same-origin and so let them read a token out of the page as
/// well; it is the `Host` allowlist above, not a token, that stops it.
fn cross_site_reason(headers: &HeaderMap, portal_url: &str) -> Option<&'static str> {
    if let Some(site) = headers.get("sec-fetch-site") {
        let site = site.as_bytes();
        if site.eq_ignore_ascii_case(b"cross-site") || site.eq_ignore_ascii_case(b"same-site") {
            return Some("Sec-Fetch-Site says the form came from another site");
        }
    }

    let portal = origin_of(portal_url);
    // HTTP/1.1 makes Host mandatory, and HTTP/1 is the only listener we run.
    let addressed = host_authority(headers)
        .filter(|h| is_apple_probe_host(h))
        .map(|h| format!("http://{h}"));
    let allowed = |origin: &str| {
        portal.is_some_and(|p| p.eq_ignore_ascii_case(origin))
            || addressed
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(origin))
    };

    if let Some(origin) = headers.get(header::ORIGIN) {
        return match origin.to_str() {
            Ok(o) if allowed(o) => None,
            _ => Some("Origin is neither the portal's nor the request's own"),
        };
    }

    if let Some(referer) = headers.get(header::REFERER) {
        return match referer.to_str().ok().and_then(origin_of) {
            Some(o) if allowed(o) => None,
            _ => Some("Referer is neither the portal's nor the request's own"),
        };
    }

    None
}

pub async fn connect(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<ConnectForm>,
) -> Response {
    // Before validation, so a forged request learns nothing about what the
    // form would have accepted, and long before the radio is touched.
    if let Some(reason) = cross_site_reason(&headers, &shared.portal_url) {
        warn!(
            reason,
            host = ?headers.get(header::HOST),
            origin = ?headers.get(header::ORIGIN),
            referer = ?headers.get(header::REFERER),
            sec_fetch_site = ?headers.get("sec-fetch-site"),
            "rejected a cross-site POST /connect"
        );
        return no_store(
            (
                StatusCode::FORBIDDEN,
                Html(assets::render_index_with_error(
                    &shared.branding,
                    &shared.networks(),
                    "That request did not come from this setup page, so it was ignored \
                     and nothing was changed. To set up this device, choose a network \
                     below and connect again. If this message comes back every time, \
                     your browser is hiding where the request came from: try another \
                     browser.",
                )),
            )
                .into_response(),
        );
    }

    let request = match validate(&form, &shared.networks())
        .and_then(|r| check_policy(&r, shared.eap_server_verified).map(|()| r))
    {
        Ok(r) => r,
        Err(e) => {
            // No teardown: the user stays on the portal and fixes the typo.
            return no_store(
                (
                    StatusCode::BAD_REQUEST,
                    Html(assets::render_index_with_error(
                        &shared.branding,
                        &shared.networks(),
                        &e.message(),
                    )),
                )
                    .into_response(),
            );
        }
    };

    let ssid = request.ssid.to_display_string();

    if !shared.submit(request).await {
        return no_store(
            (
                StatusCode::CONFLICT,
                Html(assets::render_connecting(&shared.branding, &ssid)),
            )
                .into_response(),
        );
    }

    // Answer now, before the state machine tears the access point down.
    // Anything not already flushed dies with the client's connection.
    no_store(
        (
            StatusCode::ACCEPTED,
            Html(assets::render_connecting(&shared.branding, &ssid)),
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(ssid_hex: &str, ssid: &str, passphrase: &str) -> ConnectForm {
        ConnectForm {
            ssid_hex: ssid_hex.into(),
            ssid: ssid.into(),
            identity: String::new(),
            passphrase: passphrase.into(),
            ..ConnectForm::default()
        }
    }

    #[test]
    fn a_selected_network_is_identified_by_its_exact_bytes() {
        let r = validate(&form("4d79ff", "", "abcdefgh"), &[]).unwrap();
        assert_eq!(r.ssid.as_bytes(), &[0x4d, 0x79, 0xff]);
        assert!(!r.hidden, "a scanned network is not hidden");
    }

    #[test]
    fn a_typed_network_is_treated_as_hidden() {
        let r = validate(&form("", "  My Hidden Net  ", "abcdefgh"), &[]).unwrap();
        assert_eq!(
            r.ssid,
            Ssid::from("My Hidden Net"),
            "whitespace must be trimmed"
        );
        assert!(r.hidden);
    }

    #[test]
    fn the_selected_network_wins_over_a_typed_one() {
        let r = validate(&form("486f6d65", "Typed", "abcdefgh"), &[]).unwrap();
        assert_eq!(r.ssid, Ssid::from("Home"));
    }

    #[test]
    fn a_submission_with_no_network_is_rejected() {
        for f in [
            form("", "", "abcdefgh"),
            form("", "   ", "abcdefgh"),
            form("zzz", "", "abcdefgh"),
        ] {
            assert_eq!(validate(&f, &[]).unwrap_err(), FormError::NoNetwork);
        }
    }

    /// A seven-character password is one of the commonest causes of a failed
    /// join. Catching it here saves a thirty-second access-point bounce that
    /// would teach the user nothing.
    #[test]
    fn a_short_passphrase_is_rejected_before_the_radio_is_touched() {
        let err = validate(&form("486f6d65", "", "short"), &[]).unwrap_err();
        match err {
            FormError::BadPassphrase(m) => assert!(m.contains('8'), "unhelpful: {m}"),
            other => panic!("expected a passphrase error, got {other:?}"),
        }
    }

    #[test]
    fn an_over_long_passphrase_is_rejected() {
        let err = validate(&form("486f6d65", "", &"a".repeat(64)), &[]).unwrap_err();
        assert!(matches!(err, FormError::BadPassphrase(_)));
    }

    #[test]
    fn an_empty_passphrase_means_an_open_network() {
        let r = validate(&form("486f6d65", "", ""), &[]).unwrap();
        assert!(r.passphrase.is_none());
    }

    #[test]
    fn an_identity_is_carried_for_enterprise_networks() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "  alice  ".into();
        let r = validate(&f, &[]).unwrap();
        assert_eq!(r.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn a_blank_identity_is_dropped_rather_than_sent_as_empty() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "   ".into();
        assert!(validate(&f, &[]).unwrap().identity.is_none());
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    const PORTAL: &str = "http://192.168.42.1/";

    #[test]
    fn the_origin_of_a_url_is_its_scheme_and_authority() {
        assert_eq!(origin_of(PORTAL), Some("http://192.168.42.1"));
        assert_eq!(
            origin_of("http://10.0.0.1:8080/"),
            Some("http://10.0.0.1:8080")
        );
        assert_eq!(
            origin_of("http://192.168.42.1/connect?x=1#y"),
            Some("http://192.168.42.1")
        );
        assert_eq!(
            origin_of("http://192.168.42.1?x"),
            Some("http://192.168.42.1")
        );
        assert_eq!(origin_of("http:///nohost"), None);
        assert_eq!(origin_of("/relative"), None);
    }

    #[test]
    fn a_post_from_the_portal_page_is_not_cross_site() {
        let h = headers(&[
            ("host", "192.168.42.1"),
            ("origin", "http://192.168.42.1"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert_eq!(cross_site_reason(&h, PORTAL), None);
    }

    /// The portal URL carries the port when it is not 80, and so does the
    /// browser's Origin; the two must still match, and a different port is
    /// a different origin.
    #[test]
    fn a_non_default_port_is_part_of_the_portal_origin() {
        let portal = "http://10.0.0.1:8080/";
        let ok = headers(&[
            ("host", "10.0.0.1:8080"),
            ("origin", "http://10.0.0.1:8080"),
        ]);
        assert_eq!(cross_site_reason(&ok, portal), None);

        let other_port = headers(&[("host", "10.0.0.1:8080"), ("origin", "http://10.0.0.1")]);
        assert!(cross_site_reason(&other_port, portal).is_some());
    }

    /// iOS: the CNA loads `captive.apple.com/hotspot-detect.html`, we answer
    /// with the portal page in place, and its relative form action posts
    /// back to `captive.apple.com`. Rejecting this would break every iPhone.
    #[test]
    fn a_post_from_the_portal_served_in_place_under_a_probe_host_is_accepted() {
        let h = headers(&[
            ("host", "captive.apple.com"),
            ("origin", "http://captive.apple.com"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert_eq!(cross_site_reason(&h, PORTAL), None);
    }

    /// DNS rebinding: an attacker's page re-resolves its own name to the
    /// gateway and posts to it, so Origin and Host agree perfectly. Only a
    /// name under `apple.com` is trusted that way, and lookalikes are not.
    #[test]
    fn a_matching_origin_and_host_outside_apple_com_is_cross_site() {
        for host in [
            "evil.example",
            "evilapple.com",
            "apple.com.evil.example",
            "captive.apple.com.evil.example",
            "connectivity-check.ubuntu.com",
        ] {
            let h = headers(&[
                ("host", host),
                ("origin", &format!("http://{host}")),
                ("sec-fetch-site", "same-origin"),
            ]);
            assert!(cross_site_reason(&h, PORTAL).is_some(), "{host} accepted");
        }
    }

    /// A default port or a fully-qualified trailing dot in Host is still
    /// the same Apple name the browser's Origin spells without them.
    #[test]
    fn an_apple_host_is_recognised_in_its_spellings() {
        for (host, origin) in [
            ("captive.apple.com:80", "http://captive.apple.com"),
            ("captive.apple.com.", "http://captive.apple.com."),
            ("WWW.Apple.COM", "http://www.apple.com"),
        ] {
            let h = headers(&[("host", host), ("origin", origin)]);
            assert_eq!(cross_site_reason(&h, PORTAL), None, "{host}");
        }
        // A non-default port is a different origin, Apple or not.
        let h = headers(&[
            ("host", "captive.apple.com:8080"),
            ("origin", "http://captive.apple.com"),
        ]);
        assert!(cross_site_reason(&h, PORTAL).is_some());
    }

    /// The form is only ever served under a host whose POST would be
    /// accepted; everything else is sent to the portal first.
    #[test]
    fn the_page_is_served_in_place_only_where_its_form_can_be_submitted() {
        for host in [
            "192.168.42.1",
            "192.168.42.1:80",
            "captive.apple.com",
            "www.apple.com",
        ] {
            let h = headers(&[("host", host)]);
            assert!(serves_page_in_place(&h, PORTAL), "{host} redirected");
        }
        for host in [
            "connectivity-check.ubuntu.com",
            "neverssl.com",
            "www.appleiphonecell.com",
            "192.168.42.1:8080",
        ] {
            let h = headers(&[("host", host)]);
            assert!(!serves_page_in_place(&h, PORTAL), "{host} served in place");
        }
        assert!(serves_page_in_place(&HeaderMap::new(), PORTAL));

        let portal = "http://10.0.0.1:8080/";
        assert!(serves_page_in_place(
            &headers(&[("host", "10.0.0.1:8080")]),
            portal
        ));
        assert!(!serves_page_in_place(
            &headers(&[("host", "10.0.0.1")]),
            portal
        ));
    }

    #[test]
    fn a_post_from_another_origin_is_cross_site() {
        for origin in [
            "http://evil.example",
            "https://192.168.42.1",
            "http://192.168.42.1:8080",
            "http://192.168.42.10",
            "http://192.168.42.1.evil.example",
        ] {
            let h = headers(&[("host", "192.168.42.1"), ("origin", origin)]);
            assert!(cross_site_reason(&h, PORTAL).is_some(), "{origin} accepted");
        }
    }

    /// The portal is plain HTTP, so an https page that merely shares the
    /// Host's name cannot be one we served.
    #[test]
    fn an_https_origin_matching_the_host_name_is_still_rejected() {
        let h = headers(&[
            ("host", "captive.apple.com"),
            ("origin", "https://captive.apple.com"),
        ]);
        assert!(cross_site_reason(&h, PORTAL).is_some());
    }

    #[test]
    fn a_null_origin_is_rejected() {
        let h = headers(&[("host", "192.168.42.1"), ("origin", "null")]);
        assert!(cross_site_reason(&h, PORTAL).is_some());
    }

    /// Origin outranks Referer: a matching Referer cannot rescue a foreign
    /// Origin.
    #[test]
    fn a_matching_referer_does_not_rescue_a_foreign_origin() {
        let h = headers(&[
            ("host", "192.168.42.1"),
            ("origin", "http://evil.example"),
            ("referer", "http://192.168.42.1/"),
        ]);
        assert!(cross_site_reason(&h, PORTAL).is_some());
    }

    #[test]
    fn referer_decides_when_origin_is_absent() {
        let ok = headers(&[
            ("host", "192.168.42.1"),
            ("referer", "http://192.168.42.1/?error=1"),
        ]);
        assert_eq!(cross_site_reason(&ok, PORTAL), None);

        // A Referer whose *path* mentions the portal is not the portal.
        let bad = headers(&[
            ("host", "192.168.42.1"),
            ("referer", "http://evil.example/http://192.168.42.1/"),
        ]);
        assert!(cross_site_reason(&bad, PORTAL).is_some());

        let garbage = headers(&[("host", "192.168.42.1"), ("referer", "not a url")]);
        assert!(cross_site_reason(&garbage, PORTAL).is_some());
    }

    #[test]
    fn sec_fetch_site_alone_can_reject() {
        for site in ["cross-site", "same-site", "Cross-Site"] {
            let h = headers(&[
                ("host", "192.168.42.1"),
                ("origin", "http://192.168.42.1"),
                ("sec-fetch-site", site),
            ]);
            assert!(cross_site_reason(&h, PORTAL).is_some(), "{site} accepted");
        }
    }

    /// No Origin, no Referer, no Sec-Fetch-Site: not something a browser
    /// can be tricked into sending cross-site, so nothing to defend.
    #[test]
    fn a_request_without_any_provenance_headers_is_accepted() {
        let h = headers(&[("host", "192.168.42.1")]);
        assert_eq!(cross_site_reason(&h, PORTAL), None);
        assert_eq!(cross_site_reason(&HeaderMap::new(), PORTAL), None);
    }

    #[test]
    fn the_passphrase_does_not_leak_through_the_request_debug() {
        let r = validate(&form("486f6d65", "", "sup3rsecret"), &[]).unwrap();
        assert!(!format!("{r:?}").contains("sup3rsecret"));
    }

    #[test]
    fn a_server_domain_is_carried_normalised() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "alice@example.com".into();
        f.server_domain = "  Radius.Example.COM.  ".into();
        let r = validate(&f, &[]).unwrap();
        assert_eq!(
            r.server_domain.as_deref(),
            Some("radius.example.com"),
            "trimmed, lower-cased, and without the absolute-form dot"
        );
    }

    #[test]
    fn a_blank_server_domain_is_simply_not_supplied() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.server_domain = "   ".into();
        assert!(validate(&f, &[]).unwrap().server_domain.is_none());
    }

    /// The value goes to the supplicant verbatim, and wpa_supplicant reads
    /// `;` in `domain_suffix_match` as "or". Anything but a host name must
    /// be refused before it can widen the match.
    #[test]
    fn a_server_domain_that_is_not_a_host_name_is_rejected() {
        for bad in [
            ".",
            "example.com;evil.net",
            "example .com",
            "example..com",
            ".example.com",
            "-radius.example.com",
            "radius-.example.com",
            "radius_1.example.com",
            "*.example.com",
            "exämple.com",
            "radius.example.com/x",
        ] {
            assert_eq!(
                server_domain(bad).unwrap_err(),
                FormError::BadServerDomain,
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn server_domain_length_limits_are_enforced() {
        let label63 = "a".repeat(63);
        assert!(server_domain(&format!("{label63}.com")).is_ok());
        assert!(server_domain(&format!("{}a.com", label63)).is_err());

        // 4 x 63 + 3 dots = 255 > 253.
        let long = [label63.as_str(); 4].join(".");
        assert!(server_domain(&long).is_err());
        // A single label is a valid suffix to match on.
        assert_eq!(server_domain("corp").unwrap().as_deref(), Some("corp"));
    }

    /// Rejected before the radio is touched, like a bad passphrase: a typo
    /// here would otherwise cost an access-point bounce and come back as a
    /// generic authentication failure.
    #[test]
    fn a_bad_server_domain_fails_the_whole_submission() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "alice".into();
        f.server_domain = "example.com;evil.net".into();
        assert_eq!(validate(&f, &[]).unwrap_err(), FormError::BadServerDomain);
    }

    /// "Home" (486f6d65) as the portal listed it.
    fn scanned(security: Security) -> Vec<WifiNetwork> {
        vec![WifiNetwork::new(
            Ssid::from("Home"),
            80,
            security,
            Some(2437),
        )]
    }

    /// A 40-bit WEP key is five characters, below WPA's minimum of eight,
    /// so a scanned WEP network must not be held to WPA's rules.
    #[test]
    fn a_scanned_wep_network_takes_a_wep_key() {
        for key in ["abcde", "0123456789abcdef0123456789", "a long passphrase"] {
            let r = validate(&form("486f6d65", "", key), &scanned(Security::Wep)).unwrap();
            assert!(r.wep, "{key}");
            assert_eq!(r.passphrase.as_ref().unwrap().expose(), key);
        }
        let too_long = "x".repeat(65);
        assert!(matches!(
            validate(&form("486f6d65", "", &too_long), &scanned(Security::Wep)),
            Err(FormError::BadPassphrase(_))
        ));
        assert!(matches!(
            validate(&form("486f6d65", "", "caf\u{e9}s"), &scanned(Security::Wep)),
            Err(FormError::BadPassphrase(_))
        ));
    }

    /// WEP is only known from a scan; everywhere else a short key is still
    /// refused as a WPA passphrase, and a join is never marked WEP.
    #[test]
    fn only_a_scanned_wep_network_is_joined_as_wep() {
        assert!(validate(&form("486f6d65", "", "abcde"), &scanned(Security::WpaPsk)).is_err());
        assert!(validate(&form("", "Home", "abcde"), &scanned(Security::Wep)).is_err());
        let r = validate(
            &form("486f6d65", "", "abcdefgh"),
            &scanned(Security::WpaPsk),
        )
        .unwrap();
        assert!(!r.wep);
    }

    /// The portal hides the username block for a PSK network but a hidden
    /// input still submits, and autofill or a crafted POST can fill it
    /// anyway. A username is what makes a join 802.1X, so on a network the
    /// scan says is PSK it must be dropped, or a correct WPA password goes
    /// out as an EAP login and the join fails.
    #[test]
    fn a_username_sent_for_a_scanned_psk_network_is_dropped() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "alice".into();
        f.server_domain = "radius.example.com".into();
        let r = validate(&f, &scanned(Security::WpaPsk)).unwrap();
        assert!(r.identity.is_none(), "would have been joined as EAP");
        assert!(r.server_domain.is_none());
        assert!(r.passphrase.is_some());
    }

    /// Ignored, so not validated either: a leftover typo in a field the
    /// user can no longer see must not block a PSK join.
    #[test]
    fn a_leftover_bad_server_domain_does_not_fail_a_psk_join() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "alice".into();
        f.server_domain = "example.com;evil.net".into();
        assert!(validate(&f, &scanned(Security::WpaPsk)).is_ok());
    }

    #[test]
    fn a_username_is_kept_for_a_scanned_enterprise_network() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "alice".into();
        f.server_domain = "radius.example.com".into();
        let r = validate(&f, &scanned(Security::Enterprise)).unwrap();
        assert_eq!(r.identity.as_deref(), Some("alice"));
        assert_eq!(r.server_domain.as_deref(), Some("radius.example.com"));
    }

    /// The 8..=63 rule is WPA-PSK's. Directory passwords are routinely
    /// longer, shorter, or non-ASCII.
    #[test]
    fn enterprise_passwords_are_not_held_to_the_wpa_psk_rules() {
        for pw in [
            "a".repeat(64),
            "a".repeat(200),
            "short".into(),
            "pässwörd".into(),
        ] {
            let mut f = form("486f6d65", "", &pw);
            f.identity = "alice".into();
            let r = validate(&f, &scanned(Security::Enterprise)).unwrap();
            assert_eq!(r.passphrase.unwrap().expose(), pw);
        }
        // The same password without a username is a PSK and still checked.
        let f = form("486f6d65", "", &"a".repeat(64));
        assert!(matches!(
            validate(&f, &scanned(Security::Enterprise)).unwrap_err(),
            FormError::BadPassphrase(_)
        ));
    }

    /// A typed hidden network was never scanned, so the username is the
    /// only signal; it must still reach the join.
    #[test]
    fn a_hidden_network_keeps_its_username() {
        let mut f = form("", "Home", "abcdefgh");
        f.identity = "alice".into();
        let r = validate(&f, &scanned(Security::WpaPsk)).unwrap();
        assert!(r.hidden);
        assert_eq!(r.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn an_enterprise_join_without_a_method_is_peap() {
        let r = validate(&enterprise("abc123"), &[]).unwrap();
        assert_eq!(r.eap_method, EapMethod::PeapMschapv2);
    }

    #[test]
    fn each_enterprise_method_is_read_from_the_form() {
        for (value, method) in [
            ("peap", EapMethod::PeapMschapv2),
            ("ttls-mschapv2", EapMethod::TtlsMschapv2),
            (" ttls-pap ", EapMethod::TtlsPap),
        ] {
            let mut f = enterprise("abc123");
            f.eap_method = value.into();
            assert_eq!(validate(&f, &[]).unwrap().eap_method, method, "{value}");
        }
    }

    #[test]
    fn an_unknown_method_fails_the_submission() {
        let mut f = enterprise("abc123");
        f.eap_method = "tls".into();
        assert_eq!(validate(&f, &[]).unwrap_err(), FormError::BadEapMethod);
    }

    /// Like the server domain: meaningless without a username, so ignored
    /// rather than validated.
    #[test]
    fn a_leftover_method_does_not_touch_a_psk_join() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.eap_method = "nonsense".into();
        let r = validate(&f, &[]).unwrap();
        assert_eq!(r.eap_method, EapMethod::default());
    }

    #[test]
    fn ttls_pap_is_refused_only_when_the_server_goes_unchecked() {
        let mut f = enterprise("abc123");
        f.eap_method = "ttls-pap".into();
        let r = validate(&f, &[]).unwrap();
        assert_eq!(check_policy(&r, true), Ok(()));
        assert_eq!(
            check_policy(&r, false),
            Err(FormError::PlaintextPasswordToUnverifiedServer)
        );

        f.eap_method = "ttls-mschapv2".into();
        let r = validate(&f, &[]).unwrap();
        assert_eq!(check_policy(&r, false), Ok(()));
    }

    /// Blank addressing fields are automatic addressing, which is what
    /// every join was before there were any.
    #[test]
    fn a_form_without_addressing_joins_automatically() {
        let r = validate(&form("486f6d65", "", "abcdefgh"), &[]).unwrap();
        assert!(r.ip.is_automatic());
    }

    #[test]
    fn static_addressing_on_both_families_is_carried() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.ipv4_address = "192.168.1.50/24".into();
        f.ipv4_gateway = "192.168.1.1".into();
        f.ipv6_address = "2001:db8::50/64".into();
        f.ipv6_gateway = "fe80::1".into();
        f.dns = "192.168.1.1, 2001:db8::1".into();
        let ip = validate(&f, &[]).unwrap().ip;
        assert_eq!(ip.ipv4.unwrap().prefix, 24);
        assert_eq!(ip.ipv6.unwrap().prefix, 64);
        assert_eq!(ip.dns.len(), 2);
    }

    /// Caught here, before the access point goes down, rather than as a
    /// device that joined and can reach nothing.
    #[test]
    fn bad_addressing_fails_the_submission_with_a_reason() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.ipv4_address = "192.168.1.50/24".into();
        f.ipv4_gateway = "10.0.0.1".into();
        f.dns = "1.1.1.1".into();
        let e = validate(&f, &[]).unwrap_err();
        assert!(
            matches!(&e, FormError::BadIp(m) if m.contains("10.0.0.1")),
            "{e:?}"
        );
    }

    fn enterprise(passphrase: &str) -> ConnectForm {
        let mut f = form("486f6d65", "", passphrase);
        f.identity = "alice".into();
        f
    }

    /// RADIUS passwords are not WPA-PSK passphrases: a six-character account
    /// password is perfectly valid on an 802.1X network.
    #[test]
    fn a_short_enterprise_password_is_accepted() {
        let r = validate(&enterprise("abc123"), &[]).unwrap();
        assert_eq!(r.passphrase.unwrap().expose(), "abc123");
        assert_eq!(r.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn a_non_ascii_enterprise_password_is_accepted() {
        let r = validate(&enterprise("pässwörd€漢字"), &[]).unwrap();
        assert_eq!(r.passphrase.unwrap().expose(), "pässwörd€漢字");
    }

    /// wpa_supplicant's MSCHAPv2 cannot hash a character beyond U+FFFF, so
    /// such a password can only fail, and only after the AP has bounced.
    #[test]
    fn an_enterprise_password_outside_the_bmp_is_rejected() {
        for p in ["pass\u{1F600}word", "\u{10000}", "\u{10FFFF}"] {
            assert!(
                matches!(
                    validate(&enterprise(p), &[]),
                    Err(FormError::BadPassphrase(_))
                ),
                "accepted {p:?}"
            );
        }
        assert!(validate(&enterprise("\u{FFFD}"), &[]).is_ok());
    }

    /// PSK's 63-character ceiling does not apply, but some ceiling does.
    #[test]
    fn an_enterprise_password_is_bounded_by_mschapv2_not_by_psk() {
        assert!(validate(&enterprise(&"a".repeat(64)), &[]).is_ok());
        assert!(validate(&enterprise(&"a".repeat(EAP_PASSWORD_MAX_LEN)), &[]).is_ok());
        let err = validate(&enterprise(&"a".repeat(EAP_PASSWORD_MAX_LEN + 1)), &[]).unwrap_err();
        match err {
            FormError::BadPassphrase(m) => assert!(m.contains("256"), "unhelpful: {m}"),
            other => panic!("expected a passphrase error, got {other:?}"),
        }
    }

    #[test]
    fn an_enterprise_password_with_control_characters_is_rejected() {
        for p in [
            "pass\0word",
            "pass\nword",
            "pass\rword",
            "pass\u{7f}word",
            "pass\u{85}word",
        ] {
            assert!(
                matches!(
                    validate(&enterprise(p), &[]),
                    Err(FormError::BadPassphrase(_))
                ),
                "accepted {p:?}"
            );
        }
    }

    /// The relaxed rules hinge on the identity; without one the password is
    /// a pre-shared key and the WPA-PSK rules still hold.
    #[test]
    fn psk_rules_still_apply_without_an_identity() {
        for p in ["abc123", "pässwörd", &"a".repeat(64)] {
            assert!(
                matches!(
                    validate(&form("486f6d65", "", p), &[]),
                    Err(FormError::BadPassphrase(_))
                ),
                "accepted {p:?} as a PSK"
            );
        }
    }

    /// An identity with no password would otherwise become an open join that
    /// silently discards the identity and can only fail.
    #[test]
    fn an_identity_without_a_password_is_rejected() {
        let err = validate(&enterprise(""), &[]).unwrap_err();
        match err {
            FormError::BadPassphrase(m) => assert!(m.contains("password"), "unhelpful: {m}"),
            other => panic!("expected a passphrase error, got {other:?}"),
        }
    }

    /// The portal only hides the username block when the user switches
    /// networks, and a hidden input still submits. On a scanned open
    /// network that leftover username must not demand a password the user
    /// cannot enter: the password field is disabled there.
    #[test]
    fn a_stale_username_does_not_block_an_open_network() {
        let r = validate(&enterprise(""), &scanned(Security::Open)).unwrap();
        assert!(r.identity.is_none());
        assert!(r.passphrase.is_none());
    }

    #[test]
    fn a_scanned_enterprise_network_keeps_the_username_and_its_rules() {
        let r = validate(&enterprise("abc123"), &scanned(Security::Enterprise)).unwrap();
        assert_eq!(r.identity.as_deref(), Some("alice"));
        assert!(matches!(
            validate(&enterprise(""), &scanned(Security::Enterprise)).unwrap_err(),
            FormError::BadPassphrase(_)
        ));
    }
}
