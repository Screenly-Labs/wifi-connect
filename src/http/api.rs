//! The portal's handlers.

use axum::Form;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use tracing::warn;

use crate::nm::JoinRequest;
use crate::passphrase;
use crate::secret::Secret;
use crate::ssid::Ssid;
use crate::state::{PortalState, Shared};

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

/// Render the portal page with the current networks and any pending error.
fn render_portal(shared: &Shared) -> String {
    assets::render_index(&shared.branding, &shared.networks(), &shared.state())
}

pub async fn index(State(shared): State<Shared>) -> Response {
    no_store(Html(render_portal(&shared)).into_response())
}

/// Apple's probe family: the portal page itself, served as HTML.
pub async fn probe_html(State(shared): State<Shared>) -> Response {
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
#[derive(Debug, serde::Deserialize)]
pub struct ConnectForm {
    #[serde(default)]
    pub ssid_hex: String,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub passphrase: String,
}

/// Why a submission was rejected before we touched the radio.
#[derive(Debug, PartialEq, Eq)]
pub enum FormError {
    NoNetwork,
    BadPassphrase(String),
}

impl FormError {
    fn message(&self) -> String {
        match self {
            FormError::NoNetwork => "Choose a network, or enter its name.".into(),
            FormError::BadPassphrase(m) => m.clone(),
        }
    }
}

/// Turn a submitted form into a join request.
///
/// Validating here rather than letting NetworkManager reject the profile is
/// what lets the portal say "passwords must be at least 8 characters"
/// instead of surfacing an opaque `InvalidProperty`. It also avoids a
/// thirty-second access-point bounce that teaches the user nothing: on a
/// validation failure the AP never goes down at all.
pub fn validate(form: &ConnectForm) -> Result<JoinRequest, FormError> {
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

    let passphrase = if form.passphrase.is_empty() {
        None
    } else {
        passphrase::validate(&form.passphrase)
            .map_err(|e| FormError::BadPassphrase(e.to_string()))?;
        Some(Secret::new(form.passphrase.clone()))
    };

    let identity = {
        let t = form.identity.trim();
        (!t.is_empty()).then(|| t.to_string())
    };

    Ok(JoinRequest {
        ssid,
        identity,
        passphrase,
        hidden,
    })
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
/// - **the one the request was addressed to** (`http://` + `Host`). Apple's
///   Captive Network Assistant is answered with the portal page *in place*
///   at `http://captive.apple.com/hotspot-detect.html` (see [`probe_html`]),
///   and the form's relative `action="/connect"` then posts back to that
///   same foreign host. Accepting only the portal origin would break setup
///   on every iPhone. A page served from the very origin it posts to is
///   same-origin by definition; that is not CSRF.
///
/// Evidence, in order of strength:
///
/// 1. `Sec-Fetch-Site: cross-site` or `same-site` — the browser itself says
///    the form lives elsewhere. (`same-site` covers another port on the
///    gateway; nothing legitimate posts from there.)
/// 2. `Origin`, which every current browser sends on a POST. `Origin: null`
///    (sandboxed iframes, `data:` and `file:` pages) is rejected: our own
///    page never produces it, and it is the classic way to launder a
///    cross-site POST past a naive "is the header present?" check.
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
/// learn a token nor forge the browser-set headers. The one attack that
/// defeats the header check, DNS-rebinding an attacker's name onto the
/// gateway, makes the attacker same-origin and so lets them read a token out
/// of the page as well. A token would add state and a template field for no
/// additional protection.
fn cross_site_reason(headers: &HeaderMap, portal_url: &str) -> Option<&'static str> {
    if let Some(site) = headers.get("sec-fetch-site") {
        let site = site.as_bytes();
        if site.eq_ignore_ascii_case(b"cross-site") || site.eq_ignore_ascii_case(b"same-site") {
            return Some("Sec-Fetch-Site says the form came from another site");
        }
    }

    let portal = origin_of(portal_url);
    // HTTP/1.1 makes Host mandatory, and HTTP/1 is the only listener we run.
    let addressed = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
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
            origin = ?headers.get(header::ORIGIN),
            referer = ?headers.get(header::REFERER),
            "rejected a cross-site POST /connect"
        );
        return no_store(
            (
                StatusCode::FORBIDDEN,
                Html(assets::render_index_with_error(
                    &shared.branding,
                    &shared.networks(),
                    "That request did not come from this setup page, so it was ignored. \
                     Choose a network below to continue.",
                )),
            )
                .into_response(),
        );
    }

    let request = match validate(&form) {
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
        }
    }

    #[test]
    fn a_selected_network_is_identified_by_its_exact_bytes() {
        let r = validate(&form("4d79ff", "", "abcdefgh")).unwrap();
        assert_eq!(r.ssid.as_bytes(), &[0x4d, 0x79, 0xff]);
        assert!(!r.hidden, "a scanned network is not hidden");
    }

    #[test]
    fn a_typed_network_is_treated_as_hidden() {
        let r = validate(&form("", "  My Hidden Net  ", "abcdefgh")).unwrap();
        assert_eq!(
            r.ssid,
            Ssid::from("My Hidden Net"),
            "whitespace must be trimmed"
        );
        assert!(r.hidden);
    }

    #[test]
    fn the_selected_network_wins_over_a_typed_one() {
        let r = validate(&form("486f6d65", "Typed", "abcdefgh")).unwrap();
        assert_eq!(r.ssid, Ssid::from("Home"));
    }

    #[test]
    fn a_submission_with_no_network_is_rejected() {
        for f in [
            form("", "", "abcdefgh"),
            form("", "   ", "abcdefgh"),
            form("zzz", "", "abcdefgh"),
        ] {
            assert_eq!(validate(&f).unwrap_err(), FormError::NoNetwork);
        }
    }

    /// A seven-character password is one of the commonest causes of a failed
    /// join. Catching it here saves a thirty-second access-point bounce that
    /// would teach the user nothing.
    #[test]
    fn a_short_passphrase_is_rejected_before_the_radio_is_touched() {
        let err = validate(&form("486f6d65", "", "short")).unwrap_err();
        match err {
            FormError::BadPassphrase(m) => assert!(m.contains('8'), "unhelpful: {m}"),
            other => panic!("expected a passphrase error, got {other:?}"),
        }
    }

    #[test]
    fn an_over_long_passphrase_is_rejected() {
        let err = validate(&form("486f6d65", "", &"a".repeat(64))).unwrap_err();
        assert!(matches!(err, FormError::BadPassphrase(_)));
    }

    #[test]
    fn an_empty_passphrase_means_an_open_network() {
        let r = validate(&form("486f6d65", "", "")).unwrap();
        assert!(r.passphrase.is_none());
    }

    #[test]
    fn an_identity_is_carried_for_enterprise_networks() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "  alice  ".into();
        let r = validate(&f).unwrap();
        assert_eq!(r.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn a_blank_identity_is_dropped_rather_than_sent_as_empty() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "   ".into();
        assert!(validate(&f).unwrap().identity.is_none());
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
        let r = validate(&form("486f6d65", "", "sup3rsecret")).unwrap();
        assert!(!format!("{r:?}").contains("sup3rsecret"));
    }
}
