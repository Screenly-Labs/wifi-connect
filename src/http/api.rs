//! The portal's handlers.

use axum::Form;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

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

    let identity = {
        let t = form.identity.trim();
        (!t.is_empty()).then(|| t.to_string())
    };

    // An identity is what makes this an enterprise (802.1X) join: the NM
    // backend turns identity + password into WPA-EAP and a bare password
    // into WPA-PSK. The two secrets obey different rules, so which rules
    // apply has to follow the same split.
    let passphrase = match (identity.is_some(), form.passphrase.is_empty()) {
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
        (false, false) => {
            passphrase::validate(&form.passphrase)
                .map_err(|e| FormError::BadPassphrase(e.to_string()))?;
            Some(Secret::new(form.passphrase.clone()))
        }
    };

    Ok(JoinRequest {
        ssid,
        identity,
        passphrase,
        hidden,
    })
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
    Ok(())
}

pub async fn connect(State(shared): State<Shared>, Form(form): Form<ConnectForm>) -> Response {
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

    fn enterprise(passphrase: &str) -> ConnectForm {
        let mut f = form("486f6d65", "", passphrase);
        f.identity = "alice".into();
        f
    }

    /// RADIUS passwords are not WPA-PSK passphrases: a six-character account
    /// password is perfectly valid on an 802.1X network.
    #[test]
    fn a_short_enterprise_password_is_accepted() {
        let r = validate(&enterprise("abc123")).unwrap();
        assert_eq!(r.passphrase.unwrap().expose(), "abc123");
        assert_eq!(r.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn a_non_ascii_enterprise_password_is_accepted() {
        let r = validate(&enterprise("pässwörd\u{1F600}")).unwrap();
        assert_eq!(r.passphrase.unwrap().expose(), "pässwörd\u{1F600}");
    }

    /// PSK's 63-character ceiling does not apply, but some ceiling does.
    #[test]
    fn an_enterprise_password_is_bounded_by_mschapv2_not_by_psk() {
        assert!(validate(&enterprise(&"a".repeat(64))).is_ok());
        assert!(validate(&enterprise(&"a".repeat(EAP_PASSWORD_MAX_LEN))).is_ok());
        let err = validate(&enterprise(&"a".repeat(EAP_PASSWORD_MAX_LEN + 1))).unwrap_err();
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
                matches!(validate(&enterprise(p)), Err(FormError::BadPassphrase(_))),
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
                    validate(&form("486f6d65", "", p)),
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
        let err = validate(&enterprise("")).unwrap_err();
        match err {
            FormError::BadPassphrase(m) => assert!(m.contains("password"), "unhelpful: {m}"),
            other => panic!("expected a passphrase error, got {other:?}"),
        }
    }

    #[test]
    fn the_passphrase_does_not_leak_through_the_request_debug() {
        let r = validate(&form("486f6d65", "", "sup3rsecret")).unwrap();
        assert!(!format!("{r:?}").contains("sup3rsecret"));
    }
}
