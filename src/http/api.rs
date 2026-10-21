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
    let css = shared.brand_css.as_deref().unwrap_or("");
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
    assets::render_index(
        &shared.brand_name,
        &shared.networks(),
        &shared.state(),
        shared.brand_css.is_some(),
    )
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
    no_store(
        Html(assets::render_connecting(
            &shared.brand_name,
            &ssid,
            shared.brand_css.is_some(),
        ))
        .into_response(),
    )
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
    /// Enterprise only: the domain the RADIUS server's certificate must
    /// belong to. Optional; see [`server_domain`].
    #[serde(default)]
    pub server_domain: String,
}

/// Why a submission was rejected before we touched the radio.
#[derive(Debug, PartialEq, Eq)]
pub enum FormError {
    NoNetwork,
    BadPassphrase(String),
    BadServerDomain,
}

impl FormError {
    fn message(&self) -> String {
        match self {
            FormError::NoNetwork => "Choose a network, or enter its name.".into(),
            FormError::BadPassphrase(m) => m.clone(),
            FormError::BadServerDomain => {
                "The server domain must be a host name such as radius.example.com.".into()
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

    let server_domain = server_domain(&form.server_domain)?;

    Ok(JoinRequest {
        ssid,
        identity,
        passphrase,
        server_domain,
        hidden,
    })
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
                        &shared.brand_name,
                        &shared.networks(),
                        &e.message(),
                        shared.brand_css.is_some(),
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
                Html(assets::render_connecting(
                    &shared.brand_name,
                    &ssid,
                    shared.brand_css.is_some(),
                )),
            )
                .into_response(),
        );
    }

    // Answer now, before the state machine tears the access point down.
    // Anything not already flushed dies with the client's connection.
    no_store(
        (
            StatusCode::ACCEPTED,
            Html(assets::render_connecting(
                &shared.brand_name,
                &ssid,
                shared.brand_css.is_some(),
            )),
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
            server_domain: String::new(),
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

    #[test]
    fn the_passphrase_does_not_leak_through_the_request_debug() {
        let r = validate(&form("486f6d65", "", "sup3rsecret")).unwrap();
        assert!(!format!("{r:?}").contains("sup3rsecret"));
    }

    #[test]
    fn a_server_domain_is_carried_normalised() {
        let mut f = form("486f6d65", "", "abcdefgh");
        f.identity = "alice@example.com".into();
        f.server_domain = "  Radius.Example.COM.  ".into();
        let r = validate(&f).unwrap();
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
        assert!(validate(&f).unwrap().server_domain.is_none());
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
        assert_eq!(validate(&f).unwrap_err(), FormError::BadServerDomain);
    }
}
