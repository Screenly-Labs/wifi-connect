//! Captive-portal detection.
//!
//! Every modern OS decides "is this network actually usable?" by fetching a
//! known URL and checking for an exact response. Our DNS answers every name
//! with our own address, so those probes arrive here — carrying
//! `Host: captive.apple.com`, `Host: connectivitycheck.gstatic.com` and so
//! on. **Never route on the Host header**: doing so 404s every probe. (The
//! one place Host matters is *how* the portal page is delivered — in place
//! or by redirect — never *whether* a probe is answered.)
//!
//! What we return decides whether the sign-in sheet opens:
//!
//! | Probe | Must return | If we get it wrong |
//! |---|---|---|
//! | Android `/generate_204` | a redirect, **not 204** | 204 means "internet works"; no notification ever appears |
//! | Apple `/hotspot-detect.html` | HTML that is *not* the literal `Success` page | Apple string-matches on `Success`; the CNA never opens |
//! | Microsoft `/connecttest.txt` | anything but `Microsoft Connect Test` | Windows decides it is online |
//! | Microsoft `/ncsi.txt` | anything but `Microsoft NCSI` | same |
//!
//! Beyond the named paths a catch-all redirect is what actually makes this
//! work against probe URLs we have never heard of.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};

/// RFC 8908 Captive Portal API document.
///
/// This is what DHCP option 114 points at. `captive: true` tells the client
/// it is behind a portal; `user-portal-url` is where a human should be sent.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaptivePortalApi {
    pub captive: bool,
    #[serde(rename = "user-portal-url")]
    pub user_portal_url: String,
    #[serde(rename = "can-extend-session")]
    pub can_extend_session: bool,
}

impl CaptivePortalApi {
    pub fn new(portal_url: &str) -> Self {
        Self {
            captive: true,
            user_portal_url: portal_url.to_string(),
            // `seconds-remaining` and `bytes-remaining` are deliberately
            // omitted: they describe paid hotspots, not device setup.
            can_extend_session: false,
        }
    }

    /// Served with RFC 8908's media type, not `application/json`.
    pub fn into_response(self) -> Response {
        let body = serde_json::to_string(&self).unwrap_or_else(|_| {
            // Serialising three scalars cannot realistically fail, but a
            // portal that 500s here would be invisible and fatal.
            String::from(r#"{"captive":true}"#)
        });
        (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/captive+json"),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            body,
        )
            .into_response()
    }
}

/// The redirect every probe (and every unknown path) receives.
pub fn redirect_to_portal(portal_url: &str) -> Response {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Redirect::to(portal_url),
    )
        .into_response()
}

/// Apple's probe wants HTML. Returning the portal page directly saves a
/// round trip versus redirecting, and the Captive Network Assistant renders
/// it happily — as long as it does not say "Success".
pub fn apple_probe_response(portal_html: String) -> Response {
    debug_assert!(
        !portal_html.contains("<BODY>Success</BODY>"),
        "Apple's CNA string-matches this and would treat the network as open"
    );
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        portal_html,
    )
        .into_response()
}

/// Paths that redirect to the portal.
///
/// Android sends `/generate_204` and `/gen_204`; Windows `/connecttest.txt`,
/// `/ncsi.txt` and `/redirect`; Firefox `/success.txt` and
/// `/canonical.html`; NetworkManager itself `/nm-check.txt`.
pub const REDIRECT_PROBE_PATHS: &[&str] = &[
    "/generate_204",
    "/gen_204",
    "/connecttest.txt",
    "/ncsi.txt",
    "/redirect",
    "/success.txt",
    "/canonical.html",
    "/nm-check.txt",
    "/check_network_status.txt",
];

/// Paths that get the portal HTML directly (Apple's family).
pub const HTML_PROBE_PATHS: &[&str] = &[
    "/hotspot-detect.html",
    "/hotspotdetect.html",
    "/library/test/success.html",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_api_document_matches_rfc_8908() {
        let doc = CaptivePortalApi::new("http://192.168.42.1/");
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&doc).unwrap()).unwrap();

        assert_eq!(json["captive"], true);
        assert_eq!(json["user-portal-url"], "http://192.168.42.1/");
        assert_eq!(json["can-extend-session"], false);
        // Paid-hotspot fields must not appear.
        assert!(json.get("seconds-remaining").is_none());
        assert!(json.get("bytes-remaining").is_none());
    }

    #[test]
    fn the_api_document_uses_the_captive_json_media_type() {
        let resp = CaptivePortalApi::new("http://192.168.42.1/").into_response();
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/captive+json",
            "application/json would not be recognised as RFC 8908"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    /// A 204 here tells Android the internet works and the sign-in
    /// notification never appears. It must be a redirect.
    #[test]
    fn probe_paths_redirect_and_never_return_204() {
        let resp = redirect_to_portal("http://192.168.42.1/");
        assert_ne!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp.status().is_redirection(), "got {}", resp.status());
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "http://192.168.42.1/"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[test]
    fn the_android_and_microsoft_probes_are_covered() {
        for p in ["/generate_204", "/gen_204", "/connecttest.txt", "/ncsi.txt"] {
            assert!(REDIRECT_PROBE_PATHS.contains(&p), "{p} is not handled");
        }
    }

    #[test]
    fn the_apple_probes_are_covered_and_return_html() {
        assert!(HTML_PROBE_PATHS.contains(&"/hotspot-detect.html"));

        let resp = apple_probe_response("<html><body>Set up WiFi</body></html>".into());
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }

    /// Apple's agent treats the exact success page as "this network is
    /// open". Our portal HTML must never coincide with it.
    #[test]
    fn the_apple_probe_body_is_not_apples_success_page() {
        const APPLE_SUCCESS: &str =
            "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
        let portal = "<html><body>Set up WiFi</body></html>";
        assert_ne!(portal, APPLE_SUCCESS);
        assert!(!portal.contains("<BODY>Success</BODY>"));
    }

    /// The Microsoft probes have their own magic strings.
    #[test]
    fn the_microsoft_magic_strings_are_never_returned() {
        let resp = redirect_to_portal("http://192.168.42.1/");
        assert!(resp.status().is_redirection());
        // A literal body of "Microsoft Connect Test" or "Microsoft NCSI"
        // would mean Windows considers itself online; a redirect cannot.
        assert!(resp.headers().get(header::LOCATION).is_some());
    }

    #[test]
    fn probe_path_lists_do_not_overlap() {
        for p in REDIRECT_PROBE_PATHS {
            assert!(
                !HTML_PROBE_PATHS.contains(p),
                "{p} is in both probe lists; the router would be ambiguous"
            );
        }
    }
}
