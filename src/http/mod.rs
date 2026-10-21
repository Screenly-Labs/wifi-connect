//! The portal's HTTP server.
//!
//! The ordering constraint that shapes this whole module: the radio cannot
//! be an access point and a station at the same time, so the moment we start
//! a join the user's phone loses the network. Any response we have not
//! already flushed dies with it.
//!
//! So `POST /connect` validates synchronously, answers **immediately** with
//! a page that explains what is about to happen, and only then hands the
//! credentials to the state machine. Responding after the join would show
//! the user a spinner that never resolves — even when the join succeeded.

pub mod api;
pub mod assets;
pub mod captive;

use axum::Router;
use axum::routing::{get, post};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::state::Shared;

/// Build the portal's router.
pub fn router(shared: Shared) -> Router {
    let mut app = Router::new()
        .route("/", get(api::index))
        .route("/connect", post(api::connect))
        .route("/connecting", get(api::connecting))
        .route("/api/networks", get(api::networks))
        .route("/api/status", get(api::status))
        .route("/api/captive-portal", get(api::captive_portal_api))
        .route("/brand.css", get(api::brand_css))
        .route("/assets/{*path}", get(assets::serve));

    // OS probe endpoints. Registered explicitly so they are covered by
    // tests, but the fallback below is what actually catches the probe URLs
    // we have never heard of.
    for path in captive::REDIRECT_PROBE_PATHS {
        app = app.route(path, get(api::probe_redirect).head(api::probe_redirect));
    }
    for path in captive::HTML_PROBE_PATHS {
        app = app.route(path, get(api::probe_html));
    }

    app.fallback(api::probe_redirect).with_state(shared)
}

/// Serve the portal on `addr` until `cancel` fires.
pub async fn serve(
    addr: std::net::SocketAddr,
    shared: Shared,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let listener = crate::sockets::bind_tcp_retrying(addr).await?;
    debug!(%addr, "portal listening");

    let result = axum::serve(listener, router(shared))
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await;

    if let Err(e) = &result {
        warn!(error = %e, "portal server stopped with an error");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Branding;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        let (shared, _rx) =
            Shared::new("http://192.168.42.1/".into(), Branding::new("WiFi Connect"));
        router(shared)
    }

    async fn get_path(path: &str) -> axum::response::Response {
        app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn get_path_branded(path: &str) -> axum::response::Response {
        let (shared, _rx) = Shared::new(
            "http://192.168.42.1/".into(),
            Branding {
                css: Some(std::sync::Arc::from(":root{--color-accent:#ffe11a}")),
                ..Branding::new("WiFi Connect")
            },
        );
        router(shared)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn brand_css_serves_the_configured_stylesheet() {
        let resp = get_path_branded("/brand.css").await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css; charset=utf-8"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b":root{--color-accent:#ffe11a}");
    }

    /// Not a 404, and not the catch-all redirect: the fallback turns every
    /// unknown path into a probe redirect, so a missing route here would
    /// hand the browser an HTML page with a text/css expectation.
    #[tokio::test]
    async fn brand_css_is_empty_but_present_when_unconfigured() {
        let resp = get_path("/brand.css").await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    /// The single most important assertion in the HTTP layer. A 204 here
    /// tells Android the internet works and the sign-in notification never
    /// appears — a silent failure with nothing in any log to explain it.
    #[tokio::test]
    async fn android_probes_redirect_and_never_return_204() {
        for path in ["/generate_204", "/gen_204"] {
            let resp = get_path(path).await;
            assert_ne!(
                resp.status(),
                StatusCode::NO_CONTENT,
                "{path} returned 204; the portal would never open"
            );
            assert!(
                resp.status().is_redirection(),
                "{path} returned {}",
                resp.status()
            );
        }
    }

    #[tokio::test]
    async fn microsoft_probes_never_return_the_magic_strings() {
        for path in ["/connecttest.txt", "/ncsi.txt"] {
            let resp = get_path(path).await;
            assert!(resp.status().is_redirection(), "{path}");

            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let text = String::from_utf8_lossy(&body);
            assert!(!text.contains("Microsoft Connect Test"), "{path}");
            assert!(!text.contains("Microsoft NCSI"), "{path}");
        }
    }

    /// Apple's agent string-matches its own success page. Anything else
    /// opens the Captive Network Assistant.
    #[tokio::test]
    async fn apple_probe_returns_html_that_is_not_the_success_page() {
        let resp = get_path("/hotspot-detect.html").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("<BODY>Success</BODY>"),
            "Apple would treat this network as already open"
        );
    }

    /// Our DNS answers every name, so probes arrive with someone else's
    /// Host header. Routing on Host would 404 all of them.
    #[tokio::test]
    async fn an_unknown_path_with_a_foreign_host_still_redirects() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/some/unknown/probe")
                    .header(header::HOST, "connectivitycheck.gstatic.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(resp.status().is_redirection());
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "http://192.168.42.1/"
        );
    }

    /// POST /connect with an empty form: if the provenance check lets it
    /// through it is rejected by validation with a 400, which proves the
    /// request got past the check without ever reaching the radio.
    async fn post_connect(extra: &[(&str, &str)]) -> axum::response::Response {
        let mut req = Request::builder()
            .method("POST")
            .uri("/connect")
            .header(header::HOST, "192.168.42.1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        app()
            .oneshot(req.body(Body::from("ssid_hex=&ssid=")).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_same_origin_connect_reaches_validation() {
        let resp = post_connect(&[
            ("origin", "http://192.168.42.1"),
            ("sec-fetch-site", "same-origin"),
        ])
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// The heart of the fix: a page on the open internet, loaded over
    /// cellular, must not be able to make the device change networks.
    #[tokio::test]
    async fn a_cross_origin_connect_is_forbidden() {
        let resp = post_connect(&[("origin", "http://evil.example")]).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .map(|v| v.to_str().unwrap()),
            Some("no-store")
        );
        // The portal page, so a confused human still has a way forward.
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("action=\"/connect\""), "not the portal page");
        assert!(text.contains("did not come from this setup page"));
    }

    #[tokio::test]
    async fn a_null_origin_connect_is_forbidden() {
        let resp = post_connect(&[("origin", "null")]).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_cross_site_fetch_metadata_connect_is_forbidden() {
        let resp = post_connect(&[("sec-fetch-site", "cross-site")]).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_connect_with_only_a_matching_referer_reaches_validation() {
        let resp = post_connect(&[("referer", "http://192.168.42.1/")]).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_connect_with_only_a_foreign_referer_is_forbidden() {
        let resp = post_connect(&[("referer", "http://evil.example/page")]).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_connect_without_provenance_headers_reaches_validation() {
        let resp = post_connect(&[]).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// iOS end to end: the CNA's probe under Apple's host name gets the
    /// portal page in place, and the form on it posts back to that host.
    /// Both halves must work, or iPhones cannot be set up.
    #[tokio::test]
    async fn the_apple_probe_page_can_submit_back_to_its_own_host() {
        let probe = app()
            .oneshot(
                Request::builder()
                    .uri("/hotspot-detect.html")
                    .header(header::HOST, "captive.apple.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK);

        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connect")
                    .header(header::HOST, "captive.apple.com")
                    .header(header::ORIGIN, "http://captive.apple.com")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("ssid_hex=&ssid="))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// The page is only served in place where its form can be submitted.
    /// GNOME's portal helper fetches `/` under
    /// `connectivity-check.ubuntu.com`; serving the form there would post
    /// back to a host `POST /connect` refuses, so it must be redirected.
    #[tokio::test]
    async fn the_page_is_redirected_to_the_portal_under_a_foreign_host() {
        for (path, host) in [
            ("/", "connectivity-check.ubuntu.com"),
            ("/", "neverssl.com"),
            ("/library/test/success.html", "www.appleiphonecell.com"),
        ] {
            let resp = app()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::HOST, host)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(resp.status().is_redirection(), "{host}{path}");
            assert_eq!(
                resp.headers().get(header::LOCATION).unwrap(),
                "http://192.168.42.1/"
            );
        }

        for (path, host) in [
            ("/", "192.168.42.1"),
            ("/hotspot-detect.html", "captive.apple.com"),
            ("/library/test/success.html", "www.apple.com"),
        ] {
            let resp = app()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::HOST, host)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{host}{path}");
        }
    }

    /// DNS rebinding end to end: the attacker's own name, now resolving to
    /// the gateway, posting same-origin. Refused.
    #[tokio::test]
    async fn a_rebound_attacker_host_cannot_connect() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connect")
                    .header(header::HOST, "rebind.evil.example")
                    .header(header::ORIGIN, "http://rebind.evil.example")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("ssid_hex=&ssid="))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// The check is for state-changing requests only. Probes arrive with
    /// foreign Host headers and an Origin is meaningless on them; none of
    /// that may change how they are routed.
    #[tokio::test]
    async fn get_probes_with_a_foreign_host_and_origin_are_unaffected() {
        for path in ["/generate_204", "/connecttest.txt", "/some/unknown/probe"] {
            let resp = app()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::HOST, "connectivitycheck.gstatic.com")
                        .header(header::ORIGIN, "http://evil.example")
                        .header("sec-fetch-site", "cross-site")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(resp.status().is_redirection(), "{path}: {}", resp.status());
        }

        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/hotspot-detect.html")
                    .header(header::HOST, "captive.apple.com")
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_captive_portal_api_is_served_with_the_rfc_media_type() {
        let resp = get_path("/api/captive-portal").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/captive+json"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["captive"], true);
        assert_eq!(json["user-portal-url"], "http://192.168.42.1/");
    }

    #[tokio::test]
    async fn the_index_is_served_and_is_not_redirected() {
        let resp = get_path("/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
    }

    /// Assets must be served, not swallowed by the catch-all redirect.
    #[tokio::test]
    async fn a_missing_asset_404s_rather_than_redirecting() {
        let resp = get_path("/assets/definitely-not-here.js").await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "assets must not fall through to the portal redirect"
        );
    }

    #[tokio::test]
    async fn status_reports_the_portal_state() {
        let resp = get_path("/api/status").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["state"], "portal");
    }

    #[tokio::test]
    async fn networks_is_json_and_empty_before_a_scan() {
        let resp = get_path("/api/networks").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn every_portal_response_forbids_caching() {
        // A mini-browser that caches the portal shows a stale page after the
        // AP bounces, which looks exactly like a hang.
        for path in ["/", "/api/status", "/api/captive-portal"] {
            let resp = get_path(path).await;
            assert_eq!(
                resp.headers()
                    .get(header::CACHE_CONTROL)
                    .map(|v| v.to_str().unwrap()),
                Some("no-store"),
                "{path} is cacheable"
            );
        }
    }
}
