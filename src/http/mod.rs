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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, header};
use axum::response::Response;
use axum::routing::{get, post};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
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
        .route("/brand-logo", get(api::brand_logo))
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

    app.fallback(api::probe_redirect)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY))
        .layer(axum::middleware::map_response_with_state(
            shared.clone(),
            security_headers,
        ))
        .with_state(shared)
}

/// Headers every portal response carries, whatever route produced it.
///
/// A layer rather than per-handler calls so that a route added later, the
/// fallback, and axum's own 404/405 responses cannot miss them.
///
/// They go on every response, not only HTML: `/assets/` serves the raw
/// templates as text/html and `/brand-logo` may be an SVG, which is a
/// document that can carry script; on JSON, CSS and redirects they are
/// inert. The page is reached over the setup access point, but the phone
/// may still have a cellular connection, so a page from the internet could
/// otherwise frame the password form and dress it up as something else.
///
/// The page policy depends on where the pages came from: the embedded UI's
/// hashes are compiled in, a `--ui-directory` computed its own at startup.
async fn security_headers(State(shared): State<Shared>, mut resp: Response) -> Response {
    let is_svg = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("image/svg+xml"));
    let csp = if is_svg {
        HeaderValue::from_static(assets::SVG_CONTENT_SECURITY_POLICY)
    } else {
        match &shared.branding.ui {
            Some(ui) => ui.content_security_policy(),
            None => assets::content_security_policy(),
        }
    };
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    // frame-ancestors supersedes this where it is understood; the header is
    // for the captive-portal webviews old enough not to.
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Nothing off the portal learns where the user came from, but our own
    // requests keep their provenance. NOT `no-referrer`: under that policy
    // a browser sends `Origin: null` on the form's POST (Fetch, "append a
    // request `Origin` header") and drops `Referer`, which is exactly the
    // evidence a cross-site-POST check on /connect relies on. `same-origin`
    // sends both, unchanged, to ourselves and nothing to anyone else.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    resp
}

/// Serve the portal on `addr`, pinned to `interface`, until `cancel` fires.
///
/// The pin is what keeps the unauthenticated `POST /connect` off every other
/// interface on the device; see [`crate::sockets`] for why the address alone
/// does not.
pub async fn serve(
    interface: &str,
    addr: std::net::SocketAddr,
    shared: Shared,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let listener = crate::sockets::bind_tcp_retrying(interface, addr).await?;
    debug!(%interface, %addr, "portal listening");

    serve_on(listener, router(shared), Limits::PORTAL, cancel).await;
    Ok(())
}

/// The bounds that keep one client from holding the portal hostage.
///
/// Anyone who can associate with the access point can open TCP connections
/// to us, and the passphrase on the AP is printed on a screen. `axum::serve`
/// sets no hyper timer, so it has no header-read timeout and no connection
/// cap: a client that opens connections and never finishes a request keeps
/// each one — and its file descriptor — forever. A few hundred of those
/// exhaust the default 1024-descriptor limit, and the real user's phone
/// then cannot load the page at all.
///
/// None of this stops a determined client on the AP from competing for the
/// connection slots; it turns "held forever" into "held for seconds", and
/// keeps descriptors well short of the limit so DHCP and DNS keep working.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// From the moment we start waiting for a request head until the whole
    /// head has arrived. A deadline, not an idle timer: trickling one byte
    /// at a time does not extend it. It also applies between requests on a
    /// kept-alive connection, which closes idle browser connections too.
    header_read_timeout: Duration,
    /// Total life of one connection. Covers what the header timeout cannot:
    /// a request head followed by a body that never arrives, or a client
    /// that stops reading our response. At the deadline the connection is
    /// asked to finish what it is doing and close, then dropped after
    /// `drain_grace`.
    max_connection_age: Duration,
    /// Connections served at once. Beyond this we stop accepting; the kernel
    /// backlog holds new connections until a slot frees, rather than us
    /// spending a descriptor on each.
    max_connections: usize,
    /// Connections served at once for any one client address. We are the
    /// DHCP server on this network and nothing NATs in front of us, so an
    /// address is a device. Without this, one device that opens
    /// `max_connections` slow requests and renews each as it expires keeps
    /// every other phone in the kernel backlog for as long as it likes.
    max_connections_per_client: usize,
    /// How long a connection gets to finish once asked to close, either at
    /// `max_connection_age` or on shutdown. Bounds how long a stalled client
    /// can delay the access point coming down.
    drain_grace: Duration,
}

impl Limits {
    /// A phone's captive-portal browser opens a handful of connections
    /// (page, assets, status polling, OS probes); 64 is plenty for that and
    /// for a second device, and leaves the descriptor limit far away. Ten
    /// seconds for a request head is generous on a link a few metres long.
    /// A browser opens at most six connections to one host; sixteen per
    /// device leaves room for the OS's own probes beside it.
    const PORTAL: Self = Self {
        header_read_timeout: Duration::from_secs(10),
        max_connection_age: Duration::from_secs(60),
        max_connections: 64,
        max_connections_per_client: 16,
        drain_grace: Duration::from_secs(5),
    };
}

/// The form is an SSID, an identity and a passphrase: a few hundred bytes.
/// axum's default limit is 2 MB, which only helps someone trying to make a
/// small board buffer things.
const MAX_REQUEST_BODY: usize = 16 * 1024;

/// hyper's per-connection read buffer, and so the largest request head it
/// will hold before answering 431. Its default is about 400 KiB, which at
/// `max_connections` is 26 MB of a small board's memory for heads alone.
/// A phone's request head is well under 2 KiB.
const MAX_CONNECTION_BUFFER: usize = 32 * 1024;

/// Open connections per client address. A slot is taken after `accept`,
/// once the address is known, and given back when the connection's task
/// ends, however it ends.
#[derive(Debug, Default)]
struct PerClient(Mutex<HashMap<IpAddr, usize>>);

/// One client's claim on a connection; dropping it gives the slot back.
struct ClientSlot {
    clients: Arc<PerClient>,
    ip: IpAddr,
}

impl PerClient {
    fn take(self: &Arc<Self>, ip: IpAddr, limit: usize) -> Option<ClientSlot> {
        let mut open = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let n = open.entry(ip).or_insert(0);
        if *n >= limit {
            return None;
        }
        *n += 1;
        Some(ClientSlot {
            clients: Arc::clone(self),
            ip,
        })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut open = self.clients.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = open.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                // Phones come and go; do not keep an entry per address ever seen.
                open.remove(&self.ip);
            }
        }
    }
}

/// Accept and serve connections on `listener` until `cancel` fires, then
/// stop accepting and give open connections `drain_grace` to finish.
///
/// Drives hyper's HTTP/1 connection directly instead of `axum::serve`,
/// because that is the only way to give hyper a timer, and without a timer
/// hyper silently ignores its header-read timeout.
async fn serve_on(listener: TcpListener, app: Router, limits: Limits, cancel: CancellationToken) {
    // Each connection holds a permit until its task ends. That is both the
    // cap and, on shutdown, the way to wait for every connection: take all
    // the permits back.
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let clients = Arc::new(PerClient::default());

    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .max_buf_size(MAX_CONNECTION_BUFFER);

    loop {
        // Take the slot before accepting, so at the cap the connection
        // waits in the kernel backlog instead of costing us a descriptor.
        let permit = tokio::select! {
            _ = cancel.cancelled() => break,
            p = slots.clone().acquire_owned() => p.expect("the semaphore is never closed"),
        };
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // A client that gave up while queued: its problem, not
                // ours, and no reason to pause accepting everyone else.
                Err(e) if is_connection_error(&e) => {
                    debug!(error = %e, "portal accept: client went away");
                    continue;
                }
                Err(e) => {
                    // EMFILE and friends: the next accept fails the same
                    // way at once, so back off rather than spin the one
                    // thread this program has.
                    warn!(error = %e, "portal accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Some(client_slot) = clients.take(peer.ip(), limits.max_connections_per_client) else {
            // Closing at once, rather than leaving it in the backlog, is
            // what keeps this device's surplus from queueing ahead of
            // everyone else's. The global permit goes back with it.
            debug!(client = %peer.ip(), "portal connection refused: client at its limit");
            continue;
        };

        let conn =
            http.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app.clone()));
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _client_slot = client_slot;
            let mut conn = std::pin::pin!(conn);
            let finished = tokio::select! {
                r = conn.as_mut() => Some(r),
                _ = tokio::time::sleep(limits.max_connection_age) => None,
                _ = cancel.cancelled() => None,
            };
            let result = match finished {
                Some(r) => r,
                None => {
                    // Let an in-flight response complete (the answer to
                    // POST /connect must reach the phone), then close.
                    conn.as_mut().graceful_shutdown();
                    match tokio::time::timeout(limits.drain_grace, conn).await {
                        Ok(r) => r,
                        Err(_) => {
                            debug!("portal connection did not drain in time; dropped");
                            return;
                        }
                    }
                }
            };
            if let Err(e) = result {
                // Header timeouts land here; routine, not a server fault.
                debug!(error = %e, "portal connection ended with an error");
            }
        });
    }

    // Stop accepting before waiting, so nothing new starts during drain.
    drop(listener);
    let _ = slots.acquire_many(limits.max_connections as u32).await;
}

/// Errors `accept()` reports about one queued connection rather than about
/// the listener. The same set `axum::serve` skips without backing off.
fn is_connection_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset};
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionRefused | ConnectionReset
    )
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

    #[tokio::test]
    async fn the_logo_route_serves_the_bytes_with_its_own_content_type() {
        let (shared, _rx) = Shared::new(
            "http://192.168.42.1/".into(),
            Branding {
                logo: Some(crate::state::BrandLogo {
                    bytes: std::sync::Arc::from(
                        &b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"[..],
                    ),
                    content_type: "image/svg+xml",
                }),
                ..Branding::new("Anthias")
            },
        );
        let resp = router(shared)
            .oneshot(
                Request::builder()
                    .uri("/brand-logo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"<svg"));
    }

    /// 404, not the empty 200 that `/brand.css` returns: the page only
    /// references the logo when one is set, so a request without one is a
    /// stale cache or a prober, and an empty body would render as a broken
    /// image rather than falling back to the alt text.
    #[tokio::test]
    async fn the_logo_route_is_404_when_no_logo_is_configured() {
        let resp = get_path("/brand-logo").await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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

    /// Under `Referrer-Policy: no-referrer` browsers send `Origin: null` on
    /// a form POST even to the page's own origin, which the check rejects,
    /// so every page that can carry the form, the 403 page included, must
    /// pin a policy that keeps the real Origin.
    #[tokio::test]
    async fn every_page_that_can_post_the_form_keeps_the_origin_header() {
        let policy = |resp: &axum::response::Response| {
            resp.headers()
                .get(header::REFERRER_POLICY)
                .map(|v| v.to_str().unwrap().to_owned())
        };
        for path in ["/", "/hotspot-detect.html", "/generate_204", "/connecting"] {
            let resp = get_path(path).await;
            assert_eq!(policy(&resp).as_deref(), Some("same-origin"), "{path}");
        }
        let forbidden = post_connect(&[("origin", "http://evil.example")]).await;
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(policy(&forbidden).as_deref(), Some("same-origin"));
        let invalid = post_connect(&[("origin", "http://192.168.42.1")]).await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(policy(&invalid).as_deref(), Some("same-origin"));
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

    /// The form is a few hundred bytes; anything near axum's 2 MB default
    /// is not a form submission.
    #[tokio::test]
    async fn an_oversized_form_is_refused_before_it_is_buffered() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connect")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "ssid=x&passphrase={}",
                        "a".repeat(MAX_REQUEST_BODY)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // The tests below run the real accept loop on a loopback socket, with
    // the limits shrunk to fractions of a second so they finish quickly.
    // Real time rather than paused time: hyper's timer and the kernel's
    // sockets have to agree on what "now" is.

    use std::net::SocketAddr;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Long enough that a test which expects it never to fire cannot be
    /// rescued by it.
    const NEVER: Duration = Duration::from_secs(30);

    /// Upper bound on waiting for something that should happen in a fraction
    /// of a second, so a regression fails the test instead of hanging it.
    const PATIENCE: Duration = Duration::from_secs(5);

    struct Running {
        addr: SocketAddr,
        cancel: CancellationToken,
        server: tokio::task::JoinHandle<()>,
    }

    async fn start(limits: Limits) -> Running {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_on(listener, app(), limits, cancel.clone()));
        Running {
            addr,
            cancel,
            server,
        }
    }

    /// Read until the server closes the connection. Panics if it does not
    /// within `PATIENCE`.
    async fn read_until_closed(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        tokio::time::timeout(PATIENCE, stream.read_to_end(&mut out))
            .await
            .expect("the server never closed the connection")
            .ok();
        out
    }

    const STATUS_REQUEST: &[u8] =
        b"GET /api/status HTTP/1.1\r\nHost: 192.168.42.1\r\nConnection: close\r\n\r\n";

    #[tokio::test]
    async fn the_accept_loop_serves_an_ordinary_request() {
        let server = start(Limits::PORTAL).await;

        let mut client = TcpStream::connect(server.addr).await.unwrap();
        client.write_all(STATUS_REQUEST).await.unwrap();
        let response = read_until_closed(&mut client).await;

        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    /// The slowloris case: connect and say nothing. Before this fix the
    /// connection, and its descriptor, lived until the client gave up.
    #[tokio::test]
    async fn a_connection_that_never_sends_a_request_is_closed_after_the_header_timeout() {
        let server = start(Limits {
            header_read_timeout: Duration::from_millis(200),
            max_connection_age: NEVER,
            ..Limits::PORTAL
        })
        .await;

        let started = Instant::now();
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        read_until_closed(&mut client).await;

        assert!(
            started.elapsed() >= Duration::from_millis(150),
            "closed after {:?}, before the timeout could have fired",
            started.elapsed()
        );
    }

    /// The timeout is a deadline for the whole head, not an idle timer: a
    /// client sending one byte every 50 ms must not keep it alive.
    ///
    /// The bytes go into one header value rather than a header line each:
    /// hyper refuses a head with more than 100 headers, which would close a
    /// line-per-tick connection after ~5 s with no timeout at all, right at
    /// `PATIENCE`. A byte per tick never reaches hyper's buffer limit, so
    /// with an idle timer instead of a deadline the connection outlives
    /// `PATIENCE` and the test fails. No tight bound on elapsed time is
    /// needed, which keeps this stable under qemu on CI.
    #[tokio::test]
    async fn trickling_a_header_does_not_extend_the_header_deadline() {
        let server = start(Limits {
            header_read_timeout: Duration::from_millis(300),
            max_connection_age: NEVER,
            ..Limits::PORTAL
        })
        .await;

        let client = TcpStream::connect(server.addr).await.unwrap();
        let (mut rx, mut tx) = client.into_split();
        let trickle = tokio::spawn(async move {
            tx.write_all(b"GET / HTTP/1.1\r\nX-Slow: ").await?;
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                tx.write_all(b"a").await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });

        let mut out = Vec::new();
        tokio::time::timeout(PATIENCE, rx.read_to_end(&mut out))
            .await
            .expect("a trickling client kept the connection open")
            .ok();
        trickle.abort();

        assert!(
            out.is_empty(),
            "a timed-out head got a response: {}",
            String::from_utf8_lossy(&out)
        );
    }

    /// A captive mini-browser keeps connections alive after each response
    /// and may never reuse them. Each holds a slot, so an idle kept-alive
    /// connection must be closed by the header timeout too, or one phone's
    /// ordinary browsing and OS probes could fill the cap.
    #[tokio::test]
    async fn an_idle_kept_alive_connection_is_closed_after_the_header_timeout() {
        let server = start(Limits {
            header_read_timeout: Duration::from_millis(200),
            max_connection_age: NEVER,
            ..Limits::PORTAL
        })
        .await;

        let mut client = TcpStream::connect(server.addr).await.unwrap();
        client
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: 192.168.42.1\r\n\r\n")
            .await
            .unwrap();
        let response = read_until_closed(&mut client).await;

        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("connection: close"),
            "the server opted out of keep-alive, so this tests nothing: {text}"
        );
    }

    /// The flow the module docs are about, through the real accept loop:
    /// shutdown starts the moment the join request reaches the state
    /// machine, as the access point coming down would. The 202 page must
    /// still arrive whole.
    #[tokio::test]
    async fn the_connect_answer_arrives_whole_even_if_shutdown_starts_at_once() {
        let (shared, mut joins) =
            Shared::new("http://192.168.42.1/".into(), Branding::new("WiFi Connect"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_on(
            listener,
            router(shared),
            Limits::PORTAL,
            cancel.clone(),
        ));
        let state_machine = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let request = joins.recv().await;
                cancel.cancel();
                request
            })
        };

        let body = "ssid=Home&passphrase=correct-horse";
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                format!(
                    "POST /connect HTTP/1.1\r\nHost: 192.168.42.1\r\n\
                     Content-Type: application/x-www-form-urlencoded\r\n\
                     Content-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_until_closed(&mut client).await;

        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 202"), "{text}");
        let (head, page) = text.split_once("\r\n\r\n").expect("no end of head");
        let length: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap())
            })
            .expect("no content-length");
        assert_eq!(page.len(), length, "the page was cut short");

        assert!(state_machine.await.unwrap().is_some());
        tokio::time::timeout(PATIENCE, server)
            .await
            .expect("shutdown hung")
            .unwrap();
    }

    /// The header timeout cannot see a client that sends a complete head
    /// and then never sends the body it promised; the connection age can.
    #[tokio::test]
    async fn a_body_that_never_arrives_is_dropped_at_the_connection_age() {
        let server = start(Limits {
            header_read_timeout: NEVER,
            max_connection_age: Duration::from_millis(200),
            drain_grace: Duration::from_millis(100),
            ..Limits::PORTAL
        })
        .await;

        let mut client = TcpStream::connect(server.addr).await.unwrap();
        client
            .write_all(
                b"POST /connect HTTP/1.1\r\nHost: 192.168.42.1\r\n\
                  Content-Type: application/x-www-form-urlencoded\r\n\
                  Content-Length: 100\r\n\r\nssid=",
            )
            .await
            .unwrap();

        read_until_closed(&mut client).await;
    }

    /// At the cap the server stops accepting; the next connection sits in
    /// the kernel backlog, costing us nothing, and is served as soon as a
    /// slot frees.
    #[tokio::test]
    async fn connections_beyond_the_cap_wait_until_a_slot_frees() {
        let server = start(Limits {
            header_read_timeout: NEVER,
            max_connection_age: NEVER,
            max_connections: 1,
            ..Limits::PORTAL
        })
        .await;

        // Connected first, so first in the accept queue: it takes the slot.
        let hog = TcpStream::connect(server.addr).await.unwrap();

        let mut waiting = TcpStream::connect(server.addr).await.unwrap();
        waiting.write_all(STATUS_REQUEST).await.unwrap();

        let mut buf = [0u8; 1];
        let early = tokio::time::timeout(Duration::from_millis(300), waiting.read(&mut buf)).await;
        assert!(
            early.is_err(),
            "a connection beyond the cap was served while the slot was held"
        );

        drop(hog);
        let response = read_until_closed(&mut waiting).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    /// One device must not be able to take every slot. Its surplus is
    /// closed at once, and the slot it held is given back when it hangs up.
    #[tokio::test]
    async fn one_client_cannot_take_more_than_its_share_of_slots() {
        let server = start(Limits {
            header_read_timeout: NEVER,
            max_connection_age: NEVER,
            max_connections_per_client: 1,
            ..Limits::PORTAL
        })
        .await;

        let hog = TcpStream::connect(server.addr).await.unwrap();

        // Refused, not queued: closed well before any limit could fire.
        let mut surplus = TcpStream::connect(server.addr).await.unwrap();
        read_until_closed(&mut surplus).await;

        // Once the hog hangs up its slot comes back. The server notices the
        // hang-up asynchronously, so give it a moment.
        drop(hog);
        let started = Instant::now();
        loop {
            let mut client = TcpStream::connect(server.addr).await.unwrap();
            let _ = client.write_all(STATUS_REQUEST).await;
            let response = read_until_closed(&mut client).await;
            if response.starts_with(b"HTTP/1.1 200") {
                break;
            }
            assert!(
                started.elapsed() < PATIENCE,
                "the client's slot was never given back"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// hyper would otherwise buffer about 400 KiB of request head per
    /// connection before giving up on it.
    #[tokio::test]
    async fn an_oversized_request_head_is_refused() {
        let server = start(Limits::PORTAL).await;

        let mut client = TcpStream::connect(server.addr).await.unwrap();
        let head = format!(
            "GET / HTTP/1.1\r\nHost: 192.168.42.1\r\nConnection: close\r\nX-Big: {}\r\n\r\n",
            // hyper checks the limit between reads, and one read can carry
            // it past by up to the buffer's size; exceed it by more.
            "a".repeat(4 * MAX_CONNECTION_BUFFER)
        );
        // The server may hang up before it has read all of this.
        let _ = client.write_all(head.as_bytes()).await;
        let response = read_until_closed(&mut client).await;

        assert!(
            response.starts_with(b"HTTP/1.1 431"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    /// Shutdown is what brings the access point down and lets the join
    /// start. A stalled client mid-request must not hold that up beyond
    /// the drain grace.
    #[tokio::test]
    async fn shutdown_is_not_held_up_by_a_stalled_client() {
        let server = start(Limits {
            header_read_timeout: NEVER,
            max_connection_age: NEVER,
            drain_grace: Duration::from_millis(200),
            ..Limits::PORTAL
        })
        .await;

        let mut stalled = TcpStream::connect(server.addr).await.unwrap();
        stalled.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        // Let the server accept it and start reading the head.
        tokio::time::sleep(Duration::from_millis(100)).await;

        server.cancel.cancel();
        tokio::time::timeout(PATIENCE, server.server)
            .await
            .expect("shutdown waited on a stalled client")
            .unwrap();

        read_until_closed(&mut stalled).await;
        assert!(
            TcpStream::connect(server.addr).await.is_err(),
            "the listener is still accepting after shutdown"
        );
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

    async fn get_path_with_ui(
        ui: &crate::http::assets::TestUiDir,
        path: &str,
    ) -> axum::response::Response {
        let (shared, _rx) = Shared::new(
            "http://192.168.42.1/".into(),
            Branding {
                ui: Some(std::sync::Arc::new(ui.load().unwrap())),
                ..Branding::new("WiFi Connect")
            },
        );
        router(shared)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_ui_directory_serves_the_index_and_its_assets() {
        let ui = crate::http::assets::TestUiDir::new();
        ui.write("img/logo.svg", "<svg/>");

        let resp = get_path_with_ui(&ui, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("OVERRIDE-INDEX"));

        let resp = get_path_with_ui(&ui, "/assets/img/logo.svg").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/svg+xml");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"<svg/>");
    }

    /// All-or-nothing: with a directory set, the embedded files are gone
    /// from /assets/ too, not quietly mixed in.
    #[tokio::test]
    async fn a_ui_directory_hides_the_embedded_assets() {
        assert_eq!(
            get_path("/assets/brand.example.css").await.status(),
            StatusCode::OK
        );
        let ui = crate::http::assets::TestUiDir::new();
        assert_eq!(
            get_path_with_ui(&ui, "/assets/brand.example.css")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    /// The wildcard is percent-decoded before it reaches the handler, so
    /// these arrive as `../`, absolute paths, a backslash and an embedded
    /// NUL. None of them may name a file outside the UI, whichever source
    /// is serving.
    #[tokio::test]
    async fn asset_paths_cannot_traverse_out_of_the_ui() {
        let ui = crate::http::assets::TestUiDir::new();
        // A real file next to the UI directory, so a traversal that
        // worked would have something to find.
        let outside_name = format!(
            "{}-outside.txt",
            ui.0.file_name().unwrap().to_string_lossy()
        );
        let outside = ui.0.parent().unwrap().join(&outside_name);
        std::fs::write(&outside, "outside").unwrap();

        let attempts = [
            format!("/assets/..%2f{outside_name}"),
            format!("/assets/%2e%2e%2f{outside_name}"),
            format!("/assets/img/..%2f..%2f{outside_name}"),
            format!(
                "/assets/{}",
                outside.display().to_string().replace('/', "%2f")
            ),
            "/assets/%2fetc%2fpasswd".to_owned(),
            "/assets/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd".to_owned(),
            "/assets/index.html%00.css".to_owned(),
            "/assets/..%5cindex.html".to_owned(),
        ];
        for path in &attempts {
            for resp in [get_path_with_ui(&ui, path).await, get_path(path).await] {
                assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path} was served");
            }
        }
        let _ = std::fs::remove_file(outside);
    }

    /// Every security header, on a response that came back from `resp`.
    fn assert_security_headers(resp: &axum::response::Response, what: &str) {
        let get = |name: header::HeaderName| {
            resp.headers()
                .get(&name)
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_else(|| panic!("{what}: no {name} header"))
        };
        assert_eq!(get(header::X_CONTENT_TYPE_OPTIONS), "nosniff", "{what}");
        assert_eq!(get(header::X_FRAME_OPTIONS), "DENY", "{what}");
        assert_eq!(get(header::REFERRER_POLICY), "same-origin", "{what}");

        let csp = get(header::CONTENT_SECURITY_POLICY);
        for directive in [
            "default-src 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'none'",
        ] {
            assert!(csp.contains(directive), "{what}: CSP lacks {directive}");
        }
        // The point of the hashes: inline script must never be allowed
        // wholesale, or the policy is no backstop for an escaping bug. The
        // 'unsafe-inline' kept for CSP 1.0 browsers is ignored by every
        // later one only because a hash sits beside it.
        assert!(
            csp.contains("script-src 'unsafe-inline' 'sha256-"),
            "{what}: {csp}"
        );
        assert!(
            csp.contains("style-src 'self' 'unsafe-inline' 'sha256-"),
            "{what}: {csp}"
        );
    }

    /// With `--ui-directory` every response carries that directory's
    /// policy: its own hashes, `'self'` for `<script src>`, and every
    /// other protection unchanged. An SVG under `/assets/` keeps the SVG
    /// policy.
    #[tokio::test]
    async fn a_ui_directory_gets_a_policy_for_its_own_pages() {
        let ui = crate::http::assets::TestUiDir::new();
        ui.write(
            "index.html",
            "<style>h1{color:red}</style>{{NETWORKS}}<script src=\"/assets/app.js\"></script>",
        );
        ui.write("app.js", "void 0");
        ui.write("img/logo.svg", "<svg/>");
        let style_hash = {
            use base64::Engine;
            use sha2::Digest;
            format!(
                "'sha256-{}'",
                base64::engine::general_purpose::STANDARD
                    .encode(sha2::Sha256::digest(b"h1{color:red}"))
            )
        };

        for path in ["/", "/connecting", "/assets/app.js", "/no/such/path"] {
            let resp = get_path_with_ui(&ui, path).await;
            let csp = resp.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .to_owned();
            assert!(csp.contains("script-src 'self';"), "{path}: {csp}");
            assert!(
                csp.contains(&format!("style-src 'self' 'unsafe-inline' {style_hash};")),
                "{path}: {csp}"
            );
            for directive in [
                "default-src 'none'",
                "frame-ancestors 'none'",
                "form-action 'self'",
                "base-uri 'none'",
            ] {
                assert!(csp.contains(directive), "{path}: CSP lacks {directive}");
            }
            assert_eq!(resp.headers()[header::X_FRAME_OPTIONS], "DENY");
            assert_eq!(resp.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        }

        let resp = get_path_with_ui(&ui, "/assets/img/logo.svg").await;
        assert_eq!(
            resp.headers()[header::CONTENT_SECURITY_POLICY],
            crate::http::assets::SVG_CONTENT_SECURITY_POLICY
        );
    }

    /// The built-in pages inline everything, so their policy keeps
    /// `'self'` out of script-src.
    #[tokio::test]
    async fn the_built_in_policy_does_not_allow_script_from_self() {
        let resp = get_path("/").await;
        let csp = resp.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        let script = csp
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("script-src "))
            .unwrap();
        assert!(!script.contains("'self'"), "{csp}");
    }

    /// An SVG logo gets its own policy: its inline styling survives, and
    /// nothing in it can run or be framed.
    #[tokio::test]
    async fn an_svg_logo_keeps_its_styles_but_cannot_run_script() {
        let (shared, _rx) = Shared::new(
            "http://192.168.42.1/".into(),
            Branding {
                logo: Some(crate::state::BrandLogo {
                    bytes: std::sync::Arc::from(&b"<svg/>"[..]),
                    content_type: "image/svg+xml",
                }),
                ..Branding::new("Anthias")
            },
        );
        let resp = router(shared)
            .oneshot(
                Request::builder()
                    .uri("/brand-logo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let csp = resp.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("style-src 'unsafe-inline'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(!csp.contains("script-src"), "{csp}");
        assert_eq!(resp.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(resp.headers()[header::X_FRAME_OPTIONS], "DENY");
    }

    #[tokio::test]
    async fn every_page_carries_the_security_headers() {
        // The pages a user sees, the probe that opens the sign-in sheet on
        // Apple devices, a redirecting probe, JSON, and the fallback.
        for path in [
            "/",
            "/connecting",
            "/hotspot-detect.html",
            "/generate_204",
            "/api/status",
            "/brand.css",
            "/assets/index.html",
            "/no/such/path",
        ] {
            let resp = get_path(path).await;
            assert_security_headers(&resp, path);
        }
    }

    /// The validation-error page is rendered by the POST handler, a
    /// different path from GET /, and is the one carrying the form back.
    #[tokio::test]
    async fn the_connect_error_page_carries_the_security_headers() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connect")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("ssid_hex=&ssid=&passphrase="))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_security_headers(&resp, "POST /connect (error)");
    }

    /// The layer adds headers; it must not take away the ones handlers set.
    #[tokio::test]
    async fn the_layer_keeps_the_handlers_own_headers() {
        let resp = get_path("/").await;
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
    }
}
