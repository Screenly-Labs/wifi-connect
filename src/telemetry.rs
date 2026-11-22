//! Crash and error reporting to Sentry.
//!
//! The portal runs on devices nobody is looking at: when it panics or
//! fails to raise the access point, the only witness is a journal on a box
//! that has just lost its network. Reporting the failure is how it reaches
//! anyone.
//!
//! On by default, off with `--no-sentry`. What is sent is deliberately
//! narrow:
//!
//! * panics, through the panic hook, which flushes before the process
//!   aborts (the release profile is `panic = "abort"`, so a destructor
//!   would never get the chance);
//! * `ERROR` log lines, as events;
//! * `WARN` log lines, as breadcrumbs attached to the next event.
//!
//! `INFO` and below are never sent. That is where `--log-passphrase` writes
//! the setup passphrase, and raising the log level to troubleshoot a radio
//! must not start shipping it off the device. No spans are sent either:
//! there is no tracing sample rate, and building transactions only to drop
//! them would be wasted work on a Pi Zero.
//!
//! The level filter is not enough on its own. NetworkManager can echo a
//! property value back inside an error string (see [`crate::secret`]), and
//! that string is logged at `ERROR` like any other failure. So every
//! passphrase this process hands to NetworkManager is registered with
//! [`redact`], and every event and breadcrumb is scrubbed of all of them
//! on its way out, in `before_send` and `before_breadcrumb`.

use std::borrow::Cow;
use std::sync::{Mutex, PoisonError};

use sentry::integrations::tracing::{BreadcrumbLayer, ErrorLayer};
use sentry::protocol::{Breadcrumb, Context, Event, Map, Value};
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::registry::LookupSpan;

use crate::cli::{Cli, DEFAULT_SENTRY_DSN};
use crate::secret::Secret;

/// What a redacted secret is replaced with.
const REDACTED: &str = "[redacted]";

/// Every secret seen so far in this process, longest first.
///
/// Kept for the life of the process rather than replaced: a breadcrumb
/// recorded early still rides along with a later event.
static SECRETS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Scrub `secret` from every report sent from now on.
///
/// Call it before the secret is handed to anything that could put it in
/// an error message.
pub fn redact(secret: &Secret) {
    let value = secret.expose();
    if value.is_empty() {
        return;
    }
    let mut secrets = SECRETS.lock().unwrap_or_else(PoisonError::into_inner);
    if !secrets.iter().any(|s| s == value) {
        secrets.push(value.to_owned());
        // Longest first, so a secret that contains another is replaced
        // whole rather than leaving its remainder behind.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    }
}

/// Bind the Sentry client for this process, unless it is turned off.
///
/// The returned guard flushes queued events when dropped, bounded by the
/// client's shutdown timeout. Keep it alive for the whole of `main`.
///
/// Call after [`Cli::validate`], which rejects a DSN that does not parse.
pub fn init(args: &Cli) -> Option<sentry::ClientInitGuard> {
    if !reports_to(&args.sentry_dsn, cfg!(debug_assertions)) {
        return None;
    }
    let dsn = args.sentry_dsn().ok().flatten()?;
    Some(sentry::init((
        dsn,
        sentry::ClientOptions::new()
            .maybe_release(sentry::release_name!())
            // Nothing here is an HTTP server integration, so this mostly
            // decides whether Sentry infers the client's address. A device
            // on a customer's network has no business sending that.
            .send_default_pii(false)
            .before_send(|event| Some(scrub_event(event)))
            .before_breadcrumb(|crumb| Some(scrub_breadcrumb(crumb))),
    )))
}

/// Should a build report to `dsn`?
///
/// A debug build is a developer's or a test rig's, never a device's: the
/// release images and the snap are built with `--release`. Sentry tags
/// such a build `environment=development`, but the events still land in
/// this project's issue list, where a deliberately broken bus address on
/// a CI box reads exactly like a fleet of devices that cannot reach
/// NetworkManager. So a debug build does not use the project's own DSN.
/// Passing one explicitly still works, for testing the reporting itself.
fn reports_to(dsn: &str, debug_build: bool) -> bool {
    !(debug_build && dsn == DEFAULT_SENTRY_DSN)
}

/// Run `f` with the registered secrets, unless there are none.
fn with_secrets<T>(value: T, f: impl FnOnce(T, &[String]) -> T) -> T {
    let secrets = SECRETS.lock().unwrap_or_else(PoisonError::into_inner);
    if secrets.is_empty() {
        value
    } else {
        f(value, &secrets)
    }
}

fn scrub_event(event: Event<'static>) -> Event<'static> {
    with_secrets(event, |mut event, secrets| {
        scrub_option(&mut event.message, secrets);
        if let Some(entry) = &mut event.logentry {
            scrub_string(&mut entry.message, secrets);
            entry
                .params
                .iter_mut()
                .for_each(|v| scrub_value(v, secrets));
        }
        for exception in event.exception.values.iter_mut() {
            scrub_option(&mut exception.value, secrets);
        }
        for value in event.tags.values_mut() {
            scrub_string(value, secrets);
        }
        scrub_map(&mut event.extra, secrets);
        for context in event.contexts.values_mut() {
            if let Context::Other(map) = context {
                scrub_map(map, secrets);
            }
        }
        // Already scrubbed as each was recorded, but a breadcrumb can
        // predate the secret it carries being registered.
        for crumb in event.breadcrumbs.values.iter_mut() {
            scrub_breadcrumb_in_place(crumb, secrets);
        }
        event
    })
}

fn scrub_breadcrumb(crumb: Breadcrumb) -> Breadcrumb {
    with_secrets(crumb, |mut crumb, secrets| {
        scrub_breadcrumb_in_place(&mut crumb, secrets);
        crumb
    })
}

fn scrub_breadcrumb_in_place(crumb: &mut Breadcrumb, secrets: &[String]) {
    scrub_option(&mut crumb.message, secrets);
    scrub_map(&mut crumb.data, secrets);
}

fn scrub_map(map: &mut Map<String, Value>, secrets: &[String]) {
    map.values_mut().for_each(|v| scrub_value(v, secrets));
}

fn scrub_value(value: &mut Value, secrets: &[String]) {
    match value {
        Value::String(s) => scrub_string(s, secrets),
        Value::Array(items) => items.iter_mut().for_each(|v| scrub_value(v, secrets)),
        Value::Object(map) => map.values_mut().for_each(|v| scrub_value(v, secrets)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn scrub_option(value: &mut Option<String>, secrets: &[String]) {
    if let Some(s) = value {
        scrub_string(s, secrets);
    }
}

fn scrub_string(value: &mut String, secrets: &[String]) {
    let mut scrubbed = Cow::Borrowed(value.as_str());
    for secret in secrets {
        if scrubbed.contains(secret.as_str()) {
            scrubbed = Cow::Owned(scrubbed.replace(secret.as_str(), REDACTED));
        }
    }
    if let Cow::Owned(s) = scrubbed {
        *value = s;
    }
}

/// The tracing layer that turns log lines into events and breadcrumbs.
///
/// Inert until [`init`] binds a client, so it is installed whether or not
/// reporting is on.
pub fn layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    // The breadcrumb layer goes first so a warning logged just before an
    // error is already recorded when that error is captured.
    BreadcrumbLayer::new()
        .with_filter(filter_fn(|m: &Metadata<'_>| {
            m.is_event() && is_breadcrumb(*m.level())
        }))
        .and_then(ErrorLayer::new().with_filter(filter_fn(|m: &Metadata<'_>| {
            m.is_event() && is_event(*m.level())
        })))
}

/// `ERROR` lines become Sentry events.
fn is_event(level: Level) -> bool {
    level == Level::ERROR
}

/// `WARN` lines become breadcrumbs on the next event. Errors are not also
/// recorded as breadcrumbs: they are the event.
fn is_breadcrumb(level: Level) -> bool {
    level == Level::WARN
}

#[cfg(test)]
mod tests {
    use sentry::protocol::{Exception, LogEntry};

    use super::*;

    /// NetworkManager's error for a rejected access point profile can
    /// carry the PSK it was given. That error is logged at ERROR, which
    /// makes it an event; the passphrase must not be in it anywhere.
    #[test]
    fn a_registered_passphrase_is_scrubbed_from_events_and_breadcrumbs() {
        let psk = "scrub-test-correct-horse-42";
        redact(&Secret::new(psk));
        // Registering twice, or an empty value, changes nothing.
        redact(&Secret::new(psk));
        redact(&Secret::new(""));

        let leak = format!("invalid property 802-11-wireless-security.psk: '{psk}'");
        let mut fields = Map::new();
        fields.insert("error".into(), Value::String(leak.clone()));
        fields.insert(
            "nested".into(),
            serde_json::json!({ "list": [leak.clone(), 7] }),
        );
        let mut crumb_data = Map::new();
        crumb_data.insert("error".into(), Value::String(leak.clone()));

        let event = Event {
            message: Some(leak.clone()),
            logentry: Some(LogEntry {
                message: leak.clone(),
                params: vec![Value::String(leak.clone())],
            }),
            exception: vec![Exception {
                ty: "panic".into(),
                value: Some(leak.clone()),
                ..Default::default()
            }]
            .into(),
            tags: [("t".to_string(), leak.clone())].into_iter().collect(),
            extra: fields.clone(),
            contexts: [("Rust Tracing Fields".to_string(), Context::Other(fields))]
                .into_iter()
                .collect(),
            breadcrumbs: vec![Breadcrumb {
                message: Some(leak.clone()),
                data: crumb_data.clone(),
                ..Default::default()
            }]
            .into(),
            ..Default::default()
        };

        let sent = serde_json::to_string(&scrub_event(event)).unwrap();
        assert!(!sent.contains(psk), "{sent}");
        assert!(sent.contains("psk: '[redacted]'"), "{sent}");

        let crumb = scrub_breadcrumb(Breadcrumb {
            message: Some(leak.clone()),
            data: crumb_data,
            ..Default::default()
        });
        let sent = serde_json::to_string(&crumb).unwrap();
        assert!(!sent.contains(psk), "{sent}");
    }

    #[test]
    fn a_debug_build_does_not_report_to_the_project_dsn() {
        assert!(reports_to(DEFAULT_SENTRY_DSN, false));
        assert!(!reports_to(DEFAULT_SENTRY_DSN, true));
        // An explicit DSN is a deliberate choice, in any build.
        assert!(reports_to("https://key@example.com/1", true));
        assert!(reports_to("https://key@example.com/1", false));
    }

    #[test]
    fn a_longer_secret_containing_a_shorter_one_is_replaced_whole() {
        let mut s = "a abcdefgh-xyz b".to_string();
        let mut secrets = vec!["abcdefgh".to_string(), "abcdefgh-xyz".to_string()];
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        scrub_string(&mut s, &secrets);
        assert_eq!(s, "a [redacted] b");
    }

    /// The setup passphrase is logged at INFO when the operator opts in.
    /// Nothing at that level may reach Sentry, not even as a breadcrumb.
    #[test]
    fn only_warnings_and_errors_are_sent() {
        assert!(is_event(Level::ERROR));
        assert!(!is_breadcrumb(Level::ERROR));
        assert!(is_breadcrumb(Level::WARN));
        assert!(!is_event(Level::WARN));
        for level in [Level::INFO, Level::DEBUG, Level::TRACE] {
            assert!(!is_event(level), "{level}");
            assert!(!is_breadcrumb(level), "{level}");
        }
    }
}
