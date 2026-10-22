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

use sentry::integrations::tracing::EventFilter;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::registry::LookupSpan;

use crate::cli::Cli;

/// Bind the Sentry client for this process, unless it is turned off.
///
/// The returned guard flushes queued events when dropped, bounded by the
/// client's shutdown timeout. Keep it alive for the whole of `main`.
///
/// Call after [`Cli::validate`], which rejects a DSN that does not parse.
pub fn init(args: &Cli) -> Option<sentry::ClientInitGuard> {
    let dsn = args.sentry_dsn().ok().flatten()?;
    Some(sentry::init((
        dsn,
        sentry::ClientOptions::new()
            .maybe_release(sentry::release_name!())
            // Nothing here is an HTTP server integration, so this mostly
            // decides whether Sentry infers the client's address. A device
            // on a customer's network has no business sending that.
            .send_default_pii(false),
    )))
}

/// The tracing layer that turns log lines into events and breadcrumbs.
///
/// Inert until [`init`] binds a client, so it is installed whether or not
/// reporting is on.
pub fn layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    sentry::integrations::tracing::layer()
        .event_filter(event_filter)
        .span_filter(|_| false)
}

fn event_filter(metadata: &Metadata<'_>) -> EventFilter {
    filter_for(*metadata.level())
}

fn filter_for(level: Level) -> EventFilter {
    match level {
        Level::ERROR => EventFilter::Event,
        Level::WARN => EventFilter::Breadcrumb,
        _ => EventFilter::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The setup passphrase is logged at INFO when the operator opts in.
    /// Nothing at that level may reach Sentry, not even as a breadcrumb.
    #[test]
    fn only_warnings_and_errors_are_sent() {
        assert_eq!(filter_for(Level::ERROR).bits(), EventFilter::Event.bits());
        assert_eq!(
            filter_for(Level::WARN).bits(),
            EventFilter::Breadcrumb.bits()
        );
        for level in [Level::INFO, Level::DEBUG, Level::TRACE] {
            assert_eq!(
                filter_for(level).bits(),
                EventFilter::Ignore.bits(),
                "{level}"
            );
        }
    }
}
