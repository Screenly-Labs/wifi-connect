//! wifi-connect: raise an encrypted WiFi access point with a captive
//! portal, and join the network the user chooses.
//!
//! The whole flow lives in this process. In particular the connectivity
//! probe, the retry loop and the timeout are *not* delegated to a shell
//! wrapper: the integration this replaces did exactly that, and because its
//! wrapper ran `wget` under `set -euo pipefail` the failing probe aborted
//! the script before the test that was meant to detect it. The
//! captive-portal branch was unreachable for three years and nobody noticed.

#![forbid(unsafe_code)]

mod app;
mod cli;
mod dhcp;
mod dns;
mod http;
mod nm;
mod passphrase;
mod qr;
mod secret;
mod sockets;
mod ssid;
mod state;

use std::io::IsTerminal;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use cli::{Cli, LogFormat};
use nm::nmrs_impl::NmrsControl;
use secret::Secret;
use ssid::Ssid;

fn init_logging(args: &Cli) {
    // RUST_LOG wins when set, so an operator can turn on nmrs's own tracing
    // (`RUST_LOG=nmrs=debug`) without touching our flags. nmrs logs through
    // `log`, which tracing-subscriber's tracing-log feature bridges for us —
    // genuinely valuable on hardware that misbehaves.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(args.log_level.clone()));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        // Colour escapes in journald or a balena log stream are noise.
        .with_ansi(std::io::stdout().is_terminal());

    match args.log_format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Text => builder.init(),
    }
}

/// Publish the join QR: to disk for the host application to display, and to
/// stdout for a plain console.
///
/// This is the primary way the generated passphrase reaches the user. It is
/// rendered locally because it is what gets you *onto* the network — it
/// cannot be served over that network.
fn publish_qr(args: &Cli, ssid: &Ssid, passphrase: Option<&Secret>) {
    let Some(passphrase) = passphrase else {
        warn!(
            "the access point is OPEN: everything typed into the portal crosses \
             the air in clear"
        );
        return;
    };

    let payload = qr::wifi_payload(ssid, passphrase, false);
    let code = match qr::JoinQr::encode(&payload) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "could not encode the join QR code");
            return;
        }
    };

    if let Some(dir) = &args.qr_output {
        if let Err(e) = std::fs::create_dir_all(dir) {
            error!(error = %e, path = %dir.display(), "could not create the QR output directory");
        } else {
            let svg = dir.join("wifi-connect-qr.svg");
            match std::fs::write(&svg, code.to_svg(512)) {
                Ok(()) => info!(path = %svg.display(), "wrote the join QR code"),
                Err(e) => error!(error = %e, path = %svg.display(), "could not write the QR code"),
            }
            // The raw payload too, so a host application can render the
            // code itself at whatever size its screen wants.
            let txt = dir.join("wifi-connect-qr.txt");
            if let Err(e) = std::fs::write(&txt, &payload) {
                error!(error = %e, path = %txt.display(), "could not write the QR payload");
            }
        }
    }

    if !args.no_qr_stdout {
        // Printed, not logged: a log formatter would mangle the block
        // characters and a journald line-wrap would make it unscannable.
        println!();
        println!("Scan to join \"{ssid}\":");
        println!();
        print!("{}", code.to_unicode());
        println!();
    }

    // The fallback for anyone whose scanner refuses, and for operators
    // reading the journal. The passphrase is deliberately exposed here and
    // nowhere else: this is the one place it is meant to be read.
    info!(
        ssid = %ssid,
        passphrase = %passphrase.expose(),
        "setup access point credentials"
    );
}

/// The /24 broadcast address for a gateway.
fn broadcast_for(gateway: Ipv4Addr) -> Ipv4Addr {
    let o = gateway.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 255)
}

async fn run() -> ExitCode {
    let args = Cli::parse();
    init_logging(&args);

    let dhcp_range = match args.validate() {
        Ok(r) => r,
        Err(e) => {
            error!("{e}");
            return ExitCode::from(2);
        }
    };

    // Generated once per RUN, not per activation. A failed join re-raises
    // the access point, and the user's phone only reassociates
    // automatically if the SSID and passphrase are byte-identical to the
    // ones it already stored.
    let passphrase = if args.insecure_open_portal {
        None
    } else {
        Some(
            args.portal_passphrase
                .clone()
                .map(Secret::new)
                .unwrap_or_else(passphrase::generate),
        )
    };

    let ssid = Ssid::from(args.portal_ssid.as_str());
    publish_qr(&args, &ssid, passphrase.as_ref());

    let nm = match NmrsControl::connect().await {
        Ok(nm) => nm,
        Err(e) => {
            error!("{e}");
            error!(
                "the bus address comes from $DBUS_SYSTEM_BUS_ADDRESS, defaulting \
                 to /var/run/dbus/system_bus_socket. In a balena container set the \
                 io.balena.features.dbus label and point it at \
                 unix:path=/host/run/dbus/system_bus_socket."
            );
            return ExitCode::from(5);
        }
    };

    let run_config = app::RunConfig {
        ap: nm::ApConfig {
            ssid: ssid.clone(),
            passphrase: passphrase.clone(),
            security: args.ap_security(),
            gateway: args.portal_gateway,
            prefix: 24,
            channel: None,
        },
        interface: args.interface.clone(),
        autoconnect_budget: args.wait_for_connection(),
        join_budget: args.connection_timeout(),
        activity_timeout: args.activity_timeout(),
        force: args.force,
    };

    // Decide whether the portal is needed at all before binding a socket.
    let device = match app::preflight(&nm, &run_config).await {
        Ok(None) => return ExitCode::from(0),
        Ok(Some(d)) => d,
        Err(e) => return ExitCode::from(app::report(&Err(e)) as u8),
    };

    let (shared, joins) = state::Shared::new(args.portal_url(), args.brand_name.clone());
    let cancel = CancellationToken::new();

    // DHCP, DNS and HTTP. DHCP is pinned to the access-point interface;
    // DNS and HTTP bind the gateway address specifically. None of the three
    // can touch another interface on this device, which matters when the
    // box also has a live ethernet link to a customer LAN.
    let servers = {
        let cancel = cancel.clone();
        let gateway = args.portal_gateway;
        let interface = device.interface.clone();
        let api_url = args.captive_portal_api_url();
        let port = args.portal_listening_port;
        let shared = shared.clone();

        tokio::spawn(async move {
            let leases = dhcp::lease::Leases::new(dhcp_range.first, dhcp_range.last);
            let dhcp_cfg = dhcp::reply::ServerConfig {
                gateway,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                broadcast: broadcast_for(gateway),
                captive_portal_api_url: api_url,
            };

            let dhcp = dhcp::serve(&interface, 67, dhcp_cfg, leases, cancel.clone());
            let dns = dns::serve(gateway, 53, cancel.clone());
            let portal = http::serve(SocketAddr::from((gateway, port)), shared, cancel.clone());

            // Any one of the three failing makes the portal useless, so say
            // so rather than limping on with a page nobody can reach.
            tokio::select! {
                r = dhcp => if let Err(e) = r { error!(error = %e, "the DHCP server stopped") },
                r = dns => if let Err(e) = r { error!(error = %e, "the DNS server stopped") },
                r = portal => if let Err(e) = r { error!(error = %e, "the portal stopped") },
            }
        })
    };

    // balena sends SIGTERM on every update, and leaving the radio in AP
    // mode would strand the device.
    let signals = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "could not install the SIGTERM handler");
                        return;
                    }
                };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => info!("interrupted"),
                _ = term.recv() => info!("terminated"),
            }
            cancel.cancel();
        })
    };

    let result = app::run_portal(&nm, &device, &run_config, &shared, joins, cancel.clone()).await;

    cancel.cancel();
    signals.abort();
    let _ = servers.await;

    ExitCode::from(app::report(&result) as u8)
}

// current_thread: there is no CPU work in this program, and one thread
// keeps resident memory down on a Pi Zero-class board.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_is_derived_from_the_gateway() {
        assert_eq!(
            broadcast_for(Ipv4Addr::new(192, 168, 42, 1)),
            Ipv4Addr::new(192, 168, 42, 255)
        );
        assert_eq!(
            broadcast_for(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 255)
        );
    }
}
