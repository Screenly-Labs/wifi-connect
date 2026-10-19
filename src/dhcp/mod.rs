//! The DHCP server.
//!
//! Binds `0.0.0.0:67` pinned to the access point interface — see
//! [`crate::sockets::bind_dhcp`] for why it cannot bind the gateway address
//! and why the interface pin is a safety requirement rather than a tidiness
//! one.

pub mod lease;
pub mod reply;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use dhcproto::v4::Message;
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::sockets;
use lease::Leases;
use reply::ServerConfig;

/// The DHCP client port. Replies are broadcast here.
const CLIENT_PORT: u16 = 68;

/// Big enough for any DHCP message we will see; the protocol's own minimum
/// is 576 bytes and options rarely push past 1500.
const MAX_DATAGRAM: usize = 1500;

/// Serve DHCP on `interface` until `cancel` fires.
pub async fn serve(
    interface: &str,
    port: u16,
    cfg: ServerConfig,
    mut leases: Leases,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let socket = sockets::bind_dhcp(interface, port).await?;
    debug!(interface, port, gateway = %cfg.gateway, "DHCP server listening");

    // Always broadcast. The client has no address yet, so unicasting would
    // require an ARP entry for a host that has not configured the address we
    // are in the middle of offering it.
    let broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, CLIENT_PORT));

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, peer) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("DHCP server stopping");
                return Ok(());
            }
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "DHCP receive failed");
                    continue;
                }
            },
        };

        let msg = match Message::decode(&mut Decoder::new(&buf[..len])) {
            Ok(m) => m,
            Err(e) => {
                trace!(%peer, error = %e, "dropped an undecodable DHCP message");
                continue;
            }
        };

        let Some(response) = reply::respond(&msg, &cfg, &mut leases, Instant::now()) else {
            continue;
        };

        let mut out = Vec::with_capacity(MAX_DATAGRAM);
        if let Err(e) = response.encode(&mut Encoder::new(&mut out)) {
            warn!(error = %e, "failed to encode a DHCP reply");
            continue;
        }

        if let Err(e) = socket.send_to(&out, broadcast).await {
            warn!(error = %e, "DHCP reply failed");
        }
    }
}
