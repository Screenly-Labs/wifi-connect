//! The wildcard DNS server.
//!
//! Binds the portal's own address specifically — never `0.0.0.0` — and pins
//! the socket to the access point interface with `SO_BINDTODEVICE`. On a
//! device with a live ethernet link, a wildcard bind would put a lying
//! resolver on the real LAN; and the address alone is not enough either,
//! because Linux delivers a packet for the gateway address that arrives on
//! *any* interface (see [`crate::sockets`]).

pub mod answer;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::sockets;

/// 512 bytes is the classic non-EDNS limit. We never emit a large answer, so
/// a bigger buffer would only let a client make us allocate more.
const MAX_DATAGRAM: usize = 512;

/// Serve wildcard DNS on `gateway:53`, pinned to `interface`, until `cancel`
/// fires.
pub async fn serve(
    interface: &str,
    gateway: Ipv4Addr,
    port: u16,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let socket =
        Arc::new(sockets::bind_udp_retrying(interface, SocketAddr::from((gateway, port))).await?);
    debug!(%interface, %gateway, port, "DNS server listening");

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, peer) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("DNS server stopping");
                return Ok(());
            }
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    // A transient receive error must not kill the server;
                    // the portal would look alive but resolve nothing.
                    warn!(error = %e, "DNS receive failed");
                    continue;
                }
            },
        };

        match answer::respond(&buf[..len], gateway) {
            Some(reply) => {
                if let Err(e) = socket.send_to(&reply, peer).await {
                    warn!(error = %e, %peer, "DNS reply failed");
                }
            }
            None => trace!(%peer, len, "dropped an unanswerable DNS datagram"),
        }
    }
}
