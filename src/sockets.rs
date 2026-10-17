//! Socket construction for the three portal listeners.
//!
//! Two things here are easy to get wrong and expensive to get wrong:
//!
//! 1. **DHCP cannot bind the gateway address.** A `DHCPDISCOVER` arrives from
//!    source `0.0.0.0` addressed to `255.255.255.255`; a socket bound to
//!    `192.168.42.1` will never see it. So the DHCP socket binds `0.0.0.0:67`
//!    and is pinned to the access point interface with `SO_BINDTODEVICE`.
//!    That pin is not a nicety — without it we would answer DHCP on the
//!    customer's ethernet LAN, handing out leases on a network we do not own.
//!
//! 2. **The address is not bindable the instant NetworkManager says the
//!    connection is ACTIVATED.** There is a short window between NM's netlink
//!    write and the address being usable. Rather than sleeping a guessed
//!    amount, retry the bind.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tracing::trace;

/// How long to keep retrying a bind that fails with `EADDRNOTAVAIL`.
const BIND_RETRY_BUDGET: Duration = Duration::from_secs(5);
const BIND_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// `EADDRNOTAVAIL`. The one errno that means "that address is not on this box
/// *yet*" rather than "this will never work".
const EADDRNOTAVAIL: i32 = 99;

/// `true` when retrying could plausibly succeed. A permanent failure such as
/// `EACCES` (binding a privileged port unprivileged) must surface at once
/// rather than after a five-second stall that hides the real cause.
fn is_transient_bind_error(e: &io::Error) -> bool {
    e.raw_os_error() == Some(EADDRNOTAVAIL)
}

async fn retry_bind<T, F>(what: &str, mut attempt: F) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    let deadline = tokio::time::Instant::now() + BIND_RETRY_BUDGET;
    loop {
        match attempt() {
            Ok(v) => return Ok(v),
            Err(e) if is_transient_bind_error(&e) && tokio::time::Instant::now() < deadline => {
                trace!(%what, error = %e, "address not ready yet, retrying bind");
                tokio::time::sleep(BIND_RETRY_INTERVAL).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Bind a UDP socket to a specific address, riding out the window where the
/// access point's address exists in NetworkManager but not yet in the kernel.
pub async fn bind_udp_retrying(addr: SocketAddr) -> io::Result<UdpSocket> {
    retry_bind("udp", || {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into())
    })
    .await
}

/// Bind a TCP listener to a specific address, with the same retry.
pub async fn bind_tcp_retrying(addr: SocketAddr) -> io::Result<TcpListener> {
    retry_bind("tcp", || {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        socket.listen(128)?;
        TcpListener::from_std(socket.into())
    })
    .await
}

/// Bind the DHCP server socket: `0.0.0.0:67`, pinned to `interface`.
///
/// `SO_BINDTODEVICE` has been unprivileged since Linux 5.7 for a socket that
/// has not yet been bound, so this needs no capability on any kernel we
/// target. On an older kernel it requires `CAP_NET_RAW`, which is why the
/// systemd unit keeps that in its bounding set and the balena compose example
/// carries a commented-out `NET_ADMIN`.
pub async fn bind_dhcp(interface: &str, port: u16) -> io::Result<UdpSocket> {
    retry_bind("dhcp", || {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        // Replies go to 255.255.255.255: the client has no address to
        // unicast to yet, and unicasting would need an ARP entry for a host
        // that has not configured the address we are about to offer it.
        socket.set_broadcast(true)?;
        socket.bind_device(Some(interface.as_bytes()))?;
        socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_a_loopback_udp_socket() {
        let s = bind_udp_retrying(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        assert_eq!(s.local_addr().unwrap().ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn binds_a_loopback_tcp_listener() {
        let l = bind_tcp_retrying(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        assert!(l.local_addr().unwrap().port() > 0);
    }

    /// An address that never appears must give up, not hang forever. Paused
    /// time makes the five-second budget elapse instantly.
    #[tokio::test(start_paused = true)]
    async fn an_address_that_never_appears_eventually_gives_up() {
        // TEST-NET-3: guaranteed not to be a local address.
        let r = bind_udp_retrying(SocketAddr::from(([203, 0, 113, 1], 0))).await;
        let err = r.expect_err("binding a non-local address should fail");
        assert!(is_transient_bind_error(&err), "unexpected errno: {err}");
    }

    #[test]
    fn only_eaddrnotavail_counts_as_transient() {
        assert!(is_transient_bind_error(&io::Error::from_raw_os_error(
            EADDRNOTAVAIL
        )));
        // EACCES: binding a privileged port unprivileged. Retrying this for
        // five seconds would just delay a clear error message.
        assert!(!is_transient_bind_error(&io::Error::from_raw_os_error(13)));
        // EADDRINUSE: something else already holds the port.
        assert!(!is_transient_bind_error(&io::Error::from_raw_os_error(98)));
    }
}
