//! Socket construction for the three portal listeners.
//!
//! Three things here are easy to get wrong and expensive to get wrong:
//!
//! 1. **Every listener is pinned to the access point interface with
//!    `SO_BINDTODEVICE`.** Binding the gateway address alone is not enough.
//!    Linux is a weak-host stack: a packet addressed to `192.168.42.1` is
//!    delivered to a socket bound to `192.168.42.1` whichever interface it
//!    arrived on. A host on the customer's ethernet LAN only needs a route
//!    to `192.168.42.1` via this device's ethernet address (one `ip route
//!    add`) to reach the portal — and `POST /connect` is unauthenticated, so
//!    that host could repoint the device at a network of its choosing
//!    without ever knowing the access point passphrase. The default
//!    `arp_ignore=0` and loose `rp_filter` do nothing to stop it. With the
//!    device pin, the kernel only matches the socket for traffic that
//!    arrived on the access point interface.
//!
//! 2. **DHCP cannot bind the gateway address.** A `DHCPDISCOVER` arrives from
//!    source `0.0.0.0` addressed to `255.255.255.255`; a socket bound to
//!    `192.168.42.1` will never see it. So the DHCP socket binds `0.0.0.0:67`
//!    and the device pin is the *only* thing scoping it — without it we
//!    would answer DHCP on the customer's ethernet LAN, handing out leases on
//!    a network we do not own.
//!
//! 3. **The address is not bindable the instant NetworkManager says the
//!    connection is ACTIVATED.** There is a short window between NM's netlink
//!    write and the address being usable. Rather than sleeping a guessed
//!    amount, retry the bind.
//!
//! Since Linux 5.7, `SO_BINDTODEVICE` needs no capability as long as the
//! socket is not already pinned to a device (only *changing* an existing pin
//! needs `CAP_NET_RAW`), so on any kernel we target it is unprivileged for
//! UDP and TCP alike. On an older kernel it always requires `CAP_NET_RAW`,
//! which is why the systemd unit keeps that in its bounding set and the
//! balena compose example carries a commented-out `NET_RAW`. The pin is set
//! *before* `bind` so that the socket is never bound and receiving without
//! it, not because the capability check depends on the order.
//!
//! The pin is to the interface's index, resolved once at startup. It
//! survives the access point going down and coming back up (the address
//! disappears and reappears; the socket stays bound and starts receiving
//! again), which is what a failed join does. It would not survive the
//! interface being deleted and recreated under a new index (a driver reset,
//! a USB dongle re-enumerating); the DHCP pin never did either.

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

/// Pin `socket` to `interface` with `SO_BINDTODEVICE`. Called before `bind`,
/// so the socket never receives unpinned (see the module docs for the
/// pre-5.7 `CAP_NET_RAW` caveat).
///
/// The error names the interface: a bare "No such device" or "Operation not
/// permitted" at startup says nothing about which knob to turn.
fn pin_to_interface(socket: &Socket, interface: &str) -> io::Result<()> {
    socket.bind_device(Some(interface.as_bytes())).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot pin socket to interface {interface:?} (SO_BINDTODEVICE): {e}"),
        )
    })
}

/// Bind a UDP socket to a specific address on `interface`, riding out the
/// window where the access point's address exists in NetworkManager but not
/// yet in the kernel.
///
/// The interface is not optional: the address alone does not keep the
/// socket off other interfaces (see the module docs).
pub async fn bind_udp_retrying(interface: &str, addr: SocketAddr) -> io::Result<UdpSocket> {
    retry_bind("udp", || {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        pin_to_interface(&socket, interface)?;
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into())
    })
    .await
}

/// Bind a TCP listener to a specific address on `interface`, with the same
/// retry and the same mandatory pin. Connections accepted from the listener
/// inherit its device binding, so the pin covers them too.
pub async fn bind_tcp_retrying(interface: &str, addr: SocketAddr) -> io::Result<TcpListener> {
    retry_bind("tcp", || {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        pin_to_interface(&socket, interface)?;
        socket.bind(&addr.into())?;
        socket.listen(128)?;
        TcpListener::from_std(socket.into())
    })
    .await
}

/// Bind the DHCP server socket: `0.0.0.0:67`, pinned to `interface`.
pub async fn bind_dhcp(interface: &str, port: u16) -> io::Result<UdpSocket> {
    retry_bind("dhcp", || {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        // Replies go to 255.255.255.255: the client has no address to
        // unicast to yet, and unicasting would need an ARP entry for a host
        // that has not configured the address we are about to offer it.
        socket.set_broadcast(true)?;
        pin_to_interface(&socket, interface)?;
        socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use socket2::SockRef;

    /// The interface a socket is pinned to, read back with
    /// `getsockopt(SO_BINDTODEVICE)`.
    ///
    /// `Err(())` means the read-back itself is unsupported: qemu-user (which
    /// the armv7 CI job runs the tests under) forwards the `setsockopt` but
    /// answers the `getsockopt` with `EINVAL`. The behavioural tests below
    /// still cover the pin there; only the read-back is skipped.
    fn pinned_device(socket: SockRef<'_>) -> Result<Option<Vec<u8>>, ()> {
        match socket.device() {
            Ok(dev) => Ok(dev),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                eprintln!("getsockopt(SO_BINDTODEVICE) unsupported here ({e}); skipping read-back");
                Err(())
            }
            Err(e) => panic!("getsockopt(SO_BINDTODEVICE) failed: {e}"),
        }
    }

    /// Some interface other than `lo`, to pin a loopback-bound socket to.
    /// `None` in a sandbox that has only `lo`.
    fn a_non_loopback_interface() -> Option<String> {
        std::fs::read_to_string("/proc/net/dev")
            .unwrap()
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next())
            .map(str::trim)
            .find(|name| *name != "lo")
            .map(str::to_owned)
    }

    #[tokio::test]
    async fn binds_a_loopback_udp_socket() {
        let s = bind_udp_retrying("lo", SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        assert_eq!(s.local_addr().unwrap().ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn binds_a_loopback_tcp_listener() {
        let l = bind_tcp_retrying("lo", SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        assert!(l.local_addr().unwrap().port() > 0);
    }

    /// The DNS socket must actually carry the device pin, not just the
    /// address: the address alone lets a LAN host with a static route reach
    /// it through the ethernet interface.
    #[tokio::test]
    async fn the_udp_socket_is_pinned_to_the_interface() {
        let s = bind_udp_retrying("lo", SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        if let Ok(dev) = pinned_device(SockRef::from(&s)) {
            assert_eq!(dev.as_deref(), Some(&b"lo"[..]));
        }
    }

    /// Same for the portal listener — and, since `POST /connect` is served on
    /// the *accepted* socket, the pin has to carry over to every connection
    /// the listener hands out.
    #[tokio::test]
    async fn the_tcp_listener_and_its_connections_are_pinned_to_the_interface() {
        let l = bind_tcp_retrying("lo", SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let Ok(dev) = pinned_device(SockRef::from(&l)) else {
            return;
        };
        assert_eq!(dev.as_deref(), Some(&b"lo"[..]));

        let addr = l.local_addr().unwrap();
        let (accepted, _client) = tokio::join!(l.accept(), tokio::net::TcpStream::connect(addr));
        let (conn, _) = accepted.unwrap();
        let dev = pinned_device(SockRef::from(&conn)).unwrap();
        assert_eq!(dev.as_deref(), Some(&b"lo"[..]));
    }

    /// The property the pin exists for, reproduced on one box: a listener
    /// bound to an address that is perfectly reachable, but pinned to a
    /// *different* interface than the one the traffic arrives on, must
    /// refuse the connection. Here the address is `127.0.0.1`, the traffic
    /// arrives on `lo`, and the listener is pinned to some other interface
    /// — the same shape as the gateway address being reached through the
    /// ethernet port instead of the access point.
    ///
    /// Needs a second interface to pin to; a sandbox with only `lo` skips.
    #[tokio::test]
    async fn a_tcp_connection_arriving_on_another_interface_is_refused() {
        let Some(other) = a_non_loopback_interface() else {
            eprintln!("no non-loopback interface to pin to; skipping");
            return;
        };

        let l = bind_tcp_retrying(&other, SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let err = match tokio::net::TcpStream::connect(l.local_addr().unwrap()).await {
            Ok(_) => panic!("a listener pinned to {other} accepted a connection over lo"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err}");
    }

    /// The same for DNS: a query arriving on another interface must never
    /// reach the socket. Proving a negative over UDP needs a timeout, so the
    /// control — the same datagram reaching a socket pinned to `lo` — is what
    /// shows the timeout is long enough to mean something.
    #[tokio::test]
    async fn a_udp_datagram_arriving_on_another_interface_is_not_delivered() {
        let Some(other) = a_non_loopback_interface() else {
            eprintln!("no non-loopback interface to pin to; skipping");
            return;
        };
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let wait = Duration::from_millis(500);
        let client = UdpSocket::bind(loopback).await.unwrap();
        let mut buf = [0u8; 16];

        let pinned_lo = bind_udp_retrying("lo", loopback).await.unwrap();
        client
            .send_to(b"query", pinned_lo.local_addr().unwrap())
            .await
            .unwrap();
        tokio::time::timeout(wait, pinned_lo.recv_from(&mut buf))
            .await
            .expect("control: a socket pinned to lo should receive over lo")
            .unwrap();

        let pinned_other = bind_udp_retrying(&other, loopback).await.unwrap();
        client
            .send_to(b"query", pinned_other.local_addr().unwrap())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(wait, pinned_other.recv_from(&mut buf))
                .await
                .is_err(),
            "a socket pinned to {other} received a datagram that arrived on lo"
        );
    }

    /// An interface that does not exist is a configuration error, not a
    /// race: it must fail at once, and say which interface it was, rather
    /// than spend the retry budget and surface a bare "No such device".
    /// Paused time would let a wrongly-retried bind finish instantly too, so
    /// the elapsed clock is what proves no retry happened.
    #[tokio::test(start_paused = true)]
    async fn an_unknown_interface_fails_at_once_with_its_name_in_the_error() {
        let start = tokio::time::Instant::now();
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));

        let udp = bind_udp_retrying("nosuchif0", addr)
            .await
            .expect_err("pinning to a missing interface should fail");
        let tcp = bind_tcp_retrying("nosuchif0", addr)
            .await
            .expect_err("pinning to a missing interface should fail");
        let dhcp = bind_dhcp("nosuchif0", 0)
            .await
            .expect_err("pinning to a missing interface should fail");

        for err in [udp, tcp, dhcp] {
            let msg = err.to_string();
            assert!(
                msg.contains("\"nosuchif0\""),
                "error does not name the interface: {msg}"
            );
            assert!(
                msg.contains("SO_BINDTODEVICE"),
                "error does not name the option: {msg}"
            );
        }
        assert_eq!(
            start.elapsed(),
            Duration::ZERO,
            "a missing interface was retried"
        );
    }

    /// An address that never appears must give up, not hang forever. Paused
    /// time makes the five-second budget elapse instantly.
    #[tokio::test(start_paused = true)]
    async fn an_address_that_never_appears_eventually_gives_up() {
        // TEST-NET-3: guaranteed not to be a local address.
        let r = bind_udp_retrying("lo", SocketAddr::from(([203, 0, 113, 1], 0))).await;
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
