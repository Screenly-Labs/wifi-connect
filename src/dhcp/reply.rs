//! Turning a received DHCP message into the one we send back.
//!
//! Pure: message in, message out. The socket and the clock live in the
//! parent module.
//!
//! Two options here are load-bearing for captive-portal detection and are
//! easy to mistake for boilerplate:
//!
//! * **Option 114 (RFC 8910)** must carry the URL of the *API endpoint* that
//!   serves the RFC 8908 JSON — not the user-facing HTML page. The JSON then
//!   points at the page via `user-portal-url`. Putting the HTML URL here is a
//!   common mistake that makes iOS fall back to the legacy probe path.
//! * **Option 3 (Router)** is advertised even though we route nowhere.
//!   Without a default gateway, Android marks the network unusable and never
//!   runs its captive-portal probe at all, so the sign-in sheet never shows.

use std::net::Ipv4Addr;
use std::time::Instant;

use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode, OptionCode};

use super::lease::{Leases, MacAddr};

/// Everything the reply builder needs to know about the portal.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    /// The RFC 8908 API endpoint, e.g. `http://192.168.42.1/api/captive-portal`.
    pub captive_portal_api_url: String,
}

fn mac_of(msg: &Message) -> Option<MacAddr> {
    let chaddr = msg.chaddr();
    if chaddr.len() < 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&chaddr[..6]);
    Some(mac)
}

fn message_type(msg: &Message) -> Option<MessageType> {
    match msg.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(t)) => Some(*t),
        _ => None,
    }
}

fn requested_ip(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    }
}

fn server_identifier(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

/// Start a reply that echoes the client's transaction so it can match it up.
fn base_reply(req: &Message) -> Message {
    let mut reply = Message::default();
    reply
        .set_opcode(Opcode::BootReply)
        .set_htype(req.htype())
        .set_xid(req.xid())
        .set_flags(req.flags())
        .set_chaddr(req.chaddr())
        .set_giaddr(req.giaddr());
    reply
}

fn push_common_options(reply: &mut Message, cfg: &ServerConfig, lease_secs: u32) {
    let opts = reply.opts_mut();
    opts.insert(DhcpOption::ServerIdentifier(cfg.gateway));
    opts.insert(DhcpOption::AddressLeaseTime(lease_secs));
    opts.insert(DhcpOption::SubnetMask(cfg.netmask));
    opts.insert(DhcpOption::BroadcastAddr(cfg.broadcast));
    // We are the router and the resolver. Both point at us.
    opts.insert(DhcpOption::Router(vec![cfg.gateway]));
    opts.insert(DhcpOption::DomainNameServer(vec![cfg.gateway]));
    opts.insert(DhcpOption::CaptivePortal(
        cfg.captive_portal_api_url.clone(),
    ));
}

/// Build the response to one DHCP message, or `None` to stay silent.
pub fn respond(
    req: &Message,
    cfg: &ServerConfig,
    leases: &mut Leases,
    now: Instant,
) -> Option<Message> {
    // Only requests, only Ethernet, and never a relayed message: a non-zero
    // giaddr means it came through a relay agent and is not ours to answer.
    if req.opcode() != Opcode::BootRequest || req.giaddr() != Ipv4Addr::UNSPECIFIED {
        return None;
    }
    let mac = mac_of(req)?;
    let lease_secs = leases.lease_time().as_secs() as u32;

    match message_type(req)? {
        MessageType::Discover => {
            let offer = leases.offer(mac, requested_ip(req), now)?;
            let mut reply = base_reply(req);
            reply.set_yiaddr(offer).set_siaddr(cfg.gateway);
            reply
                .opts_mut()
                .insert(DhcpOption::MessageType(MessageType::Offer));
            push_common_options(&mut reply, cfg, lease_secs);
            Some(reply)
        }

        MessageType::Request => {
            // A REQUEST in the SELECTING state names us (or someone else) in
            // the server identifier. If it names another server, the client
            // chose them and we must not answer.
            if let Some(sid) = server_identifier(req)
                && sid != cfg.gateway
            {
                return None;
            }

            // The address being requested is in option 50 while the client
            // has no address, and in ciaddr once it is renewing.
            let wanted = requested_ip(req).or_else(|| {
                let c = req.ciaddr();
                (c != Ipv4Addr::UNSPECIFIED).then_some(c)
            })?;

            let mut reply = base_reply(req);
            if leases.may_use(mac, wanted, now) {
                leases.commit(mac, wanted, now);
                reply.set_yiaddr(wanted).set_siaddr(cfg.gateway);
                reply
                    .opts_mut()
                    .insert(DhcpOption::MessageType(MessageType::Ack));
                push_common_options(&mut reply, cfg, lease_secs);
            } else {
                // The usual cause is a phone still holding a lease from its
                // home network. NAK tells it to start over, which is exactly
                // what we want.
                reply
                    .opts_mut()
                    .insert(DhcpOption::MessageType(MessageType::Nak));
                reply
                    .opts_mut()
                    .insert(DhcpOption::ServerIdentifier(cfg.gateway));
            }
            Some(reply)
        }

        // Windows sends these to ask for options without wanting an address.
        MessageType::Inform => {
            let mut reply = base_reply(req);
            reply.set_ciaddr(req.ciaddr());
            reply
                .opts_mut()
                .insert(DhcpOption::MessageType(MessageType::Ack));
            push_common_options(&mut reply, cfg, lease_secs);
            // RFC 2131: no lease is being granted, so no lease time.
            reply.opts_mut().remove(OptionCode::AddressLeaseTime);
            Some(reply)
        }

        MessageType::Release => {
            leases.release(mac);
            None
        }

        // Only honoured when this MAC holds the address; see
        // `Leases::decline` for why.
        MessageType::Decline => {
            if let Some(ip) = requested_ip(req) {
                leases.decline(mac, ip, now);
            }
            None
        }

        // Offer, Ack, Nak and friends are server-to-client; seeing one means
        // another DHCP server is on this link, which is not our problem.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::{Decodable, Decoder, Encodable, Encoder};
    use std::time::Duration;

    const CLIENT: MacAddr = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    const OTHER: MacAddr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 42, 1);

    fn cfg() -> ServerConfig {
        ServerConfig {
            gateway: GW,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 42, 255),
            captive_portal_api_url: "http://192.168.42.1/api/captive-portal".into(),
        }
    }

    fn leases() -> Leases {
        Leases::with_lease_time(
            Ipv4Addr::new(192, 168, 42, 10),
            Ipv4Addr::new(192, 168, 42, 12),
            Duration::from_secs(600),
        )
    }

    fn request(kind: MessageType) -> Message {
        let mut m = Message::default();
        m.set_opcode(Opcode::BootRequest)
            .set_xid(0xdead_beef)
            .set_chaddr(&CLIENT);
        m.opts_mut().insert(DhcpOption::MessageType(kind));
        m
    }

    fn kind_of(m: &Message) -> MessageType {
        message_type(m).expect("reply must carry a message type")
    }

    fn opt(m: &Message, code: OptionCode) -> Option<&DhcpOption> {
        m.opts().get(code)
    }

    #[test]
    fn discover_is_answered_with_an_offer() {
        let (c, mut l) = (cfg(), leases());
        let reply = respond(&request(MessageType::Discover), &c, &mut l, Instant::now()).unwrap();

        assert_eq!(reply.opcode(), Opcode::BootReply);
        assert_eq!(kind_of(&reply), MessageType::Offer);
        assert_eq!(reply.xid(), 0xdead_beef, "xid must be echoed");
        assert_eq!(reply.yiaddr(), Ipv4Addr::new(192, 168, 42, 10));
        assert_eq!(&reply.chaddr()[..6], &CLIENT);
    }

    /// RFC 8910. The value must be the API endpoint, because that is what
    /// serves the RFC 8908 document; the HTML page is reached from inside it.
    #[test]
    fn offer_carries_the_captive_portal_api_url() {
        let (c, mut l) = (cfg(), leases());
        let reply = respond(&request(MessageType::Discover), &c, &mut l, Instant::now()).unwrap();

        match opt(&reply, OptionCode::CaptivePortal) {
            Some(DhcpOption::CaptivePortal(url)) => {
                assert!(url.contains("/api/captive-portal"), "got {url}");
            }
            other => panic!("option 114 missing or wrong: {other:?}"),
        }
    }

    /// Without a router option Android declares the network unusable and
    /// never runs the probe that opens the sign-in sheet.
    #[test]
    fn offer_advertises_a_router_and_a_resolver() {
        let (c, mut l) = (cfg(), leases());
        let reply = respond(&request(MessageType::Discover), &c, &mut l, Instant::now()).unwrap();

        assert!(matches!(
            opt(&reply, OptionCode::Router),
            Some(DhcpOption::Router(r)) if r == &vec![GW]
        ));
        assert!(matches!(
            opt(&reply, OptionCode::DomainNameServer),
            Some(DhcpOption::DomainNameServer(d)) if d == &vec![GW]
        ));
        assert!(matches!(
            opt(&reply, OptionCode::ServerIdentifier),
            Some(DhcpOption::ServerIdentifier(s)) if *s == GW
        ));
    }

    #[test]
    fn request_for_an_offered_address_is_acked() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();
        let offer = respond(&request(MessageType::Discover), &c, &mut l, now).unwrap();

        let mut req = request(MessageType::Request);
        req.opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offer.yiaddr()));

        let ack = respond(&req, &c, &mut l, now).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert_eq!(ack.yiaddr(), offer.yiaddr());
    }

    /// The phone that walked in from another network still holding a lease.
    #[test]
    fn request_for_a_foreign_subnet_is_naked() {
        let (c, mut l) = (cfg(), leases());
        let mut req = request(MessageType::Request);
        req.opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 1, 2, 3)));

        let nak = respond(&req, &c, &mut l, Instant::now()).unwrap();
        assert_eq!(kind_of(&nak), MessageType::Nak);
        assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn a_request_naming_another_server_is_ignored() {
        let (c, mut l) = (cfg(), leases());
        let mut req = request(MessageType::Request);
        req.opts_mut()
            .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(
                192, 168, 42, 99,
            )));
        req.opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                192, 168, 42, 10,
            )));

        assert!(respond(&req, &c, &mut l, Instant::now()).is_none());
    }

    #[test]
    fn a_renewing_client_is_acked_from_ciaddr() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();
        let held = Ipv4Addr::new(192, 168, 42, 11);
        l.commit(CLIENT, held, now);

        let mut req = request(MessageType::Request);
        req.set_ciaddr(held);

        let ack = respond(&req, &c, &mut l, now).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert_eq!(ack.yiaddr(), held);
    }

    #[test]
    fn release_gets_no_reply_and_frees_the_address() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 168, 42, 10);
        l.commit(CLIENT, ip, now);

        let mut rel = request(MessageType::Release);
        rel.set_ciaddr(ip);
        assert!(respond(&rel, &c, &mut l, now).is_none());
        assert!(l.may_use(OTHER, ip, now));
    }

    #[test]
    fn decline_of_our_own_lease_gets_no_reply_and_withdraws_it() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 168, 42, 10);
        l.commit(CLIENT, ip, now);

        let mut dec = request(MessageType::Decline);
        dec.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        assert!(respond(&dec, &c, &mut l, now).is_none());
        assert!(
            !l.may_use(CLIENT, ip, now),
            "declined address must be withdrawn"
        );
        assert!(!l.may_use(OTHER, ip, now), "from everyone");

        // The client starts over and is steered elsewhere.
        let offer = respond(&request(MessageType::Discover), &c, &mut l, now).unwrap();
        assert_eq!(kind_of(&offer), MessageType::Offer);
        assert_ne!(offer.yiaddr(), ip);
    }

    /// Any client on the AP can put any MAC in chaddr. A DECLINE naming an
    /// address it does not hold must not evict the client that does, nor
    /// take the address out of the pool.
    #[test]
    fn decline_of_someone_elses_lease_is_ignored() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();
        let ip = Ipv4Addr::new(192, 168, 42, 10);
        l.commit(OTHER, ip, now);

        let mut dec = request(MessageType::Decline);
        dec.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        assert!(respond(&dec, &c, &mut l, now).is_none());

        // OTHER renews and is still ACKed for its address.
        let mut renew = request(MessageType::Request);
        renew.set_chaddr(&OTHER).set_ciaddr(ip);
        let ack = respond(&renew, &c, &mut l, now).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert_eq!(ack.yiaddr(), ip);
    }

    /// Declining every pool address it was never given must leave the pool
    /// usable for the next client.
    #[test]
    fn declines_for_unleased_addresses_do_not_drain_the_pool() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();
        for last in 10..=12u8 {
            let mut dec = request(MessageType::Decline);
            dec.opts_mut()
                .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                    192, 168, 42, last,
                )));
            assert!(respond(&dec, &c, &mut l, now).is_none());
        }

        let mut disc = request(MessageType::Discover);
        disc.set_chaddr(&OTHER);
        let offer = respond(&disc, &c, &mut l, now).unwrap();
        assert_eq!(offer.yiaddr(), Ipv4Addr::new(192, 168, 42, 10));
    }

    /// The residual starvation risk, pinned so it stays bounded: REQUESTs
    /// under made-up MACs can fill the pool, but only for one lease time.
    #[test]
    fn a_pool_filled_by_spoofed_requests_recovers_after_a_lease_time() {
        let (c, mut l) = (cfg(), leases());
        let t0 = Instant::now();
        for last in 10..=12u8 {
            let mut req = request(MessageType::Request);
            req.set_chaddr(&[0x02, 0, 0, 0, 0, last]);
            req.opts_mut()
                .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                    192, 168, 42, last,
                )));
            let ack = respond(&req, &c, &mut l, t0).unwrap();
            assert_eq!(kind_of(&ack), MessageType::Ack);
        }

        let mut disc = request(MessageType::Discover);
        disc.set_chaddr(&OTHER);
        assert!(respond(&disc, &c, &mut l, t0).is_none(), "pool is full");

        let later = t0 + l.lease_time();
        let offer = respond(&disc, &c, &mut l, later).unwrap();
        assert_eq!(kind_of(&offer), MessageType::Offer);
    }

    #[test]
    fn inform_is_acked_with_options_but_no_address_or_lease() {
        let (c, mut l) = (cfg(), leases());
        let mut inf = request(MessageType::Inform);
        inf.set_ciaddr(Ipv4Addr::new(192, 168, 42, 50));

        let ack = respond(&inf, &c, &mut l, Instant::now()).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert_eq!(ack.yiaddr(), Ipv4Addr::UNSPECIFIED);
        assert!(opt(&ack, OptionCode::AddressLeaseTime).is_none());
        assert!(opt(&ack, OptionCode::CaptivePortal).is_some());
    }

    #[test]
    fn relayed_and_non_request_messages_are_ignored() {
        let (c, mut l) = (cfg(), leases());
        let now = Instant::now();

        let mut relayed = request(MessageType::Discover);
        relayed.set_giaddr(Ipv4Addr::new(10, 0, 0, 1));
        assert!(respond(&relayed, &c, &mut l, now).is_none());

        let mut reply_op = request(MessageType::Discover);
        reply_op.set_opcode(Opcode::BootReply);
        assert!(respond(&reply_op, &c, &mut l, now).is_none());

        // Another server's OFFER on our link is not ours to answer.
        assert!(respond(&request(MessageType::Offer), &c, &mut l, now).is_none());
    }

    #[test]
    fn a_message_without_a_message_type_is_ignored() {
        let (c, mut l) = (cfg(), leases());
        let mut m = Message::default();
        m.set_opcode(Opcode::BootRequest).set_chaddr(&CLIENT);
        assert!(respond(&m, &c, &mut l, Instant::now()).is_none());
    }

    #[test]
    fn discover_on_an_exhausted_pool_is_dropped_silently() {
        let c = cfg();
        let mut l = Leases::with_lease_time(
            Ipv4Addr::new(192, 168, 42, 10),
            Ipv4Addr::new(192, 168, 42, 10),
            Duration::from_secs(600),
        );
        let now = Instant::now();
        l.commit([1, 2, 3, 4, 5, 6], Ipv4Addr::new(192, 168, 42, 10), now);

        assert!(respond(&request(MessageType::Discover), &c, &mut l, now).is_none());
    }

    /// The reply has to survive a real encode/decode round trip, not just
    /// look right in memory.
    #[test]
    fn the_offer_round_trips_on_the_wire() {
        let (c, mut l) = (cfg(), leases());
        let reply = respond(&request(MessageType::Discover), &c, &mut l, Instant::now()).unwrap();

        let mut buf = Vec::new();
        reply.encode(&mut Encoder::new(&mut buf)).unwrap();

        let decoded = Message::decode(&mut Decoder::new(&buf)).unwrap();
        assert_eq!(decoded.xid(), 0xdead_beef);
        assert_eq!(decoded.yiaddr(), Ipv4Addr::new(192, 168, 42, 10));
        assert_eq!(kind_of(&decoded), MessageType::Offer);
        assert!(matches!(
            decoded.opts().get(OptionCode::CaptivePortal),
            Some(DhcpOption::CaptivePortal(_))
        ));
    }
}
