//! The DHCP lease table.
//!
//! In memory only, and deliberately tiny: the access point lives for minutes,
//! serves a handful of phones, and is then torn down. Nothing is persisted.
//!
//! The one behaviour worth more than it looks is **stickiness by MAC**. When
//! a join attempt fails we tear the AP down and raise it again; the user's
//! phone reassociates and asks for a lease. Handing it back the same address
//! it had a moment ago means its browser's existing connection to the portal
//! still makes sense, instead of the page breaking in a second, different way
//! while the user is already confused about the first.
//!
//! ## What an associated client can still do
//!
//! DHCP has no client authentication, and on the setup AP the only identity a
//! client presents is a `chaddr` it chooses itself. Anyone who has joined the
//! AP can therefore send REQUESTs for every pool address under made-up MACs
//! and hold the whole pool for one lease time. Nothing in this table can tell
//! those apart from real phones, so it does not try. What it does guarantee:
//!
//! * leases and DECLINE bans both age out after [`LEASE_TIME`], so a flood
//!   costs the attacker continuous effort rather than poisoning the pool for
//!   the rest of the process;
//! * one MAC's message never removes the lease another MAC holds (short of
//!   spoofing that exact MAC, which no L2 check can rule out).
//!
//! A client already on the AP can disrupt it in cruder ways (deauth frames,
//! plain airtime), so this is the same exposure, not a new one.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Short, because the AP's whole life is measured in minutes and we would
/// rather reclaim a wrongly-held address quickly than hold it correctly.
pub const LEASE_TIME: Duration = Duration::from_secs(600);

pub type MacAddr = [u8; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lease {
    mac: MacAddr,
    expires: Instant,
}

/// A pool of addresses and who currently holds them.
#[derive(Debug)]
pub struct Leases {
    pool: Vec<Ipv4Addr>,
    by_mac: HashMap<MacAddr, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, Lease>,
    /// Addresses a client told us were already in use (DHCPDECLINE), and when
    /// we may try them again. A ban that lasted the whole process would let
    /// one DECLINE per address empty the pool for good; one lease time is long
    /// enough for a genuine squatter to be noticed and short enough that a
    /// bogus ban heals by itself.
    declined: HashMap<Ipv4Addr, Instant>,
    lease_time: Duration,
}

impl Leases {
    /// Build a pool spanning `first..=last` inclusive.
    pub fn new(first: Ipv4Addr, last: Ipv4Addr) -> Self {
        Self::with_lease_time(first, last, LEASE_TIME)
    }

    pub fn with_lease_time(first: Ipv4Addr, last: Ipv4Addr, lease_time: Duration) -> Self {
        let (lo, hi) = (first.to_bits(), last.to_bits());
        let pool = if lo > hi {
            Vec::new()
        } else {
            (lo..=hi).map(Ipv4Addr::from_bits).collect()
        };
        Self {
            pool,
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
            declined: HashMap::new(),
            lease_time,
        }
    }

    pub fn lease_time(&self) -> Duration {
        self.lease_time
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.pool.contains(&ip)
    }

    fn is_declined(&self, ip: Ipv4Addr, now: Instant) -> bool {
        self.declined.get(&ip).is_some_and(|until| *until > now)
    }

    fn is_free(&self, ip: Ipv4Addr, now: Instant, for_mac: MacAddr) -> bool {
        if self.is_declined(ip, now) {
            return false;
        }
        match self.by_ip.get(&ip) {
            None => true,
            Some(l) => l.mac == for_mac || l.expires <= now,
        }
    }

    /// Pick an address for `mac`, honouring a requested address when we can.
    ///
    /// Order: the address this MAC already has, then the one it asked for,
    /// then the first free one.
    pub fn offer(
        &mut self,
        mac: MacAddr,
        requested: Option<Ipv4Addr>,
        now: Instant,
    ) -> Option<Ipv4Addr> {
        if let Some(existing) = self.by_mac.get(&mac).copied()
            && self.is_free(existing, now, mac)
        {
            return Some(existing);
        }

        if let Some(req) = requested
            && self.contains(req)
            && self.is_free(req, now, mac)
        {
            return Some(req);
        }

        self.pool
            .iter()
            .copied()
            .find(|ip| self.is_free(*ip, now, mac))
    }

    /// Record that `mac` now holds `ip`.
    ///
    /// Callers check [`Self::may_use`] first, so if `ip` belonged to another
    /// MAC that lease has expired. That MAC's `by_mac` entry still points at
    /// `ip`, though, and must go: left behind, a later RELEASE or address
    /// change from the old owner would delete the new owner's lease.
    pub fn commit(&mut self, mac: MacAddr, ip: Ipv4Addr, now: Instant) {
        if let Some(old) = self.by_mac.insert(mac, ip)
            && old != ip
        {
            self.remove_lease_if_held_by(old, mac);
        }
        let previous = self.by_ip.insert(
            ip,
            Lease {
                mac,
                expires: now + self.lease_time,
            },
        );
        if let Some(prev) = previous
            && prev.mac != mac
            && self.by_mac.get(&prev.mac) == Some(&ip)
        {
            self.by_mac.remove(&prev.mac);
        }
        // A successful commit means any DECLINE ban on `ip` has lapsed; drop
        // the entry so the map does not grow with dead bans.
        self.declined.remove(&ip);
    }

    /// Drop the lease on `ip` only if `mac` is the one holding it.
    fn remove_lease_if_held_by(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        if self.by_ip.get(&ip).is_some_and(|l| l.mac == mac) {
            self.by_ip.remove(&ip);
        }
    }

    /// Would an ACK for `ip` be correct for this MAC? Used to decide between
    /// ACK and NAK on a DHCPREQUEST.
    pub fn may_use(&self, mac: MacAddr, ip: Ipv4Addr, now: Instant) -> bool {
        self.contains(ip) && self.is_free(ip, now, mac)
    }

    /// DHCPRELEASE: drop the lease.
    pub fn release(&mut self, mac: MacAddr) {
        if let Some(ip) = self.by_mac.remove(&mac) {
            self.remove_lease_if_held_by(ip, mac);
        }
    }

    /// DHCPDECLINE: the client saw an ARP conflict for this address, so
    /// something we do not manage is squatting on it. Stop offering it for
    /// one lease time.
    ///
    /// RFC 2131 4.3.3 has a client decline an address the server gave *it*.
    /// So the DECLINE is honoured only when `mac` currently holds an unexpired
    /// lease on `ip`; anything else is ignored. Without that check, any client
    /// on the AP could ban every pool address and evict other clients'
    /// leases by naming them in DECLINEs. Returns whether it was honoured.
    pub fn decline(&mut self, mac: MacAddr, ip: Ipv4Addr, now: Instant) -> bool {
        let holds_it = self
            .by_ip
            .get(&ip)
            .is_some_and(|l| l.mac == mac && l.expires > now);
        if !holds_it {
            return false;
        }
        self.by_ip.remove(&ip);
        if self.by_mac.get(&mac) == Some(&ip) {
            self.by_mac.remove(&mac);
        }
        self.declined.insert(ip, now + self.lease_time);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddr = [0x02, 0, 0, 0, 0, 0x01];
    const B: MacAddr = [0x02, 0, 0, 0, 0, 0x02];

    fn pool() -> Leases {
        Leases::new(
            Ipv4Addr::new(192, 168, 42, 10),
            Ipv4Addr::new(192, 168, 42, 12),
        )
    }

    #[test]
    fn allocates_the_first_free_address() {
        let mut l = pool();
        let now = Instant::now();
        assert_eq!(l.offer(A, None, now), Some(Ipv4Addr::new(192, 168, 42, 10)));
    }

    /// The property that keeps a phone's portal session coherent across the
    /// AP bounce that a failed join forces.
    #[test]
    fn the_same_mac_gets_the_same_address_again() {
        let mut l = pool();
        let now = Instant::now();

        let first = l.offer(A, None, now).unwrap();
        l.commit(A, first, now);

        // Another client takes the next address.
        let other = l.offer(B, None, now).unwrap();
        l.commit(B, other, now);
        assert_ne!(first, other);

        // The AP bounces; A comes back and must get its address back.
        assert_eq!(l.offer(A, None, now), Some(first));
    }

    #[test]
    fn honours_a_requested_address_when_free() {
        let mut l = pool();
        let now = Instant::now();
        let want = Ipv4Addr::new(192, 168, 42, 12);
        assert_eq!(l.offer(A, Some(want), now), Some(want));
    }

    #[test]
    fn ignores_a_requested_address_outside_the_pool() {
        let mut l = pool();
        let now = Instant::now();
        let outside = Ipv4Addr::new(10, 0, 0, 5);
        let got = l.offer(A, Some(outside), now).unwrap();
        assert!(l.contains(got));
        assert_ne!(got, outside);
    }

    #[test]
    fn ignores_a_requested_address_held_by_someone_else() {
        let mut l = pool();
        let now = Instant::now();
        let taken = l.offer(B, None, now).unwrap();
        l.commit(B, taken, now);

        let got = l.offer(A, Some(taken), now).unwrap();
        assert_ne!(got, taken);
    }

    #[test]
    fn exhaustion_yields_none() {
        let mut l = pool();
        let now = Instant::now();
        for i in 0..3u8 {
            let mac = [0x02, 0, 0, 0, 0, i];
            let ip = l
                .offer(mac, None, now)
                .expect("pool should still have room");
            l.commit(mac, ip, now);
        }
        assert_eq!(l.offer([0x02, 0, 0, 0, 0, 0xff], None, now), None);
    }

    #[test]
    fn an_expired_lease_is_reusable() {
        let mut l = pool();
        let t0 = Instant::now();

        // Fill the three-address pool with three holders, none of them
        // `NEWCOMER`, so the pool is genuinely exhausted for a fourth client.
        const NEWCOMER: MacAddr = [0x02, 0, 0, 0, 0, 0xff];
        for i in 0..3u8 {
            let mac = [0x02, 0, 0, 0, 0, 0x10 + i];
            let ip = l.offer(mac, None, t0).expect("pool should still have room");
            l.commit(mac, ip, t0);
        }
        assert_eq!(
            l.offer(NEWCOMER, None, t0),
            None,
            "pool should be exhausted"
        );

        // Once every lease has aged out, the addresses come back.
        let later = t0 + LEASE_TIME + Duration::from_secs(1);
        assert_eq!(
            l.offer(NEWCOMER, None, later),
            Some(Ipv4Addr::new(192, 168, 42, 10))
        );
    }

    #[test]
    fn release_frees_the_address() {
        let mut l = pool();
        let now = Instant::now();
        let ip = l.offer(A, None, now).unwrap();
        l.commit(A, ip, now);
        l.release(A);
        assert_eq!(l.offer(B, Some(ip), now), Some(ip));
    }

    #[test]
    fn a_declined_address_is_not_offered_for_a_lease_time() {
        let mut l = pool();
        let now = Instant::now();
        let ip = l.offer(A, None, now).unwrap();
        l.commit(A, ip, now);
        assert!(l.decline(A, ip, now));

        for _ in 0..4 {
            assert_ne!(l.offer(B, Some(ip), now), Some(ip));
        }
        assert!(!l.may_use(B, ip, now));
        // The decliner itself must not be steered straight back onto the
        // conflicting address either.
        assert_ne!(l.offer(A, None, now), Some(ip));
        assert!(!l.may_use(A, ip, now));

        let almost = now + LEASE_TIME - Duration::from_secs(1);
        assert!(!l.may_use(B, ip, almost));
    }

    /// A bogus DECLINE (or a squatter that has since gone) must not cost the
    /// pool that address for the rest of the process.
    #[test]
    fn a_declined_address_comes_back_after_a_lease_time() {
        let mut l = pool();
        let now = Instant::now();
        let ip = l.offer(A, None, now).unwrap();
        l.commit(A, ip, now);
        assert!(l.decline(A, ip, now));

        let later = now + LEASE_TIME;
        assert!(l.may_use(B, ip, later));
        assert_eq!(l.offer(B, Some(ip), later), Some(ip));
        l.commit(B, ip, later);
        assert!(!l.may_use(A, ip, later), "B now holds it");
    }

    /// RFC 2131 has a client decline an address it was given. A DECLINE
    /// naming somebody else's lease must neither evict that client nor ban
    /// the address.
    #[test]
    fn a_decline_for_another_macs_lease_is_ignored() {
        let mut l = pool();
        let now = Instant::now();
        let ip = l.offer(B, None, now).unwrap();
        l.commit(B, ip, now);

        assert!(!l.decline(A, ip, now));

        assert!(l.may_use(B, ip, now), "B must keep its lease");
        assert_eq!(l.offer(B, None, now), Some(ip), "and get it back");
        assert!(!l.may_use(A, ip, now), "and A still may not take it");
    }

    /// Without the ownership check, one client could walk the pool sending a
    /// DECLINE per address and leave nothing for anyone else.
    #[test]
    fn a_decline_for_an_unleased_address_is_ignored() {
        let mut l = pool();
        let now = Instant::now();
        for last in 10..=12u8 {
            assert!(!l.decline(A, Ipv4Addr::new(192, 168, 42, last), now));
        }
        assert_eq!(l.offer(B, None, now), Some(Ipv4Addr::new(192, 168, 42, 10)));
    }

    /// Once A's lease has run out it is no longer A's to decline; the address
    /// is simply free.
    #[test]
    fn a_decline_for_an_expired_lease_is_ignored() {
        let mut l = pool();
        let now = Instant::now();
        let ip = l.offer(A, None, now).unwrap();
        l.commit(A, ip, now);

        let later = now + LEASE_TIME + Duration::from_secs(1);
        assert!(!l.decline(A, ip, later));
        assert!(l.may_use(B, ip, later));
    }

    /// `A` held `ip`, let it expire, and `ip` went to `B`. Returns the table
    /// at that point and a time after the hand-over.
    fn handed_over_from_a_to_b(ip: Ipv4Addr) -> (Leases, Instant) {
        let mut l = pool();
        let t0 = Instant::now();
        l.commit(A, ip, t0);

        let later = t0 + LEASE_TIME + Duration::from_secs(1);
        assert!(l.may_use(B, ip, later));
        l.commit(B, ip, later);
        (l, later)
    }

    /// A's old `by_mac` entry must not survive the hand-over, or A's next
    /// RELEASE would delete B's lease.
    #[test]
    fn a_previous_holders_release_does_not_evict_the_new_holder() {
        let ip = Ipv4Addr::new(192, 168, 42, 10);
        let (mut l, later) = handed_over_from_a_to_b(ip);

        l.release(A);

        // "B may use it" would hold whether or not B's lease survived (a
        // free address is usable too), so check that it is still B's: no
        // one else may take it.
        assert!(
            !l.may_use(A, ip, later),
            "B's lease must survive A's RELEASE"
        );
        assert_ne!(l.offer(A, None, later), Some(ip));
    }

    /// Same, for A coming back and committing a different address.
    #[test]
    fn a_previous_holder_moving_address_does_not_evict_the_new_holder() {
        let ip = Ipv4Addr::new(192, 168, 42, 10);
        let other = Ipv4Addr::new(192, 168, 42, 11);
        let (mut l, later) = handed_over_from_a_to_b(ip);

        assert!(l.may_use(A, other, later));
        l.commit(A, other, later);

        assert!(!l.may_use(A, ip, later), "B's lease must survive A's move");
        assert_eq!(l.offer(B, None, later), Some(ip));
    }

    /// A phone that wandered in still holding a lease from its home network
    /// must be NAKed, not ACKed.
    #[test]
    fn an_address_outside_the_pool_may_not_be_used() {
        let l = pool();
        let now = Instant::now();
        assert!(!l.may_use(A, Ipv4Addr::new(10, 1, 2, 3), now));
        assert!(l.may_use(A, Ipv4Addr::new(192, 168, 42, 10), now));
    }

    #[test]
    fn an_inverted_range_yields_an_empty_pool() {
        let mut l = Leases::new(
            Ipv4Addr::new(192, 168, 42, 200),
            Ipv4Addr::new(192, 168, 42, 10),
        );
        assert_eq!(l.offer(A, None, Instant::now()), None);
    }

    #[test]
    fn committing_a_new_address_releases_the_old_one() {
        let mut l = pool();
        let now = Instant::now();
        let first = Ipv4Addr::new(192, 168, 42, 10);
        let second = Ipv4Addr::new(192, 168, 42, 11);
        l.commit(A, first, now);
        l.commit(A, second, now);
        assert!(
            l.may_use(B, first, now),
            "the old address should be free again"
        );
    }
}
