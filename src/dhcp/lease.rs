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

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
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
    /// The pool as a range of address bits rather than a materialised list,
    /// so memory does not scale with its width. `parse_dhcp_range` already
    /// confines it to the gateway's /24, but a startup-time `Vec` sized by
    /// operator input is one typo (`1.0.0.0,192.168.41.255`) away from
    /// allocating billions of entries; keeping this O(1) means that
    /// invariant does not have to hold at a distance.
    pool: RangeInclusive<u32>,
    by_mac: HashMap<MacAddr, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, Lease>,
    /// Addresses a client told us were already in use (DHCPDECLINE). We do
    /// not hand these out again for the life of this process.
    declined: HashSet<Ipv4Addr>,
    lease_time: Duration,
}

impl Leases {
    /// Build a pool spanning `first..=last` inclusive.
    pub fn new(first: Ipv4Addr, last: Ipv4Addr) -> Self {
        Self::with_lease_time(first, last, LEASE_TIME)
    }

    /// An inverted range (`first > last`) is an empty pool.
    pub fn with_lease_time(first: Ipv4Addr, last: Ipv4Addr, lease_time: Duration) -> Self {
        Self {
            pool: first.to_bits()..=last.to_bits(),
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
            declined: HashSet::new(),
            lease_time,
        }
    }

    pub fn lease_time(&self) -> Duration {
        self.lease_time
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.pool.contains(&ip.to_bits())
    }

    fn is_free(&self, ip: Ipv4Addr, now: Instant, for_mac: MacAddr) -> bool {
        if self.declined.contains(&ip) {
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
            .clone()
            .map(Ipv4Addr::from_bits)
            .find(|ip| self.is_free(*ip, now, mac))
    }

    /// Record that `mac` now holds `ip`.
    pub fn commit(&mut self, mac: MacAddr, ip: Ipv4Addr, now: Instant) {
        if let Some(old) = self.by_mac.insert(mac, ip)
            && old != ip
        {
            self.by_ip.remove(&old);
        }
        self.by_ip.insert(
            ip,
            Lease {
                mac,
                expires: now + self.lease_time,
            },
        );
    }

    /// Would an ACK for `ip` be correct for this MAC? Used to decide between
    /// ACK and NAK on a DHCPREQUEST.
    pub fn may_use(&self, mac: MacAddr, ip: Ipv4Addr, now: Instant) -> bool {
        self.contains(ip) && !self.declined.contains(&ip) && self.is_free(ip, now, mac)
    }

    /// DHCPRELEASE: drop the lease.
    pub fn release(&mut self, mac: MacAddr) {
        if let Some(ip) = self.by_mac.remove(&mac) {
            self.by_ip.remove(&ip);
        }
    }

    /// DHCPDECLINE: the client saw an ARP conflict for this address, so
    /// something we do not manage is squatting on it. Never offer it again.
    pub fn decline(&mut self, mac: MacAddr, ip: Ipv4Addr) {
        self.declined.insert(ip);
        if self.by_mac.get(&mac) == Some(&ip) {
            self.by_mac.remove(&mac);
        }
        self.by_ip.remove(&ip);
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
    fn a_declined_address_is_never_offered_again() {
        let mut l = pool();
        let now = Instant::now();
        let ip = l.offer(A, None, now).unwrap();
        l.commit(A, ip, now);
        l.decline(A, ip);

        for _ in 0..4 {
            assert_ne!(l.offer(B, Some(ip), now), Some(ip));
        }
        assert!(!l.may_use(B, ip, now));
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

    /// The pool must not be materialised: a range as wide as the whole
    /// address space is constructed instantly and in constant memory, rather
    /// than allocating sixteen gigabytes and taking the device down at
    /// startup. Config validation keeps such a range from ever getting here;
    /// this pins that `Leases` does not depend on it to stay alive.
    #[test]
    fn a_huge_range_does_not_allocate_the_pool() {
        let mut l = Leases::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255));
        assert!(l.contains(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(
            l.offer(A, None, Instant::now()),
            Some(Ipv4Addr::new(0, 0, 0, 0))
        );
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
