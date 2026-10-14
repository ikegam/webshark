//! Server-side per-second throughput history, so a browser that connects can
//! draw the last few minutes immediately instead of starting from an empty
//! chart. Direction classification mirrors `classify()`/`direction()` in
//! static/js/app.js; keep the two in sync.

use std::collections::VecDeque;
use std::net::IpAddr;

/// Seconds of history kept (matches the longest range in the UI).
pub const HISTORY_SECONDS: i64 = 900;
/// A packet this far behind the newest bucket means the clock was stepped
/// back (e.g. NTP after boot); start the history over instead of dropping
/// every packet until wall time catches up.
const CLOCK_STEP_BACK: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// WAN -> LAN
    Down,
    /// LAN -> WAN
    Up,
    /// LAN <-> LAN (or anything not crossing the boundary)
    Internal,
}

#[derive(Debug, Clone, Copy)]
struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    fn parse(cidr: &str) -> Option<Net> {
        let (addr, prefix) = cidr.split_once('/')?;
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Net { addr, prefix })
    }

    /// The network or broadcast address of an IPv4 subnet (/30 or larger):
    /// valid destinations, but never the address of a device.
    fn is_v4_subnet_edge(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip))
                if self.prefix <= 30 && self.contains(&IpAddr::V4(*ip)) =>
            {
                let host_bits = u32::MAX >> self.prefix;
                let ip = u32::from(*ip);
                let base = u32::from(net) & !host_bits;
                ip == base || ip == base | host_bits
            }
            _ => false,
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}

const BUILTIN_LOCAL: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "100.64.0.0/10",
    "fe80::/10",
    "fc00::/7",
    "::1/128",
];

/// Decides whether an address is on our side of the gateway.
#[derive(Debug, Clone, Default)]
pub struct Classifier {
    /// LAN networks plus private/link-local ranges: "on our side" for direction.
    nets: Vec<Net>,
    /// Only the gateway's actual LAN networks (plus link-local): where LAN
    /// devices live. Private ranges beyond the gateway (VPN, CGNAT) are not.
    lan: Vec<Net>,
    self_ips: Vec<IpAddr>,
}

impl Classifier {
    pub fn new(lan_cidrs: &[String], self_ips: &[String]) -> Self {
        let nets = lan_cidrs
            .iter()
            .map(String::as_str)
            .chain(BUILTIN_LOCAL.iter().copied())
            .filter_map(Net::parse)
            .collect();
        let mut lan: Vec<Net> = lan_cidrs.iter().filter_map(|c| Net::parse(c)).collect();
        if lan.is_empty() {
            // Not on a router (no LAN interfaces detected): fall back to private ranges.
            lan = BUILTIN_LOCAL.iter().filter_map(|c| Net::parse(c)).collect();
        } else {
            lan.extend(
                ["169.254.0.0/16", "fe80::/10"]
                    .iter()
                    .filter_map(|c| Net::parse(c)),
            );
        }
        let self_ips = self_ips.iter().filter_map(|s| s.parse().ok()).collect();
        Classifier {
            nets,
            lan,
            self_ips,
        }
    }

    /// Anything that is not a routable remote address counts as local:
    /// our own addresses, LAN/private ranges, multicast/broadcast, and
    /// non-IP placeholders such as "Unknown".
    pub fn is_local(&self, addr: &str) -> bool {
        let Ok(ip) = addr.split('%').next().unwrap_or("").parse::<IpAddr>() else {
            return true;
        };
        if ip.is_unspecified() || ip.is_multicast() || self.self_ips.contains(&ip) {
            return true;
        }
        if let IpAddr::V4(v4) = ip {
            if v4.is_broadcast() {
                return true;
            }
        }
        self.nets.iter().any(|n| n.contains(&ip))
    }

    /// The address as an IPv4 LAN device (not us, not multicast/broadcast),
    /// i.e. something worth looking up a hostname for.
    pub fn lan_device_v4(&self, addr: &str) -> Option<std::net::Ipv4Addr> {
        let v4: std::net::Ipv4Addr = addr.parse().ok()?;
        self.is_lan_device(addr).then_some(v4)
    }

    /// A unicast address of some other machine on our side of the gateway
    /// (IPv4 or IPv6; not us, not multicast/broadcast/unspecified).
    pub fn is_lan_device(&self, addr: &str) -> bool {
        let Ok(ip) = addr.split('%').next().unwrap_or("").parse::<IpAddr>() else {
            return false;
        };
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_loopback()
            || self.self_ips.contains(&ip)
        {
            return false;
        }
        if let IpAddr::V4(v4) = ip {
            if v4.is_broadcast() {
                return false;
            }
        }
        // Subnet broadcast / network address of a LAN (e.g. 192.168.0.255 on a /24).
        if self.lan.iter().any(|n| n.is_v4_subnet_edge(&ip)) {
            return false;
        }
        self.lan.iter().any(|n| n.contains(&ip))
    }

    pub fn direction(&self, src: &str, dst: &str) -> Direction {
        match (self.is_local(src), self.is_local(dst)) {
            (true, false) => Direction::Up,
            (false, true) => Direction::Down,
            _ => Direction::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Bucket {
    sec: i64,
    down: u64,
    up: u64,
    internal: u64,
    pkts: u64,
}

#[derive(Debug, Clone, Default)]
pub struct History {
    buckets: VecDeque<Bucket>,
}

impl History {
    pub fn add(&mut self, timestamp: f64, dir: Direction, bytes: u32) {
        let sec = timestamp.floor() as i64;
        if self
            .buckets
            .back()
            .is_some_and(|b| sec < b.sec - CLOCK_STEP_BACK)
        {
            self.buckets.clear();
        }
        let newest = self.buckets.back().map(|b| b.sec);
        let bucket = match newest {
            Some(n) if sec > n => {
                self.buckets.push_back(Bucket {
                    sec,
                    ..Default::default()
                });
                self.buckets.back_mut()
            }
            None => {
                self.buckets.push_back(Bucket {
                    sec,
                    ..Default::default()
                });
                self.buckets.back_mut()
            }
            // Slightly out-of-order packet: add to its bucket, creating it in
            // order if that second had no packets yet.
            Some(_) => {
                let pos = self.buckets.partition_point(|b| b.sec < sec);
                if self.buckets.get(pos).is_none_or(|b| b.sec != sec) {
                    self.buckets.insert(
                        pos,
                        Bucket {
                            sec,
                            ..Default::default()
                        },
                    );
                }
                self.buckets.get_mut(pos)
            }
        };
        if let Some(b) = bucket {
            let bytes = u64::from(bytes);
            match dir {
                Direction::Down => b.down += bytes,
                Direction::Up => b.up += bytes,
                Direction::Internal => b.internal += bytes,
            }
            b.pkts += 1;
        }
        let newest = self.buckets.back().map_or(sec, |b| b.sec);
        while self
            .buckets
            .front()
            .is_some_and(|b| b.sec <= newest - HISTORY_SECONDS)
        {
            self.buckets.pop_front();
        }
    }

    /// `[sec, down_bytes, up_bytes, internal_bytes, packets]` per second,
    /// oldest first. Clients subscribe to the live stream before taking this
    /// snapshot, so every packet is in exactly one of the two.
    pub fn snapshot(&self) -> Vec<[i64; 5]> {
        self.buckets
            .iter()
            .map(|b| {
                [
                    b.sec,
                    b.down as i64,
                    b.up as i64,
                    b.internal as i64,
                    b.pkts as i64,
                ]
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::new(
            &["192.168.0.1/24".into(), "2409:10:bec0:4201::1/64".into()],
            &["192.168.0.1".into(), "160.13.93.49".into()],
        )
    }

    #[test]
    fn classifies_lan_wan_and_special_addresses() {
        let c = classifier();
        assert!(c.is_local("192.168.0.109"));
        assert!(c.is_local("2409:10:bec0:4201:44a7:97ad:4a05:cff3"));
        assert!(c.is_local("fe80::1"));
        assert!(c.is_local("160.13.93.49")); // our own WAN address
        assert!(c.is_local("224.0.0.251"));
        assert!(c.is_local("ff02::fb"));
        assert!(c.is_local("255.255.255.255"));
        assert!(c.is_local("Unknown"));
        assert!(!c.is_local("8.8.8.8"));
        assert!(!c.is_local("2404:6800:4004:6::1"));
        assert!(!c.is_local("2409:10:bec0:4200::5")); // upstream link, not LAN
    }

    #[test]
    fn lan_device_v4_filters_non_devices() {
        let c = classifier();
        assert_eq!(
            c.lan_device_v4("192.168.0.129"),
            Some("192.168.0.129".parse().unwrap())
        );
        assert_eq!(c.lan_device_v4("192.168.0.1"), None); // us
        assert_eq!(c.lan_device_v4("192.168.0.255"), None);
        assert_eq!(c.lan_device_v4("224.0.0.251"), None);
        assert_eq!(c.lan_device_v4("8.8.8.8"), None);
        assert_eq!(c.lan_device_v4("fe80::1"), None);
        // Private, but beyond the gateway (VPN / CGNAT): not a LAN device.
        assert!(!c.is_lan_device("10.8.0.5"));
        assert!(!c.is_lan_device("100.64.1.1"));
        assert!(c.is_lan_device("fe80::1234"));
        assert!(c.is_local("10.8.0.5")); // still "our side" for direction
    }

    #[test]
    fn subnet_broadcast_and_network_addresses_are_not_devices() {
        let c = classifier(); // LAN 192.168.0.0/24
        assert!(!c.is_lan_device("192.168.0.255"));
        assert!(!c.is_lan_device("192.168.0.0"));
        assert!(c.is_lan_device("192.168.0.254"));
        // Computed from the real prefix, not "last octet is 255".
        let wide = Classifier::new(&["10.1.2.3/16".into()], &[]);
        assert!(wide.is_lan_device("10.1.0.255"));
        assert!(!wide.is_lan_device("10.1.255.255"));
        let small = Classifier::new(&["10.9.9.1/25".into()], &[]);
        assert!(!small.is_lan_device("10.9.9.127"));
        assert!(small.is_lan_device("10.9.9.100"));
    }

    #[test]
    fn direction_follows_the_boundary() {
        let c = classifier();
        assert_eq!(c.direction("192.168.0.109", "8.8.8.8"), Direction::Up);
        assert_eq!(
            c.direction("2404:6800:4004:6::1", "192.168.0.129"),
            Direction::Down
        );
        assert_eq!(
            c.direction("192.168.0.108", "192.168.0.10"),
            Direction::Internal
        );
    }

    #[test]
    fn history_buckets_ordering_and_trimming() {
        let mut h = History::default();
        h.add(100.2, Direction::Down, 1000);
        h.add(100.9, Direction::Up, 10);
        h.add(101.0, Direction::Internal, 5);
        h.add(100.5, Direction::Down, 1); // out of order
        h.add(104.0, Direction::Down, 7);
        h.add(102.5, Direction::Up, 3); // late packet for a second with no bucket yet
        assert_eq!(
            h.snapshot(),
            vec![
                [100, 1001, 10, 0, 3],
                [101, 0, 0, 5, 1],
                [102, 0, 3, 0, 1],
                [104, 7, 0, 0, 1]
            ]
        );

        // Clock stepped back far: start over rather than drop everything.
        let mut h2 = History::default();
        h2.add(10_000.0, Direction::Down, 1);
        h2.add(9_000.0, Direction::Down, 2);
        assert_eq!(h2.snapshot(), vec![[9_000, 2, 0, 0, 1]]);

        h.add(100.0 + HISTORY_SECONDS as f64 + 1.0, Direction::Down, 1);
        assert!(h.snapshot().iter().all(|b| b[0] > 100));
    }
}
