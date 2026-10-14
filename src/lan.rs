//! LAN inventory: what this gateway can learn about the local network.
//!
//! Built from captured packets (devices keyed by MAC, their addresses,
//! traffic, services they answer on, DHCP hostnames, CDP/LLDP neighbours and
//! LAN-internal traffic between devices) plus the gateway's own interface,
//! route and neighbour tables. All tables are bounded.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::history::{Classifier, Direction};
use crate::types::PacketInfo;

const MAX_DEVICES: usize = 1024;
const MAX_IPS_PER_DEVICE: usize = 16;
const MAX_PORTS_PER_DEVICE: usize = 32;
const MAX_SERVICES_PER_DEVICE: usize = 32;
const MAX_PAIRS: usize = 4096;
const MAX_L2: usize = 64;

/// Link-layer neighbour announcement (CDP or LLDP).
#[derive(Debug, Clone, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct L2Info {
    pub proto: String,
    pub name: Option<String>,
    pub port: Option<String>,
    pub platform: Option<String>,
    pub mgmt: Option<String>,
    pub vlan: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Device {
    pub mac: String,
    /// address -> last seen (capture time, s)
    pub ips: BTreeMap<String, f64>,
    pub first: f64,
    pub last: f64,
    /// bytes sent to / received from the internet, and LAN-internal bytes
    pub up: u64,
    pub down: u64,
    pub internal: u64,
    pub pkts: u64,
    /// "tcp/443" -> times seen answering a connection (SYN+ACK)
    pub ports: BTreeMap<String, u64>,
    /// mDNS service types advertised, e.g. "_airplay._tcp"
    pub services: BTreeSet<String>,
    pub dhcp_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Pair {
    pub a: String,
    pub b: String,
    pub bytes: u64,
    pub last: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct L2Neighbor {
    pub mac: String,
    /// Kept separately: devices often send both, and they carry different
    /// details (CDP: model; LLDP: OS description, management address).
    pub cdp: Option<L2Info>,
    pub lldp: Option<L2Info>,
    pub last: f64,
}

#[derive(Debug, Default, Clone)]
pub struct Inventory {
    pub started: Option<f64>,
    devices: HashMap<String, Device>,
    pairs: HashMap<(String, String), Pair>,
    l2: HashMap<String, L2Neighbor>,
}

/// Individual (not multicast/broadcast) MAC address: group bit clear.
pub fn is_unicast_mac(mac: &str) -> bool {
    mac.get(0..2)
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x01 == 0)
}

/// mDNS record name -> service type ("ENIAC._airplay._tcp.local" -> "_airplay._tcp").
pub fn service_type(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.').strip_suffix(".local")?;
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    if n < 2 {
        return None;
    }
    let (svc, proto) = (labels[n - 2], labels[n - 1]);
    if !(proto == "_tcp" || proto == "_udp") || !svc.starts_with('_') || svc.len() < 2 {
        return None;
    }
    if svc == "_services" || svc == "_dns-sd" || svc.contains("_sub") {
        return None;
    }
    Some(format!("{}.{}", svc.to_ascii_lowercase(), proto))
}

fn evict_oldest<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    max: usize,
    last: impl Fn(&V) -> f64,
) {
    if map.len() <= max {
        return;
    }
    let mut entries: Vec<(K, f64)> = map.iter().map(|(k, v)| (k.clone(), last(v))).collect();
    entries.sort_by(|a, b| a.1.total_cmp(&b.1));
    for (k, _) in entries.into_iter().take(map.len() - max * 9 / 10) {
        map.remove(&k);
    }
}

impl Inventory {
    fn device(&mut self, mac: &str, t: f64) -> &mut Device {
        let d = self
            .devices
            .entry(mac.to_string())
            .or_insert_with(|| Device {
                mac: mac.to_string(),
                first: t,
                last: t,
                ..Default::default()
            });
        d.last = d.last.max(t);
        d
    }

    fn touch_ip(d: &mut Device, ip: &str, t: f64) {
        d.ips.insert(ip.to_string(), t);
        if d.ips.len() > MAX_IPS_PER_DEVICE {
            if let Some(oldest) = d
                .ips
                .iter()
                .min_by(|a, b| a.1.total_cmp(b.1))
                .map(|(k, _)| k.clone())
            {
                d.ips.remove(&oldest);
            }
        }
    }

    /// Account one packet. `self_macs` are this gateway's own interfaces.
    pub fn observe(&mut self, p: &PacketInfo, c: &Classifier, self_macs: &HashSet<String>) {
        let t = p.timestamp;
        self.started.get_or_insert(t);
        let len = u64::from(p.length);

        let lan_mac = |ip: &str, mac: &Option<String>| -> Option<String> {
            let mac = mac.as_deref()?;
            (c.is_lan_device(ip) && is_unicast_mac(mac) && !self_macs.contains(mac))
                .then(|| mac.to_string())
        };
        let src = lan_mac(&p.src_ip, &p.src_mac);
        let dst = lan_mac(&p.dst_ip, &p.dst_mac);
        let dir = c.direction(&p.src_ip, &p.dst_ip);

        if let Some(mac) = &src {
            let d = self.device(mac, t);
            Self::touch_ip(d, &p.src_ip, t);
            d.pkts += 1;
            match dir {
                Direction::Up => d.up += len,
                Direction::Internal => d.internal += len,
                Direction::Down => {}
            }
            // SYN+ACK from the device: it is serving on this port.
            if p.tcp_flags.is_some_and(|f| f & 0x12 == 0x12) {
                if let Some(port) = p.src_port {
                    let key = format!("tcp/{}", port);
                    if d.ports.contains_key(&key) || d.ports.len() < MAX_PORTS_PER_DEVICE {
                        *d.ports.entry(key).or_insert(0) += 1;
                    }
                }
            }
            if p.src_port == Some(5353) {
                for s in &p.mdns_names {
                    if let Some(svc) = service_type(s) {
                        if d.services.len() < MAX_SERVICES_PER_DEVICE {
                            d.services.insert(svc);
                        }
                    }
                }
            }
        }
        if let Some(mac) = &dst {
            let d = self.device(mac, t);
            Self::touch_ip(d, &p.dst_ip, t);
            match dir {
                Direction::Down => d.down += len,
                Direction::Internal => d.internal += len,
                Direction::Up => {}
            }
        }
        if let (Some(a), Some(b)) = (&src, &dst) {
            if a != b {
                let key = if a < b {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                };
                let pair = self.pairs.entry(key.clone()).or_insert_with(|| Pair {
                    a: key.0,
                    b: key.1,
                    ..Default::default()
                });
                pair.bytes += len;
                pair.last = t;
                evict_oldest(&mut self.pairs, MAX_PAIRS, |p| p.last);
            }
        }

        // DHCP requests carry the client's hostname (the source IP may still be 0.0.0.0).
        if let (Some(name), Some(mac)) = (&p.dhcp_hostname, &p.src_mac) {
            if is_unicast_mac(mac) && !self_macs.contains(mac) {
                self.device(mac, t).dhcp_name = Some(name.clone());
            }
        }
        if let (Some(info), Some(mac)) = (&p.l2, &p.src_mac) {
            let n = self.l2.entry(mac.clone()).or_insert_with(|| L2Neighbor {
                mac: mac.clone(),
                cdp: None,
                lldp: None,
                last: t,
            });
            n.last = t;
            if info.proto == "CDP" {
                n.cdp = Some(info.clone());
            } else {
                n.lldp = Some(info.clone());
            }
            evict_oldest(&mut self.l2, MAX_L2, |n| n.last);
        }
        evict_oldest(&mut self.devices, MAX_DEVICES, |d| d.last);
    }

    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }
    pub fn pairs(&self) -> impl Iterator<Item = &Pair> {
        self.pairs.values()
    }
    pub fn l2(&self) -> impl Iterator<Item = &L2Neighbor> {
        self.l2.values()
    }
}

// ---------- this gateway's own view (ip -j ...) ----------

fn ip_json(args: &[&str]) -> Value {
    std::process::Command::new("ip")
        .arg("-j")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())
        .unwrap_or(Value::Array(Vec::new()))
}

/// MAC addresses of this machine's interfaces.
pub fn own_macs() -> HashSet<String> {
    parse_own_macs(&ip_json(&["link", "show"]))
}

pub fn parse_own_macs(links: &Value) -> HashSet<String> {
    links
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| l.get("address")?.as_str())
        .filter(|m| m.len() == 17 && *m != "00:00:00:00:00:00")
        .map(|m| m.to_ascii_lowercase())
        .collect()
}

/// Interfaces with role ("wan" carries a default route, "lan" has a global
/// address, otherwise "down"/"other"), addresses and state.
pub fn parse_interfaces(addrs: &Value, wan: &[String]) -> Vec<Value> {
    addrs
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| {
            let name = i.get("ifname")?.as_str()?;
            if name == "lo" {
                return None;
            }
            let state = i
                .get("operstate")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN");
            let mut global = false;
            let addrs: Vec<Value> = i
                .get("addr_info")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|a| {
                    let local = a.get("local")?.as_str()?;
                    let scope = a.get("scope").and_then(Value::as_str).unwrap_or("");
                    global |= scope == "global";
                    Some(json!({
                        "addr": local,
                        "prefix": a.get("prefixlen"),
                        "family": a.get("family"),
                        "scope": scope,
                    }))
                })
                .collect();
            let role = if wan.iter().any(|w| w == name) {
                "wan"
            } else if state == "DOWN" {
                "down"
            } else if global {
                "lan"
            } else {
                "other"
            };
            Some(json!({
                "name": name,
                "state": state,
                "mac": i.get("address"),
                "type": i.get("link_type"),
                "mtu": i.get("mtu"),
                "role": role,
                "addrs": addrs,
            }))
        })
        .collect()
}

pub fn parse_routes(routes: &Value, family: &str) -> Vec<Value> {
    routes
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| json!({ "family": family, "dev": r.get("dev"), "via": r.get("gateway") }))
        .collect()
}

pub fn parse_neighbors(neigh: &Value) -> Vec<Value> {
    neigh
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| {
            let state = n
                .get("state")
                .and_then(Value::as_array)
                .and_then(|s| s.first())
                .and_then(Value::as_str)
                .unwrap_or("");
            let mac = n.get("lladdr").and_then(Value::as_str)?;
            if state == "FAILED" || state == "INCOMPLETE" {
                return None;
            }
            Some(json!({
                "ip": n.get("dst"),
                "dev": n.get("dev"),
                "mac": mac.to_ascii_lowercase(),
                "state": state,
                "router": n.get("router").is_some(),
            }))
        })
        .collect()
}

/// Everything the LAN view needs, as JSON.
pub fn snapshot(inv: &Inventory, lan_names: &HashMap<String, String>, now: f64) -> Value {
    let v4_routes = ip_json(&["route", "show", "default"]);
    let v6_routes = ip_json(&["-6", "route", "show", "default"]);
    let wan: Vec<String> = [&v4_routes, &v6_routes]
        .iter()
        .flat_map(|r| r.as_array().cloned().unwrap_or_default())
        .filter_map(|r| r.get("dev")?.as_str().map(str::to_string))
        .collect();
    let mut routes = parse_routes(&v4_routes, "inet");
    routes.extend(parse_routes(&v6_routes, "inet6"));
    let neighbors = parse_neighbors(&ip_json(&["neigh", "show"]));

    let devices: Vec<Value> = inv
        .devices()
        .map(|d| {
            let names: BTreeSet<&String> =
                d.ips.keys().filter_map(|ip| lan_names.get(ip)).collect();
            json!({
                "mac": d.mac,
                "vendor": crate::oui::vendor(&d.mac),
                "random_mac": crate::oui::is_local_admin(&d.mac),
                "ips": d.ips,
                "names": names,
                "dhcp_name": d.dhcp_name,
                "first": d.first,
                "last": d.last,
                "up": d.up,
                "down": d.down,
                "internal": d.internal,
                "pkts": d.pkts,
                "ports": d.ports,
                "services": d.services,
            })
        })
        .collect();
    // Vendors for neighbour-table entries not (yet) seen in traffic.
    let neighbor_vendors: HashMap<String, Option<String>> = neighbors
        .iter()
        .filter_map(|n| {
            n.get("mac")?
                .as_str()
                .map(|m| (m.to_string(), crate::oui::vendor(m)))
        })
        .collect();
    let l2: Vec<Value> = inv
        .l2()
        .map(|n| {
            let mut v = serde_json::to_value(n).unwrap_or(Value::Null);
            v["vendor"] = json!(crate::oui::vendor(&n.mac));
            v
        })
        .collect();

    json!({
        "hostname": crate::utils::get_hostname(),
        "now": now,
        "since": inv.started,
        "interfaces": parse_interfaces(&ip_json(&["addr", "show"]), &wan),
        "routes": routes,
        "neighbors": neighbors,
        "neighbor_vendors": neighbor_vendors,
        "devices": devices,
        "pairs": inv.pairs().collect::<Vec<_>>(),
        "l2": l2,
        "oui": crate::oui::db_path().exists(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::new(
            &["192.168.0.1/24".into()],
            &["192.168.0.1".into(), "160.13.93.49".into()],
        )
    }

    fn pkt(src: &str, dst: &str, sm: &str, dm: &str, len: u32) -> PacketInfo {
        PacketInfo {
            timestamp: 100.0,
            src_ip: src.into(),
            dst_ip: dst.into(),
            protocol: "TCP".into(),
            sub_protocol: None,
            app: "tcp".into(),
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            dns_name: None,
            dns_addrs: vec![],
            server_name: None,
            src_mac: Some(sm.into()),
            dst_mac: Some(dm.into()),
            mdns_names: vec![],
            dhcp_hostname: None,
            l2: None,
            length: len,
            info: String::new(),
        }
    }

    const ROUTER: &str = "32:01:02:44:1c:80";
    const PC: &str = "68:24:99:1e:4d:47";
    const NAS: &str = "34:76:c5:94:7f:1d";

    #[test]
    fn counts_wan_and_internal_traffic_per_device() {
        let c = classifier();
        let own: HashSet<String> = [ROUTER.to_string()].into();
        let mut inv = Inventory::default();
        inv.observe(&pkt("192.168.0.108", "8.8.8.8", PC, ROUTER, 100), &c, &own);
        inv.observe(&pkt("8.8.8.8", "192.168.0.108", ROUTER, PC, 1000), &c, &own);
        inv.observe(
            &pkt("192.168.0.108", "192.168.0.10", PC, NAS, 500),
            &c,
            &own,
        );
        inv.observe(
            &pkt("192.168.0.1", "192.168.0.108", ROUTER, PC, 70),
            &c,
            &own,
        ); // router itself

        let pc = inv.devices().find(|d| d.mac == PC).unwrap();
        // Internal = with the NAS (500) + with the router itself (70).
        assert_eq!((pc.up, pc.down, pc.internal), (100, 1000, 570));
        let nas = inv.devices().find(|d| d.mac == NAS).unwrap();
        assert_eq!(nas.internal, 500);
        assert!(inv.devices().all(|d| d.mac != ROUTER));
        let pairs: Vec<_> = inv.pairs().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].bytes, 500);
    }

    #[test]
    fn learns_services_ports_dhcp_and_l2() {
        let c = classifier();
        let own: HashSet<String> = [ROUTER.to_string()].into();
        let mut inv = Inventory::default();

        let mut synack = pkt("192.168.0.10", "192.168.0.108", NAS, PC, 60);
        synack.src_port = Some(445);
        synack.tcp_flags = Some(0x12);
        inv.observe(&synack, &c, &own);

        let mut mdns = pkt("192.168.0.10", "224.0.0.251", NAS, "01:00:5e:00:00:fb", 300);
        mdns.src_port = Some(5353);
        mdns.mdns_names = vec![
            "truenas._smb._tcp.local".into(),
            "_services._dns-sd._udp.local".into(),
            "truenas.local".into(),
        ];
        inv.observe(&mdns, &c, &own);

        let mut dhcp = pkt(
            "0.0.0.0",
            "255.255.255.255",
            "38:c6:ce:8a:79:ea",
            "ff:ff:ff:ff:ff:ff",
            342,
        );
        dhcp.dhcp_hostname = Some("Nintendo-Switch".into());
        inv.observe(&dhcp, &c, &own);

        let mut cdp = pkt(
            "Unknown",
            "Unknown",
            "00:2c:c8:99:ad:7c",
            "01:00:0c:cc:cc:cc",
            400,
        );
        cdp.l2 = Some(L2Info {
            proto: "CDP".into(),
            name: Some("sw1".into()),
            port: Some("Gi0/1".into()),
            ..Default::default()
        });
        inv.observe(&cdp, &c, &own);

        let nas = inv.devices().find(|d| d.mac == NAS).unwrap();
        assert_eq!(nas.ports.get("tcp/445"), Some(&1));
        assert_eq!(nas.services.iter().collect::<Vec<_>>(), vec!["_smb._tcp"]);
        let sw = inv
            .devices()
            .find(|d| d.mac == "38:c6:ce:8a:79:ea")
            .unwrap();
        assert_eq!(sw.dhcp_name.as_deref(), Some("Nintendo-Switch"));
        assert!(sw.ips.is_empty()); // 0.0.0.0 is not an address of the device
        let l2: Vec<_> = inv.l2().collect();
        assert_eq!(l2[0].cdp.as_ref().unwrap().name.as_deref(), Some("sw1"));
        assert!(l2[0].lldp.is_none());
    }

    #[test]
    fn ignores_broadcast_and_multicast_macs() {
        let c = classifier();
        let own: HashSet<String> = [ROUTER.to_string()].into();
        let mut inv = Inventory::default();
        // e.g. a DHCP offer: unicast IP, broadcast MAC
        inv.observe(
            &pkt(
                "192.168.0.1",
                "192.168.0.104",
                ROUTER,
                "ff:ff:ff:ff:ff:ff",
                342,
            ),
            &c,
            &own,
        );
        inv.observe(
            &pkt("192.168.0.108", "192.168.0.20", PC, "01:00:5e:00:00:12", 60),
            &c,
            &own,
        );
        assert!(inv.devices().all(|d| is_unicast_mac(&d.mac)));
        assert!(is_unicast_mac(PC) && !is_unicast_mac("33:33:00:00:00:fb"));
    }

    #[test]
    fn service_type_extraction() {
        assert_eq!(
            service_type("ENIAC._airplay._tcp.local").as_deref(),
            Some("_airplay._tcp")
        );
        assert_eq!(
            service_type("_googlecast._tcp.local.").as_deref(),
            Some("_googlecast._tcp")
        );
        assert_eq!(service_type("_services._dns-sd._udp.local"), None);
        assert_eq!(
            service_type("_printer._sub._http._tcp.local"),
            Some("_http._tcp".into())
        );
        assert_eq!(service_type("truenas.local"), None);
        assert_eq!(service_type("example.com"), None);
    }

    #[test]
    fn parses_ip_json() {
        let links = json!([{"ifname":"lo","address":"00:00:00:00:00:00"},{"ifname":"enp3s0","address":"32:01:02:44:1C:80"},{"ifname":"ppp0"}]);
        assert_eq!(
            parse_own_macs(&links),
            ["32:01:02:44:1c:80".to_string()].into()
        );

        let addrs = json!([
            {"ifname":"enp3s0","operstate":"UP","address":"32:01:02:44:1c:80","addr_info":[{"family":"inet","local":"192.168.0.1","prefixlen":24,"scope":"global"}]},
            {"ifname":"ppp0","operstate":"UNKNOWN","addr_info":[{"family":"inet","local":"160.13.93.49","prefixlen":32,"scope":"global"}]},
            {"ifname":"enp2s0","operstate":"DOWN","addr_info":[]},
            {"ifname":"wlx0","operstate":"UP","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}
        ]);
        let ifs = parse_interfaces(&addrs, &["ppp0".to_string()]);
        let roles: Vec<&str> = ifs.iter().map(|i| i["role"].as_str().unwrap()).collect();
        assert_eq!(roles, vec!["lan", "wan", "down", "other"]);

        let neigh = json!([
            {"dst":"192.168.0.10","dev":"enp3s0","lladdr":"34:76:C5:94:7F:1D","state":["STALE"]},
            {"dst":"192.168.0.5","dev":"enp3s0","state":["FAILED"]}
        ]);
        let n = parse_neighbors(&neigh);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0]["mac"], "34:76:c5:94:7f:1d");
    }
}
