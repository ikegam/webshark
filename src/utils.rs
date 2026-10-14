use std::process::Command;

use crate::types::PacketInfo;

/// Every address assigned to this machine, including link-local ones
/// (`hostname -I` omits those).
pub fn get_local_ips() -> Vec<String> {
    let mut ips = parse_all_addrs(&run("ip", &["-o", "addr", "show"]));
    for ip in run("hostname", &["-I"]).split_whitespace() {
        if !ips.iter().any(|i| i == ip) {
            ips.push(ip.to_string());
        }
    }
    ips
}

/// Addresses (without prefix length) from `ip -o addr show`.
pub fn parse_all_addrs(addr_output: &str) -> Vec<String> {
    addr_output
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.get(2) {
                Some(&"inet") | Some(&"inet6") => words
                    .get(3)
                    .map(|a| a.split('/').next().unwrap_or(a).to_string()),
                _ => None,
            }
        })
        .collect()
}

pub fn get_hostname() -> String {
    run("hostname", &[]).trim().to_string()
}

/// A network attached to this machine on a non-WAN interface.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LanNet {
    pub iface: String,
    /// Interface address with prefix length, e.g. "192.168.0.1/24".
    pub cidr: String,
}

fn run(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Interfaces that carry a default route (`dev X` in `ip route show default`).
/// These face the internet, so their networks are not "LAN".
pub fn parse_default_route_ifaces(route_output: &str) -> Vec<String> {
    route_output
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words
                .find(|w| *w == "dev")
                .and_then(|_| words.next())
                .map(str::to_string)
        })
        .collect()
}

/// Global-scope networks from `ip -o addr show`, excluding loopback and the
/// given WAN interfaces. Link-local ranges are handled by the client.
pub fn parse_lan_nets(addr_output: &str, wan_ifaces: &[String]) -> Vec<LanNet> {
    addr_output
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let iface = words.get(1)?.trim_end_matches(':');
            let family = *words.get(2)?;
            let cidr = *words.get(3)?;
            let global = line.contains("scope global");
            if iface == "lo" || wan_ifaces.iter().any(|w| w == iface) || !global {
                return None;
            }
            if (family != "inet" && family != "inet6") || !cidr.contains('/') {
                return None;
            }
            Some(LanNet {
                iface: iface.to_string(),
                cidr: cidr.to_string(),
            })
        })
        .collect()
}

pub fn get_lan_nets() -> Vec<LanNet> {
    let mut wan = parse_default_route_ifaces(&run("ip", &["route", "show", "default"]));
    wan.extend(parse_default_route_ifaces(&run(
        "ip",
        &["-6", "route", "show", "default"],
    )));
    parse_lan_nets(&run("ip", &["-o", "addr", "show"]), &wan)
}

/// Separator tshark uses between multiple occurrences of one field
/// (`-E aggregator=;`). Must match capture.rs.
pub const AGGREGATOR: char = ';';

/// First occurrence of a possibly multi-valued field. ICMP errors, for example,
/// quote the offending packet, so `ip.src` can be "outer;inner".
fn first_value(field: &str) -> &str {
    field.split(AGGREGATOR).next().unwrap_or("").trim()
}

fn opt_value(field: &str) -> Option<String> {
    let v = first_value(field);
    (!v.is_empty()).then(|| v.to_string())
}

fn first_non_empty(parts: &[&str], indices: &[usize]) -> String {
    indices
        .iter()
        .find_map(|&idx| parts.get(idx).and_then(|part| opt_value(part)))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn parse_protocols(hierarchy: &str) -> (String, Option<String>) {
    if hierarchy.is_empty() {
        return ("Unknown".to_string(), None);
    }

    let protocols = effective_layers(hierarchy);

    let sub_proto = if protocols.contains(&"tls") || protocols.contains(&"ssl") {
        Some("TLS".to_string())
    } else if protocols.contains(&"websocket") || protocols.contains(&"ws") {
        Some("WEBSOCKET".to_string())
    } else if protocols.contains(&"quic") {
        Some("QUIC".to_string())
    } else {
        None
    };

    let base = if protocols.contains(&"tcp") {
        "TCP".to_string()
    } else if protocols.contains(&"udp") {
        "UDP".to_string()
    } else if protocols.contains(&"icmp") || protocols.contains(&"icmpv6") {
        "ICMP".to_string()
    } else if protocols.contains(&"arp") {
        "ARP".to_string()
    } else if protocols.contains(&"ipv6") {
        "IPv6".to_string()
    } else if protocols.contains(&"ip") {
        "IP".to_string()
    } else {
        protocols.last().map_or("Unknown", |v| v).to_uppercase()
    };

    (base, sub_proto)
}

/// Protocol layers of a packet. Layers after ICMP/ICMPv6 belong to the packet
/// quoted inside an ICMP error, not to this packet, so they are dropped.
fn effective_layers(hierarchy: &str) -> Vec<&str> {
    let layers: Vec<&str> = hierarchy.split(':').collect();
    match layers.iter().position(|l| *l == "icmp" || *l == "icmpv6") {
        Some(i) => layers[..=i].to_vec(),
        None => layers,
    }
}

/// Pick the highest meaningful layer from a tshark protocol chain such as
/// `eth:ethertype:ip:udp:dns`. Generic payload markers are skipped.
fn parse_app(hierarchy: &str) -> String {
    const SKIP: &[&str] = &[
        "data",
        "tcp.segments",
        "_ws.malformed",
        "_ws.short",
        "_ws.expert",
    ];
    effective_layers(hierarchy)
        .into_iter()
        .rev()
        .find(|p| !p.is_empty() && !SKIP.contains(p))
        .unwrap_or("unknown")
        .to_string()
}

fn parse_port(field: &str) -> Option<u16> {
    first_value(field).parse().ok()
}

fn parse_flags(field: &str) -> Option<u16> {
    let f = first_value(field);
    let hex = f.strip_prefix("0x").or_else(|| f.strip_prefix("0X"))?;
    u16::from_str_radix(hex, 16).ok()
}

/// Number of `|`-separated fields tshark emits; must match the `-e` list in
/// capture.rs. `_ws.col.Info` is last so a `|` inside it cannot shift fields.
pub const FIELD_COUNT: usize = 33;

/// First line of a field tshark printed with escaped newlines ("a\\nb").
fn first_line(v: Option<String>) -> Option<String> {
    v.and_then(|s| s.split("\\n").next().map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
}

/// CDP / LLDP fields: cdp.deviceid, cdp.portid, cdp.platform, cdp.native_vlan,
/// lldp.system.name, lldp.port.id, lldp.port.desc, lldp.system.desc, lldp.mgn.addr.ip4
fn parse_l2(f: &[&str]) -> Option<crate::lan::L2Info> {
    let v = |i: usize| f.get(i).and_then(|s| opt_value(s));
    if let Some(name) = v(0) {
        return Some(crate::lan::L2Info {
            proto: "CDP".into(),
            name: Some(name),
            port: v(1),
            platform: first_line(v(2)),
            vlan: v(3),
            mgmt: None,
        });
    }
    if v(4).is_some() || v(5).is_some() {
        return Some(crate::lan::L2Info {
            proto: "LLDP".into(),
            name: v(4),
            port: v(6).or_else(|| v(5)),
            platform: first_line(v(7)),
            vlan: None,
            mgmt: v(8),
        });
    }
    None
}

pub fn parse_tshark_line(line: &str) -> Option<PacketInfo> {
    let parts: Vec<&str> = line.splitn(FIELD_COUNT, '|').collect();
    if parts.len() < FIELD_COUNT {
        return None;
    }

    let timestamp = parts[0].parse::<f64>().ok()?;

    let src_ip = first_non_empty(&parts, &[1, 3, 5]);
    let dst_ip = first_non_empty(&parts, &[2, 4, 6]);

    let (protocol, sub_protocol) = parse_protocols(parts[7]);
    let app = parse_app(parts[7]);
    let length = parts[8].parse::<u32>().unwrap_or(0);
    let src_port = parse_port(parts[9]).or_else(|| parse_port(parts[11]));
    let dst_port = parse_port(parts[10]).or_else(|| parse_port(parts[12]));
    let tcp_flags = parse_flags(parts[13]);
    let dns_addrs: Vec<String> = parts[15]
        .split(AGGREGATOR)
        .chain(parts[16].split(AGGREGATOR))
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect();
    let dns_name = if dns_addrs.is_empty() {
        None
    } else {
        opt_value(parts[14])
    };
    let server_name = opt_value(parts[17]).or_else(|| opt_value(parts[18]));
    let src_mac = opt_value(parts[19]).map(|m| m.to_ascii_lowercase());
    let dst_mac = opt_value(parts[20]).map(|m| m.to_ascii_lowercase());
    let l2 = parse_l2(&parts[21..30]);
    let mdns_names: Vec<String> = parts[30]
        .split(AGGREGATOR)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .take(64)
        .map(str::to_string)
        .collect();
    let dhcp_hostname = opt_value(parts[31]);
    let info = if parts[32].is_empty() {
        "Unknown".to_string()
    } else {
        parts[32].to_string()
    };

    Some(PacketInfo {
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        sub_protocol,
        app,
        src_port,
        dst_port,
        tcp_flags,
        dns_name,
        dns_addrs,
        server_name,
        src_mac,
        dst_mac,
        mdns_names,
        dhcp_hostname,
        l2,
        length,
        info,
    })
}

pub fn validate_tshark_filter(filter: &str) -> bool {
    if filter.is_empty() {
        return true; // Empty filter is valid
    }

    // The filter is handed to tshark as a single argv entry (no shell), so this is
    // not about shell injection. Restrict it to the character set BPF capture
    // filters actually use, which still allows grouping such as
    // `tcp and (port 80 or port 443)` and `net 192.168.0.0/24`.
    if filter.len() > 512 {
        return false;
    }
    filter.chars().all(|c| {
        c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || ".:/()[]-_!=<>&|".contains(c)
    })
}
