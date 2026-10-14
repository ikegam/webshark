//! Active hostname resolution for LAN devices.
//!
//! Each LAN IPv4 address seen in the capture is looked up once:
//!  1. a unicast mDNS reverse query (`d.c.b.a.in-addr.arpa PTR`) sent straight
//!     to the device's port 5353 — Apple devices, avahi (Linux/NAS), printers
//!     and many IoT devices answer these;
//!  2. otherwise a regular reverse lookup through the system resolver.
//!
//! Queries are unicast on purpose: a multicast query would follow the default
//! route, which on a gateway is the WAN interface.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::types::SharedStats;

const MDNS_TIMEOUT: Duration = Duration::from_millis(1500);
const RETRY_UNRESOLVED: Duration = Duration::from_secs(600);
const REFRESH_RESOLVED: Duration = Duration::from_secs(3600);
const MAX_NAMES: usize = 4096;

pub type ResolveSender = mpsc::UnboundedSender<Ipv4Addr>;

/// Long-running task: resolve addresses received on `rx` and store results in
/// `stats.lan_names`.
pub async fn resolver_task(stats: SharedStats, mut rx: mpsc::UnboundedReceiver<Ipv4Addr>) {
    let mut attempted: HashMap<Ipv4Addr, (Instant, bool)> = HashMap::new();
    while let Some(ip) = rx.recv().await {
        if let Some((when, resolved)) = attempted.get(&ip) {
            let wait = if *resolved {
                REFRESH_RESOLVED
            } else {
                RETRY_UNRESOLVED
            };
            if when.elapsed() < wait {
                continue;
            }
        }
        let name = match mdns_reverse(ip).await {
            Some(n) => Some(n),
            None => system_reverse(ip).await,
        };
        attempted.insert(ip, (Instant::now(), name.is_some()));
        if attempted.len() > MAX_NAMES * 2 {
            attempted.retain(|_, (when, _)| when.elapsed() < RETRY_UNRESOLVED);
        }
        match name {
            Some(name) => {
                info!("Resolved {} -> {}", ip, name);
                if let Ok(mut s) = stats.lock() {
                    if s.lan_names.len() < MAX_NAMES || s.lan_names.contains_key(&ip.to_string()) {
                        s.lan_names.insert(ip.to_string(), name);
                    }
                }
            }
            None => debug!("No name for {}", ip),
        }
    }
}

/// `129.0.168.192.in-addr.arpa`
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Build a DNS query for `name` (type PTR, class IN).
pub fn build_ptr_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // flags, QD=1, AN=NS=AR=0
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 12, 0, 1]); // PTR, IN
    q
}

/// Read a (possibly compressed) domain name starting at `pos`. Returns the
/// name and the offset just past it in the original (uncompressed) position.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ptr;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
    None // pointer loop
}

/// Extract the first PTR answer for `qname` from a DNS response.
pub fn parse_ptr_response(msg: &[u8], qname: &str) -> Option<String> {
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return None; // not a response
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, next) = read_name(msg, pos)?;
        pos = next + 4;
    }
    for _ in 0..an {
        let (name, next) = read_name(msg, pos)?;
        let rtype = u16::from_be_bytes([*msg.get(next)?, *msg.get(next + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(next + 8)?, *msg.get(next + 9)?]) as usize;
        let rdata = next + 10;
        if rtype == 12 && name.eq_ignore_ascii_case(qname) {
            let (target, _) = read_name(msg, rdata)?;
            let target = target.trim_end_matches('.').to_string();
            return (!target.is_empty()).then_some(target);
        }
        pos = rdata + rdlen;
    }
    None
}

async fn mdns_reverse(ip: Ipv4Addr) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let qname = reverse_name(ip);
    let id = (u32::from(ip) as u16) ^ 0x5a5a;
    sock.send_to(&build_ptr_query(id, &qname), (ip, 5353))
        .await
        .ok()?;
    let mut buf = [0u8; 1500];
    let deadline = tokio::time::Instant::now() + MDNS_TIMEOUT;
    loop {
        let (n, from) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        if from.ip() != ip {
            continue;
        }
        if let Some(name) = parse_ptr_response(&buf[..n], &qname) {
            return Some(name);
        }
    }
}

async fn system_reverse(ip: Ipv4Addr) -> Option<String> {
    let lookup = tokio::process::Command::new("getent")
        .args(["hosts", &ip.to_string()])
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(3), lookup)
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let name = text
        .split_whitespace()
        .nth(1)?
        .trim_end_matches('.')
        .to_string();
    // getent echoes the address back when there is no name.
    (name != ip.to_string()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_name_and_query_layout() {
        let ip: Ipv4Addr = "192.168.0.129".parse().unwrap();
        assert_eq!(reverse_name(ip), "129.0.168.192.in-addr.arpa");
        let q = build_ptr_query(0x1234, "129.0.168.192.in-addr.arpa");
        assert_eq!(&q[..6], &[0x12, 0x34, 0, 0, 0, 1]);
        assert_eq!(&q[12..16], &[3, b'1', b'2', b'9']);
        assert_eq!(&q[q.len() - 4..], &[0, 12, 0, 1]);
    }

    #[test]
    fn parses_compressed_ptr_answer() {
        let qname = "129.0.168.192.in-addr.arpa";
        // Response: echo the question, then one PTR answer whose owner name is a
        // pointer to the question (offset 12) and whose target is "ENIAC.local".
        let mut msg = build_ptr_query(0x1234, qname);
        msg[2] = 0x84; // QR + AA
        msg[7] = 1; // ANCOUNT = 1
        let mut rdata = Vec::new();
        for l in ["ENIAC", "local"] {
            rdata.push(l.len() as u8);
            rdata.extend_from_slice(l.as_bytes());
        }
        rdata.push(0);
        msg.extend_from_slice(&[0xC0, 12, 0, 12, 0x80, 1, 0, 0, 0, 120]);
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        assert_eq!(
            parse_ptr_response(&msg, qname).as_deref(),
            Some("ENIAC.local")
        );
    }

    #[test]
    fn rejects_queries_and_garbage() {
        let qname = "1.0.168.192.in-addr.arpa";
        assert_eq!(parse_ptr_response(&build_ptr_query(1, qname), qname), None);
        assert_eq!(parse_ptr_response(&[0x00, 0x01, 0x84], qname), None);
        // pointer loop
        let mut msg = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(&[0xC0, 12]);
        assert_eq!(parse_ptr_response(&msg, qname), None);
    }
}
