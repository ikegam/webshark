use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// Capture time in seconds since the Unix epoch (sub-second precision).
    pub timestamp: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub sub_protocol: Option<String>,
    /// Highest-layer protocol from the dissector chain (e.g. "dns", "tls", "quic").
    pub app: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// Raw TCP flags (e.g. 0x002 = SYN) for TCP packets.
    pub tcp_flags: Option<u16>,
    /// DNS query name, present on DNS responses that carry addresses.
    pub dns_name: Option<String>,
    /// Addresses (A/AAAA) answered for `dns_name`.
    pub dns_addrs: Vec<String>,
    /// Server name from TLS SNI or the HTTP Host header.
    pub server_name: Option<String>,
    /// Ethernet addresses (absent on the Linux "any" pseudo-interface).
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    /// Record names in a DNS/mDNS response (used to learn advertised services).
    #[serde(default)]
    pub mdns_names: Vec<String>,
    /// Client hostname from a DHCP request (option 12).
    pub dhcp_hostname: Option<String>,
    /// CDP/LLDP announcement carried by this frame.
    pub l2: Option<crate::lan::L2Info>,
    pub length: u32,
    pub info: String,
}

pub const PROTOCOLS: [&str; 9] = [
    "TCP",
    "UDP",
    "ICMP",
    "ARP",
    "IPv6",
    "IP",
    "TLS",
    "WEBSOCKET",
    "QUIC",
];

/// Wire format sent to browsers. Field names are kept short because this is
/// serialized for every packet.
#[derive(Debug, Clone, Serialize)]
pub struct PacketCompact {
    #[serde(rename = "t")]
    pub timestamp: f64,
    #[serde(rename = "s")]
    pub src_ip: String,
    #[serde(rename = "d")]
    pub dst_ip: String,
    #[serde(rename = "p")]
    pub proto: u8,
    #[serde(rename = "sp", skip_serializing_if = "Option::is_none")]
    pub sub_proto: Option<String>,
    #[serde(rename = "a")]
    pub app: String,
    #[serde(rename = "sP", skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(rename = "dP", skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<u16>,
    #[serde(rename = "dn", skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(rename = "da", skip_serializing_if = "Vec::is_empty")]
    pub dns_addrs: Vec<String>,
    #[serde(rename = "sn", skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(rename = "sm", skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<String>,
    #[serde(rename = "dm", skip_serializing_if = "Option::is_none")]
    pub dst_mac: Option<String>,
    #[serde(rename = "l")]
    pub length: u32,
    #[serde(rename = "i")]
    pub info: String,
}

impl From<PacketInfo> for PacketCompact {
    fn from(p: PacketInfo) -> Self {
        PacketCompact {
            timestamp: p.timestamp,
            proto: protocol_to_id(&p.protocol),
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            sub_proto: p.sub_protocol,
            app: p.app,
            src_port: p.src_port,
            dst_port: p.dst_port,
            tcp_flags: p.tcp_flags,
            dns_name: p.dns_name,
            dns_addrs: p.dns_addrs,
            server_name: p.server_name,
            src_mac: p.src_mac,
            dst_mac: p.dst_mac,
            length: p.length,
            info: p.info,
        }
    }
}

pub fn protocol_to_id(proto: &str) -> u8 {
    PROTOCOLS
        .iter()
        .position(|p| p.eq_ignore_ascii_case(proto))
        .map(|v| v as u8)
        .unwrap_or(u8::MAX)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PacketStats {
    pub total_packets: u64,
    pub protocols: HashMap<String, u64>,
    pub top_sources: HashMap<String, u64>,
    pub top_destinations: HashMap<String, u64>,
    /// Per-second throughput history, sent to browsers when they connect.
    #[serde(skip)]
    pub history: crate::history::History,
    /// Hostnames resolved for LAN addresses (see names.rs).
    #[serde(skip)]
    pub lan_names: HashMap<String, String>,
    /// What we know about devices on the LAN (see lan.rs).
    #[serde(skip)]
    pub lan: crate::lan::Inventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub tshark_filter: Option<String>,
}

pub enum CaptureCommand {
    Restart,
}

pub type SharedStats = Arc<Mutex<PacketStats>>;
pub type SharedFilter = Arc<Mutex<FilterConfig>>;
pub type Broadcaster = broadcast::Sender<PacketInfo>;
pub type CommandSender = mpsc::UnboundedSender<CaptureCommand>;
