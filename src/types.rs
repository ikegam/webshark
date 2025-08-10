use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub sub_protocol: Option<String>,
    pub length: u32,
    pub info: String,
}

pub const PROTOCOLS: [&str; 9] = [
    "TCP", "UDP", "ICMP", "ARP", "IPv6", "IP", "TLS", "WEBSOCKET", "QUIC",
];

#[derive(Debug, Clone, Serialize)]
pub struct PacketCompact {
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub proto: u8,
    pub sub_proto: Option<String>,
    pub length: u32,
    pub info: String,
}

pub fn protocol_to_id(proto: &str) -> u8 {
    PROTOCOLS
        .iter()
        .position(|p| p.eq_ignore_ascii_case(proto))
        .map(|v| v as u8)
        .unwrap_or(u8::MAX)
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketStats {
    pub total_packets: u64,
    pub protocols: HashMap<String, u64>,
    pub top_sources: HashMap<String, u64>,
    pub top_destinations: HashMap<String, u64>,
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

