//! Cached view of this machine's network configuration (own addresses, LAN
//! networks, hostname).
//!
//! Addresses change at run time on a gateway (PPPoE reconnects, a new
//! delegated IPv6 prefix, SLAAC), so this is refreshed periodically. Readers
//! compare `version` to notice changes: the capture loop rebuilds its LAN/WAN
//! classifier and WebSocket clients are sent the new configuration.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;
use tracing::info;

use crate::utils::{LanNet, get_hostname, get_lan_nets, get_local_ips};

const REFRESH: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct NetInfo {
    #[serde(skip)]
    pub version: u64,
    pub local_ips: Vec<String>,
    pub lan_nets: Vec<LanNet>,
    pub hostname: String,
}

impl NetInfo {
    pub fn lan_cidrs(&self) -> Vec<String> {
        self.lan_nets.iter().map(|n| n.cidr.clone()).collect()
    }
}

static CURRENT: RwLock<Option<Arc<NetInfo>>> = RwLock::new(None);

pub fn current() -> Arc<NetInfo> {
    CURRENT
        .read()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default()
}

/// Re-read the configuration (runs `ip`/`hostname`; call from a blocking context).
pub fn refresh() {
    let mut fresh = NetInfo {
        version: 0,
        local_ips: get_local_ips(),
        lan_nets: get_lan_nets(),
        hostname: get_hostname(),
    };
    let old = current();
    let same = old.local_ips == fresh.local_ips
        && old.lan_nets == fresh.lan_nets
        && old.hostname == fresh.hostname;
    if same && old.version > 0 {
        return;
    }
    fresh.version = old.version + 1;
    if old.version > 0 {
        info!("Network configuration changed: LAN {:?}", fresh.lan_cidrs());
    }
    if let Ok(mut g) = CURRENT.write() {
        *g = Some(Arc::new(fresh));
    }
}

pub async fn refresh_task() {
    loop {
        tokio::time::sleep(REFRESH).await;
        let _ = tokio::task::spawn_blocking(refresh).await;
    }
}
