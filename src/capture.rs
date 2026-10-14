use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as TokioCommand,
    sync::mpsc,
};
use tracing::{error, info, warn};

use std::collections::HashMap;

use crate::history::Classifier;
use crate::names::ResolveSender;
use crate::types::{Broadcaster, CaptureCommand, SharedFilter, SharedStats};
use crate::utils::{get_lan_nets, get_local_ips, parse_tshark_line};

/// When a per-host stats map reaches this many entries, prune it.
const MAX_HOST_ENTRIES: usize = 4096;
/// Number of heaviest hosts to keep after pruning.
const KEEP_HOST_ENTRIES: usize = 1024;

/// Port the web UI listens on (from WEBSHARK_BIND, default 3000).
fn ui_port() -> u16 {
    std::env::var("WEBSHARK_BIND")
        .ok()
        .and_then(|b| b.rsplit(':').next().and_then(|p| p.parse().ok()))
        .unwrap_or(3000)
}

/// Combine the user's capture filter with an exclusion of the UI's own port.
pub fn build_capture_filter(user: Option<&str>, port: u16) -> String {
    let own = format!("not tcp port {}", port);
    match user.map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => format!("({}) and {}", f, own),
        None => own,
    }
}

/// Keep only the `keep` entries with the highest counts once `map` grows past
/// `max`. This bounds memory for 24/7 captures while preserving the "top talkers"
/// that the UI actually displays.
fn prune_top_map(map: &mut HashMap<String, u64>, max: usize, keep: usize) {
    if map.len() < max {
        return;
    }
    let mut entries: Vec<(String, u64)> = map.drain().collect();
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    entries.truncate(keep);
    *map = entries.into_iter().collect();
}

pub async fn capture_packets_manager(
    stats: SharedStats,
    filter: SharedFilter,
    tx: Broadcaster,
    mut cmd_rx: mpsc::UnboundedReceiver<CaptureCommand>,
    resolve_tx: ResolveSender,
) {
    info!("Starting packet capture manager");

    loop {
        // Create abort handle for graceful shutdown
        let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
        let mut capture_task = tokio::spawn(capture_packets(
            stats.clone(),
            filter.clone(),
            tx.clone(),
            resolve_tx.clone(),
            abort_rx,
        ));

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(CaptureCommand::Restart) => {
                            info!("Restarting packet capture...");
                            let _ = abort_tx.send(());
                            let _ = capture_task.await;
                            break;
                        }
                        None => {
                            info!("Command channel closed, stopping capture manager");
                            let _ = abort_tx.send(());
                            let _ = capture_task.await;
                            return;
                        }
                    }
                }
                result = &mut capture_task => {
                    match result {
                        Ok(_) => info!("Capture task ended unexpectedly, restarting..."),
                        Err(e) => error!("Capture task panicked: {}", e),
                    }
                    // Slight delay to avoid rapid restart loops
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    break;
                }
            }
        }
    }
}

async fn capture_packets(
    stats: SharedStats,
    filter: SharedFilter,
    tx: Broadcaster,
    resolve_tx: ResolveSender,
    mut abort_rx: tokio::sync::oneshot::Receiver<()>,
) {
    info!("Starting packet capture");

    // Capture interface is configurable via WEBSHARK_IFACE (default: all).
    // On a router you may want e.g. WEBSHARK_IFACE=ppp0 or enp3s0.
    let iface = std::env::var("WEBSHARK_IFACE").unwrap_or_else(|_| "any".to_string());
    info!("Capturing on interface {}", iface);

    // Never capture our own web UI traffic: when capturing on the interface the
    // UI is served on, every batch we send would be captured and sent again.
    let user_filter = {
        let filter_guard = filter.lock().unwrap();
        filter_guard.tshark_filter.clone()
    };
    let capture_filter = build_capture_filter(user_filter.as_deref(), ui_port());

    // Capture with dumpcap writing pcapng to a pipe, and dissect with tshark
    // reading that pipe. Letting tshark drive dumpcap itself (`tshark -i`)
    // makes dumpcap spool every packet into a temporary file under /tmp that
    // is never trimmed, which fills the disk on a long-running gateway.
    let dumpcap = TokioCommand::new("dumpcap")
        .args(["-i", &iface, "-f", &capture_filter, "-q", "-w", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut dumpcap = match dumpcap {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to start dumpcap: {}", e);
            warn!("Please ensure tshark/dumpcap is installed");
            return;
        }
    };
    let pcap_pipe: Stdio = match dumpcap
        .stdout
        .take()
        .map(|out| -> std::io::Result<Stdio> { out.try_into() })
    {
        Some(Ok(pipe)) => pipe,
        _ => {
            error!("Failed to get stdout from dumpcap process");
            return;
        }
    };

    // tshark arguments. The field order must match utils::parse_tshark_line;
    // `_ws.col.Info` stays last.
    let mut args: Vec<String> = vec!["-r".into(), "-".into()];
    for field in [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "frame.protocols",
        "frame.len",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.flags",
        "dns.qry.name",
        "dns.a",
        "dns.aaaa",
        "tls.handshake.extensions_server_name",
        "http.host",
        "eth.src",
        "eth.dst",
        "cdp.deviceid",
        "cdp.portid",
        "cdp.platform",
        "cdp.native_vlan",
        "lldp.tlv.system.name",
        "lldp.port.id",
        "lldp.port.desc",
        "lldp.tlv.system.desc",
        "lldp.mgn.addr.ip4",
        "dns.resp.name",
        "dhcp.option.hostname",
        "_ws.col.Info",
    ] {
        args.push("-e".into());
        args.push(field.into());
    }
    args.extend(
        [
            "-T",
            "fields",
            "-E",
            "separator=|",
            // Keep every occurrence (DNS answers can carry many addresses) and
            // join them with ';'. The parser takes the first value for
            // single-valued fields, e.g. ICMP errors that quote an inner header.
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=;",
            "-l", // Line buffering
            "-n", // No name resolution (avoids DNS lookups from the capture box)
            // Reset dissection state periodically. tshark otherwise keeps
            // per-conversation state forever and grows without bound when
            // running 24/7.
            "-M",
            "200000",
        ]
        .map(String::from),
    );

    let cmd = TokioCommand::new("tshark")
        .args(&args)
        .stdin(pcap_pipe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();

    let mut child = match cmd {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to start tshark: {}", e);
            warn!("Please ensure tshark is installed");
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            error!("Failed to get stdout from tshark process");
            return;
        }
    };
    let mut reader = BufReader::new(stdout).lines();

    // Addresses can change (PPPoE reconnects, SLAAC), so rebuild the
    // LAN/WAN classifier whenever capture (re)starts.
    let lan_cidrs: Vec<String> = get_lan_nets().into_iter().map(|n| n.cidr).collect();
    let classifier = Classifier::new(&lan_cidrs, &get_local_ips());
    // LAN addresses already handed to the name resolver during this run.
    let mut requested: std::collections::HashSet<std::net::Ipv4Addr> =
        std::collections::HashSet::new();
    let own_macs = crate::lan::own_macs();

    // Both tools report errors (bad interface, permissions, ...) and status on
    // stderr. It must be drained: an unread pipe eventually fills and blocks
    // the process. Forward it to our log instead.
    forward_stderr("dumpcap", dumpcap.stderr.take());
    forward_stderr("tshark", child.stderr.take());

    loop {
        tokio::select! {
            line_result = reader.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        if let Some(packet) = parse_tshark_line(&line) {
                            // Update statistics
                            if let Ok(mut stats) = stats.lock() {
                                stats.total_packets += 1;
                                let dir = classifier.direction(&packet.src_ip, &packet.dst_ip);
                                stats.history.add(packet.timestamp, dir, packet.length);
                                stats.lan.observe(&packet, &classifier, &own_macs);
                                // mDNS answers name the responder's own addresses.
                                if packet.src_port == Some(5353) {
                                    if let Some(name) = &packet.dns_name {
                                        for addr in &packet.dns_addrs {
                                            if classifier.is_lan_device(addr) && (stats.lan_names.len() < 4096 || stats.lan_names.contains_key(addr)) {
                                                stats.lan_names.insert(addr.clone(), name.clone());
                                            }
                                        }
                                    }
                                }
                                *stats.protocols.entry(packet.protocol.clone()).or_insert(0) += 1;
                                *stats.top_sources.entry(packet.src_ip.clone()).or_insert(0) += 1;
                                *stats.top_destinations.entry(packet.dst_ip.clone()).or_insert(0) += 1;

                                // Keep per-host maps bounded so a long-running capture on a
                                // busy gateway cannot grow memory without limit. Prune to the
                                // heaviest hosts once a map gets large.
                                prune_top_map(&mut stats.top_sources, MAX_HOST_ENTRIES, KEEP_HOST_ENTRIES);
                                prune_top_map(&mut stats.top_destinations, MAX_HOST_ENTRIES, KEEP_HOST_ENTRIES);
                            } else {
                                warn!("Failed to acquire stats lock, skipping packet statistics update");
                            }

                            for addr in [&packet.src_ip, &packet.dst_ip] {
                                if let Some(ip) = classifier.lan_device_v4(addr) {
                                    if requested.len() < 4096 && requested.insert(ip) {
                                        let _ = resolve_tx.send(ip);
                                    }
                                }
                            }

                            // Send to WebSocket clients
                            let _ = tx.send(packet);
                        }
                    }
                    Ok(None) => {
                        // End of stream
                        info!("tshark stream ended");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading from tshark: {}", e);
                        break;
                    }
                }
            }
            _ = &mut abort_rx => {
                info!("Received abort signal, stopping packet capture");
                break;
            }
        }
    }

    // Stop both processes (also covers tshark exiting on its own).
    for (name, proc) in [("dumpcap", &mut dumpcap), ("tshark", &mut child)] {
        if let Err(e) = proc.kill().await {
            warn!("Failed to kill {} process: {}", name, e);
        }
    }
    info!("Packet capture stopped");
}

fn forward_stderr(name: &'static str, stderr: Option<tokio::process::ChildStderr>) {
    let Some(stderr) = stderr else { return };
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Informational status lines are not problems.
            if line.starts_with("Capturing on")
                || line.ends_with("packets captured")
                || line.starts_with("File: ")
            {
                info!("{}: {}", name, line);
            } else {
                warn!("{}: {}", name, line);
            }
        }
    });
}

#[cfg(test)]
mod prune_tests {
    use super::prune_top_map;
    use std::collections::HashMap;

    #[test]
    fn prune_keeps_heaviest_entries() {
        let mut m: HashMap<String, u64> = (0..10u64).map(|i| (format!("h{}", i), i)).collect();
        prune_top_map(&mut m, 10, 3);
        let mut keys: Vec<_> = m.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["h7", "h8", "h9"]);
    }

    #[test]
    fn prune_is_noop_below_limit() {
        let mut m: HashMap<String, u64> = (0..5u64).map(|i| (format!("h{}", i), i)).collect();
        prune_top_map(&mut m, 10, 3);
        assert_eq!(m.len(), 5);
    }
}
