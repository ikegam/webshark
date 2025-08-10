use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as TokioCommand,
    sync::mpsc,
};
use tracing::{error, info, warn};

use crate::types::{Broadcaster, CaptureCommand, SharedFilter, SharedStats};
use crate::utils::parse_tshark_line;

pub async fn capture_packets_manager(
    stats: SharedStats,
    filter: SharedFilter,
    tx: Broadcaster,
    mut cmd_rx: mpsc::UnboundedReceiver<CaptureCommand>,
) {
    info!("Starting packet capture manager");

    loop {
        // Create abort handle for graceful shutdown
        let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
        let mut capture_task = tokio::spawn(capture_packets(
            stats.clone(),
            filter.clone(),
            tx.clone(),
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
    mut abort_rx: tokio::sync::oneshot::Receiver<()>,
) {
    info!("Starting packet capture");

    // Basic tshark command arguments
    let mut args = vec![
        "-i",
        "any", // All interfaces
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "arp.src.proto_ipv4",
        "-e",
        "arp.dst.proto_ipv4",
        "-e",
        "frame.protocols",
        "-e",
        "frame.len",
        "-e",
        "_ws.col.Info",
        "-E",
        "separator=|",
        "-l", // Line buffering
    ];

    // Add filter if configured
    let filter_string = {
        let filter_guard = filter.lock().unwrap();
        filter_guard.tshark_filter.clone()
    };

    if let Some(ref filter_str) = filter_string {
        if !filter_str.trim().is_empty() {
            args.push("-f");
            args.push(filter_str);
        }
    }

    let cmd = TokioCommand::new("tshark")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    loop {
        tokio::select! {
            line_result = reader.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        if let Some(packet) = parse_tshark_line(&line) {
                            // Update statistics
                            if let Ok(mut stats) = stats.lock() {
                                stats.total_packets += 1;
                                *stats.protocols.entry(packet.protocol.clone()).or_insert(0) += 1;
                                *stats.top_sources.entry(packet.src_ip.clone()).or_insert(0) += 1;
                                *stats.top_destinations.entry(packet.dst_ip.clone()).or_insert(0) += 1;
                            } else {
                                warn!("Failed to acquire stats lock, skipping packet statistics update");
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
                // Kill the child process gracefully
                if let Err(e) = child.kill().await {
                    warn!("Failed to kill tshark process: {}", e);
                } else {
                    info!("Successfully terminated tshark process");
                }
                break;
            }
        }
    }
}

