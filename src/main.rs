use axum::{
    Json,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{Html, Response},
    routing::{Router, get},
};
use flate2::{Compression, write::GzEncoder};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::Write;
use std::{
    collections::HashMap,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as TokioCommand,
    sync::{broadcast, mpsc},
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PacketInfo {
    timestamp: u64,
    src_ip: String,
    dst_ip: String,
    protocol: String,
    sub_protocol: Option<String>,
    length: u32,
    info: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::extract::State;

    #[test]
    fn test_parse_tshark_line_basic() {
        let line = "1616161616.123|192.168.0.1|192.168.0.2|||||eth:ip:tcp:tls|60|Example";
        let packet = parse_tshark_line(line).expect("packet parsed");
        assert_eq!(packet.src_ip, "192.168.0.1");
        assert_eq!(packet.dst_ip, "192.168.0.2");
        assert_eq!(packet.protocol, "TCP");
        assert_eq!(packet.sub_protocol.as_deref(), Some("TLS"));
        assert_eq!(packet.length, 60);
        assert_eq!(packet.info, "Example");
    }

    #[test]
    fn test_parse_tshark_line_info_with_pipe() {
        let line = "1616161616.123|192.168.0.1|192.168.0.2|||||eth:ip:tcp|60|Example|with|pipe";
        let packet = parse_tshark_line(line).expect("packet parsed");
        assert_eq!(packet.info, "Example|with|pipe");
    }

    #[tokio::test]
    async fn test_set_filter_handler_updates_filter() {
        let stats = Arc::new(Mutex::new(PacketStats {
            total_packets: 0,
            protocols: HashMap::new(),
            top_sources: HashMap::new(),
            top_destinations: HashMap::new(),
        }));

        let filter = Arc::new(Mutex::new(FilterConfig {
            tshark_filter: None,
        }));
        let (tx, _) = broadcast::channel(1);
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

        let new_filter = FilterConfig {
            tshark_filter: Some("tcp".to_string()),
        };
        let state = State((stats, filter.clone(), tx, cmd_tx));
        let result = set_filter_handler(state, Json(new_filter.clone()))
            .await
            .expect("handler ok");

        assert_eq!(result.0.tshark_filter, Some("tcp".to_string()));
        assert_eq!(
            filter.lock().unwrap().tshark_filter,
            Some("tcp".to_string())
        );
        assert!(matches!(cmd_rx.try_recv(), Ok(CaptureCommand::Restart)));
    }
}

const PROTOCOLS: [&str; 9] = [
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

fn get_local_ips() -> Vec<String> {
    if let Ok(output) = Command::new("hostname").arg("-I").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    Vec::new()
}

#[derive(Debug, Clone, Serialize)]
struct PacketCompact {
    timestamp: u64,
    src_ip: String,
    dst_ip: String,
    proto: u8,
    sub_proto: Option<String>,
    length: u32,
    info: String,
}

fn protocol_to_id(proto: &str) -> u8 {
    PROTOCOLS
        .iter()
        .position(|p| p.eq_ignore_ascii_case(proto))
        .map(|v| v as u8)
        .unwrap_or(u8::MAX)
}

#[derive(Debug, Clone, Serialize)]
struct PacketStats {
    total_packets: u64,
    protocols: HashMap<String, u64>,
    top_sources: HashMap<String, u64>,
    top_destinations: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FilterConfig {
    tshark_filter: Option<String>,
}

enum CaptureCommand {
    Restart,
}

type SharedStats = Arc<Mutex<PacketStats>>;
type SharedFilter = Arc<Mutex<FilterConfig>>;
type Broadcaster = broadcast::Sender<PacketInfo>;
type CommandSender = mpsc::UnboundedSender<CaptureCommand>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let stats = Arc::new(Mutex::new(PacketStats {
        total_packets: 0,
        protocols: HashMap::new(),
        top_sources: HashMap::new(),
        top_destinations: HashMap::new(),
    }));

    let filter = Arc::new(Mutex::new(FilterConfig {
        tshark_filter: None,
    }));

    let (tx, _rx) = broadcast::channel(1000);
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    // Start packet capture task
    let stats_clone = stats.clone();
    let filter_clone = filter.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        capture_packets_manager(stats_clone, filter_clone, tx_clone, cmd_rx).await;
    });

    // Configure web server
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/filter", axum::routing::post(set_filter_handler))
        .route("/ws", get(websocket_handler))
        .nest_service("/static", ServeDir::new("static"))
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
        .with_state((stats, filter, tx, cmd_tx));

    info!("Starting packet visualization server... http://localhost:3000");

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:3000").await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to port 3000: {}", e);
            error!("Please ensure port 3000 is not in use by another application");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

async fn capture_packets_manager(
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
                                *stats
                                    .top_destinations
                                    .entry(packet.dst_ip.clone())
                                    .or_insert(0) += 1;
                            } else {
                                warn!("Failed to acquire stats lock, skipping packet statistics update");
                            }

                            // Send to WebSocket clients
                            if let Err(_) = tx.send(packet) {
                                // Ignore if no clients are connected
                            }
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

fn first_non_empty(parts: &[&str], indices: &[usize]) -> String {
    indices
        .iter()
        .find_map(|&idx| {
            parts.get(idx).and_then(|&part| {
                if !part.is_empty() {
                    Some(part.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

fn parse_protocols(hierarchy: &str) -> (String, Option<String>) {
    if hierarchy.is_empty() {
        return ("Unknown".to_string(), None);
    }

    let protocols: Vec<&str> = hierarchy.split(':').collect();

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

fn parse_tshark_line(line: &str) -> Option<PacketInfo> {
    // Limit splitting to the first 9 separators to avoid breaking the info
    // field if it contains the separator character.
    let parts: Vec<&str> = line.splitn(10, '|').collect();
    if parts.len() < 10 {
        return None;
    }

    let timestamp = parts[0].parse::<f64>().ok()? as u64;

    let src_ip = first_non_empty(&parts, &[1, 3, 5]);
    let dst_ip = first_non_empty(&parts, &[2, 4, 6]);

    let (protocol, sub_protocol) = parse_protocols(parts[7]);
    let length = parts[8].parse::<u32>().unwrap_or(0);
    let info = if parts[9].is_empty() {
        "Unknown".to_string()
    } else {
        parts[9].to_string()
    };

    Some(PacketInfo {
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        sub_protocol,
        length,
        info,
    })
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn stats_handler(
    State((stats, _, _, _)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
) -> Result<Json<PacketStats>, StatusCode> {
    let stats = match stats.lock() {
        Ok(stats) => stats,
        Err(e) => {
            error!("Failed to acquire stats lock: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Ok(Json(stats.clone()))
}

fn validate_tshark_filter(filter: &str) -> bool {
    // Basic filter validation - check for dangerous characters and basic syntax
    if filter.is_empty() {
        return true; // Empty filter is valid
    }

    // Check for potentially dangerous characters that could be used for command injection
    let dangerous_chars = &['&', '|', ';', '`', '$', '(', ')', '<', '>', '"', '\''];
    if filter.chars().any(|c| dangerous_chars.contains(&c)) {
        return false;
    }

    // Check for basic tshark filter keywords
    let valid_keywords = &[
        "tcp",
        "udp",
        "icmp",
        "arp",
        "ip",
        "ipv6",
        "port",
        "host",
        "src",
        "dst",
        "and",
        "or",
        "not",
        "proto",
        "ether",
        "broadcast",
        "multicast",
    ];

    // Simple word-based validation - at least one valid keyword should be present
    let words: Vec<&str> = filter.split_whitespace().collect();
    if words
        .iter()
        .any(|word| valid_keywords.contains(&word.to_lowercase().as_str()))
    {
        return true;
    }

    // Also allow numeric patterns for ports and IPs
    if filter
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || ".:".contains(c))
    {
        return true;
    }

    false
}

async fn set_filter_handler(
    State((_, filter, _, cmd_tx)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
    Json(new_filter): Json<FilterConfig>,
) -> Result<Json<FilterConfig>, StatusCode> {
    // Validate filter if provided
    if let Some(ref filter_str) = new_filter.tshark_filter {
        if !validate_tshark_filter(filter_str) {
            warn!("Invalid tshark filter rejected: {}", filter_str);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let mut filter_guard = match filter.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire filter lock: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    *filter_guard = new_filter.clone();
    info!("Filter updated: {:?}", new_filter.tshark_filter);

    // Restart packet capture
    if let Err(_) = cmd_tx.send(CaptureCommand::Restart) {
        error!("Failed to send capture restart command");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(new_filter))
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State((_, _, tx, _)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
) -> Response {
    ws.on_upgrade(move |socket| websocket_task(socket, tx))
}

async fn websocket_task(socket: WebSocket, tx: Broadcaster) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = tx.subscribe();
    let mut packet_buffer: Vec<PacketCompact> = Vec::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    let ctx = serde_json::json!({
        "type": "ctx",
        "protocols": PROTOCOLS,
        "local_ips": get_local_ips()
    });
    if sender.send(Message::Text(ctx.to_string())).await.is_err() {
        return;
    }

    // Packet reception task (batch + compression)
    let packet_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(packet) => {
                            let compact = PacketCompact {
                                timestamp: packet.timestamp,
                                src_ip: packet.src_ip,
                                dst_ip: packet.dst_ip,
                                proto: protocol_to_id(&packet.protocol),
                                sub_proto: packet.sub_protocol,
                                length: packet.length,
                                info: packet.info,
                            };
                            packet_buffer.push(compact);
                        },
                        Err(_) => break,
                    }
                },
                _ = interval.tick() => {
                    if !packet_buffer.is_empty() {
                        let batch_data = match serde_json::to_vec(&packet_buffer) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize packet buffer: {}", e);
                                packet_buffer.clear();
                                continue;
                            }
                        };

                        // gzip compression
                        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
                        if let Err(e) = encoder.write_all(&batch_data) {
                            error!("Failed to compress batch data: {}", e);
                            break;
                        }
                        let compressed = match encoder.finish() {
                            Ok(compressed) => compressed,
                            Err(e) => {
                                error!("Failed to finish compression: {}", e);
                                break;
                            }
                        };

                        if sender.send(Message::Binary(compressed)).await.is_err() {
                            break;
                        }

                        packet_buffer.clear();
                    }
                }
            }
        }
        // Flush remaining packets
        if !packet_buffer.is_empty() {
            if let Ok(batch_data) = serde_json::to_vec(&packet_buffer) {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
                if encoder.write_all(&batch_data).is_ok() {
                    if let Ok(compressed) = encoder.finish() {
                        let _ = sender.send(Message::Binary(compressed)).await;
                    }
                }
            }
        }
    });

    // Handle client messages (ping/pong etc.)
    let ping_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            if msg.is_err() {
                break;
            }
        }
    });

    // Exit when either task ends
    tokio::select! {
        _ = packet_task => {},
        _ = ping_task => {},
    }
}
