use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    http::StatusCode,
    response::{Html, Response},
    routing::{get, Router},
    Json,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json;
use flate2::{write::GzEncoder, Compression};
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
            return stdout
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
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
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
        )
        .with_state((stats, filter, tx, cmd_tx));

    info!("Starting packet visualization server... http://localhost:3000");
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn capture_packets_manager(
    stats: SharedStats, 
    filter: SharedFilter, 
    tx: Broadcaster, 
    mut cmd_rx: mpsc::UnboundedReceiver<CaptureCommand>
) {
    info!("Starting packet capture manager");
    
    loop {
        let capture_task = tokio::spawn(capture_packets(stats.clone(), filter.clone(), tx.clone()));
        
        // Wait for restart command
        if let Some(CaptureCommand::Restart) = cmd_rx.recv().await {
            info!("Restarting packet capture...");
            capture_task.abort();
            continue;
        } else {
            // Exit if command channel is closed
            break;
        }
    }
}

async fn capture_packets(stats: SharedStats, filter: SharedFilter, tx: Broadcaster) {
    info!("Starting packet capture");

    // Basic tshark command arguments
    let mut args = vec![
        "-i", "any",  // All interfaces
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "arp.src.proto_ipv4",
        "-e", "arp.dst.proto_ipv4",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "_ws.col.Info",
        "-E", "separator=|",
        "-l"  // Line buffering
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

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    while let Ok(Some(line)) = reader.next_line().await {
        if let Some(packet) = parse_tshark_line(&line) {
            // Update statistics
            {
                let mut stats = stats.lock().unwrap();
                stats.total_packets += 1;
                *stats.protocols.entry(packet.protocol.clone()).or_insert(0) += 1;
                *stats.top_sources.entry(packet.src_ip.clone()).or_insert(0) += 1;
                *stats.top_destinations.entry(packet.dst_ip.clone()).or_insert(0) += 1;
            }

            // Send to WebSocket clients
            if let Err(_) = tx.send(packet) {
                // Ignore if no clients are connected
            }
        }
    }
}

fn parse_tshark_line(line: &str) -> Option<PacketInfo> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 10 {
        return None;
    }

    let timestamp = parts[0].parse::<f64>().ok()? as u64;

    let src_ip = if !parts[1].is_empty() {
        parts[1].to_string()
    } else if !parts[3].is_empty() {
        parts[3].to_string()
    } else if !parts[5].is_empty() {
        parts[5].to_string()
    } else {
        "Unknown".to_string()
    };

    let dst_ip = if !parts[2].is_empty() {
        parts[2].to_string()
    } else if !parts[4].is_empty() {
        parts[4].to_string()
    } else if !parts[6].is_empty() {
        parts[6].to_string()
    } else {
        "Unknown".to_string()
    };

    let (protocol, sub_protocol) = if parts[7].is_empty() {
        ("Unknown".to_string(), None)
    } else {
        // Extract actual protocol from protocol hierarchy (e.g. "sll:ethertype:ip:tcp" -> "tcp")
        let protocols: Vec<&str> = parts[7].split(':').collect();

        // Detect sub protocols like TLS, WebSocket and QUIC
        let mut sub_proto: Option<String> = None;
        if protocols.contains(&"tls") || protocols.contains(&"ssl") {
            sub_proto = Some("TLS".to_string());
        } else if protocols.contains(&"websocket") || protocols.contains(&"ws") {
            sub_proto = Some("WEBSOCKET".to_string());
        } else if protocols.contains(&"quic") {
            sub_proto = Some("QUIC".to_string());
        }

        // Priority: tcp, udp, icmp, arp, others
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
            // Use the last protocol (most specific)
            protocols.last().map_or("Unknown", |v| v).to_uppercase()
        };

        (base, sub_proto)
    };
    let length = parts[8].parse::<u32>().unwrap_or(0);
    let info = if parts[9].is_empty() { "Unknown".to_string() } else { parts[9].to_string() };

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

async fn stats_handler(State((stats, _, _, _)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>) -> Json<PacketStats> {
    let stats = stats.lock().unwrap();
    Json(stats.clone())
}

async fn set_filter_handler(
    State((_, filter, _, cmd_tx)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
    Json(new_filter): Json<FilterConfig>,
) -> Result<Json<FilterConfig>, StatusCode> {
    let mut filter_guard = filter.lock().unwrap();
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
    let mut last_flush = std::time::Instant::now();

    let ctx = serde_json::json!({
        "type": "ctx",
        "protocols": PROTOCOLS,
        "local_ips": get_local_ips()
    });
    if sender
        .send(Message::Text(ctx.to_string()))
        .await
        .is_err()
    {
        return;
    }

    // Packet reception task (batch + compression)
    let packet_task = tokio::spawn(async move {
        while let Ok(packet) = rx.recv().await {
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
            
            // Batch send every 100ms or 50 packets
            if packet_buffer.len() >= 50 || last_flush.elapsed() >= std::time::Duration::from_millis(100) {
                if !packet_buffer.is_empty() {
                    let batch_data = serde_json::to_vec(&packet_buffer).unwrap();

                    // gzip compression
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
                    encoder.write_all(&batch_data).unwrap();
                    let compressed = encoder.finish().unwrap();
                    
                    if sender.send(Message::Binary(compressed)).await.is_err() {
                        break;
                    }
                    
                    packet_buffer.clear();
                    last_flush = std::time::Instant::now();
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