use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    http::StatusCode,
    response::{Html, Response},
    routing::{get, Router},
    Json,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    process::Stdio,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as TokioCommand,
    sync::broadcast,
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
    length: u32,
    info: String,
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

type SharedStats = Arc<Mutex<PacketStats>>;
type SharedFilter = Arc<Mutex<FilterConfig>>;
type Broadcaster = broadcast::Sender<PacketInfo>;

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

    // パケットキャプチャタスクを開始
    let stats_clone = stats.clone();
    let filter_clone = filter.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        capture_packets(stats_clone, filter_clone, tx_clone).await;
    });

    // Webサーバーを設定
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
        .with_state((stats, filter, tx));

    info!("パケット可視化サーバーを起動中... http://localhost:3000");
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn capture_packets(stats: SharedStats, filter: SharedFilter, tx: Broadcaster) {
    info!("パケットキャプチャを開始");

    // 基本的なtsharkコマンド引数
    let mut args = vec![
        "-i", "any",  // 全インターフェース
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst", 
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "_ws.col.Info",
        "-E", "separator=|",
        "-l"  // 行バッファリング
    ];

    // フィルタが設定されている場合は追加
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
            error!("tsharkの起動に失敗: {}", e);
            warn!("tsharkがインストールされていることを確認してください");
            return;
        }
    };

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    while let Ok(Some(line)) = reader.next_line().await {
        if let Some(packet) = parse_tshark_line(&line) {
            // 統計を更新
            {
                let mut stats = stats.lock().unwrap();
                stats.total_packets += 1;
                *stats.protocols.entry(packet.protocol.clone()).or_insert(0) += 1;
                *stats.top_sources.entry(packet.src_ip.clone()).or_insert(0) += 1;
                *stats.top_destinations.entry(packet.dst_ip.clone()).or_insert(0) += 1;
            }

            // WebSocketクライアントに送信
            if let Err(_) = tx.send(packet) {
                // 接続されているクライアントがいない場合は無視
            }
        }
    }
}

fn parse_tshark_line(line: &str) -> Option<PacketInfo> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 6 {
        return None;
    }

    let timestamp = parts[0].parse::<f64>().ok()? as u64;
    let src_ip = if parts[1].is_empty() { "N/A".to_string() } else { parts[1].to_string() };
    let dst_ip = if parts[2].is_empty() { "N/A".to_string() } else { parts[2].to_string() };
    let protocol = if parts[3].is_empty() { "Unknown".to_string() } else { 
        parts[3].split(':').next().unwrap_or("Unknown").to_string()
    };
    let length = parts[4].parse::<u32>().unwrap_or(0);
    let info = if parts[5].is_empty() { "N/A".to_string() } else { parts[5].to_string() };

    Some(PacketInfo {
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        length,
        info,
    })
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn stats_handler(State((stats, _, _)): State<(SharedStats, SharedFilter, Broadcaster)>) -> Json<PacketStats> {
    let stats = stats.lock().unwrap();
    Json(stats.clone())
}

async fn set_filter_handler(
    State((_, filter, _)): State<(SharedStats, SharedFilter, Broadcaster)>,
    Json(new_filter): Json<FilterConfig>,
) -> Result<Json<FilterConfig>, StatusCode> {
    let mut filter_guard = filter.lock().unwrap();
    *filter_guard = new_filter.clone();
    info!("フィルタが更新されました: {:?}", new_filter.tshark_filter);
    Ok(Json(new_filter))
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State((_, _, tx)): State<(SharedStats, SharedFilter, Broadcaster)>,
) -> Response {
    ws.on_upgrade(move |socket| websocket_task(socket, tx))
}

async fn websocket_task(socket: WebSocket, tx: Broadcaster) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = tx.subscribe();

    // パケット受信タスク
    let packet_task = tokio::spawn(async move {
        while let Ok(packet) = rx.recv().await {
            let msg = serde_json::to_string(&packet).unwrap();
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // クライアントからのメッセージ処理（ping/pong等）
    let ping_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            if msg.is_err() {
                break;
            }
        }
    });

    // どちらかのタスクが終了したら終了
    tokio::select! {
        _ = packet_task => {},
        _ = ping_task => {},
    }
}