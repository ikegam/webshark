use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use flate2::{Compression, write::GzEncoder};
use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, warn};

use crate::types::{
    Broadcaster, CommandSender, PROTOCOLS, PacketCompact, SharedFilter, SharedStats,
};
use crate::utils::{get_hostname, get_lan_nets, get_local_ips};

/// Upper bound on packets buffered for one client between flushes. Anything
/// beyond this is dropped (and reported) rather than growing memory.
const MAX_BATCH: usize = 5000;
const FLUSH_INTERVAL_MS: u64 = 500;

/// Reject cross-site WebSocket connections. Browsers always send `Origin` on a
/// WebSocket handshake; without this check any web page a LAN user visits could
/// connect to the gateway and read the live traffic feed.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        // Non-browser clients (curl, scripts) don't send Origin.
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin_host = origin.split("://").nth(1).unwrap_or("");
    origin_host.eq_ignore_ascii_case(host)
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State((stats, _, tx, _)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
) -> Response {
    if !origin_allowed(&headers) {
        warn!(
            "Rejected cross-origin WebSocket connection: {:?}",
            headers.get(header::ORIGIN)
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    ws.on_upgrade(move |socket| websocket_task(socket, tx, stats))
}

fn gzip_json<T: serde::Serialize>(value: &T) -> Option<Vec<u8>> {
    let data = serde_json::to_vec(value)
        .map_err(|e| error!("Failed to serialize packet buffer: {}", e))
        .ok()?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&data)
        .map_err(|e| error!("Failed to compress batch data: {}", e))
        .ok()?;
    encoder
        .finish()
        .map_err(|e| error!("Failed to finish compression: {}", e))
        .ok()
}

async fn websocket_task(socket: WebSocket, tx: Broadcaster, stats: SharedStats) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = tx.subscribe();
    let (history, lan_names) = stats
        .lock()
        .map(|s| (s.history.snapshot(), s.lan_names.clone()))
        .unwrap_or_default();
    let mut packet_buffer: Vec<PacketCompact> = Vec::new();
    let mut dropped: u64 = 0;
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(FLUSH_INTERVAL_MS));

    let ctx = serde_json::json!({
        "type": "ctx",
        "protocols": PROTOCOLS,
        "local_ips": get_local_ips(),
        "lan_nets": get_lan_nets(),
        "hostname": get_hostname(),
        "history": history,
        "lan_names": lan_names
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
                            if packet_buffer.len() >= MAX_BATCH {
                                dropped += 1;
                                continue;
                            }
                            packet_buffer.push(PacketCompact::from(packet));
                        }
                        // A slow client fell behind the broadcast channel. Previously
                        // this disconnected the client; skip ahead and report instead.
                        Err(RecvError::Lagged(n)) => {
                            dropped += n;
                        }
                        Err(RecvError::Closed) => break,
                    }
                },
                _ = interval.tick() => {
                    if dropped > 0 {
                        let msg = serde_json::json!({ "type": "dropped", "count": dropped });
                        if sender.send(Message::Text(msg.to_string())).await.is_err() {
                            break;
                        }
                        dropped = 0;
                    }
                    if packet_buffer.is_empty() {
                        continue;
                    }
                    if let Some(compressed) = gzip_json(&packet_buffer) {
                        if sender.send(Message::Binary(compressed)).await.is_err() {
                            break;
                        }
                    }
                    packet_buffer.clear();
                }
            }
        }
    });

    // Drain client messages so pings/close frames are processed.
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            if matches!(msg, Err(_) | Ok(Message::Close(_))) {
                break;
            }
        }
    });

    // Exit when either side ends, and stop the other task so it doesn't linger.
    let packet_abort = packet_task.abort_handle();
    let recv_abort = recv_task.abort_handle();
    tokio::select! {
        _ = packet_task => recv_abort.abort(),
        _ = recv_task => packet_abort.abort(),
    }
}

#[cfg(test)]
mod tests {
    use super::origin_allowed;
    use axum::http::{HeaderMap, HeaderValue, header};

    fn headers(origin: Option<&str>, host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        if let Some(o) = origin {
            h.insert(header::ORIGIN, HeaderValue::from_str(o).unwrap());
        }
        h
    }

    #[test]
    fn same_origin_is_allowed() {
        assert!(origin_allowed(&headers(
            Some("http://192.168.0.1:3000"),
            "192.168.0.1:3000"
        )));
    }

    #[test]
    fn cross_origin_is_rejected() {
        assert!(!origin_allowed(&headers(
            Some("https://evil.example"),
            "192.168.0.1:3000"
        )));
    }

    #[test]
    fn missing_origin_is_allowed() {
        assert!(origin_allowed(&headers(None, "192.168.0.1:3000")));
    }
}
