use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
};
use flate2::{write::GzEncoder, Compression};
use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use tracing::error;

use crate::types::{protocol_to_id, Broadcaster, CommandSender, PacketCompact, PROTOCOLS, SharedFilter, SharedStats};
use crate::utils::get_local_ips;

pub async fn websocket_handler(
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

