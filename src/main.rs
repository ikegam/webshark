mod capture;
mod handlers;
mod history;
mod names;
mod types;
mod utils;
mod websocket;

use axum::routing::{Router, get};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};
use types::{FilterConfig, PacketStats};

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let stats = Arc::new(Mutex::new(PacketStats::default()));

    let filter = Arc::new(Mutex::new(FilterConfig {
        tshark_filter: None,
    }));

    let (tx, _rx) = broadcast::channel(1000);
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (resolve_tx, resolve_rx) = mpsc::unbounded_channel();

    // Resolve hostnames of LAN devices as they appear.
    tokio::spawn(names::resolver_task(stats.clone(), resolve_rx));

    // Start packet capture task
    let stats_clone = stats.clone();
    let filter_clone = filter.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        capture::capture_packets_manager(stats_clone, filter_clone, tx_clone, cmd_rx, resolve_tx)
            .await;
    });

    // Configure web server
    let app = Router::new()
        .route("/", get(handlers::index_handler))
        .route("/api/stats", get(handlers::stats_handler))
        .route("/api/names", get(handlers::names_handler))
        .route(
            "/api/filter",
            get(handlers::filter_handler).post(handlers::set_filter_handler),
        )
        .route("/ws", get(websocket::websocket_handler))
        .route("/static/*path", get(handlers::static_handler))
        .with_state((stats, filter, tx, cmd_tx));

    // Bind address is configurable via WEBSHARK_BIND. Default to loopback so the
    // server is never accidentally exposed on a WAN interface when run on a
    // gateway/router. Set e.g. WEBSHARK_BIND=192.168.0.1:3000 to serve the LAN.
    let bind_addr = std::env::var("WEBSHARK_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    info!(
        "Starting packet visualization server... http://{}",
        bind_addr
    );

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to {}: {}", bind_addr, e);
            error!("Please ensure the address/port is free and the address is valid");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}
