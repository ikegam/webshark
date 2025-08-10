mod types;
mod utils;
mod capture;
mod handlers;
mod websocket;

use axum::{routing::{Router, get}};
use std::{collections::HashMap, sync::{Arc, Mutex}};
use tokio::sync::{broadcast, mpsc};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::{error, info};
use types::{PacketStats, FilterConfig, SharedStats, SharedFilter, Broadcaster, CommandSender};

#[cfg(test)]
mod tests;

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
        capture::capture_packets_manager(stats_clone, filter_clone, tx_clone, cmd_rx).await;
    });

    // Configure web server
    let app = Router::new()
        .route("/", get(handlers::index_handler))
        .route("/api/stats", get(handlers::stats_handler))
        .route("/api/filter", axum::routing::post(handlers::set_filter_handler))
        .route("/ws", get(websocket::websocket_handler))
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
