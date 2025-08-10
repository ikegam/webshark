use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    Json,
};
use tracing::{error, info, warn};

use crate::types::{Broadcaster, CommandSender, FilterConfig, SharedFilter, SharedStats, PacketStats, CaptureCommand};
use crate::utils::validate_tshark_filter;

pub async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

pub async fn stats_handler(
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

pub async fn set_filter_handler(
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

