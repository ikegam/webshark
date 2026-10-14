use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use std::process::Stdio;
use tracing::{error, info, warn};

use crate::types::{
    Broadcaster, CaptureCommand, CommandSender, FilterConfig, PacketStats, SharedFilter,
    SharedStats,
};
use crate::utils::validate_tshark_filter;

pub async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// Static assets are embedded in the binary so it can run from any directory.
pub async fn static_handler(Path(path): Path<String>) -> Response {
    let (body, mime): (&'static str, &'static str) = match path.as_str() {
        "css/styles.css" => (
            include_str!("../static/css/styles.css"),
            "text/css; charset=utf-8",
        ),
        "js/app.js" => (
            include_str!("../static/js/app.js"),
            "text/javascript; charset=utf-8",
        ),
        "js/geo.js" => (
            include_str!("../static/js/geo.js"),
            "text/javascript; charset=utf-8",
        ),
        "js/ws.js" => (
            include_str!("../static/js/ws.js"),
            "text/javascript; charset=utf-8",
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub struct GeoRequest {
    ips: Vec<String>,
}

/// Look up locations for up to 1000 addresses. Unknown/private addresses map to null.
pub async fn geo_handler(
    Json(req): Json<GeoRequest>,
) -> Json<std::collections::HashMap<String, Option<crate::geo::GeoInfo>>> {
    Json(
        req.ips
            .into_iter()
            .take(1000)
            .map(|ip| {
                let info = crate::geo::lookup(&ip);
                (ip, info)
            })
            .collect(),
    )
}

pub async fn names_handler(
    State((stats, _, _, _)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
) -> Json<std::collections::HashMap<String, String>> {
    Json(
        stats
            .lock()
            .map(|s| s.lan_names.clone())
            .unwrap_or_default(),
    )
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

/// Interpret `dumpcap -d` output. dumpcap exits 0 even when the filter does not
/// compile, so success is judged by the presence of compiled BPF instructions
/// such as "(000) ldh [12]" on stdout.
pub fn filter_compile_result(stdout: &str, stderr: &str) -> Result<(), String> {
    if stdout.lines().any(|l| l.trim_start().starts_with("(000)")) {
        return Ok(());
    }
    let msg: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty() && !l.starts_with("Capturing on") && !l.starts_with("See the User")
        })
        .collect();
    Err(if msg.is_empty() {
        "invalid capture filter".to_string()
    } else {
        msg.join(" ")
    })
}

/// Ask dumpcap to compile the capture filter without capturing. Returns the
/// compiler's error message if the filter is invalid. If dumpcap cannot be run
/// at all (e.g. not installed), the check is skipped.
async fn compile_capture_filter(filter: &str) -> Result<(), String> {
    let iface = std::env::var("WEBSHARK_IFACE").unwrap_or_else(|_| "any".to_string());
    let child = tokio::process::Command::new("dumpcap")
        .args(["-i", &iface, "-f", filter, "-d"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(5), child).await {
        Ok(Ok(out)) => filter_compile_result(
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Ok(Err(e)) => {
            warn!(
                "Could not run dumpcap to validate filter, skipping check: {}",
                e
            );
            Ok(())
        }
        Err(_) => Err("filter validation timed out".to_string()),
    }
}

pub async fn set_filter_handler(
    State((_, filter, _, cmd_tx)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
    Json(new_filter): Json<FilterConfig>,
) -> Result<Json<FilterConfig>, (StatusCode, String)> {
    // Validate filter if provided
    if let Some(ref filter_str) = new_filter.tshark_filter {
        if !validate_tshark_filter(filter_str) {
            warn!("Invalid tshark filter rejected: {}", filter_str);
            return Err((
                StatusCode::BAD_REQUEST,
                "filter contains unsupported characters".to_string(),
            ));
        }
        // An invalid BPF expression would make tshark exit immediately and the
        // capture manager would restart it forever. Reject it up front instead.
        if !filter_str.trim().is_empty() {
            if let Err(msg) = compile_capture_filter(filter_str).await {
                warn!("Capture filter failed to compile: {}: {}", filter_str, msg);
                return Err((StatusCode::BAD_REQUEST, msg));
            }
        }
    }

    let mut filter_guard = match filter.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire filter lock: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ));
        }
    };

    *filter_guard = new_filter.clone();
    drop(filter_guard);
    info!("Filter updated: {:?}", new_filter.tshark_filter);

    // Restart packet capture
    if cmd_tx.send(CaptureCommand::Restart).is_err() {
        error!("Failed to send capture restart command");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to restart capture".to_string(),
        ));
    }

    Ok(Json(new_filter))
}

pub async fn filter_handler(
    State((_, filter, _, _)): State<(SharedStats, SharedFilter, Broadcaster, CommandSender)>,
) -> Json<FilterConfig> {
    let current = filter.lock().map(|f| f.clone()).unwrap_or(FilterConfig {
        tshark_filter: None,
    });
    Json(current)
}
