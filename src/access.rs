//! Host header allow-list (DNS-rebinding protection).
//!
//! A page on evil.example can re-point its own name at the gateway's address;
//! the browser then treats requests to the gateway as same-origin, with
//! `Host: evil.example:3000`. Accepting only Host values that name this
//! machine (its addresses, hostname, localhost, or WEBSHARK_ALLOWED_HOSTS)
//! closes that hole. The WebSocket Origin check compares Origin to Host, so
//! it relies on this too.

use std::net::SocketAddr;

use axum::{
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;

use crate::netinfo::NetInfo;

/// Split a Host header into (host, port). Handles "[v6]:port" and "v6".
fn split_host(value: &str) -> Option<(String, Option<u16>)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    match value.matches(':').count() {
        0 => Some((value.to_ascii_lowercase(), None)),
        1 => {
            let (h, p) = value.split_once(':')?;
            Some((h.to_ascii_lowercase(), Some(p.parse().ok()?)))
        }
        _ => Some((value.to_ascii_lowercase(), None)), // bare IPv6 literal
    }
}

pub fn host_allowed(host_header: &str, bind: SocketAddr, net: &NetInfo, extra: &[String]) -> bool {
    let Some((host, port)) = split_host(host_header) else {
        return false;
    };
    if port.unwrap_or(80) != bind.port() {
        return false;
    }
    let host = host.trim_end_matches('.');
    let mut names: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if bind.ip().is_unspecified() {
        names.extend(net.local_ips.iter().map(|ip| ip.to_ascii_lowercase()));
    } else {
        names.push(bind.ip().to_string().to_ascii_lowercase());
    }
    if !net.hostname.is_empty() {
        let h = net.hostname.to_ascii_lowercase();
        names.push(format!("{}.local", h));
        names.push(h);
    }
    names.extend(
        extra
            .iter()
            .map(|e| e.trim().trim_end_matches('.').to_ascii_lowercase()),
    );
    names.iter().any(|n| n == host)
}

fn extra_hosts() -> Vec<String> {
    std::env::var("WEBSHARK_ALLOWED_HOSTS")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub async fn check_host(req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host_allowed(
        host,
        crate::capture::ui_bind(),
        &crate::netinfo::current(),
        &extra_hosts(),
    ) {
        return next.run(req).await;
    }
    warn!("Rejected request with unexpected Host header {:?}", host);
    (
        StatusCode::MISDIRECTED_REQUEST,
        "Unexpected Host header. Add the name to WEBSHARK_ALLOWED_HOSTS to allow it.",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetInfo {
        NetInfo {
            version: 1,
            local_ips: vec!["192.168.0.1".into(), "2409:10:bec0:4201::1".into()],
            lan_nets: vec![],
            hostname: "route2".into(),
        }
    }

    #[test]
    fn allows_own_names_and_addresses() {
        let bind: SocketAddr = "192.168.0.1:3000".parse().unwrap();
        let n = net();
        for h in [
            "192.168.0.1:3000",
            "route2:3000",
            "ROUTE2.local:3000",
            "localhost:3000",
            "[::1]:3000",
        ] {
            assert!(host_allowed(h, bind, &n, &[]), "{h}");
        }
        assert!(host_allowed(
            "webshark.home.arpa:3000",
            bind,
            &n,
            &["webshark.home.arpa".into()]
        ));
    }

    #[test]
    fn rejects_rebinding_and_wrong_port() {
        let bind: SocketAddr = "192.168.0.1:3000".parse().unwrap();
        let n = net();
        for h in [
            "evil.example:3000",
            "192.168.0.1:8080",
            "192.168.0.1",
            "",
            "[::1",
            "route2:abc",
        ] {
            assert!(!host_allowed(h, bind, &n, &[]), "{h}");
        }
        // Only the bound address, not every local address, when bound to one.
        assert!(!host_allowed("[2409:10:bec0:4201::1]:3000", bind, &n, &[]));
    }

    #[test]
    fn unspecified_bind_allows_all_local_addresses() {
        let bind: SocketAddr = "0.0.0.0:3000".parse().unwrap();
        assert!(host_allowed(
            "[2409:10:bec0:4201::1]:3000",
            bind,
            &net(),
            &[]
        ));
    }
}
