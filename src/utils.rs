use std::process::Command;

use crate::types::PacketInfo;

pub fn get_local_ips() -> Vec<String> {
    if let Ok(output) = Command::new("hostname").arg("-I").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    Vec::new()
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

pub fn parse_tshark_line(line: &str) -> Option<PacketInfo> {
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

pub fn validate_tshark_filter(filter: &str) -> bool {
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
        "tcp", "udp", "icmp", "arp", "ip", "ipv6", "port", "host", "src", "dst", "and",
        "or", "not", "proto", "ether", "broadcast", "multicast",
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

