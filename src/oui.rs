//! MAC address vendor lookup from the IEEE OUI registry (MA-L, `oui.csv`).
//!
//! The file is optional; it is downloaded by `webshark-data-update` and
//! reloaded automatically when replaced.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::SystemTime;

use tracing::{info, warn};

const DEFAULT_PATH: &str = "/var/lib/webshark/oui.csv";

struct Loaded {
    vendors: HashMap<u32, String>,
    modified: Option<SystemTime>,
}

static DB: RwLock<Option<Loaded>> = RwLock::new(None);

pub fn db_path() -> PathBuf {
    std::env::var("WEBSHARK_OUI")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PATH))
}

/// Split one CSV line, honouring double quotes ("" is an escaped quote).
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// Parse the IEEE `oui.csv` (Registry,Assignment,Organization Name,...).
pub fn parse_csv(text: &str) -> HashMap<u32, String> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f = csv_fields(line);
            let prefix = u32::from_str_radix(f.get(1)?.trim(), 16).ok()?;
            let name = f.get(2)?.trim();
            (!name.is_empty() && prefix <= 0xFF_FFFF).then(|| (prefix, name.to_string()))
        })
        .collect()
}

pub fn reload_if_changed() {
    let path = db_path();
    let current = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    let loaded = DB.read().ok().and_then(|g| g.as_ref().map(|l| l.modified));
    if current.is_none() || loaded == Some(current) {
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let vendors = parse_csv(&text);
            info!(
                "Loaded {} OUI vendors from {}",
                vendors.len(),
                path.display()
            );
            if let Ok(mut g) = DB.write() {
                *g = Some(Loaded {
                    vendors,
                    modified: current,
                });
            }
        }
        Err(e) => warn!("Failed to read OUI database {}: {}", path.display(), e),
    }
}

fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = mac.split([':', '-']);
    for b in out.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Locally administered (e.g. randomized "private" Wi-Fi addresses).
pub fn is_local_admin(mac: &str) -> bool {
    parse_mac(mac).is_some_and(|m| m[0] & 0x02 != 0)
}

/// Vendor for a MAC address, if known.
pub fn vendor(mac: &str) -> Option<String> {
    let m = parse_mac(mac)?;
    if m[0] & 0x02 != 0 {
        return None;
    }
    let prefix = (u32::from(m[0]) << 16) | (u32::from(m[1]) << 8) | u32::from(m[2]);
    DB.read().ok()?.as_ref()?.vendors.get(&prefix).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ieee_csv_with_quotes() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
MA-L,38C6CE,\"Nintendo Co.,Ltd\",\"11-1 Kamitoba, Kyoto JP 601-8501\"\n\
MA-L,245EBE,QNAP Systems Inc.,Taipei TW\n\
bad line\n";
        let v = parse_csv(csv);
        assert_eq!(
            v.get(&0x38C6CE).map(String::as_str),
            Some("Nintendo Co.,Ltd")
        );
        assert_eq!(
            v.get(&0x245EBE).map(String::as_str),
            Some("QNAP Systems Inc.")
        );
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn mac_helpers() {
        assert!(is_local_admin("b6:3f:88:7b:2b:6d"));
        assert!(!is_local_admin("38:c6:ce:8a:79:ea"));
        assert!(parse_mac("38:c6:ce:8a:79").is_none());
        assert!(parse_mac("38-C6-CE-8A-79-EA").is_some());
        assert!(vendor("b6:3f:88:7b:2b:6d").is_none()); // random MAC never has a vendor
    }
}
