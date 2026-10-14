//! IP geolocation from a local MaxMind-format database (DB-IP "IP to City
//! Lite" by default). Lookups happen on this machine; addresses are never sent
//! to a third party.
//!
//! The database is reopened automatically when the file is replaced (the
//! update script swaps it in with an atomic rename), so updating it does not
//! require restarting the service.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use maxminddb::{Mmap, Reader, geoip2};
use serde::Serialize;
use tracing::{info, warn};

pub const ATTRIBUTION: &str = "IP Geolocation by DB-IP";
pub const ATTRIBUTION_URL: &str = "https://db-ip.com";
const DEFAULT_PATH: &str = "/var/lib/webshark/dbip-city-lite.mmdb";
const RELOAD_CHECK: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoInfo {
    pub lat: f64,
    pub lon: f64,
    /// ISO 3166-1 alpha-2 country code.
    pub cc: String,
    pub country: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
}

struct Loaded {
    reader: Reader<Mmap>,
    modified: Option<SystemTime>,
}

static DB: RwLock<Option<Arc<Loaded>>> = RwLock::new(None);

pub fn db_path() -> PathBuf {
    std::env::var("WEBSHARK_GEOIP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PATH))
}

fn modified(path: &PathBuf) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// (Re)open the database if it exists and changed since it was last loaded.
pub fn reload_if_changed() {
    let path = db_path();
    let current = modified(&path);
    let loaded = DB.read().ok().and_then(|g| g.as_ref().map(|l| l.modified));
    if current.is_none() || loaded == Some(current) {
        return;
    }
    // SAFETY: the file is only ever replaced by renaming a new file over it,
    // never modified in place, so the mapped pages stay valid for the lifetime
    // of this mapping.
    match unsafe { Reader::open_mmap(&path) } {
        Ok(reader) => {
            info!(
                "Loaded GeoIP database {} ({})",
                path.display(),
                reader.metadata().database_type
            );
            if let Ok(mut g) = DB.write() {
                *g = Some(Arc::new(Loaded {
                    reader,
                    modified: current,
                }));
            }
        }
        Err(e) => warn!("Failed to open GeoIP database {}: {}", path.display(), e),
    }
}

/// Periodically pick up a replaced database file.
pub async fn reload_task() {
    loop {
        tokio::time::sleep(RELOAD_CHECK).await;
        tokio::task::spawn_blocking(reload_if_changed).await.ok();
    }
}

pub fn enabled() -> bool {
    DB.read().map(|g| g.is_some()).unwrap_or(false)
}

fn pick<'a>(names: &geoip2::Names<'a>) -> Option<&'a str> {
    names.japanese.or(names.english)
}

pub fn lookup(addr: &str) -> Option<GeoInfo> {
    let ip: IpAddr = addr.parse().ok()?;
    let db = DB.read().ok()?.clone()?;
    let result = db.reader.lookup(ip).ok()?;
    let city: geoip2::City = result.decode().ok()??;
    let lat = city.location.latitude?;
    let lon = city.location.longitude?;
    let cc = city.country.iso_code?.to_string();
    Some(GeoInfo {
        lat,
        lon,
        country: pick(&city.country.names).unwrap_or(&cc).to_string(),
        cc,
        city: pick(&city.city.names).map(str::to_string),
    })
}

/// Where this gateway is: `WEBSHARK_HOME=lat,lon` if set, otherwise the
/// location of the first of our public addresses found in the database.
pub fn home(local_ips: &[String]) -> Option<GeoInfo> {
    if let Ok(v) = std::env::var("WEBSHARK_HOME") {
        if let Some(home) = parse_home(&v) {
            return Some(home);
        }
        warn!(
            "Ignoring invalid WEBSHARK_HOME={:?} (expected \"lat,lon\")",
            v
        );
    }
    local_ips.iter().find_map(|ip| lookup(ip))
}

pub fn parse_home(v: &str) -> Option<GeoInfo> {
    let (lat, lon) = v.split_once(',')?;
    let (lat, lon): (f64, f64) = (lat.trim().parse().ok()?, lon.trim().parse().ok()?);
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some(GeoInfo {
        lat,
        lon,
        cc: String::new(),
        country: String::new(),
        city: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_home_accepts_lat_lon() {
        let h = parse_home(" 35.68, 139.76 ").unwrap();
        assert_eq!((h.lat, h.lon), (35.68, 139.76));
        assert!(parse_home("139.76").is_none());
        assert!(parse_home("95,10").is_none());
        assert!(parse_home("a,b").is_none());
    }

    #[test]
    fn lookup_without_database_is_none() {
        // No database is loaded in unit tests.
        assert!(lookup("8.8.8.8").is_none());
        assert!(lookup("not-an-ip").is_none());
    }
}
