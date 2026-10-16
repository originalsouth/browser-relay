//! Local MMDB lookup shared by the desktop and mobile storage adapters.
use crate::Result;
use serde_json::Value;
use std::net::IpAddr;
#[derive(Clone)]
pub struct Location {
    pub name: String,
    pub country_code: String,
    pub detail: String,
}
pub fn lookup(path: &std::path::Path, ip: IpAddr) -> Result<Location> {
    let reader = maxminddb::Reader::open_readfile(path)
        .map_err(|e| format!("Could not read local GeoIP database: {e}"))?;
    let value: Value = reader
        .lookup(ip)
        .map_err(|e| e.to_string())?
        .decode()
        .map_err(|e| e.to_string())?
        .ok_or("The local GeoIP database has no entry for this IP.")?;
    let city = value["city"]["names"]["en"].as_str();
    let country = value["country"]["names"]["en"]
        .as_str()
        .or(value["country"]["iso_code"].as_str());
    let location = [city, country]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
    let detail = format!(
        "{}\nDatabase: {} · built {}\nApproximate IP location; may identify a CDN/proxy, not the origin server. DB-IP Lite data, when installed: db-ip.com · CC BY 4.0.",
        if location.is_empty() {
            "Location unavailable"
        } else {
            &location
        },
        path.display(),
        time::OffsetDateTime::from_unix_timestamp(reader.metadata().build_epoch as i64)
            .map(|date| date.date().to_string())
            .unwrap_or_else(|_| "unknown".into())
    );
    Ok(Location {
        name: if location.is_empty() {
            "Location unavailable".into()
        } else {
            location
        },
        country_code: value["country"]["iso_code"].as_str().unwrap_or("").into(),
        detail,
    })
}
