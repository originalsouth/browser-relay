//! Full subdomain-inclusive Tranco index. Inspected hostnames never leave the device.
use crate::{
    Result,
    domain_list::{MAX_RANK_CACHE, MAX_RANK_CSV, Rankings},
    inspect::{self, Cancel},
    list_cache,
};
use std::{
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::Duration,
};
const METADATA: &str = "https://tranco-list.eu/api/lists/date/latest?subdomains=true";
const STALE_AFTER: u64 = 7 * 86400;
static CACHE: OnceLock<Mutex<Option<list_cache::Cached<Rankings>>>> = OnceLock::new();
pub struct Report {
    pub rank: Option<u32>,
    pub caption: String,
    pub detail: String,
    pub available: bool,
    pub stale: bool,
}
fn path() -> Result<std::path::PathBuf> {
    list_cache::path("BROWSER_RELAY_TRANCO_DIR", "tranco.bin")
}
fn report(db: &Rankings, names: &[String], now: u64) -> Report {
    let latest = names
        .last()
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    let applicable = latest.parse::<IpAddr>().is_err();
    let matched = applicable.then(|| db.lookup(&latest)).flatten();
    let stale = gtk::glib::DateTime::from_iso8601(&db.domains.modified, None)
        .ok()
        .and_then(|date| u64::try_from(date.to_unix()).ok())
        .is_none_or(|date| now < date || now - date > STALE_AFTER)
        || now < db.downloaded
        || now.saturating_sub(db.downloaded) > STALE_AFTER;
    let caption = match matched {
        Some((domain, _)) if domain != latest => format!("Parent · {domain}"),
        Some(_) => format!("Exact · {latest}"),
        None if !applicable => "IP address · not ranked".into(),
        None => "Outside this top million".into(),
    };
    let route: Vec<_> = names.iter().map(|name| {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        match db.lookup(&name) {
            Some((domain, rank)) if domain == name => format!("{name}: #{rank} (exact hostname)"),
            Some((domain, rank)) => format!("{name}: unranked; parent {domain} is #{rank}. This is NOT the subdomain's rank."),
            None => format!("{name}: no rank in this list"),
        }
    }).collect();
    Report {
        rank: matched.map(|(_, rank)| rank),
        caption,
        available: true,
        stale,
        detail: format!(
            "{}\n\nTranco top million, including subdomains · list {}\n{} web hostnames indexed; non-web DNS records excluded without changing ranks.\nSource date: {} · downloaded {} days ago{}\nPopularity is not trust or a safety verdict. An unranked hostname is not necessarily unsafe. Parent matches are context only; OISD warnings are never overridden. The tile describes the latest inspected host; the history above covers all inspected hosts.\nMatching is offline. Manual downloads send no inspected hostname or URL.\nSource and data terms: https://tranco-list.eu/",
            route.join("\n"),
            db.list_id,
            db.domains.len(),
            db.domains.modified,
            now.saturating_sub(db.downloaded) / 86400,
            if stale { " · STALE: update lists" } else { "" }
        ),
    }
}
pub fn check(names: &[String]) -> Report {
    match path().and_then(|path| {
        list_cache::load(
            path,
            CACHE.get_or_init(|| Mutex::new(None)),
            MAX_RANK_CACHE,
            Rankings::decode,
        )
    }) {
        Ok(db) => report(&db, names, list_cache::now()),
        Err(error) => Report {
            rank: None,
            caption: "Download lists to enable".into(),
            detail: format!("Tranco unavailable: {error}\nNo online fallback was used."),
            available: false,
            stale: false,
        },
    }
}
fn metadata(bytes: &[u8]) -> Result<(String, String)> {
    let data: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if data["available"].as_bool() != Some(true)
        || data["failed"].as_bool() != Some(false)
        || data["configuration"]["filterPLD"].as_str() == Some("on")
    {
        return Err("The subdomain-inclusive Tranco list is unavailable.".into());
    }
    let id = data["list_id"].as_str().ok_or("Missing Tranco list ID.")?;
    if id.is_empty() || id.len() > 32 || !id.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err("Invalid Tranco list ID.".into());
    }
    let date = data["configuration"]["endDate"]
        .as_str()
        .ok_or("Missing Tranco source date.")?;
    if date.len() != 10
        || !date.bytes().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
    {
        return Err("Invalid Tranco date.".into());
    }
    let date = format!("{date}T00:00:00Z");
    gtk::glib::DateTime::from_iso8601(&date, None).map_err(|_| "Invalid Tranco date.")?;
    // Never trust a server-supplied download URL: keep both requests on the fixed publisher origin.
    Ok((
        format!("https://tranco-list.eu/download/{id}/1000000"),
        date,
    ))
}
pub fn update(cancel: &Cancel) -> Result<String> {
    inspect::run_async(cancel, async {
        let client = inspect::client_builder()
            .https_only(true)
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;
        let (url, date) = metadata(&list_cache::download(&client, METADATA, 65536).await?)?;
        let bytes = list_cache::download(&client, &url, MAX_RANK_CSV).await?;
        let csv = std::str::from_utf8(&bytes).map_err(|_| "Tranco CSV is not UTF-8.")?;
        let id = url.split('/').nth(4).ok_or("Invalid list URL.")?;
        let db = Rankings::parse(csv, id, &date, list_cache::now())?;
        if db.source_entries != 1_000_000 {
            return Err("Incomplete Tranco top million; previous cache kept.".into());
        }
        list_cache::write(path()?, &db.encode(), cancel)?;
        Ok(format!(
            "Tranco {id}: {} web hostnames indexed from 1,000,000 entries including subdomains. Inspected URLs were not shared.",
            db.domains.len()
        ))
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_cannot_redirect_downloads_or_disable_subdomains() {
        let mut value = serde_json::json!({"available":true,"failed":false,"list_id":"ABC12","download":"https://evil.example/", "configuration":{"endDate":"2026-10-14"}});
        assert_eq!(
            metadata(value.to_string().as_bytes()).unwrap().0,
            "https://tranco-list.eu/download/ABC12/1000000"
        );
        value["list_id"] = "../evil".into();
        assert!(metadata(value.to_string().as_bytes()).is_err());
        value["list_id"] = "ABC12".into();
        value["configuration"]["filterPLD"] = "on".into();
        assert!(metadata(value.to_string().as_bytes()).is_err());
    }
    #[test]
    fn parent_context_is_explicit_and_final_host_does_not_inherit_previous_rank() {
        let db = Rankings::parse(
            "1,example.com\n2,child.example.com\n",
            "TEST",
            "1970-01-01T00:01:40Z",
            100,
        )
        .unwrap();
        let exact = report(&db, &["CHILD.example.com.".into()], 101);
        assert_eq!(exact.rank, Some(2));
        assert!(exact.caption.starts_with("Exact"));
        assert!(!exact.stale);
        let parent = report(&db, &["tenant.example.com".into()], 101);
        assert!(parent.caption.starts_with("Parent"));
        assert!(parent.detail.contains("NOT the subdomain's rank"));
        let final_host = report(&db, &["example.com".into(), "unranked.invalid".into()], 101);
        assert!(final_host.rank.is_none());
        assert!(final_host.detail.contains("example.com: #1"));
        assert!(report(&db, &["example.com".into()], STALE_AFTER + 101).stale);
        assert!(report(&db, &["127.0.0.1".into()], 101).rank.is_none());
    }
}
