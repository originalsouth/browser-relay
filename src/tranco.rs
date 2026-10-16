//! Full subdomain-inclusive Tranco index. Inspected hostnames never leave the device.
use crate::{
    Result,
    domain_list::{MAX_RANK_CSV, Rankings},
    inspect::{self, Cancel},
    list_cache,
};
use browser_relay::insights::TRANCO_METADATA as METADATA;
use std::{
    sync::{Mutex, OnceLock},
    time::Duration,
};
static CACHE: OnceLock<Mutex<Option<list_cache::Cached<Rankings>>>> = OnceLock::new();
pub use browser_relay::insights::RankReport as Report;
use browser_relay::insights::{rank_report as report, tranco_metadata as metadata};
fn path() -> Result<std::path::PathBuf> {
    list_cache::path("BROWSER_RELAY_TRANCO_DIR", "tranco.bin")
}
pub fn check(names: &[String]) -> Report {
    match path().and_then(|path| {
        list_cache::load(
            path,
            CACHE.get_or_init(|| Mutex::new(None)),
            Rankings::read_sized,
        )
    }) {
        Ok(db) => report(&db, names, list_cache::now()),
        Err(error) => Report {
            rank: None,
            position: None,
            caption: "Download lists to enable".into(),
            detail: format!("Tranco unavailable: {error}\nNo online fallback was used."),
            available: false,
            stale: false,
        },
    }
}
pub fn update(cancel: &Cancel) -> Result<String> {
    inspect::run_async(cancel, async {
        let client = inspect::client_builder()
            .https_only(true)
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;
        let source = metadata(&list_cache::download(&client, METADATA, 65536).await?)?;
        let bytes = list_cache::download(&client, &source.url(), MAX_RANK_CSV).await?;
        let db = browser_relay::insights::parse_tranco(&source, &bytes, list_cache::now())?;
        let id = &db.list_id;
        list_cache::write(path()?, &db.encode(), cancel)?;
        Ok(format!(
            "Tranco {id}: {} web hostnames indexed from 1,000,000 entries including subdomains. Inspected URLs were not shared.",
            db.domains.len()
        ))
    })
}
