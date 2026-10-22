//! Full subdomain-inclusive Tranco index. Inspected hostnames never leave the device.
use crate::{
    Result,
    domain_list::{MAX_RANK_CSV, Rankings},
    inspect::{self, Cancel},
    list_cache,
};
use browser_relay::insights::TRANCO_METADATA as METADATA;
use browser_relay::{
    lookalike::BrandIndex,
    risk::{self, Context, Factor, Facts},
};
use std::{
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};
static CACHE: OnceLock<Mutex<Option<list_cache::Cached<Rankings>>>> = OnceLock::new();
pub use browser_relay::insights::RankReport as Report;
use browser_relay::insights::{rank_report as report, tranco_metadata as metadata};
fn path() -> Result<std::path::PathBuf> {
    list_cache::path("BROWSER_RELAY_TRANCO_DIR", "tranco.bin")
}
/// Holds the source index weakly so a replaced ranking list can be freed.
static BRANDS: Mutex<Option<(Weak<Rankings>, Arc<BrandIndex>)>> = Mutex::new(None);

fn rankings() -> Result<Arc<Rankings>> {
    path().and_then(|path| {
        list_cache::load(
            path,
            CACHE.get_or_init(|| Mutex::new(None)),
            Rankings::read_sized,
        )
    })
}
/// Built once per loaded index; rebuilt only when the cache file changes.
fn brands(db: &Arc<Rankings>) -> Arc<BrandIndex> {
    let mut cached = BRANDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((source, index)) = cached.as_ref()
        && source
            .upgrade()
            .is_some_and(|alive| Arc::ptr_eq(&alive, db))
    {
        return index.clone();
    }
    let index = Arc::new(BrandIndex::build(db));
    *cached = Some((Arc::downgrade(db), index.clone()));
    index
}
/// Factors plus whether lookalike checks could run (a ranking index is loaded).
pub fn risk(facts: &Facts) -> (Vec<Factor>, bool) {
    let now = i64::try_from(list_cache::now()).unwrap_or(i64::MAX);
    match rankings() {
        Ok(db) => {
            let brands = brands(&db);
            (
                risk::assess(
                    facts,
                    Some(&Context {
                        rankings: &db,
                        brands: &brands,
                    }),
                    now,
                ),
                true,
            )
        }
        Err(_) => (risk::assess(facts, None, now), false),
    }
}
pub fn check(names: &[String]) -> Report {
    match rankings() {
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
