//! Local OISD domain matching. Only explicit updates contact the list publisher.
use crate::list_cache::{self, now};
use crate::{
    Result,
    inspect::{self, Cancel},
};
#[cfg(test)]
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

#[cfg(test)]
use crate::domain_list::List;
use crate::domain_list::{MAX_LIST, Snapshot as Database};
use browser_relay::insights::OISD_SOURCES as SOURCES;

pub use browser_relay::insights::OisdReport as Report;
fn cache_path() -> Result<PathBuf> {
    list_cache::path("BROWSER_RELAY_OISD_DIR", "oisd.bin")
}
type Cached = list_cache::Cached<Database>;
static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();
fn load_cached(path: PathBuf, shared: &Mutex<Option<Cached>>) -> Result<Arc<Database>> {
    list_cache::load(path, shared, Database::read_sized)
}

pub fn check(names: &[String]) -> Report {
    match cache_path().and_then(|path| load_cached(path, CACHE.get_or_init(|| Mutex::new(None)))) {
        Ok(db) => browser_relay::insights::oisd_report(&db, names, now()),
        Err(error) => Report {
            big: None,
            nsfw: None,
            stale: false,
            summary: "OISD · unavailable".into(),
            detail: format!(
                "{error}\nNo safety or content classification was made. No online fallback was used."
            ),
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
        let (big, adult) = tokio::try_join!(
            list_cache::download(&client, SOURCES[0], MAX_LIST),
            list_cache::download(&client, SOURCES[1], MAX_LIST),
        )?;
        let data = browser_relay::insights::parse_oisd(&big, &adult, now())?.encode();
        let path = cache_path()?;
        list_cache::write(path.clone(), &data, cancel)?;
        Ok(format!(
            "OISD Big and NSFW updated in {}. Inspected URLs were not shared.",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_is_shared_and_invalid_replacement_is_not_treated_as_clear() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("relay-cache-test-{}-{nonce}", std::process::id()));
        let snapshot = Database {
            big: List::parse("||listed.example^").unwrap(),
            nsfw: List::parse("||xxx^").unwrap(),
            downloaded: 1,
        };
        fs::write(&path, snapshot.encode()).unwrap();
        let shared = Mutex::new(None);
        let first = load_cached(path.clone(), &shared).unwrap();
        let second = load_cached(path.clone(), &shared).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        fs::write(&path, b"invalid replacement").unwrap();
        assert!(load_cached(path.clone(), &shared).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn domain_boundaries_and_unknown_syntax() {
        let list =
            List::parse("[Adblock Plus]\n! Last modified: today\n||listed.example^\n").unwrap();
        assert_eq!(
            list.matching_domain("a.listed.example"),
            Some("listed.example")
        );
        let tld = List::parse("||xxx^").unwrap();
        assert_eq!(tld.matching_domain("site.xxx"), Some("xxx"));
        assert!(tld.matching_domain("notxxx").is_none());
        for name in ["notlisted.example", "listed.example.evil", "example"] {
            assert!(list.matching_domain(name).is_none());
        }
        for text in [
            "",
            "<html>error</html>",
            "||listed.example^\n@@||exception.example^",
            "||*.example^",
            "||bad..example^",
        ] {
            assert!(List::parse(text).is_err());
        }
    }
}
