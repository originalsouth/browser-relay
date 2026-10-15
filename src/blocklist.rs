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
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use crate::domain_list::{List, MAX_CACHE, MAX_LIST, Snapshot as Database};
const STALE_AFTER: u64 = 7 * 24 * 60 * 60;
const SOURCES: [&str; 2] = ["https://big.oisd.nl/", "https://nsfw.oisd.nl/"];

pub struct Report {
    pub summary: String,
    pub detail: String,
    pub big: Option<bool>,
    pub nsfw: Option<bool>,
    pub stale: bool,
}
fn cache_path() -> Result<PathBuf> {
    list_cache::path("BROWSER_RELAY_OISD_DIR", "oisd.bin")
}
type Cached = list_cache::Cached<Database>;
static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();
impl Database {
    fn load() -> Result<Arc<Self>> {
        Self::load_cached(cache_path()?, CACHE.get_or_init(|| Mutex::new(None)))
    }
    fn load_cached(path: PathBuf, shared: &Mutex<Option<Cached>>) -> Result<Arc<Self>> {
        list_cache::load(path, shared, MAX_CACHE, Self::decode)
    }
    fn report(&self, names: &[String], timestamp: u64) -> Report {
        let mut big = false;
        let mut nsfw = false;
        let mut details = Vec::new();
        for name in names {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.parse::<IpAddr>().is_ok() {
                details.push(format!(
                    "{name}: IP literal; these domain lists cannot classify it."
                ));
                continue;
            }
            let a = self.big.matching_domain(&name);
            let b = self.nsfw.matching_domain(&name);
            big |= a.is_some();
            nsfw |= b.is_some();
            details.push(format!(
                "{name}\n  OISD Big: {}\n  OISD NSFW: {}",
                a.unwrap_or("not listed"),
                b.unwrap_or("not listed")
            ));
        }
        let source_stale = [&self.big, &self.nsfw].iter().any(|list| {
            gtk::glib::DateTime::from_iso8601(&list.modified, None)
                .ok()
                .and_then(|date| u64::try_from(date.to_unix()).ok())
                .is_none_or(|date| timestamp < date || timestamp - date > STALE_AFTER)
        });
        let stale = source_stale
            || timestamp < self.downloaded
            || timestamp - self.downloaded > STALE_AFTER;
        let ip_only = !names.is_empty() && names.iter().all(|n| n.parse::<IpAddr>().is_ok());
        let verdict = match (big, nsfw, ip_only) {
            (true, true, _) => "OISD + NSFW listed",
            (true, false, _) => "OISD listed · category mixed",
            (false, true, _) => "NSFW listed",
            (_, _, true) => "OISD · IPs not classified",
            _ => "OISD · not listed · trust unknown",
        };
        Report {
            big: (!ip_only).then_some(big),
            nsfw: (!ip_only).then_some(nsfw),
            stale,
            summary: format!("{verdict}{}", if stale { " · stale cache" } else { "" }),
            detail: format!(
                "{}\n\nOISD Big: ads/tracking and security threats; a match does not distinguish them. NSFW: adult/shock content, not a malware verdict. Not listed never means safe. Rules include subdomains. Results cover only the hostnames inspected so far.\n\nBig source date: {}\nNSFW source date: {}\nCache age: {} days{}. Updates are manual. Matching is offline; no inspected name or URL is sent to OISD.\nSource: https://oisd.nl/setup · data license: https://github.com/sjhgvr/oisd/blob/main/LICENSE",
                details.join("\n"),
                self.big.modified,
                self.nsfw.modified,
                timestamp.saturating_sub(self.downloaded) / 86400,
                if stale {
                    " — stale or clock changed; update before relying on coverage"
                } else {
                    ""
                }
            ),
        }
    }
}
pub fn check(names: &[String]) -> Report {
    match Database::load() {
        Ok(db) => db.report(names, now()),
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
        let mut lists = Vec::new();
        for source in SOURCES {
            let bytes = list_cache::download(&client, source, MAX_LIST).await?;
            let text = String::from_utf8(bytes).map_err(|_| "OISD download is not UTF-8.")?;
            lists.push(List::parse(&text)?);
        }
        let nsfw = lists.pop().unwrap();
        let big = lists.pop().unwrap();
        let data = Database {
            big,
            nsfw,
            downloaded: now(),
        }
        .encode();
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
        let first = Database::load_cached(path.clone(), &shared).unwrap();
        let second = Database::load_cached(path.clone(), &shared).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        fs::write(&path, b"invalid replacement").unwrap();
        assert!(Database::load_cached(path.clone(), &shared).is_err());
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
    #[test]
    fn categories_accumulate_without_claiming_safety() {
        let db = Database {
            big: List::parse("! Last modified: 1970-01-01T00:01:40+0000\n||track.example^")
                .unwrap(),
            nsfw: List::parse("! Last modified: 1970-01-01T00:01:40+0000\n||adult.example^")
                .unwrap(),
            downloaded: 100,
        };
        let report = db.report(
            &[
                "TRACK.example.".into(),
                "www.adult.example".into(),
                "clean.example".into(),
            ],
            101,
        );
        assert_eq!(report.summary, "OISD + NSFW listed");
        assert_eq!(
            (report.big, report.nsfw, report.stale),
            (Some(true), Some(true), false)
        );
        assert!(
            report.detail.contains("category") || report.detail.contains("does not distinguish")
        );
        assert!(
            db.report(&["clean.example".into()], 101)
                .summary
                .contains("trust unknown")
        );
        assert!(
            db.report(&["clean.example".into()], STALE_AFTER + 101)
                .summary
                .contains("stale")
        );
        let stale_source = Database {
            downloaded: STALE_AFTER + 200,
            ..db
        };
        assert!(
            stale_source
                .report(&["clean.example".into()], STALE_AFTER + 201)
                .summary
                .contains("stale")
        );
        assert!(
            stale_source
                .report(&["127.0.0.1".into()], 101)
                .summary
                .contains("not classified")
        );
    }
}
