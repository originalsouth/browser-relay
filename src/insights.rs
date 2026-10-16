//! Shared local reputation assessments and list-publisher protocol.
use crate::{
    Result,
    domain_list::{Rankings, Snapshot},
};
use std::net::IpAddr;
pub const OISD_SOURCES: [&str; 2] = ["https://big.oisd.nl/", "https://nsfw.oisd.nl/"];
pub const TRANCO_METADATA: &str = "https://tranco-list.eu/api/lists/date/latest?subdomains=true";
const STALE_AFTER: u64 = 7 * 86400;
fn source_timestamp(value: &str) -> Option<u64> {
    // OISD uses ISO 8601's +0000; Tranco uses RFC 3339's Z or +00:00.
    let mut normalized = value.to_owned();
    if value.len() >= 5 {
        let offset = &value.as_bytes()[value.len() - 5..];
        if matches!(offset[0], b'+' | b'-') && offset[1..].iter().all(u8::is_ascii_digit) {
            normalized.insert(value.len() - 2, ':');
        }
    }
    time::OffsetDateTime::parse(&normalized, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|d| u64::try_from(d.unix_timestamp()).ok())
}
pub struct OisdReport {
    pub summary: String,
    pub detail: String,
    pub big: Option<bool>,
    pub nsfw: Option<bool>,
    pub stale: bool,
}
impl OisdReport {
    pub fn note(&self, rank: &RankReport) -> String {
        let state = match (self.big, self.nsfw) {
            (Some(true), Some(true)) => "Blocklist + adult matches",
            (Some(true), _) => "Blocklist match",
            (_, Some(true)) => "Adult content match",
            (None, _) | (_, None) => "Classification unavailable",
            _ if !rank.available => "Popularity unavailable",
            _ => "No list matches · trust unknown",
        };
        format!(
            "{state}{}",
            if self.stale || rank.stale {
                " · stale data"
            } else {
                ""
            }
        )
    }
}
pub fn oisd_report(db: &Snapshot, names: &[String], timestamp: u64) -> OisdReport {
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
        let a = db.big.matching_domain(&name);
        let b = db.nsfw.matching_domain(&name);
        big |= a.is_some();
        nsfw |= b.is_some();
        details.push(format!(
            "{name}\n  OISD Big: {}\n  OISD NSFW: {}",
            a.unwrap_or("not listed"),
            b.unwrap_or("not listed")
        ));
    }
    let source_stale = [&db.big, &db.nsfw].iter().any(|list| {
        source_timestamp(&list.modified)
            .is_none_or(|date| timestamp < date || timestamp - date > STALE_AFTER)
    });
    let stale =
        source_stale || timestamp < db.downloaded || timestamp - db.downloaded > STALE_AFTER;
    let ip_only = !names.is_empty() && names.iter().all(|n| n.parse::<IpAddr>().is_ok());
    let verdict = match (big, nsfw, ip_only) {
        (true, true, _) => "OISD + NSFW listed",
        (true, false, _) => "OISD listed · category mixed",
        (false, true, _) => "NSFW listed",
        (_, _, true) => "OISD · IPs not classified",
        _ => "OISD · not listed · trust unknown",
    };
    OisdReport {
        big: (!ip_only).then_some(big),
        nsfw: (!ip_only).then_some(nsfw),
        stale,
        summary: format!("{verdict}{}", if stale { " · stale cache" } else { "" }),
        detail: format!(
            "{}\n\nOISD Big: ads/tracking and security threats; a match does not distinguish them. NSFW: adult/shock content, not a malware verdict. Not listed never means safe. Rules include subdomains. Results cover only the hostnames inspected so far.\n\nBig source date: {}\nNSFW source date: {}\nCache age: {} days{}. Updates are manual. Matching is offline; no inspected name or URL is sent to OISD.\nSource: https://oisd.nl/setup · data license: https://github.com/sjhgvr/oisd/blob/main/LICENSE",
            details.join("\n"),
            db.big.modified,
            db.nsfw.modified,
            timestamp.saturating_sub(db.downloaded) / 86400,
            if stale {
                " — stale or clock changed; update before relying on coverage"
            } else {
                ""
            }
        ),
    }
}
/// Normalized arctangent over logarithmic rank: #1 = green (0), #1M = red (1).
/// This measures popularity, never probability of harm.
pub fn popularity_position(rank: u32) -> f64 {
    // Center the bend near #100k so established regional sites remain green.
    // Normalize both ends after atan; log rank alone would turn amber at #1k.
    let logarithmic = f64::from(rank.clamp(1, 1_000_000)).log10();
    let lower = (-10.0_f64).atan();
    let upper = 2.0_f64.atan();
    (((2.0 * (logarithmic - 5.0)).atan() - lower) / (upper - lower)).clamp(0.0, 1.0)
}

/// Shared green → amber → red palette for the native interfaces.
pub fn popularity_rgb(position: f64) -> [u8; 3] {
    let position = position.clamp(0.0, 1.0);
    let green = [140.0, 221.0, 165.0];
    let amber = [255.0, 194.0, 125.0];
    let red = [255.0, 137.0, 149.0];
    let (start, end, blend) = if position <= 0.5 {
        (green, amber, position * 2.0)
    } else {
        (amber, red, (position - 0.5) * 2.0)
    };
    std::array::from_fn(|i| (start[i] + (end[i] - start[i]) * blend).round() as u8)
}

pub struct RankReport {
    pub rank: Option<u32>,
    pub position: Option<f64>,
    pub caption: String,
    pub detail: String,
    pub available: bool,
    pub stale: bool,
}
pub fn rank_report(db: &Rankings, names: &[String], now: u64) -> RankReport {
    let latest = names
        .last()
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    let applicable = !latest.is_empty() && latest.parse::<IpAddr>().is_err();
    let matched = applicable.then(|| db.lookup(&latest)).flatten();
    let exact_rank = matched
        .filter(|(domain, _)| *domain == latest)
        .map(|(_, rank)| rank);
    let stale = source_timestamp(&db.domains.modified)
        .is_none_or(|date| now < date || now - date > STALE_AFTER)
        || now < db.downloaded
        || now.saturating_sub(db.downloaded) > STALE_AFTER;
    let caption = match matched {
        Some((domain, rank)) if domain != latest => format!("Parent #{rank} · {domain}"),
        Some(_) => format!("Exact · {latest}"),
        None if latest.is_empty() => "No hostname · not ranked".into(),
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
    RankReport {
        rank: exact_rank,
        position: applicable.then(|| exact_rank.map_or(1.0, popularity_position)),
        caption,
        available: true,
        stale,
        detail: format!(
            "{}\n\nTranco top million, including subdomains · list {}\n{} web hostnames indexed; non-web DNS records excluded without changing ranks.\nSource date: {} · downloaded {} days ago{}\nColor scale: log rank with normalized arctangent, 0 = #1 (green), 1 = #1,000,000 or outside the index (red). Gray means unavailable or not applicable. Popularity is not trust or a safety verdict. An unranked hostname is not necessarily unsafe. Parent matches are context only; OISD warnings are never overridden. The tile describes the latest inspected host; the history above covers all inspected hosts.\nMatching is offline. Manual downloads send no inspected hostname or URL.\nSource and data terms: https://tranco-list.eu/",
            route.join("\n"),
            db.list_id,
            db.domains.len(),
            db.domains.modified,
            now.saturating_sub(db.downloaded) / 86400,
            if stale { " · STALE: update lists" } else { "" }
        ),
    }
}
pub fn tranco_metadata(bytes: &[u8]) -> Result<TrancoSource> {
    let data: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if data["available"].as_bool() != Some(true)
        || data["failed"].as_bool() != Some(false)
        || data["configuration"]["filterPLD"].as_str() == Some("on")
    {
        return Err("The subdomain-inclusive Tranco list is unavailable.".into());
    }
    TrancoSource::new(
        data["list_id"].as_str().ok_or("Missing Tranco list ID.")?,
        data["configuration"]["endDate"]
            .as_str()
            .ok_or("Missing Tranco source date.")?,
    )
}

/// One validated publisher descriptor binds the download URL to the resulting index.
pub struct TrancoSource {
    id: String,
    date: String,
}
impl TrancoSource {
    pub fn new(id: &str, date: &str) -> Result<Self> {
        if id.is_empty() || id.len() > 32 || !id.bytes().all(|c| c.is_ascii_alphanumeric()) {
            return Err("Invalid Tranco list ID.".into());
        }
        if date.len() != 10
            || !date.bytes().enumerate().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == b'-'
                } else {
                    c.is_ascii_digit()
                }
            })
            || source_timestamp(&format!("{date}T00:00:00Z")).is_none()
        {
            return Err("Invalid Tranco date.".into());
        }
        Ok(Self {
            id: id.into(),
            date: date.into(),
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn date(&self) -> &str {
        &self.date
    }
    pub fn url(&self) -> String {
        // Never use a server-provided download URL.
        format!("https://tranco-list.eu/download/{}/1000000", self.id)
    }
}

#[cfg(test)]
mod rank_tests {
    use super::*;
    use super::{rank_report as report, tranco_metadata as metadata};
    #[test]
    fn popularity_curve_has_exact_endpoints_and_is_monotonic() {
        assert_eq!(popularity_position(1), 0.0);
        assert!(popularity_position(10_000) < 0.15);
        // nos.nl is #4,821 in the development snapshot; keep that rank clearly green.
        assert!((0.10..0.11).contains(&popularity_position(4_821)));
        assert!((0.5..0.6).contains(&popularity_position(100_000)));
        assert_eq!(popularity_position(1_000_000), 1.0);
        assert_eq!(popularity_rgb(0.0), [140, 221, 165]);
        assert_eq!(popularity_rgb(0.5), [255, 194, 125]);
        assert_eq!(popularity_rgb(1.0), [255, 137, 149]);
        let mut previous = 0.0;
        for rank in (1..=1_000_000).step_by(37) {
            let position = popularity_position(rank);
            assert!((0.0..=1.0).contains(&position) && position >= previous);
            previous = position;
        }
        let db = Rankings::parse("1,example.com\n", "TEST", "1970-01-01T00:01:40Z", 100).unwrap();
        assert_eq!(
            report(&db, &["tenant.example.com".into()], 101).position,
            Some(1.0)
        );
        assert_eq!(
            report(&db, &["unranked.invalid".into()], 101).position,
            Some(1.0)
        );
        assert_eq!(report(&db, &["127.0.0.1".into()], 101).position, None);
        assert_eq!(report(&db, &[], 101).position, None);
    }
    #[test]
    fn metadata_cannot_redirect_downloads_or_disable_subdomains() {
        let mut value = serde_json::json!({"available":true,"failed":false,"list_id":"ABC12","download":"https://evil.example/", "configuration":{"endDate":"2026-10-14"}});
        assert_eq!(
            metadata(value.to_string().as_bytes()).unwrap().url(),
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
        assert!(parent.caption.starts_with("Parent #1"));
        assert_eq!(parent.rank, None);
        assert_eq!(parent.position, Some(1.0));
        assert!(parent.detail.contains("NOT the subdomain's rank"));
        let final_host = report(&db, &["example.com".into(), "unranked.invalid".into()], 101);
        assert!(final_host.rank.is_none());
        assert!(final_host.detail.contains("example.com: #1"));
        assert!(report(&db, &["example.com".into()], STALE_AFTER + 101).stale);
        assert!(report(&db, &["127.0.0.1".into()], 101).rank.is_none());
    }
}

#[cfg(test)]
mod oisd_tests {
    use super::*;
    use crate::domain_list::List;
    #[test]
    fn empty_hosts_are_not_ip_only_and_warnings_take_precedence() {
        let db = Snapshot {
            big: List::parse("! Last modified: 1970-01-01T00:01:40+0000\n||track.example^")
                .unwrap(),
            nsfw: List::parse("! Last modified: 1970-01-01T00:01:40+0000\n||adult.example^")
                .unwrap(),
            downloaded: 100,
        };
        let rankings =
            Rankings::parse("1,clean.example\n", "TEST", "1970-01-01T00:01:40Z", 100).unwrap();
        let mut rank = rank_report(&rankings, &[], 101);
        let empty = oisd_report(&db, &[], 101);
        assert_eq!((empty.big, empty.nsfw), (Some(false), Some(false)));
        assert!(empty.summary.contains("not listed"));
        assert_eq!(oisd_report(&db, &["127.0.0.1".into()], 101).big, None);
        for (names, warning) in [
            (vec!["track.example".into()], "Blocklist match"),
            (vec!["adult.example".into()], "Adult content match"),
            (
                vec!["track.example".into(), "adult.example".into()],
                "Blocklist + adult matches",
            ),
        ] {
            let report = oisd_report(&db, &names, 101);
            rank.available = true;
            assert_eq!(report.note(&rank), warning);
            rank.available = false;
            assert_eq!(report.note(&rank), warning);
            rank.stale = true;
            assert_eq!(report.note(&rank), format!("{warning} · stale data"));
            rank.stale = false;
        }
        rank.available = true;
        assert_eq!(empty.note(&rank), "No list matches · trust unknown");
    }

    #[test]
    fn categories_accumulate_without_claiming_safety() {
        let db = Snapshot {
            big: List::parse("! Last modified: 1970-01-01T00:01:40+0000\n||track.example^")
                .unwrap(),
            nsfw: List::parse("! Last modified: 1970-01-01T00:01:40+0000\n||adult.example^")
                .unwrap(),
            downloaded: 100,
        };
        let report = oisd_report(
            &db,
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
            oisd_report(&db, &["clean.example".into()], 101)
                .summary
                .contains("trust unknown")
        );
        assert!(
            oisd_report(&db, &["clean.example".into()], STALE_AFTER + 101)
                .summary
                .contains("stale")
        );
        let stale_source = Snapshot {
            downloaded: STALE_AFTER + 200,
            ..db
        };
        assert!(
            oisd_report(&stale_source, &["clean.example".into()], STALE_AFTER + 201)
                .summary
                .contains("stale")
        );
        assert!(
            oisd_report(&stale_source, &["127.0.0.1".into()], 101)
                .summary
                .contains("not classified")
        );
    }
}

/// Parse both OISD lists before an adapter replaces the previous on-device snapshot.
pub fn parse_oisd(big: &[u8], adult: &[u8], downloaded: u64) -> Result<Snapshot> {
    use crate::domain_list::List;
    Ok(Snapshot {
        big: List::parse(std::str::from_utf8(big).map_err(|_| "OISD download is not UTF-8.")?)?,
        nsfw: List::parse(std::str::from_utf8(adult).map_err(|_| "OISD download is not UTF-8.")?)?,
        downloaded,
    })
}

/// A partial publisher response must never replace a previously complete top million.
pub fn parse_tranco(source: &TrancoSource, csv: &[u8], downloaded: u64) -> Result<Rankings> {
    let db = Rankings::parse(
        std::str::from_utf8(csv).map_err(|_| "Tranco CSV is not UTF-8.")?,
        source.id(),
        &format!("{}T00:00:00Z", source.date()),
        downloaded,
    )?;
    if db.source_entries != 1_000_000 {
        return Err("Incomplete Tranco top million; previous cache kept.".into());
    }
    Ok(db)
}
