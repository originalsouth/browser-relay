//! Opt-in Cert Spotter protocol and disclosure shared by desktop and macOS.
use crate::{Result, display_text::clean, link::public_name};
use serde_json::Value;
use url::Url;
pub const MAX_RESPONSE: usize = 1024 * 1024;
pub const PROVIDER: &str = "api.certspotter.com";
#[derive(Debug, Clone)]
pub struct Lookup {
    pub host: String,
    pub url: Url,
    pub disclosure: String,
}
pub fn prepare(host: &str) -> Result<Lookup> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !public_name(&host) || host.parse::<std::net::IpAddr>().is_ok() {
        return Err("Certificate history is available only for public DNS names.".into());
    }
    let mut url = Url::parse("https://api.certspotter.com/v1/issuances").unwrap();
    url.query_pairs_mut()
        .append_pair("domain", &host)
        .append_pair("include_subdomains", "false")
        .append_pair("match_wildcards", "true")
        .append_pair("expand", "dns_names")
        .append_pair("expand", "issuer");
    let disclosure = format!(
        "Send {host} to SSLMate Cert Spotter ({PROVIDER})? This exact hostname, including its subdomain, and your connection IP are visible to the provider. The link's path, query and fragment are omitted. One page of unexpired certificate issuances is requested, including matching wildcards. No redirects or automatic follow-up requests. This is partial certificate history, not domain age or proof of safety."
    );
    Ok(Lookup {
        host,
        url,
        disclosure,
    })
}
pub const AUTH_DISCLOSURE: &str = "An optional API key is sent only to api.certspotter.com and links this lookup to your SSLMate account. It stays in memory for this panel; it is never saved in reports or files. Each click requests one page; Load next page explicitly requests newer results.";
pub fn validate_key(key: &str) -> Result<()> {
    if key.len() > 4096
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
    {
        return Err("Invalid API key format (maximum 4096 ASCII token characters).".into());
    }
    Ok(())
}
pub fn page_url(lookup: &Lookup, after: Option<&str>) -> Result<Url> {
    let mut url = prepare(&lookup.host)?.url;
    if let Some(after) = after {
        if after.is_empty() || after.len() > 128 || !after.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("Invalid certificate-history cursor.".into());
        }
        url.query_pairs_mut().append_pair("after", after);
    }
    Ok(url)
}
#[derive(Debug)]
pub struct Page {
    pub summary: String,
    pub next: Option<String>,
}
pub fn status_error(status: u16) -> Result<()> {
    match status {
        200 => Ok(()),
        429 => Err("Cert Spotter's rate limit was reached. No automatic retry was made; try again later.".into()),
        401..=403 => Err("Cert Spotter requires an account or API access for this request. No fallback service was contacted.".into()),
        _ => Err(format!("Certificate history returned HTTP {status}. Redirects are not followed.")),
    }
}
pub fn summary(bytes: &[u8], lookup: &Lookup) -> Result<String> {
    page(bytes, lookup, None).map(|page| page.summary)
}
pub fn page(bytes: &[u8], lookup: &Lookup, after: Option<&str>) -> Result<Page> {
    if bytes.len() > MAX_RESPONSE {
        return Err("Certificate history response exceeds 1 MiB.".into());
    }
    let data: Value =
        serde_json::from_slice(bytes).map_err(|_| "Invalid certificate history JSON.")?;
    let rows = data
        .as_array()
        .filter(|r| r.len() <= 1000)
        .ok_or("Invalid or oversized certificate history page.")?;
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|id| id.len() <= 128)
            .ok_or("Missing certificate issuance ID.")?;
        if !seen.insert(id) {
            continue;
        }
        let names = row["dns_names"]
            .as_array()
            .filter(|n| n.len() <= 1000)
            .ok_or("Missing certificate DNS names.")?;
        let matching = names.iter().filter_map(Value::as_str).any(|name| {
            let name = name.to_ascii_lowercase();
            name == lookup.host
                || name.strip_prefix("*.").is_some_and(|suffix| {
                    lookup
                        .host
                        .split_once('.')
                        .is_some_and(|(_, parent)| parent == suffix)
                })
        });
        if !matching {
            return Err("Provider returned a certificate for a different hostname.".into());
        }
        let time = |key| -> Result<time::OffsetDateTime> {
            time::OffsetDateTime::parse(
                row[key].as_str().ok_or("Missing certificate date.")?,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| "Invalid certificate history date.".into())
        };
        let start = time("not_before")?;
        let end = time("not_after")?;
        if start >= end {
            return Err("Invalid certificate validity interval.".into());
        }
        let issuer = row["issuer"]["friendly_name"]
            .as_str()
            .or_else(|| row["issuer"]["name"].as_str())
            .unwrap_or("Issuer not stated");
        page_url(lookup, Some(id))?;
        entries.push((
            start,
            format!(
                "{} → {} · {}",
                start.date(),
                end.date(),
                clean(issuer).chars().take(240).collect::<String>()
            ),
        ));
    }
    entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
    let headline = if entries.is_empty() {
        "No unexpired issuances returned".into()
    } else {
        format!("{} unexpired issuance(s) in this page", entries.len())
    };
    let next = rows
        .last()
        .and_then(|row| row["id"].as_str())
        .map(str::to_owned);
    if next.as_deref().is_some_and(|id| Some(id) == after) {
        return Err("Provider repeated the same page; no follow-up request was made.".into());
    }
    Ok(Page {
        next,
        summary: format!(
            "{headline}\nHostname: {}\nSource: SSLMate Cert Spotter\n{}\nOne page only; showing at most eight newest-by-validity entries on this page. Use Load next page for newer-discovered issuances; an empty page ends the results. Expired certificates are excluded. Dates show certificate validity, not first-ever issuance or domain registration. Absence is not proof of missing CT or of safety.",
            lookup.host,
            entries
                .iter()
                .take(8)
                .map(|(_, s)| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        ),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disclosure_and_endpoint_are_exact_and_private_names_stay_local() {
        for host in [
            "localhost",
            "private.invalid",
            "127.0.0.1",
            "github.com/path?secret",
            "github.com:443",
            "https://github.com",
        ] {
            assert!(prepare(host).is_err(), "{host}");
        }
        let q = prepare("Docs.GitHub.com.").unwrap();
        assert_eq!(q.url.host_str(), Some(PROVIDER));
        assert_eq!(
            q.url.query_pairs().find(|(k, _)| k == "domain").unwrap().1,
            "docs.github.com"
        );
        assert!(q.disclosure.contains("including its subdomain"));
    }
    #[test]
    fn paging_and_credentials_cannot_change_the_provider() {
        let mut lookup = prepare("github.com").unwrap();
        lookup.url = Url::parse("https://other.example/").unwrap();
        let url = page_url(&lookup, Some("opaque&domain=other.example")).unwrap();
        assert_eq!(url.host_str(), Some(PROVIDER));
        assert_eq!(url.query_pairs().filter(|(k, _)| k == "domain").count(), 1);
        assert!(validate_key("valid_key-123=").is_ok());
        assert!(validate_key("secret\r\nInjected: yes").is_err());
        assert!(validate_key(&"x".repeat(4097)).is_err());
        assert!(page(b"[]", &lookup, None).unwrap().next.is_none());
        let data = br#"[{"id":"cursor","dns_names":["github.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2026-12-31T00:00:00Z"}]"#;
        assert_eq!(
            page(data, &lookup, None).unwrap().next.as_deref(),
            Some("cursor")
        );
        assert!(page(data, &lookup, Some("cursor")).is_err());
    }
    #[test]
    fn limits_partial_history_and_rejects_wrong_hosts() {
        let lookup = prepare("docs.github.com").unwrap();
        let mut data = serde_json::json!([{"id":"1","dns_names":["*.github.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2026-12-31T00:00:00Z","issuer":{"friendly_name":"Test\u{202e}CA"}}]);
        let result = summary(&serde_json::to_vec(&data).unwrap(), &lookup).unwrap();
        assert!(result.contains("One page only"));
        assert!(!result.contains('\u{202e}'));
        data[0]["dns_names"] = serde_json::json!(["*.com"]);
        assert!(summary(&serde_json::to_vec(&data).unwrap(), &lookup).is_err());
        for code in [301, 302, 403, 429, 500] {
            assert!(status_error(code).is_err());
        }
        assert!(summary(&vec![b' '; MAX_RESPONSE + 1], &lookup).is_err());
    }
}
