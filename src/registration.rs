//! RDAP provider selection and parsing; performs no network requests.
use crate::Result;
use serde_json::Value;
use std::net::IpAddr;
use url::Url;
#[derive(Clone, Debug)]
pub struct Lookup {
    pub domain: String,
    pub url: Url,
}
pub fn registered_domain(host: &str) -> Result<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok()
        || !crate::link::public_name(&host)
        || host.len() > 253
        || host
            .split('.')
            .any(|label| label.len() > 63 || label.starts_with('-') || label.ends_with('-'))
    {
        return Err(
            "Domain WHOIS is unavailable for IPs, local names, or invalid hostnames.".into(),
        );
    }
    let mut candidate = host.as_str();
    loop {
        let suffix = psl::suffix(candidate.as_bytes()).ok_or("No registration suffix found.")?;
        match suffix.typ() {
            Some(psl::Type::Icann) => {
                let suffix = std::str::from_utf8(suffix.as_bytes()).unwrap();
                let prefix = host
                    .strip_suffix(suffix)
                    .and_then(|name| name.strip_suffix('.'))
                    .ok_or("No registrable domain found.")?;
                let label = prefix
                    .rsplit('.')
                    .next()
                    .filter(|label| !label.is_empty())
                    .ok_or("No registrable domain found.")?;
                return Ok(format!("{label}.{suffix}"));
            }
            // Walk past private hosting suffixes to the ICANN registration boundary.
            Some(psl::Type::Private) => {
                candidate = candidate
                    .split_once('.')
                    .ok_or("No registry domain found.")?
                    .1
            }
            None => return Err("This suffix has no known registration boundary.".into()),
        }
    }
}
pub fn endpoint(domain: &str, bootstrap: &Value) -> Result<Url> {
    let services = bootstrap["services"]
        .as_array()
        .ok_or("Invalid RDAP registry map.")?;
    let service = services
        .iter()
        .filter_map(|service| {
            let length = service[0]
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .filter(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
                .map(str::len)
                .max()?;
            Some((length, service))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, service)| service)
        .ok_or("No RDAP registry is listed for this domain; no fallback service was contacted.")?;
    let base = service[1].as_array().ok_or("Invalid RDAP service.")?.iter()
        .filter_map(Value::as_str).filter_map(|value| Url::parse(value).ok())
        .find(|url| url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
            && url.query().is_none() && url.fragment().is_none() && url.port_or_known_default() == Some(443)
            && url.host_str().is_some_and(crate::link::public_name) && url.path().ends_with('/'))
        .ok_or("This registry has no supported HTTPS RDAP service. No plaintext WHOIS fallback was used.")?;
    base.join(&format!("domain/{domain}"))
        .map_err(|e| e.to_string())
}
pub fn prepare(host: &str) -> Result<Lookup> {
    let domain = registered_domain(host)?;
    let map: Value = serde_json::from_slice(include_bytes!("../assets/rdap-dns.json"))
        .map_err(|_| "Bundled RDAP registry map is invalid.")?;
    Ok(Lookup {
        url: endpoint(&domain, &map)?,
        domain,
    })
}
fn clean(value: &str) -> String {
    crate::display_text::safe_chars(value).take(300).collect()
}

fn card_name(entity: &Value) -> Option<String> {
    let card = entity["vcardArray"][1].as_array()?;
    let mut fields = Vec::new();
    for field in card.iter().take(64) {
        if matches!(field[0].as_str(), Some("fn" | "org")) {
            let value = match &field[3] {
                Value::String(value) => clean(value),
                Value::Array(values) => values
                    .iter()
                    .take(8)
                    .filter_map(Value::as_str)
                    .map(clean)
                    .collect::<Vec<_>>()
                    .join(" · "),
                _ => continue,
            };
            if !value.is_empty() && !fields.contains(&value) {
                fields.push(value);
            }
        }
    }
    (!fields.is_empty()).then(|| fields.join(" · "))
}
fn entity_name(data: &Value, role: &str) -> Option<String> {
    // Registry-level roles only. Following linked registrar records would disclose
    // the domain to another party and requires separate consent.
    data["entities"].as_array()?.iter().find_map(|entity| {
        entity["roles"]
            .as_array()?
            .iter()
            .any(|value| value.as_str() == Some(role))
            .then(|| card_name(entity))
            .flatten()
    })
}
pub fn summary(data: &Value, lookup: &Lookup) -> Result<String> {
    if data["objectClassName"].as_str() != Some("domain")
        || !data["ldhName"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&lookup.domain))
    {
        return Err("The registry did not return a matching domain registration record.".into());
    }
    let registrar =
        entity_name(data, "registrar").unwrap_or_else(|| "Not returned by registry".into());
    let registrant =
        entity_name(data, "registrant").unwrap_or_else(|| "Not disclosed (may be redacted)".into());
    let event = |action: &str| {
        data["events"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|event| event["eventAction"].as_str() == Some(action))
            .and_then(|event| event["eventDate"].as_str())
            .map(clean)
            .unwrap_or_else(|| "Not returned".into())
    };
    let servers = data["nameservers"]
        .as_array()
        .into_iter()
        .flatten()
        .take(12)
        .filter_map(|ns| ns["ldhName"].as_str())
        .map(clean)
        .collect::<Vec<_>>();
    let status = data["status"]
        .as_array()
        .into_iter()
        .flatten()
        .take(12)
        .filter_map(Value::as_str)
        .map(clean)
        .collect::<Vec<_>>();
    Ok(format!(
        "Registrar · {registrar}\n\nDomain: {}\nRegistrant: {registrant}\nRegistered: {}\nExpires: {}\nLast changed: {}\nStatus: {}\nNameservers: {}\nDNSSEC signed: {}\n\nSource: {}\nRegistry record only; registrar referrals are not followed. Registration details can be redacted or incomplete and do not verify a site's operator or safety.",
        lookup.domain,
        event("registration"),
        event("expiration"),
        event("last changed"),
        if status.is_empty() {
            "Not returned".into()
        } else {
            status.join(", ")
        },
        if servers.is_empty() {
            "Not returned".into()
        } else {
            servers.join(", ")
        },
        match data["secureDNS"]["delegationSigned"].as_bool() {
            Some(true) => "Yes",
            Some(false) => "No",
            None => "Not returned",
        },
        lookup.url
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_registered_domain_is_disclosed() {
        for (host, expected) in [
            ("secret.example.com", "example.com"),
            ("www.example.co.uk", "example.co.uk"),
            ("EXAMPLE.COM.", "example.com"),
        ] {
            let plan = prepare(host).unwrap();
            assert_eq!(plan.domain, expected);
            assert!(plan.url.path().ends_with(&format!("/domain/{expected}")));
            assert!(plan.url.query().is_none());
        }
        let name = crate::link::host(&crate::link::target("https://пример.рф/").unwrap());
        assert_eq!(registered_domain(&name).unwrap(), name);
        // Private-hosting reduction is independent of whether its registry offers RDAP.
        assert_eq!(
            registered_domain("private-project.github.io").unwrap(),
            "github.io"
        );
        assert_eq!(
            registered_domain("tenant.blogspot.com").unwrap(),
            "blogspot.com"
        );
        for name in [
            "localhost",
            "secret.internal",
            "127.0.0.1",
            "::1",
            "co.uk",
            "example.com/path?secret",
            "user@example.com",
            "-bad.com",
            "example.invalid",
        ] {
            assert!(prepare(name).is_err(), "{name}");
        }
    }
    #[test]
    fn bootstrap_requires_https_and_label_boundaries() {
        let map =
            serde_json::json!({"services":[[["com"],["https://registry.example.com/rdap/"]]]});
        assert!(endpoint("example.com", &map).is_ok());
        assert!(endpoint("notcom", &map).is_err());
        for base in [
            "http://registry.example.com/",
            "https://user:secret@registry.example.com/",
            "https://127.0.0.1/",
            "https://registry.example.com/?token=secret",
            "https://registry.example.com:444/",
        ] {
            let map = serde_json::json!({"services":[[["com"],[base]]]});
            assert!(endpoint("example.com", &map).is_err(), "{base}");
        }
    }
    #[test]
    fn registration_fields_and_redaction_are_honest() {
        let plan = prepare("www.example.com").unwrap();
        let mut data = serde_json::json!({"objectClassName":"domain","ldhName":"EXAMPLE.COM", "entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar"]]]}], "events":[{"eventAction":"registration","eventDate":"2000-01-01"}],"nameservers":[{"ldhName":"ns.example.com"}],"secureDNS":{"delegationSigned":true}});
        let text = summary(&data, &plan).unwrap();
        for value in [
            "Example Registrar",
            "Not disclosed",
            "2000-01-01",
            "Expires: Not returned",
            "ns.example.com",
            "DNSSEC signed: Yes",
        ] {
            assert!(text.contains(value), "{text}");
        }
        data["ldhName"] = "different.com".into();
        assert!(summary(&data, &plan).is_err());
        assert_eq!(clean("fake\n\u{202e}name"), "fakename");
    }
}
