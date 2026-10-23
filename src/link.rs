//! URL validation and disclosure rules shared by Linux and macOS.
use crate::Result;
use std::net::IpAddr;
use url::Url;

pub fn target(link: &str) -> Result<Url> {
    let mut url = Url::parse(link).map_err(|_| "Enter a complete HTTP or HTTPS URL.")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("Only HTTP and HTTPS links can be inspected.".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Links containing a username or password are not inspected. Remove the credentials first.".into());
    }
    let name = host(&url);
    if name.starts_with(['-', '+', '@'])
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c))
    {
        return Err("The hostname contains unsupported characters.".into());
    }
    url.set_fragment(None);
    Ok(url)
}

pub fn host(url: &Url) -> String {
    url.host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .to_string()
}

/// Website ownership boundary, including private hosting suffixes such as
/// github.io. WHOIS deliberately uses a different, ICANN-only boundary.
pub fn site_domain(name: &str) -> Result<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !public_name(&name) || name.parse::<IpAddr>().is_ok() {
        return Err("No public website boundary found.".into());
    }
    Ok(psl::domain_str(&name).unwrap_or(&name).to_owned())
}

// Conservative exclusion of non-public/special-purpose networks. Mapped IPv6
// must not bypass the IPv4 checks. This gates disclosure, not a trust verdict.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..128).contains(&b))
                && !(a == 192 && (b == 0 || (b == 88 && c == 99)))
                && !(a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(ip));
            }
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub fn public_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63
                && !label.starts_with('-') && !label.ends_with('-')
                && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        // The PSL recognizes punycode TLDs as well as ASCII ones. Unknown
        // namespaces stay private; a dotted name alone is not a public domain.
        && psl::suffix(name.as_bytes()).is_some_and(|suffix| suffix.is_known())
        && ![
            "local",
            "localhost",
            "internal",
            "lan",
            "corp",
            "home",
            "test",
            "invalid",
            "example",
            "onion",
            "arpa",
        ]
        .iter()
        .any(|suffix| name.ends_with(&format!(".{suffix}")))
}

pub fn reputation_url(name: &str) -> Result<String> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        if public_ip(ip) {
            return Ok(format!("https://www.virustotal.com/gui/ip-address/{ip}"));
        }
    } else if public_name(name) {
        return Ok(format!("https://www.virustotal.com/gui/domain/{name}"));
    }
    Err("Online lookups are disabled for local or reserved destinations.".into())
}
