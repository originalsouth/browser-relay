//! Explainable risk factors from the observed route and local indexes. No
//! network access and no score: each factor states its evidence and what to
//! do, and an empty list never means safe. Presentation helpers here are
//! shared by the GTK and iOS interfaces so both read the same.
use crate::{
    domain_list::Rankings,
    link::{host, public_ip, public_name, site_domain},
    lookalike::{BrandIndex, Match},
};
use std::{collections::HashSet, net::IpAddr};
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Notice,
    Caution,
    Warning,
}
impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Caution => "caution",
            Self::Warning => "warning",
        }
    }
    pub fn word(self) -> &'static str {
        match self {
            Self::Notice => "Notice",
            Self::Caution => "Caution",
            Self::Warning => "Warning",
        }
    }
    fn mark(self) -> &'static str {
        match self {
            Self::Notice => "●",
            Self::Caution => "▲",
            Self::Warning => "⚠",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Factor {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub evidence: String,
    /// (as shown to the user, the brand it resembles) for character comparison.
    pub compare: Option<(String, String)>,
}

#[derive(Clone, Copy, Debug)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}
#[derive(Clone, Debug)]
pub struct Hop {
    pub url: Url,
    pub status: Option<u16>,
    pub validity: Option<Validity>,
}
/// The original link plus every attempted hop, in order. Pending (unconsented)
/// redirects are not hops.
#[derive(Clone, Debug)]
pub struct Facts {
    pub link: Url,
    pub hops: Vec<Hop>,
}
impl Facts {
    pub fn new(link: Url) -> Self {
        Self {
            link,
            hops: Vec::new(),
        }
    }
}
pub struct Context<'a> {
    pub rankings: &'a Rankings,
    pub brands: &'a BrandIndex,
}

const DAY: i64 = 86_400;
/// Short-lived ACME profiles (six days) are always young; their age says nothing.
const SHORT_LIVED: i64 = 10 * DAY;
pub const SHORTENERS: &[&str] = &[
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "s.id",
    "shorturl.at",
    "t.co",
    "t.ly",
    "tiny.cc",
    "tinyurl.com",
];
const DESTINATION_KEYS: &[&str] = &[
    "continue",
    "dest",
    "destination",
    "goto",
    "next",
    "out",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_to",
    "returnurl",
    "target",
    "u",
    "url",
];

fn site(name: &str) -> String {
    site_domain(name).unwrap_or_else(|_| name.to_ascii_lowercase())
}
fn local(name: &str) -> bool {
    match name.parse::<IpAddr>() {
        Ok(ip) => !public_ip(ip),
        Err(_) => !public_name(name),
    }
}
fn factor(
    id: &'static str,
    severity: Severity,
    title: impl Into<String>,
    evidence: impl Into<String>,
) -> Factor {
    Factor {
        id,
        severity,
        title: title.into(),
        evidence: evidence.into(),
        compare: None,
    }
}

pub fn assess(facts: &Facts, context: Option<&Context<'_>>, now: i64) -> Vec<Factor> {
    let mut factors = Vec::new();
    let urls: Vec<&Url> = std::iter::once(&facts.link)
        .chain(facts.hops.iter().map(|hop| &hop.url))
        .collect();
    let mut hosts = HashSet::new();
    for url in &urls {
        let name = host(url);
        embedded_destination(url, &name, &mut factors);
        port_factor(url, &name, &mut factors);
        if hosts.insert(name.clone()) {
            host_factors(&name, context, &mut factors);
        }
    }
    for pair in urls.windows(2) {
        let (from, to) = (site(&host(pair[0])), site(&host(pair[1])));
        if from != to {
            factors.push(factor(
                "cross-site",
                Severity::Notice,
                format!("Redirects from {from} to {to}"),
                format!("The link hands you to a different site than the one it names. Make sure {to} is where you meant to go."),
            ));
        }
    }
    for hop in &facts.hops {
        let name = host(&hop.url);
        if hop.url.scheme() == "http" {
            factors.push(factor(
                "plain-http",
                if local(&name) { Severity::Notice } else { Severity::Caution },
                format!("Unencrypted connection to {name}"),
                "Anyone on the network path can read or change this page. Don't enter passwords or personal details.",
            ));
        }
        if let Some(validity) = hop.validity {
            certificate_age(&name, validity, now, &mut factors);
        }
    }
    if let Some(last) = facts
        .hops
        .last()
        .and_then(|hop| hop.status)
        .filter(|status| *status >= 400)
    {
        factors.push(factor(
            "refused",
            Severity::Notice,
            format!("Server answered HTTP {last} to the check"),
            "The server refused this check, so a browser may see a different page. Its content was not observed.",
        ));
    }
    ordered(factors)
}

pub fn ordered(mut factors: Vec<Factor>) -> Vec<Factor> {
    let mut seen = HashSet::new();
    factors.retain(|f| seen.insert((f.id, f.title.clone())));
    factors.sort_by_key(|f| std::cmp::Reverse(f.severity));
    factors
}

fn port_factor(url: &Url, name: &str, factors: &mut Vec<Factor>) {
    // `Url::port` is None for the scheme's default port.
    if let Some(port) = url.port() {
        factors.push(factor(
            "unusual-port",
            Severity::Notice,
            format!("Non-standard port {port} on {name}"),
            "Public web pages normally use ports 80 and 443. Expect this only for self-hosted or development services.",
        ));
    }
}

fn host_factors(name: &str, context: Option<&Context<'_>>, factors: &mut Vec<Factor>) {
    if let Ok(ip) = name.parse::<IpAddr>() {
        factors.push(if public_ip(ip) {
            factor(
                "ip-host",
                Severity::Caution,
                format!("Address is a bare IP: {name}"),
                "Established sites almost always use a domain name. Only continue if you know this server.",
            )
        } else {
            factor(
                "local-address",
                Severity::Notice,
                format!("Local network address: {name}"),
                "Normal for your own router, NAS or development server; unexpected in a link from someone else.",
            )
        });
    } else if local(name) {
        factors.push(factor(
            "local-address",
            Severity::Notice,
            format!("Local network address: {name}"),
            "Normal for your own router, NAS or development server; unexpected in a link from someone else.",
        ));
    }
    let domain = site(name);
    if SHORTENERS.contains(&domain.as_str()) {
        factors.push(factor(
            "shortener",
            Severity::Notice,
            format!("Link shortener: {domain}"),
            "Shorteners hide the destination. The steps below show where it really leads.",
        ));
    }
    if let Some(context) = context {
        lookalike_factor(name, context, factors);
    }
}

/// Host-only factors can be reused while response status, ports and certificate
/// ages change. This contains no URL path or query data.
pub fn lookalikes(names: &[String], context: &Context<'_>) -> Vec<Factor> {
    let mut factors = Vec::new();
    for name in names {
        lookalike_factor(name, context, &mut factors);
    }
    factors
}
fn lookalike_factor(name: &str, context: &Context<'_>, factors: &mut Vec<Factor>) {
    let domain = site(name);
    let own = context
        .rankings
        .lookup(&domain)
        .filter(|(matched, _)| *matched == domain)
        .map(|(_, rank)| rank);
    let (shown, _) = idna::domain_to_unicode(&domain);
    let spelled = if shown == domain {
        String::new()
    } else {
        format!(" It is spelled {domain} in ASCII.")
    };
    let found = match context.brands.check(name, own) {
        Some(Match::Confusable(brand)) => Factor {
            compare: Some((shown.clone(), brand.domain.clone())),
            ..factor(
                "lookalike",
                Severity::Warning,
                format!("{shown} imitates {}", brand.domain),
                format!(
                    "Its name reads like {} (Tranco #{}) but it is a different domain.{spelled} To visit {}, type its address yourself.",
                    brand.domain, brand.rank, brand.domain
                ),
            )
        },
        Some(Match::SameName(brand)) => factor(
            "same-name",
            Severity::Notice,
            format!("Same name as {} on {domain}", brand.domain),
            format!(
                "{domain} uses the same name as {} (Tranco #{}) but is a different domain. Many organisations own several endings; check that this is the one you meant.",
                brand.domain, brand.rank
            ),
        ),
        Some(Match::Embedded(brand)) => factor(
            "brand-elsewhere",
            Severity::Warning,
            format!("{}'s name used on {domain}", brand.domain),
            format!(
                "{name} contains the name of {} (Tranco #{}) but belongs to {domain}, whose owner chooses everything to its left. To visit {}, type its address yourself.",
                brand.domain, brand.rank, brand.domain
            ),
        ),
        Some(Match::Subdomain(brand)) => factor(
            "brand-subdomain",
            Severity::Caution,
            format!("{}'s name in an address on {domain}", brand.domain),
            format!(
                "{name} uses the name of {} (Tranco #{}) as a subdomain, but belongs to {domain}. Self-hosted services often do this; phishing pages do too. Only continue if you trust {domain}.",
                brand.domain, brand.rank
            ),
        ),
        Some(Match::NearMiss(brand)) => Factor {
            compare: Some((shown.clone(), brand.domain.clone())),
            ..factor(
                "near-brand",
                Severity::Caution,
                format!("{shown} is one letter from {}", brand.domain),
                format!(
                    "A single typo separates it from {} (Tranco #{}).{spelled} Check the spelling before you continue.",
                    brand.domain, brand.rank
                ),
            )
        },
        None => return,
    };
    factors.push(found);
}

fn embedded_destination(url: &Url, name: &str, factors: &mut Vec<Factor>) {
    let own = site(name);
    for (key, value) in url.query_pairs() {
        let key = key.to_ascii_lowercase();
        let Some(&key) = DESTINATION_KEYS.iter().find(|k| **k == key) else {
            continue;
        };
        let Ok(inner) = Url::parse(&value) else {
            continue;
        };
        let other = host(&inner);
        if !matches!(inner.scheme(), "http" | "https") || other.is_empty() || site(&other) == own {
            continue;
        }
        factors.push(factor(
            "embedded-destination",
            Severity::Notice,
            format!("Link carries another destination: {other}"),
            format!(
                "Parameter '{key}' points to {other}. Sign-in and tracking links do this legitimately; attackers use it to pass through a trusted domain. Check where you end up."
            ),
        ));
    }
}

fn certificate_age(name: &str, validity: Validity, now: i64, factors: &mut Vec<Factor>) {
    let age = now.saturating_sub(validity.not_before);
    if age < 0 || validity.not_after.saturating_sub(validity.not_before) <= SHORT_LIVED {
        return;
    }
    let (severity, when) = match age {
        a if a < 3_600 => (Severity::Caution, "within the last hour".to_owned()),
        a if a < 7_200 => (Severity::Caution, "an hour ago".to_owned()),
        a if a < 2 * DAY => (Severity::Caution, format!("{} hours ago", a / 3_600)),
        a if a < 7 * DAY => (Severity::Notice, format!("{} days ago", a / DAY)),
        _ => return,
    };
    factors.push(factor(
        "new-certificate",
        severity,
        format!("Certificate for {name} issued {when}"),
        "New sites and phishing pages often have brand-new certificates; renewals look the same. Be careful if it asks you to sign in.",
    ));
}

/// Plain-text rendering for the details log and the iOS bridge.
pub fn detail(factors: &[Factor]) -> String {
    if factors.is_empty() {
        return "None in the observed route. Offline checks only; this does not establish that the site is safe.".into();
    }
    factors
        .iter()
        .map(|f| format!("[{}] {}\n  {}", f.severity.label(), f.title, f.evidence))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One-line card summary and the colour to give it (None = muted).
pub fn summary(factors: &[Factor], finished: bool, complete: bool) -> (String, Option<Severity>) {
    let highest = factors.iter().map(|f| f.severity).max();
    if factors.is_empty() {
        let text = match (finished, complete) {
            (false, _) => "Nothing found yet · checking",
            (true, false) => "None in the route so far · trust unknown",
            (true, true) => "No risk factors found · trust unknown",
        };
        return (text.into(), None);
    }
    let mut parts = Vec::new();
    for severity in [Severity::Warning, Severity::Caution, Severity::Notice] {
        let count = factors.iter().filter(|f| f.severity == severity).count();
        if count > 0 {
            let plural = if count == 1 { "" } else { "s" };
            parts.push(format!("{count} {}{plural}", severity.label()));
        }
    }
    if !finished {
        parts.push("checking".into());
    } else if !complete {
        parts.push("route incomplete".into());
    }
    (parts.join(" · "), highest)
}

/// Common leading and trailing character counts, so a UI highlights only
/// what differs. `prefix + suffix` never exceeds the shorter string.
pub fn differing_span(a: &str, b: &str) -> (usize, usize) {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let room = a.len().min(b.len()) - prefix;
    let suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take(room)
        .take_while(|(x, y)| x == y)
        .count();
    (prefix, suffix)
}

/// Status line for the chooser after the inspector closes. Only cautions and
/// warnings are carried over; silence must not read as an all-clear.
pub fn chooser_note(factors: &[Factor]) -> Option<String> {
    let serious: Vec<_> = factors
        .iter()
        .filter(|f| f.severity >= Severity::Caution)
        .collect();
    let first = serious.first()?;
    let more = match serious.len() - 1 {
        0 => String::new(),
        n => format!(" (+{n} more)"),
    };
    Some(format!(
        "Inspection: {} {}{more}",
        first.severity.mark(),
        first.title
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;

    fn facts(link: &str, hops: &[(&str, u16)]) -> Facts {
        let mut facts = Facts::new(Url::parse(link).unwrap());
        for (url, status) in hops {
            facts.hops.push(Hop {
                url: Url::parse(url).unwrap(),
                status: Some(*status),
                validity: None,
            });
        }
        facts
    }
    fn ids(factors: &[Factor]) -> Vec<&'static str> {
        factors.iter().map(|f| f.id).collect()
    }
    fn sample(severity: Severity, title: &str) -> Factor {
        Factor {
            id: "x",
            severity,
            title: title.into(),
            evidence: String::new(),
            compare: None,
        }
    }

    #[test]
    fn hosting_tenants_have_separate_identity_and_do_not_inherit_provider_rank() {
        let ranks = Rankings::parse(
            "1,paypal.com\n2,github.io\n3,blogspot.com",
            "TEST",
            "date",
            0,
        )
        .unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context {
            rankings: &ranks,
            brands: &brands,
        };
        for (url, expected) in [
            ("https://paypa1.github.io/", "lookalike"),
            (
                "https://paypal.com.attacker.blogspot.com/",
                "brand-elsewhere",
            ),
            (
                "https://alice.github.io/?next=https://bob.github.io/",
                "embedded-destination",
            ),
        ] {
            assert!(
                ids(&assess(&facts(url, &[]), Some(&context), NOW)).contains(&expected),
                "{url}"
            );
        }
        let f = facts(
            "https://alice.github.io/",
            &[
                ("https://alice.github.io/", 302),
                ("https://bob.github.io/", 200),
            ],
        );
        assert!(ids(&assess(&f, Some(&context), NOW)).contains(&"cross-site"));
        assert_eq!(
            crate::registration::registered_domain("alice.github.io").unwrap(),
            "github.io",
            "WHOIS still uses ICANN registration"
        );
    }

    #[test]
    fn attempted_destinations_and_same_host_ports_are_checked() {
        let ranks = Rankings::parse("1,paypal.com", "TEST", "date", 0).unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context {
            rankings: &ranks,
            brands: &brands,
        };
        let mut f = facts(
            "https://example.org/",
            &[
                ("https://example.org/", 302),
                ("https://example.org:8443/", 302),
            ],
        );
        f.hops.push(Hop {
            url: Url::parse("https://paypa1.com/").unwrap(),
            status: None,
            validity: None,
        });
        let found = assess(&f, Some(&context), NOW);
        assert!(ids(&found).contains(&"unusual-port"));
        assert!(ids(&found).contains(&"lookalike"));
        assert!(!ids(&found).contains(&"refused"));
    }

    #[test]
    fn ordinary_https_route_has_no_factors() {
        let f = facts(
            "https://www.example.org/a?b=1",
            &[("https://www.example.org/a?b=1", 200)],
        );
        assert!(assess(&f, None, NOW).is_empty());
        assert!(detail(&[]).contains("does not establish that the site is safe"));
    }

    #[test]
    fn shortener_and_cross_site_redirect() {
        let f = facts(
            "https://bit.ly/x",
            &[("https://bit.ly/x", 301), ("https://example.org/", 200)],
        );
        assert_eq!(ids(&assess(&f, None, NOW)), ["shortener", "cross-site"]);
    }

    #[test]
    fn public_bare_ip_unusual_port_and_plain_http() {
        let f = facts(
            "http://93.184.215.14:8080/",
            &[("http://93.184.215.14:8080/", 200)],
        );
        let found = assess(&f, None, NOW);
        assert_eq!(ids(&found), ["ip-host", "plain-http", "unusual-port"]);
        assert_eq!(found[0].severity, Severity::Caution);
    }

    #[test]
    fn local_destinations_get_gentle_accurate_wording() {
        let f = facts("http://192.168.1.1/", &[("http://192.168.1.1/", 200)]);
        let found = assess(&f, None, NOW);
        assert_eq!(ids(&found), ["local-address", "plain-http"]);
        assert!(found.iter().all(|f| f.severity == Severity::Notice));
    }

    #[test]
    fn embedded_destination_only_for_other_sites() {
        let other = facts(
            "https://accounts.example.com/login?next=https://evil.example.net/x&q=1",
            &[],
        );
        let found = assess(&other, None, NOW);
        assert_eq!(ids(&found), ["embedded-destination"]);
        assert!(found[0].title.ends_with("evil.example.net"));
        assert!(
            !found[0].evidence.contains("/x"),
            "never repeats the embedded path"
        );
        let same = facts(
            "https://accounts.example.com/login?next=https://www.example.com/home",
            &[],
        );
        assert!(assess(&same, None, NOW).is_empty());
        let unlisted = facts("https://a.example.com/?q=https://evil.example.net/", &[]);
        assert!(assess(&unlisted, None, NOW).is_empty());
    }

    #[test]
    fn certificate_age_survives_extreme_validity_values() {
        for (not_before, not_after) in [
            (i64::MIN, i64::MAX),
            (i64::MAX, i64::MIN),
            (i64::MIN, 0),
            (0, i64::MAX),
        ] {
            let mut f = facts("https://example.org/", &[("https://example.org/", 200)]);
            f.hops[0].validity = Some(Validity {
                not_before,
                not_after,
            });
            let _ = assess(&f, None, NOW);
            let _ = assess(&f, None, i64::MIN);
            let _ = assess(&f, None, i64::MAX);
        }
    }

    #[test]
    fn certificate_age_ignores_short_lived_and_older_certificates() {
        let at = |age: i64, span: i64| {
            let mut f = facts("https://example.org/", &[("https://example.org/", 200)]);
            f.hops[0].validity = Some(Validity {
                not_before: NOW - age,
                not_after: NOW - age + span,
            });
            assess(&f, None, NOW)
        };
        let fresh = at(1_800, 90 * DAY);
        assert_eq!(
            (fresh[0].id, fresh[0].severity),
            ("new-certificate", Severity::Caution)
        );
        assert!(fresh[0].title.ends_with("within the last hour"));
        assert!(at(5 * 3_600, 90 * DAY)[0].title.ends_with("5 hours ago"));
        assert_eq!(at(3 * DAY, 90 * DAY)[0].severity, Severity::Notice);
        assert!(
            at(3_600, 6 * DAY).is_empty(),
            "six-day ACME certificates are always young"
        );
        assert!(at(30 * DAY, 90 * DAY).is_empty());
        assert!(
            at(-DAY, 90 * DAY).is_empty(),
            "future notBefore means clock skew, not news"
        );
    }

    #[test]
    fn refused_check_is_reported_as_unobserved() {
        let f = facts("https://example.org/", &[("https://example.org/", 403)]);
        let found = assess(&f, None, NOW);
        assert_eq!(ids(&found), ["refused"]);
        assert!(found[0].title.contains("403"));
    }

    #[test]
    fn lookalikes_come_first_carry_a_comparison_and_repeats_collapse() {
        let ranks = Rankings::parse("1,paypal.com", "TEST", "2026-10-01", 0).unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context {
            rankings: &ranks,
            brands: &brands,
        };
        let f = facts(
            "https://bit.ly/a",
            &[
                ("https://bit.ly/a", 301),
                ("https://bit.ly/b", 301),
                ("https://paypa1.com/", 200),
            ],
        );
        let found = assess(&f, Some(&context), NOW);
        assert_eq!(ids(&found), ["lookalike", "shortener", "cross-site"]);
        assert_eq!(found[0].title, "paypa1.com imitates paypal.com");
        assert_eq!(
            found[0].compare,
            Some(("paypa1.com".into(), "paypal.com".into()))
        );
        assert!(found[0].evidence.ends_with("type its address yourself."));
        let idn = facts("https://xn--pypal-4ve.com/", &[]);
        let found = assess(&idn, Some(&context), NOW);
        assert_eq!(
            found[0].compare.as_ref().unwrap().0,
            "pаypal.com",
            "shows what the user saw"
        );
        assert!(found[0].evidence.contains("xn--pypal-4ve.com"));
        let genuine = facts(
            "https://www.paypal.com/",
            &[("https://www.paypal.com/", 200)],
        );
        assert!(assess(&genuine, Some(&context), NOW).is_empty());
    }

    #[test]
    fn titles_follow_the_copy_rules() {
        let f = facts(
            "http://93.184.215.14:8080/?url=https://a-very-long-subdomain-name.example.net/",
            &[("http://93.184.215.14:8080/", 403)],
        );
        for factor in assess(&f, None, NOW) {
            assert!(!factor.title.is_empty());
            assert!(
                factor.title.chars().count() <= 60 || factor.id == "embedded-destination",
                "{}",
                factor.title
            );
            assert!(factor.evidence.ends_with('.'), "{}", factor.evidence);
        }
    }

    #[test]
    fn detail_lists_each_factor_with_evidence() {
        let f = facts("http://93.184.215.14/", &[]);
        let text = detail(&assess(&f, None, NOW));
        assert!(text.starts_with("[caution] Address is a bare IP: 93.184.215.14\n  "));
    }

    #[test]
    fn summary_covers_every_state_without_claiming_safety() {
        let w = sample(Severity::Warning, "w");
        let c = sample(Severity::Caution, "c");
        let n = sample(Severity::Notice, "n");
        assert_eq!(
            summary(&[], false, false),
            ("Nothing found yet · checking".into(), None)
        );
        assert_eq!(
            summary(&[], true, false),
            ("None in the route so far · trust unknown".into(), None)
        );
        assert_eq!(
            summary(&[], true, true),
            ("No risk factors found · trust unknown".into(), None)
        );
        assert_eq!(
            summary(std::slice::from_ref(&w), false, false),
            ("1 warning · checking".into(), Some(Severity::Warning))
        );
        assert_eq!(
            summary(&[w.clone(), w.clone(), c.clone()], true, true),
            ("2 warnings · 1 caution".into(), Some(Severity::Warning))
        );
        assert_eq!(
            summary(&[n.clone(), n], true, false),
            (
                "2 notices · route incomplete".into(),
                Some(Severity::Notice)
            )
        );
        for (text, _) in [summary(&[], true, true), summary(&[c], true, true)] {
            assert!(!text.to_lowercase().contains("safe"));
        }
    }

    #[test]
    fn differing_span_isolates_the_changed_characters() {
        assert_eq!(differing_span("paypa1.com", "paypal.com"), (5, 4));
        assert_eq!(differing_span("pаypal.com", "paypal.com"), (1, 8));
        assert_eq!(differing_span("amazom.com", "amazon.com"), (5, 4));
        assert_eq!(differing_span("gooogle.net", "google.com"), (3, 0));
        assert_eq!(differing_span("same", "same"), (4, 0));
    }

    #[test]
    fn same_name_on_another_ending_is_a_notice_without_comparison() {
        let ranks = Rankings::parse("1,paypal.com", "TEST", "2026-10-01", 0).unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context {
            rankings: &ranks,
            brands: &brands,
        };
        let found = assess(&facts("https://paypal.xyz/", &[]), Some(&context), NOW);
        assert_eq!(ids(&found), ["same-name"]);
        assert_eq!(found[0].severity, Severity::Notice);
        assert_eq!(found[0].title, "Same name as paypal.com on paypal.xyz");
        assert_eq!(found[0].compare, None);
        assert_eq!(chooser_note(&found), None);
    }

    #[test]
    fn brand_as_a_subdomain_word_is_a_caution_and_its_address_a_warning() {
        let ranks = Rankings::parse("1,gitlab.com\n2,paypal.com", "TEST", "2026-10-01", 0).unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context {
            rankings: &ranks,
            brands: &brands,
        };
        let found = assess(&facts("https://gitlab.acme.de/", &[]), Some(&context), NOW);
        assert_eq!(ids(&found), ["brand-subdomain"]);
        assert_eq!(found[0].severity, Severity::Caution);
        assert_eq!(found[0].title, "gitlab.com's name in an address on acme.de");
        assert_eq!(
            found[0].evidence,
            "gitlab.acme.de uses the name of gitlab.com (Tranco #1) as a subdomain, but belongs to acme.de. Self-hosted services often do this; phishing pages do too. Only continue if you trust acme.de."
        );
        assert_eq!(found[0].compare, None);
        let found = assess(
            &facts("https://paypal.com.evil.top/", &[]),
            Some(&context),
            NOW,
        );
        assert_eq!(ids(&found), ["brand-elsewhere"]);
        assert_eq!(found[0].severity, Severity::Warning);
        assert_eq!(found[0].compare, None);
    }

    #[test]
    fn chooser_note_only_for_cautions_and_warnings() {
        assert_eq!(chooser_note(&[]), None);
        assert_eq!(chooser_note(&[sample(Severity::Notice, "n")]), None);
        assert_eq!(
            chooser_note(&[
                sample(Severity::Warning, "paypa1.com imitates paypal.com"),
                sample(Severity::Caution, "c"),
                sample(Severity::Notice, "n")
            ]),
            Some("Inspection: ⚠ paypa1.com imitates paypal.com (+1 more)".into())
        );
        assert_eq!(
            chooser_note(&[sample(Severity::Caution, "c")]),
            Some("Inspection: ▲ c".into())
        );
    }

    /// Benign: Tranco hostnames ranked past ESTABLISHED (legitimate but not
    /// famous, so lookalike rules apply). Phish: one URL per line, e.g. from
    /// Phishing.Database's phishing-links-ACTIVE.txt, downloaded by hand.
    #[test]
    #[ignore = "Needs a local tranco.bin and RISK_EVAL_PHISH; prints rates"]
    fn evaluate_url_only_factors() {
        use std::collections::BTreeMap;
        const FAMILY: [&str; 4] = [
            "lookalike",
            "brand-elsewhere",
            "brand-subdomain",
            "near-brand",
        ];
        let dir = std::env::var("BROWSER_RELAY_TRANCO_DIR").expect("BROWSER_RELAY_TRANCO_DIR");
        let bytes = std::fs::read(std::path::Path::new(&dir).join("tranco.bin")).unwrap();
        let ranks = Rankings::decode(&bytes).unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context {
            rankings: &ranks,
            brands: &brands,
        };
        let rate = |urls: Vec<String>| {
            let mut hits: BTreeMap<&'static str, usize> = BTreeMap::new();
            let total = urls.len();
            for url in urls {
                let Ok(link) = Url::parse(&url) else { continue };
                let found = assess(&Facts::new(link), Some(&context), NOW);
                for f in &found {
                    *hits.entry(f.id).or_default() += 1;
                }
                if found.iter().any(|f| FAMILY.contains(&f.id)) {
                    *hits.entry("(lookalike family)").or_default() += 1;
                }
            }
            (total, hits)
        };
        let benign: Vec<String> = ranks
            .entries()
            .filter(|(_, rank)| *rank > crate::lookalike::ESTABLISHED)
            .step_by(20)
            .map(|(name, _)| format!("https://{name}/"))
            .collect();
        let phish_file = std::env::var("RISK_EVAL_PHISH").expect("RISK_EVAL_PHISH");
        let phish: Vec<String> = std::fs::read_to_string(phish_file)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        for (label, (total, hits)) in [("benign", rate(benign)), ("phish", rate(phish))] {
            println!("{label}: {total} URLs");
            for (id, count) in hits {
                println!(
                    "  {id:<22} {count:>7}  {:.3}%",
                    100.0 * count as f64 / total as f64
                );
            }
        }
    }
}
