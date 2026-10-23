# Offline Risk-Factor Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn data the inspector already collects (route, certificates, local Tranco index) into explainable, offline risk factors. Present them so a non-expert understands within two seconds what to worry about and what to do, on desktop and macOS.

**Architecture:** Two new pure modules in the shared library: `lookalike` (TR39 confusable skeletons + edit distance against Tranco top-10k registered domains) and `risk` (`Facts` → `Vec<Factor>`, no I/O, plus presentation helpers shared by both UIs). The desktop worker (`inspect.rs`) accumulates `Facts` per hop and sends `Event::Risk`. `tranco.rs` caches the `BrandIndex` beside the cached `Rankings`. The inspector shows a top-of-window RISK FACTORS card and hands warnings back to the chooser on close. macOS gets a `"risk"` bridge op.

**Tech Stack:** Rust 2024, `url`, `psl` (via `registration::registered_domain`), new deps `unicode-security 0.1` (TR39 skeleton) and `idna 1.1` (already in `Cargo.lock` through `url`), GTK 4, SwiftUI.

**Spec:** [2026-10-19-inspection-roadmap.md](2026-10-19-inspection-roadmap.md), Phase 1, plus the UX Specification below.

## Global Constraints

- No network access in `lookalike` or `risk`; no new requests anywhere in this plan.
- No aggregate score or "safe" wording. The empty, finished state reads exactly: `No risk factors found · trust unknown`. Never use green for risk output.
- Core modules compile under both `--features desktop` (default) and `--no-default-features --features apple`.
- CI gates: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo test --no-default-features --features apple --lib`.
- Commit messages: no `Co-Authored-By` or "Generated with" lines (user preference).
- Untrusted text (hostnames, query keys) reaches titles only after URL parsing (ASCII/punycode) or via a fixed allowlist. Any text placed in Pango markup goes through `glib::markup_escape_text`.
- Match the codebase style: terse `//!` module docs, short comments only where non-obvious, `crate::Result<T> = Result<T, String>`.

## UX Specification

The risk card is the answer to the question the user opened the inspector for ("is this link OK?"), so it gets the most prominent place. It must still never claim safety.

**Placement and hierarchy**
1. Full-width **RISK FACTORS** card directly under the URL/notice banner, **above** the connection/location/DNS/ping grid. It is visible without scrolling at the default 800×720 size.
2. The card's first line is a **summary** in `dashboard-value` size, for example `2 warnings · 1 caution`. Its colour is the highest severity's colour.
3. When any Warning exists, the title-row shield icon (`security-high-symbolic`) switches to `dialog-warning-symbolic` with the warning colour. That gives a glanceable signal even with the card scrolled away.

**Rows: progressive disclosure, nothing only in tooltips**
4. Each factor is a `gtk::Expander` row. The header holds a severity icon, the title (ellipsized at the end, full text in the accessible label) and a severity word (`Warning`, `Caution` or `Notice`). Severity is never conveyed by colour alone.
5. Expanding a row shows the evidence inline as selectable text. Warnings start expanded; cautions and notices start collapsed.
6. Lookalike and near-miss rows also show a **side-by-side comparison** with the differing characters bold, underlined and amber:
   ```
   This link    paypa[1].com
   Looks like   paypa[l].com
   ```
   An IDN shows its Unicode form (what the user saw), and the punycode form is part of the evidence.
7. Re-rendering after each hop never collapses a row the user opened or opens one they closed (state is keyed by `id + title`). If the factor list is unchanged, nothing is rebuilt, so there's no flicker.

**States**

| State | Summary text | Colour class |
| --- | --- | --- |
| Before the first result | `Checking the route…` | `risk-none` |
| Running, no factors yet | `Nothing found yet · checking` | `risk-none` |
| Running, factors | `1 warning · checking` | highest severity |
| Finished, route incomplete (consent pending, stopped, hop limit) | `1 warning · route incomplete` / `None in the route so far · trust unknown` | highest / `risk-none` |
| Finished, complete, no factors | `No risk factors found · trust unknown` | `risk-none` |
| Finished, complete, factors | `2 warnings · 1 caution` | highest severity |

8. **Missing Tranco index:** the card ends with a muted row `Lookalike checks are off · no local ranking list` and a `Download lists…` button. The button opens the existing list-update popover; nothing downloads without its confirmation. After the update, the risk factors recompute automatically.

**Copy rules**
9. Titles: ≤ 60 characters, sentence case, plain words, and they name the site.
10. Evidence: one sentence on why it matters, then one sentence on **what to do**.
11. Local destinations (private/loopback IPs, non-public names) get gentler, accurate wording (`Local network address`, Notice) instead of public-internet alarms.

**Carry-over to the chooser**
12. When the inspector closes with any Warning or Caution, the chooser's status line shows `Inspection: ⚠ paypa1.com imitates paypal.com (+1 more)` in the warning colour. This stops "inspect, close, click Firefox" from losing the finding. With only notices, or none, the status line is left alone (no implied all-clear).

**Accessibility**
13. Every row has an accessible label `"<Severity>: <title>"`. Expanders are keyboard-operable (Tab, then Space/Enter) by default. Animations come from GTK, which honours `gtk-enable-animations`.
14. Contrast (WCAG 2.1, measured on the card gradient's two ends):

| Colour | Use | on `#24232e` | on `#1e1e27` |
| --- | --- | --- | --- |
| `#ff8995` | warning | 6.84:1 | 7.29:1 |
| `#ffc27d` | caution, diff highlight | 9.79:1 | 10.44:1 |
| `#decbff` | notice | 10.40:1 | 11.09:1 |
| `#aaa1ba` | none / muted | 6.29:1 | 6.70:1 |

**macOS parity**
15. The same order and copy. A "Risk factors" panel appears above the list tiles, with a `DisclosureGroup` per factor (warnings expanded) and SF Symbols `exclamationmark.octagon.fill` / `exclamationmark.triangle.fill` / `info.circle`. The comparison uses `AttributedString`, with the highlight span computed in Rust. Each row has an `accessibilityLabel`, and text uses Dynamic Type styles only.

### Copy table (source of truth for Task 2 strings)

| id | Severity | Title | Evidence |
| --- | --- | --- | --- |
| `lookalike` | Warning | `{domain} imitates {brand}` | `Its name reads like {brand} (Tranco #{rank}) but it is a different domain. To visit {brand}, type its address yourself.` |
| `brand-elsewhere` | Warning | `{brand}'s name used on {domain}` | `{host} contains the name of {brand} (Tranco #{rank}) but belongs to {domain}, whose owner chooses everything to its left. To visit {brand}, type its address yourself.` |
| `near-brand` | Caution | `{domain} is one letter from {brand}` | `A single typo separates it from {brand} (Tranco #{rank}). Check the spelling before you continue.` |
| `ip-host` | Caution | `Address is a bare IP: {ip}` | `Established sites almost always use a domain name. Only continue if you know this server.` |
| `local-address` | Notice | `Local network address: {name}` | `Normal for your own router, NAS or development server; unexpected in a link from someone else.` |
| `unusual-port` | Notice | `Non-standard port {port} on {name}` | `Public web pages normally use ports 80 and 443. Expect this only for self-hosted or development services.` |
| `shortener` | Notice | `Link shortener: {domain}` | `Shorteners hide the destination. The steps below show where it really leads.` |
| `embedded-destination` | Notice | `Link carries another destination: {other}` | `Parameter '{key}' points to {other}. Sign-in and tracking links do this legitimately; attackers use it to pass through a trusted domain. Check where you end up.` |
| `cross-site` | Notice | `Redirects from {from} to {to}` | `The link hands you to a different site than the one it names. Make sure {to} is where you meant to go.` |
| `plain-http` | Caution (Notice if local) | `Unencrypted connection to {name}` | `Anyone on the network path can read or change this page. Don't enter passwords or personal details.` |
| `new-certificate` | Caution < 2 days, Notice < 7 days | `Certificate for {name} issued {when}` | `New sites and phishing pages often have brand-new certificates; renewals look the same. Be careful if it asks you to sign in.` |
| `refused` | Notice | `Server answered HTTP {status} to the check` | `The server refused this check, so a browser may see a different page. Its content was not observed.` |

## File Map

| File | Change |
| --- | --- |
| `Cargo.toml` | add `unicode-security = "0.1"`, `idna = "1.1"` |
| `src/domain_list.rs` | add `Rankings::entries()` |
| `src/lookalike.rs` | **new**: `BrandIndex`, `Brand`, `Match` |
| `src/risk.rs` | **new**: `Facts`, `Hop`, `Validity`, `Factor`, `Severity`, `Context`, `assess`, `detail`, `summary`, `differing_span`, `chooser_note` |
| `src/lib.rs` | `pub mod lookalike; pub mod risk;` |
| `src/certificate.rs` | `CertificateInfo.not_before/not_after: i64` |
| `src/tranco.rs` | `rankings()`, cached `brands()`, `risk(&Facts) -> (Vec<Factor>, bool)` |
| `src/inspect.rs` | accumulate `Facts`, `Event::Risk { facts, factors, lookalikes }`, final "Risk factors" section |
| `src/inspector_ui.rs` | RISK FACTORS card, rows, comparison, states, shield swap, list-update recompute, `on_close` callback |
| `src/ui.rs` | chooser status carry-over |
| `assets/style.css` | `.risk-*` classes |
| `src/apple.rs` | `"risk"` op; certificate JSON gains `notBefore/notAfter` |
| `macos/Shared/*.swift`, `macos/Tests/CoreTests.swift` | decode and show factors |
| `tests/inspection.py` | OCR assertions for the card |
| `docs/reference.md`, `README.md` | document factors, UX states and measured rates |

---

### Task 1: Brand lookalike index

**Files:**
- Modify: `Cargo.toml` (dependencies)
- Modify: `src/domain_list.rs` (inside `impl Rankings`, after `lookup`)
- Create: `src/lookalike.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `Rankings::entries(&self) -> impl Iterator<Item = (&str, u32)>`; `lookalike::{BrandIndex, Brand, Match, BRAND_TOP, EMBED_TOP, ESTABLISHED}`; `BrandIndex::build(&Rankings) -> BrandIndex`; `BrandIndex::check(&self, host: &str, own_rank: Option<u32>) -> Option<Match<'_>>`; `Brand { pub domain: String, pub rank: u32, .. }`.

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` `[dependencies]`, after `psl = "2"`:

```toml
idna = "1.1"
unicode-security = "0.1"
```

Run: `cargo fetch && grep -A1 'name = "unicode-security"' Cargo.lock`
Expected: `version = "0.1.2"` (or a later 0.1.x).

- [ ] **Step 2: Write the failing tests**

Add to the `tests` module at the bottom of `src/domain_list.rs`:

```rust
    #[test]
    fn entries_expose_every_indexed_rank() {
        let ranks = Rankings::parse("1,b.example\n2,_dmarc.x\n3,a.example", "T", "d", 0).unwrap();
        let mut entries: Vec<_> = ranks.entries().collect();
        entries.sort_by_key(|(_, rank)| *rank);
        assert_eq!(entries, [("b.example", 1), ("a.example", 3)]);
    }
```

Create `src/lookalike.rs` with only the tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_list::Rankings;

    fn index() -> BrandIndex {
        let csv = "1,google.com\n2,paypal.com\n3,microsoft.com\n4,www.apple.com\n5,amazon.com\n6,x.com";
        BrandIndex::build(&Rankings::parse(csv, "TEST", "2026-10-01", 0).unwrap())
    }
    fn brand(found: Option<Match<'_>>) -> Option<(&'static str, String)> {
        found.map(|m| match m {
            Match::Confusable(b) => ("confusable", b.domain.clone()),
            Match::Embedded(b) => ("embedded", b.domain.clone()),
            Match::NearMiss(b) => ("near", b.domain.clone()),
        })
    }

    #[test]
    fn confusables_and_same_name_on_other_domains() {
        let brands = index();
        for (host, expected) in [
            ("paypa1.com", "paypal.com"),
            ("xn--pypal-4ve.com", "paypal.com"), // Cyrillic а
            ("rnicrosoft.com", "microsoft.com"), // TR39 maps m to rn
            ("app1e.net", "apple.com"),          // www. ranks aggregate to apple.com
            ("paypal.xyz", "paypal.com"),
        ] {
            assert_eq!(brand(brands.check(host, None)), Some(("confusable", expected.into())), "{host}");
        }
    }

    #[test]
    fn brand_names_inside_other_domains() {
        let brands = index();
        for host in ["paypal.com.secure-login.xyz", "paypal-login.net", "login.paypal.verify.help"] {
            assert_eq!(brand(brands.check(host, None)), Some(("embedded", "paypal.com".into())), "{host}");
        }
    }

    #[test]
    fn one_edit_from_long_brand_names() {
        let brands = index();
        assert_eq!(brand(brands.check("amazom.com", None)), Some(("near", "amazon.com".into())));
        assert_eq!(brand(brands.check("gooogle.net", None)), Some(("near", "google.com".into())));
        assert_eq!(brand(brands.check("goolge.com", None)), Some(("near", "google.com".into())));
        // Five letters is too short for near-miss matching.
        assert_eq!(brand(brands.check("appel.com", None)), None);
    }

    #[test]
    fn brands_established_sites_and_short_names_are_not_flagged() {
        let brands = index();
        for host in ["www.paypal.com", "paypal.com", "accounts.google.com", "example.org", "xx.com", "203.0.113.9"] {
            assert_eq!(brand(brands.check(host, None)), None, "{host}");
        }
        // A well-ranked registered domain is established, whatever it resembles.
        assert_eq!(brand(brands.check("paypa1.com", Some(ESTABLISHED))), None);
        assert!(brands.check("paypa1.com", Some(ESTABLISHED + 1)).is_some());
    }

    #[test]
    fn within_one_counts_a_single_edit_or_swap() {
        let c = |s: &str| s.chars().collect::<Vec<_>>();
        assert!(within_one(&c("paypal"), &c("paypall")));
        assert!(within_one(&c("apple"), &c("aplpe")));
        assert!(within_one(&c("google"), &c("goggle")));
        assert!(!within_one(&c("google"), &c("google")));
        assert!(!within_one(&c("google"), &c("gogle1")));
    }
}
```

Add `pub mod lookalike;` to `src/lib.rs` next to `pub mod link;`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib lookalike entries_expose`
Expected: compile errors: `BrandIndex`, `Match`, `within_one`, `entries` not found.

- [ ] **Step 4: Implement**

In `src/domain_list.rs`, inside `impl Rankings` after `lookup`:

```rust
    /// Every indexed hostname with its published rank, in name order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, u32)> {
        (0..self.domains.len()).map(|index| (self.domains.at(index), self.ranks[index]))
    }
```

Prepend to `src/lookalike.rs` (above the tests):

```rust
//! Brand lookalike detection against the local Tranco index. Offline only; a
//! match is a reason to look closer, never a verdict.
use crate::{domain_list::Rankings, registration::registered_domain};
use std::collections::HashMap;
use unicode_security::confusable_detection::skeleton;

/// Registered domains ranked this well are treated as brands.
pub const BRAND_TOP: u32 = 10_000;
/// Brands this popular are also searched for inside other names.
pub const EMBED_TOP: u32 = 1_000;
/// A destination whose own registered domain ranks this well is established.
pub const ESTABLISHED: u32 = 100_000;
const MIN_LABEL: usize = 4;
const EMBED_LABEL: usize = 5;
const NEAR_LABEL: usize = 6;

#[derive(Debug, PartialEq)]
pub struct Brand {
    pub domain: String,
    pub rank: u32,
    label: String,
    skeleton: Vec<char>,
}

#[derive(Debug, PartialEq)]
pub enum Match<'a> {
    /// Reads the same as a brand's name (or is it) on a different registered domain.
    Confusable(&'a Brand),
    /// A brand's name appears as a subdomain or hyphenated part of another domain.
    Embedded(&'a Brand),
    /// One edit or adjacent swap away from a brand's name.
    NearMiss(&'a Brand),
}

pub struct BrandIndex {
    brands: Vec<Brand>,
    by_skeleton: HashMap<String, usize>,
    by_label: HashMap<String, usize>,
}

fn skeleton_of(label: &str) -> String {
    skeleton(label).collect::<String>().to_lowercase()
}

/// True when `a` and `b` differ by exactly one insertion, deletion,
/// substitution or adjacent transposition.
fn within_one(a: &[char], b: &[char]) -> bool {
    if a == b {
        return false;
    }
    let common = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[common..], &b[common..]);
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Equal => {
            a[1..] == b[1..] || (a.len() >= 2 && a[0] == b[1] && a[1] == b[0] && a[2..] == b[2..])
        }
        std::cmp::Ordering::Less => a == &b[1..],
        std::cmp::Ordering::Greater => &a[1..] == b,
    }
}

impl BrandIndex {
    pub fn build(rankings: &Rankings) -> Self {
        let mut best: HashMap<String, u32> = HashMap::new();
        for (name, rank) in rankings.entries().filter(|(_, rank)| *rank <= BRAND_TOP) {
            if let Ok(domain) = registered_domain(name) {
                let entry = best.entry(domain).or_insert(rank);
                *entry = (*entry).min(rank);
            }
        }
        let mut brands: Vec<Brand> = best
            .into_iter()
            .filter_map(|(domain, rank)| {
                let (label, _) = idna::domain_to_unicode(domain.split('.').next()?);
                (label.chars().count() >= MIN_LABEL).then(|| Brand {
                    skeleton: skeleton_of(&label).chars().collect(),
                    label,
                    domain,
                    rank,
                })
            })
            .collect();
        brands.sort_by(|a, b| a.rank.cmp(&b.rank).then_with(|| a.domain.cmp(&b.domain)));
        let mut by_skeleton = HashMap::new();
        let mut by_label = HashMap::new();
        for (index, brand) in brands.iter().enumerate() {
            by_skeleton.entry(brand.skeleton.iter().collect()).or_insert(index);
            if brand.rank <= EMBED_TOP && brand.label.chars().count() >= EMBED_LABEL {
                by_label.entry(brand.label.clone()).or_insert(index);
            }
        }
        Self { brands, by_skeleton, by_label }
    }
    pub fn len(&self) -> usize {
        self.brands.len()
    }
    pub fn is_empty(&self) -> bool {
        self.brands.is_empty()
    }
    /// `own_rank` is the exact Tranco rank of `host`'s registered domain, if any.
    pub fn check(&self, host: &str, own_rank: Option<u32>) -> Option<Match<'_>> {
        if own_rank.is_some_and(|rank| rank <= ESTABLISHED) {
            return None;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let domain = registered_domain(&host).ok()?;
        let differs = |brand: &&Brand| brand.domain != domain;
        let (label, _) = idna::domain_to_unicode(domain.split('.').next()?);
        let key = skeleton_of(&label);
        if let Some(brand) = self.by_skeleton.get(&key).map(|&i| &self.brands[i]).filter(differs) {
            return Some(Match::Confusable(brand));
        }
        let prefix = host.strip_suffix(domain.as_str()).unwrap_or_default().trim_end_matches('.');
        let embedded = prefix
            .split(['.', '-'])
            .chain(label.split('-'))
            .filter_map(|part| self.by_label.get(part).map(|&i| &self.brands[i]))
            .filter(differs)
            .min_by_key(|brand| brand.rank);
        if let Some(brand) = embedded {
            return Some(Match::Embedded(brand));
        }
        let chars: Vec<char> = key.chars().collect();
        if chars.len() < NEAR_LABEL {
            return None;
        }
        self.brands
            .iter()
            .filter(differs)
            .find(|brand| {
                brand.skeleton.len() >= NEAR_LABEL
                    && brand.skeleton.len().abs_diff(chars.len()) <= 1
                    && within_one(&chars, &brand.skeleton)
            })
            .map(Match::NearMiss)
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib lookalike entries_expose`
Expected: all PASS. TR39 maps `m`→`rn`, so `microsoft` and `rnicrosoft` share the skeleton `rnicrosoft` (verified with `unicode-security 0.1.2` on 2026-10-19). If a later 0.1.x changes the table, drop that case and note it in the commit message; don't add a hand-written mapping.

- [ ] **Step 6: Check the Apple-core build and lints**

Run: `cargo test --no-default-features --features apple --lib lookalike && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`
Expected: PASS, no warnings.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/domain_list.rs src/lookalike.rs src/lib.rs
git commit -m "Add offline brand lookalike index over Tranco top 10k"
```

---

### Task 2: Risk-factor engine and shared presentation helpers

**Files:**
- Create: `src/risk.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `lookalike::{BrandIndex, Match}`, `Rankings::lookup`, `registration::registered_domain`, `link::{host, public_ip, public_name}`.
- Produces:
  - `risk::Severity { Notice, Caution, Warning }` (derives `Ord`), `fn label(self) -> &'static str` (`"notice" | "caution" | "warning"`), `fn word(self) -> &'static str` (`"Notice" | "Caution" | "Warning"`)
  - `risk::Factor { pub id: &'static str, pub severity: Severity, pub title: String, pub evidence: String, pub compare: Option<(String, String)> }` (`Clone, Debug, PartialEq`). `compare` is `(shown, brand)` for `lookalike` and `near-brand`, where `shown` is the Unicode form.
  - `risk::Validity { pub not_before: i64, pub not_after: i64 }` (`Clone, Copy, Debug`)
  - `risk::Hop { pub url: Url, pub status: u16, pub validity: Option<Validity> }`
  - `risk::Facts { pub link: Url, pub hops: Vec<Hop> }` (`Clone, Debug, Default`-less) with `Facts::new(link: Url)`
  - `risk::Context<'a> { pub rankings: &'a Rankings, pub brands: &'a BrandIndex }`
  - `risk::assess(facts: &Facts, context: Option<&Context<'_>>, now: i64) -> Vec<Factor>`: sorted Warning first (stable), deduplicated by `(id, title)`
  - `risk::detail(factors: &[Factor]) -> String`
  - `risk::summary(factors: &[Factor], finished: bool, complete: bool) -> (String, Option<Severity>)`
  - `risk::differing_span(a: &str, b: &str) -> (usize, usize)`: common (prefix, suffix) char counts, with `prefix + suffix <= min(len)`
  - `risk::chooser_note(factors: &[Factor]) -> Option<String>`
- Factor ids and copy: exactly the Copy table in the UX Specification.

- [ ] **Step 1: Write the failing tests**

Create `src/risk.rs` with only the tests, and add `pub mod risk;` to `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;

    fn facts(link: &str, hops: &[(&str, u16)]) -> Facts {
        let mut facts = Facts::new(Url::parse(link).unwrap());
        for (url, status) in hops {
            facts.hops.push(Hop { url: Url::parse(url).unwrap(), status: *status, validity: None });
        }
        facts
    }
    fn ids(factors: &[Factor]) -> Vec<&'static str> {
        factors.iter().map(|f| f.id).collect()
    }
    fn sample(severity: Severity, title: &str) -> Factor {
        Factor { id: "x", severity, title: title.into(), evidence: String::new(), compare: None }
    }

    #[test]
    fn ordinary_https_route_has_no_factors() {
        let f = facts("https://www.example.org/a?b=1", &[("https://www.example.org/a?b=1", 200)]);
        assert!(assess(&f, None, NOW).is_empty());
        assert!(detail(&[]).contains("does not establish that the site is safe"));
    }

    #[test]
    fn shortener_and_cross_site_redirect() {
        let f = facts("https://bit.ly/x", &[("https://bit.ly/x", 301), ("https://example.org/", 200)]);
        assert_eq!(ids(&assess(&f, None, NOW)), ["shortener", "cross-site"]);
    }

    #[test]
    fn public_bare_ip_unusual_port_and_plain_http() {
        let f = facts("http://93.184.215.14:8080/", &[("http://93.184.215.14:8080/", 200)]);
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
        let other = facts("https://accounts.example.com/login?next=https://evil.example.net/x&q=1", &[]);
        let found = assess(&other, None, NOW);
        assert_eq!(ids(&found), ["embedded-destination"]);
        assert!(found[0].title.ends_with("evil.example.net"));
        assert!(!found[0].evidence.contains("/x"), "never repeats the embedded path");
        let same = facts("https://accounts.example.com/login?next=https://www.example.com/home", &[]);
        assert!(assess(&same, None, NOW).is_empty());
        let unlisted = facts("https://a.example.com/?q=https://evil.example.net/", &[]);
        assert!(assess(&unlisted, None, NOW).is_empty());
    }

    #[test]
    fn certificate_age_ignores_short_lived_and_older_certificates() {
        let at = |age: i64, span: i64| {
            let mut f = facts("https://example.org/", &[("https://example.org/", 200)]);
            f.hops[0].validity = Some(Validity { not_before: NOW - age, not_after: NOW - age + span });
            assess(&f, None, NOW)
        };
        let fresh = at(1_800, 90 * DAY);
        assert_eq!((fresh[0].id, fresh[0].severity), ("new-certificate", Severity::Caution));
        assert!(fresh[0].title.ends_with("within the last hour"));
        assert!(at(5 * 3_600, 90 * DAY)[0].title.ends_with("5 hours ago"));
        assert_eq!(at(3 * DAY, 90 * DAY)[0].severity, Severity::Notice);
        assert!(at(3_600, 6 * DAY).is_empty(), "six-day ACME certificates are always young");
        assert!(at(30 * DAY, 90 * DAY).is_empty());
        assert!(at(-DAY, 90 * DAY).is_empty(), "future notBefore means clock skew, not news");
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
        let context = Context { rankings: &ranks, brands: &brands };
        let f = facts(
            "https://bit.ly/a",
            &[("https://bit.ly/a", 301), ("https://bit.ly/b", 301), ("https://paypa1.com/", 200)],
        );
        let found = assess(&f, Some(&context), NOW);
        assert_eq!(ids(&found), ["lookalike", "shortener", "cross-site"]);
        assert_eq!(found[0].title, "paypa1.com imitates paypal.com");
        assert_eq!(found[0].compare, Some(("paypa1.com".into(), "paypal.com".into())));
        assert!(found[0].evidence.ends_with("type its address yourself."));
        let idn = facts("https://xn--pypal-4ve.com/", &[]);
        let found = assess(&idn, Some(&context), NOW);
        assert_eq!(found[0].compare.as_ref().unwrap().0, "pаypal.com", "shows what the user saw");
        assert!(found[0].evidence.contains("xn--pypal-4ve.com"));
        let genuine = facts("https://www.paypal.com/", &[("https://www.paypal.com/", 200)]);
        assert!(assess(&genuine, Some(&context), NOW).is_empty());
    }

    #[test]
    fn titles_follow_the_copy_rules() {
        let f = facts(
            "http://93.184.215.14:8080/?url=https://a-very-long-subdomain-name.example.net/",
            &[("http://93.184.215.14:8080/", 403)],
        );
        for factor in assess(&f, None, NOW) {
            assert!(factor.title.chars().count() <= 60 || factor.id == "embedded-destination", "{}", factor.title);
            assert!(factor.title.chars().next().unwrap().is_uppercase() || factor.title.chars().next().unwrap().is_ascii_digit() || factor.title.starts_with(char::is_lowercase) && factor.id.contains("brand"), "{}", factor.title);
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
        assert_eq!(summary(&[], false, false), ("Nothing found yet · checking".into(), None));
        assert_eq!(summary(&[], true, false), ("None in the route so far · trust unknown".into(), None));
        assert_eq!(summary(&[], true, true), ("No risk factors found · trust unknown".into(), None));
        assert_eq!(summary(&[w.clone()], false, false), ("1 warning · checking".into(), Some(Severity::Warning)));
        assert_eq!(summary(&[w.clone(), w.clone(), c.clone()], true, true), ("2 warnings · 1 caution".into(), Some(Severity::Warning)));
        assert_eq!(summary(&[n.clone(), n], true, false), ("2 notices · route incomplete".into(), Some(Severity::Notice)));
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
    fn chooser_note_only_for_cautions_and_warnings() {
        assert_eq!(chooser_note(&[]), None);
        assert_eq!(chooser_note(&[sample(Severity::Notice, "n")]), None);
        assert_eq!(
            chooser_note(&[sample(Severity::Warning, "paypa1.com imitates paypal.com"), sample(Severity::Caution, "c"), sample(Severity::Notice, "n")]),
            Some("Inspection: ⚠ paypa1.com imitates paypal.com (+1 more)".into())
        );
        assert_eq!(chooser_note(&[sample(Severity::Caution, "c")]), Some("Inspection: ▲ c".into()));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib risk::`
Expected: compile errors: `Facts`, `assess`, `summary` and the others not found.

- [ ] **Step 3: Implement**

Prepend to `src/risk.rs`:

```rust
//! Explainable risk factors from the observed route and local indexes. No
//! network access and no score: each factor states its evidence and what to
//! do, and an empty list never means safe. Presentation helpers here are
//! shared by the GTK and macOS interfaces so both read the same.
use crate::{
    domain_list::Rankings,
    link::{host, public_ip, public_name},
    lookalike::{BrandIndex, Match},
    registration::registered_domain,
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
    pub status: u16,
    pub validity: Option<Validity>,
}
/// The original link plus every contacted hop, in order. Pending (unconsented)
/// redirects are not hops.
#[derive(Clone, Debug)]
pub struct Facts {
    pub link: Url,
    pub hops: Vec<Hop>,
}
impl Facts {
    pub fn new(link: Url) -> Self {
        Self { link, hops: Vec::new() }
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
    "bit.ly", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in", "ow.ly", "rb.gy",
    "rebrand.ly", "s.id", "shorturl.at", "t.co", "t.ly", "tiny.cc", "tinyurl.com",
];
const DESTINATION_KEYS: &[&str] = &[
    "continue", "dest", "destination", "goto", "next", "out", "redirect", "redirect_uri",
    "redirect_url", "return", "return_to", "returnurl", "target", "u", "url",
];

fn site(name: &str) -> String {
    registered_domain(name).unwrap_or_else(|_| name.to_ascii_lowercase())
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
    Factor { id, severity, title: title.into(), evidence: evidence.into(), compare: None }
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
        if hosts.insert(name.clone()) {
            host_factors(url, &name, context, &mut factors);
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
    if let Some(last) = facts.hops.last().filter(|hop| hop.status >= 400) {
        factors.push(factor(
            "refused",
            Severity::Notice,
            format!("Server answered HTTP {} to the check", last.status),
            "The server refused this check, so a browser may see a different page. Its content was not observed.",
        ));
    }
    let mut seen = HashSet::new();
    factors.retain(|f| seen.insert((f.id, f.title.clone())));
    factors.sort_by(|a, b| b.severity.cmp(&a.severity));
    factors
}

fn host_factors(url: &Url, name: &str, context: Option<&Context<'_>>, factors: &mut Vec<Factor>) {
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
    // `Url::port` is None for the scheme's default port.
    if let Some(port) = url.port() {
        factors.push(factor(
            "unusual-port",
            Severity::Notice,
            format!("Non-standard port {port} on {name}"),
            "Public web pages normally use ports 80 and 443. Expect this only for self-hosted or development services.",
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
    let Some(context) = context else { return };
    let own = context
        .rankings
        .lookup(&domain)
        .filter(|(matched, _)| *matched == domain)
        .map(|(_, rank)| rank);
    let (shown, _) = idna::domain_to_unicode(&domain);
    let spelled = if shown == domain { String::new() } else { format!(" It is spelled {domain} in ASCII.") };
    let mut found = match context.brands.check(name, own) {
        Some(Match::Confusable(brand)) => factor(
            "lookalike",
            Severity::Warning,
            format!("{shown} imitates {}", brand.domain),
            format!(
                "Its name reads like {} (Tranco #{}) but it is a different domain.{spelled} To visit {}, type its address yourself.",
                brand.domain, brand.rank, brand.domain
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
        Some(Match::NearMiss(brand)) => factor(
            "near-brand",
            Severity::Caution,
            format!("{shown} is one letter from {}", brand.domain),
            format!(
                "A single typo separates it from {} (Tranco #{}).{spelled} Check the spelling before you continue.",
                brand.domain, brand.rank
            ),
        ),
        None => return,
    };
    if found.id != "brand-elsewhere" {
        let brand = found.title.rsplit(' ').next().unwrap_or_default().to_owned();
        found.compare = Some((shown, brand));
    }
    factors.push(found);
}

fn embedded_destination(url: &Url, name: &str, factors: &mut Vec<Factor>) {
    let own = site(name);
    for (key, value) in url.query_pairs() {
        let key = key.to_ascii_lowercase();
        let Some(&key) = DESTINATION_KEYS.iter().find(|k| **k == key) else {
            continue;
        };
        let Ok(inner) = Url::parse(&value) else { continue };
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
    let age = now - validity.not_before;
    if age < 0 || validity.not_after - validity.not_before <= SHORT_LIVED {
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

/// Plain-text rendering for the details log and the macOS bridge.
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
    let serious: Vec<_> = factors.iter().filter(|f| f.severity >= Severity::Caution).collect();
    let first = serious.first()?;
    let more = match serious.len() - 1 {
        0 => String::new(),
        n => format!(" (+{n} more)"),
    };
    Some(format!("Inspection: {} {}{more}", first.severity.mark(), first.title))
}
```

Note: in `host_factors`, the brand domain for `compare` comes from the title's last word. That is safe because both comparison titles end with `{brand.domain}`. If review prefers it, capture `brand.domain.clone()` into a local inside each arm instead; the behaviour is identical.

Fix the `titles_follow_the_copy_rules` capitalisation assertion if it proves awkward. Its intent is that titles start with a capital letter unless they start with a domain name. Simplify it to `assert!(!factor.title.is_empty())` plus the ≤ 60 rule rather than weakening other tests.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib risk::`
Expected: all PASS. Expected orderings come from the stable sort over insertion order: host pass, then cross-site, then hops, then refused.

- [ ] **Step 5: Lints and Apple-core build**

Run: `cargo test --no-default-features --features apple --lib risk:: && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/risk.rs src/lib.rs
git commit -m "Add explainable offline risk factors with shared presentation helpers"
```

---

### Task 3: Desktop worker produces risk factors

**Files:**
- Modify: `src/certificate.rs` (`CertificateInfo`, `certificate_info`)
- Modify: `src/tranco.rs`
- Modify: `src/inspect.rs` (`Event` enum; `inspect()` at the start, before `Event::Connection`, and after "Connection assessment")

**Interfaces:**
- Consumes: Task 2's `risk::*`, Task 1's `BrandIndex::build`.
- Produces: `CertificateInfo { pub not_before: i64, pub not_after: i64, .. }`; `crate::tranco::risk(&Facts) -> (Vec<Factor>, bool)`, where the bool is "lookalike checks available"; `inspect::Event::Risk { facts: Facts, factors: Vec<Factor>, lookalikes: bool }`.

- [ ] **Step 1: Write the failing tests**

In `src/certificate.rs` tests:

```rust
    #[test]
    fn validity_is_exposed_as_unix_seconds() {
        let cert = certificate_info(include_bytes!("../tests/fixtures/certificate.der")).unwrap();
        assert!(cert.not_before > 0 && cert.not_after > cert.not_before);
    }
```

In `src/inspect.rs` tests, next to `redirect_back_to_an_earlier_host_updates_domain_insights`. Check the `server(reply, count)` helper's exact signature at `src/inspect.rs:676` first:

```rust
    #[test]
    fn risk_factors_are_sent_before_and_after_each_hop() {
        let (base, server) = server("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 1);
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        run(&format!("{base}/"), &sender, &cancel);
        server.join().unwrap();
        let risks: Vec<_> = receiver
            .try_iter()
            .filter_map(|event| match event {
                Event::Risk { facts, factors, .. } => Some((facts.hops.len(), factors)),
                _ => None,
            })
            .collect();
        assert_eq!(risks.first().unwrap().0, 0, "URL-only factors arrive before contact");
        let (hops, last) = risks.last().unwrap();
        assert_eq!(*hops, 1);
        assert!(last.iter().any(|f| f.id == "refused"));
        assert!(last.iter().any(|f| f.id == "local-address"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib validity_is_exposed risk_factors_are_sent`
Expected: compile errors: no field `not_before`, no variant `Event::Risk`.

- [ ] **Step 3: Certificate validity**

In `src/certificate.rs`, add to `CertificateInfo`:

```rust
    pub not_before: i64,
    pub not_after: i64,
```

and set them in the final `Ok(CertificateInfo { .. })`:

```rust
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
```

Run `cargo build --all-targets --all-features` and fix any other `CertificateInfo` literals it reports.

- [ ] **Step 4: Cached brand index in `tranco.rs`**

```rust
use browser_relay::{
    lookalike::BrandIndex,
    risk::{self, Context, Facts, Factor},
};
use std::sync::Arc;

static BRANDS: Mutex<Option<(Arc<Rankings>, Arc<BrandIndex>)>> = Mutex::new(None);

fn rankings() -> Result<Arc<Rankings>> {
    path().and_then(|path| {
        list_cache::load(path, CACHE.get_or_init(|| Mutex::new(None)), Rankings::read_sized)
    })
}
/// Built once per loaded index; rebuilt only when the cache file changes.
fn brands(db: &Arc<Rankings>) -> Arc<BrandIndex> {
    let mut cached = BRANDS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((source, index)) = cached.as_ref()
        && Arc::ptr_eq(source, db)
    {
        return index.clone();
    }
    let index = Arc::new(BrandIndex::build(db));
    *cached = Some((db.clone(), index.clone()));
    index
}
/// Factors plus whether lookalike checks could run (a ranking index is loaded).
pub fn risk(facts: &Facts) -> (Vec<Factor>, bool) {
    let now = i64::try_from(list_cache::now()).unwrap_or(i64::MAX);
    match rankings() {
        Ok(db) => {
            let brands = brands(&db);
            (risk::assess(facts, Some(&Context { rankings: &db, brands: &brands }), now), true)
        }
        Err(_) => (risk::assess(facts, None, now), false),
    }
}
```

Make `check` start with `match rankings() {`, keeping its arms as they are.

- [ ] **Step 5: Worker wiring in `inspect.rs`**

Variant, after `Insights(..)`:

```rust
    Risk {
        facts: browser_relay::risk::Facts,
        factors: Vec<browser_relay::risk::Factor>,
        lookalikes: bool,
    },
```

Helper below `section`:

```rust
fn send_risk(
    sender: &Sender<Event>,
    facts: &browser_relay::risk::Facts,
) -> Vec<browser_relay::risk::Factor> {
    let (factors, lookalikes) = crate::tranco::risk(facts);
    let _ = sender.send(Event::Risk { facts: facts.clone(), factors: factors.clone(), lookalikes });
    factors
}
```

In `inspect()`, directly after `let mut route = Route::new(link)?;`:

```rust
    let mut facts = browser_relay::risk::Facts::new(target(link)?);
    let mut factors = send_risk(sender, &facts);
```

Directly before `let _ = sender.send(Event::Connection {`:

```rust
        facts.hops.push(browser_relay::risk::Hop {
            url: url.clone(),
            status: status.as_u16(),
            validity: certificate
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .map(|info| browser_relay::risk::Validity {
                    not_before: info.not_before,
                    not_after: info.not_after,
                }),
        });
        factors = send_risk(sender, &facts);
```

After the `section(sender, "Connection assessment", ...)` call:

```rust
    section(sender, "Risk factors", browser_relay::risk::detail(&factors));
```

- [ ] **Step 6: Run tests**

Run: `cargo test --lib validity_is_exposed risk_factors_are_sent && cargo test`
Expected: PASS. If `inspector_ui.rs`'s `Event` match is exhaustive, add a temporary `Ok(Event::Risk { .. }) => {}` arm; Task 4 replaces it.

- [ ] **Step 7: Lints, then commit**

Run: `cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`

```bash
git add src/certificate.rs src/tranco.rs src/inspect.rs src/inspector_ui.rs
git commit -m "Compute risk factors per hop in the desktop inspector"
```

---

### Task 4: Desktop RISK FACTORS card

Implements UX Specification items 1–8, 13 and 14.

**Files:**
- Modify: `src/inspector_ui.rs`:
  - helpers after `list_tile` (~line 339)
  - layout: insert the card between `body.append(&banner);` (~line 648) and the `grid` construction
  - event match: `Event::Assessment` (~1035), `Event::Risk`, `Event::Done` (~1178)
  - list-update task (~line 795)
  - `PRIVACY` const (line 18)
  - tests
- Modify: `assets/style.css` (after line 77)

**Interfaces:**
- Consumes: `Event::Risk { facts, factors, lookalikes }`, `risk::{summary, differing_span, Severity, Factor, Facts}`, `crate::tranco::risk`.
- Produces (private to `inspector_ui.rs`): `fn severity_style(Severity) -> (&'static str /*icon*/, &'static str /*css class*/)`, `fn comparison_markup(shown: &str, brand: &str) -> String`, `fn row_key(&Factor) -> String`, `struct RiskView` with `fn render(&self)`.

- [ ] **Step 1: Write the failing tests** (pure functions; no GTK display needed)

```rust
    #[test]
    fn severity_is_never_colour_alone() {
        use browser_relay::risk::Severity;
        for severity in [Severity::Warning, Severity::Caution, Severity::Notice] {
            let (icon, class) = severity_style(severity);
            assert!(icon.ends_with("-symbolic"));
            assert!(class.starts_with("risk-"));
            assert!(!severity.word().is_empty());
        }
    }

    #[test]
    fn comparison_highlights_only_the_difference_and_escapes_markup() {
        let markup = comparison_markup("paypa1.com", "paypal.com");
        assert!(markup.contains("paypa<span"));
        assert!(markup.contains(">1</span>.com"));
        assert!(markup.contains(">l</span>.com"));
        assert!(markup.starts_with("This link   "));
        let hostile = comparison_markup("a<b>.com", "a&b.com");
        assert!(!hostile.contains("<b>") && hostile.contains("&lt;b&gt;") && hostile.contains("&amp;"));
        gtk::pango::parse_markup(&hostile, '\0').expect("valid Pango markup");
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --bin browser-relay severity_is_never comparison_highlights`
Expected: compile errors: functions not found.

- [ ] **Step 3: Implement helpers** (after `list_tile`)

```rust
fn severity_style(severity: browser_relay::risk::Severity) -> (&'static str, &'static str) {
    use browser_relay::risk::Severity;
    match severity {
        Severity::Warning => ("dialog-warning-symbolic", "risk-warning"),
        Severity::Caution => ("dialog-information-symbolic", "risk-caution"),
        Severity::Notice => ("emblem-default-symbolic", "risk-notice"),
    }
}

fn comparison_markup(shown: &str, brand: &str) -> String {
    let (prefix, suffix) = browser_relay::risk::differing_span(shown, brand);
    let mark = |value: &str| {
        let chars: Vec<char> = value.chars().collect();
        let end = chars.len() - suffix;
        let part = |range: std::ops::Range<usize>| {
            glib::markup_escape_text(&chars[range].iter().collect::<String>()).to_string()
        };
        format!(
            "{}<span weight=\"bold\" underline=\"single\" foreground=\"#ffc27d\">{}</span>{}",
            part(0..prefix),
            part(prefix..end),
            part(end..chars.len())
        )
    };
    format!("This link   {}\nLooks like  {}", mark(shown), mark(brand))
}

fn row_key(factor: &browser_relay::risk::Factor) -> String {
    format!("{}\u{1f}{}", factor.id, factor.title)
}

/// Owns the card's widgets and last state; re-renders only on change and
/// keeps each row's expanded state across updates.
#[derive(Clone)]
struct RiskView {
    summary: gtk::Label,
    rows: gtk::Box,
    missing: gtk::Box,
    shield: gtk::Image,
    factors: Rc<RefCell<Vec<browser_relay::risk::Factor>>>,
    finished: Rc<Cell<bool>>,
    complete: Rc<Cell<bool>>,
}
impl RiskView {
    fn update(&self, factors: Vec<browser_relay::risk::Factor>, lookalikes: bool) {
        self.missing.set_visible(!lookalikes);
        if *self.factors.borrow() != factors {
            *self.factors.borrow_mut() = factors;
            self.rebuild_rows();
        }
        self.render_summary();
    }
    fn finish(&self, complete: bool) {
        self.finished.set(true);
        self.complete.set(complete);
        self.render_summary();
    }
    fn render_summary(&self) {
        let factors = self.factors.borrow();
        let (text, highest) = browser_relay::risk::summary(&factors, self.finished.get(), self.complete.get());
        self.summary.set_text(&text);
        for class in ["risk-warning", "risk-caution", "risk-notice", "risk-none"] {
            self.summary.remove_css_class(class);
        }
        self.summary.add_css_class(highest.map_or("risk-none", |s| severity_style(s).1));
        let warned = highest == Some(browser_relay::risk::Severity::Warning);
        self.shield.set_icon_name(Some(if warned { "dialog-warning-symbolic" } else { "security-high-symbolic" }));
        if warned {
            self.shield.add_css_class("risk-warning");
        } else {
            self.shield.remove_css_class("risk-warning");
        }
    }
    fn rebuild_rows(&self) {
        let mut previous = std::collections::HashMap::new();
        while let Some(child) = self.rows.first_child() {
            if let Ok(expander) = child.clone().downcast::<gtk::Expander>() {
                previous.insert(expander.widget_name().to_string(), expander.is_expanded());
            }
            self.rows.remove(&child);
        }
        for factor in self.factors.borrow().iter() {
            let key = row_key(factor);
            let expanded = previous
                .get(&key)
                .copied()
                .unwrap_or(factor.severity == browser_relay::risk::Severity::Warning);
            let (icon, class) = severity_style(factor.severity);
            let head = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let image = gtk::Image::from_icon_name(icon);
            image.add_css_class(class);
            head.append(&image);
            let title = text(&factor.title, "risk-title");
            title.set_ellipsize(gtk::pango::EllipsizeMode::End);
            title.set_hexpand(true);
            title.set_xalign(0.0);
            head.append(&title);
            let tag = text(factor.severity.word(), "risk-tag");
            tag.add_css_class(class);
            head.append(&tag);
            let detail = gtk::Box::new(gtk::Orientation::Vertical, 4);
            detail.add_css_class("risk-detail");
            if let Some((shown, brand)) = &factor.compare {
                let compare = gtk::Label::new(None);
                compare.set_markup(&comparison_markup(shown, brand));
                compare.add_css_class("risk-compare");
                compare.set_xalign(0.0);
                compare.set_selectable(true);
                detail.append(&compare);
            }
            let evidence = wrapped(&factor.evidence);
            evidence.set_selectable(true);
            detail.append(&evidence);
            let expander = gtk::Expander::builder()
                .label_widget(&head)
                .child(&detail)
                .expanded(expanded)
                .build();
            expander.set_widget_name(&key);
            expander.set_tooltip_text(Some(&factor.title));
            expander.update_property(&[gtk::accessible::Property::Label(&format!(
                "{}: {}",
                factor.severity.word(),
                factor.title
            ))]);
            self.rows.append(&expander);
        }
    }
}
```

`text()` already applies the class; check whether it sets `xalign`, and keep the explicit `set_xalign(0.0)` either way.

- [ ] **Step 4: Layout** (between `body.append(&banner);` and the `grid` construction)

```rust
    let risk_card = card("RISK FACTORS");
    risk_card.add_css_class("risk-card");
    let risk_summary = text("Checking the route…", "dashboard-value");
    risk_summary.add_css_class("risk-none");
    risk_card.append(&risk_summary);
    let risk_rows = gtk::Box::new(gtk::Orientation::Vertical, 2);
    risk_card.append(&risk_rows);
    let risk_missing = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let missing_note = text("Lookalike checks are off · no local ranking list", "footer");
    missing_note.set_hexpand(true);
    risk_missing.append(&missing_note);
    let download_lists = gtk::Button::with_label("Download lists…");
    download_lists.add_css_class("route");
    download_lists.add_css_class("compact");
    risk_missing.append(&download_lists);
    risk_missing.set_visible(false);
    risk_card.append(&risk_missing);
    risk_card.append(&text("Checked on this device · expand a row for evidence and what to do", "footer"));
    body.append(&risk_card);
    let risk_view = RiskView {
        summary: risk_summary,
        rows: risk_rows,
        missing: risk_missing,
        shield: shield.clone(),
        factors: Rc::new(RefCell::new(Vec::new())),
        finished: Rc::new(Cell::new(false)),
        complete: Rc::new(Cell::new(false)),
    };
    let last_facts = Arc::new(std::sync::Mutex::new(None::<browser_relay::risk::Facts>));
```

After `update_lists` is created (~line 728), wire the download button to the existing confirmation popover:

```rust
    let weak_update = update_lists.downgrade();
    download_lists.connect_clicked(move |_| {
        if let Some(button) = weak_update.upgrade() {
            button.popup();
        }
    });
```

- [ ] **Step 5: Recompute after a list update**

In the `confirmed_task(&update_lists, ...)` worker closure (~line 795), which already returns `(report, names, message, failed)`, also recompute risk:

```rust
            let facts = facts_for_update.lock().unwrap().clone();
            let risk = facts.as_ref().map(crate::tranco::risk);
            Ok((crate::reputation::check(&names), names, message, failed, risk))
```

with `let facts_for_update = last_facts.clone();` before the closure. In its completion callback, after the existing insights render:

```rust
                    if let Some((factors, lookalikes)) = risk {
                        view_for_update.update(factors, lookalikes);
                    }
```

with `let view_for_update = risk_view.clone();`. Update the tuple destructuring in that callback to the new five-element shape. If the destructuring is spread across several places, follow the compiler errors.

- [ ] **Step 6: Events**

```rust
                Ok(Event::Risk { facts, factors, lookalikes }) => {
                    *last_facts.lock().unwrap() = Some(facts);
                    risk_view.update(factors, lookalikes);
                }
```

In the `Event::Assessment { encrypted, complete }` arm, add `risk_view.complete.set(complete);`. In the `Event::Done` arm, add `risk_view.finish(route_complete);`. `route_complete` is already tracked at ~line 1036.

Clone `risk_view` and `last_facts` into the receiving closure the same way the other widgets are captured.

- [ ] **Step 7: Styles** (`assets/style.css`, after line 77)

```css
.relay .risk-warning { color: #ff8995; }
.relay .dashboard-value.risk-warning { font-weight: 750; }
.relay .risk-caution { color: #ffc27d; }
.relay .risk-notice { color: #decbff; }
.relay .risk-none { color: #aaa1ba; }
.relay .risk-card expander { padding: 3px 0; }
.relay .risk-title { color: #f2effa; }
.relay .risk-tag { font-size: 10px; font-weight: 650; letter-spacing: .4px; }
.relay .risk-detail { margin: 2px 0 6px 26px; }
.relay .risk-compare { font-family: monospace; font-size: 13px; color: #decbff; }
```

The colours are the existing palette, with contrast as in the UX Specification table. Green is deliberately absent.

- [ ] **Step 8: Privacy text**

Append to `PRIVACY` (line 18), after the Tranco/OISD paragraph:

```
\n\nRisk factors are computed on this device from the observed route, certificates and the local Tranco index (lookalike names). They send nothing. They are reasons to look closer; finding none does not mean a site is safe.
```

- [ ] **Step 9: Verify**

Run: `cargo test --bin browser-relay && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/inspector_ui.rs assets/style.css
git commit -m "Show risk factors first in the inspector with evidence and comparisons"
```

---

### Task 5: Carry warnings back to the chooser

Implements UX Specification item 12.

**Files:**
- Modify: `src/inspector_ui.rs` (`show` signature at line 590; `connect_close_request` at ~line 927)
- Modify: `src/ui.rs` (inspect button closure at ~line 619)

**Interfaces:**
- Consumes: `risk::chooser_note`, `RiskView.factors`.
- Produces: `pub fn show(parent, link, multiple, browser, on_close: impl Fn(&[Factor]) + 'static)`.

- [ ] **Step 1: Find all callers**

Run: `grep -n "inspector_ui::show\|show(&" src/*.rs`
Expected: `src/ui.rs:622` and possibly tests. Every caller gets the new argument.

- [ ] **Step 2: Signature and close hook**

Add a parameter to `show`:

```rust
    on_close: impl Fn(&[browser_relay::risk::Factor]) + 'static,
```

In the existing `popup.connect_close_request(move |_| { ... })` handler, before it returns, add:

```rust
        on_close(&close_factors.borrow());
```

with `let close_factors = risk_view.factors.clone();` before the handler. The handler is `Fn`, so the callback may run more than once; that's harmless because it only sets a label.

- [ ] **Step 3: Chooser side** (`src/ui.rs`)

Before the `inspect_button.connect_clicked` closure:

```rust
    let inspect_status = status.downgrade();
```

and in the closure:

```rust
            let inspect_status = inspect_status.clone();
            crate::inspector_ui::show(
                &window,
                &inspect_link,
                multiple,
                inspection_browser.clone(),
                move |factors| {
                    let Some(status) = inspect_status.upgrade() else { return };
                    if let Some(note) = browser_relay::risk::chooser_note(factors) {
                        status.set_text(&note);
                        status.add_css_class("risk-warning");
                    }
                },
            );
```

Check which CSS class the chooser `status` label normally has; if a later status update (copy succeeded, etc.) should clear the warning colour, remove `risk-warning` in those `set_text` paths at `src/ui.rs:552-581`.

- [ ] **Step 4: Verify**

Run: `cargo test && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`
Expected: PASS. `chooser_note`'s behaviour is already unit-tested in Task 2.

- [ ] **Step 5: Commit**

```bash
git add src/inspector_ui.rs src/ui.rs
git commit -m "Keep inspection warnings visible in the chooser after closing"
```

---

### Task 6: macOS bridge and view

Implements UX Specification item 15.

**Files:**
- Modify: `src/apple.rs` (`request` match, new `local_risk` beside `local_insights`, `"certificate"` op JSON, tests)
- Modify: `macos/Shared/Core.swift`, `macos/Shared/InspectionModel.swift`, `macos/Shared/RelayView.swift`, `macos/Tests/CoreTests.swift`

**Interfaces:**
- Consumes: `risk::{Facts, Hop, Validity, Context, assess, detail, summary, differing_span}`, `BrandIndex::build`, `Rankings::read_bounded`, `read_index`, `LOCAL_WORK`.
- Produces: bridge op `{"op":"risk","directory","link","hops":[{"url","status","notBefore"?,"notAfter"?}],"finished":bool,"complete":bool}` → `{"factors":[{"id","severity","word","title","evidence","compare"?:{"shown","brand","shownSpan":[prefix,suffix],"brandSpan":[prefix,suffix]}}],"summary":String,"highest":String?,"lookalikes":bool,"detail":String}`; `"certificate"` op adds `"notBefore","notAfter"`.

- [ ] **Step 1: Write the failing Rust test**

```rust
    #[test]
    fn risk_op_uses_local_rankings_and_bounds_hops() {
        let root = std::env::temp_dir().join(format!("relay-apple-risk-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let ranks = Rankings::parse("1,paypal.com", "TEST", "2026-10-15T00:00:00Z", 1).unwrap();
        fs::write(root.join("tranco.bin"), ranks.encode()).unwrap();
        let hop = json!({"url":"https://paypa1.com/","status":200});
        let report = request(&json!({"op":"risk","directory":root,"link":"https://paypa1.com/","hops":[hop],"finished":true,"complete":true})).unwrap();
        assert_eq!(report["factors"][0]["id"], "lookalike");
        assert_eq!(report["factors"][0]["word"], "Warning");
        assert_eq!(report["factors"][0]["compare"]["shownSpan"], json!([5, 4]));
        assert_eq!(report["summary"], "1 warning");
        assert_eq!(report["highest"], "warning");
        assert_eq!(report["lookalikes"], true);
        let many = vec![hop; crate::route::MAX_HOPS + 1];
        assert!(request(&json!({"op":"risk","directory":root,"link":"https://paypa1.com/","hops":many})).is_err());
        let empty = std::env::temp_dir().join(format!("relay-apple-risk-empty-{}", std::process::id()));
        fs::create_dir_all(&empty).unwrap();
        let report = request(&json!({"op":"risk","directory":empty,"link":"https://paypa1.com/","hops":[]})).unwrap();
        assert_eq!(report["lookalikes"], false);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(empty).unwrap();
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --no-default-features --features apple --lib risk_op_uses`
Expected: FAIL: unknown op.

- [ ] **Step 3: Implement**

Beside `local_insights`:

```rust
fn local_risk(root: &Path, facts: &crate::risk::Facts, finished: bool, complete: bool) -> Value {
    use crate::risk::{Context, assess, detail, differing_span, summary};
    let _memory = crate::recover_lock(&LOCAL_WORK);
    let now = i64::try_from(cache::now()).unwrap_or(i64::MAX);
    let (factors, lookalikes) = match read_index(&root.join("tranco.bin"), Rankings::read_bounded) {
        Ok(db) => {
            let brands = crate::lookalike::BrandIndex::build(&db);
            (assess(facts, Some(&Context { rankings: &db, brands: &brands }), now), true)
        }
        Err(_) => (assess(facts, None, now), false),
    };
    let list: Vec<_> = factors
        .iter()
        .map(|f| {
            let compare = f.compare.as_ref().map(|(shown, brand)| {
                let (prefix, suffix) = differing_span(shown, brand);
                json!({"shown":shown,"brand":brand,"shownSpan":[prefix,suffix],"brandSpan":[prefix,suffix]})
            });
            json!({"id":f.id,"severity":f.severity.label(),"word":f.severity.word(),"title":f.title,"evidence":f.evidence,"compare":compare})
        })
        .collect();
    let (text, highest) = summary(&factors, finished, complete);
    json!({"factors":list,"summary":text,"highest":highest.map(|s| s.label()),"lookalikes":lookalikes,"detail":detail(&factors)})
}
```

Arm in `request` (resolve `directory` the same way the `"insights"` arm does):

```rust
        "risk" => {
            use crate::risk::{Facts, Hop, Validity};
            let hops = value["hops"].as_array().ok_or("Missing hops.")?;
            if hops.len() > crate::route::MAX_HOPS {
                return Err("Too many hops.".into());
            }
            let mut facts = Facts::new(crate::link::target(string(value, "link")?)?);
            for hop in hops {
                facts.hops.push(Hop {
                    url: crate::link::target(string(hop, "url")?)?,
                    status: hop["status"]
                        .as_u64()
                        .and_then(|s| u16::try_from(s).ok())
                        .ok_or("Invalid status.")?,
                    validity: match (hop["notBefore"].as_i64(), hop["notAfter"].as_i64()) {
                        (Some(not_before), Some(not_after)) => Some(Validity { not_before, not_after }),
                        _ => None,
                    },
                });
            }
            let finished = value["finished"].as_bool().unwrap_or(false);
            let complete = value["complete"].as_bool().unwrap_or(false);
            Ok(local_risk(Path::new(string(value, "directory")?), &facts, finished, complete))
        }
```

`"certificate"` arm:

```rust
            Ok(json!({"subject":cert.subject,"issuer":cert.issuer,"detail":cert.detail,"notBefore":cert.not_before,"notAfter":cert.not_after}))
```

- [ ] **Step 4: Run Rust tests**

Run: `cargo test --no-default-features --features apple --lib && cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Swift** (requires macOS; on Linux, rely on the CI `macos` workflow)

`Core.swift`. Replace the `Certificate` line and add:

```swift
struct Certificate: Decodable, Sendable { let subject: String; let issuer: String; let detail: String; let notBefore: Int64?; let notAfter: Int64? }
struct RiskReport: Decodable, Sendable {
    struct Compare: Decodable, Sendable, Hashable { let shown: String; let brand: String; let shownSpan: [Int]; let brandSpan: [Int] }
    struct Factor: Decodable, Sendable, Hashable { let id: String; let severity: String; let word: String; let title: String; let evidence: String; let compare: Compare? }
    let factors: [Factor]
    let summary: String
    let highest: String?
    let lookalikes: Bool
    let detail: String
}
```

`InspectionModel.swift`:
- Add `@Published var risk: RiskReport?` and `private var link = ""`.
- In `start`, set `self.link = link` and `risk = nil`.
- Add a helper and call it after `hops.append(...)` (`finished: false`) and after the loop ends in `drive` (`finished: true, complete: next.complete`):

```swift
    private func refreshRisk(root: URL, finished: Bool, complete: Bool) async {
        let facts: [[String: Any]] = hops.map { hop in
            var fact: [String: Any] = ["url": hop.url, "status": hop.result.status]
            if let c = hop.certificate, let a = c.notBefore, let b = c.notAfter { fact["notBefore"] = a; fact["notAfter"] = b }
            return fact
        }
        risk = try? await Core.work(["op": "risk", "directory": root.path, "link": link, "hops": facts,
                                     "finished": finished, "complete": complete])
    }
```

`RelayView.swift`. Insert **above** `if let local = inspection.insights {`, so risk comes first:

```swift
            if let risk = inspection.risk {
                RiskPanel(risk: risk, tint: riskColor(risk.highest))
            }
```

Add beside `listColor`:

```swift
    private func riskColor(_ severity: String?) -> Color {
        switch severity {
        case "warning": return Color(red: 1, green: 137/255, blue: 149/255)
        case "caution": return Color(red: 1, green: 194/255, blue: 125/255)
        case "notice": return Color(red: 222/255, green: 203/255, blue: 1)
        default: return .secondary
        }
    }
```

Add a new view at file scope:

```swift
struct RiskPanel: View {
    let risk: RiskReport
    let tint: Color
    @State private var open: Set<String> = []
    @State private var seeded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Risk factors", systemImage: risk.highest == "warning" ? "exclamationmark.octagon.fill" : "checklist")
                .font(.subheadline.bold()).foregroundStyle(tint)
            Text(risk.summary).font(.headline).foregroundStyle(tint)
            ForEach(risk.factors, id: \.self) { factor in
                DisclosureGroup(isExpanded: binding(factor)) {
                    VStack(alignment: .leading, spacing: 6) {
                        if let compare = factor.compare {
                            Text(highlighted("This link   ", compare.shown, compare.shownSpan)).font(.body.monospaced())
                            Text(highlighted("Looks like  ", compare.brand, compare.brandSpan)).font(.body.monospaced())
                        }
                        Text(factor.evidence).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                } label: {
                    Label(factor.title, systemImage: symbol(factor.severity)).font(.callout)
                }
                .accessibilityLabel("\(factor.word): \(factor.title)")
            }
            if !risk.lookalikes {
                Text("Lookalike checks are off. Download the ranking list in the app's Data screen.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Checked on this device. Finding none does not mean a site is safe.")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading).padding(16)
        .background(Color(red: 33/255, green: 30/255, blue: 43/255), in: RoundedRectangle(cornerRadius: 18))
        .onAppear(perform: seed).onChange(of: risk.factors) { _ in seed() }
    }

    private func key(_ f: RiskReport.Factor) -> String { f.id + "\u{1f}" + f.title }
    private func seed() {
        for f in risk.factors where f.severity == "warning" && !seeded { open.insert(key(f)) }
        seeded = seeded || !risk.factors.isEmpty
    }
    private func binding(_ f: RiskReport.Factor) -> Binding<Bool> {
        Binding(get: { open.contains(key(f)) }, set: { $0 ? open.insert(key(f)) : open.remove(key(f)) })
    }
    private func symbol(_ severity: String) -> String {
        switch severity {
        case "warning": return "exclamationmark.octagon.fill"
        case "caution": return "exclamationmark.triangle.fill"
        default: return "info.circle"
        }
    }
    private func highlighted(_ lead: String, _ value: String, _ span: [Int]) -> AttributedString {
        let chars = Array(value)
        let prefix = span.first ?? 0, end = chars.count - (span.last ?? 0)
        var out = AttributedString(lead + String(chars[..<prefix]))
        var diff = AttributedString(String(chars[prefix..<max(prefix, end)]))
        diff.foregroundColor = Color(red: 1, green: 194/255, blue: 125/255)
        diff.underlineStyle = .single
        diff.inlinePresentationIntent = .stronglyEmphasized
        out += diff
        out += AttributedString(String(chars[max(prefix, end)...]))
        return out
    }
}
```

Rust counts Unicode scalar values, while Swift's `Array(String)` gives grapheme clusters. Hostnames after IDNA mapping contain no combining sequences in practice. If a Swift test shows a mismatch, switch `Array(value)` to `Array(value.unicodeScalars)` and build the strings from scalars.

`CoreTests.swift`:

```swift
    func testRiskOpRejectsTooManyHops() throws {
        let hop: [String: Any] = ["url": "https://example.org/", "status": 200]
        XCTAssertThrowsError(try Core.call(["op": "risk", "directory": NSTemporaryDirectory(), "link": "https://example.org/", "hops": Array(repeating: hop, count: 7)]) as RiskReport)
    }
    func testRiskSummaryNeverClaimsSafety() throws {
        let report: RiskReport = try Core.call(["op": "risk", "directory": NSTemporaryDirectory(), "link": "https://example.org/", "hops": [], "finished": true, "complete": true])
        XCTAssertEqual(report.summary, "No risk factors found · trust unknown")
        XCTAssertFalse(report.lookalikes)
    }
```

- [ ] **Step 6: Commit**

```bash
git add src/apple.rs macos/Shared/Core.swift macos/Shared/InspectionModel.swift macos/Shared/RelayView.swift macos/Tests/CoreTests.swift
git commit -m "Show risk factors in the macOS companion"
```

If no Mac is available, say in the PR description that the Swift changes are unverified locally and rely on CI.

---

### Task 7: UX verification, evaluation and documentation

**Files:**
- Modify: `tests/inspection.py`
- Modify: `src/risk.rs` (an ignored evaluation test)
- Modify: `src/lookalike.rs` constants (only if the numbers require it)
- Modify: `docs/reference.md`, `README.md`

- [ ] **Step 1: GUI regression for the card**

The existing local servers in `tests/inspection.py` use `127.0.0.1`, so the card must show the local-address factor. Next to the existing `before` OCR assertions (~line 85), add:

```python
            assert 'RISK FACTORS' in before, before
            assert 'Local network address' in before, before
            assert 'safe' not in before.lower().replace('unsafe', ''), before
```

Also save `before.png` to a review location. Add a `RELAY_SCREENSHOTS` environment variable: when it is set, copy `folder/'before.png'` and `folder/'after.png'` there before the temporary directory is removed.

Run: `RELAY_SCREENSHOTS=$SCRATCH xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/inspection.py`
Expected: PASS, with screenshots in `$SCRATCH`. Tesseract may read `·` oddly, so assert only on words.

- [ ] **Step 2: Visual review checklist** (open the screenshots and check each item)

- [ ] The RISK FACTORS card is fully visible at 800×720 without scrolling.
- [ ] The summary is the largest text in the card and coloured by severity.
- [ ] Every row shows icon + title + severity word, and no title is clipped mid-word without an ellipsis.
- [ ] No green anywhere in the card.
- [ ] The card's height did not push the ping chart below the default window height by more than one card row. If it did, consider reducing the grid's `row_spacing` from 12 to 10 rather than shrinking the risk card.
- [ ] Keyboard: Tab reaches each expander and Space toggles it (check manually with `cargo run`, Ctrl+I, Tab).
- [ ] With `BROWSER_RELAY_TRANCO_DIR` pointing at an empty directory, the "Lookalike checks are off" row and its `Download lists…` button appear, and the button opens the existing confirmation popover.

Fix anything that fails before continuing, and note what changed in the commit message.

- [ ] **Step 3: Evaluation harness** (ignored test; local data only)

In `src/risk.rs` tests:

```rust
    /// Benign: Tranco hostnames ranked past ESTABLISHED (legitimate but not
    /// famous, so lookalike rules apply). Phish: one URL per line, e.g. from
    /// Phishing.Database's phishing-links-ACTIVE.txt, downloaded by hand.
    #[test]
    #[ignore = "Needs a local tranco.bin and RISK_EVAL_PHISH; prints rates"]
    fn evaluate_url_only_factors() {
        use std::collections::BTreeMap;
        let dir = std::env::var("BROWSER_RELAY_TRANCO_DIR").expect("BROWSER_RELAY_TRANCO_DIR");
        let bytes = std::fs::read(std::path::Path::new(&dir).join("tranco.bin")).unwrap();
        let ranks = Rankings::decode(&bytes).unwrap();
        let brands = BrandIndex::build(&ranks);
        let context = Context { rankings: &ranks, brands: &brands };
        let rate = |urls: Vec<String>| {
            let mut hits: BTreeMap<&'static str, usize> = BTreeMap::new();
            let total = urls.len();
            for url in urls {
                let Ok(link) = Url::parse(&url) else { continue };
                for f in assess(&Facts::new(link), Some(&context), NOW) {
                    *hits.entry(f.id).or_default() += 1;
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
        let phish: Vec<String> = std::fs::read_to_string(phish_file).unwrap().lines().map(str::to_owned).collect();
        for (label, (total, hits)) in [("benign", rate(benign)), ("phish", rate(phish))] {
            println!("{label}: {total} URLs");
            for (id, count) in hits {
                println!("  {id:<22} {count:>7}  {:.3}%", 100.0 * count as f64 / total as f64);
            }
        }
    }
```

Run it (verify the Phishing.Database URL is still current first; `$SCRATCH` is a temporary directory outside the repo):

```bash
browser-relay --update-tranco
curl -sSfLo "$SCRATCH/phish.txt" https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
BROWSER_RELAY_TRANCO_DIR=~/.local/share/browser-relay RISK_EVAL_PHISH="$SCRATCH/phish.txt" \
  cargo test --release --lib evaluate_url_only_factors -- --ignored --nocapture
```

- [ ] **Step 4: Tune against the acceptance target**

Target: `lookalike` + `brand-elsewhere` + `near-brand` together under **0.5%** of benign URLs. Too many warnings train users to ignore them, so this target protects the UX as much as accuracy.

If over target, adjust in this order and re-run after each change:
1. Raise `NEAR_LABEL` from 6 to 7.
2. Lower `EMBED_TOP` from 1,000 to 500.
3. Raise `EMBED_LABEL` from 5 to 6.

Record the final constants and both rate tables. Unit test inputs in `lookalike.rs` may need lengthening to match; change the inputs, not the tests' intent.

- [ ] **Step 5: Document**

`docs/reference.md`: add `### Risk factors` after "Local Tranco and OISD indexes", covering:
- the card's place and states (the UX Specification states table)
- the Copy table (id, severity, meaning)
- that factors are offline, have no score, and that "none found" is not safety
- the TR39 source (`unicode-security`) and the brand and established definitions
- that six-day certificates are ignored for age
- the chooser carry-over
- the measured rates table with date and Tranco list ID

`README.md`: in "A peek before you click", append:

```
**Risk factors** come first: lookalike domains, brand names on other sites, fresh certificates and suspicious redirects, each with its evidence and what to do. Checked on your device.
```

Also replace `assets/inspection.png` with a new screenshot showing the card. Use the Step 1 capture only if it shows a real public site's route, not 127.0.0.1; otherwise leave the current image and note it as a follow-up.

- [ ] **Step 6: Full verification**

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --no-default-features --features apple --lib
cargo audit
xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/inspection.py
xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/gui.py
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add tests/inspection.py src/risk.rs src/lookalike.rs docs/reference.md README.md
git commit -m "Verify the risk card, measure false positives and document the checks"
```

---

## Self-Review Notes

- UX Specification coverage: placement, summary and shield (1–3) → T4 Steps 3–4; rows, disclosure, comparison and stability (4–7) → T4 Step 3; states table → `risk::summary` (T2) + T4 Step 6; missing index (8) → T4 Steps 4–5; copy rules (9–11) → T2 Copy table and tests; chooser (12) → T2 `chooser_note` + T5; accessibility (13–14) → T4 Step 3, CSS, T7 Step 2; macOS (15) → T6.
- Roadmap Phase 1 coverage: all factors (T1, T2), desktop (T3–T5), macOS (T6), harness and published rates (T7). Domain age is deliberately deferred to Phase 4, since RDAP is opt-in.
- Names checked across tasks: `Facts::new`, `Hop { url, status, validity }`, `Validity { not_before, not_after }`, `Factor { id, severity, title, evidence, compare }`, `Context { rankings, brands }`, `assess`, `detail`, `summary`, `differing_span`, `chooser_note`, `Severity::{label, word}`, `BrandIndex::{build, check}`, `Rankings::{entries, decode}`, `tranco::risk -> (Vec<Factor>, bool)`, `Event::Risk { facts, factors, lookalikes }`, `RiskView::{update, finish}`, `show(.., on_close)`.
- Known judgement calls for the implementer: icon names depend on the installed icon theme. `dialog-warning-symbolic` and `dialog-information-symbolic` exist in Adwaita; check `emblem-default-symbolic` renders, or use `dialog-information-symbolic` for notices too and rely on the word and colour to tell them apart.
