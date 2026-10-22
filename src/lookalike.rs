//! Brand lookalike detection against the local Tranco index. Offline only; a
//! match is a reason to look closer, never a verdict.
use crate::{domain_list::Rankings, link::site_domain};
use unicode_security::confusable_detection::skeleton;

/// Sites (including private hosting boundaries) ranked this well are treated as brands.
pub const BRAND_TOP: u32 = 10_000;
/// Brands this popular are also searched for inside other names.
pub const EMBED_TOP: u32 = 500;
/// A destination whose own site ranks this well is established.
pub const ESTABLISHED: u32 = 100_000;
const MIN_LABEL: usize = 4;
const EMBED_LABEL: usize = 6;
const NEAR_LABEL: usize = 7;

#[derive(Debug, PartialEq)]
pub struct Brand {
    pub domain: String,
    pub rank: u32,
    label: String,
    skeleton: Vec<char>,
}

#[derive(Debug, PartialEq)]
pub enum Match<'a> {
    /// Reads the same as a brand's name, spelled differently, on another registered domain.
    Confusable(&'a Brand),
    /// Exactly a brand's name under another registered domain (other ending).
    SameName(&'a Brand),
    /// A brand's full address inside another name (`paypal.com.evil.top`), or
    /// the brand's name as a hyphenated part of the registered name (`paypal-login.xyz`).
    Embedded(&'a Brand),
    /// A brand's name only as a subdomain word (`gitlab.acme.de`); self-hosted
    /// services do this, so it is weaker than [`Match::Embedded`].
    Subdomain(&'a Brand),
    /// One edit or adjacent swap away from a brand's name.
    NearMiss(&'a Brand),
}

pub struct BrandIndex {
    brands: Vec<Brand>,
    by_skeleton: Vec<usize>,
    by_label: Vec<usize>,
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
        Self::build_bounded(rankings, usize::MAX).expect("bounded domain lengths")
    }
    /// Budget includes owned storage, reference arrays and temporary Unicode
    /// conversion storage. Sorting is in-place; all vectors reserve once.
    pub fn build_bounded(rankings: &Rankings, budget: usize) -> crate::Result<Self> {
        const SCRATCH: usize = 64 * 1024;
        let reserve = |remaining: &mut usize, bytes: usize| -> crate::Result<()> {
            *remaining = remaining
                .checked_sub(bytes)
                .ok_or("Lookalike index exceeds the lookup memory budget.")?;
            Ok(())
        };
        let mut remaining = budget;
        reserve(&mut remaining, SCRATCH)?;
        let count = rankings
            .entries()
            .filter(|(_, rank)| *rank <= BRAND_TOP)
            .count();
        reserve(
            &mut remaining,
            count * (std::mem::size_of::<Brand>() + 2 * std::mem::size_of::<usize>()),
        )?;
        let mut brands = Vec::with_capacity(count);
        for (name, rank) in rankings.entries().filter(|(_, rank)| *rank <= BRAND_TOP) {
            let Ok(domain) = site_domain(name) else {
                continue;
            };
            let (label, _) = idna::domain_to_unicode(domain.split('.').next().unwrap());
            if label.chars().count() < MIN_LABEL {
                continue;
            }
            // These strings are small temporary conversions inside SCRATCH.
            let key = skeleton_of(&label);
            let chars = key.chars().count();
            reserve(
                &mut remaining,
                domain.capacity() + label.capacity() + chars * std::mem::size_of::<char>(),
            )?;
            let mut skeleton = Vec::with_capacity(chars);
            skeleton.extend(key.chars());
            brands.push(Brand {
                domain,
                rank,
                label,
                skeleton,
            });
        }
        // Keep the best-ranked occurrence of each site (www. and other hosts).
        brands.sort_unstable_by(|a, b| a.domain.cmp(&b.domain).then(a.rank.cmp(&b.rank)));
        brands.dedup_by(|a, b| a.domain == b.domain);
        brands.sort_unstable_by(|a, b| a.rank.cmp(&b.rank).then(a.domain.cmp(&b.domain)));
        let mut by_skeleton = Vec::with_capacity(count);
        by_skeleton.extend(0..brands.len());
        by_skeleton
            .sort_unstable_by(|&a, &b| brands[a].skeleton.cmp(&brands[b].skeleton).then(a.cmp(&b)));
        let mut by_label = Vec::with_capacity(count);
        by_label.extend((0..brands.len()).filter(|&i| {
            brands[i].rank <= EMBED_TOP && brands[i].label.chars().count() >= EMBED_LABEL
        }));
        by_label.sort_unstable_by(|&a, &b| brands[a].label.cmp(&brands[b].label).then(a.cmp(&b)));
        Ok(Self {
            brands,
            by_skeleton,
            by_label,
        })
    }
    pub fn len(&self) -> usize {
        self.brands.len()
    }
    pub fn is_empty(&self) -> bool {
        self.brands.is_empty()
    }
    /// `own_rank` is the exact Tranco rank of `host`'s site boundary, if any.
    pub fn check(&self, host: &str, own_rank: Option<u32>) -> Option<Match<'_>> {
        if own_rank.is_some_and(|rank| rank <= ESTABLISHED) {
            return None;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let domain = site_domain(&host).ok()?;
        let differs = |brand: &&Brand| brand.domain != domain;
        let (label, _) = idna::domain_to_unicode(domain.split('.').next()?);
        let key: Vec<char> = skeleton_of(&label).chars().collect();
        let mut same_name = None;
        if let Some(brand) = self
            .by_skeleton
            .get(
                self.by_skeleton
                    .partition_point(|&i| self.brands[i].skeleton < key),
            )
            .map(|&i| &self.brands[i])
            .filter(|brand| brand.skeleton == key)
            .filter(differs)
        {
            if brand.label != label {
                return Some(Match::Confusable(brand));
            }
            same_name = Some(brand);
        }
        let prefix = host
            .strip_suffix(domain.as_str())
            .unwrap_or_default()
            .trim_end_matches('.');
        let words: Vec<&str> = prefix.split('.').filter(|w| !w.is_empty()).collect();
        let keep = |brand: &&Brand| {
            differs(brand) && same_name.is_none_or(|own| own.domain != brand.domain)
        };
        let lookup = |part: &str| {
            self.by_label
                .get(
                    self.by_label
                        .partition_point(|&i| self.brands[i].label.as_str() < part),
                )
                .map(|&i| &self.brands[i])
                .filter(|brand| brand.label == part)
                .filter(keep)
        };
        fn better<'b>(slot: &mut Option<&'b Brand>, brand: &'b Brand) {
            if slot.is_none_or(|best| brand.rank < best.rank) {
                *slot = Some(brand);
            }
        }
        let (mut strong, mut weak) = (None, None);
        for (at, word) in words.iter().enumerate() {
            for part in word.split('-') {
                let Some(brand) = lookup(part) else { continue };
                // The brand's own address spelled out: its name ends this word
                // and its public suffix follows (paypal.com.evil.top).
                let suffix: Vec<&str> = brand.domain.split('.').skip(1).collect();
                if word.rsplit('-').next() == Some(part) && words[at + 1..].starts_with(&suffix) {
                    better(&mut strong, brand);
                } else {
                    better(&mut weak, brand);
                }
            }
        }
        for brand in label.split('-').filter_map(lookup) {
            better(&mut strong, brand);
        }
        if let Some(brand) = strong {
            return Some(Match::Embedded(brand));
        }
        if let Some(brand) = weak {
            return Some(Match::Subdomain(brand));
        }
        if let Some(brand) = same_name {
            return Some(Match::SameName(brand));
        }
        let chars = key;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_list::Rankings;

    fn index() -> BrandIndex {
        let csv = "1,google.com\n2,paypal.com\n3,microsoft.com\n4,www.apple.com\n5,amazon.com\n6,x.com\n7,gitlab.com\n8,outlook.com";
        BrandIndex::build(&Rankings::parse(csv, "TEST", "2026-10-01", 0).unwrap())
    }
    fn brand(found: Option<Match<'_>>) -> Option<(&'static str, String)> {
        found.map(|m| match m {
            Match::Confusable(b) => ("confusable", b.domain.clone()),
            Match::SameName(b) => ("same-name", b.domain.clone()),
            Match::Embedded(b) => ("embedded", b.domain.clone()),
            Match::Subdomain(b) => ("subdomain", b.domain.clone()),
            Match::NearMiss(b) => ("near", b.domain.clone()),
        })
    }

    #[test]
    fn bounded_build_rejects_before_growing_past_its_allowance() {
        let csv = (0..10_000)
            .map(|i| format!("{},a{i:019}.com\n", i + 1))
            .collect::<String>();
        let ranks = Rankings::parse(&csv, "TEST", "date", 0).unwrap();
        assert!(BrandIndex::build_bounded(&ranks, 128 * 1024).is_err());
        let index = BrandIndex::build_bounded(&ranks, 4 * 1024 * 1024).unwrap();
        assert_eq!(index.len(), 10_000);
        // This is the allowance left by the near-budget file used in the review.
        assert!(BrandIndex::build_bounded(&ranks, 32 * 1024 * 1024 - 32_000_008).is_err());
    }

    #[test]
    fn confusables_and_same_name_on_other_domains() {
        let brands = index();
        for (host, expected) in [
            ("paypa1.com", "paypal.com"),
            ("xn--pypal-4ve.com", "paypal.com"), // Cyrillic а
            ("rnicrosoft.com", "microsoft.com"), // TR39 maps m to rn
            ("app1e.net", "apple.com"),          // www. ranks aggregate to apple.com
        ] {
            assert_eq!(
                brand(brands.check(host, None)),
                Some(("confusable", expected.into())),
                "{host}"
            );
        }
        assert_eq!(
            brand(brands.check("paypal.xyz", None)),
            Some(("same-name", "paypal.com".into()))
        );
    }

    #[test]
    fn embedded_brand_outranks_same_name() {
        let brands = index();
        assert_eq!(
            brand(brands.check("www.google.com.paypal.xyz", None)),
            Some(("embedded", "google.com".into()))
        );
    }

    #[test]
    fn brand_names_inside_other_domains() {
        let brands = index();
        for (host, expected) in [
            ("paypal.com.evil.top", "paypal.com"),
            ("paypal.com.secure-login.xyz", "paypal.com"),
            ("secure-paypal.com.evil.top", "paypal.com"),
            ("paypal-login.net", "paypal.com"),
            ("www.google.com.paypal.xyz", "google.com"),
            ("login.google.com.evil.top", "google.com"),
        ] {
            assert_eq!(
                brand(brands.check(host, None)),
                Some(("embedded", expected.into())),
                "{host}"
            );
        }
    }

    #[test]
    fn brand_names_as_bare_subdomain_words_are_weaker() {
        let brands = index();
        for (host, expected) in [
            ("gitlab.acme.de", "gitlab.com"),
            ("login.paypal.verify.help", "paypal.com"),
            ("paypal-login.verify.help", "paypal.com"),
            // A brand's name followed by some other ending is not its address.
            ("paypal.net.evil.top", "paypal.com"),
            ("outlook.mycorp.com", "outlook.com"),
        ] {
            assert_eq!(
                brand(brands.check(host, None)),
                Some(("subdomain", expected.into())),
                "{host}"
            );
        }
        // The strong shape wins over a better-ranked bare word.
        assert_eq!(
            brand(brands.check("google.paypal.com.evil.top", None)),
            Some(("embedded", "paypal.com".into()))
        );
    }

    #[test]
    fn one_edit_from_long_brand_names() {
        let brands = index();
        for host in [
            "micrsoft.com",
            "microsooft.net",
            "microsfot.com",
            "mircosoft.org",
        ] {
            assert_eq!(
                brand(brands.check(host, None)),
                Some(("near", "microsoft.com".into())),
                "{host}"
            );
        }
        // Six letters is too short for near-miss matching.
        assert_eq!(brand(brands.check("gooogle.net", None)), None);
    }

    #[test]
    fn brands_established_sites_and_short_names_are_not_flagged() {
        let brands = index();
        for host in [
            "www.paypal.com",
            "paypal.com",
            "accounts.google.com",
            "example.org",
            "xx.com",
            "203.0.113.9",
        ] {
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
