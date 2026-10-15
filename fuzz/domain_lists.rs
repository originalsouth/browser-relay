#![no_main]
#[path = "../src/domain_list.rs"]
mod domain_list;
use domain_list::{List, Snapshot};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(index) = domain_list::Rankings::decode(data) {
        assert_eq!(index.encode(), data);
        for name in [
            "example.com",
            "child.example.com",
            "notexample.com",
            "example.com.invalid",
        ] {
            let _ = index.lookup(name);
        }
    }
    if let Ok(csv) = std::str::from_utf8(data)
        && let Ok(index) = domain_list::Rankings::parse(csv, "TEST", "2026-10-15T00:00:00Z", 1)
    {
        let decoded = domain_list::Rankings::decode(&index.encode()).unwrap();
        let lower = csv.to_ascii_lowercase();
        let rows: Vec<_> = lower
            .lines()
            .map(|line| {
                let (rank, name) = line.split_once(',').unwrap();
                (name, rank.parse::<u32>().unwrap())
            })
            .filter(|(name, _)| {
                name.contains('.')
                    && name.parse::<std::net::IpAddr>().is_err()
                    && List::parse(&format!("||{name}^")).is_ok()
            })
            .collect();
        for (name, _) in rows.iter().take(64) {
            for query in [
                name.to_string(),
                format!("child.{name}"),
                format!("not{name}"),
                format!("{name}.invalid"),
            ] {
                let expected = rows
                    .iter()
                    .filter(|(name, _)| query == *name || query.ends_with(&format!(".{name}")))
                    .max_by_key(|(name, _)| name.len());
                assert_eq!(decoded.lookup(&query), expected.copied());
            }
        }
    }
    if let Ok(snapshot) = Snapshot::decode(data) {
        // Re-encoding a valid cache must preserve its canonical representation.
        assert_eq!(snapshot.encode(), data);
        for name in ["example.com", "sub.example.com", "xxx", "badexample.com"] {
            let _ = snapshot.big.matching_domain(name);
            let _ = snapshot.nsfw.matching_domain(name);
        }
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(list) = List::parse(text)
    {
        let snapshot = Snapshot {
            big: list,
            nsfw: List::parse("||xxx^").unwrap(),
            downloaded: 1,
        };
        let decoded = Snapshot::decode(&snapshot.encode()).unwrap();
        assert_eq!(decoded.big.len(), snapshot.big.len());
        // Exercise matching and domain boundaries against a simple oracle.
        let names: Vec<_> = text
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("||")?
                    .strip_suffix('^')
                    .map(str::to_ascii_lowercase)
            })
            .collect();
        for rule in names.iter().take(64) {
            for query in [
                rule.clone(),
                format!("child.{rule}"),
                format!("not{rule}"),
                format!("{rule}.invalid"),
            ] {
                let expected = names
                    .iter()
                    .filter(|name| query == **name || query.ends_with(&format!(".{name}")))
                    .max_by_key(|name| name.len());
                assert_eq!(
                    decoded.big.matching_domain(&query),
                    expected.map(String::as_str)
                );
            }
        }
    }
});
