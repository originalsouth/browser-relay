//! rustc --edition=2024 -O -C lto=fat tools/bench_blocklist.rs -o /tmp/relay-bench
//! /tmp/relay-bench ~/.local/share/browser-relay/oisd.bin
#[allow(dead_code)]
#[path = "../src/domain_list.rs"]
mod domain_list;
use std::{hint::black_box, time::Instant};
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("Pass the local oisd.bin path");
    let started = Instant::now();
    let bytes = std::fs::read(path).unwrap();
    let snapshot = domain_list::Snapshot::decode(&bytes).unwrap();
    println!(
        "Initial file read + validation: {:.2} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!(
        "Rules: {} Big + {} NSFW; packed storage: {:.2} MiB",
        snapshot.big.len(),
        snapshot.nsfw.len(),
        (snapshot.big.storage_bytes() + snapshot.nsfw.storage_bytes()) as f64 / 1048576.0
    );
    let started = Instant::now();
    let mut matches = 0;
    for _ in 0..100_000 {
        for query in [
            "example.com",
            "sub.doubleclick.net",
            "site.xxx",
            "www.wikipedia.org",
            "notlisted.invalid",
        ] {
            matches += usize::from(
                black_box(&snapshot.big)
                    .matching_domain(black_box(query))
                    .is_some(),
            );
            matches += usize::from(
                black_box(&snapshot.nsfw)
                    .matching_domain(black_box(query))
                    .is_some(),
            );
        }
    }
    let elapsed = started.elapsed();
    println!(
        "1,000,000 warm list lookups: {:.2} ms; {:.0} ns/lookup; matches: {}",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_nanos() as f64 / 1_000_000.0,
        black_box(matches)
    );
    if let Some(path) = std::env::args().nth(2) {
        let started = Instant::now();
        let bytes = std::fs::read(path).unwrap();
        let index = domain_list::Rankings::decode(&bytes).unwrap();
        println!(
            "Tranco initial file read + validation: {:.2} ms; {} entries; {:.2} MiB packed",
            started.elapsed().as_secs_f64() * 1000.0,
            index.domains.len(),
            index.storage_bytes() as f64 / 1048576.0
        );
        let started = Instant::now();
        let mut matches = 0;
        for _ in 0..200_000 {
            for query in [
                "example.com",
                "www.google.com",
                "docs.google.com",
                "unranked.invalid",
                "tenant.github.io",
            ] {
                matches += usize::from(black_box(&index).lookup(black_box(query)).is_some());
            }
        }
        println!(
            "1,000,000 Tranco warm lookups: {:.2} ms; {:.0} ns/lookup; matches: {}",
            started.elapsed().as_secs_f64() * 1000.0,
            started.elapsed().as_nanos() as f64 / 1_000_000.0,
            black_box(matches)
        );
        for query in [
            "example.com",
            "www.google.com",
            "docs.google.com",
            "tenant.github.io",
        ] {
            println!("{query}: {:?}", index.lookup(query));
        }
    }
}
