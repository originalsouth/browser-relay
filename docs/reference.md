# Reference

[Back to the README](../README.md)

## Using Browser Relay

Choose a button, press **1–5**, or use **Tab** and **Enter**. **Esc** cancels.
The chooser uses a dark theme with violet accents. Missing browsers are disabled;
a failed action leaves the chooser open so you can try another option.

**Show QR code** (**4**) reveals a locally generated code for the first link.
It stays hidden until requested; **Esc** or **Hide QR code** dismisses it.
Links over 106 UTF-8 bytes show a warning instead to keep the compact code readable.
Opening and copying still use the complete link.

**Inspect link** (**5**) checks the first link in a compact dashboard: DNS addresses,
HTTP redirects, TLS validation, certificate subject and issuer, connected peers,
local GeoIP with country flags, and eight ping probes per peer. The IP selector
switches location and latency results together. **Details & privacy** opens the
full report; closing the inspector cancels outstanding checks.

![Link inspection dashboard](../assets/inspection.png)

Same-origin redirects are automatic; another origin needs confirmation.
The report preserves earlier hops and warnings, with a six-request limit across
the session. HTTPS-to-HTTP downgrades are blocked. Checks use Rust libraries,
not command-line utilities. Ping may be unavailable when the OS restricts ICMP.
HEAD responses can differ from browser visits; scripts and page resources are
not examined. A valid certificate identifies a domain, not a trustworthy site.

**GeoIP stays local.** Set `BROWSER_RELAY_GEOIP_DB` to a GeoLite2/GeoIP2 City or
Country MMDB, or place it at
`${XDG_DATA_HOME:-~/.local/share}/browser-relay/GeoIP-Country.mmdb`.
Standard City/Country filenames in `/usr/share/GeoIP` and `/var/lib/GeoIP` also work.
There is no automatic download, update, or online fallback. Locations are estimates
and may describe a CDN or proxy. [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite)
is supported; its [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) license
requires attribution to [DB-IP](https://db-ip.com/).

### Local Tranco and OISD indexes

**Domain insights** combines [Tranco's subdomain-inclusive top million](https://tranco-list.eu/)
with [OISD Big and NSFW](https://oisd.nl/setup). Matching is local:

- **Tranco** shows popularity for the latest inspected hostname, including return
  redirects. Exact ranks take precedence; a parent match is labeled explicitly.
  Popularity is not a whitelist or safety score.
- **OISD Big** mixes ads/tracking with phishing, malware and other threats.
  A match does not identify which category caused it.
- **OISD NSFW** flags adult/shock content separately from malware.
- **No match** means trust is unknown. Missing or invalid indexes show unavailable;
  IP literals cannot be classified by domain lists.

OISD parent-domain rules apply to subdomains, and warnings accumulate across
redirects. Tranco never suppresses them. Hover or open **Details & privacy** for
matched names, rank history, and source dates. Data older than seven days is
marked stale. Use the refresh icon to review the download disclosure, or run:

```sh
browser-relay --update-lists       # Tranco + both OISD lists
browser-relay --update-tranco      # popularity only
browser-relay --update-blocklists  # OISD only
```

Updates download complete lists from `big.oisd.nl`, `nsfw.oisd.nl`, and
`tranco-list.eu`; **no inspected hostname or URL is sent**. There are no automatic
updates. Validated snapshots replace caches atomically; failures retain old data,
and partial update failures are reported. Tranco preserves published ranks when
excluding non-web DNS entries. It covers listed subdomains, not every subdomain.

Caches live in `${XDG_DATA_HOME:-~/.local/share}/browser-relay/` as `oisd.bin` and
`tranco.bin`. `BROWSER_RELAY_OISD_DIR` and `BROWSER_RELAY_TRANCO_DIR` override their
directories. Packed text, 32-bit offsets and binary search keep lookups compact
and allocation-free; validated indexes are shared between checks.
OISD lists are capped at 32 MiB each, Tranco CSV at 64 MiB; download redirects
and cookies are disabled.

Data is downloaded separately under [OISD's GPL-3.0 license](https://github.com/sjhgvr/oisd/blob/main/LICENSE)
and [Tranco's source data terms](https://tranco-list.eu/), with source dates and
attribution preserved. Neither dataset is bundled with the app.

### Optional online checks and WHOIS

**WHOIS / RDAP**, **VirusTotal**, and **Online GeoIP** are opt-in. Each button
shows the identifier and destination before sharing anything. Domain checks are
unavailable for proxy/private destinations. Reopen WHOIS or GeoIP to read the
result, or find it in **Details & privacy**.

WHOIS-style registration data uses [RDAP over HTTPS](https://www.icann.org/rdap/).
The public suffix list selects the registered domain locally: `private.example.co.uk`
becomes `example.co.uk`, and `tenant.github.io` becomes `github.io`.
Only that domain is sent to the disclosed registry. Results include registrar,
registrant when disclosed, dates, nameservers, status, and DNSSEC registration
information. Records may be redacted and do not certify site safety.

Registry selection uses the bundled [IANA bootstrap map](https://data.iana.org/rdap/dns.json)
in [`assets/rdap-dns.json`](../assets/rdap-dns.json) (retrieved 2026-10-15, published 2026-09-30), with no runtime
bootstrap request. Maintainers can refresh it from that URL; suffix updates come
through `psl`. Missing HTTPS registry entries show unavailable. Registry addresses
must be public; responses are capped at 1 MiB. No redirects, registrar referrals,
or plaintext WHOIS fallback are followed. This checks the initial domain, not
its redirect destinations.

### Inspection privacy

Reviewed 2026-10-15. Opening the chooser or QR popup makes no inspection requests.
Inspect sends a HEAD request **including the link's path and query** to its
destination. Your resolver sees hostnames; peers see ICMP probes. Fragments are
removed, credentials are rejected, and no cookies or Referer headers are sent.
Another origin requires confirmation.

HTTP honors proxy and NO_PROXY settings. With proxy environment variables present,
separate DNS/ping checks and hostname lookup buttons are disabled to avoid
bypassing the proxy. Online checks exclude private/reserved IPs, local or unknown
namespaces, and names resolving to private addresses. Public IDN names are supported.
Confidential public hostnames cannot always be recognized: review the disclosure.

| Optional action | Information disclosed | Privacy limits |
| --- | --- | --- |
| Update local indexes | Connection IP, request metadata, public list version; **no inspected hostname or URL** | Full lists only on request. [Tranco logs requests](https://tranco-list.eu/privacy_policy). Matching stays offline. |
| WHOIS / RDAP | Registered domain to its authoritative registry | Registry policies vary; domain/IP logging is possible. No bootstrap intermediary or referrals. |
| Online GeoIP | One public connected peer IP | [ipwho.is policy](https://ipwhois.io/privacy) permits usage/IP logging and Cloudflare processing; no fixed retention guarantee is claimed here. |
| VirusTotal report | Initial hostname or public IP, via your browser | Browser cookies, account identity and history may apply. Its [privacy notice](https://cloud.google.com/terms/secops/privacy-notice) covers usage, identifiers and IP addresses. No full URL is submitted for scanning. |

All providers also see your connection IP (or proxy egress) and request metadata.
Optional checks receive no original URL path, query, credentials, or fragment.
Online GeoIP uses HTTPS without redirects or cookies, with a 64 KiB response cap.
Browser report pages can load their own third parties; their retention cannot be
verified by the app. Reports stay in memory, with no telemetry. Missing data,
failed pings, and unranked domains never imply safety.

Multiple links are opened together or copied as newline-separated text. Local
file paths and `file:` URLs work too. Links are passed as separate arguments,
without a shell. The clipboard needs a graphical session even in terminal mode.

Browser lookup uses `PATH`: `chromium` or `chromium-browser`, and `firefox` or
`firefox-esr`. The optional `BROWSER_RELAY_DIALOG=zenity` setting uses a basic
Zenity chooser instead of the GTK window.

## Development

`src/main.rs` handles arguments and terminal/Zenity interaction. `src/relay.rs`
launches browsers and clipboard helpers. `src/ui.rs` contains the chooser;
`src/inspector_ui.rs` renders reports. `src/inspect.rs` implements checks and privacy
boundaries, and `src/whois.rs` handles registration lookups. `src/domain_list.rs`
contains the packed OISD and Tranco indexes; `src/list_cache.rs` shares validated
snapshots and handles bounded downloads and atomic cache replacement.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
cargo audit --file fuzz/Cargo.lock
shellcheck install.sh uninstall.sh
cargo build --release --locked
python3 tests/install.py
```

The routing tests use fake executables; the installer tests use a temporary
home and fake XDG tools. Native GUI tests additionally need Xvfb, xdotool, ImageMagick, and
`zbarimg` (to decode QR codes from the captured windows):

```sh
xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/gui.py
```

Local TLS/redirect GUI regressions additionally need OpenSSL and Tesseract:

```sh
xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/inspection.py
xvfb-run -a -s '-screen 0 1280x1024x24' python3 tests/reputation.py
# Offline regression for a lookup finishing after the selected peer changes:
xvfb-run -a cargo test peer_change_discards_a_late_online_lookup -- --ignored --test-threads=1
```

The domain-list parser, binary-cache decoder and suffix matcher have a standalone
coverage-guided fuzz target (nightly Rust, `cargo-fuzz`, AddressSanitizer):

```sh
mkdir -p fuzz/corpus/domain_lists
cp fuzz/seeds/* fuzz/corpus/domain_lists/
cargo +nightly fuzz run domain_lists -- -max_total_time=60 -max_len=65536
```

Benchmark the downloaded data without networking or GTK:

```sh
rustc --edition=2024 -O -C lto=fat tools/bench_blocklist.rs -o /tmp/relay-bench
/tmp/relay-bench ~/.local/share/browser-relay/oisd.bin ~/.local/share/browser-relay/tranco.bin
```

For reference, a release microbenchmark on the development machine (2026-10-15)
loaded and validated Tranco list Q2Y54 in 71 ms. Its 999,713 web hostnames occupy
23.62 MiB of packed index storage; 287 non-web entries were excluded without
renumbering ranks. One million warm lookups over five mixed exact/parent/missing
queries took 74 ms (74 ns per lookup). OISD's two indexes occupy another 14.54 MiB.
These are index measurements, not end-to-end inspection times; the OS file cache
may already be warm, and download/parsing memory is higher than steady storage.

The installer always builds with `--release --locked`, fat LTO and one codegen
unit, and installs that build from the repository's target directory. It overrides
conflicting Cargo environment settings for those profile values.

The optional live smoke test is excluded from normal runs. It contacts only
`example.com`, plus an explicit `ipwho.is` lookup using public test
identifiers, and requires a local GeoIP database:

```sh
cargo test live_public_inspection -- --ignored --nocapture
# Separately contact example.com's authoritative registration service:
cargo test whois::tests::live_registry_lookup -- --ignored --nocapture
```

The regular checks do not open your browsers or modify your desktop preferences or
clipboard. The GUI test captures its windows under `/tmp/browser-relay-*.png`.

