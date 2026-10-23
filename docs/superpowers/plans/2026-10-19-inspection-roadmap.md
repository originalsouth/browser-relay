# Inspection Roadmap: From Context Tiles to State-of-the-Art Link Assessment

Date: 2026-10-19. Status: proposed. Each phase gets its own implementation plan;
Phase 1 is planned in [2026-10-19-risk-factors.md](2026-10-19-risk-factors.md).

## Where we are

The transport and privacy design is strong: consent for cross-origin redirects,
no downgrades, hop and loop limits, disclosure before every optional lookup,
cancellation that drops all work. The *assessment* is weak:

| Gap | Evidence in code |
| --- | --- |
| Signals measure popularity and ad-blocking, not threats | `insights.rs` (Tranco rank, OISD Big mixes ads with threats) |
| Matching is hostname-only; malicious paths on shared hosts are invisible | `domain_list::List::matching_domain` |
| HEAD probe with a non-browser User-Agent is easy to cloak | `inspect.rs:82`, `client.head(...)` |
| Any non-3xx status (403, 405, 503) counts as "complete" | `route.rs` `Route::response` |
| Meta-refresh and JavaScript redirects are not seen | HEAD only, no body |
| Collected data is not used: cert age, lookalikes, domain age | `certificate.rs` prints `notBefore`; Tranco index unused for lookalikes; RDAP date only displayed |
| ICMP ping adds little reliability information | `inspect.rs` `ping` |

## Principles (unchanged, and binding for every phase)

1. **No verdict, no score.** Output explainable *factors*, each with evidence.
   "Nothing found" never reads as "safe".
2. **Local first.** Default checks send nothing beyond what Inspect already sends.
   Every online check is opt-in and shows exactly what it shares.
3. **Shared core.** Logic lives in the library (`src/lib.rs` modules) so the
   desktop and macOS apps agree; platforms only do transport and UI.
4. **Measured.** Heuristic thresholds are tuned against a labeled corpus, and
   their false-positive rates are published in `docs/reference.md`.

## Phases

### Phase 1 — Offline risk-factor engine (plan written)
New core modules `lookalike` and `risk`. Factors: confusable/lookalike of a
Tranco top-10k brand (Unicode TR39 skeletons), brand embedded in another domain
(combosquatting), one-edit near-miss, newly issued certificate (ignoring
short-lived ACME profiles), bare IP host, non-standard port, link shortener,
embedded destination parameter, cross-site redirect, plain HTTP, server refused
the check. Desktop "Risk factors" card, macOS bridge op, evaluation harness with
measured false-positive rates.
**Done when:** factors show on desktop and are exposed over the macOS bridge;
lookalike-family false positives below 0.5% on the benign corpus.

### Phase 2 — Probe fidelity
- When HEAD returns 403/405/501, retry once with `GET` and a 64 KiB body cap.
  Abort early once the cap is reached.
- Scan the capped body for `<meta http-equiv=refresh>` (treat it as a redirect
  through the existing consent rules) and for password forms posting to
  another origin (a new `credential-form` factor).
- Report 4xx/5xx as *inconclusive*, not complete. This changes `Route` and both
  UIs' assessment wording.
- When the query looks like a token (`token`, `code`, `key`, `sig`, `otp`,
  long high-entropy values), skip the probe by default and ask first. GET
  (and sometimes HEAD) can consume one-time links.
- Optional browser-like User-Agent, with a disclosure.
**Done when:** the tests in `tests/inspection.py` cover a 405 server, a
meta-refresh page and a cloaking server that answers HEAD differently.

### Phase 3 — Threat-intelligence feeds with URL-level matching
- Add [URLhaus](https://urlhaus.abuse.ch/) (CC0 malware URLs) and a phishing
  feed (Phishing.Database or the OpenPhish community feed) to the existing
  download → validate → atomic-swap pipeline (`list_cache`, `cache`).
- Add a URL index (normalized scheme+host+path, query stripped) next to the
  domain index. Both use the same packed format and bounded decoding.
- Each feed gets its own tile and threat label. OISD Big becomes "ads & tracking
  context" rather than the headline threat signal.
- Feed matches become `Warning` factors in the Phase 1 engine.
**Done when:** a URL in a feed is flagged while its host's other paths are not;
fuzz seeds cover the new index format.

### Phase 4 — Opt-in online intelligence
- **RDAP domain age into factors:** `registration::registered_at` gives a
  `new-domain` factor (Warning under 30 days, Notice under 180) once the user
  runs WHOIS. The UI re-runs `risk::assess` when the result arrives.
- **Google Safe Browsing v5, hash-prefix mode:** a user-supplied API key; only
  32-bit hash prefixes leave the device, and only after a local prefix hit.
  Off by default.
- **Cloudflare Radar URL Scanner:** a link-out button like VirusTotal. The
  disclosure states that the *full URL including path and query is published*
  (free-tier scans are public). Disabled when the query looks like a token
  (shared helper from Phase 2).
**Done when:** each service shows its disclosure, has privacy-table rows in
`docs/reference.md`, and its tests cover the identifier sent.

### Phase 5 — Reliability signals
- Replace the ping chart's headline with connection timings from the request:
  DNS, TCP connect, TLS handshake, time to first byte. Keep ping as a secondary
  detail.
- HSTS: the response header plus the Chromium HSTS preload list (downloaded
  like the other lists).
- DNSSEC validation status via Hickory, certificate expiry within 7 days,
  OCSP-must-staple / CT SCT presence as information-only rows.
**Done when:** timings work behind restricted ICMP and under proxies (where
they cover only the proxy hop, which the UI says).

## Order and dependencies

Phase 1 comes first: every later phase reports through its `Factor` type.
Phases 2 and 3 are independent of each other. Phase 4 depends on Phase 2's
token detector for the Radar button. Phase 5 is independent.
