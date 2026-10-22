# iOS

The iOS client is a native SwiftUI app and Share extension backed by the same Rust
core as Linux. It targets iOS 17 and later. **The native build and device behavior
still need validation on a Mac**. The shared Rust core is tested on Linux; its
cryptography dependency requires the Apple SDK for iPhone and Simulator builds.

## Build on a Mac

Install Xcode with an iOS Simulator runtime, Rust through rustup, and
[XcodeGen](https://github.com/yonaskolb/XcodeGen). Select the full Xcode installation
with `xcode-select` if your active developer directory is Command Line Tools.

```sh
./ios/build-rust.sh
cd ios
xcodegen generate
cd ..
./ios/test.sh
open ios/BrowserRelay.xcodeproj
```

The Rust script produces an XCFramework for iPhone and both Simulator
architectures. Every slice uses `--release --locked`, fat LTO and one codegen unit.
Rerun it after changing Rust. The generated project and build artifacts stay out
of Git. The macOS CI job runs the same Simulator tests and builds both schemes.

For a physical device, choose your signing team for the app and Share extension.
Use bundle identifiers registered to your team and provision the same App Group
for both targets; change `RELAY_APP_GROUP` in the project settings accordingly.
Without a working App Group, each target falls back to its own container, so data
installed in the app will not be available to the extension.

## Using it

Enter a complete web address to browse, or inspect it before opening. Link tools
provide Copy, QR and Inspect; Chrome and Firefox handoff buttons appear when their
declared URL schemes are available. iOS does not expose Linux's desktop browser
registry. In another app, use **Share → Browser Relay** to inspect a shared address.
The extension loads neither the page nor its QR code automatically.

The **Data** screen downloads OISD Big, OISD NSFW and Tranco's subdomain-inclusive
top million after confirmation. Matching is local. Import a country MMDB under
16 MiB for GeoIP; use a database you are licensed to use. DB-IP Lite attribution:
[DB-IP.com](https://db-ip.com/), CC BY 4.0. Rust supplies the download/import limits
to Swift. Mobile lookups stream one index at a time directly into final storage,
then release it; indexes are not cached in memory. A 32 MiB allocation budget
covers the reader buffer, decoded index and rank-validation scratch, plus the
lookalike index when built alongside Tranco. Local work
is serialized so concurrent inspections cannot multiply that allowance. Larger
indexes report unavailable; updates validate that same allowance before replacing
a working index. If Tranco leaves too little room for lookalikes, those checks
report unavailable while rank lookups remain usable. Only small host-factor
reports are cached; unchanged hosts reuse them, and replacing the index
invalidates them. Route and certificate factors are recomputed for each attempt.
The UI and OS add their own memory use; Share-extension
behavior still needs device testing. List updates run in the main app.

An earlier Linux release probe, before lookalike checks, of the mobile Rust core with 14.54 MiB OISD and 23.62 MiB
Tranco indexes peaked at 28.7 MiB process RSS. Three complete lookup passes took
305 ms with warm OS file caches. This excludes SwiftUI and is not an iOS device
measurement.

| Capability | Linux | iOS |
| --- | --- | --- |
| URL rules, QR, redirect consent and limits | Shared Rust | Shared Rust |
| OISD, Tranco, certificate parsing, local GeoIP | Shared Rust | Shared Rust |
| Embedded SCT signatures and history parsing | Shared Rust | Shared Rust |
| Opt-in history, inclusion proofs and signed key updates | Shared Rust + HTTP adapter | Shared Rust + URLSession |
| Browser discovery and launch | Desktop registrations | Chrome/Firefox schemes, native browser |
| Clipboard and interface | GTK / desktop | UIKit / SwiftUI |
| Network and TLS | Rust libraries / system roots | URLSession / iOS trust |
| DNS records and ICMP charts | Available | HTTP response-time chart only |
| Opt-in RDAP, VirusTotal and online GeoIP | Available | Not exposed yet |

## Default-browser support

The ordinary **BrowserRelay** scheme supports browsing and sharing without asking
for Apple's managed browser entitlement. **BrowserRelayDefault** additionally
registers HTTP/HTTPS and requests `com.apple.developer.web-browser`. Shipping this
configuration requires Apple's approval and the corresponding provisioning profile;
adding an entitlement file alone does not make the app a selectable default.

Apple requires incoming default-browser links to navigate directly and render
content. The app therefore opens these links in WKWebView, with inspection
available from Link tools. It cannot be a chooser-only default browser under
those requirements. See [Apple's default-browser requirements](https://developer.apple.com/documentation/xcode/preparing-your-app-to-be-the-default-browser).

## Boundaries and privacy

`src/lib.rs` exposes the common Rust core. `route.rs` owns redirect decisions,
visited hosts, the six-request budget and the accumulated encryption assessment.
`link.rs`, `certificate.rs`, `geo.rs`, `insights.rs`, `registration.rs`,
`domain_list.rs` and `cache.rs` contain shared validation, parsing and storage
formats. Linux calls these directly; `mobile.rs` exposes bounded JSON over an
owned-buffer C ABI. Swift releases every returned buffer and inspection handle.

`ios/Shared/Transfer.swift` is the iOS transport boundary. Inspection sends HEAD
requests only after a tap, strips fragments through Rust, rejects automatic
redirects, and uses an ephemeral session without browser cookies, saved
credentials or a response cache. Cross-origin continuation needs confirmation;
HTTPS downgrades are rejected by Rust. Responses have size and time limits;
closing an inspection cancels its request. iOS controls DNS and proxy routing.
Server addresses from task metrics may describe a CDN, proxy or VPN endpoint.

Inspection retains the OS SSL/hostname trust policies and requires successful
trust evaluation. Missing-certificate fetching is disabled and revocation checks
use locally available information only. A chain that needs a network fetch may
fail. This does not establish site trust or current revocation status. Ordinary
WKWebView browsing uses the system's normal browser behavior, including page
scripts, cookies and third-party resources; it is separate from inspection.

Explicit dataset updates contact only the fixed OISD and Tranco publishers. They
send no inspected URL or hostname. Redirects from publishers are rejected; Rust
validates formats and atomically replaces complete snapshots. Closing Data
cancels network transfers; a local validation/write already underway may finish.
Caches are excluded from backups. No telemetry or automatic online GeoIP fallback.
The privacy manifest declares local file metadata access and elapsed-time
measurement. Opening or inspecting a LAN address can trigger iOS's local-network
permission prompt.

Other online checks (RDAP, VirusTotal and online GeoIP) remain Linux-only until
their disclosure, public-address validation and destination pinning can be
preserved in the mobile adapter.
Shared RDAP parsing and provider selection are already in Rust.

Before distribution, run the native tests and check actual Safari sharing,
long-link QR warnings, redirect consent, certificate failures, cancellation,
list updates, App Group access, memory use, and Chrome/Firefox handoff on a device.
Default-browser selection additionally requires the approved build and profile.

The normal desktop build emits only the shared Rust library (`rlib`).
`build-rust.sh` explicitly requests a `staticlib` for each iOS target, with fat LTO.
Completed and stopped routes release their Rust handles automatically; Swift also
releases handles on cancellation and model destruction. Pending handles expire
after five idle minutes. At the 32-handle limit, the oldest consent prompt is
reclaimed first, or the oldest pending request if none await consent. An expired
inspection must be restarted; it cannot silently resume a redirect.

Authentication challenges are declined without sending credentials; HTTP 401
remains a result. Servers that require a client certificate can still refuse the
connection. Certificate and registry identity text strips control and bidi formatting.

Certificate transparency uses the leaf and issuer from iOS's verified trust chain.
The CT evidence is local; the separate certificate-history sheet names the initial
hostname and provider before requesting anything. It uses an ephemeral bounded
transfer, with no cookies, redirects or persistent report cache. Its optional API
key stays in memory and is restricted to Cert Spotter; each next page needs a
click. The separate inclusion sheet discloses the certificate-identifying hash
before requesting a signed tree head and proof. **Local data → Update log keys**
refreshes signed metadata without sharing an inspected link.
Both interfaces use the same Rust protocol and verification rules; see the
[CT limitations and data disclosure](reference.md#certificate-transparency).
The shared cryptography dependency builds native code, so iOS cross-checks now
require Apple's SDK and `xcrun` on macOS as well as the Rust target.
