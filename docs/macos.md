# macOS

The Mac client is a native SwiftUI/AppKit link chooser backed by the same Rust core
as Linux. Requires **macOS 14 or later**; the build
includes Apple Silicon and Intel. Native compilation, launch registration and UI
behavior still need validation on a Mac. Linux checks cannot establish those.

## Install from source

Install full Xcode, Rust via rustup, and XcodeGen (`brew install xcodegen` if you
use Homebrew). Open Xcode once to finish setup. If `xcode-select -p` points to
Command Line Tools, select Xcode in its Settings → Locations.

```sh
git clone https://github.com/originalsouth/browser-relay.git
cd browser-relay
./macos/install.sh
open -a "$HOME/Applications/BrowserRelay.app" 'https://github.com/originalsouth/browser-relay'
```

The installer builds both architectures with **fat LTO and one codegen unit**,
packages the existing icon, signs the local app ad hoc, and installs it in
`~/Applications/BrowserRelay.app`. It builds before replacing a working copy.
Quit an older running copy before launching the update. No GTK, XDG utilities,
clipboard helper or Apple developer account is required. This source build is
not a notarized download for distribution to other Macs.

Defaults are unchanged by installation. Choose **gear → Make default browser…**
in the app; macOS handles consent. Afterwards:

```sh
open 'https://github.com/originalsouth/browser-relay'
```

To undo that choice, select another browser under System Settings → Desktop & Dock
→ Default web browser. Quit Browser Relay and remove its app bundle to uninstall.
Local indexes remain in `~/Library/Application Support/BrowserRelay`; remove that
folder too if you no longer need them.

## Using it

Launch Services supplies the available HTTP/HTTPS handlers. The current default
appears first when it is another browser; Browser Relay excludes every copy of
itself. A chosen browser receives the original encoded link and is activated.
Launch failures keep the chooser open. Links arriving during an existing choice
or inspection queue up instead of replacing it. A batch can be opened together or
copied as separate lines; QR and inspection require a single link.

**⌘1–9** select browsers; **⇧⌘C** copies the link, **⌘R** shows the QR code, and
**⌘I** inspects. Ordinary **⌘C** still copies selected text. **Esc** dismisses a
choice. Closing or quitting is blocked while a launch or default-browser change
is pending. The app remains available after its window closes for the next link.

The address field accepts complete HTTP/HTTPS URLs. Local filenames and free text
are not silently sent to a website or search engine. Opening the chooser, copying
and generating a QR code make no inspection requests.

Use **Local data** to explicitly download OISD and Tranco, update signed CT keys,
or import a country MMDB. Index formats and bounds come from Rust. Lookups stay
local; updates send public dataset requests without an inspected address. GeoIP
has no online fallback. Index loading uses the shared bounded-memory reader.

## Shared checks and platform boundaries

URL rules, redirect consent, QR generation, certificate parsing, CT signatures and
proof verification, OISD matching, Tranco ranking, lookalike/risk factors and local
GeoIP all use the common Rust modules. `src/apple.rs` is the bounded C/JSON bridge,
not a second implementation of those checks.

`macos/App/BrowserRegistry.swift` handles discovery, activation and default browser
selection through NSWorkspace. AppKit owns URL events and window lifetime;
SwiftUI owns the views. NSPasteboard and Application Support supply clipboard and
storage integration. The app delegates page rendering to your chosen browser.

`macos/Shared/Transfer.swift` uses ephemeral URLSession requests with system DNS,
proxy settings and TLS verification. Inspection uses HEAD requests. Rust decides
whether to continue a redirect; cross-origin hops require consent. It sends no
browser cookies, saved credentials, Referer header or page scripts. Certificate
network fetching is disabled, so missing intermediates or unavailable cached
revocation data can differ from a normal browser visit.

Certificate history (Cert Spotter), classic-log inclusion proofs and signed log-key
updates each require explicit action and disclose their destination. An optional
history API key stays in memory and is restricted to the provider's fixed HTTPS
endpoint; each extra page requires another click. Log proofs send a
certificate-identifying hash. Native transport uses ordinary system routing; it
does not implement Linux's resolved-public-address pinning for optional checks.

The Mac dashboard shows **HTTP response timing**, not ICMP ping. Dedicated DNS
record queries, ICMP probes, WHOIS/RDAP, VirusTotal and online GeoIP controls are
currently Linux-only. CT checks are not full browser CT policy, consistency audits
or a guarantee of site safety; tiled-log inclusion proofs are not implemented.

## Develop and test

```sh
./macos/build-rust.sh
(cd macos && xcodegen generate)
./macos/test.sh
open macos/BrowserRelay.xcodeproj
```

The Rust script builds the universal static library and XCFramework plus app-icon
sizes. Rerun it after changing Rust. Generated artifacts are ignored by Git.
`test.sh` runs native tests with local transport fixtures, builds a universal
release app and checks both architectures. The `macOS` workflow runs this sequence on Apple Silicon and Intel runners.
Native tests cover bridge decoding, redirect consent, cancellation, API credential
scope, queued links, launch failures, pending-launch lifetime and browser deduping.
They do not change your default browser or send live inspection requests.

The portable core can be checked on Linux:

```sh
cargo test --locked --no-default-features --features apple --lib
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 tests/macos_install.py
python3 tests/macos_package.py
python3 tests/macos_release.py
```

Before calling this release-ready, test cold and warm `open` delivery, real browser
activation, default-browser consent, keyboard/VoiceOver behavior and small-screen
layout on macOS. This repository does not yet contain a verified Mac screenshot.

## CI builds

The [macOS workflow](https://github.com/originalsouth/browser-relay/actions/workflows/macos.yml)
runs on pushes, pull requests and manual dispatches. Both native architectures run
the shared Rust tests, Clippy and XCTest suite, then build and verify a universal
fat-LTO release. The Apple Silicon job packages that app with `macos/package.sh`.
Each job retains Xcode test results and logs for seven days, including failed runs.

Every push to `main` gets a tag such as `v0.2.0-build.42`: the Cargo version plus
that workflow's run number. The tag points to the exact pushed commit; reruns reuse
it. Both Mac jobs must pass before the ZIP and checksum are published as a
[GitHub prerelease](https://github.com/originalsouth/browser-relay/releases).
Failed builds keep their tag but publish no package. Main pushes do not cancel
each other's builds. Branches, pull requests and manual runs only upload CI artifacts.

Download `BrowserRelay-macos-universal.zip` and its `.sha256` file, then verify:

```sh
shasum -a 256 -c BrowserRelay-macos-universal.zip.sha256
```

Extract the ZIP and move `BrowserRelay.app` into Applications. Release downloads
remain available; CI artifacts expire after 14 days. These builds are ad-hoc signed,
**not Developer ID signed or Apple notarized**; macOS may block a downloaded build.
Build from source for local use, or approve a trusted build through macOS Privacy
& Security. The workflow uses GitHub's built-in token to create tags and releases;
no additional secret is needed. It does not change browser defaults.
