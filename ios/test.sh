#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# Run build-rust.sh and xcodegen first. Pick an installed iPhone rather than a specific model.
device=$(xcrun simctl list devices available -j | python3 -c '
import json, sys
for devices in json.load(sys.stdin)["devices"].values():
    for device in devices:
        if device["name"].startswith("iPhone"):
            print(device["udid"])
            sys.exit(0)
sys.exit("No available iPhone simulator. Install one in Xcode Settings > Components.")
')
xcodebuild test -project BrowserRelay.xcodeproj -scheme BrowserRelay \
    -destination "platform=iOS Simulator,id=$device" -derivedDataPath build/DerivedData \
    CODE_SIGNING_ALLOWED=NO
xcodebuild build -project BrowserRelay.xcodeproj -scheme BrowserRelayDefault \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath build/DerivedData \
    CODE_SIGNING_ALLOWED=NO
