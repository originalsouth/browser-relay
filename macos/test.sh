#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# Run build-rust.sh and xcodegen first. Native tests use local transport fixtures.
mkdir -p build
# Xcode requires a fresh result bundle; remove only this generated test artifact.
rm -rf -- build/TestResults.xcresult
xcodebuild test -project BrowserRelay.xcodeproj -scheme BrowserRelay \
    -destination "platform=macOS,arch=$(uname -m)" -derivedDataPath build/DerivedData \
    -resultBundlePath build/TestResults.xcresult \
    CODE_SIGNING_ALLOWED=NO 2>&1 | tee build/Test.log
xcodebuild build -project BrowserRelay.xcodeproj -scheme BrowserRelay -configuration Release \
    -destination 'generic/platform=macOS' -derivedDataPath build/Release \
    ARCHS='arm64 x86_64' ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO 2>&1 | tee build/Release.log
lipo build/Release/Build/Products/Release/BrowserRelay.app/Contents/MacOS/BrowserRelay -verify_arch arm64 x86_64
