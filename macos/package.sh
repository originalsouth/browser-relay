#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $(uname -s) != Darwin ]]; then
    echo 'Packaging the macOS app requires a Mac.' >&2
    exit 1
fi
source_app="$PWD/build/Release/Build/Products/Release/BrowserRelay.app"
[[ -d "$source_app" ]] || { echo 'Run macos/test.sh or macos/install.sh first.' >&2; exit 1; }
output="$PWD/build/dist"
mkdir -p "$output"
stage=$(mktemp -d "$PWD/build/package.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
# Package a copy so diagnostics still describe the original build products.
ditto "$source_app" "$stage/BrowserRelay.app"
lipo -verify_arch arm64 x86_64 "$stage/BrowserRelay.app/Contents/MacOS/BrowserRelay"
# CI artifacts are test builds: ad-hoc signing, no Developer ID secrets or notarization.
codesign --force --sign - --options runtime "$stage/BrowserRelay.app"
codesign --verify --deep --strict "$stage/BrowserRelay.app"
archive=BrowserRelay-macos-universal.zip
ditto -c -k --sequesterRsrc --keepParent "$stage/BrowserRelay.app" "$stage/$archive"
(cd "$stage" && shasum -a 256 "$archive" > "$archive.sha256")
mv -f -- "$stage/$archive" "$stage/$archive.sha256" "$output/"
echo "Packaged: $output/$archive"
