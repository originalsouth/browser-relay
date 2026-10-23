#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $(uname -s) != Darwin ]]; then
    echo 'Use ./install.sh on Linux; this installer requires macOS 14 or later and Xcode.' >&2
    exit 1
fi
if (( $# != 0 )); then
    echo 'Usage: ./macos/install.sh' >&2
    exit 2
fi
for tool in xcodebuild xcodegen cargo rustup codesign ditto; do
    command -v "$tool" >/dev/null || { echo "Missing dependency: $tool. See docs/macos.md." >&2; exit 1; }
done
./build-rust.sh
xcodegen generate
xcodebuild build -project BrowserRelay.xcodeproj -scheme BrowserRelay -configuration Release \
    -destination 'generic/platform=macOS' -derivedDataPath build/Release \
    ARCHS='arm64 x86_64' ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO
source_app="$PWD/build/Release/Build/Products/Release/BrowserRelay.app"
# Build and sign before touching a working installation. No account is needed for a local build.
codesign --force --sign - --options runtime "$source_app"
codesign --verify --deep --strict "$source_app"
applications="$HOME/Applications"
mkdir -p "$applications"
stage=$(mktemp -d "$applications/.browser-relay.XXXXXX")
backup=''
cleanup() {
    if [[ -n $backup && -e $backup && ! -e "$applications/BrowserRelay.app" ]]; then
        mv -- "$backup" "$applications/BrowserRelay.app"
    fi
    rm -rf -- "$stage"
}
trap cleanup EXIT
ditto "$source_app" "$stage/BrowserRelay.app"
if [[ -e "$applications/BrowserRelay.app" ]]; then
    backup="$stage/previous.app"
    mv -- "$applications/BrowserRelay.app" "$backup"
fi
mv -- "$stage/BrowserRelay.app" "$applications/BrowserRelay.app"
echo "Installed: $applications/BrowserRelay.app"
echo 'Quit any older running copy, then launch Browser Relay from Applications.'
echo 'Use its gear menu to make it your default browser. Existing defaults were not changed.'
echo "Try: open -a '$applications/BrowserRelay.app' 'https://github.com/originalsouth/browser-relay'"
