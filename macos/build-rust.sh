#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $(uname -s) != Darwin ]]; then
    echo 'Building the macOS app requires a Mac with Xcode.' >&2
    exit 1
fi
for tool in xcodebuild xcrun rustup cargo lipo sips python3; do
    command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done
export SDKROOT
SDKROOT=$(xcrun --sdk macosx --show-sdk-path)
export MACOSX_DEPLOYMENT_TARGET=14.0
export CARGO_TARGET_DIR="$PWD/target/macos"
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
targets=(aarch64-apple-darwin x86_64-apple-darwin)
rustup target add "${targets[@]}"
for target in "${targets[@]}"; do
    cargo rustc --release --locked --no-default-features --features apple --lib --crate-type staticlib --target "$target"
done
output="$PWD/macos/build"
mkdir -p "$output/universal" "$output/headers"
cp macos/Shared/RelayCore.h "$output/headers/"
lipo -create "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libbrowser_relay.a" \
    "$CARGO_TARGET_DIR/x86_64-apple-darwin/release/libbrowser_relay.a" \
    -output "$output/universal/libbrowser_relay.a"
# Only generated artifacts are replaced.
rm -rf -- "$output/RelayCore.xcframework"
xcodebuild -create-xcframework \
    -library "$output/universal/libbrowser_relay.a" -headers "$output/headers" \
    -output "$output/RelayCore.xcframework"
python3 macos/icons.py
