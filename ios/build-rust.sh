#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $(uname -s) != Darwin ]]; then
    echo 'Building the XCFramework requires macOS and Xcode.' >&2
    exit 1
fi
command -v xcodebuild >/dev/null
command -v rustup >/dev/null
# Always build distributable code with the same release profile as the Linux installer.
export CARGO_TARGET_DIR="$PWD/target/ios"
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
rustup target add "${targets[@]}"
for target in "${targets[@]}"; do
    IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo rustc --release --locked --no-default-features --features mobile --lib --crate-type staticlib --target "$target"
done
output="$PWD/ios/build"
mkdir -p "$output/simulator" "$output/headers"
cp ios/Shared/RelayCore.h "$output/headers/"
lipo -create "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libbrowser_relay.a" \
    "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libbrowser_relay.a" \
    -output "$output/simulator/libbrowser_relay.a"
# Remove only the generated artifact; xcodebuild refuses an existing output directory.
rm -rf -- "$output/RelayCore.xcframework"
xcodebuild -create-xcframework \
    -library "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libbrowser_relay.a" -headers "$output/headers" \
    -library "$output/simulator/libbrowser_relay.a" -headers "$output/headers" \
    -output "$output/RelayCore.xcframework"
