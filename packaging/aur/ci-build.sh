#!/usr/bin/env bash
set -euo pipefail
if (( $# != 2 )); then
    echo 'Usage: ci-build.sh SOURCE_REPOSITORY OUTPUT_DIRECTORY' >&2
    exit 2
fi
repo=$(realpath "$1")
mkdir -p "$2"
output=$(realpath "$2")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/recipe" "$output/packages" "$output/aur/browser-relay-git"
cp "$repo/packaging/aur/browser-relay-git/"{PKGBUILD,.SRCINFO,browser-relay.desktop} "$work/recipe/"
cd "$work/recipe"
makepkg --printsrcinfo > "$work/generated.SRCINFO"
diff -u .SRCINFO "$work/generated.SRCINFO"
# Build precisely this workflow's commit (including PR merges), not remote main.
# The published PKGBUILD keeps the canonical upstream URL.
revision=$(git -C "$repo" rev-parse HEAD)
git clone --bare --no-hardlinks "$repo" "$work/upstream.git"
git --git-dir="$work/upstream.git" update-ref refs/heads/main "$revision"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="url.file://$work/upstream.git.insteadOf"
export GIT_CONFIG_VALUE_0=https://github.com/originalsouth/browser-relay.git
export PKGDEST="$output/packages"
makepkg --noconfirm --cleanbuild --clean 2>&1 | tee "$output/build.log"
makepkg --printsrcinfo > .SRCINFO
cp PKGBUILD .SRCINFO browser-relay.desktop "$output/aur/browser-relay-git/"
tar -C "$output/aur" -czf "$output/browser-relay-git-aur.tar.gz" browser-relay-git
printf '%s\n' "$revision" > "$output/source-commit.txt"
