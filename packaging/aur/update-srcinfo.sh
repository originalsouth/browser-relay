#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/browser-relay-git"
# Update metadata atomically; an invalid recipe must not empty a working .SRCINFO.
stage=$(mktemp .SRCINFO.XXXXXX)
trap 'rm -f -- "$stage"' EXIT
makepkg --printsrcinfo > "$stage"
mv -- "$stage" .SRCINFO
