#!/usr/bin/env python3
"""Tag main pushes and publish the tested universal app; safe to rerun."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "originalsouth/browser-relay"
ARCHIVE = "BrowserRelay-macos-universal.zip"
ASSETS = (ARCHIVE, ARCHIVE + ".sha256")


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True).strip()


def api(path, *, optional=False):
    result = subprocess.run(["gh", "api", path], text=True, capture_output=True)
    if result.returncode:
        # A missing ref/release is expected on the first run; auth and service
        # failures must stop publication instead of masquerading as absence.
        try:
            missing = str(json.loads(result.stdout).get("status")) == "404"
        except (ValueError, AttributeError):
            missing = False
        if optional and missing:
            return None
        raise RuntimeError(result.stderr.strip() or f"GitHub request failed: {path}")
    return json.loads(result.stdout)


def context(env, root=ROOT):
    if (env.get("GITHUB_REPOSITORY") != REPOSITORY
            or env.get("GITHUB_EVENT_NAME") != "push"
            or env.get("GITHUB_REF") != "refs/heads/main"):
        raise ValueError("Automatic releases are only for pushes to originalsouth/browser-relay main.")
    sha, number = env.get("GITHUB_SHA", ""), env.get("GITHUB_RUN_NUMBER", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[1-9][0-9]*", number):
        raise ValueError("Missing commit SHA or workflow run number.")
    with (root / "Cargo.toml").open("rb") as file:
        version = tomllib.load(file)["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a numeric Cargo release version.")
    return f"v{version}-build.{number}", sha


def check_tag(tag, sha, *, create=False):
    endpoint = f"repos/{REPOSITORY}/git/ref/tags/{tag}"
    existing = api(endpoint, optional=create)
    if existing is None:
        gh("api", f"repos/{REPOSITORY}/git/refs", "-f", f"ref=refs/tags/{tag}", "-f", f"sha={sha}")
    elif existing["object"].get("type") != "commit" or existing["object"].get("sha") != sha:
        raise ValueError(f"Tag {tag} does not point directly to this commit; refusing to move it.")


def verify_assets(folder):
    files = [folder / name for name in ASSETS]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Expected the universal app ZIP and checksum as regular files.")
    with files[0].open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    if files[1].read_text().split() != [digest, ARCHIVE]:
        raise ValueError("Universal app checksum does not match.")
    return files


def publish(tag, sha, folder):
    files = verify_assets(folder)
    check_tag(tag, sha)
    release = api(f"repos/{REPOSITORY}/releases/tags/{tag}", optional=True)
    if release is not None and not release["draft"]:
        if not all(any(asset["name"] == name and asset["state"] == "uploaded"
                       for asset in release["assets"]) for name in ASSETS):
            raise ValueError("Published release is missing assets; refusing to modify it.")
        print(f"Already published: https://github.com/{REPOSITORY}/releases/tag/{tag}")
        return
    if release is None:
        notes = (
            f"Automatic build from [{sha[:7]}](https://github.com/{REPOSITORY}/commit/{sha}).\n\n"
            "Universal macOS app for Apple Silicon and Intel, tested on both architectures.\n"
            "Download the ZIP and checksum, then verify with:\n\n"
            f"```sh\nshasum -a 256 -c {ARCHIVE}.sha256\n```\n\n"
            "Extract the ZIP and move BrowserRelay.app into Applications. Requires macOS 14+.\n\n"
            "Ad-hoc signed; not Developer ID signed or Apple notarized. macOS may require approval "
            "in Privacy & Security.\n"
        )
        with tempfile.TemporaryDirectory(prefix="relay-release-") as temp:
            path = Path(temp) / "notes.md"
            path.write_text(notes)
            gh("release", "create", tag, "--repo", REPOSITORY, "--verify-tag", "--draft",
               "--prerelease", "--latest=false", "--title", f"Browser Relay {tag}",
               "--notes-file", str(path))
    # Upload only to a draft, so a partial failure cannot expose an incomplete
    # release. Retrying resumes that draft; published assets are never replaced.
    gh("release", "upload", tag, *(str(file) for file in files), "--repo", REPOSITORY, "--clobber")
    gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--prerelease", "--latest=false")
    print(f"Published: https://github.com/{REPOSITORY}/releases/tag/{tag}")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("tag", "publish"):
        raise SystemExit("Usage: release.py tag|publish")
    tag, sha = context(os.environ)
    if sys.argv[1] == "tag":
        check_tag(tag, sha, create=True)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as file:
            file.write(f"tag={tag}\n")
        print(f"Tagged {sha}: {tag}")
    else:
        if os.environ.get("RELEASE_TAG") != tag:
            raise ValueError("Release tag does not match this workflow run.")
        publish(tag, sha, ROOT / "macos/build/dist")


if __name__ == "__main__":
    main()
