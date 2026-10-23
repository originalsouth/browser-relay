#!/usr/bin/env python3
"""Copy only managed AUR files, avoiding commits for VCS version-only changes."""
from pathlib import Path
import re
import shutil
import sys

FILES = ("PKGBUILD", ".SRCINFO", "browser-relay.desktop")


def normalized(name: str, text: str) -> str:
    if name == "PKGBUILD":
        return re.sub(r"^pkgver=.*$", "pkgver=<generated>", text, flags=re.MULTILINE)
    if name == ".SRCINFO":
        return re.sub(r"^\s*pkgver = .*$", "\tpkgver = <generated>", text, flags=re.MULTILINE)
    return text


def sync(source: Path, destination: Path) -> bool:
    # Validate the whole input before changing any remote checkout files.
    texts = {}
    for name in FILES:
        path = source / name
        target = destination / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Expected a regular recipe file: {name}")
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError(f"Unexpected destination type: {name}")
        texts[name] = path.read_text()
    changed = any(
        not (destination / name).exists()
        or normalized(name, texts[name]) != normalized(name, (destination / name).read_text())
        for name in FILES
    )
    if changed:
        for name in FILES:
            shutil.copyfile(source / name, destination / name)
            (destination / name).chmod(0o644)
    return changed


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: sync-recipe.py RECIPE_DIRECTORY AUR_CHECKOUT")
    changed = sync(Path(sys.argv[1]), Path(sys.argv[2]))
    print("Updated AUR recipe files." if changed else "No packaging changes to publish.")
