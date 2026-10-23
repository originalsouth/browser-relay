#!/usr/bin/env python3
"""Package the existing icon into the sizes required by the macOS asset compiler."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
assets = root / "build/Assets.xcassets"
icons = assets / "AppIcon.appiconset"
icons.mkdir(parents=True, exist_ok=True)
info = {"author": "xcode", "version": 1}
(assets / "Contents.json").write_text(json.dumps({"info": info}) + "\n")
images = []
for size in (16, 32, 128, 256, 512):
    for scale in (1, 2):
        filename = f"icon_{size}_{scale}x.png"
        subprocess.run(["sips", "-z", str(size * scale), str(size * scale),
                        str(root / "AppIcon.png"), "--out", str(icons / filename)],
                       check=True, stdout=subprocess.DEVNULL)
        images.append({"idiom": "mac", "size": f"{size}x{size}",
                       "scale": f"{scale}x", "filename": filename})
(icons / "Contents.json").write_text(json.dumps({"images": images, "info": info}, indent=2) + "\n")
