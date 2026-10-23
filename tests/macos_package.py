#!/usr/bin/env python3
"""Verify package publication stops on architecture/signature failures without a Mac SDK."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MacPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="relay-package-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.project = self.root / "project with spaces"
        self.project.mkdir()
        shutil.copy2(ROOT / "macos/package.sh", self.project / "package.sh")
        app = self.project / "build/Release/Build/Products/Release/BrowserRelay.app"
        app.mkdir(parents=True)
        (app / "payload").write_bytes(b"fixture application")
        self.script("uname", "echo Darwin\n")
        self.script("lipo", 'exit "${FAIL_ARCH:-0}"\n')
        self.script("codesign", 'exit "${FAIL_SIGN:-0}"\n')
        self.script("ditto", '''
if [[ $1 == -c ]]; then
    if [[ ${FAIL_ARCHIVE:-0} == 1 ]]; then exit 1; fi
    cp -- "$5/payload" "$6"
else
    cp -R -- "$1" "$2"
fi
''')
        self.env = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ["PATH"])
        self.output = self.project / "build/dist"

    def script(self, name, body):
        path = self.tools / name
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
        path.chmod(0o755)

    def run_package(self, **env):
        return subprocess.run([str(self.project / "package.sh")], env=self.env | env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_success_publishes_artifact_with_matching_checksum(self):
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = self.output / "BrowserRelay-macos-universal.zip"
        expected = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(Path(str(archive) + ".sha256").read_text().split()[0], expected)
        self.assertEqual(list((self.project / "build").glob("package.*")), [])

    def test_invalid_binary_or_failed_archive_never_publishes(self):
        for failure in ("FAIL_ARCH", "FAIL_SIGN", "FAIL_ARCHIVE"):
            with self.subTest(failure=failure):
                result = self.run_package(**{failure: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(self.output.iterdir()), [])
                self.assertEqual(list((self.project / "build").glob("package.*")), [])


if __name__ == "__main__":
    unittest.main()
