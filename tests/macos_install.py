#!/usr/bin/env python3
"""Exercise the Mac install transaction with fake build tools; no SDK/network needed."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MacInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="relay-mac-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home with spaces"
        self.tools = self.root / "tools"
        self.project = self.root / "project"
        self.tools.mkdir()
        self.project.mkdir()
        self.home.mkdir()
        self.installed = self.home / "Applications/BrowserRelay.app"
        self.installed.mkdir(parents=True)
        (self.installed / "version").write_text("old")
        shutil.copy2(ROOT / "macos/install.sh", self.project / "install.sh")
        self.script(self.project / "build-rust.sh", 'exit "${FAIL_BUILD:-0}"\n')
        for tool in ("xcodegen", "cargo", "rustup"):
            self.script(self.tools / tool, 'exit 0\n')
        self.script(self.tools / "uname", 'echo Darwin\n')
        self.script(self.tools / "xcodebuild", '''
mkdir -p build/Release/Build/Products/Release/BrowserRelay.app
printf new > build/Release/Build/Products/Release/BrowserRelay.app/version
''')
        self.script(self.tools / "codesign", 'exit "${FAIL_SIGN:-0}"\n')
        self.script(self.tools / "ditto", '''
if [[ ${FAIL_COPY:-0} == 1 ]]; then exit 1; fi
cp -R -- "$1" "$2"
''')
        # Fail only the final replacement, allowing cleanup to restore the old app.
        self.script(self.tools / "mv", f'''
if [[ ${{FAIL_REPLACE:-0}} == 1 && ${{2:-}} == */.browser-relay.*/BrowserRelay.app ]]; then exit 1; fi
exec '{shutil.which("mv")}' "$@"
''')
        self.env = dict(os.environ, HOME=str(self.home), PATH=str(self.tools) + os.pathsep + os.environ["PATH"])

    @staticmethod
    def script(path, body):
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
        path.chmod(0o755)

    def run_install(self, **env):
        return subprocess.run([str(self.project / "install.sh")], env=self.env | env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def assert_no_staging_directory(self):
        self.assertEqual(list((self.home / "Applications").glob(".browser-relay.*")), [])

    def test_success_installs_new_app_without_changing_defaults(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.installed / "version").read_text(), "new")
        self.assertIn("Existing defaults were not changed", result.stdout)
        self.assert_no_staging_directory()

    def test_failures_preserve_existing_installation(self):
        for failure in ("FAIL_BUILD", "FAIL_SIGN", "FAIL_COPY", "FAIL_REPLACE"):
            with self.subTest(failure=failure):
                result = self.run_install(**{failure: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.installed / "version").read_text(), "old")
                self.assert_no_staging_directory()

    def test_linux_invocation_fails_before_building(self):
        self.script(self.tools / "uname", "echo Linux\n")
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires macOS", result.stderr)
        self.assertFalse((self.project / "build").exists())
        self.assertEqual((self.installed / "version").read_text(), "old")


if __name__ == "__main__":
    unittest.main()
