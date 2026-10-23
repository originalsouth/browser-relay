#!/usr/bin/env python3
"""Test AUR synchronization locally; never contact AUR or load credentials."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import sys
import re
import os
import subprocess
import unittest

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("aur_sync", ROOT / "packaging/aur/sync-recipe.py")
sync_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_module)


class AURPublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aur-sync-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "recipe"
        self.target = Path(self.temp.name) / "aur"
        self.target.mkdir()
        shutil.copytree(ROOT / "packaging/aur/browser-relay-git", self.source)

    def test_initial_submission_then_noop(self):
        self.assertTrue(sync_module.sync(self.source, self.target))
        self.assertEqual(set(p.name for p in self.target.iterdir()), set(sync_module.FILES))
        self.assertFalse(sync_module.sync(self.source, self.target))

    def test_vcs_version_only_change_keeps_existing_metadata(self):
        sync_module.sync(self.source, self.target)
        original = re.search(r"^pkgver=(.+)$", (self.source / "PKGBUILD").read_text(), re.MULTILINE)[1]
        for name in ("PKGBUILD", ".SRCINFO"):
            path = self.source / name
            path.write_text(path.read_text().replace(original, "0.2.0.r99.g1234567"))
        self.assertFalse(sync_module.sync(self.source, self.target))
        self.assertIn(original, (self.target / "PKGBUILD").read_text())

    def test_packaging_change_updates_files_and_preserves_unmanaged_files(self):
        sync_module.sync(self.source, self.target)
        (self.target / "README").write_text("Maintainer notes")
        path = self.source / "PKGBUILD"
        path.write_text(path.read_text().replace("pkgrel=1", "pkgrel=2"))
        self.assertTrue(sync_module.sync(self.source, self.target))
        self.assertIn("pkgrel=2", (self.target / "PKGBUILD").read_text())
        self.assertEqual((self.target / "README").read_text(), "Maintainer notes")

    def test_destination_symlink_is_rejected_before_any_file_changes(self):
        outside = Path(self.temp.name) / "outside"
        outside.write_text("unchanged")
        (self.target / "browser-relay.desktop").symlink_to(outside)
        with self.assertRaises(ValueError):
            sync_module.sync(self.source, self.target)
        self.assertEqual(outside.read_text(), "unchanged")
        self.assertFalse((self.target / "PKGBUILD").exists())

    def test_source_symlink_is_rejected(self):
        path = self.source / ".SRCINFO"
        path.unlink()
        path.symlink_to(self.source / "PKGBUILD")
        with self.assertRaises(ValueError):
            sync_module.sync(self.source, self.target)
        self.assertEqual(list(self.target.iterdir()), [])


class AURPublisherIntegrationTests(unittest.TestCase):
    """Run the publisher against local Git repositories with disposable SSH fixtures."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aur-publisher-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.remote = self.root / "aur.git"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.real_git = shutil.which("git")
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_AUTHOR_NAME="Publisher fixture", GIT_AUTHOR_EMAIL="fixture@invalid",
                        GIT_COMMITTER_NAME="Publisher fixture", GIT_COMMITTER_EMAIL="fixture@invalid")
        self.git("init", "--quiet", "--initial-branch=main", str(self.source))
        self.git("init", "--quiet", "--bare", "--initial-branch=master", str(self.remote))
        folder = self.source / "packaging/aur"
        folder.mkdir(parents=True)
        for name in ("publish.sh", "sync-recipe.py"):
            shutil.copy2(ROOT / "packaging/aur" / name, folder / name)
        shutil.copytree(ROOT / "packaging/aur/browser-relay-git", folder / "browser-relay-git")
        self.git("-C", str(self.source), "add", ".")
        self.git("-C", str(self.source), "commit", "--quiet", "-m", "Fixture")
        key = self.root / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        self.env.update(AUR_SSH_PRIVATE_KEY=key.read_text(),
                        AUR_KNOWN_HOSTS="aur.archlinux.org " + key.with_suffix(".pub").read_text(),
                        AUR_GIT_NAME="AUR fixture", AUR_GIT_EMAIL="aur-fixture@invalid",
                        FIXTURE_GIT=self.real_git, FIXTURE_SOURCE=str(self.source), FIXTURE_AUR=str(self.remote),
                        PATH=str(self.tools) + os.pathsep + os.environ["PATH"])
        wrapper = self.tools / "git"
        wrapper.write_text("#!" + sys.executable + "\n" + r'''import os, sys
args = sys.argv[1:]
if args[:2] == ["ls-remote", "https://github.com/originalsouth/browser-relay.git"]:
    if os.environ.get("FAIL_UPSTREAM"):
        sys.exit(1)
    if os.environ.get("STALE_UPSTREAM"):
        print("0" * 40 + "\trefs/heads/main")
        sys.exit(0)
    args[1] = os.environ["FIXTURE_SOURCE"]
elif args[:3] == ["clone", "--no-checkout", "ssh://aur@aur.archlinux.org/browser-relay-git.git"]:
    args[2] = os.environ["FIXTURE_AUR"]
os.execv(os.environ["FIXTURE_GIT"], [os.environ["FIXTURE_GIT"]] + args)
''')
        wrapper.chmod(0o755)

    def git(self, *args):
        return subprocess.check_output([self.real_git, *args], env=self.env, stderr=subprocess.PIPE, text=True)

    def publish(self, **env):
        return subprocess.run([str(self.source / "packaging/aur/publish.sh")],
                              env=self.env | env, text=True, capture_output=True)

    def test_initial_push_and_idempotent_rerun(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        names = self.git("--git-dir=" + str(self.remote), "ls-tree", "--name-only", "master").splitlines()
        self.assertEqual(set(names), set(sync_module.FILES))
        first = self.git("--git-dir=" + str(self.remote), "rev-parse", "master")
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already up to date", result.stdout)
        self.assertEqual(first, self.git("--git-dir=" + str(self.remote), "rev-parse", "master"))

    def test_stale_run_does_not_publish(self):
        result = self.publish(STALE_UPSTREAM="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no longer the current main", result.stdout)
        self.assertEqual(self.git("--git-dir=" + str(self.remote), "for-each-ref"), "")

    def test_upstream_lookup_failure_is_an_error_and_never_publishes(self):
        result = self.publish(FAIL_UPSTREAM="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publication stopped", result.stderr)
        self.assertEqual(self.git("--git-dir=" + str(self.remote), "for-each-ref"), "")


if __name__ == "__main__":
    unittest.main()
