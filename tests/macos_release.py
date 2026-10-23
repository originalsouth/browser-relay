#!/usr/bin/env python3
"""Offline tests of tag identity, publication retries and failure boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release", ROOT / "macos/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = "a" * 40
TAG = "v0.2.0-build.42"
REF = {"object": {"type": "commit", "sha": SHA, "url": "https://fixture.invalid/commit"}}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="relay-release-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.2.0"\n')
        (self.root / release.ARCHIVE).write_bytes(b"fixture app archive")
        digest = hashlib.sha256(b"fixture app archive").hexdigest()
        (self.root / (release.ARCHIVE + ".sha256")).write_text(f"{digest}  {release.ARCHIVE}\n")
        self.env = {"GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_REF": "refs/heads/main",
                    "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": SHA, "GITHUB_RUN_NUMBER": "42"}

    def test_only_main_pushes_get_unique_stable_tags(self):
        self.assertEqual(release.context(self.env, self.root), (TAG, SHA))
        self.assertEqual(release.context(self.env | {"GITHUB_RUN_ATTEMPT": "2"}, self.root), (TAG, SHA))
        self.assertNotEqual(release.context(self.env | {"GITHUB_RUN_NUMBER": "43"}, self.root)[0], TAG)
        for key, value in [("GITHUB_REF", "refs/heads/topic"), ("GITHUB_REF", "refs/tags/v1.0.0"),
                           ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                           ("GITHUB_REPOSITORY", "someone/fork"), ("GITHUB_SHA", "main"),
                           ("GITHUB_RUN_NUMBER", "42\ninjection")]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                release.context(self.env | {key: value}, self.root)

    def test_new_tag_uses_event_sha_and_existing_tag_is_not_moved(self):
        with patch.object(release, "api", return_value=None), patch.object(release, "gh") as gh:
            release.check_tag(TAG, SHA, create=True)
            self.assertIn(f"sha={SHA}", gh.call_args.args)
            self.assertIn(f"ref=refs/tags/{TAG}", gh.call_args.args)
        with patch.object(release, "api", return_value=REF), patch.object(release, "gh") as gh:
            release.check_tag(TAG, SHA, create=True)
            gh.assert_not_called()
        with patch.object(release, "api", return_value=REF), patch.object(release, "gh") as gh:
            with self.assertRaises(ValueError):
                release.check_tag(TAG, "b" * 40, create=True)
            gh.assert_not_called()

    def test_only_404_means_missing(self):
        for status in (404, 403, 500):
            result = subprocess.CompletedProcess([], 1, json.dumps({"status": str(status)}), "fixture failure")
            with patch.object(release.subprocess, "run", return_value=result):
                if status == 404:
                    self.assertIsNone(release.api("fixture", optional=True))
                else:
                    with self.assertRaises(RuntimeError):
                        release.api("fixture", optional=True)

    def test_bad_checksum_stops_before_any_github_request(self):
        (self.root / release.ARCHIVE).write_bytes(b"damaged")
        with patch.object(release, "api") as api, patch.object(release, "gh") as gh:
            with self.assertRaises(ValueError):
                release.publish(TAG, SHA, self.root)
            api.assert_not_called()
            gh.assert_not_called()

    def test_publication_uploads_to_draft_before_publishing(self):
        with patch.object(release, "api", side_effect=[REF, None]), patch.object(release, "gh") as gh:
            release.publish(TAG, SHA, self.root)
            calls = [call.args for call in gh.call_args_list]
            self.assertEqual([args[1] for args in calls], ["create", "upload", "edit"])
            self.assertIn("--verify-tag", calls[0])
            self.assertIn("--draft", calls[0])
            self.assertIn("--prerelease", calls[0])
            self.assertIn(str(self.root / release.ARCHIVE), calls[1])
            self.assertIn(str(self.root / (release.ARCHIVE + ".sha256")), calls[1])
            self.assertIn("--draft=false", calls[2])

    def test_upload_failure_keeps_release_draft_and_retry_resumes_it(self):
        with patch.object(release, "api", side_effect=[REF, None]), patch.object(release, "gh") as gh:
            gh.side_effect = ["", RuntimeError("upload failed")]
            with self.assertRaises(RuntimeError):
                release.publish(TAG, SHA, self.root)
            self.assertEqual([call.args[1] for call in gh.call_args_list], ["create", "upload"])
        with patch.object(release, "api", side_effect=[REF, {"draft": True}]), patch.object(release, "gh") as gh:
            release.publish(TAG, SHA, self.root)
            self.assertEqual([call.args[1] for call in gh.call_args_list], ["upload", "edit"])

    def test_published_assets_are_never_overwritten(self):
        published = {"draft": False, "assets": [{"name": name, "state": "uploaded"} for name in release.ASSETS]}
        with patch.object(release, "api", side_effect=[REF, published]), patch.object(release, "gh") as gh:
            release.publish(TAG, SHA, self.root)
            gh.assert_not_called()
        published["assets"].pop()
        with patch.object(release, "api", side_effect=[REF, published]), patch.object(release, "gh") as gh:
            with self.assertRaises(ValueError):
                release.publish(TAG, SHA, self.root)
            gh.assert_not_called()


if __name__ == "__main__":
    unittest.main()
