#!/usr/bin/env python3
"""Regression boundaries for the installed credential-setter profile."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "compat/x86_64/owned_credentials_profile_probe.c"
RUNNER = ROOT / "compat/x86_64/run_owned_credentials_profile.sh"


class OwnedCredentialsProfileTests(unittest.TestCase):
    def test_direct_setters_use_valid_current_ids_and_retain_raw_transcripts(self) -> None:
        source = PROBE.read_text(encoding="utf-8")

        self.assertIn("gid_t groups[1] = { before->effective_gid };", source)
        self.assertIn("result->status = setgroups(1, groups);", source)
        self.assertNotIn("setgroups((size_t)-1, NULL)", source)
        self.assertIn("result->status == -1 && result->error == EPERM", source)
        for name, call in (
            ("setresuid-current", "setresuid(before->real_uid, before->effective_uid,"),
            ("setresgid-current", "setresgid(before->real_gid, before->effective_gid,"),
            ("setuid-current", "setuid(before->effective_uid)"),
            ("setgid-current", "setgid(before->effective_gid)"),
        ):
            self.assertIn(name, source)
            self.assertIn(call, source)
        self.assertIn("status=%d errno=%d", source)
        self.assertIn("before=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu", source)
        self.assertIn("after=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu", source)
        self.assertIn("ids=unchanged", source)
        self.assertIn("fflush(stdout)", source)

    def test_runner_validates_raw_transcripts_and_every_linked_product(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        self.assertIn("validate_transcript", source)
        self.assertIn("aliases-profile", source)
        self.assertIn("--link-receipt", source)
        self.assertIn("owned_posix_product_evidence", source)
        self.assertIn("validate_link", source)


if __name__ == "__main__":
    unittest.main()
