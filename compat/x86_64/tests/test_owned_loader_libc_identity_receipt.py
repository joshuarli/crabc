#!/usr/bin/env python3
"""Physical native-shadow receipt for copied-loader libc identity cases."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipt  # noqa: E402

RUNNER = "owned-loader-libc-identity"
EVIDENCE = re.compile(r"evidence: (/workspace/\.work/x86_64/tmp/owned-loader-libc-identity\.[^\s]+)")
LAYOUTS = {
    "copied-prefix-root-libc",
    "prefix-only-libc",
    "hardlink-one-identity",
    "two-distinct-libc-identities",
    "override-without-canonical-identity",
}


def evidence_file_command(path: Path, *command: str) -> None:
    work_root = ROOT / ".work/x86_64"
    relative = path.relative_to(work_root)
    if not relative.parts:
        raise ValueError("refusing to remove the work root")
    subprocess.run([
        "docker", "run", "--rm", "--network", "none",
        "--volume", f"{work_root}:/evidence",
        os.environ.get("CRABC_X86_64_CORE_IMAGE", "crabc-core-evidence:x86_64"),
        *command, f"/evidence/{relative.as_posix()}",
    ], check=True, capture_output=True, text=True, timeout=120)


class OwnedLoaderLibcIdentityReceiptTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_IDENTITY_DYNAMIC_SYSROOT"), "requires supplied native-shadow product")
    def test_runner_retains_executed_identity_cases_after_work_cleanup(self) -> None:
        latest = receipt.receipt_directory(ROOT, RUNNER)
        if latest.exists():
            evidence_file_command(latest, "rm", "-rf")
        with self.assertRaisesRegex(receipt.ReceiptError, "no receipt"):
            receipt.read_receipt(ROOT, RUNNER)

        completed = subprocess.run(
            [str(ROOT / "scripts/dev-x86_64.sh"), RUNNER, os.environ["CRABC_IDENTITY_DYNAMIC_SYSROOT"]],
            cwd=ROOT, capture_output=True, text=True, timeout=900,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        match = EVIDENCE.search(completed.stdout)
        self.assertIsNotNone(match, completed.stdout)
        work = ROOT / ".work/x86_64/tmp" / Path(match.group(1)).name
        self.assertTrue(work.is_dir() and not work.is_symlink())

        published = receipt.read_receipt(ROOT, RUNNER, case_prefix="pie-")
        self.assertEqual(published.parameters["ALLOCATOR_BACKEND"], "native-shadow")
        expected = {f"{mode}-{layout}" for mode in ("pie", "non-pie") for layout in LAYOUTS}
        self.assertEqual({case["id"] for case in published.cases}, expected | {"runner"})
        self.assertEqual({path.stem for path in work.glob("*.status")}, expected | {"runner"})
        self.assertTrue({
            "dynamic-loader", "dynamic-libc", "dynamic-loader-provenance",
            "dynamic-libc-provenance", "dynamic-manifest", "dynamic-product-state",
            "identity-source", "pie-copied-prefix-root-libc-prefix-lib-loader",
            "non-pie-two-distinct-libc-identities-consumer-mutated",
            "pie-override-without-canonical-identity-override-libc.so",
        } <= set(published.products))
        for case in published.cases:
            if case["id"] == "runner":
                continue
            expected_status = 127 if case["id"].endswith((
                "two-distinct-libc-identities", "override-without-canonical-identity",
            )) else 0
            self.assertEqual((work / f"{case['id']}.status").read_text(), f"{expected_status}\n")

        evidence_file_command(work, "rm", "-rf")
        self.assertFalse(work.exists())
        receipt.read_receipt(ROOT, RUNNER, case_prefix="non-pie-")
        with self.assertRaisesRegex(receipt.ReceiptError, "receipt seals"):
            receipt.read_receipt(ROOT, RUNNER, seal={"revision": "0" * 40, "worktree_sha256": "0" * 64})
        for case_id in expected:
            logs = latest / "logs"
            actual = int((logs / f"{case_id}.status").read_text())
            self.assertIn(f"prefix/lib/loader", (logs / f"{case_id}.identity").read_text())
            if actual == 0:
                self.assertEqual((logs / f"{case_id}.stdout").read_bytes(),
                                 (logs / f"{case_id}.expected.stdout").read_bytes())
                self.assertEqual((logs / f"{case_id}.stderr").read_bytes(), b"")
            else:
                self.assertEqual(actual, 127)
                self.assertEqual((logs / f"{case_id}.stdout").read_bytes(), b"")
                self.assertEqual((logs / f"{case_id}.stderr").read_bytes(),
                                 (logs / "expected-libcidentity.stderr").read_bytes())
        retained = latest / "products/pie-copied-prefix-root-libc-prefix-lib-loader"
        evidence_file_command(retained, "chmod", "a+rw")
        original = retained.read_bytes()
        retained.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        retained.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)
        log = latest / "logs/pie-two-distinct-libc-identities.status"
        evidence_file_command(log, "chmod", "a+rw")
        original = log.read_bytes()
        log.write_bytes(b"0\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        log.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)


if __name__ == "__main__":
    unittest.main()
