#!/usr/bin/env python3
"""Physical native-shadow receipt for copied-loader libc identity cases."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipt  # noqa: E402
import owned_loader_libc_identity_receipt as identity_receipt  # noqa: E402

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
        identity_receipt.read_identity_receipt(ROOT)
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

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            document["cases"] = [case for case in document["cases"]
                                 if case["id"] != "pie-hardlink-one-identity"]
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "missing identity cases"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            case_id = "pie-prefix-only-libc"
            identity = copied / "logs" / f"{case_id}.identity"
            lines = identity.read_text().splitlines()
            root_line = next(line for line in lines if line.split(" dev=")[0].endswith(
                f"/{case_id}/usr/lib/libc.so"))
            prefix_line = next(line for line in lines if line.split(" dev=")[0].endswith(
                f"/{case_id}/prefix/usr/lib/libc.so"))
            root_id = root_line.split(" dev=")[1].split(" size=")[0]
            prefix_id = prefix_line.split(" dev=")[1].split(" size=")[0]
            self.assertNotEqual(root_id, prefix_id)
            lines[lines.index(prefix_line)] = prefix_line.replace(f" dev={prefix_id} size=",
                                                                   f" dev={root_id} size=")
            changed = ("\n".join(lines) + "\n").encode()
            identity.write_bytes(changed)
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            case = next(case for case in document["cases"] if case["id"] == case_id)
            case["logs"][f"{case_id}.identity"] = {
                "sha256": hashlib.sha256(changed).hexdigest(), "size": len(changed),
            }
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "alias identity"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            case_id = "pie-copied-prefix-root-libc"
            log_name = f"{case_id}.stdout"
            changed = (copied / "logs" / log_name).read_bytes().replace(
                b"identity libc /usr/lib/libc.so", b"identity libc /prefix/usr/lib/libc.so")
            (copied / "logs" / log_name).write_bytes(changed)
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            case = next(case for case in document["cases"] if case["id"] == case_id)
            case["logs"][log_name] = {"sha256": hashlib.sha256(changed).hexdigest(), "size": len(changed)}
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "wrong successful transcript"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            state_file = copied / "products/dynamic-product-state"
            state = json.loads(state_file.read_text())
            state["payload_files"]["lib/ld-crabc-x86_64.so.1"] = "0" * 64
            changed = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
            state_file.write_bytes(changed)
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            document["products"]["dynamic-product-state"] = {
                "sha256": hashlib.sha256(changed).hexdigest(), "size": len(changed),
            }
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "product provenance"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            case_id = "non-pie-hardlink-one-identity"
            product_name = f"{case_id}-executed-program"
            changed = (copied / "products" / f"{case_id}-plugins-libcli.so").read_bytes()
            (copied / "products" / product_name).write_bytes(changed)
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            document["products"][product_name] = {
                "sha256": hashlib.sha256(changed).hexdigest(), "size": len(changed),
            }
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "executed fixture"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            source = copied / "products/identity-source"
            changed = source.read_bytes().replace(b"identity application main 17",
                                                  b"identity application main 16")
            self.assertNotEqual(changed, source.read_bytes())
            source.write_bytes(changed)
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            document["products"]["identity-source"] = {
                "sha256": hashlib.sha256(changed).hexdigest(), "size": len(changed),
            }
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "fixture source differs"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)

        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64/tmp") as temporary:
            copied_root = Path(temporary)
            copied = receipt.receipt_directory(copied_root, RUNNER)
            copied.parent.mkdir(parents=True)
            shutil.copytree(latest, copied)
            case_id = "non-pie-copied-prefix-root-libc"
            changed = (copied / "products/pie-copied-prefix-root-libc-consumer").read_bytes()
            report = copied / "receipt.json"
            document = json.loads(report.read_text())
            for name in (f"{case_id}-consumer", f"{case_id}-executed-program"):
                (copied / "products" / name).write_bytes(changed)
                document["products"][name] = {
                    "sha256": hashlib.sha256(changed).hexdigest(), "size": len(changed),
                }
            identity = copied / "logs" / f"{case_id}.identity"
            lines = identity.read_text().splitlines()
            consumer = next(line for line in lines if line.split(" dev=")[0].endswith(
                f"/{case_id}/consumer"))
            lines[lines.index(consumer)] = consumer.rsplit(" size=", 1)[0] + f" size={len(changed)}"
            changed_identity = ("\n".join(lines) + "\n").encode()
            identity.write_bytes(changed_identity)
            case = next(case for case in document["cases"] if case["id"] == case_id)
            case["logs"][f"{case_id}.identity"] = {
                "sha256": hashlib.sha256(changed_identity).hexdigest(), "size": len(changed_identity),
            }
            report.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            receipt.read_receipt(copied_root, RUNNER, seal=published.source)
            with self.assertRaisesRegex(receipt.ReceiptError, "consumer ELF entry mode"):
                identity_receipt.read_identity_receipt(copied_root, seal=published.source)


if __name__ == "__main__":
    unittest.main()
