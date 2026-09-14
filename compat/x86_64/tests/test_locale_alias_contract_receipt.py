#!/usr/bin/env python3
"""Process-free controls for retained locale/time alias receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import locale_alias_contract_receipt as receipt


class LocaleAliasContractReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/locale-alias-contract-receipt-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="receipt-", dir=scratch))
        self.addCleanup(shutil.rmtree, self.root)

    @staticmethod
    def digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def write(self, relative: str, value: bytes) -> dict[str, object]:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return {
            "path": relative,
            "bytes": len(value),
            "sha256": self.digest(value),
        }

    def fixed_command(self) -> dict[str, object]:
        return {
            "schema": receipt.COMMAND_SCHEMA,
            "role": "compile",
            "cwd": "/workspace",
            "argv": ["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            "status": 0,
            "stdout": self.write("raw/compile.stdout", b""),
            "stderr": self.write("raw/compile.stderr", b""),
            "status_stream": self.write("raw/compile.status", b"0\n"),
        }

    def test_retained_command_requires_exact_argv_and_all_raw_streams(self) -> None:
        record = self.fixed_command()
        receipt.validate_command_record(
            self.root,
            record,
            role="compile",
            cwd="/workspace",
            argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
        )

        (self.root / "raw/compile.stdout").unlink()
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "stdout"):
            receipt.validate_command_record(
                self.root,
                record,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            )

        self.write("raw/compile.stdout", b"")
        forged = json.loads(json.dumps(record))
        forged["argv"][-1] = "--forged"
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "argv"):
            receipt.validate_command_record(
                self.root,
                forged,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            )

    def test_source_records_bind_current_bytes_not_only_claimed_hashes(self) -> None:
        source = self.root / "source/owned_calendar.rs"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"#[export_name = \"__asctime_r\"]\n")
        records = receipt.source_records(self.root, ("source/owned_calendar.rs",))
        receipt.validate_source_records(self.root, records)

        source.write_bytes(b"#[export_name = \"__forged___\"]\n")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "source bytes"):
            receipt.validate_source_records(self.root, records)

    def test_source_contract_keeps_the_full_roster_and_hidden_time_boundary(self) -> None:
        for relative in (receipt.CONTRACT_PATH, *receipt.IMPLEMENTATION_SOURCES):
            source = ROOT / relative
            copied = self.root / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        observed = receipt.validate_source_contract(self.root)
        self.assertEqual((observed["visible_pairs"], observed["hidden_pairs"]), (43, 4))
        self.assertFalse(observed["wcsftime_l_in_contract"])

        timezone = self.root / "libc/src/c_abi/x86_64/owned_timezone.rs"
        timezone.write_text(timezone.read_text(encoding="utf-8").replace('fn refresh_tzset()', 'fn forged_refresh()'), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "tzset boundary"):
            receipt.validate_source_contract(self.root)

    def test_runner_plan_is_the_closed_35_command_normal_consumer_matrix(self) -> None:
        plan = receipt._runner_plan(".work/x86_64/locale-alias-contract-receipt")
        self.assertEqual([role for role, _argv in plan], list(receipt.RUNNER_STEMS))
        self.assertEqual(len(plan), 35)
        self.assertEqual(plan[0][1][-2:], ["-o", "/workspace/.work/x86_64/locale-alias-contract-receipt/tmp/runner/probe.o"])
        self.assertNotIn("wcsftime_l", "\n".join(argument for _role, argv in plan for argument in argv))

    def test_validate_report_entry_joins_every_required_retained_relation(self) -> None:
        report_root = Path(tempfile.mkdtemp(prefix="report-", dir=ROOT / ".work/x86_64"))
        self.addCleanup(shutil.rmtree, report_root)
        report = {
            "schema": receipt.SCHEMA,
            "status": receipt.STATUS,
            "oracle": {"oracle": "ok"},
            "source_before": {"source": "same"},
            "source_after": {"source": "same"},
            "source_contract": {"contract": "ok"},
            "products": {"products": "ok"},
            "collector_commands": [{"collector": "ok"}],
            "runner_commands": [{"runner": "ok"}],
            "snapshots": {"before": {"records": ["same"]}, "after": {"records": ["same"]}},
            "artifacts": {"object": "ok"},
            "runtime": {"runtime": "ok"},
            "symbols": {"symbols": "ok"},
            "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with mock.patch.object(receipt, "_validate_source_seal", return_value=[{"source": "ok"}]) as source_seal, \
             mock.patch.object(receipt, "validate_source_contract", return_value={"contract": "ok"}) as source_contract, \
             mock.patch.object(receipt, "_oracle_records", return_value={"oracle": "ok"}) as oracle, \
             mock.patch.object(receipt, "_validate_products", return_value={"products": "ok"}) as products, \
             mock.patch.object(receipt, "_validate_collector_commands", return_value=[{"collector": "ok"}]) as collector, \
             mock.patch.object(receipt, "_runner_records", return_value=[{"runner": "ok"}]) as runner, \
             mock.patch.object(receipt, "_validate_artifacts", return_value={"object": "ok"}) as artifacts, \
             mock.patch.object(receipt, "_validate_snapshot", side_effect=lambda _root, value, _name: value) as snapshots, \
             mock.patch.object(receipt, "_validate_runtime_and_headers", return_value={"runtime": "ok"}) as runtime, \
             mock.patch.object(receipt, "_validate_symbol_observation", return_value={"symbols": "ok"}) as symbols:
            admitted = receipt.validate_report(ROOT, report_path)

        self.assertEqual(admitted["status"], receipt.STATUS)
        for boundary in (source_seal, source_contract, oracle, products, collector, runner, artifacts, snapshots, runtime, symbols):
            self.assertGreaterEqual(boundary.call_count, 1)

        malformed = dict(report)
        malformed.pop("artifacts")
        report_path.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "fields changed"):
            receipt.validate_report(ROOT, report_path)


class LocaleAliasRunnerRetentionTests(unittest.TestCase):
    def test_runner_accepts_a_fresh_explicit_receipt_directory_and_records_cwd(self) -> None:
        runner = (ROOT / "compat/x86_64/run_locale_alias_contract.sh").read_text(encoding="utf-8")
        self.assertIn("--receipt-dir", runner)
        self.assertIn('"$work/$stem.cwd"', runner)
        self.assertIn("receipt directory must be below checkout-local TMPDIR", runner)


if __name__ == "__main__":
    unittest.main()
