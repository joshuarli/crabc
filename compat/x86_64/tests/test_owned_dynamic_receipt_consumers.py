#!/usr/bin/env python3
"""The remaining installed dynamic consumers accept only closed link receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_receipt as receipt_contract
RUNNERS = {
    "io-cancellation": (
        ROOT / "compat/x86_64/run_owned_dynamic_io_cancellation.sh",
        'python3 -B - "$ROOT" "$installed" "$mode" "$candidate" "$interpreter" <<\'PY\'\n',
    ),
    "process-control": (
        ROOT / "compat/x86_64/run_owned_process_control.sh",
        'python3 -B - "$ROOT" "$product" "$consumer" "$mode" "$object" "$receipt" <<\'PY\'\n',
    ),
    "driver-source-inputs": (
        ROOT / "compat/x86_64/run_owned_dynamic_driver_source_inputs.sh",
        'python3 -B - "$ROOT" "$work/export-main.crabc-link.json" "$work/export-main" <<\'PY\'\n',
    ),
    "syslog": (
        ROOT / "compat/x86_64/run_owned_syslog.sh",
        'python3 -B - "$ROOT" "$family" "$mode" "$candidate" "$receipt" "$candidate.provider-symbols" <<\'PY\'\n',
    ),
    "error-reporting": (
        ROOT / "compat/x86_64/run_owned_error_reporting.sh",
        'python3 -B - "$ROOT" "$family" "$mode" "$candidate" "$receipt" "$candidate.provider-symbols" <<\'PY\'\n',
    ),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwnedDynamicReceiptConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.product = self.work / "product"
        self.manifest = self.product / "share/crabc/manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_bytes(b"sealed installed product\n")
        self.candidate = self.work / "consumer"
        self.candidate.write_bytes(b"owned dynamic consumer\n")
        self.object = self.work / "workload.o"
        self.object.write_bytes(b"one installed workload object\n")
        self.provider = self.work / "provider-symbols"
        self.provider.write_text(
            "WEAK FUNC DEFAULT vsyslog\n"
            + "".join(f"FUNC GLOBAL DEFAULT 1 {name}\n" for name in (
                "perror", "err", "errx", "verr", "verrx", "warn", "warnx", "vwarn", "vwarnx",
            )),
            encoding="utf-8",
        )
        self.candidate.with_suffix(".header").write_text(
            "Machine: Advanced Micro Devices X86-64\nType: DYN\n", encoding="utf-8"
        )
        self.candidate.with_suffix(".segments").write_text(
            f"Requesting program interpreter: {INTERPRETER}]\n", encoding="utf-8"
        )
        self.candidate.with_suffix(".dynamic").write_text(
            " 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n", encoding="utf-8"
        )
        self.candidate.with_suffix(".symbols").write_text(
            "FUNC GLOBAL DEFAULT 1 closelog\n"
            "FUNC GLOBAL DEFAULT 1 openlog\n"
            "FUNC GLOBAL DEFAULT 1 setlogmask\n"
            "FUNC GLOBAL DEFAULT 1 syslog\n"
            "FUNC GLOBAL DEFAULT 1 vsyslog\n",
            encoding="utf-8",
        )
        self.receipt_path = Path(str(self.candidate) + ".crabc-link.json")

    @staticmethod
    def _block(runner: Path, anchor: str) -> str:
        source = runner.read_text(encoding="utf-8")
        start = source.index(anchor) + len(anchor)
        end = source.index("\nPY", start)
        return source[start:end]

    def _receipt(self, schema: int) -> dict[str, object]:
        runtime = sorted("usr/lib/" + name for name in (
            "Scrt1.o", "crabc-dynamic-attach.o", "crti.o", "libc.so", "libcrabc-builtins.a", "crtn.o",
        ))
        record: dict[str, object] = {
            "schema": schema,
            "format": FORMAT,
            "mode": "pie",
            "binding": "now",
            "runtime_imports": [],
            "application_runpath": "/usr/lib",
            "output_path": str(self.candidate.resolve()),
            "output_sha256": sha256(self.candidate),
            "manifest_sha256": sha256(self.manifest),
            "application_dsos": {},
            "owned_runtime_inputs": runtime,
            "input_receipts": [{"path": str(self.object), "sha256": sha256(self.object)}],
            "resolved_linker": {"path": "/owned/ld.lld", "sha256": "0" * 64},
            "link_command": ["/owned/ld.lld", "--export-dynamic"],
            "link_trace": [str(self.object)],
            "campaign_complete": False,
        }
        if schema == 2:
            record.update({
                "application_search_kind": "runpath",
                "application_rpath": None,
                "application_hash_style": "sysv",
            })
        return record

    def _transitive_receipt(self) -> dict[str, object]:
        """A schema-3 root/leaf closure with one actual linker DSO input.

        The direct root reaches the leaf through its own DT_NEEDED edge.  The
        leaf is still a receipt-bound application input, but it must never
        appear in the executable link command or LLD trace.
        """

        root = self.work / "libroot.so"
        leaf = self.work / "libleaf.so"
        root.write_bytes(b"root DSO bytes\n")
        leaf.write_bytes(b"leaf DSO bytes\n")
        base = self._receipt(2)
        records = [
            {"role": "linker-input", **entry}
            for entry in base["input_receipts"]  # type: ignore[index]
        ]
        records.extend((
            {
                "role": "direct-application-dso", "name": root.name,
                "path": str(root), "sha256": sha256(root),
            },
            {
                "role": "transitive-application-dso", "name": leaf.name,
                "path": str(leaf), "sha256": sha256(leaf),
            },
        ))
        return {
            **base,
            "schema": 3,
            "application_dsos": {root.name: sha256(root), leaf.name: sha256(leaf)},
            "application_dso_roles": {root.name: "direct", leaf.name: "transitive"},
            "application_dso_needed": {
                root.name: [leaf.name, "libc.so"],
                leaf.name: ["libc.so"],
            },
            "input_receipts": records,
            "link_command": ["/owned/ld.lld", "--export-dynamic", str(root)],
            "link_trace": [str(self.object), str(root)],
        }

    @staticmethod
    def _contract_failure(message: str) -> None:
        raise ValueError(message)

    def _run(self, label: str, receipt: dict[str, object]) -> subprocess.CompletedProcess[str]:
        runner, anchor = RUNNERS[label]
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        arguments = {
            "io-cancellation": [ROOT, self.product, "pie", self.candidate, INTERPRETER],
            "process-control": [ROOT, self.product, self.candidate, "pie", self.object, self.receipt_path],
            "driver-source-inputs": [ROOT, self.receipt_path, self.candidate],
            "syslog": [ROOT, "dynamic", "pie", self.candidate, self.receipt_path, self.provider],
            "error-reporting": [ROOT, "dynamic", "pie", self.candidate, self.receipt_path, self.provider],
        }[label]
        return subprocess.run(
            ["python3", "-B", "-c", self._block(runner, anchor), *(str(item) for item in arguments)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_schema_two_receipt_is_accepted_by_every_inline_dynamic_audit(self) -> None:
        for label in RUNNERS:
            with self.subTest(label=label):
                result = self._run(label, self._receipt(2))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_schema_one_receipt_remains_accepted_by_the_common_contract(self) -> None:
        for label in RUNNERS:
            with self.subTest(label=label):
                result = self._run(label, self._receipt(1))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_schema_three_closure_requires_explicit_reader_admission_and_typed_roles(self) -> None:
        receipt = self._transitive_receipt()
        with self.assertRaisesRegex(ValueError, "application DSO closure"):
            receipt_contract.validate(
                receipt, format=FORMAT, label="transitive receipt", fail=self._contract_failure,
            )
        contract = receipt_contract.validate(
            receipt, format=FORMAT, label="transitive receipt", fail=self._contract_failure,
            allow_application_dso_closure=True,
        )
        self.assertEqual(contract.schema, 3)

        cycle = json.loads(json.dumps(receipt))
        cycle["application_dso_needed"]["libleaf.so"] = ["libroot.so", "libc.so"]
        self.assertEqual(
            receipt_contract.validate(
                cycle, format=FORMAT, label="cyclic transitive receipt", fail=self._contract_failure,
                allow_application_dso_closure=True,
            ).schema,
            3,
        )

        for name in ("libc.so", "ld-crabc-x86_64.so.1", "ld-musl-x86_64.so.1"):
            with self.subTest(reserved_name=name):
                reserved = json.loads(json.dumps(receipt).replace("libroot.so", name))
                with self.assertRaisesRegex(ValueError, "reserved"):
                    receipt_contract.validate(
                        reserved, format=FORMAT, label="reserved transitive receipt",
                        fail=self._contract_failure, allow_application_dso_closure=True,
                    )

        forged = json.loads(json.dumps(receipt))
        forged["application_dso_roles"]["libleaf.so"] = "direct"
        with self.assertRaisesRegex(ValueError, "role"):
            receipt_contract.validate(
                forged, format=FORMAT, label="forged transitive receipt", fail=self._contract_failure,
                allow_application_dso_closure=True,
            )

        missing = json.loads(json.dumps(receipt))
        missing["application_dso_needed"]["libroot.so"][0] = "libmissing.so"
        with self.assertRaisesRegex(ValueError, "closure"):
            receipt_contract.validate(
                missing, format=FORMAT, label="missing transitive receipt", fail=self._contract_failure,
                allow_application_dso_closure=True,
            )

        unexpected = json.loads(json.dumps(receipt))
        unexpected["application_dsos"]["libextra.so"] = "c" * 64
        unexpected["application_dso_roles"]["libextra.so"] = "transitive"
        unexpected["application_dso_needed"]["libextra.so"] = ["libc.so"]
        unexpected["input_receipts"].append({
            "role": "transitive-application-dso", "name": "libextra.so",
            "path": str(self.work / "libextra.so"), "sha256": "c" * 64,
        })
        with self.assertRaisesRegex(ValueError, "unreachable"):
            receipt_contract.validate(
                unexpected, format=FORMAT, label="unexpected transitive receipt", fail=self._contract_failure,
                allow_application_dso_closure=True,
            )

    def test_inline_dynamic_audits_reject_unversioned_mixed_and_extra_receipts(self) -> None:
        valid = self._receipt(2)
        invalid = {
            "unversioned": {key: value for key, value in valid.items() if key != "schema"},
            "boolean-schema": {**valid, "schema": True},
            "schema-one-mixed": {**self._receipt(1), "application_search_kind": "runpath"},
            "schema-two-extra": {**valid, "unsealed_extra": True},
        }
        for label in RUNNERS:
            for description, receipt in invalid.items():
                with self.subTest(label=label, description=description):
                    result = self._run(label, receipt)
                    self.assertNotEqual(result.returncode, 0)

    def test_inline_dynamic_audits_reject_non_sysv_or_non_runpath_search_profiles(self) -> None:
        for description, changed in (
            ("gnu", {"application_hash_style": "gnu"}),
            ("rpath", {"application_search_kind": "rpath", "application_runpath": None,
                       "application_rpath": "/usr/lib"}),
        ):
            for label in RUNNERS:
                with self.subTest(label=label, description=description):
                    result = self._run(label, {**self._receipt(2), **changed})
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
