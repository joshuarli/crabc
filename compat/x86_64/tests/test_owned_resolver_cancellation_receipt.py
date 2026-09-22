"""Focused contract tests for the public resolver-cancellation receipt reader."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_resolver_cancellation as cancellation  # noqa: E402
import owned_resolver_cancellation_receipt as receipt  # noqa: E402
from owned_dynamic_qualification import source_digest  # noqa: E402


class FakeFixture:
    """Exercise receipt wiring without turning this reader test into a linker test."""

    @staticmethod
    def tree_identity(path: Path) -> dict[str, object]:
        value = sha256()
        entries = 0
        for item in sorted(path.rglob("*")):
            if item.is_dir():
                continue
            entries += 1
            value.update(item.relative_to(path).as_posix().encode("utf-8") + b"\0")
            value.update(item.read_bytes())
        return {"entry_count": entries, "sha256": value.hexdigest()}

    @staticmethod
    def static_receipt_audit(_product: Path, mode: str, object_file: Path, output: Path,
                             link_receipt: Path) -> dict[str, object]:
        return {"mode": mode, "object": receipt.digest(object_file), "output": receipt.digest(output),
                "link_receipt": receipt.digest(link_receipt)}

    @staticmethod
    def dynamic_receipt_audit(_product: Path, mode: str, object_file: Path, output: Path,
                              link_receipt: Path) -> dict[str, object]:
        return {"mode": mode, "object": receipt.digest(object_file), "output": receipt.digest(output),
                "link_receipt": receipt.digest(link_receipt)}

    @staticmethod
    def elf_audit(output: Path, *, mode: str, dynamic: bool) -> dict[str, object]:
        return {"mode": mode, "dynamic": dynamic, "output": receipt.digest(output)}


class OwnedResolverCancellationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.parent = Path(tempfile.mkdtemp(prefix="resolver-cancellation-receipt.", dir=ROOT / ".work"))
        self.work = self.parent / "receipt"
        self.static = self.parent / "static"
        self.dynamic = self.parent / "dynamic"
        self.work.mkdir()
        self.static.mkdir()
        (self.dynamic / "usr/lib").mkdir(parents=True)
        (self.static / "product").write_bytes(b"static product\n")
        (self.dynamic / "product").write_bytes(b"dynamic product\n")
        (self.dynamic / "usr/lib/libc.so").write_bytes(b"dynamic libc\n")
        self.fixture = FakeFixture()
        self._write_complete_receipt()

    def tearDown(self) -> None:
        shutil.rmtree(self.parent)

    def _write(self, name: str, contents: bytes) -> None:
        (self.work / name).write_bytes(contents)

    @staticmethod
    def _observation(**changes: int) -> bytes:
        values = {
            "canceled": 0,
            "returned": 0,
            "cleanup": 0,
            "cleanup_fds": 0,
            "leaked": 0,
            "state": 0,
            "transmitted": 0,
            "success": 0,
            "errno": 0,
        }
        values.update(changes)
        return (" ".join(f"{key}={value}" for key, value in values.items()) + "\n").encode("ascii")

    def _audit_artifacts(self) -> dict[str, object]:
        result: dict[str, object] = {}
        object_file = self.work / "workload.o"
        for label, mode, elf_mode in receipt.STATIC_ARTIFACTS:
            output = self.work / label
            link = self.work / (label + ".receipt.json")
            result[label] = {
                "receipt": self.fixture.static_receipt_audit(self.static, mode, object_file, output, link),
                "elf": self.fixture.elf_audit(output, mode=elf_mode, dynamic=False),
            }
        for label, mode, elf_mode in receipt.DYNAMIC_ARTIFACTS:
            output = self.work / label
            link = self.work / (label + ".crabc-link.json")
            result[label] = {
                "receipt": self.fixture.dynamic_receipt_audit(self.dynamic, mode, object_file, output, link),
                "elf": self.fixture.elf_audit(output, mode=elf_mode, dynamic=True),
            }
        return result

    def _write_complete_receipt(self) -> None:
        self._write("workload.o", b"same application object\n")
        self._write("oracle", b"oracle\n")
        for label, _mode, _elf_mode in receipt.STATIC_ARTIFACTS:
            self._write(label, (label + " binary\n").encode())
            self._write(label + ".receipt.json", (label + " receipt\n").encode())
        for label, _mode, _elf_mode in receipt.DYNAMIC_ARTIFACTS:
            self._write(label, (label + " binary\n").encode())
            self._write(label + ".crabc-link.json", (label + " receipt\n").encode())
        audit = {
            "source_sha256": receipt._source_digest(ROOT),
            "source": receipt.artifact_record(ROOT / receipt.SOURCE),
            "object": receipt.artifact_record(self.work / "workload.o"),
            "products": {"static": self.fixture.tree_identity(self.static), "dynamic": self.fixture.tree_identity(self.dynamic)},
            "artifacts": self._audit_artifacts(),
        }
        self._write(receipt.ARTIFACT_AUDIT, json.dumps(audit, sort_keys=True).encode())
        isolation = {
            "interfaces": ["lo"],
            "network_namespace": "net:[101]",
            "user_namespace": "user:[202]",
            "loopback_up": True,
            "isolation": "docker-network-none",
            "parent_network_namespace": "net:[100]",
        }
        self._write(receipt.NETWORK_ISOLATION, json.dumps(isolation).encode())
        transition = self._observation(**receipt.TRANSITION_OBSERVATION)
        self._write("oracle-fastopen-transition.stdout", transition)
        self._write("oracle-fastopen-transition.stderr",
                    b"tcp-fastopen-option state=1\ntcp-sendmsg fastopen=1 state=1\ntcp-sendmsg fastopen=0 state=0\n")
        self._write("oracle-connect-transition.stdout", transition)
        self._write("oracle-connect-transition.stderr",
                    b"tcp-fastopen-option state=1\ntcp-connect state=1\ntcp-sendmsg fastopen=0 state=0\n")
        for entry in receipt.ENTRY_LABELS:
            for api, scenario in cancellation.CASES:
                label = f"{entry}-{api}-{scenario}"
                errno = 11 if (api, scenario) in cancellation.SOURCE_LATER_ERRNOS else 0
                self._write(label + ".stdout", self._observation(errno=errno))
                self._write(label + ".stderr", b"")
        self._write(receipt.STATUS, json.dumps(receipt._expected_status(cancellation)).encode())
        self._write(receipt.ORDINARY_DIFFERENCES, b"[]")
        self._write(receipt.SOURCE_LATER_DIFFERENCES, b"[]")

    def _validate(self) -> dict[str, object]:
        with patch.object(receipt, "_fixture", return_value=self.fixture), \
             patch.object(receipt, "_replay_provider_symbols") as providers:
            result = receipt.validate_report(ROOT, self.work, static_product=self.static, dynamic_product=self.dynamic)
        providers.assert_called_once_with(self.work, self.dynamic, cancellation)
        return result

    def test_complete_raw_matrix_replays_only_with_same_source_and_products(self) -> None:
        report = self._validate()

        self.assertEqual(report["schema"], receipt.SCHEMA)
        self.assertEqual(report["entry_modes"], list(receipt.ENTRY_MODES))
        self.assertEqual(report["case_count"], len(cancellation.CASES))
        self.assertEqual(report["execution_count"], len(cancellation.CASES) * len(receipt.ENTRY_LABELS))
        self.assertEqual(report["ordinary_errno_differences"], [])
        self.assertEqual(report["source_later_errno_differences"], [])

    def test_source_digest_matches_the_cancellation_producer(self) -> None:
        self.assertEqual(receipt._source_digest(ROOT), source_digest())

    def test_rejects_missing_status_cell_before_accepting_raw_outputs(self) -> None:
        status = receipt._expected_status(cancellation)
        self._write(receipt.STATUS, json.dumps(status[:-1]).encode())

        with patch.object(receipt, "_fixture", return_value=self.fixture), \
             patch.object(receipt, "_replay_provider_symbols"):
            with self.assertRaisesRegex(receipt.ReceiptError, "execution status matrix differs"):
                receipt.validate_report(ROOT, self.work, static_product=self.static, dynamic_product=self.dynamic)

    def test_rejects_a_product_that_differs_from_the_raw_driver_and_elf_audits(self) -> None:
        (self.static / "product").write_bytes(b"substituted static product\n")

        with patch.object(receipt, "_fixture", return_value=self.fixture), \
             patch.object(receipt, "_replay_provider_symbols"):
            with self.assertRaisesRegex(receipt.ReceiptError, "installed product tree differs"):
                receipt.validate_report(ROOT, self.work, static_product=self.static, dynamic_product=self.dynamic)

    def test_rejects_lifecycle_drift_even_when_candidate_exit_status_is_zero(self) -> None:
        label = "static-et-exec-query-udp.stdout"
        self._write(label, self._observation(cleanup=1))

        with patch.object(receipt, "_fixture", return_value=self.fixture), \
             patch.object(receipt, "_replay_provider_symbols"):
            with self.assertRaisesRegex(receipt.ReceiptError, "cancellation observation differs"):
                receipt.validate_report(ROOT, self.work, static_product=self.static, dynamic_product=self.dynamic)

    def test_provider_rows_reject_duplicate_or_undefined_provider(self) -> None:
        rows = b"\n".join(
            f"{index}: 0000000000000000 0 FUNC GLOBAL DEFAULT 1 {name}".encode()
            for index, name in enumerate(sorted(cancellation.PROVIDERS), start=1)
        ) + b"\n"
        self.assertEqual(set(receipt._provider_rows(rows, cancellation.PROVIDERS)), cancellation.PROVIDERS)

        duplicate = rows + b"9: 0000000000000000 0 FUNC GLOBAL DEFAULT 1 res_query\n"
        with self.assertRaisesRegex(receipt.ReceiptError, "duplicates res_query"):
            receipt._provider_rows(duplicate, cancellation.PROVIDERS)


if __name__ == "__main__":
    unittest.main()
