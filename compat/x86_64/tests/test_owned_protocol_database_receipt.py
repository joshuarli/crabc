"""Focused contract tests for the fixed-musl protocol-database receipt."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_protocol_database as producer  # noqa: E402
import owned_protocol_database_receipt as receipt  # noqa: E402


class OwnedProtocolDatabaseReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        (ROOT / ".work").mkdir(exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="protocol-database-receipt.", dir=ROOT / ".work"))

    def tearDown(self) -> None:
        shutil.rmtree(self.work)

    def test_fixed_table_matrix_has_three_nonreused_six_mode_arms(self) -> None:
        matrix = producer.expected_executions()

        self.assertEqual(tuple(producer.ARMS), ("installed", "reproduction", "extracted"))
        self.assertEqual(tuple(producer.ENTRY_MODES), tuple(receipt.ENTRY_MODES))
        self.assertEqual(set(matrix), {"oracle", *{
            f"{arm}-{mode}" for arm in producer.ARMS for mode in producer.ENTRY_MODES
        }})
        self.assertEqual(len(matrix), 19)
        self.assertEqual(matrix["installed-dynamic-pie-direct"][1], ["/lib/ld-crabc-x86_64.so.1", "/workload"])

    def test_receipt_source_map_selects_proto_c_provider_not_system_parser(self) -> None:
        sources = producer.source_records()
        provider = (ROOT / producer.RUST_PROVIDER).read_text(encoding="utf-8")

        self.assertEqual(set(sources), {path.as_posix() for path in producer.SOURCE_FILES})
        self.assertIn("src/network/proto.c", provider)
        self.assertIn("PROTOCOLS", provider)
        self.assertNotIn("SYS_OPENAT", provider)

    def test_provider_projection_rejects_missing_or_undefined_proto_symbol(self) -> None:
        rows = b"\n".join(
            f"{index}: 0000000000000000 0 FUNC GLOBAL DEFAULT 1 {name}".encode()
            for index, name in enumerate(producer.PROVIDERS, start=1)
        ) + b"\n"
        self.assertEqual(set(producer.provider_rows(rows, "test provider")), set(producer.PROVIDERS))

        incomplete = rows.replace(b"getprotoent\n", b"")
        with self.assertRaisesRegex(producer.ProtocolDatabaseError, "lacks getprotoent"):
            producer.provider_rows(incomplete, "incomplete provider")
        undefined = rows.replace(b"DEFAULT 1 getprotoent", b"DEFAULT UND getprotoent")
        with self.assertRaisesRegex(producer.ProtocolDatabaseError, "invalid provider binding"):
            producer.provider_rows(undefined, "undefined provider")

    def test_reader_has_a_fixed_nonpromoting_component_identity(self) -> None:
        self.assertEqual(receipt.SCHEMA, "crabc.x86_64-owned-protocol-database-products/v1")
        self.assertEqual(receipt.COMPONENT, "protocol-database-product")
        self.assertEqual(receipt.REPORT_NAME, "owned-protocol-database-products.json")

    def test_pinned_musl_archive_path_normalizes_compiler_lexical_parent_components(self) -> None:
        raw = "/usr/lib/gcc/x86_64-alpine-linux-musl/15.2.0/../../../../lib/libc.a\n"

        self.assertEqual(
            producer.canonical_pinned_musl_archive(raw),
            Path("/usr/lib/libc.a"),
        )
        with self.assertRaisesRegex(producer.ProtocolDatabaseError, "relative path"):
            producer.canonical_pinned_musl_archive("lib/libc.a")

    def test_product_arms_admit_byte_identical_extraction_directory_modes(self) -> None:
        """Extraction may preserve setgid header directories without changing payload bytes."""

        class ProductFixture:
            @staticmethod
            def static_manifest(_root: Path) -> None:
                return None

            @staticmethod
            def dynamic_manifest(_root: Path) -> None:
                return None

            @staticmethod
            def receipt_tree_identity(root: Path) -> dict[str, object]:
                return producer.fixture_module().receipt_tree_identity(root)

        roots: dict[str, Path] = {}
        for arm in producer.ARMS:
            for kind in ("static", "dynamic"):
                root = self.work / f"{arm}-{kind}"
                (root / "share/crabc").mkdir(parents=True)
                (root / "usr/include").mkdir(parents=True)
                root.chmod(0o755)
                (root / "usr").chmod(0o755)
                (root / "usr/include").chmod(0o755)
                (root / "share/crabc/manifest.json").write_text("{}\n", encoding="utf-8")
                (root / "usr/include/netdb.h").write_text("fixed payload\n", encoding="utf-8")
                if arm == "extracted" and kind == "dynamic":
                    (root / "usr").chmod(0o2755)
                    (root / "usr/include").chmod(0o2755)
                roots[f"{arm}-{kind}"] = root

        products = producer._products(ProductFixture(), roots)

        self.assertEqual(
            products["installed"]["dynamic"]["payload_tree"],
            products["extracted"]["dynamic"]["payload_tree"],
        )
        self.assertNotEqual(
            products["installed"]["dynamic"]["physical_tree"],
            products["extracted"]["dynamic"]["physical_tree"],
        )

    def test_raw_replay_rejects_one_candidate_stream_that_differs_from_musl(self) -> None:
        entries: dict[str, object] = {}
        expected = producer.expected_executions()
        roots = {root: self.work for root, _argv in expected.values()}
        for label, (root, argv) in expected.items():
            directory = self.work / label
            directory.mkdir()
            argv_path = directory / "argv.json"
            status = directory / "status"
            stdout = directory / "stdout"
            stderr = directory / "stderr"
            argv_path.write_text(json.dumps(argv) + "\n", encoding="utf-8")
            status.write_bytes(b"0\n")
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            entries[label] = {
                "root": root,
                "argv": producer.artifact(ROOT, argv_path),
                "status": producer.artifact(ROOT, status),
                "stdout": producer.artifact(ROOT, stdout),
                "stderr": producer.artifact(ROOT, stderr),
            }

        receipt._executions(ROOT, entries, roots)
        drift = self.work / "installed-static-et-exec/stdout"
        drift.write_bytes(b"unexpected\n")
        entries["installed-static-et-exec"]["stdout"] = producer.artifact(ROOT, drift)  # type: ignore[index]
        with self.assertRaisesRegex(receipt.ReceiptError, "raw outcome differs"):
            receipt._executions(ROOT, entries, roots)


if __name__ == "__main__":
    unittest.main()
