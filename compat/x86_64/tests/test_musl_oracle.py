from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("native_musl_pin_test", ROOT / "compat/x86_64/musl_oracle.py")
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class NativeMuslOracleTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / ".work/tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pin = ORACLE.load_pin(ROOT / "compat/upstreams.toml")

    def archive(self, name=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for path, contents, mode in (("VERSION", b"1.2.6\n", 0o644), ("configure", b"#!/bin/sh\n", 0o755)):
                entry = tarfile.TarInfo((name or f"musl-{self.pin['fallback_revision']}") + "/" + path)
                entry.size = len(contents)
                entry.mode = mode
                archive.addfile(entry, io.BytesIO(contents))
        data = output.getvalue()
        self.pin["sha256"] = hashlib.sha256(data).hexdigest()
        return data

    def test_snapshot_fetch_normalizes_exact_archive_root_and_retains_marker(self):
        data = self.archive()
        destination = self.root / "source"
        def fetch(args, **kwargs):
            self.assertEqual(args[-1], self.pin["source"])
            Path(args[args.index("--output") + 1]).write_bytes(data)
            return subprocess.CompletedProcess(args, 0)
        with patch.object(ORACLE.subprocess, "run", side_effect=fetch) as run:
            ORACLE.acquire_source(self.pin, destination)
        self.assertEqual(run.call_count, 1)
        self.assertEqual((destination / "VERSION").read_bytes(), b"1.2.6\n")
        self.assertEqual((destination / "configure").stat().st_mode & 0o777, 0o755)
        self.assertEqual((destination / ".crabc-oracle").read_text(), ORACLE.manifest(self.pin))
        self.assertFalse(destination.with_name("source.tar.gz").exists())

    def test_bad_archive_checksum_never_uses_git_fallback(self):
        def fetch(args, **kwargs):
            Path(args[args.index("--output") + 1]).write_bytes(b"stale archive")
            return subprocess.CompletedProcess(args, 0)
        with patch.object(ORACLE.subprocess, "run", side_effect=fetch) as run:
            with self.assertRaisesRegex(ValueError, "digest differs"):
                ORACLE.acquire_source(self.pin, self.root / "source")
        self.assertEqual(run.call_count, 1)
        self.assertFalse((self.root / "source").exists())

    def test_git_fallback_fetches_exact_commit_and_rejects_other_checkout(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 22 if args[0] == "curl" else 0)
        with patch.object(ORACLE.subprocess, "run", side_effect=command), patch.object(
                ORACLE.subprocess, "check_output", return_value="0" * 40 + "\n"):
            with self.assertRaisesRegex(ValueError, "checkout revision differs"):
                ORACLE.acquire_source(self.pin, self.root / "source")
        self.assertEqual(calls[2][-4:], ["--depth", "1", self.pin["fallback_repository"], self.pin["fallback_revision"]])
        self.assertEqual(calls[3][-3:], ["checkout", "--detach", "FETCH_HEAD"])

    def test_git_fallback_accepts_only_verified_commit_and_emits_same_marker(self):
        destination = self.root / "source"
        def command(args, **kwargs):
            if args[0] == "curl":
                return subprocess.CompletedProcess(args, 22)
            if args[1] == "init":
                destination.mkdir()
                (destination / ".git").mkdir()
                (destination / "VERSION").write_text("1.2.6\n")
            return subprocess.CompletedProcess(args, 0)
        with patch.object(ORACLE.subprocess, "run", side_effect=command), patch.object(
                ORACLE.subprocess, "check_output", return_value=self.pin["fallback_revision"] + "\n"):
            ORACLE.acquire_source(self.pin, destination)
        self.assertEqual((destination / ".crabc-oracle").read_text(), ORACLE.manifest(self.pin))
        self.assertFalse((destination / ".git").exists())

    def test_archive_rejects_wrong_root_and_traversal_before_extraction(self):
        for root in ("musl-1.2.6", f"musl-{self.pin['fallback_revision']}/../escape", "/absolute"):
            with self.subTest(root=root):
                data = self.archive(root)
                archive = self.root / "archive.tar.gz"
                archive.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "archive root differs"):
                    ORACLE.extract_archive(archive, self.root / "source", self.pin)
                self.assertFalse((self.root / "source").exists())

    def test_missing_native_pin_cannot_select_release(self):
        path = self.root / "pins.toml"
        path.write_text('[musl]\nversion = "1.2.6"\n')
        with self.assertRaises(KeyError):
            ORACLE.load_pin(path)

    def test_live_pthread_receipts_reject_release_oracle_commit(self):
        import importlib
        import tomllib
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        release = tomllib.loads((ROOT / "compat/upstreams.toml").read_text())["musl"]
        oracle = {"release": "musl-" + release["version"], "source_commit": release["fallback_revision"],
                  "compiler": "retained/oracle/compiler-wrapper", "shared": "retained/oracle/libc.so",
                  "archive": "retained/oracle/libc.a"}
        for name in ("owned_pthread_alias_contract_reader", "owned_pthread_timed_feature_contract_reader"):
            with self.subTest(reader=name):
                reader = importlib.import_module(name)
                with self.assertRaisesRegex(reader.ReceiptError, "pinned musl oracle identity changed"):
                    reader._validate_oracle(self.root, oracle, {}, {})

    def test_live_syscall_receipt_rejects_release_oracle_commit(self):
        import tomllib
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        import owned_syscall_alias_contract_reader as reader
        release = tomllib.loads((ROOT / "compat/upstreams.toml").read_text())["musl"]
        report = {"schema": reader.SCHEMA, "status": reader.STATUS, "image": reader.IMAGE,
                  "musl_source_commit": release["fallback_revision"]}
        path = self.root / "report.json"
        import json
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(reader.ReceiptError, "schema/status/image differs"):
            reader.validate_report(path)

    def test_pin_rejects_moving_archive_and_unknown_fields(self):
        for field, value in (("source", "https://codeload.github.com/ifduyue/musl/tar.gz/master"),
                             ("unknown", "value")):
            pin = dict(self.pin, **{field: value})
            path = self.root / "pins.toml"
            path.write_text("[musl_native]\n" + "".join(f'{key} = "{item}"\n' for key, item in pin.items()))
            with self.assertRaises(ValueError):
                ORACLE.load_pin(path)


if __name__ == "__main__":
    unittest.main()
