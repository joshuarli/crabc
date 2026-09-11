#!/usr/bin/env python3
"""The loader/corpus retained-reader boundary rejects incomplete receipts."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import owned_loader_corpus_evidence as evidence


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwnedLoaderCorpusEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        parent = ROOT / ".work/x86_64/tmp"
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.product = self.work / "product"
        self._make_product()

    def _put(self, relative: str, contents: bytes, *, executable: bool = False) -> Path:
        path = self.product / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        if executable:
            path.chmod(0o755)
        return path

    def _make_product(self) -> None:
        product_contract = evidence._product_reader()
        for relative in product_contract.DYNAMIC_REQUIRED:
            self._put(relative, ("sealed " + relative + "\n").encode(), executable=relative == "bin/crabc-cc-dynamic")
        (self.product / "usr/include").mkdir(parents=True)
        alias = self.product / "lib/ld-musl-x86_64.so.1"
        alias.symlink_to("ld-crabc-x86_64.so.1")
        files = {
            path.relative_to(self.product).as_posix(): sha256(path)
            for path in self.product.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        manifest = {
            "schema": 1,
            "format": product_contract.DYNAMIC_PRODUCT_FORMAT,
            "target": product_contract.TARGET,
            "files": files,
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        manifest_path = self.product / "share/crabc/manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    def _loader_report(self) -> Path:
        report_root = self.work / "loader"
        report_root.mkdir()
        cases: dict[str, dict[str, object]] = {}
        oracle_runtime = b"pinned musl runtime\n"
        for case in evidence.LOADER_CASES:
            raw = report_root / "cases" / case / "raw"
            raw.mkdir(parents=True)
            observation = {
                "argv": ["/usr/sbin/chroot", "/root", "/case"],
                "returncode": 0,
                "stdout_hex": "6f6b0a",
                "stderr_hex": "",
                "timed_out": False,
            }
            raw_record = {"cwd": str(report_root), "environment": {}, **observation}
            for index in range(1, 4):
                stem = f"{index:04d}-observation"
                (raw / (stem + ".stdout")).write_bytes(bytes.fromhex(observation["stdout_hex"]))
                (raw / (stem + ".stderr")).write_bytes(b"")
                (raw / (stem + ".json")).write_text(json.dumps(raw_record), encoding="utf-8")
            oracle_root = raw.parent / "oracle-root"
            (oracle_root / "lib").mkdir(parents=True)
            (oracle_root / "usr/lib").mkdir(parents=True)
            (oracle_root / "lib/ld-musl-x86_64.so.1").write_bytes(oracle_runtime)
            (oracle_root / "usr/lib/libc.so").write_bytes(oracle_runtime)
            candidate_root = raw.parent / "candidate-root"
            shutil.copytree(self.product, candidate_root, symlinks=True)
            value = {
                "status": "pass",
                "result": "pass",
                "raw_directory": evidence.recorded_path(ROOT, "/workspace", raw),
                "execution_roots": {
                    "oracle": evidence.loader_tree_seal(oracle_root),
                    "candidate": evidence.loader_tree_seal(candidate_root),
                },
                "behavior": {"oracle": observation, "candidate": dict(observation), "candidate_direct": dict(observation)},
            }
            (raw.parent / "case.json").write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            cases[case] = value
        source = evidence.current_loader_source(ROOT)
        product_seal = evidence.loader_tree_seal(self.product)
        oracle = {
            "compiler": "/opt/musl-1.2.6/bin/musl-gcc",
            "compiler_sha256": "a" * 64,
            "libc": "/opt/musl-1.2.6/lib/libc.so",
            "libc_sha256": hashlib.sha256(oracle_runtime).hexdigest(),
        }
        report = {
            "schema": 1,
            "runner": "compat/ldso/run_x86.py",
            "architecture": "x86_64",
            "source_mount": "/workspace",
            "selected_passed": True,
            "component_complete": True,
            "family_complete": False,
            "selected": list(evidence.LOADER_CASES),
            "source_before": source,
            "source_after": source,
            "product_before": product_seal,
            "product_after": product_seal,
            "oracle_before": oracle,
            "oracle_after": oracle,
            "cases": cases,
            "elapsed_seconds": 1.0,
        }
        path = report_root / "report.json"
        path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        return path

    def test_loader_reader_accepts_full_receipt_and_returns_manifest_identity(self) -> None:
        report = self._loader_report()
        identity = evidence.validate_loader_report(report, self.product, root=ROOT)
        self.assertEqual(identity["case_count"], len(evidence.LOADER_CASES))
        self.assertEqual(identity["product_manifest_sha256"], sha256(self.product / "share/crabc/manifest.json"))

    def test_loader_reader_rejects_a_partial_passing_selection(self) -> None:
        report = self._loader_report()
        value = json.loads(report.read_text(encoding="utf-8"))
        omitted = evidence.LOADER_CASES[-1]
        value["selected"].remove(omitted)
        del value["cases"][omitted]
        report.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(evidence.LoaderCorpusEvidenceError, "roster|selection"):
            evidence.validate_loader_report(report, self.product, root=ROOT)

    def test_loader_reader_rejects_summary_without_matching_raw_streams(self) -> None:
        report = self._loader_report()
        value = json.loads(report.read_text(encoding="utf-8"))
        raw = Path(value["cases"][evidence.LOADER_CASES[0]]["raw_directory"].replace("/workspace", str(ROOT), 1))
        (raw / "0001-observation.stdout").write_bytes(b"changed\n")
        with self.assertRaisesRegex(evidence.LoaderCorpusEvidenceError, "raw"):
            evidence.validate_loader_report(report, self.product, root=ROOT)

    def test_loader_reader_rejects_stale_current_source(self) -> None:
        report = self._loader_report()
        value = json.loads(report.read_text(encoding="utf-8"))
        value["source_after"] = {"entries": [], "sha256": "0" * 64}
        report.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(evidence.LoaderCorpusEvidenceError, "source"):
            evidence.validate_loader_report(report, self.product, root=ROOT)

    def test_loader_reader_accepts_only_the_documented_retained_readability_mode_change(self) -> None:
        report = self._loader_report()
        for root in report.parent.glob("cases/*/*-root"):
            for path in (root, *root.rglob("*")):
                mode = path.lstat().st_mode
                if path.is_dir():
                    os.chmod(path, mode | 0o555)
                elif path.is_file() and not path.is_symlink():
                    os.chmod(path, mode | 0o444)
        identity = evidence.validate_loader_report(report, self.product, root=ROOT)
        self.assertEqual(identity["case_count"], 21)

    def test_stream_comparison_rejects_false_success_claim(self) -> None:
        comparison = {
            "passed": True,
            "normalization": "none",
            "status_match": True,
            "stdout_match": True,
            "stderr_match": True,
            "oracle": {"status": 0, "timed_out": False, "stdout": evidence.stream_snapshot(b"oracle"), "stderr": evidence.stream_snapshot(b"")},
            "candidate": {"status": 0, "timed_out": False, "stdout": evidence.stream_snapshot(b"candidate"), "stderr": evidence.stream_snapshot(b"")},
        }
        with self.assertRaisesRegex(evidence.LoaderCorpusEvidenceError, "comparison"):
            evidence.validate_corpus_comparison(comparison)

    def test_current_corpus_source_binds_the_frozen_34_case_manifest_without_runtime_execution(self) -> None:
        source = evidence.current_corpus_source(ROOT)
        self.assertEqual(len(evidence._corpus_cases()), 34)
        self.assertEqual(set(source), {"runner", "native_manifest", "workload_source", "process_lifetime_helpers"})

    def test_corpus_reader_accepts_a_full_retained_roster_and_rejects_a_changed_private_root(self) -> None:
        class FixtureCorpus:
            SCHEMA = "crabc.x86_64-owned-package-corpus/v2"
            CANONICAL_INTERPRETER = "/lib/ld-musl-x86_64.so.1"
            CANONICAL_LIBC = "/lib/libc.musl-x86_64.so.1"
            CASE_ENVIRONMENT = {"PATH": "/bin:/usr/bin", "HOME": "/root", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}

            @staticmethod
            def tree_sha256(root: Path, label: str) -> str:
                digest = hashlib.sha256()
                for path in sorted(root.rglob("*")):
                    if path.is_dir():
                        continue
                    digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
                return digest.hexdigest()

            @staticmethod
            def source_identity(manifest: object) -> dict[str, object]:
                return {"fixture": "current-source"}

            def __init__(self, manifest: object, product: Path):
                self.manifest = manifest
                self.product = product

            def load_manifest(self) -> object:
                return self.manifest

            def validate_product(self, product: Path) -> dict[str, object]:
                raw = json.loads((product / "share/crabc/manifest.json").read_text(encoding="utf-8"))
                return {"path": str(product), "manifest_sha256": sha256(product / "share/crabc/manifest.json"),
                        "files": dict(sorted(raw["files"].items())), "aliases": raw["symlinks"]}

        cases = tuple(
            SimpleNamespace(id=f"case-{index:02d}", tier="A", package="fixture", path=f"/bin/case-{index:02d}",
                            argv=(f"case-{index:02d}",), stateful=False, requires_dt_relr=False)
            for index in range(34)
        )
        manifest = SimpleNamespace(cases=cases, archive_roster={"fixture-1.apk": "c" * 64}, index_sha256="d" * 64,
                                   package_library_dirs=("/usr/lib",), base_image_files={})
        corpus = FixtureCorpus(manifest, self.product)
        root = self.work / "corpus"
        root.mkdir()
        payload = root / "application-payload"
        (payload / "bin").mkdir(parents=True)
        (payload / "bin/payload").write_bytes(b"payload ELF")
        product_manifest = json.loads((self.product / "share/crabc/manifest.json").read_text(encoding="utf-8"))
        candidate_product = corpus.validate_product(self.product)
        candidate_product["path"] = evidence.recorded_path(ROOT, "/workspace", self.product)
        oracle_bytes = b"oracle runtime"
        oracle_hash = hashlib.sha256(oracle_bytes).hexdigest()
        oracle = {"root": "/opt/musl-1.2.6", "runtime": {"path": "/opt/musl-1.2.6/lib/libc.so", "sha256": oracle_hash},
                  "loader": {"path": "/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1", "target": "libc.so", "resolved_path": "/opt/musl-1.2.6/lib/libc.so"},
                  "source_manifest": {"path": "/opt/musl-1.2.6/.crabc-oracle", "sha256": "e" * 64}}
        base = {"image_files": {}, "directories": {"/tmp": {"mode": 0o1777}, "/root": {"mode": 0o700}, "/dev": {"mode": 0o755}},
                "device": {"path": "/dev/null", "kind": "character", "mode": 0o666, "major": 1, "minor": 3}}

        def runtime_root(case: object, arm: str) -> dict[str, object]:
            private = root / f"{case.id}-{arm}"
            (private / "lib").mkdir(parents=True)
            (private / "bin").mkdir()
            if arm == "candidate":
                loader = (self.product / "lib/ld-crabc-x86_64.so.1").read_bytes()
                libc = (self.product / "usr/lib/libc.so").read_bytes()
                runtime = {
                    "loader": {"source": evidence.recorded_path(ROOT, "/workspace", self.product / "lib/ld-crabc-x86_64.so.1"),
                               "resolved_source": evidence.recorded_path(ROOT, "/workspace", self.product / "lib/ld-crabc-x86_64.so.1"),
                               "sha256": product_manifest["files"]["lib/ld-crabc-x86_64.so.1"]},
                    "libc": {"source": evidence.recorded_path(ROOT, "/workspace", self.product / "usr/lib/libc.so"),
                             "resolved_source": evidence.recorded_path(ROOT, "/workspace", self.product / "usr/lib/libc.so"),
                             "sha256": product_manifest["files"]["usr/lib/libc.so"]},
                }
            else:
                loader = libc = oracle_bytes
                runtime = {
                    "loader": {"source": oracle["loader"]["path"], "resolved_source": oracle["runtime"]["path"], "sha256": oracle_hash},
                    "libc": {"source": oracle["runtime"]["path"], "resolved_source": oracle["runtime"]["path"], "sha256": oracle_hash},
                }
            (private / "lib/ld-musl-x86_64.so.1").write_bytes(loader)
            (private / "lib/libc.musl-x86_64.so.1").write_bytes(libc)
            executable = private / case.path.lstrip("/")
            executable.write_bytes((case.id + arm).encode())
            seal = corpus.tree_sha256(private, "fixture")
            return {"base_fixtures": base, "runtime": {**runtime, "canonical_interpreter": corpus.CANONICAL_INTERPRETER, "canonical_libc": corpus.CANONICAL_LIBC},
                    "execution_tree_before_sha256": seal, "execution_tree_after_sha256": seal,
                    "executable": {"path": case.path, "sha256": sha256(executable), "interpreter": corpus.CANONICAL_INTERPRETER, "dt_relr": False}}

        outcome = []
        comparison = {"passed": True, "normalization": "none", "status_match": True, "stdout_match": True, "stderr_match": True,
                      "oracle": {"status": 0, "timed_out": False, "stdout": evidence.stream_snapshot(b"ok\n"), "stderr": evidence.stream_snapshot(b"")},
                      "candidate": {"status": 0, "timed_out": False, "stdout": evidence.stream_snapshot(b"ok\n"), "stderr": evidence.stream_snapshot(b"")}}
        for case in cases:
            outcome.append({"id": case.id, "tier": case.tier, "package": case.package, "path": case.path, "argv": list(case.argv),
                            "environment": corpus.CASE_ENVIRONMENT, "stateful": False, "requires_dt_relr": False,
                            "roots": {"oracle": runtime_root(case, "oracle"), "candidate": runtime_root(case, "candidate")},
                            "comparison": comparison})
        inputs = {"verification_before": {"identity": {"directory": "/workspace/.work/input", "index": {"path": "/workspace/.work/index", "sha256": manifest.index_sha256},
                                                         "archives": {"fixture-1.apk": {"sha256": "c" * 64}}},
                                            "index_signature": {"stdout": "verified", "stderr": ""},
                                            "archive_signatures": {"fixture-1.apk": {"metadata": {"pkgname": "fixture", "pkgver": "1", "arch": "x86_64"}, "signature_stdout": "verified", "signature_stderr": ""}}},
                  "after": {"directory": "/workspace/.work/input", "index": {"path": "/workspace/.work/index", "sha256": manifest.index_sha256},
                            "archives": {"fixture-1.apk": {"sha256": "c" * 64}}}}
        source = corpus.source_identity(manifest)
        tools = {"path": "/sbin/apk", "sha256": "a" * 64, "version": "apk-tools 3.0.6-r0, compiled for x86_64.",
                 "keys": {"alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": "b" * 64}, "readelf": {"path": "/usr/bin/readelf", "sha256": "c" * 64}}
        report = {"schema": corpus.SCHEMA, "source_mount": "/workspace", "passed": True, "source": {"before": source, "after": source},
                  "tools": {"before": tools, "after": tools}, "inputs": inputs, "oracle": {"before": oracle, "after": oracle},
                  "candidate_product": {"before": candidate_product, "after": candidate_product},
                  "application_payload": {"path": evidence.recorded_path(ROOT, "/workspace", payload), "sha256": corpus.tree_sha256(payload, "fixture"),
                                          "package_library_dirs": ["/usr/lib"], "elf_closure": [{"path": "/bin/payload", "sha256": sha256(payload / "bin/payload"), "search_paths": [], "needed": {}}]},
                  "execution_root": evidence.recorded_path(ROOT, "/workspace", root), "report_path": evidence.recorded_path(ROOT, "/workspace", root / "report.json"),
                  "case_count": len(cases), "outcomes": outcome}
        report_path = root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with mock.patch.object(evidence, "_corpus", return_value=corpus), mock.patch.object(evidence, "_corpus_cases", return_value=cases):
            identity = evidence.validate_corpus_report(report_path, self.product, root=ROOT)
            self.assertEqual(identity["case_count"], 34)
            (root / "case-00-candidate/lib/libc.musl-x86_64.so.1").write_bytes(b"tampered")
            with self.assertRaisesRegex(evidence.LoaderCorpusEvidenceError, "root|libc"):
                evidence.validate_corpus_report(report_path, self.product, root=ROOT)

    def test_container_mount_mapping_is_bounded_to_the_checkout(self) -> None:
        path = self.work / "safe.json"
        path.write_text("{}", encoding="utf-8")
        self.assertEqual(
            evidence.mounted_path(ROOT, "/workspace", "/workspace/" + path.relative_to(ROOT).as_posix()),
            path,
        )
        with self.assertRaisesRegex(evidence.LoaderCorpusEvidenceError, "unsafe|mount|escape"):
            evidence.mounted_path(ROOT, "/workspace", "/workspace/../outside")


if __name__ == "__main__":
    unittest.main()
