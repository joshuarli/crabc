#!/usr/bin/env python3
"""Contracts for Lua consumption of an immutable dynamic product cohort."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "compat/lua/run_x86_dynamic_supplied.py"
if str(RUNNER_PATH.parent) not in sys.path:
    sys.path.insert(0, str(RUNNER_PATH.parent))
SPEC = importlib.util.spec_from_file_location("crabc_lua_dynamic_supplied_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class SuppliedDynamicLuaTests(unittest.TestCase):
    """Keep supplied products immutable while the Lua consumer uses both arms."""

    scratch_root = ROOT / ".work" / "lua-dynamic-supplied-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="supplied-", dir=self.scratch_root))
        self.state_parent = self.temporary / "state-parent"
        self.seed = self.temporary / "lua-5.4.8.tar.gz"
        self.seed.write_bytes(b"sealed Lua source archive\n")
        self.manifest = {
            "lua": {
                "version": "5.4.8",
                "sha256": RUNNER.LUA.sha256_file(self.seed),
                "archive_root": "lua-5.4.8",
            }
        }
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)

    @staticmethod
    def lane(label: str, *, passed: bool = True) -> dict[str, object]:
        artifacts: dict[str, object] = {}
        for name in ("liblua", "lua", "luac", "probe", "failure", "missing_symbol"):
            artifacts[name] = {
                "artifact": {"sha256": hashlib.sha256(f"{label}:{name}".encode()).hexdigest()}
            }
        return {"passed": passed, "candidate": {"artifacts": artifacts}}

    @staticmethod
    def cohort_snapshot() -> dict[str, object]:
        return {
            "checkout": "/cohort",
            "receipt": {"path": "/cohort/.work/qualification.json", "sha256": "a" * 64},
            "reader": {"path": "/cohort/compat/x86_64/owned_dynamic_qualification.py", "sha256": "b" * 64},
            "source_sha256": "c" * 64,
            "products": {"installed": "d" * 64, "second": "d" * 64, "extracted": "d" * 64},
            "roots": {
                "installed": {"path": "/cohort/.work/installed", "manifest": {"sha256": "d" * 64}},
                "extracted": {"path": "/cohort/.work/extracted", "manifest": {"sha256": "d" * 64}},
            },
        }

    def dispatch(
        self, lanes: list[dict[str, object]], *, seed: Path | None = None,
    ) -> tuple[dict[str, object], Path, mock.Mock]:
        dynamic_lane = mock.Mock(side_effect=lanes)
        seal = {"revision": "e" * 40, "inputs": {"compat/lua/manifest.toml": {"sha256": "f" * 64}}}
        validation = {"status": 0, "stdout": {"text": "validated"}, "stderr": {"text": ""}}
        with (
            mock.patch.object(RUNNER, "consumer_source_seal", return_value=seal),
            mock.patch.object(RUNNER, "validate_cohort", side_effect=[
                (self.cohort_snapshot(), validation), (self.cohort_snapshot(), validation),
            ]),
            mock.patch.object(RUNNER.LUA, "load_manifest", return_value=self.manifest),
            mock.patch.object(RUNNER.DYNAMIC, "run_dynamic_lane", dynamic_lane),
        ):
            report, report_path = RUNNER.run_supplied_dynamic(
                cohort_checkout=Path("/cohort"), cohort_receipt=Path("/cohort/.work/qualification.json"),
                installed_sysroot=Path("/cohort/.work/installed"), extracted_sysroot=Path("/cohort/.work/extracted"),
                archive_seed=self.seed if seed is None else seed,
                jobs=2, timeout=5.0, state_parent=self.state_parent,
            )
        return report, report_path, dynamic_lane

    def test_two_offline_lanes_share_a_private_seeded_cache_without_a_producer(self) -> None:
        installed = self.lane("same")
        extracted = self.lane("same")

        report, report_path, dynamic_lane = self.dispatch([installed, extracted])

        self.assertTrue(report["passed"])
        self.assertEqual(report["result"], "pass")
        self.assertEqual(dynamic_lane.call_count, 2)
        caches = [Path(call.kwargs["cache"]) for call in dynamic_lane.call_args_list]
        self.assertEqual(caches[0], caches[1])
        self.assertTrue((caches[0] / "lua-5.4.8.tar.gz").is_file())
        self.assertEqual(
            [call.kwargs["offline"] for call in dynamic_lane.call_args_list], [True, True]
        )
        self.assertEqual(
            [call.kwargs["sysroot_path"] for call in dynamic_lane.call_args_list],
            [Path("/cohort/.work/installed"), Path("/cohort/.work/extracted")],
        )
        dispatcher = report["dispatcher"]
        self.assertEqual(dispatcher["producer"], "absent (supplied immutable cohort)")
        self.assertEqual(dispatcher["package"], "absent (supplied immutable cohort)")
        self.assertEqual(dispatcher["extract"], "absent (supplied immutable cohort)")
        self.assertEqual(dispatcher["publication"], "absent (live source-consumer gate only)")
        self.assertTrue(report_path.is_file())
        self.assertTrue(json.loads(report_path.read_text(encoding="utf-8"))["passed"])

    def test_artifact_drift_retains_a_failing_private_report(self) -> None:
        report, report_path, dynamic_lane = self.dispatch([self.lane("installed"), self.lane("extracted")])

        self.assertFalse(report["passed"])
        self.assertEqual(report["result"], "fail")
        self.assertEqual(report["reproducibility"]["status"], "rejected")
        self.assertEqual(dynamic_lane.call_count, 2)
        self.assertTrue(report_path.is_file())
        self.assertFalse(json.loads(report_path.read_text(encoding="utf-8"))["passed"])

    def test_bad_archive_seed_stops_before_any_lane(self) -> None:
        bad_seed = self.temporary / "bad-lua-5.4.8.tar.gz"
        bad_seed.write_bytes(b"different archive\n")

        report, report_path, dynamic_lane = self.dispatch([self.lane("unused"), self.lane("unused")], seed=bad_seed)

        self.assertFalse(report["passed"])
        self.assertIn("seed hash differs", report["error"])
        self.assertEqual(dynamic_lane.call_count, 0)
        self.assertTrue(report_path.is_file())


class SuppliedDynamicCohortIdentityTests(unittest.TestCase):
    """The supplied roots must match the immutable cohort receipt exactly."""

    scratch_root = ROOT / ".work" / "lua-dynamic-supplied-identity-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="identity-", dir=self.scratch_root))
        self.root = self.temporary / "root"
        self.manifest = self.root / "share/crabc/manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_bytes(b"sealed manifest\n")
        self.wrapper = self.root / "bin/crabc-cc-dynamic"
        self.wrapper.parent.mkdir(parents=True)
        self.wrapper.write_bytes(b"wrapper\n")
        self.headers = self.root / "usr/include"
        self.headers.mkdir(parents=True)
        self.libc = self.root / "usr/lib/libc.so"
        self.libc.parent.mkdir(parents=True)
        self.libc.write_bytes(b"libc\n")
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)

    def test_root_manifest_mismatch_is_rejected_after_owned_sysroot_validation(self) -> None:
        runtime = {"headers": self.headers, "libc.so": self.libc}
        with mock.patch.object(RUNNER.DYNAMIC, "owned_dynamic_sysroot", return_value=(self.root, self.wrapper, runtime, {})):
            with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "does not match the cohort receipt"):
                RUNNER._supplied_root_identity(self.root, "installed", "0" * 64)

    def test_receipt_rejects_promoted_or_incomplete_product_state(self) -> None:
        receipt = self.temporary / "qualification.json"
        receipt.write_text(json.dumps({
            "status": "qualified-pending-review",
            "source_sha256": "a" * 64,
            "products": {"installed": "b" * 64, "second": "b" * 64, "extracted": "b" * 64},
            "runtime_v1_published": False,
            "family_completion": False,
            "promotion_ready": True,
            "public_support": False,
        }), encoding="utf-8")

        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "non-promoting state"):
            RUNNER._read_qualification_receipt(receipt)

        receipt.write_text(json.dumps({
            "status": "qualified-pending-review",
            "source_sha256": "a" * 64,
            "products": {"installed": "b" * 64, "extracted": "b" * 64},
            "runtime_v1_published": False,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }), encoding="utf-8")
        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "wrong dynamic product roster"):
            RUNNER._read_qualification_receipt(receipt)

    def test_linked_cohort_reader_uses_current_mount_git_metadata(self) -> None:
        checkout = self.temporary / ".work/worktrees/frozen-cohort"
        checkout.mkdir(parents=True)
        metadata = self.temporary / ".git/worktrees/frozen-cohort"
        metadata.mkdir(parents=True)
        pointer = checkout / ".git"
        pointer.write_text("gitdir: /host/crabc/.git/worktrees/frozen-cohort\n", encoding="utf-8")
        metadata_pointer = metadata / "gitdir"
        metadata_pointer.write_text(
            "/host/crabc/.work/worktrees/frozen-cohort/.git\n", encoding="utf-8"
        )

        with mock.patch.object(RUNNER, "ROOT", self.temporary):
            environment, context = RUNNER._cohort_git_context(checkout, self.temporary / "state")

        self.assertEqual(environment["GIT_DIR"], str(metadata))
        self.assertEqual(environment["GIT_WORK_TREE"], str(checkout))
        self.assertEqual(context["git_dir"], str(metadata))
        self.assertEqual(context["git_work_tree"], str(checkout))
        self.assertEqual(context["worktree_pointer"]["sha256"], RUNNER.LUA.sha256_file(pointer))
        self.assertEqual(context["metadata_pointer"]["sha256"], RUNNER.LUA.sha256_file(metadata_pointer))

    def test_linked_cohort_reader_rejects_metadata_for_another_checkout(self) -> None:
        checkout = self.temporary / ".work/worktrees/frozen-cohort"
        checkout.mkdir(parents=True)
        metadata = self.temporary / ".git/worktrees/frozen-cohort"
        metadata.mkdir(parents=True)
        (checkout / ".git").write_text(
            "gitdir: /host/crabc/.git/worktrees/frozen-cohort\n", encoding="utf-8"
        )
        (metadata / "gitdir").write_text(
            "/host/crabc/.work/worktrees/other-cohort/.git\n", encoding="utf-8"
        )

        with mock.patch.object(RUNNER, "ROOT", self.temporary):
            with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "names a different checkout"):
                RUNNER._cohort_git_context(checkout, self.temporary / "state")


if __name__ == "__main__":
    unittest.main()
